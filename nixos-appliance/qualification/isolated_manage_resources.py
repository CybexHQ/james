"""Exact-label Docker resources and explicit environment for the isolated fixture."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import shlex

LABEL = 'net.cybex.james.qualification.owner'
ROLE = 'net.cybex.james.qualification.role'
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']


def write(path, body, *, uid=0, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, uid, uid)
        view = memoryview(body)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def env_body(values):
    return ''.join(f'{key}={shlex.quote(str(value))}\n' for key, value in sorted(values.items())).encode()


def environment(config, secrets, release, db_password, ssh_ca, proxy_url):
    values = {
        'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/var/lib/cybex',
        'CYBEX_DATABASE_URL': f'postgres://fixture:{db_password}@db:5432/fixture',
        'CYBEX_PORT': '8080', 'CYBEX_STATIC_DIR': '/opt/cybex/web/dist',
        'CYBEX_NIXPKGS_ICON_CACHE_DIR': '/var/lib/cybex/app-icons',
        'CYBEX_PUBLIC_API_URL': config['manage_origin'],
        'CYBEX_JAMES_PROVISIONING_MANAGE_ORIGIN': config['manage_origin'],
        'CYBEX_JAMES_PROVISIONING_PRIVATE_KEY_B64': secrets['seed'],
        'CYBEX_JAMES_PROVISIONING_EXPECTED_PUBLIC_KEY': secrets['public_key'],
        'CYBEX_JAMES_SSH_CA_PRIVATE_KEY_B64': ssh_ca,
        'CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY': config['release_public_key'],
        'CYBEX_SECRET_ENCRYPTION_KEY': secrets['encryption_key'],
        'CYBEX_ALLOW_OPEN_ENROLLMENT': 'false', 'CYBEX_BACKGROUND_RECONCILERS': 'enabled',
        'CYBEX_JAMES_APPLIANCE_AUTOMATIC_ROLLOUTS': 'false',
        'CYBEX_JAMES_UPDATE_QUALIFICATION_ENABLED': 'false',
        'CYBEX_JAMES_RELEASE_MANIFEST_URL': release['manifest_url'],
        'CYBEX_JAMES_RELEASE_MANIFEST_SHA256': release['manifest_sha256'],
        'CYBEX_JAMES_RELEASE_VERSION': release['version'],
        'CYBEX_JAMES_COMPATIBILITY_PROJECTION_SHA256': release['compatibility_sha256'],
    }
    if proxy_url:
        values.update(HTTPS_PROXY=proxy_url, https_proxy=proxy_url,
                      HTTP_PROXY=proxy_url, http_proxy=proxy_url, NO_PROXY='db,127.0.0.1,localhost',
                      no_proxy='db,127.0.0.1,localhost')
    return values


def nginx_config(receipt):
    hostname = receipt['manage_origin'][8:]
    challenge = json.dumps({key: receipt[key] for key in ('owner', 'challenge', 'manage_origin')}, separators=(',', ':'))
    return f'''worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events {{ worker_connections 256; }}
http {{
  access_log off;
  client_body_temp_path /tmp/client;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;
  server {{
    listen 8443 ssl;
    server_name {hostname};
    ssl_certificate /run/fixture/tls.crt;
    ssl_certificate_key /run/fixture/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    if ($host != {hostname}) {{ return 444; }}
    location = /.well-known/cybex-qualification/{receipt['challenge']} {{
      default_type application/json;
      return 200 '{challenge}';
    }}
    location / {{
      proxy_pass http://app:8080;
      proxy_set_header Host {hostname};
      proxy_set_header X-Forwarded-Proto https;
      proxy_redirect off;
      proxy_read_timeout 120s;
      client_max_body_size 32m;
    }}
  }}
}}
'''.encode()


class Docker:
    def __init__(self, run, owner, prefix):
        self.run, self.owner, self.prefix = run, owner, prefix

    def call(self, *args):
        return self.run(DOCKER + list(args))

    def name(self, role):
        return self.prefix + '-' + role

    def image(self, reference, role, revision=None):
        value = json.loads(self.call('image', 'inspect', reference))[0]
        if ((reference.startswith('sha256:') and value['Id'] != reference)
                or ('@' in reference and reference not in (value.get('RepoDigests') or []))):
            raise ValueError('fixture image does not match its pinned identity')
        config = value.get('Config', {})
        if set(config.get('Volumes') or {}) - ({'/var/lib/postgresql/data'} if role == 'db' else set()):
            raise ValueError('fixture image declares unowned persistent volumes')
        labels = config.get('Labels') or {}
        if role == 'app' and (labels.get('org.opencontainers.image.revision') != revision
                             or labels.get('org.opencontainers.image.source') != 'https://github.com/CybexHQ/development'):
            raise ValueError('Manage fixture image lacks exact reviewed development source labels')
        return value['Id']

    def labels(self, role):
        return ['--label', LABEL + '=' + self.owner, '--label', ROLE + '=' + role]

    def network(self, subnet):
        # No adoption: a prior name, even one bearing this owner, is an error.
        existing = [json.loads(line) for line in self.call('network', 'ls', '--format', 'json').splitlines()]
        for network in existing:
            if network['Name'] == self.name('backend'):
                raise ValueError('refusing to adopt an existing fixture Docker network')
            value = json.loads(self.call('network', 'inspect', network['ID']))[0]
            for config in value.get('IPAM', {}).get('Config') or []:
                if config.get('Subnet') and ipaddress.ip_network(subnet).overlaps(ipaddress.ip_network(config['Subnet'])):
                    raise ValueError('fixture backend overlaps an existing Docker network')
        for route in json.loads(self.run(['ip', '-j', '-4', 'route', 'show'])):
            if route.get('dst') not in {None, 'default'} and ipaddress.ip_network(subnet).overlaps(ipaddress.ip_network(route['dst'], strict=False)):
                raise ValueError('fixture backend overlaps a host route')
        identity = self.call('network', 'create', '--driver', 'bridge', '--internal',
                             '--subnet', subnet, '--gateway', str(ipaddress.ip_network(subnet)[1]),
                             *self.labels('backend'), self.name('backend')).decode().strip()
        self.verify_network(identity, subnet)
        return identity

    def verify_network(self, identity, subnet, members=()):
        value = json.loads(self.call('network', 'inspect', self.name('backend')))[0]
        if (value['Id'] != identity or value['Name'] != self.name('backend') or value['Driver'] != 'bridge'
                or not value['Internal'] or value.get('EnableIPv6')
                or value.get('Labels', {}).get(LABEL) != self.owner
                or value.get('Labels', {}).get(ROLE) != 'backend'
                or value['IPAM']['Config'] != [{'Subnet': subnet, 'Gateway': str(ipaddress.ip_network(subnet)[1])}]
                or set(value.get('Containers') or {}) != set(members)):
            raise ValueError('fixture Docker network ownership or isolation changed')
        return value

    def create(self, role, image, uid, network_id, state, mounts, *, dns, peer=None):
        address = ipaddress.ip_address(dns)
        if (address.version != 4 or str(address) != dns
                or not any(address in ipaddress.ip_network(block)
                           for block in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))):
            raise ValueError('fixture DNS must be its owned private IPv4 peer')
        # All arguments are generated from validated inputs. Never pass an env
        # file to Docker: the launch shell reads a single owned, mounted file.
        args = ['container', 'create', '--name', self.name(role), *self.labels(role),
                '--network', network_id, '--network-alias', role, '--dns', dns,
                '--log-driver', 'local', '--log-opt', 'max-size=10m', '--log-opt', 'max-file=2', '--user', str(uid) + ':' + str(uid),
                '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--pids-limit', '256', '--no-healthcheck', '--restart', 'no',
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
                '--entrypoint', '/usr/bin/env']
        if role == 'db':
            args += ['--tmpfs', '/var/run/postgresql:rw,nosuid,nodev,noexec,size=16m,uid=999,gid=999,mode=0700']
        for source, target, readonly in mounts:
            if ',' in str(source):
                raise ValueError('fixture mount paths cannot contain commas')
            args += ['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if readonly else '')]
        if peer:
            args += ['--publish', peer + ':443:8443/tcp']
        args += [image, '-i', '/bin/sh', '/run/fixture/launch.sh']
        identity = self.call(*args).decode().strip()
        self.verify_container(role, identity, image, uid, network_id, mounts, dns=dns, peer=peer, created=True)
        return identity

    def verify_container(self, role, identity, image, uid, network_id, mounts, *, dns, peer=None, created=False):
        # Labels and identity must come from one atomic inspect result.
        value = json.loads(self.call('container', 'inspect', identity))[0]
        labels = value.get('Config', {}).get('Labels', {})
        if labels.get(LABEL) != self.owner or labels.get(ROLE) != role:
            raise ValueError('fixture container ownership changed')
        host, config = value['HostConfig'], value['Config']
        attached = list(value['NetworkSettings']['Networks'].values())
        expected_mounts = {(str(source), target, not readonly) for source, target, readonly in mounts}
        actual_mounts = {(entry['Source'], entry['Destination'], entry['RW']) for entry in value['Mounts'] if entry['Type'] == 'bind'}
        tmpfs = {'/tmp': 'rw,nosuid,nodev,noexec,size=64m'}
        if role == 'db':
            tmpfs['/var/run/postgresql'] = 'rw,nosuid,nodev,noexec,size=16m,uid=999,gid=999,mode=0700'
        ports = {'8443/tcp': [{'HostIp': peer, 'HostPort': '443'}]} if peer else {}
        if (value['Id'] != identity or value['Image'] != image or config['User'] != f'{uid}:{uid}'
                or config['Entrypoint'] != ['/usr/bin/env'] or config['Cmd'] != ['-i', '/bin/sh', '/run/fixture/launch.sh']
                or host['Privileged'] or not host['ReadonlyRootfs'] or host['CapAdd']
                or host['CapDrop'] != ['ALL'] or host['SecurityOpt'] != ['no-new-privileges:true']
                or host.get('Devices') or host.get('DeviceRequests') or host.get('PidMode')
                or host.get('PidsLimit') != 256
                or host.get('IpcMode') not in {'private', ''} or host.get('Tmpfs') != tmpfs
                or host.get('RestartPolicy', {}).get('Name') != 'no'
                or host.get('Dns') != [dns] or host.get('DnsSearch') not in ([], None)
                or host.get('LogConfig') != {'Type': 'local', 'Config': {'max-size': '10m', 'max-file': '2'}}
                or len(attached) != 1 or attached[0]['NetworkID'] not in ({network_id, ''} if created else {network_id})
                or actual_mounts != expected_mounts or any(m['Type'] not in {'bind', 'tmpfs'} for m in value['Mounts'])
                or any(m['Destination'] not in tmpfs for m in value['Mounts'] if m['Type'] == 'tmpfs')
                or (host.get('PortBindings') or {}) != ports or host.get('NetworkMode') != network_id):
            raise ValueError('fixture container identity or confinement changed')
        return value

    def remove_owned(self, role, identity=None):
        kind = 'network' if role == 'backend' else 'container'
        existing = self.call(kind, 'ls', *(['-a'] if kind == 'container' else []), '--format', '{{.ID}} {{.Name}}' if kind == 'network' else '{{.ID}} {{.Names}}')
        if not any(line.split()[-1] == self.name(role) for line in existing.decode().splitlines()):
            return
        # The inspected labels and immutable ID must describe the same object;
        # a name replacement between separate reads must never select a victim.
        value = json.loads(self.call(kind, 'inspect', self.name(role)))[0]
        labels = value.get('Labels', {}) if kind == 'network' else value.get('Config', {}).get('Labels', {})
        if labels.get(LABEL) != self.owner or labels.get(ROLE) != role:
            raise ValueError('refusing to clean up a resource owned by another run')
        actual = value['Id']
        if identity is not None and identity != actual:
            raise ValueError('refusing to clean up a replaced fixture resource')
        self.call(kind, 'rm', *(['-f'] if kind == 'container' else []), actual)
