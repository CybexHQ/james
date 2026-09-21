"""Own a fresh, private Manage deployment for exact-origin NixOS qualification.

No command-line prepare path is provided until the runner supplies a reviewed
network adapter. The adapter MUST establish DNS, guest and Docker host/egress
firewall confinement and an allowlisted proxy, then verify the actual owned
rules/processes on every verify(context, receipt) call. JSON assertions alone
are not an implementation of this contract. All three methods are required:
prepare(context), verify(context, receipt), cleanup(context, receipt).
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import runpy
import secrets as random
import shutil
import stat
import time
import uuid
from urllib.parse import urlsplit


def sibling(name):
    spec = importlib.util.spec_from_file_location('_james_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inputs = sibling('isolated_manage_config')
resources = sibling('isolated_manage_resources')
transport = sibling('isolated_manage_transport')
SCHEMA = 'cybex.james.isolated-manage.v1'
GUARD_SCHEMA = 'cybex.james.isolated-manage-network.v1'


class Owner:
    def __init__(self, state_dir, adapter, *, run=inputs.command):
        self.state = Path(state_dir)
        self.directory = self.state / 'manage'
        self.adapter, self.run = adapter, run
        if adapter is None or any(not callable(getattr(adapter, method, None)) for method in ('prepare', 'verify', 'cleanup')):
            raise ValueError('a reviewed, verifying default-deny network adapter is required')

    def scope(self):
        if os.geteuid() != 0:
            raise ValueError('isolated Manage ownership requires root')
        inputs.ordinary_path(self.state)
        module = runpy.run_path(str(Path(__file__).with_name('development-scope.py')))
        value = module['read_scope'](self.state)
        module['verify'](self.state, value['manage_origin'], value['bridge'])
        return value

    @contextlib.contextmanager
    def lock(self):
        self.scope()
        fd = os.open(self.state / 'manage.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
                raise ValueError('invalid fixture ownership lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def save(self, receipt):
        path = self.state / ('manage-receipt.' + random.token_hex(8))
        resources.write(path, inputs.canonical(receipt), mode=0o600)
        os.replace(path, self.state / 'manage.json')
        fd = os.open(self.state, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def read(self):
        scope = self.scope()
        value = json.loads(inputs.read_file(self.state / 'manage.json'))
        if (value.get('schema') != SCHEMA or value.get('owner') != scope['owner']
                or value.get('manage_origin') != scope['manage_origin']
                or value.get('prefix') != 'jnqm-' + uuid.UUID(scope['owner']).hex
                or value.get('directory') != str(self.directory)
                or value.get('context', {}).get('bridge') != scope['bridge']
                or value.get('context', {}).get('subnet') != scope['subnet']
                or value.get('peer_ipv4') != str(ipaddress.ip_interface(scope['subnet']).ip)):
            raise ValueError('isolated Manage receipt differs from the owned scope')
        return value

    def docker(self, receipt):
        return resources.Docker(self.run, receipt['owner'], receipt['prefix'])

    def network_members(self, receipt, *, complete=False):
        containers = receipt.get('containers')
        if not isinstance(containers, dict) or set(containers) - {'db', 'app', 'tls'}:
            raise ValueError('invalid fixture container ownership receipt')
        members = []
        for role in ('db', 'app', 'tls'):
            identity = containers.get(role, {}).get('id')
            if identity is not None:
                if not isinstance(identity, str) or not identity:
                    raise ValueError('invalid fixture container identity')
                members.append(identity)
            elif complete:
                raise ValueError('isolated Manage fixture is missing an owned container identity')
        return members

    def guard(self, receipt):
        context, guard = receipt['context'], receipt['guard']
        expected = {'schema': GUARD_SCHEMA, **context}
        if (not isinstance(guard, dict) or set(guard) != set(expected) | {'guard_id', 'proxy_url'}
                or any(guard.get(key) != value for key, value in expected.items())
                or not isinstance(guard['guard_id'], str) or not guard['guard_id']):
            raise ValueError('network adapter receipt does not bind the exact fixture')
        proxy = guard['proxy_url']
        if context['egress_hosts']:
            url = urlsplit(proxy or '')
            gateway = str(ipaddress.ip_network(context['backend_subnet'])[1])
            if (url.scheme != 'http' or url.hostname != gateway or not url.port or url.path
                    or url.query or url.fragment or url.username or url.password
                    or proxy != f'http://{gateway}:{url.port}'):
                raise ValueError('fixture egress needs an explicit owned backend-gateway proxy')
        elif proxy is not None:
            raise ValueError('offline fixture cannot acquire implicit egress')
        if self.adapter.verify(context, guard) is not True:
            raise ValueError('network adapter could not verify its actual owned confinement')
        return True

    def prepare(self, config_path, candidate_dir, predecessor_dir):
        with self.lock():
            if any(path.exists() or path.is_symlink()
                   for path in (self.directory, self.state / 'manage.json', self.state / 'session')):
                raise ValueError('refusing to adopt an existing Manage fixture')
            config, secret = inputs.load(config_path, self.run)
            releases = inputs.signed_releases(config, secret, candidate_dir, predecessor_dir)
            scope = self.scope()
            if config['manage_origin'] != scope['manage_origin']:
                raise ValueError('fixture config origin differs from its owned scope')
            backend = ipaddress.ip_network(config['backend_subnet'])
            if backend.overlaps(ipaddress.ip_interface(scope['subnet']).network):
                raise ValueError('fixture backend overlaps the guest network')
            receipt = {'schema': SCHEMA, 'owner': scope['owner'], 'manage_origin': config['manage_origin'],
                       'peer_ipv4': str(ipaddress.ip_interface(scope['subnet']).ip),
                       'certificate_sha256': secret['certificate_sha256'], 'challenge': random.token_hex(32),
                       'prefix': 'jnqm-' + uuid.UUID(scope['owner']).hex, 'directory': str(self.directory),
                       'source_revision': config['manage_revision'], 'releases': releases,
                       'selected_release': config['initial_release'], 'status': 'preparing',
                       'containers': {}, 'files': {}, 'guard': None, 'allowed_device_id': None,
                       'context': {'owner': scope['owner'], 'bridge': scope['bridge'], 'subnet': scope['subnet'],
                                   'manage_origin': config['manage_origin'],
                                   'peer_ipv4': str(ipaddress.ip_interface(scope['subnet']).ip),
                                   'network_id': None, 'backend_subnet': config['backend_subnet'],
                                   'egress_hosts': config['egress_hosts']}}
            docker = self.docker(receipt)
            receipt['images'] = {role: docker.image(config[key], role, config['manage_revision'])
                                 for role, key in (('app', 'app_image'), ('db', 'postgres_image'), ('tls', 'tls_image'))}
            self.directory.mkdir(mode=0o700)
            self.save(receipt)
            try:
                receipt['context']['network_id'] = docker.network(config['backend_subnet'])
                self.save(receipt)
                receipt['guard'] = self.adapter.prepare(dict(receipt['context']))
                self.save(receipt)
                self.guard(receipt)
                self.materialize(receipt, config, secret)
                for role in ('db', 'app', 'tls'):
                    spec = receipt['containers'][role]
                    spec['id'] = docker.create(role, spec['image'], spec['uid'], receipt['context']['network_id'],
                                               self.directory, spec['mounts'], dns=receipt['peer_ipv4'], peer=spec['peer'])
                    self.save(receipt)
                    self.guard(receipt)
                    docker.call('container', 'start', spec['id'])
                    docker.verify_container(role, spec['id'], spec['image'], spec['uid'],
                                            receipt['context']['network_id'], spec['mounts'], dns=receipt['peer_ipv4'], peer=spec['peer'])
                    docker.verify_network(receipt['context']['network_id'], receipt['context']['backend_subnet'],
                                          self.network_members(receipt))
                    if role == 'db':
                        self.wait_database(docker, spec['id'])
                self.wait_health(receipt)
                self.bootstrap(receipt)
                receipt['status'] = 'ready'
                self.save(receipt)
                return receipt
            except BaseException:
                # Retain the durable intent for explicit exact-owner cleanup.
                # Automatic cleanup could obscure a failed firewall adapter.
                receipt['status'] = 'failed'
                self.save(receipt)
                raise

    def materialize(self, receipt, config, secret):
        secret['encryption_key'] = base64.b64encode(random.token_bytes(32)).decode()
        ca = self.directory / 'ssh-ca'
        self.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'isolated-qualification', '-f', ca])
        ssh_ca = base64.b64encode(inputs.read_file(ca)).decode()
        database_password = random.token_hex(32)
        app_env = resources.environment(config, secret, receipt['releases'][receipt['selected_release']],
                                        database_password, ssh_ca, receipt['guard']['proxy_url'])
        values = {'app': (10001, app_env, 'exec /opt/cybex/bin/cybex\n'),
                  'db': (999, {'PATH': '/usr/local/bin:/usr/bin:/bin', 'POSTGRES_USER': 'fixture',
                               'POSTGRES_PASSWORD': database_password, 'POSTGRES_DB': 'fixture',
                               'PGDATA': '/var/lib/postgresql/data'},
                         'exec /usr/local/bin/docker-entrypoint.sh postgres\n'),
                  'tls': (101, {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'},
                          "exec /usr/sbin/nginx -c /run/fixture/nginx.conf -g 'daemon off;'\n")}
        for role, (uid, environment, executable) in values.items():
            resources.write(self.directory / (role + '.env'), resources.env_body(environment), uid=uid)
            resources.write(self.directory / (role + '.sh'),
                            ('set -eu\nset -a\n. /run/fixture/environment\nset +a\n' + executable).encode(), mode=0o444)
            mounts = [[str(self.directory / (role + '.env')), '/run/fixture/environment', True],
                      [str(self.directory / (role + '.sh')), '/run/fixture/launch.sh', True]]
            if role in {'app', 'db'}:
                data = self.directory / (role + '-data')
                data.mkdir(mode=0o700)
                os.chown(data, uid, uid)
                mounts.append([str(data), '/var/lib/cybex' if role == 'app' else '/var/lib/postgresql/data', False])
            else:
                for name, body, mode in (('tls.crt', secret['certificate'], 0o444),
                                         ('tls.key', secret['tls_key'], 0o400),
                                         ('nginx.conf', resources.nginx_config(receipt), 0o444)):
                    resources.write(self.directory / name, body, uid=uid if name == 'tls.key' else 0, mode=mode)
                    mounts.append([str(self.directory / name), '/run/fixture/' + name, True])
            receipt['containers'][role] = {'id': None, 'image': receipt['images'][role], 'uid': uid,
                                           'mounts': mounts, 'peer': receipt['peer_ipv4'] if role == 'tls' else None}
        for path in self.directory.iterdir():
            if path.is_file():
                receipt['files'][path.name] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                              'uid': path.stat().st_uid, 'mode': stat.S_IMODE(path.stat().st_mode)}
        self.save(receipt)

    def wait_database(self, docker, identity):
        deadline = time.monotonic() + 90
        while True:
            try:
                docker.call('container', 'exec', identity, '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin',
                            '/usr/bin/pg_isready', '-h', '127.0.0.1', '-U', 'fixture', '-d', 'fixture')
                return
            except ValueError:
                if time.monotonic() >= deadline:
                    raise ValueError('fresh fixture database did not become ready') from None
                time.sleep(1)

    def client(self, receipt):
        return transport.Transport(receipt, lambda: self.guard(receipt))

    def wait_health(self, receipt):
        deadline = time.monotonic() + 120
        while True:
            try:
                health = self.client(receipt).request('/v1/health')
                if (health.get('source_revision') != receipt['source_revision']
                        or health.get('source_dirty') is not False):
                    raise RuntimeError('isolated Manage binary does not match reviewed clean source')
                return
            except (ValueError, OSError):
                if time.monotonic() >= deadline:
                    raise ValueError('fresh fixture Manage did not become healthy') from None
                time.sleep(1)

    def bootstrap(self, receipt):
        password = random.token_urlsafe(48)
        value = self.client(receipt).request('/v1/auth/bootstrap', {
            'email': 'qualification-' + receipt['owner'] + '@example.invalid',
            'display_name': 'Disposable qualification operator', 'password': password,
            'organization_name': 'Disposable James qualification', 'organization_type': 'company',
            'workstation_language': 'en-US', 'workstation_keyboard': 'us',
            'workstation_timezone': 'UTC', 'workstation_region_confirmed': True})
        token = value['session_token']
        organization = str(uuid.UUID(value['organization']['id']))
        if not isinstance(token, str) or not token or '\n' in token:
            raise ValueError('fresh fixture bootstrap did not issue a valid private session')
        resources.write(self.state / 'session', (token + '\n').encode(), mode=0o600)
        receipt['organization_id'] = organization
        self.save(receipt)

    def replace_app_environment(self, receipt, device_id):
        path = self.directory / 'app.env'
        body = inputs.read_file(path, private=False, uid=10001)
        replacements = {
            'CYBEX_JAMES_UPDATE_QUALIFICATION_ENABLED': 'true',
            'CYBEX_JAMES_UPDATE_QUALIFICATION_ORGANIZATION_ID': receipt['organization_id'],
            'CYBEX_JAMES_UPDATE_QUALIFICATION_DEVICE_IDS': device_id,
        }
        found = {key: 0 for key in replacements}
        lines = []
        for line in body.decode().splitlines():
            key = line.partition('=')[0]
            if key in replacements:
                found[key] += 1
                line = key + '=' + replacements[key]
            lines.append(line)
        if found['CYBEX_JAMES_UPDATE_QUALIFICATION_ENABLED'] != 1 or any(
                found[key] for key in replacements if key != 'CYBEX_JAMES_UPDATE_QUALIFICATION_ENABLED'):
            raise ValueError('fixture qualification environment is not in its initial closed state')
        lines.extend(key + '=' + replacements[key] for key in replacements if not found[key])
        updated = ('\n'.join(lines) + '\n').encode()
        temporary = self.directory / ('app.env.' + random.token_hex(8))
        try:
            resources.write(temporary, updated, uid=10001)
            os.replace(temporary, path)
            fd = os.open(self.directory, os.O_DIRECTORY | os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)
        info = path.stat()
        receipt['files']['app.env'] = {
            'sha256': hashlib.sha256(updated).hexdigest(),
            'uid': info.st_uid,
            'mode': stat.S_IMODE(info.st_mode),
        }

    def recreate_app(self, receipt):
        """Replace the exact app after its durable image/environment receipt changed."""
        docker = self.docker(receipt)
        app = receipt['containers']['app']
        docker.remove_owned('app', app['id'])
        app['id'] = None
        self.save(receipt)
        app['id'] = docker.create('app', app['image'], app['uid'], receipt['context']['network_id'],
                                  self.directory, app['mounts'], dns=receipt['peer_ipv4'], peer=app['peer'])
        self.save(receipt)
        self.guard(receipt)
        docker.call('container', 'start', app['id'])
        value = docker.verify_container('app', app['id'], app['image'], app['uid'],
                                        receipt['context']['network_id'], app['mounts'],
                                        dns=receipt['peer_ipv4'], peer=app['peer'])
        if not value['State']['Running']:
            raise ValueError('reconfigured fixture app container is not running')
        docker.verify_network(receipt['context']['network_id'], receipt['context']['backend_subnet'],
                              self.network_members(receipt, complete=True))
        self.guard(receipt)
        tls = receipt['containers']['tls']
        docker.call('container', 'restart', tls['id'])
        value = docker.verify_container('tls', tls['id'], tls['image'], tls['uid'],
                                        receipt['context']['network_id'], tls['mounts'],
                                        dns=receipt['peer_ipv4'], peer=tls['peer'])
        if not value['State']['Running']:
            raise ValueError('fixture TLS container did not recover after app replacement')
        self.wait_health(receipt)

    def allow_device(self, device_id):
        if not re.fullmatch(r'dev_[0-9a-f]{32}', device_id):
            raise ValueError('invalid qualification device identity')
        with self.lock():
            receipt = self.verify()
            admitted = receipt.get('allowed_device_id')
            if admitted is not None:
                if admitted != device_id:
                    raise ValueError('fixture already admits a different qualification device')
                return receipt
            token = inputs.read_file(self.state / 'session', maximum=8192).decode().strip()
            detail = self.client(receipt).request('/v1/james/nodes/' + device_id, token=token)
            if detail.get('node', {}).get('device_id') != device_id:
                raise ValueError('qualification target is not an active James node in the owned organization')
            receipt['status'] = 'reconfiguring'
            receipt['allowed_device_id'] = device_id
            self.save(receipt)
            try:
                self.replace_app_environment(receipt, device_id)
                self.save(receipt)
                self.recreate_app(receipt)
                receipt['status'] = 'ready'
                self.save(receipt)
                return receipt
            except BaseException:
                receipt['status'] = 'failed'
                self.save(receipt)
                raise

    def verify(self):
        receipt = self.read()
        if receipt['status'] != 'ready':
            raise ValueError('isolated Manage fixture has not completed fresh bootstrap')
        self.guard(receipt)
        docker = self.docker(receipt)
        docker.verify_network(receipt['context']['network_id'], receipt['context']['backend_subnet'],
                              self.network_members(receipt, complete=True))
        for name, info in receipt['files'].items():
            if name != Path(name).name:
                raise ValueError('invalid fixture input receipt path')
            path = self.directory / name
            body = inputs.read_file(path, private=False, uid=info['uid'])
            if stat.S_IMODE(path.stat().st_mode) != info['mode'] or hashlib.sha256(body).hexdigest() != info['sha256']:
                raise ValueError('fixture mounted input changed')
        for role, spec in receipt['containers'].items():
            value = docker.verify_container(role, spec['id'], spec['image'], spec['uid'],
                                            receipt['context']['network_id'], spec['mounts'], dns=receipt['peer_ipv4'], peer=spec['peer'])
            if not value['State']['Running']:
                raise ValueError('isolated Manage owned container is not running')
        self.client(receipt).request('/v1/health')
        return receipt

    def api(self, path, body=None):
        receipt = self.verify()
        token = inputs.read_file(self.state / 'session', maximum=8192).decode().strip()
        return self.client(receipt).request(path, body, token)

    def refuse_mounted_state(self):
        # Same-filesystem bind mounts retain st_dev. Check the kernel mount
        # inventory as well as the top-level ownership checks before removal.
        # All fixture containers have already been removed at this boundary.
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            fields = line.split()
            if len(fields) < 7:
                raise ValueError('cannot verify fixture state mount boundaries')
            target = Path(re.sub(r'\\([0-7]{3})',
                                 lambda match: chr(int(match.group(1), 8)), fields[4]))
            if target == self.directory or self.directory in target.parents:
                raise ValueError('refusing to purge mounted fixture state')
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError('safe descriptor-based fixture removal is unavailable')

    def purge_state(self, receipt):
        if receipt['status'] != 'purging':
            raise ValueError('fixture state purge requires durable stopped intent')
        file_contract = {
            'ssh-ca': (0, 0o600), 'ssh-ca.pub': (0, 0o644),
            'app.env': (10001, 0o400), 'app.sh': (0, 0o444),
            'db.env': (999, 0o400), 'db.sh': (0, 0o444),
            'tls.env': (101, 0o400), 'tls.sh': (0, 0o444),
            'tls.crt': (0, 0o444), 'tls.key': (101, 0o400), 'nginx.conf': (0, 0o444),
        }
        directory_contract = {'app-data': 10001, 'db-data': 999}
        if self.directory.exists() or self.directory.is_symlink():
            info = os.lstat(self.directory)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError('refusing to purge an invalid fixture state directory')
            entries = list(self.directory.iterdir())
            for path in entries:
                transient = re.fullmatch(r'app\.env\.[0-9a-f]{16}', path.name)
                if path.name not in file_contract and path.name not in directory_contract and not transient:
                    raise ValueError('refusing to purge unexpected fixture state')
                entry = os.lstat(path)
                if entry.st_dev != info.st_dev:
                    raise ValueError('refusing to purge fixture state on another filesystem')
                if path.name in directory_contract:
                    if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid != directory_contract[path.name]
                            or stat.S_IMODE(entry.st_mode) != 0o700):
                        raise ValueError('refusing to purge an invalid fixture data directory')
                else:
                    uid, mode = (10001, 0o400) if transient else file_contract[path.name]
                    actual_mode = stat.S_IMODE(entry.st_mode)
                    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != uid or entry.st_nlink != 1
                            or actual_mode & ~mode):
                        raise ValueError('refusing to purge an invalid fixture input file')
        session = self.state / 'session'
        if session.exists() or session.is_symlink():
            inputs.read_file(session, maximum=8192)
        if self.directory.exists():
            self.refuse_mounted_state()
            shutil.rmtree(self.directory)
        session.unlink(missing_ok=True)
        for path in self.state.iterdir():
            if re.fullmatch(r'manage-receipt\.[0-9a-f]{16}', path.name):
                info = os.lstat(path)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600):
                    raise ValueError('refusing to purge an invalid receipt temporary')
                path.unlink()
        receipt['status'] = 'purged'
        receipt['containers'] = {}
        receipt['files'] = {}
        receipt['guard'] = None
        receipt['context']['network_id'] = None
        self.save(receipt)

    def cleanup(self, *, purge=False):
        with self.lock():
            receipt = self.read()
            if receipt['status'] == 'purged' or receipt['status'] == 'stopped' and not purge:
                return receipt
            if receipt['status'] == 'purging':
                self.purge_state(receipt)
                return receipt
            if receipt['status'] == 'stopped':
                receipt['status'] = 'purging'
                self.save(receipt)
                self.purge_state(receipt)
                return receipt
            docker = self.docker(receipt)
            phase = receipt.get('cleanup_phase')
            if phase not in (None, 'backend'):
                raise ValueError('invalid fixture cleanup phase')
            if phase is None:
                for role in ('tls', 'app', 'db'):
                    docker.remove_owned(role, receipt['containers'].get(role, {}).get('id'))
                if receipt['guard'] is not None:
                    # Cleanup adapter must itself refuse unrelated rules/processes.
                    self.adapter.cleanup(receipt['context'], receipt['guard'])
                elif receipt['context']['network_id'] is not None:
                    # prepare may have died after installing rules but before returning.
                    # A reviewed adapter must use the durable context to recover only
                    # its exact owner, and treat no receipt as partial preparation.
                    self.adapter.cleanup(receipt['context'], None)
                # Persist before deleting the network: the adapter needs it to
                # attest ownership, so retry must not call it after deletion.
                receipt['cleanup_phase'] = 'backend'
                self.save(receipt)
            docker.remove_owned('backend', receipt['context']['network_id'])
            receipt['status'] = 'stopped'
            self.save(receipt)
            if purge:
                receipt['status'] = 'purging'
                self.save(receipt)
                self.purge_state(receipt)
            return receipt
