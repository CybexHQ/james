"""Offline-only adapter for isolated_manage.Owner; no executable/automatic entry.

Integration prerequisites: Docker.create must pass --dns <peer_ipv4> explicitly
(and verify HostConfig.Dns); stop all owned VMs before cleanup. Docker's
127.0.0.11 resolver otherwise forwards on the HOST, which bridge firewall rules
cannot confine. Public artifact URLs deliberately fail offline; the Manage
downloader bypasses environment proxies. Do not solve that integration gap by
opening egress or weakening artifact/TLS verification.

Call command_plan(context) for review without privileges or host operations.
prepare installs one atomic nft transaction then pins DNS on the exact owned
Incus bridge. Failure leaves confinement installed for explicit owner cleanup.
verify reads the live rules, network identities, and DNS process/configuration
every time; a JSON receipt is never sufficient. Empty staging attests those
properties but not DNS availability. Every running owned container is queried
through its actual network namespace and bound backend address. No global flush.
This code requires isolated-VM integration qualification before operational use.
"""
import importlib.util
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
from urllib.parse import quote, urlsplit

_spec = importlib.util.spec_from_file_location('isolated_manage_network_rules', Path(__file__).with_name('isolated_manage_network_rules.py'))
rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rules)
LABEL = 'net.cybex.james.qualification.owner'
ROLE = 'net.cybex.james.qualification.role'
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
INCUS_SOCKET = '/var/lib/incus/unix.socket'
DNSMASQ = '/usr/sbin/dnsmasq'


def command(args, *, data=None):
    result = subprocess.run(args, input=data, capture_output=True, check=False,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent', 'LANG': 'C'})
    if result.returncode:
        raise ValueError('fixture network command failed: ' + args[0])
    return result.stdout


def read_owned(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022):
            raise ValueError('DNS process/configuration file ownership changed')
        value = os.read(fd, 65537)
        if len(value) > 65536:
            raise ValueError('DNS configuration exceeds bound')
        return value
    finally:
        os.close(fd)


def _read_proc(path, maximum=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        chunks = []
        size = 0
        while size <= maximum:
            chunk = os.read(fd, maximum + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        value = b''.join(chunks)
        if len(value) > maximum:
            raise ValueError('DNS process metadata exceeds bound')
        return value
    finally:
        os.close(fd)


def _start_time(pid):
    value = _read_proc(f'/proc/{pid}/stat', 4096).decode()
    _, separator, fields = value.rpartition(') ')
    if not separator:
        raise ValueError('invalid DNS process start metadata')
    values = fields.split()
    if len(values) < 20 or not values[19].isdecimal() or int(values[19]) <= 0:
        raise ValueError('invalid DNS process start metadata')
    return int(values[19])


def pin_network_namespace(pid):
    if not isinstance(pid, int) or pid <= 1:
        raise ValueError('invalid container network namespace process')
    start = _start_time(pid)
    fd = os.open(f'/proc/{pid}/ns/net', os.O_RDONLY | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        identity = {'pid': pid, 'start_ticks': start,
                    'netns_dev': info.st_dev, 'netns_ino': info.st_ino}
        if _start_time(pid) != start:
            raise ValueError('container process changed while pinning its network namespace')
        return fd, identity
    except BaseException:
        os.close(fd)
        raise


def network_namespace_identity(pid):
    fd, identity = pin_network_namespace(pid)
    os.close(fd)
    return identity


def _socket_rows(pid, owned):
    rows = []
    for protocol, name in (('tcp', 'tcp'), ('udp', 'udp'), ('tcp6', 'tcp6'), ('udp6', 'udp6')):
        content = _read_proc(f'/proc/{pid}/net/{name}').decode().splitlines()
        for line in content[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[9] not in owned:
                continue
            encoded, encoded_port = fields[1].split(':')
            port = int(encoded_port, 16)
            if protocol.endswith('6'):
                address = encoded
            else:
                address = socket.inet_ntoa(bytes.fromhex(encoded)[::-1])
            rows.append((protocol, address, port, fields[3]))
    return sorted(rows)


def inspect_dns_process(pid):
    if not isinstance(pid, int) or pid <= 1:
        raise ValueError('invalid owned DNS process')
    start = _start_time(pid)
    expected = os.open(DNSMASQ, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    actual = os.open(f'/proc/{pid}/exe', os.O_RDONLY | os.O_CLOEXEC)
    try:
        expected_info, actual_info = os.fstat(expected), os.fstat(actual)
        if (not stat.S_ISREG(expected_info.st_mode) or expected_info.st_uid != 0
                or expected_info.st_mode & 0o022
                or (expected_info.st_dev, expected_info.st_ino) != (actual_info.st_dev, actual_info.st_ino)):
            raise ValueError('DNS process executable differs from the root-owned dnsmasq binary')
        executable = [actual_info.st_dev, actual_info.st_ino]
    finally:
        os.close(actual)
        os.close(expected)
    argv = _read_proc(f'/proc/{pid}/cmdline').decode().rstrip('\0').split('\0')
    owned = set()
    for entry in os.scandir(f'/proc/{pid}/fd'):
        try:
            target = os.readlink(entry.path)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r'socket:\[([0-9]+)\]', target)
        if match:
            owned.add(match.group(1))
    sockets = _socket_rows(pid, owned)
    if _start_time(pid) != start:
        raise ValueError('DNS process changed during inspection')
    return {'pid': pid, 'start_time': start, 'executable': executable,
            'argv': argv, 'sockets': sockets}


def _dnsmasq_argv(c):
    """Return Debian Incus 6.0.4's argv for the exact owned bridge config."""
    rules.validate(c)
    directory = '/var/lib/incus/networks/' + c['bridge']
    subnet = ipaddress.ip_interface(c['subnet']).network
    return [
        'dnsmasq', '--keep-in-foreground', '--strict-order', '--bind-interfaces',
        '--except-interface=lo', '--pid-file=', '--no-ping',
        '--interface=' + c['bridge'], '--dhcp-rapid-commit', '--no-negcache',
        '--quiet-dhcp', '--quiet-dhcp6', '--quiet-ra',
        '--listen-address=' + c['peer_ipv4'], '--dhcp-no-override',
        '--dhcp-authoritative', '--dhcp-leasefile=' + directory + '/dnsmasq.leases',
        '--dhcp-hostsfile=' + directory + '/dnsmasq.hosts', '--dhcp-range',
        f'{subnet[2]},{subnet[-2]},1h', '-s', 'incus', '--interface-name',
        '_gateway.incus,' + c['bridge'], '-S', '/incus/',
        '--conf-file=' + directory + '/dnsmasq.raw', '-u', 'nobody', '-g', 'incus',
    ]


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=10)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class IncusAPI:
    def __init__(self, path=INCUS_SOCKET):
        self.path = path

    def _request(self, method, path, body=None, etag=None):
        info = os.lstat(self.path)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o002:
            raise ValueError('Incus control socket is not root-owned and private')
        connection = _UnixHTTPConnection(self.path)
        connection.connect()
        try:
            peer_pid, peer_uid, _ = struct.unpack('3i', connection.sock.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            # Socket activation retains systemd's PID 1 peer credentials even
            # after Incus inherits the listener. Root ownership remains required.
            if peer_uid != 0 or peer_pid < 1:
                raise ValueError('Incus control peer is not the root daemon')
            headers = {'Accept': 'application/json'}
            encoded = None
            if body is not None:
                encoded = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
                headers['Content-Type'] = 'application/json'
            if etag is not None:
                headers['If-Match'] = etag
            connection.request(method, path, body=encoded, headers=headers)
            response = connection.getresponse()
            content = response.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024 or response.status != 200:
                raise ValueError('Incus compare-and-swap request failed')
            value = json.loads(content)
            if value.get('type') != 'sync' or value.get('status_code') != 200:
                raise ValueError('Incus compare-and-swap response is invalid')
            return value.get('metadata'), response.getheader('ETag')
        finally:
            connection.close()

    def get(self, name):
        metadata, etag = self._request('GET', '/1.0/networks/' + quote(name, safe='') + '?project=default')
        if not isinstance(metadata, dict) or not etag:
            raise ValueError('Incus network response lacks an exact revision')
        return metadata, etag

    def replace_config(self, network, etag, config):
        body = {'description': network.get('description', ''), 'config': config}
        self._request('PUT', '/1.0/networks/' + quote(network['name'], safe='') + '?project=default',
                      body=body, etag=etag)


def command_plan(context):
    table, _ = rules.names(context)
    return {'prepare': [{'argv': ['nft', '-j', '-f', '-'], 'stdin': rules.plan(context)},
                        {'incus_put_if_match': {'network': context['bridge'],
                                                'raw.dnsmasq': rules.dns_config(context)}}],
            'cleanup': [{'incus_put_if_match': {'network': context['bridge'], 'unset': 'raw.dnsmasq'}},
                        ['nft', 'delete', 'table', 'inet', 'handle', '<verified-handle>']],
            'table': table}


class Adapter:
    def __init__(self, *, run=command, read=read_owned, incus=None,
                 process=inspect_dns_process, namespace=pin_network_namespace,
                 current_namespace=network_namespace_identity):
        self.run, self.read = run, read
        self.incus = incus or IncusAPI()
        self.process = process
        self.namespace, self.current_namespace = namespace, current_namespace

    def networks(self, c):
        rules.validate(c)
        incus, etag = self.incus.get(c['bridge'])
        cfg = incus.get('config', {})
        expected_config = {
            'user.cybex.nixos-qualification': c['owner'],
            'ipv4.address': c['subnet'],
            'ipv4.nat': 'true',
            'ipv6.address': 'none',
        }
        if isinstance(cfg, dict) and 'raw.dnsmasq' in cfg:
            expected_config['raw.dnsmasq'] = cfg['raw.dnsmasq']
        if (incus.get('name') != c['bridge'] or incus.get('type') != 'bridge' or not incus.get('managed')
                or cfg != expected_config or incus.get('used_by')):
            raise ValueError('guest network is not the exact owned fixture')
        docker = json.loads(self.run(DOCKER + ['network', 'inspect', c['network_id']]))[0]
        gateway = str(ipaddress.ip_network(c['backend_subnet'])[1])
        if (docker.get('Id') != c['network_id'] or docker.get('Name') != 'jnqm-' + c['owner'].replace('-', '') + '-backend'
                or docker.get('Driver') != 'bridge' or docker.get('Internal') is not True
                or docker.get('EnableIPv6') or docker.get('Options')
                or docker.get('Labels', {}).get(LABEL) != c['owner']
                or docker.get('Labels', {}).get(ROLE) != 'backend'
                or docker.get('IPAM', {}).get('Config') != [{'Subnet': c['backend_subnet'], 'Gateway': gateway}]):
            raise ValueError('backend network is not the exact owned internal fixture')
        # Match the actual bridge and address, not only Docker's naming convention.
        bridge = rules.names(c)[1]

        self.check_routes(c, json.loads(self.run(['ip', '-j', '-4', 'route', 'show'])))
        actual = json.loads(self.run(['ip', '-d', '-j', 'address', 'show', 'dev', bridge]))
        if (len(actual) != 1 or actual[0].get('ifname') != bridge
                or actual[0].get('linkinfo', {}).get('info_kind') != 'bridge'
                or [(entry.get('local'), entry.get('prefixlen'), entry.get('scope'))
                    for entry in actual[0].get('addr_info', []) if entry.get('family') == 'inet']
                != [(gateway, 28, 'global')]):
            raise ValueError('backend bridge or gateway differs from the actual owned network')
        links = json.loads(self.run(['ip', '-j', 'link', 'show', 'master', c['bridge']]))
        if any(link.get('ifalias') != c['owner'] or link.get('ifname') not in {c['bridge'] + 'a', c['bridge'] + 'w'} for link in links):
            raise ValueError('guest bridge has an unowned attachment')
        return incus, docker, links, etag

    @staticmethod
    def check_routes(c, routes):
        bridge = rules.names(c)[1]
        gateway = str(ipaddress.ip_network(c['backend_subnet'])[1])
        expected_routes = {
            ipaddress.ip_interface(c['subnet']).network:
                (c['bridge'], c['peer_ipv4']),
            ipaddress.ip_network(c['backend_subnet']):
                (bridge, gateway),
        }
        seen_routes = set()
        for route in routes:
            if route.get('dst') in (None, 'default'):
                continue
            destination = ipaddress.ip_network(route['dst'], strict=False)
            for owned, (device, source) in expected_routes.items():
                if destination.overlaps(owned):
                    if (destination != owned or route.get('dev') != device
                            or route.get('protocol') != 'kernel' or route.get('scope') != 'link'
                            or route.get('prefsrc') != source):
                        raise ValueError('owned fixture network overlaps a changed host route')
                    seen_routes.add(owned)
        if seen_routes != set(expected_routes):
            raise ValueError('owned fixture connected route is missing')

    def containers(self, c, backend):
        observed = set()
        containers = []
        ids = self.run(DOCKER + ['container', 'ls', '-a', '--filter', 'label=' + LABEL + '=' + c['owner'], '--format', '{{.ID}}']).decode().splitlines()
        for identity in ids:
            v = json.loads(self.run(DOCKER + ['container', 'inspect', identity]))[0]
            observed.add(v['Id'])
            containers.append(v)
            h, cfg = v['HostConfig'], v['Config']
            role = cfg.get('Labels', {}).get(ROLE)
            attached = list(v.get('NetworkSettings', {}).get('Networks', {}).values())
            allowed_networks = {c['network_id']}
            if v.get('State', {}).get('Status') == 'created':
                allowed_networks.add('')
            if (cfg.get('Labels', {}).get(LABEL) != c['owner'] or role not in {'app', 'db', 'tls'}
                    or h.get('Dns') != [c['peer_ipv4']] or h.get('DnsSearch') not in ([], None)
                    or h.get('NetworkMode') != c['network_id'] or h.get('Privileged')
                    or h.get('CapAdd') or h.get('CapDrop') != ['ALL']
                    or len(attached) != 1 or attached[0].get('NetworkID') not in allowed_networks
                    or h.get('LogConfig') != {'Type': 'local', 'Config': {'max-size': '10m', 'max-file': '2'}}):
                raise ValueError('container lacks explicit owned DNS or confinement')
            expected = {'8443/tcp': [{'HostIp': c['peer_ipv4'], 'HostPort': '443'}]} if role == 'tls' else {}
            if (h.get('PortBindings') or {}) != expected:
                raise ValueError('container publication differs from the owned TLS peer')
            if v.get('State', {}).get('Running') is True:
                self.container_ipv4(c, v)
        if set(backend.get('Containers') or {}) - observed:
            raise ValueError('backend contains an unowned container attachment')
        return containers

    @staticmethod
    def container_ipv4(c, container):
        attached = list(container.get('NetworkSettings', {}).get('Networks', {}).values())
        value = attached[0].get('IPAddress') if len(attached) == 1 else None
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError('running owned container lacks an exact backend address') from error
        subnet = ipaddress.ip_network(c['backend_subnet'])
        if (address.version != 4 or address not in subnet
                or address in {subnet.network_address, subnet.broadcast_address, subnet[1]}):
            raise ValueError('running owned container lacks an exact backend address')
        return str(address)

    def table(self, c):
        name, _ = rules.names(c)
        tables = json.loads(self.run(['nft', '-j', 'list', 'tables']))['nftables']
        if not any(t.get('table', {}).get('family') == 'inet' and t['table'].get('name') == name for t in tables):
            return None
        return json.loads(self.run(['nft', '-j', 'list', 'table', 'inet', name]))['nftables']

    @staticmethod
    def check_table(c, observed):
        if observed is None or rules.normalize(observed) != rules.normalize(rules.ruleset(c)):
            raise ValueError('actual nft confinement differs from the exact owned command plan')

    def probe_dns(self, c, prefix, source):
        host = urlsplit(c['manage_origin']).hostname
        base = [*prefix, 'dig', '-b', source]
        answer = self.run(base + ['@' + c['peer_ipv4'], host, 'A', '+short',
                                  '+time=1', '+tries=1']).decode().splitlines()
        blocked = self.run(base + ['@' + c['peer_ipv4'], c['owner'] + '.invalid', 'A',
                                   '+comments', '+time=1', '+tries=1']).decode()
        if answer != [c['peer_ipv4']] or 'status: NXDOMAIN,' not in blocked:
            raise ValueError('live DNS does not enforce the pinned offline origin')

    def attach_dns_route(self, context, identity):
        """Give one owned internal container a host route to the private DNS peer."""
        c = dict(context)
        _, backend, _, _ = self.networks(c)
        self.check_table(c, self.table(c))
        selected = [v for v in self.containers(c, backend) if v['Id'] == identity]
        if len(selected) != 1 or selected[0].get('State', {}).get('Running') is not True:
            raise ValueError('DNS route requires an exact running owned container')
        container = selected[0]
        pid = container['State']['Pid']
        source = self.container_ipv4(c, container)
        fd, namespace = self.namespace(pid)
        try:
            pinned = os.fstat(fd)
            if (namespace.get('pid') != pid or self.current_namespace(pid) != namespace
                    or (namespace['netns_dev'], namespace['netns_ino']) != (pinned.st_dev, pinned.st_ino)):
                raise ValueError('container namespace changed before private DNS routing')
            prefix = ['nsenter', '--net=' + f'/proc/{os.getpid()}/fd/{fd}', '--']
            routes = json.loads(self.run(prefix + ['ip', '-j', '-4', 'route', 'show']))
            if (len(routes) != 1 or routes[0].get('dst') != c['backend_subnet']
                    or routes[0].get('dev') != 'eth0' or routes[0].get('scope') != 'link'
                    or routes[0].get('prefsrc') != source or routes[0].get('gateway')):
                raise ValueError('new internal container has unexpected routes')
            gateway = str(ipaddress.ip_network(c['backend_subnet'])[1])
            self.run(prefix + ['ip', 'route', 'add', c['peer_ipv4'] + '/32', 'via', gateway, 'dev', 'eth0'])
            if self.current_namespace(pid) != namespace:
                raise ValueError('container namespace changed during private DNS routing')
        finally:
            os.close(fd)

    def dns(self, c, network, containers):
        expected = rules.dns_config(c)
        if network['config'].get('raw.dnsmasq') != expected:
            raise ValueError('owned DNS pin changed')
        directory = '/var/lib/incus/networks/' + c['bridge']
        # Incus writes an additional newline around the exact raw.dnsmasq value.
        if self.read(directory + '/dnsmasq.raw').decode() != expected + '\n':
            raise ValueError('DNS daemon configuration differs from the owned pin')
        saved = self.read(directory + '/dnsmasq.pid').decode()
        values = re.findall(r'^pid:\s*([0-9]+)\s*$', saved, re.MULTILINE)
        names = re.findall(r'^name:\s*([^\s]+)\s*$', saved, re.MULTILINE)
        if len(values) != 1 or int(values[0]) <= 1 or names != ['dnsmasq']:
            raise ValueError('invalid owned DNS process')
        identity = self.process(int(values[0]))
        argv = identity.get('argv', [])
        executable = identity.get('executable', [])
        if (identity.get('pid') != int(values[0]) or not isinstance(identity.get('start_time'), int)
                or identity['start_time'] <= 0 or len(executable) != 2
                or any(not isinstance(value, int) or value <= 0 for value in executable)
                or argv != _dnsmasq_argv(c)):
            raise ValueError('DNS process does not use only owned offline configuration')
        port53 = {(protocol, address, port, state) for protocol, address, port, state
                  in identity.get('sockets', []) if port == 53}
        if port53 != {('tcp', c['peer_ipv4'], 53, '0A'), ('udp', c['peer_ipv4'], 53, '07')}:
            raise ValueError('DNS process is not bound only to the owned IPv4 listener')
        for container in containers:
            state = container.get('State', {})
            if state.get('Running') is True:
                pid = state.get('Pid')
                started = state.get('StartedAt')
                if (not isinstance(pid, int) or pid <= 1 or not isinstance(started, str)
                        or not started or started.startswith('0001-')):
                    raise ValueError('running owned container lacks a network namespace process')
                source = self.container_ipv4(c, container)
                namespace_fd, namespace = self.namespace(pid)
                try:
                    if namespace.get('pid') != pid:
                        raise ValueError('owned container changed during DNS namespace probe')
                    namespace_path = f'/proc/{os.getpid()}/fd/{namespace_fd}'
                    self.probe_dns(c, ('nsenter', '--net=' + namespace_path, '--'), source)
                    current = json.loads(self.run(
                        DOCKER + ['container', 'inspect', container['Id']]))[0]
                    current_state = current.get('State', {})
                    current_networks = list(
                        current.get('NetworkSettings', {}).get('Networks', {}).values())
                    current_namespace = self.current_namespace(pid)
                    pinned_info = os.fstat(namespace_fd)
                    if (current.get('Id') != container['Id']
                            or current_state.get('Running') is not True
                            or current_state.get('Pid') != pid
                            or current_state.get('StartedAt') != started
                            or len(current_networks) != 1
                            or current_networks[0].get('NetworkID') != c['network_id']
                            or self.container_ipv4(c, current) != source
                            or current_namespace != namespace
                            or (pinned_info.st_dev, pinned_info.st_ino)
                            != (namespace['netns_dev'], namespace['netns_ino'])):
                        raise ValueError('owned container changed during DNS namespace probe')
                finally:
                    os.close(namespace_fd)

    def prepare(self, context):
        c = dict(context)
        guest, backend, links, etag = self.networks(c)
        containers = self.containers(c, backend)
        if containers or guest.get('used_by') or links or backend.get('Containers') or guest['config'].get('raw.dnsmasq'):
            raise ValueError('prepare requires empty new networks and no existing DNS customization')
        if self.table(c) is not None:
            raise ValueError('refusing to adopt an existing firewall table')
        self.run(['nft', '-j', '-f', '-'], data=json.dumps(rules.plan(c)).encode())
        # Atomic creation is first: DNS restart failure never removes confinement.
        self.check_table(c, self.table(c))
        config = dict(guest['config'])
        config['raw.dnsmasq'] = rules.dns_config(c)
        self.incus.replace_config(guest, etag, config)
        receipt = rules.receipt(c)
        self.verify(c, receipt)
        return receipt

    def verify(self, context, receipt):
        c = dict(context)
        if receipt != rules.receipt(c):
            raise ValueError('network receipt does not bind the exact offline fixture')
        guest, backend, _, _ = self.networks(c)
        self.check_table(c, self.table(c))
        containers = self.containers(c, backend)
        self.dns(c, guest, containers)
        return True

    def cleanup(self, context, receipt):
        c = dict(context)
        if receipt is not None and receipt != rules.receipt(c):
            raise ValueError('cleanup receipt differs from the exact owner context')
        guest, backend, links, etag = self.networks(c)
        if guest.get('used_by') or links or backend.get('Containers'):
            raise ValueError('stop and detach all fixture clients before removing confinement')
        actual = self.table(c)
        if actual is not None:
            self.check_table(c, actual)
            table = [item['table'] for item in actual if 'table' in item]
            if (len(table) != 1 or not isinstance(table[0].get('handle'), int)
                    or table[0]['handle'] <= 0):
                raise ValueError('owned nft table lacks an immutable deletion handle')
            handle = table[0]['handle']
        raw = guest['config'].get('raw.dnsmasq')
        if raw not in (None, '', rules.dns_config(c)):
            raise ValueError('refusing to alter replaced DNS configuration')
        # All ownership checks precede ALL cleanup mutations. Removing DNS while
        # guests are detached cannot re-enable fixture traffic. A failure retains
        # firewall confinement; no exception is swallowed.
        if raw:
            config = dict(guest['config'])
            del config['raw.dnsmasq']
            self.incus.replace_config(guest, etag, config)
        if actual is not None:
            self.run(['nft', 'delete', 'table', 'inet', 'handle', str(handle)])
        return True
