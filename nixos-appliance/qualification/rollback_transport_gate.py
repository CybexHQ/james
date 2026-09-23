"""Disposable, exact-owner transport fault for the candidate rollback boot.

The first HTTPS connection lets first-boot's network guard finish. Subsequent
connections to the owned Manage endpoint fail, so boot-bound agent contact
cannot make generation-commit healthy. The source boot has no gate.
"""
import ipaddress
import hashlib
import runpy
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
from urllib.parse import urlsplit
import uuid

NFT = '/usr/sbin/nft'
RECEIPT = 'rollback-gate.json'
COMMAND_ENV = {'LC_ALL': 'C', 'PATH': '/run/wrappers/bin:/run/current-system/sw/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}


def command(*args, data=None):
    result = subprocess.run([NFT, *args], input=data, text=True, capture_output=True,
                            env=COMMAND_ENV, check=False)
    if result.returncode:
        raise ValueError('owned rollback transport gate command failed')
    return result.stdout


def name(scope):
    owner = str(uuid.UUID(scope['owner']))
    if owner != scope['owner'] or not re.fullmatch(r'jnq[0-9a-f]{10}', scope['bridge']):
        raise ValueError('invalid rollback transport owner')
    return 'jnqg_' + uuid.UUID(owner).hex[:20]


def addresses(origin):
    parsed = urlsplit(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.port not in (None, 443)
            or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password
            or not (parsed.hostname.startswith('dev.') or parsed.hostname.endswith('.test'))):
        raise ValueError('rollback gate requires the exact development HTTPS origin')
    values = sorted({str(ipaddress.IPv4Address(row[4][0])) for row in
                     socket.getaddrinfo(parsed.hostname, 443, socket.AF_INET, socket.SOCK_STREAM)},
                    key=ipaddress.IPv4Address)
    if not values or len(values) > 8:
        raise ValueError('development origin lacks bounded IPv4 resolution')
    return values


def target(fixture):
    """Select an authenticated endpoint; isolated production never uses public DNS."""
    scope = fixture.scope
    if scope['schema'] == 'cybex.james.nixos-development-scope.v1':
        return {'owner': scope['owner'], 'bridge': scope['bridge'],
                'origin': scope['manage_origin'], 'destinations': addresses(scope['manage_origin']),
                'certificate_sha256': None}
    if scope['schema'] != 'cybex.james.nixos-isolated-scope.v1':
        raise ValueError('rollback gate requires a known owned scope')
    from isolated_manage_rpc import request
    value = request(fixture.state, 'rollback_gate_target')
    if not isinstance(value, dict) or set(value) != {
            'owner', 'bridge', 'origin', 'peer_ipv4', 'certificate_sha256'}:
        raise ValueError('isolated rollback target has unexpected fields')
    peer = str(ipaddress.IPv4Address(value['peer_ipv4']))
    if (any(value[key] != scope[expected] for key, expected in
            (('owner', 'owner'), ('bridge', 'bridge'), ('origin', 'manage_origin')))
            or peer != value['peer_ipv4']
            or peer != str(ipaddress.ip_interface(scope['subnet']).ip)
            or not re.fullmatch(r'[0-9a-f]{64}', value['certificate_sha256'])):
        raise ValueError('isolated rollback target differs from exact owned TLS peer')
    return {'owner': value['owner'], 'bridge': value['bridge'],
            'origin': value['origin'], 'destinations': [peer],
            'certificate_sha256': value['certificate_sha256']}


def specification(scope, tap, mac, guest, destinations):
    table = name(scope)
    if (tap != scope['bridge'] + 'a' or not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac)
            or ipaddress.IPv4Address(guest) not in ipaddress.ip_interface(scope['subnet']).network
            or not destinations or len(destinations) > 8):
        raise ValueError('rollback gate differs from the owned appliance fixture')
    destinations = sorted({str(ipaddress.IPv4Address(value)) for value in destinations},
                          key=ipaddress.IPv4Address)
    mark = int(uuid.UUID(scope['owner']).hex[:8], 16) | 0x80000000
    owned = f'iifname "{scope["bridge"]}" ether saddr {mac}'
    source = f'{owned} ip saddr {guest}'
    match = f'{source} ip daddr {{ {", ".join(destinations)} }} tcp dport 443'
    # conntrack runs at -200. This hook sees the pre-NAT destination and the
    # original guest MAC on the routed bridge packet. The unique table and
    # owner marker cannot match any other fixture or host traffic.
    script = f'''table inet {table} {{
  set admitted {{ type ipv4_addr; flags dynamic; }}
  counter first {{ }}
  counter retained {{ }}
  counter finished {{ }}
  counter blocked {{ }}
  counter blocked_other {{ }}
  chain ingress {{
    type filter hook prerouting priority -150; policy accept;
    {match} ct mark 0x{mark:08x} tcp flags & fin == fin counter name finished accept comment "{scope['owner']}"
    {match} ct mark 0x{mark:08x} counter name retained accept comment "{scope['owner']}"
    {match} ip saddr @admitted counter name blocked drop comment "{scope['owner']}"
    {match} ct state new add @admitted {{ ip saddr }} ct mark set 0x{mark:08x} counter name first accept comment "{scope['owner']}"
    {owned} tcp dport {{ 80, 443 }} counter name blocked_other drop comment "{scope['owner']}"
  }}
}}
'''
    return table, script


def tables():
    return {row['table']['name'] for row in json.loads(command('-j', 'list', 'tables'))['nftables']
            if 'table' in row and row['table']['family'] == 'inet'}


def intent(scope, tap, mac, guest, destinations, script):
    return {'schema': 'cybex.james.rollback-transport-gate.v1', 'owner': scope['owner'],
            'bridge': scope['bridge'], 'table': name(scope),
            'tap': tap, 'mac': mac, 'guest': guest, 'destinations': destinations,
            'script_sha256': hashlib.sha256(script.encode()).hexdigest()}


def save_intent(path, value):
    file = path / RECEIPT
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        body = (json.dumps(value, sort_keys=True) + '\n').encode()
        os.write(fd, body)
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_intent(path, scope):
    fd = os.open(path / RECEIPT, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or not 0 < info.st_size <= 4096):
            raise ValueError('rollback gate receipt is not private and owned')
        value = json.loads(os.read(fd, 4097))
    finally:
        os.close(fd)
    if (value.get('schema') != 'cybex.james.rollback-transport-gate.v1'
            or value.get('owner') != scope['owner'] or value.get('bridge') != scope['bridge']
            or value.get('table') != name(scope)
            or not re.fullmatch(r'[0-9a-f]{64}', value.get('script_sha256', ''))):
        raise ValueError('rollback gate receipt differs from owned scope')
    _, script = specification(scope, value['tap'], value['mac'], value['guest'], value['destinations'])
    if hashlib.sha256(script.encode()).hexdigest() != value['script_sha256']:
        raise ValueError('rollback gate receipt differs from its exact rules')
    return value


def match(left, right, op='=='):
    return {'match': {'op': op, 'left': left, 'right': right}}


def payload(protocol, field):
    return {'payload': {'protocol': protocol, 'field': field}}


def expected_rules(value):
    mark = int(uuid.UUID(value['owner']).hex[:8], 16) | 0x80000000
    destinations = value['destinations']
    owned = [match({'meta': {'key': 'iifname'}}, value['bridge']),
             match(payload('ether', 'saddr'), value['mac'])]
    base = owned + [match(payload('ip', 'saddr'), value['guest'])]
    target = base + [match(payload('ip', 'daddr'), destinations[0] if len(destinations) == 1
                            else {'set': destinations}), match(payload('tcp', 'dport'), 443)]
    marked = target + [match({'ct': {'key': 'mark'}}, mark)]
    return [marked + [match({'&': [payload('tcp', 'flags'), 'fin']}, 'fin'),
                      {'counter': 'finished'}, {'accept': None}],
            marked + [{'counter': 'retained'}, {'accept': None}],
            target + [match(payload('ip', 'saddr'), '@admitted'),
                      {'counter': 'blocked'}, {'drop': None}],
            target + [match({'ct': {'key': 'state'}}, 'new', 'in'),
                      {'set': {'op': 'add', 'elem': payload('ip', 'saddr'), 'set': '@admitted'}},
                      {'mangle': {'key': {'ct': {'key': 'mark'}}, 'value': mark}},
                      {'counter': 'first'}, {'accept': None}],
            owned + [match(payload('tcp', 'dport'), {'set': [80, 443]}),
                    {'counter': 'blocked_other'}, {'drop': None}]]


def inspect(table, value):
    rows = json.loads(command('-j', 'list', 'table', 'inet', table))['nftables']
    kinds = [next(iter(row)) for row in rows if 'metainfo' not in row]
    if (len(kinds) != 13 or kinds.count('table') != 1 or kinds.count('chain') != 1
            or kinds.count('set') != 1 or kinds.count('rule') != 5 or kinds.count('counter') != 5):
        raise ValueError('rollback gate live resources differ from owner specification')
    if any(body.get('family') != 'inet' or body.get('table', table) != table
           for row in rows for kind, body in row.items() if kind != 'metainfo'):
        raise ValueError('rollback gate live table identity changed')
    if any(rule.get('chain') != 'ingress' for row in rows if 'rule' in row for rule in [row['rule']]):
        raise ValueError('rollback gate rule chain changed')
    rules = [row['rule'] for row in rows if 'rule' in row]
    if (any(rule.get('comment') != value['owner'] for rule in rules)
            or [rule.get('expr') for rule in rules] != expected_rules(value)):
        raise ValueError('rollback gate rule ownership changed')
    chain = next(row['chain'] for row in rows if 'chain' in row)
    if (chain.get('name') != 'ingress' or chain.get('hook') != 'prerouting'
            or chain.get('prio') != -150 or chain.get('policy') != 'accept'):
        raise ValueError('rollback gate hook changed')
    dynamic = next(row['set'] for row in rows if 'set' in row)
    if (dynamic.get('name') != 'admitted' or dynamic.get('type') != 'ipv4_addr'
            or dynamic.get('flags') != ['dynamic']
            or any(element != value['guest'] for element in dynamic.get('elem', []))):
        raise ValueError('rollback gate admission set changed')
    counters = [row['counter']['name'] for row in rows if 'counter' in row]
    if set(counters) != {'first', 'retained', 'finished', 'blocked', 'blocked_other'}:
        raise ValueError('rollback gate counters changed')
    return rows


def recover(path, scope):
    file = path / RECEIPT
    table = name(scope)
    if not file.exists():
        if table in tables():
            raise ValueError('rollback gate exists without an ownership receipt')
        return
    value = read_intent(path, scope)
    if table in tables():
        inspect(table, value)
        command('delete', 'table', 'inet', table)
        if table in tables():
            raise ValueError('rollback gate removal is incomplete')
    file.unlink()
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class Gate:
    def __init__(self, fixture, node):
        self.fixture = fixture
        self.scope = fixture.scope
        self.table = name(self.scope)
        self.tap = fixture.tap
        mac = fixture.hardware['mac']
        network = ipaddress.ip_interface(self.scope['subnet']).network
        found = {info['local'] for interface in node['appliance_network']['interfaces']
                 if interface.get('address', '').lower() == mac
                 for info in interface.get('addr_info', [])
                 if info.get('family') == 'inet' and info.get('scope') == 'global'
                 and ipaddress.IPv4Address(info['local']) in network}
        if len(found) != 1:
            raise ValueError('rollback gate requires one reported owned guest IPv4 address')
        self.target = target(fixture)
        self.destinations = self.target['destinations']
        self.guest, self.mac = found.pop(), mac
        self.table, self.script = specification(self.scope, self.tap, mac, self.guest, self.destinations)
        self.path = Path(fixture.state)
        self.active = False

    def install(self):
        # The predecessor can run for minutes before its candidate reset. The
        # retained owner and exact TLS destination must still be authenticated.
        if target(self.fixture) != self.target:
            raise ValueError('rollback target changed before candidate reset')
        if self.table in tables():
            raise ValueError('refusing to adopt existing rollback gate')
        links = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'dev', self.tap],
                                                   text=True, env=COMMAND_ENV))
        if (len(links) != 1 or links[0].get('ifname') != self.tap
                or links[0].get('ifalias') != self.scope['owner']
                or links[0].get('master') != self.scope['bridge']):
            raise ValueError('rollback gate TAP no longer belongs to this fixture')
        scope_module = runpy.run_path(str(Path(__file__).with_name('development-scope.py')))
        observed_scope, _ = scope_module['verify'](
            self.path, self.scope['manage_origin'], self.scope['bridge'])
        if observed_scope != self.scope:
            raise ValueError('rollback scope changed before candidate reset')
        save_intent(self.path, intent(self.scope, self.tap, self.mac, self.guest,
                                      self.destinations, self.script))
        self.active = True
        command('-f', '-', data=self.script)

    def counters(self):
        if not self.active:
            raise ValueError('rollback gate is not installed')
        rows = inspect(self.table, read_intent(self.path, self.scope))
        observed = {row['counter']['name']: row['counter']['packets'] for row in rows if 'counter' in row}
        if set(observed) != {'first', 'retained', 'finished', 'blocked', 'blocked_other'}:
            raise ValueError('rollback gate counters differ from owner specification')
        return observed

    def remove(self):
        if self.active or (self.path / RECEIPT).exists():
            recover(self.path, self.scope)
            self.active = False
