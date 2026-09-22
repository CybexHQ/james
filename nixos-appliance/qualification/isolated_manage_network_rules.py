"""Pure, reviewable nftables command plan for an offline owned fixture.

Only RFC1918 fixture interfaces are matched. No flush, NAT, global policy, or
pre-existing host chain is changed. Drops in this table cannot be overridden by
an accept in Docker/Incus chains; their drops may still prevent connectivity.
"""
import importlib.util
from pathlib import Path

import hashlib
import ipaddress
import json
import re
import uuid
from urllib.parse import urlsplit

_spec = importlib.util.spec_from_file_location('fixture_tls_client_hello', Path(__file__).with_name('tls_client_hello.py'))
egress = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(egress)

FIELDS = {'owner', 'bridge', 'subnet', 'manage_origin', 'peer_ipv4', 'network_id',
          'backend_subnet', 'egress_hosts'}
SCHEMA = 'cybex.james.isolated-manage-network.v1'


def validate(c):
    if not isinstance(c, dict) or set(c) != FIELDS:
        raise ValueError('adapter requires an exact private fixture context')
    egress.hosts(c['egress_hosts'])
    if str(uuid.UUID(c['owner'])) != c['owner'] or not re.fullmatch(r'jnq[0-9a-f]{10}', c['bridge']):
        raise ValueError('invalid fixture owner or bridge')
    if not re.fullmatch(r'[0-9a-f]{64}', c['network_id']):
        raise ValueError('full Docker network identity required')
    origin = urlsplit(c['manage_origin'])
    host = origin.hostname or ''
    if (c['manage_origin'] != 'https://' + host or '.' not in host
            or len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', s) for s in host.split('.'))):
        raise ValueError('canonical exact fixture origin required')
    guest, backend = ipaddress.ip_interface(c['subnet']), ipaddress.ip_network(c['backend_subnet'])
    private = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if (guest.version != 4 or backend.version != 4 or guest.network.prefixlen != 24
            or backend.prefixlen != 28 or str(guest) != c['subnet'] or str(backend) != c['backend_subnet']
            or not all(any(n.subnet_of(p) for p in private) for n in (guest.network, backend))
            or guest.network.overlaps(backend) or str(guest.ip) != c['peer_ipv4']
            or guest.ip in {guest.network.network_address, guest.network.broadcast_address}):
        raise ValueError('invalid disjoint private fixture networks')
    return c


def names(c):
    validate(c)
    return 'jnqm_' + uuid.UUID(c['owner']).hex, 'br-' + c['network_id'][:12]


def dns_config(c):
    validate(c)
    return ('# cybex qualification owner ' + c['owner'] + '\nno-resolv\nno-hosts\nlocal=/#/\n'
            + ''.join('host-record=' + host + ',' + c['peer_ipv4'] + '\n'
                      for host in (urlsplit(c['manage_origin']).hostname, *c['egress_hosts'])))


def match(left, right, op='=='):
    return {'match': {'op': op, 'left': left, 'right': right}}


def meta(key, value):
    return match({'meta': {'key': key}}, value)


def payload(protocol, field, value):
    return match({'payload': {'protocol': protocol, 'field': field}}, value)


def prefix(value):
    network = ipaddress.ip_network(value)
    return {'prefix': {'addr': str(network.network_address), 'len': network.prefixlen}}


def ruleset(c):
    table, backend = names(c)
    guest, peer = c['bridge'], c['peer_ipv4']
    guest_network = prefix(ipaddress.ip_interface(c['subnet']).network)
    backend_network = prefix(c['backend_subnet'])
    backend_gateway = str(ipaddress.ip_network(c['backend_subnet'])[1])
    objects = [{'table': {'family': 'inet', 'name': table, 'comment': c['owner']}}]
    interfaces = {'set': [guest, backend]}
    established = match({'ct': {'key': 'state'}}, {'set': ['established', 'related']})
    def rule(chain, expressions, verdict):
        objects.append({'rule': {'family': 'inet', 'table': table, 'chain': chain,
                                'expr': expressions + [{verdict: None}], 'comment': c['owner']}})
    for chain in ('input', 'forward', 'output'):
        objects.append({'chain': {'family': 'inet', 'table': table, 'name': chain,
                                  'type': 'filter', 'hook': chain, 'prio': -10, 'policy': 'accept'}})
    artifact_endpoints = ((peer, 18082), (backend_gateway, 18081), (backend_gateway, 18083))
    # Self-checks use the same bound address on both ends of the local route.
    # These exact TCP tuples precede source-spoof drops; no other loopback
    # traffic with fixture addresses acquires an exception.
    for address, port in (*artifact_endpoints, (peer, 443)):
        for chain, direction in (('input', 'iifname'), ('output', 'oifname')):
            local = [meta(direction, 'lo'), payload('ip', 'saddr', address),
                     payload('ip', 'daddr', address)]
            rule(chain, local + [payload('tcp', 'dport', port)], 'accept')
            rule(chain, local + [payload('tcp', 'sport', port), established], 'accept')
    # Reject fixture-source addresses arriving anywhere except their exact bridge.
    # Interface-only rules otherwise accept a packet that spoofs an owned address.
    for chain in ('input', 'forward'):
        rule(chain, [payload('ip', 'saddr', guest_network),
                     match({'meta': {'key': 'iifname'}}, guest, '!=')], 'drop')
        rule(chain, [payload('ip', 'saddr', backend_network),
                     match({'meta': {'key': 'iifname'}}, backend, '!=')], 'drop')
    # Host services: exact DNS, DHCP, published TLS, and immutable artifact
    # listeners. Backend manifests/ISOs and guest closures/bundles stay separate.
    for port in (18081, 18083):
        rule('input', [meta('iifname', backend), payload('ip', 'saddr', backend_network),
                       payload('ip', 'daddr', backend_gateway), payload('tcp', 'dport', port)], 'accept')
    rule('input', [meta('iifname', guest), payload('ip', 'saddr', guest_network),
                   payload('ip', 'daddr', peer), payload('tcp', 'dport', 18082)], 'accept')
    # Also exclude unrelated host interfaces from these listeners, even when
    # their source is outside either fixture subnet.
    for address, port in artifact_endpoints:
        rule('input', [payload('ip', 'daddr', address), payload('tcp', 'dport', port)], 'drop')
    for source, source_network in ((guest, guest_network), (backend, backend_network)):
        for protocol in ('tcp', 'udp'):
            rule('input', [meta('iifname', source), payload('ip', 'saddr', source_network),
                           payload('ip', 'daddr', peer), payload(protocol, 'dport', 53)], 'accept')
        rule('input', [meta('iifname', source), payload('ip', 'saddr', source_network), established], 'accept')
    rule('input', [meta('iifname', guest), payload('ip', 'saddr', '0.0.0.0'),
                   payload('udp', 'sport', 68), payload('udp', 'dport', 67)], 'accept')
    rule('input', [meta('iifname', guest), payload('ip', 'saddr', guest_network),
                   payload('udp', 'sport', 68), payload('udp', 'dport', 67)], 'accept')
    rule('input', [meta('iifname', guest), payload('ip', 'saddr', guest_network),
                   payload('ip', 'daddr', peer), payload('tcp', 'dport', 443)], 'accept')
    rule('input', [meta('iifname', interfaces)], 'drop')
    # DNAT is already applied here. Bind its ORIGINAL destination to the owned
    # published TLS listener; containers' port bindings are separately verified.
    rule('forward', [meta('iifname', guest), meta('oifname', backend),
                     payload('ip', 'saddr', guest_network), payload('ip', 'daddr', backend_network),
                     match({'ct': {'key': 'ip daddr', 'dir': 'original'}}, peer),
                     match({'ct': {'key': 'proto-dst', 'dir': 'original'}}, 443),
                     payload('tcp', 'dport', 8443)], 'accept')
    rule('forward', [meta('iifname', backend), meta('oifname', guest),
                     payload('ip', 'saddr', backend_network), payload('ip', 'daddr', guest_network),
                     established], 'accept')
    for interface, network in ((guest, guest_network), (backend, backend_network)):
        rule('forward', [meta('iifname', interface), meta('oifname', interface),
                         payload('ip', 'saddr', network), payload('ip', 'daddr', network),
                         meta('nfproto', 'ipv4')], 'accept')
    rule('forward', [meta('iifname', interfaces)], 'drop')
    rule('forward', [meta('oifname', interfaces)], 'drop')
    # Host DNS/DHCP replies, recovery SSH, and owned TLS proxy traffic. Source
    # drops below prevent DNS or any fixture-address packet escaping externally.
    rule('output', [meta('oifname', guest), payload('ip', 'saddr', peer),
                    payload('ip', 'daddr', guest_network), established], 'accept')
    rule('output', [meta('oifname', backend), payload('ip', 'saddr', peer),
                    payload('ip', 'daddr', backend_network), established], 'accept')
    for port in (18081, 18083):
        rule('output', [meta('oifname', backend), payload('ip', 'saddr', backend_gateway),
                        payload('ip', 'daddr', backend_network), payload('tcp', 'sport', port),
                        established], 'accept')
    rule('output', [meta('oifname', guest), payload('ip', 'saddr', peer),
                    payload('udp', 'sport', 67), payload('udp', 'dport', 68)], 'accept')
    rule('output', [meta('oifname', guest), payload('ip', 'saddr', peer),
                    payload('ip', 'daddr', guest_network), payload('tcp', 'dport', 22)], 'accept')
    rule('output', [meta('oifname', backend), payload('ip', 'saddr', backend_gateway),
                    payload('ip', 'daddr', backend_network), payload('tcp', 'dport', 8443)], 'accept')
    rule('output', [meta('oifname', interfaces)], 'drop')
    rule('output', [payload('ip', 'saddr', guest_network)], 'drop')
    rule('output', [payload('ip', 'saddr', backend_network)], 'drop')
    # Family drops precede exceptions, including conntrack and DHCP.
    for chain, direction in [('input', 'iifname'), ('forward', 'iifname'), ('forward', 'oifname'), ('output', 'oifname')]:
        index = next(i for i, obj in enumerate(objects) if obj.get('rule', {}).get('chain') == chain)
        objects.insert(index, {'rule': {'family': 'inet', 'table': table, 'chain': chain,
                            'expr': [meta(direction, interfaces), meta('nfproto', 'ipv6'), {'drop': None}],
                            'comment': c['owner']}})
    return objects


def plan(c):
    objects = ruleset(c)
    return {'nftables': [{'create' if 'table' in obj else 'add': obj} for obj in objects]}


def receipt(c):
    digest = hashlib.sha256(json.dumps(plan(c), sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'schema': SCHEMA, **c, 'guard_id': digest, 'proxy_url': None}


def normalize(objects):
    result = []
    for obj in objects:
        if 'metainfo' in obj:
            continue
        obj = json.loads(json.dumps(obj))
        for value in obj.values():
            value.pop('handle', None)
        result.append(obj)
    # nft lists each chain immediately followed by its rules.
    return sorted((obj for obj in result if 'rule' not in obj), key=lambda v: json.dumps(v, sort_keys=True)) + sorted((obj for obj in result if 'rule' in obj), key=lambda v: v['rule']['chain'])
