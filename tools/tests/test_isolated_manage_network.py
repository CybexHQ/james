"""Offline command-model tests; never execute host firewall/Docker/Incus commands."""
import copy
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import stat
import struct

PATH = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification/isolated_manage_network.py'
spec = importlib.util.spec_from_file_location('network_adapter_tests', PATH)
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
rules = network.rules


def context():
    return {'owner': '20dcb130-736e-4d79-b8d2-338781735419', 'bridge': 'jnq0123456789',
            'subnet': '10.99.16.1/24', 'manage_origin': 'https://dev.example.test',
            'peer_ipv4': '10.99.16.1', 'network_id': 'a' * 64,
            'backend_subnet': '10.99.17.0/28', 'egress_hosts': []}


def running_container(c, identity='b' * 64, pid=4321, address='10.99.17.2'):
    return {'Id': identity, 'State': {'Status': 'running', 'Running': True, 'Pid': pid,
                                      'StartedAt': '2026-09-21T12:00:00.000000000Z'},
            'Config': {'Labels': {network.LABEL: c['owner'], network.ROLE: 'app'}},
            'HostConfig': {'Dns': [c['peer_ipv4']], 'NetworkMode': c['network_id'],
                           'CapDrop': ['ALL'], 'LogConfig': {'Type': 'local', 'Config': {
                               'max-size': '10m', 'max-file': '2'}}},
            'NetworkSettings': {'Networks': {'backend': {
                'NetworkID': c['network_id'], 'IPAddress': address}}}}


class Host:
    def __init__(self):
        self.c = context()
        self.commands = []
        self.live = None
        self.fail_dns = False
        self.replace_incus_before_put = False
        self.replace_nft_before_delete = False
        self.incus_version = 1
        self.links = []
        self.containers = []
        self.guest = {'name': self.c['bridge'], 'description': '', 'type': 'bridge', 'managed': True, 'used_by': [],
                      'config': {'user.cybex.nixos-qualification': self.c['owner'],
                                 'ipv4.address': self.c['subnet'], 'ipv4.nat': 'true', 'ipv6.address': 'none'}}
        self.backend = {'Id': self.c['network_id'], 'Name': 'jnqm-' + self.c['owner'].replace('-', '') + '-backend',
                        'Driver': 'bridge', 'Internal': True, 'EnableIPv6': False,
                        'Labels': {network.LABEL: self.c['owner'], network.ROLE: 'backend'},
                        'IPAM': {'Config': [{'Subnet': self.c['backend_subnet'], 'Gateway': '10.99.17.1'}]}, 'Containers': {}}
        self.backend_bridge = [{'ifname': rules.names(self.c)[1], 'linkinfo': {'info_kind': 'bridge'},
                                'addr_info': [{'family': 'inet', 'local': '10.99.17.1', 'prefixlen': 28, 'scope': 'global'}]}]
        self.routes = [
            {'dst': 'default', 'gateway': '192.0.2.1', 'dev': 'external'},
            {'dst': '10.99.16.0/24', 'dev': self.c['bridge'], 'protocol': 'kernel',
             'scope': 'link', 'prefsrc': self.c['peer_ipv4']},
            {'dst': self.c['backend_subnet'], 'dev': rules.names(self.c)[1], 'protocol': 'kernel',
             'scope': 'link', 'prefsrc': '10.99.17.1'},
        ]
        self.dns_identity = {
            'pid': 1234, 'start_time': 99, 'executable': [1, 2],
            'argv': network._dnsmasq_argv(self.c),
            'sockets': [('tcp', self.c['peer_ipv4'], 53, '0A'),
                        ('udp', self.c['peer_ipv4'], 53, '07')],
        }
        self.namespace_identity = {'pid': 4321, 'start_ticks': 100,
                                   'netns_dev': 4, 'netns_ino': 5}
        self.adapter = network.Adapter(run=self.run, read=self.read, incus=self,
                                       process=lambda pid: copy.deepcopy(self.dns_identity),
                                       namespace=self.pin_namespace,
                                       current_namespace=lambda pid: copy.deepcopy(
                                           self.namespace_identity | {'pid': pid}))

    def pin_namespace(self, pid):
        fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        info = os.fstat(fd)
        identity = copy.deepcopy(self.namespace_identity | {'pid': pid,
                                                             'netns_dev': info.st_dev,
                                                             'netns_ino': info.st_ino})
        self.namespace_identity = copy.deepcopy(identity)
        return fd, identity

    @staticmethod
    def with_handles(objects, table_handle=100):
        value = copy.deepcopy(objects)
        for index, item in enumerate(value, 1):
            next(iter(item.values()))['handle'] = table_handle if 'table' in item else table_handle + index
        return value

    def get(self, name):
        self.commands.append((['incus-get', name], None))
        if name != self.guest['name']:
            raise ValueError('wrong network')
        return copy.deepcopy(self.guest), 'etag-' + str(self.incus_version)

    def replace_config(self, network, etag, config):
        self.commands.append((['incus-cas', network['name'], etag], copy.deepcopy(config)))
        if self.replace_incus_before_put:
            self.replace_incus_before_put = False
            self.guest['config']['user.cybex.nixos-qualification'] = 'foreign'
            self.incus_version += 1
        if etag != 'etag-' + str(self.incus_version):
            raise ValueError('Incus compare-and-swap request failed')
        if self.fail_dns and 'raw.dnsmasq' in config:
            raise ValueError('DNS restart failed')
        self.guest['config'] = copy.deepcopy(config)
        self.incus_version += 1

    def run(self, args, *, data=None):
        self.commands.append((args, data))
        if args[:4] == ['ip', '-d', '-j', 'address']:
            value = self.backend_bridge
        elif args == ['ip', '-j', '-4', 'route', 'show']:
            value = self.routes
        elif args[:3] == ['ip', '-j', 'link']:
            value = self.links
        elif args[:3] == network.DOCKER:
            if args[3:5] == ['network', 'inspect']:
                value = [self.backend]
            elif args[3:5] == ['container', 'ls']:
                return '\n'.join(str(i) for i in range(len(self.containers))).encode()
            elif args[3:5] == ['container', 'inspect']:
                identity = args[-1]
                if identity.isdecimal():
                    value = [self.containers[int(identity)]]
                else:
                    value = [next(item for item in self.containers if item['Id'] == identity)]
            else:
                raise AssertionError(args)
        elif args == ['nft', '-j', 'list', 'tables']:
            value = {'nftables': [] if self.live is None else [self.live[0]]}
        elif args[:4] == ['nft', '-j', 'list', 'table']:
            value = {'nftables': self.live}
        elif args == ['nft', '-j', '-f', '-']:
            if self.live is not None:
                raise ValueError('exclusive create collision')
            self.live = self.with_handles([next(iter(v.values())) for v in json.loads(data)['nftables']])
            return b''
        elif args[:3] == ['nft', 'delete', 'table']:
            if self.replace_nft_before_delete:
                self.replace_nft_before_delete = False
                self.live = self.with_handles(rules.ruleset(self.c), 500)
            if args != ['nft', 'delete', 'table', 'inet', 'handle', str(self.live[0]['table']['handle'])]:
                raise ValueError('nft handle no longer exists')
            self.live = None
            return b''
        elif 'dig' in args:
            return (b'status: NXDOMAIN,' if any(arg.endswith('.invalid') for arg in args)
                    else self.c['peer_ipv4'].encode() + b'\n')
        else:
            raise AssertionError(args)
        return json.dumps(value).encode()

    def read(self, path):
        if path.endswith('dnsmasq.raw'):
            return (rules.dns_config(self.c) + '\n').encode()
        if path.endswith('dnsmasq.pid'):
            return b'name: dnsmasq\npid: 1234\nuid: 0\ngid: 0\n'
        raise AssertionError(path)

    def mutations(self):
        return [args for args, _ in self.commands if args[:1] == ['incus-cas']
                or args[:3] == ['nft', 'delete', 'table']
                or args == ['nft', '-j', '-f', '-']]


class Tests(unittest.TestCase):
    def test_private_dns_route_is_limited_to_owned_container_and_peer(self):
        for foreign_route in (False, True):
            with self.subTest(foreign_route=foreign_route):
                host = Host()
                host.adapter.prepare(host.c)
                container = running_container(host.c)
                host.containers.append(container)
                host.backend['Containers'][container['Id']] = {}
                run = host.adapter.run
                added = []
                def commands(args, **options):
                    if args[0] == 'nsenter' and args[3:] == ['ip', '-j', '-4', 'route', 'show']:
                        return json.dumps([{'dst': 'default' if foreign_route else host.c['backend_subnet'],
                                            'dev': 'eth0', 'scope': 'link', 'prefsrc': '10.99.17.2'}]).encode()
                    if args[0] == 'nsenter' and args[3:6] == ['ip', 'route', 'add']:
                        added.append(args[3:])
                        return b''
                    return run(args, **options)
                host.adapter.run = commands
                if foreign_route:
                    with self.assertRaisesRegex(ValueError, 'unexpected routes'):
                        host.adapter.attach_dns_route(host.c, container['Id'])
                    self.assertEqual(added, [])
                else:
                    host.adapter.attach_dns_route(host.c, container['Id'])
                    self.assertEqual(added, [['ip', 'route', 'add', '10.99.16.1/32',
                                             'via', '10.99.17.1', 'dev', 'eth0']])
                with self.assertRaisesRegex(ValueError, 'exact running owned container'):
                    host.adapter.attach_dns_route(host.c, 'f' * 64)

    def test_proc_reads_consume_short_chunks_and_enforce_bound(self):
        for chunks, maximum, expected in (([b'first', b'second', b''], 20, b'firstsecond'),
                                         ([b'first', b'second'], 10, None)):
            with self.subTest(maximum=maximum), patch.object(network.os, 'open', return_value=12), \
                    patch.object(network.os, 'read', side_effect=chunks), \
                    patch.object(network.os, 'close') as close:
                if expected is None:
                    with self.assertRaisesRegex(ValueError, 'exceeds bound'):
                        network._read_proc('/proc/test/net/tcp', maximum)
                else:
                    self.assertEqual(network._read_proc('/proc/test/net/tcp', maximum), expected)
                close.assert_called_once_with(12)

    def test_incus_accepts_root_socket_activation_and_rejects_foreign_peers(self):
        for pid, uid, allowed in ((1, 0, True), (123, 0, True), (0, 0, False), (123, 1000, False)):
            with self.subTest(pid=pid, uid=uid):
                connection = Mock()
                connection.sock.getsockopt.return_value = struct.pack('3i', pid, uid, 0)
                response = connection.getresponse.return_value
                response.status = 200
                response.read.return_value = b'{"type":"sync","status_code":200,"metadata":{}}'
                with patch.object(network.os, 'lstat', return_value=Mock(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)), \
                        patch.object(network, '_UnixHTTPConnection', return_value=connection):
                    if allowed:
                        network.IncusAPI().get('fixture')
                        connection.request.assert_called_once()
                    else:
                        with self.assertRaisesRegex(ValueError, 'root daemon'):
                            network.IncusAPI().get('fixture')
                        connection.request.assert_not_called()
                connection.close.assert_called_once()

    def test_plan_is_pure_scoped_and_has_no_global_flush_or_proxy(self):
        c = context()
        plan = network.command_plan(c)
        self.assertEqual(list(plan['prepare'][0]['stdin']['nftables'][0]), ['create'])
        self.assertNotIn('flush', json.dumps(plan))
        self.assertIsNone(rules.receipt(c)['proxy_url'])
        self.assertEqual(plan['cleanup'][-1], ['nft', 'delete', 'table', 'inet', 'handle', '<verified-handle>'])
        self.assertIn('local=/#/', rules.dns_config(c))
        self.assertIn('host-record=dev.example.test,10.99.16.1', rules.dns_config(c))

    def test_dns_argv_matches_pinned_debian_incus_604_contract(self):
        c = context()
        directory = '/var/lib/incus/networks/' + c['bridge']
        self.assertEqual(network._dnsmasq_argv(c), [
            'dnsmasq', '--keep-in-foreground', '--strict-order', '--bind-interfaces',
            '--except-interface=lo', '--pid-file=', '--no-ping',
            '--interface=' + c['bridge'], '--dhcp-rapid-commit', '--no-negcache',
            '--quiet-dhcp', '--quiet-dhcp6', '--quiet-ra',
            '--listen-address=' + c['peer_ipv4'], '--dhcp-no-override',
            '--dhcp-authoritative', '--dhcp-leasefile=' + directory + '/dnsmasq.leases',
            '--dhcp-hostsfile=' + directory + '/dnsmasq.hosts', '--dhcp-range',
            '10.99.16.2,10.99.16.254,1h', '-s', 'incus', '--interface-name',
            '_gateway.incus,' + c['bridge'], '-S', '/incus/',
            '--conf-file=' + directory + '/dnsmasq.raw', '-u', 'nobody', '-g', 'incus',
        ])

    def test_prepare_verify_cleanup_roundtrip_and_idempotent_partial_cleanup(self):
        h = Host()
        receipt = h.adapter.prepare(h.c)
        self.assertTrue(h.adapter.verify(h.c, receipt))
        self.assertTrue(h.adapter.cleanup(h.c, receipt))
        self.assertIsNone(h.live)
        self.assertNotIn('raw.dnsmasq', h.guest['config'])
        count = len(h.mutations())
        self.assertTrue(h.adapter.cleanup(h.c, None))
        self.assertEqual(len(h.mutations()), count)

    def test_incus_uses_etag_compare_and_swap_and_bad_receipt_never_mutates(self):
        h = Host()
        receipt = h.adapter.prepare(h.c)
        self.assertIn((['incus-cas', h.c['bridge'], 'etag-1'],
                       h.guest['config']), h.commands)
        h.commands.clear()
        for method in (h.adapter.verify, h.adapter.cleanup):
            with self.assertRaises(ValueError):
                method(h.c, receipt | {'guard_id': 'forged'})
        self.assertEqual(h.commands, [])

    def test_backend_foreign_attachment_and_wrong_dns_response_fail_verification(self):
        h = Host()
        receipt = h.adapter.prepare(h.c)
        h.backend['Containers']['foreign'] = {}
        with self.assertRaisesRegex(ValueError, 'unowned container'):
            h.adapter.verify(h.c, receipt)
        h.backend['Containers'].clear()
        identity = 'b' * 64
        h.containers.append(running_container(h.c, identity))
        h.backend['Containers'][identity] = {}
        runner = h.run
        h.adapter.run = lambda args, **kw: b'8.8.8.8\n' if 'dig' in args else runner(args, **kw)
        with self.assertRaisesRegex(ValueError, 'live DNS'):
            h.adapter.verify(h.c, receipt)

    def test_unknown_or_nonoffline_context_rejected_without_commands(self):
        for replacement in ({'egress_hosts': ['github.com']}, {'unknown': True},
                            {'peer_ipv4': '8.8.8.8'}, {'backend_subnet': '10.99.16.0/28'},
                            {'network_id': 'short'}, {'bridge': 'br0'}, {'manage_origin': 'http://public.example.org'},
                            {'manage_origin': 'https://dev.example.test:443'}):
            h = Host()
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                h.adapter.prepare(h.c | replacement)
            self.assertEqual(h.commands, [])

    def test_existing_resources_and_wrong_ownership_not_adopted(self):
        for alter in [lambda h: h.guest['config'].update({'user.cybex.nixos-qualification': 'foreign'}),
                      lambda h: h.guest['config'].update({'raw.dnsmasq': 'server=public'}),
                      lambda h: h.guest['config'].update({'dns.nameservers': '8.8.8.8'}),
                      lambda h: h.backend.update({'Internal': False}),
                      lambda h: h.links.append({'ifname': 'foreign', 'ifalias': 'foreign'}),
                      lambda h: setattr(h, 'live', rules.ruleset(h.c))]:
            h = Host()
            alter(h)
            with self.assertRaises(ValueError):
                h.adapter.prepare(h.c)
            self.assertEqual(h.mutations(), [])

    def test_dns_restart_failure_retains_firewall_and_partial_cleanup_recovers(self):
        h = Host()
        h.fail_dns = True
        with self.assertRaisesRegex(ValueError, 'DNS restart'):
            h.adapter.prepare(h.c)
        self.assertIsNotNone(h.live)
        h.adapter.cleanup(h.c, None)
        self.assertIsNone(h.live)

    def test_verify_detects_live_rule_changes_even_with_correct_receipt(self):
        for alter in [lambda h: h.live.pop(),
                      lambda h: h.live.append({'rule': {'family': 'inet', 'table': rules.names(h.c)[0], 'chain': 'extra', 'expr': [{'accept': None}]}}),
                      lambda h: h.live[0]['table'].update({'comment': 'foreign'}),
                      lambda h: h.live.append({'chain': {'family': 'inet', 'table': rules.names(h.c)[0], 'name': 'foreign'}})]:
            h = Host()
            receipt = h.adapter.prepare(h.c)
            alter(h)
            with self.assertRaisesRegex(ValueError, 'actual nft'):
                h.adapter.verify(h.c, receipt)
            h.commands.clear()
            with self.assertRaises(ValueError):
                h.adapter.cleanup(h.c, receipt)
            self.assertEqual(h.mutations(), [])

    def test_cleanup_refuses_live_guests_and_changed_dns_before_any_mutation(self):
        for alter in [lambda h: h.links.append({'ifname': h.c['bridge'] + 'a', 'ifalias': h.c['owner']}),
                      lambda h: h.backend['Containers'].update({'id': {}}),
                      lambda h: h.guest['config'].update({'raw.dnsmasq': 'foreign'})]:
            h = Host()
            receipt = h.adapter.prepare(h.c)
            alter(h)
            h.commands.clear()
            with self.assertRaises(ValueError):
                h.adapter.cleanup(h.c, receipt)
            self.assertEqual(h.mutations(), [])

    def test_embedded_docker_dns_gap_fails_before_start(self):
        h = Host()
        receipt = h.adapter.prepare(h.c)
        h.containers.append({'Id': 'b' * 64, 'Config': {'Labels': {network.LABEL: h.c['owner'], network.ROLE: 'app'}},
                             'HostConfig': {'Dns': [], 'NetworkMode': h.c['network_id'], 'CapDrop': ['ALL'],
                                            'LogConfig': {'Type': 'local', 'Config': {'max-size': '10m', 'max-file': '2'}}},
                             'NetworkSettings': {'Networks': {'backend': {'NetworkID': h.c['network_id']}}}})
        with self.assertRaisesRegex(ValueError, 'explicit owned DNS'):
            h.adapter.verify(h.c, receipt)
        h.containers[0]['HostConfig']['Dns'] = [h.c['peer_ipv4']]
        self.assertTrue(h.adapter.verify(h.c, receipt))

    def test_network_and_container_attachment_changes_fail_before_verification(self):
        alterations = [lambda h: h.guest['used_by'].append('/1.0/instances/foreign'),
                       lambda h: h.backend_bridge[0].update({'ifname': 'replaced'}),
                       lambda h: h.backend_bridge[0]['linkinfo'].update({'info_kind': 'dummy'}),
                       lambda h: h.backend_bridge[0]['addr_info'][0].update({'local': '10.99.17.2'}),
                       lambda h: h.routes.pop(),
                       lambda h: h.routes.append({'dst': '10.99.17.8/29', 'dev': 'external',
                                                  'protocol': 'static', 'scope': 'link'})]
        for alter in alterations:
            h = Host()
            receipt = h.adapter.prepare(h.c)
            alter(h)
            with self.assertRaises(ValueError):
                h.adapter.verify(h.c, receipt)
            h.commands.clear()
            with self.assertRaises(ValueError):
                h.adapter.cleanup(h.c, receipt)
            self.assertEqual(h.mutations(), [])

    def test_live_dns_process_and_config_are_required(self):
        for alter in [lambda h: setattr(h.adapter, 'read', lambda path: b'foreign'),
                      lambda h: h.dns_identity['argv'].append('--server=8.8.8.8'),
                      lambda h: h.dns_identity['sockets'].append(('udp', '0.0.0.0', 53, '07')),
                      lambda h: h.dns_identity.update({'executable': []}),
                      lambda h: h.dns_identity.update({'start_time': 0})]:
            h = Host()
            receipt = h.adapter.prepare(h.c)
            alter(h)
            with self.assertRaises(ValueError):
                h.adapter.verify(h.c, receipt)

    def test_dns_process_rejects_every_unowned_argument(self):
        for argument in ('-S8.8.8.8', '--servers-file=/tmp/unowned-servers',
                         '--conf-file=/tmp/unowned-dns.conf'):
            h = Host()
            receipt = h.adapter.prepare(h.c)
            h.dns_identity['argv'].append(argument)
            with self.subTest(argument=argument), self.assertRaisesRegex(
                    ValueError, 'only owned offline configuration'):
                h.adapter.verify(h.c, receipt)

    def test_running_container_dns_is_probed_in_its_network_namespace(self):
        h = Host()
        receipt = h.adapter.prepare(h.c)
        identity = 'b' * 64
        h.containers.append(running_container(h.c, identity))
        h.backend['Containers'][identity] = {}
        self.assertTrue(h.adapter.verify(h.c, receipt))
        probes = [args for args, _ in h.commands if args[0] == 'nsenter'
                  and args[1].startswith(f'--net=/proc/{os.getpid()}/fd/')
                  and args[2:4] == ['--', 'dig']]
        self.assertEqual(len(probes), 2)
        self.assertTrue(all(probe[4:6] == ['-b', '10.99.17.2'] for probe in probes))

        runner = h.adapter.run
        def replaced(args, **options):
            if args[3:5] == ['container', 'inspect'] and args[-1] == identity:
                changed = copy.deepcopy(h.containers[0])
                changed['State']['Pid'] = 4322
                return json.dumps([changed]).encode()
            return runner(args, **options)
        h.adapter.run = replaced
        with self.assertRaisesRegex(ValueError, 'changed during DNS namespace probe'):
            h.adapter.verify(h.c, receipt)

    def test_running_container_probe_rejects_same_pid_start_or_namespace_replacement(self):
        def fixture():
            host = Host()
            receipt = host.adapter.prepare(host.c)
            identity = 'b' * 64
            host.containers.append(running_container(host.c, identity))
            host.backend['Containers'][identity] = {}
            return host, receipt, identity

        h, receipt, identity = fixture()
        runner = h.adapter.run
        def restarted(args, **options):
            if args[3:5] == ['container', 'inspect'] and args[-1] == identity:
                changed = copy.deepcopy(h.containers[0])
                changed['State']['StartedAt'] = '2026-09-21T12:00:01.000000000Z'
                return json.dumps([changed]).encode()
            return runner(args, **options)
        h.adapter.run = restarted
        with self.assertRaisesRegex(ValueError, 'changed during DNS namespace probe'):
            h.adapter.verify(h.c, receipt)

        for field in ('start_ticks', 'netns_ino'):
            h, receipt, identity = fixture()
            original = h.adapter.current_namespace
            def replaced_namespace(pid, changed_field=field):
                value = original(pid)
                value[changed_field] += 1
                return value
            h.adapter.current_namespace = replaced_namespace
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, 'changed during DNS namespace probe'):
                h.adapter.verify(h.c, receipt)

    def test_cleanup_compare_and_swap_and_nft_handle_refuse_name_replacements(self):
        h = Host()
        receipt = h.adapter.prepare(h.c)
        h.replace_incus_before_put = True
        with self.assertRaisesRegex(ValueError, 'compare-and-swap'):
            h.adapter.cleanup(h.c, receipt)
        self.assertIsNotNone(h.live)

        h = Host()
        receipt = h.adapter.prepare(h.c)
        h.replace_nft_before_delete = True
        with self.assertRaisesRegex(ValueError, 'handle'):
            h.adapter.cleanup(h.c, receipt)
        self.assertIsNotNone(h.live)
        self.assertEqual(h.live[0]['table']['handle'], 500)

    def test_rules_reject_spoofed_fixture_sources_confine_dns_and_allow_recovery_ssh(self):
        rendered = json.dumps(rules.ruleset(context()), sort_keys=True)
        self.assertIn('"op": "!="', rendered)
        self.assertIn('"addr": "10.99.16.0", "len": 24', rendered)
        self.assertIn('"addr": "10.99.17.0", "len": 28', rendered)
        self.assertIn('"right": 22', rendered)
        output = [item['rule'] for item in rules.ruleset(context())
                  if item.get('rule', {}).get('chain') == 'output']
        self.assertTrue(any(rule['expr'][-1] == {'drop': None}
                            and any(part.get('match', {}).get('left') ==
                                    {'payload': {'protocol': 'ip', 'field': 'saddr'}}
                                    for part in rule['expr']) for rule in output))

    def test_runtime_handles_are_ignored_but_unknown_objects_are_not(self):
        c = context()
        live = copy.deepcopy(rules.ruleset(c))
        for i, obj in enumerate(live):
            next(iter(obj.values()))['handle'] = i
        network.Adapter.check_table(c, live)
        live.append({'set': {'name': 'foreign'}})
        with self.assertRaises(ValueError):
            network.Adapter.check_table(c, live)


@unittest.skipUnless(os.environ.get('CYBEX_NIXOS_NETWORK_NAMESPACE') == '1',
                     'requires an explicitly disposable root network namespace')
class KernelTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertNotEqual(os.readlink('/proc/self/ns/net'), os.readlink('/proc/1/ns/net'),
                            'refusing to change host firewall')
        self.c = context()
        self.table = rules.names(self.c)[0]

    def tearDown(self):
        subprocess.run(['nft', 'delete', 'table', 'inet', self.table], capture_output=True)

    def test_real_artifact_listener_roles_and_exact_host_self_checks(self):
        backend = rules.names(self.c)[1]
        peer, gateway = self.c['peer_ipv4'], '10.99.17.1'
        children, listeners = [], []

        def call(*args, check=True):
            return subprocess.run(args, check=check, capture_output=True, text=True)

        def child(bridge, stem, address, gateway_address):
            process = subprocess.Popen(['unshare', '--net', '--', 'sleep', '60'])
            children.append(process)
            for _ in range(100):
                if os.readlink(f'/proc/{process.pid}/ns/net') != os.readlink('/proc/self/ns/net'):
                    break
                time.sleep(0.01)
            else:
                self.fail('child did not enter its disposable namespace')
            call('ip', 'link', 'add', stem + 'h', 'type', 'veth', 'peer', 'name', stem + 'p')
            call('ip', 'link', 'set', stem + 'p', 'netns', str(process.pid))
            call('ip', 'link', 'set', stem + 'h', 'master', bridge)
            call('ip', 'link', 'set', stem + 'h', 'up')
            prefix = ['nsenter', '--target', str(process.pid), '--net', '--']
            call(*prefix, 'ip', 'link', 'set', 'lo', 'up')
            call(*prefix, 'ip', 'link', 'set', stem + 'p', 'up')
            call(*prefix, 'ip', 'address', 'add', address, 'dev', stem + 'p')
            call(*prefix, 'ip', 'route', 'add', 'default', 'via', gateway_address)
            return prefix

        def connect(prefix, address, port, source=None):
            script = ('import socket,sys; s=socket.socket(); s.settimeout(0.25); '
                      + ('s.bind((' + repr(source) + ',0)); ' if source else '')
                      + 's.connect((' + repr(address) + ',' + str(port) + ')); '
                      + 'assert s.recv(16)==b"artifact"')
            return call(*prefix, 'python3', '-c', script, check=False).returncode == 0

        bridges = [(self.c['bridge'], self.c['subnet']),
                   (backend, gateway + '/28'), ('jnq-art-ext', '192.0.2.1/24')]
        endpoints = [(peer, 18082), (gateway, 18081), (gateway, 18083),
                     (peer, 18081), (gateway, 18082), (peer, 18084), (gateway, 18084), (peer, 443)]
        try:
            call('ip', 'link', 'set', 'lo', 'up')
            for bridge, address in bridges:
                call('ip', 'link', 'add', bridge, 'type', 'bridge')
                call('ip', 'address', 'add', address, 'dev', bridge)
                call('ip', 'link', 'set', bridge, 'up')
            guest = child(self.c['bridge'], 'ag', '10.99.16.2/24', peer)
            container = child(backend, 'ab', '10.99.17.2/28', gateway)
            external = child('jnq-art-ext', 'ae', '192.0.2.2/24', '192.0.2.1')
            for address, port in endpoints:
                script = ('import socketserver; '
                          'H=type("H",(socketserver.BaseRequestHandler,),'
                          '{"handle":lambda self:self.request.sendall(b"artifact")}); '
                          'socketserver.TCPServer.allow_reuse_address=True; '
                          'socketserver.TCPServer((' + repr(address) + ',' + str(port)
                          + '),H).serve_forever()')
                listeners.append(subprocess.Popen(['python3', '-c', script],
                                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                for _ in range(40):
                    if connect([], address, port):
                        break
                    time.sleep(0.025)
                else:
                    self.fail('disposable listener did not start')
            # Positive controls show all source paths and decoys work before confinement.
            for prefix in (guest, container, external):
                for address, port in endpoints[:3]:
                    self.assertTrue(connect(prefix, address, port))
            self.assertTrue(connect(guest, peer, 18084))
            self.assertTrue(connect(container, gateway, 18084))
            subprocess.run(['nft', '-j', '-f', '-'], input=json.dumps(rules.plan(self.c)).encode(),
                           check=True, capture_output=True)
            self.assertTrue(connect(guest, peer, 18082))
            for port in (18081, 18083):
                self.assertTrue(connect(container, gateway, port))
            for address, port in endpoints[:3]:
                self.assertTrue(connect([], address, port))
                self.assertFalse(connect(external, address, port))
            self.assertTrue(connect([], peer, 443))
            self.assertTrue(connect(guest, peer, 443))
            self.assertFalse(connect(external, peer, 443))
            self.assertFalse(connect(container, peer, 443))
            for address, port in endpoints[3:-1]:
                self.assertFalse(connect([], address, port))
            for address, port in [(gateway, 18081), (gateway, 18083), (peer, 18081), (peer, 18084)]:
                self.assertFalse(connect(guest, address, port))
            for address, port in [(peer, 18082), (gateway, 18082), (gateway, 18084)]:
                self.assertFalse(connect(container, address, port))
            call(*guest, 'ip', 'address', 'add', '10.99.17.3/28', 'dev', 'agp')
            self.assertFalse(connect(guest, gateway, 18081, source='10.99.17.3'))
            observed = json.loads(subprocess.check_output(
                ['nft', '-j', 'list', 'table', 'inet', self.table]))['nftables']
            network.Adapter.check_table(self.c, observed)
        finally:
            for process in listeners + children:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=3)
            for bridge, _ in reversed(bridges):
                call('ip', 'link', 'delete', bridge, check=False)

    def test_real_kernel_plan_and_canonicalized_verification(self):
        subprocess.run(['nft', '-j', '-f', '-'],
                       input=json.dumps(rules.plan(self.c)).encode(), check=True, capture_output=True)
        observed = json.loads(subprocess.check_output(
            ['nft', '-j', 'list', 'table', 'inet', self.table]))['nftables']
        network.Adapter.check_table(self.c, observed)
        old_handle = next(item['table']['handle'] for item in observed if 'table' in item)
        subprocess.run(['nft', 'delete', 'table', 'inet', self.table], check=True, capture_output=True)
        subprocess.run(['nft', '-j', '-f', '-'],
                       input=json.dumps(rules.plan(self.c)).encode(), check=True, capture_output=True)
        replaced = subprocess.run(['nft', 'delete', 'table', 'inet', 'handle', str(old_handle)],
                                  capture_output=True)
        self.assertNotEqual(replaced.returncode, 0)
        replacement = json.loads(subprocess.check_output(
            ['nft', '-j', 'list', 'table', 'inet', self.table]))['nftables']
        network.Adapter.check_table(self.c, replacement)
        # An extra permissive rule must still fail exact ownership checking.
        subprocess.run(['nft', 'add', 'rule', 'inet', self.table, 'forward', 'accept'],
                       check=True, capture_output=True)
        changed = json.loads(subprocess.check_output(
            ['nft', '-j', 'list', 'table', 'inet', self.table]))['nftables']
        with self.assertRaisesRegex(ValueError, 'actual nft'):
            network.Adapter.check_table(self.c, changed)

    def test_real_dns_guest_and_backend_paths_spoofing_and_recovery(self):
        backend = rules.names(self.c)[1]
        children = []
        dnsmasq = None
        ssh = None

        def call(*args, check=True, **options):
            return subprocess.run(args, check=check, capture_output=True, text=True, **options)

        def child(bridge, host_link, peer_link, address, route=None):
            process = subprocess.Popen(['unshare', '--net', '--', 'sleep', '120'])
            children.append(process)
            for _ in range(50):
                if Path(f'/proc/{process.pid}/ns/net').exists():
                    break
                time.sleep(0.02)
            call('ip', 'link', 'add', host_link, 'type', 'veth', 'peer', 'name', peer_link)
            call('ip', 'link', 'set', peer_link, 'netns', str(process.pid))
            call('ip', 'link', 'set', host_link, 'master', bridge)
            call('ip', 'link', 'set', host_link, 'up')
            prefix = ['nsenter', '--target', str(process.pid), '--net', '--']
            call(*prefix, 'ip', 'link', 'set', 'lo', 'up')
            call(*prefix, 'ip', 'link', 'set', peer_link, 'up')
            call(*prefix, 'ip', 'address', 'add', address, 'dev', peer_link)
            if route:
                call(*prefix, 'ip', 'route', 'add', route[0], 'via', route[1])
            return prefix

        def dns_reply_escapes(external):
            receiver = ('import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); '
                        's.bind(("192.0.2.2",5300)); s.settimeout(0.5); '
                        '\ntry: sys.exit(0 if s.recv(64)==b"dns-response" else 1)'
                        '\nexcept TimeoutError: sys.exit(1)')
            listener = subprocess.Popen([*external, 'python3', '-c', receiver])
            time.sleep(0.05)
            sender = ('import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); '
                      's.bind(("' + self.c['peer_ipv4'] + '",53)); '
                      's.sendto(b"dns-response",("192.0.2.2",5300))')
            sent = call('python3', '-c', sender, check=False).returncode == 0
            received = listener.wait(timeout=2) == 0
            return sent and received

        try:
            call('ip', 'link', 'add', self.c['bridge'], 'type', 'bridge')
            call('ip', 'address', 'add', self.c['subnet'], 'dev', self.c['bridge'])
            call('ip', 'link', 'set', self.c['bridge'], 'up')
            call('ip', 'link', 'add', backend, 'type', 'bridge')
            call('ip', 'address', 'add', '10.99.17.1/28', 'dev', backend)
            call('ip', 'link', 'set', backend, 'up')
            call('ip', 'link', 'add', 'jnq-external', 'type', 'bridge')
            call('ip', 'address', 'add', '192.0.2.1/24', 'dev', 'jnq-external')
            call('ip', 'link', 'set', 'jnq-external', 'up')
            Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
            observed_routes = json.loads(subprocess.check_output(
                ['ip', '-j', '-4', 'route', 'show']))
            network.Adapter.check_routes(self.c, observed_routes)

            guest = child(self.c['bridge'], 'qg-host', 'qg-peer', '10.99.16.2/24',
                          ('default', self.c['peer_ipv4']))
            container = child(backend, 'qc-host', 'qc-peer', '10.99.17.2/28',
                              (self.c['peer_ipv4'] + '/32', '10.99.17.1'))
            external = child('jnq-external', 'qe-host', 'qe-peer', '192.0.2.2/24',
                             (self.c['peer_ipv4'] + '/32', '192.0.2.1'))

            call(*external, 'ip', 'route', 'add', '10.99.16.0/24', 'via', '192.0.2.1')
            self.assertEqual(call(*guest, 'ping', '-c', '1', '-W', '1',
                                  '192.0.2.2').returncode, 0)
            self.assertTrue(dns_reply_escapes(external))

            guarded_plan = rules.plan(self.c)
            spoof_drop = []
            backend_source = rules.payload('ip', 'saddr', rules.prefix(self.c['backend_subnet']))
            wrong_guest = rules.match({'meta': {'key': 'iifname'}}, backend, '!=')
            for operation in guarded_plan['nftables']:
                rule = operation.get('add', {}).get('rule', {})
                if (rule.get('chain') == 'input' and backend_source in rule.get('expr', [])
                        and wrong_guest in rule.get('expr', [])):
                    spoof_drop.append(rule)
            self.assertEqual(len(spoof_drop), 1)
            spoof_drop[0]['expr'].insert(-1, {'counter': None})
            subprocess.run(['nft', '-j', '-f', '-'], input=json.dumps(guarded_plan).encode(),
                           check=True, capture_output=True)
            self.assertFalse(dns_reply_escapes(external))
            with tempfile.TemporaryDirectory() as temporary:
                config = Path(temporary) / 'dnsmasq.raw'
                config.write_text(rules.dns_config(self.c))
                config.chmod(0o600)
                self.assertEqual(network.read_owned(config), rules.dns_config(self.c).encode())
                dnsmasq = subprocess.Popen([
                    network.DNSMASQ, '--keep-in-foreground', '--strict-order', '--bind-interfaces',
                    '--except-interface=lo', '--pid-file=', '--no-ping',
                    '--interface=' + self.c['bridge'], '--conf-file=' + str(config),
                ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                query = ['dig', '@' + self.c['peer_ipv4'], 'dev.example.test', 'A',
                         '+short', '+time=1', '+tries=1']
                for _ in range(30):
                    result = call(*guest, *query, check=False)
                    if result.stdout.splitlines() == [self.c['peer_ipv4']]:
                        break
                    if dnsmasq.poll() is not None:
                        self.fail('dnsmasq exited: ' + dnsmasq.stderr.read())
                    time.sleep(0.1)
                self.assertEqual(result.stdout.splitlines(), [self.c['peer_ipv4']])
                self.assertEqual(call(*container, *query).stdout.splitlines(), [self.c['peer_ipv4']])
                namespace_fd, namespace_identity = network.pin_network_namespace(children[1].pid)
                try:
                    pinned = ['nsenter', '--net=/proc/' + str(os.getpid()) + '/fd/'
                              + str(namespace_fd), '--']
                    self.assertEqual(call(*pinned, *query).stdout.splitlines(),
                                     [self.c['peer_ipv4']])
                    self.assertEqual(network.network_namespace_identity(children[1].pid),
                                     namespace_identity)
                finally:
                    os.close(namespace_fd)
                for prefix in (guest, container):
                    blocked = call(*prefix, 'dig', '@' + self.c['peer_ipv4'],
                                   self.c['owner'] + '.invalid', 'A', '+comments',
                                   '+time=1', '+tries=1')
                    self.assertIn('status: NXDOMAIN,', blocked.stdout)

                identity = network.inspect_dns_process(dnsmasq.pid)
                port53 = {(p, a, port, state) for p, a, port, state in identity['sockets'] if port == 53}
                self.assertEqual(port53, {('tcp', self.c['peer_ipv4'], 53, '0A'),
                                          ('udp', self.c['peer_ipv4'], 53, '07')})

                # A backend-subnet source on the guest bridge is rejected.
                call(*guest, 'ip', 'address', 'add', '10.99.17.3/28', 'dev', 'qg-peer')
                spoofed = call(*guest, 'dig', '-b', '10.99.17.3', '@' + self.c['peer_ipv4'],
                               'dev.example.test', 'A', '+short', '+time=1', '+tries=1', check=False)
                self.assertNotEqual(spoofed.stdout.splitlines(), [self.c['peer_ipv4']])
                observed = json.loads(subprocess.check_output(
                    ['nft', '-j', 'list', 'table', 'inet', self.table]))['nftables']
                counters = [part['counter'] for item in observed for part in
                            item.get('rule', {}).get('expr', []) if 'counter' in part]
                self.assertEqual(len(counters), 1)
                self.assertGreater(counters[0]['packets'], 0)

                # Guest traffic still has zero forwarding to the external bridge.
                self.assertNotEqual(call(*guest, 'ping', '-c', '1', '-W', '1',
                                         '192.0.2.2', check=False).returncode, 0)

                server = ('import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,'
                          'socket.SO_REUSEADDR,1); s.bind(("10.99.16.2",22)); s.listen(1); '
                          'c,_=s.accept(); c.sendall(b"owned-recovery"); c.close()')
                ssh = subprocess.Popen([*guest, 'python3', '-c', server])
                client = ('import socket,time; s=socket.socket(); s.bind(("10.99.16.1",0)); '
                          's.settimeout(3); s.connect(("10.99.16.2",22)); '
                          'assert s.recv(64)==b"owned-recovery"')
                for _ in range(20):
                    recovery = call('python3', '-c', client, check=False)
                    if recovery.returncode == 0:
                        break
                    time.sleep(0.05)
                self.assertEqual(recovery.returncode, 0, recovery.stderr)
                self.assertEqual(ssh.wait(timeout=3), 0)
        finally:
            if ssh is not None and ssh.poll() is None:
                ssh.terminate()
            if dnsmasq is not None and dnsmasq.poll() is None:
                dnsmasq.terminate()
                dnsmasq.wait(timeout=3)
            if dnsmasq is not None and dnsmasq.stderr is not None:
                dnsmasq.stderr.close()
            for process in children:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=3)


if __name__ == '__main__':
    unittest.main()
