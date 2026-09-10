import copy
import importlib.machinery
import importlib.util
import ipaddress
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'ubuntu-appliance/rootfs/usr/lib/cybex-james/cybex-james-pxe'
loader = importlib.machinery.SourceFileLoader('pxe', str(HELPER))
spec = importlib.util.spec_from_loader(loader.name, loader)
pxe = importlib.util.module_from_spec(spec)
loader.exec_module(pxe)

def peer(name, suffix):
    return {'server_device_id': name, 'address': f'192.0.2.{suffix}', 'mac': f'02:00:00:00:00:{suffix:02x}', 'proxy_capable': True, 'bootloader_filename': 'snponly.efi'}

def desired():
    return {'received_at': 1000, 'desired': {'schema': pxe.SCHEMA, 'complete': True,
            'server_device_id':'james-b', 'peers':[peer('james-a', 2), peer('james-b', 3)],
            'clients':[{'mac':'02:00:00:00:10:01', 'server_device_id':'james-a'},
                       {'mac':'02:00:00:00:10:02', 'server_device_id':None}]}}

def network():
    return {'interface':'eth0', 'address':'192.0.2.3', 'mac':'02:00:00:00:00:03', 'cidr':'192.0.2.0/24'}

class DiscoveryTests(unittest.TestCase):
    def test_inventory_expiry_and_incomplete_snapshot_stop_advertising(self):
        self.assertTrue(pxe.validate_desired(desired(), 1100))
        for now in (999, 1301):
            with self.assertRaisesRegex(pxe.Unavailable, 'inventory_stale'):
                pxe.validate_desired(desired(), now)
        item = desired(); item['desired']['complete'] = False
        with self.assertRaisesRegex(pxe.Unavailable, 'inventory_incomplete'):
            pxe.validate_desired(item, 1000)

    def test_untrusted_inventory_cannot_inject_dnsmasq_configuration(self):
        for field, value in [('mac', '02:00:00:00:00:01\nenable-tftp'),
                             ('address', '192.0.2.2\ndhcp-range=192.0.2.1,192.0.2.99'),
                             ('bootloader_filename', '../config.toml')]:
            item = desired(); item['desired']['peers'][0][field] = value
            with self.assertRaises((pxe.Unavailable, ValueError)):
                pxe.validate_desired(item, 1000)

    def test_duplicate_prefixes_on_separate_vlans_do_not_invalidate_inventory(self):
        item = desired(); item['desired']['peers'][0]['address'] = '192.0.2.3'
        self.assertTrue(pxe.validate_desired(item, 1000))

    def test_only_live_direct_peers_can_win_and_failover_is_deterministic(self):
        inventory = desired()['desired']
        local = {'james-b': {'ready':True, 'eligible':True}}
        self.assertEqual(pxe.choose(inventory, network(), local)[0], 'james-b')
        both = dict(local, **{'james-a':{'ready':True,'eligible':True}})
        self.assertEqual(pxe.choose(inventory, network(), both)[0], 'james-a')
        both['james-a']['eligible'] = False
        self.assertEqual(pxe.choose(inventory, network(), both)[0], 'james-b')
        self.assertIn('james-a', pxe.choose(inventory, network(), both)[2])

    def test_address_change_uses_current_approved_address(self):
        item = network(); item['address'] = '192.0.2.44'
        observations = {'james-b': {'ready':True, 'eligible':True}}
        _, default, _ = pxe.choose(desired()['desired'], item, observations)
        self.assertEqual(default['address'], '192.0.2.44')

    def test_unknown_clients_use_elected_james_and_known_clients_never_fall_back(self):
        inventory = desired()['desired']; target = inventory['peers'][1]
        config = pxe.dnsmasq_config(network(), target, {'james-b':target}, inventory['clients'])
        self.assertIn('dhcp-boot=tag:!known,snponly.efi,,192.0.2.3', config)
        self.assertIn('dhcp-host=02:00:00:00:10:01,set:known,set:blocked', config)
        self.assertIn('dhcp-host=02:00:00:00:10:02,set:known,set:blocked', config)
        self.assertIn('dhcp-ignore=tag:blocked', config)

    def test_generated_configuration_has_no_address_pool_dns_or_tftp(self):
        inventory = desired()['desired']
        config = pxe.dnsmasq_config(network(), inventory['peers'][1], {p['server_device_id']:p for p in inventory['peers']}, inventory['clients'])
        self.assertIn('port=0\n', config)
        self.assertIn('leasefile-ro\n', config)
        self.assertEqual([l for l in config.splitlines() if l.startswith('dhcp-range=')], ['dhcp-range=192.0.2.0,proxy,255.255.255.0'])
        self.assertNotIn('enable-tftp', config)
        self.assertNotIn('dhcp-authoritative', config)
        self.assertIn('dhcp-ignore=tag:!uefi64', config)
        with tempfile.NamedTemporaryFile('w') as file:
            file.write(config); file.flush()
            result = subprocess.run(['/usr/sbin/dnsmasq', '--test', f'--conf-file={file.name}'], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_peer_with_same_ip_but_wrong_identity_cannot_win(self):
        routes = json.dumps([{'dev':'eth0'}]).encode()
        with patch.object(pxe, 'run', return_value=routes), patch.object(pxe, 'http_json', return_value={'ready':True,'eligible':True,'identity':'wrong'}):
            _, result = pxe.peer_probe(peer('james-a', 2), network())
        self.assertFalse(result['eligible'])

    def test_routed_peer_is_never_treated_as_same_vlan(self):
        routes = json.dumps([{'dev':'eth0','gateway':'192.0.2.1'}]).encode()
        with patch.object(pxe, 'run', return_value=routes), patch.object(pxe, 'http_json') as probe:
            _, result = pxe.peer_probe(peer('james-a', 2), network())
        self.assertFalse(result['eligible']); probe.assert_not_called()

    def test_network_requires_approved_nic_and_unique_primary_ipv4(self):
        plan = {'network': {'version':2,'renderer':'networkd','ethernets': {'cybex-james': {'set-name':'eth0','match':{'macaddress':'02:00:00:00:00:03'},'dhcp4':True}}}}
        interfaces = [{'ifname':'eth0','flags':['UP','LOWER_UP'],'addr_info':[{'family':'inet','scope':'global','local':'192.0.2.3','prefixlen':24}]}]
        self.assertEqual(pxe.network_from(plan, interfaces, '02:00:00:00:00:03'), network())
        with self.assertRaisesRegex(pxe.Unavailable, 'interface_identity_changed'):
            pxe.network_from(plan, interfaces, '02:00:00:00:00:04')
        extra = copy.deepcopy(interfaces[0]['addr_info'][0]); extra['local'] = '192.0.2.4'
        interfaces[0]['addr_info'].append(extra)
        with self.assertRaisesRegex(pxe.Unavailable, 'address_ambiguous'):
            pxe.network_from(plan, interfaces, '02:00:00:00:00:03')

    def test_failed_responder_withdraws_long_enough_for_peer_takeover(self):
        supervisor = pxe.Supervisor()
        supervisor.winner = 'james-b'
        with patch.object(supervisor, 'status') as status, patch.object(pxe.time, 'monotonic', return_value=100):
            supervisor.failed(pxe.Unavailable('proxy_process_failed'))
            status.assert_called_once_with('unavailable', 'proxy_process_failed')
        self.assertEqual(supervisor.retry_after, 130)
        self.assertIsNone(supervisor.winner)
        with patch.object(pxe, 'read_json', return_value={'mode':'automatic'}), patch.object(pxe.time, 'monotonic', return_value=110), patch.object(supervisor, 'status') as status, patch.object(pxe, 'http_json') as probe:
            supervisor.reconcile()
            status.assert_called_once_with('unavailable', 'proxy_retry_pending')
            probe.assert_not_called()

    def test_failed_reconfiguration_stops_previous_proxy(self):
        supervisor = pxe.Supervisor()
        with patch.object(pxe.subprocess, 'Popen') as spawn:
            supervisor.process = spawn.return_value
            supervisor.stop()
            spawn.return_value.terminate.assert_called_once()
            self.assertIsNone(supervisor.process)

if __name__ == '__main__':
    unittest.main()
