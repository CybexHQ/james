import copy
from pathlib import Path
import runpy
import unittest


TARGET = runpy.run_path(str(Path(__file__).resolve().parents[2] /
                            'nixos-appliance/qualification/ssh-target.py'))['fixture_address']
MAC = '02:7b:ee:b2:33:7f'
SCOPE = {'subnet': '10.246.218.1/24'}
NODE = {
    'public_base_url': '',
    'cache_base_url': 'http://10.246.218.62/cache',
    'appliance_network': {'interfaces': [
        {'address': '00:00:00:00:00:00', 'addr_info': [
            {'family': 'inet', 'scope': 'host', 'local': '127.0.0.1'}]},
        {'address': MAC, 'addr_info': [
            {'family': 'inet', 'scope': 'global', 'local': '10.246.218.62'}]},
    ]},
}


class QualificationSshTargetTests(unittest.TestCase):
    def test_uses_reported_global_address_on_exact_fixture_mac(self):
        self.assertEqual(TARGET(NODE, SCOPE, MAC), '10.246.218.62')
        with_public_url = copy.deepcopy(NODE)
        with_public_url['public_base_url'] = 'https://10.246.218.62:8443'
        self.assertEqual(TARGET(with_public_url, SCOPE, MAC), '10.246.218.62')

    def test_rejects_another_mac_or_address_outside_owned_bridge(self):
        with self.assertRaisesRegex(ValueError, 'owned fixture MAC'):
            TARGET(NODE, SCOPE, '02:7b:ee:b2:33:80')
        outside = copy.deepcopy(NODE)
        outside['appliance_network']['interfaces'][1]['addr_info'][0]['local'] = '10.246.219.62'
        with self.assertRaisesRegex(ValueError, 'outside its disposable bridge'):
            TARGET(outside, SCOPE, MAC)

    def test_rejects_inconsistent_reported_endpoints(self):
        for field in ('public_base_url', 'cache_base_url'):
            inconsistent = copy.deepcopy(NODE)
            inconsistent[field] = 'http://10.246.218.63/cache'
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'differs'):
                TARGET(inconsistent, SCOPE, MAC)

    def test_rejects_ambiguous_fixture_addresses(self):
        ambiguous = copy.deepcopy(NODE)
        ambiguous['appliance_network']['interfaces'][1]['addr_info'].append(
            {'family': 'inet', 'scope': 'global', 'local': '10.246.218.63'})
        with self.assertRaisesRegex(ValueError, 'one global IPv4'):
            TARGET(ambiguous, SCOPE, MAC)


if __name__ == '__main__':
    unittest.main()
