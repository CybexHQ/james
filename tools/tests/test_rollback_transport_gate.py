"""Exact-owner rollback gate contracts; live packet path uses a disposable namespace probe."""
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
G = runpy.run_path(str(ROOT / 'nixos-appliance/qualification/rollback_transport_gate.py'))
SCOPE = {'owner': '12345678-1234-4234-8234-123456789abc',
         'bridge': 'jnq0123456789', 'subnet': '10.99.10.1/24'}
TAP = 'jnq0123456789a'
MAC = '02:00:00:00:00:01'
GUEST = '10.99.10.2'
DESTINATIONS = ['104.21.26.24', '172.67.135.44']


class RollbackGateTests(unittest.TestCase):
    def test_first_flow_is_exact_and_unmarked_egress_is_denied_for_any_guest_ip(self):
        _, script = G['specification'](SCOPE, TAP, MAC, GUEST, DESTINATIONS)
        value = G['intent'](SCOPE, TAP, MAC, GUEST, DESTINATIONS, script)
        rules = G['expected_rules'](value)
        self.assertEqual(len(rules), 5)
        for expression in rules[:4]:
            self.assertIn(GUEST, json.dumps(expression))
            self.assertIn(MAC, json.dumps(expression))
            self.assertIn('104.21.26.24', json.dumps(expression))
            self.assertIn('172.67.135.44', json.dumps(expression))
        self.assertNotIn(GUEST, json.dumps(rules[4]))
        self.assertIn(MAC, json.dumps(rules[4]))
        self.assertIn('blocked_other', json.dumps(rules[4]))
        self.assertIn('tcp dport { 80, 443 } counter name blocked_other drop', script)

    def test_private_receipt_binds_exact_rules_and_rejects_changes(self):
        _, script = G['specification'](SCOPE, TAP, MAC, GUEST, DESTINATIONS)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            value = G['intent'](SCOPE, TAP, MAC, GUEST, DESTINATIONS, script)
            G['save_intent'](path, value)
            self.assertEqual(G['read_intent'](path, SCOPE), value)
            value['guest'] = '10.99.10.3'
            (path / G['RECEIPT']).write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'exact rules'):
                G['read_intent'](path, SCOPE)

    def test_recovery_refuses_unreceipted_or_mutated_table(self):
        _, script = G['specification'](SCOPE, TAP, MAC, GUEST, DESTINATIONS)
        table = G['name'](SCOPE)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.dict(G['recover'].__globals__, {'tables': lambda: {table}}):
                with self.assertRaisesRegex(ValueError, 'without an ownership receipt'):
                    G['recover'](path, SCOPE)
            G['save_intent'](path, G['intent'](SCOPE, TAP, MAC, GUEST, DESTINATIONS, script))
            delete = Mock()
            with patch.dict(G['recover'].__globals__, {'tables': lambda: {table},
                        'inspect': Mock(side_effect=ValueError('foreign rule')), 'command': delete}):
                with self.assertRaisesRegex(ValueError, 'foreign rule'):
                    G['recover'](path, SCOPE)
            self.assertTrue((path / G['RECEIPT']).exists())
            delete.assert_not_called()

    def test_failed_install_remains_receipt_driven_for_cleanup(self):
        gate = G['Gate'].__new__(G['Gate'])
        with tempfile.TemporaryDirectory() as directory:
            gate.path = Path(directory)
            gate.scope = SCOPE
            gate.table, gate.script = G['specification'](SCOPE, TAP, MAC, GUEST, DESTINATIONS)
            gate.tap, gate.mac, gate.guest, gate.destinations = TAP, MAC, GUEST, DESTINATIONS
            gate.active = False
            links = [{'ifname': TAP, 'ifalias': SCOPE['owner'], 'master': SCOPE['bridge']}]
            forward = {'verify': Mock()}
            calls = []
            def execute(*args, **kwargs):
                calls.append(args)
                if args[:2] == ('-f', '-'):
                    self.assertTrue((gate.path / G['RECEIPT']).exists())
                    raise ValueError('injected nft failure')
            with patch.dict(G['Gate'].install.__globals__, {'tables': lambda: set(), 'command': execute}), \
                 patch.dict(G['Gate'].remove.__globals__, {'recover': Mock()}) as symbols, \
                 patch.object(G['subprocess'], 'check_output', return_value=json.dumps(links)), \
                 patch.object(G['runpy'], 'run_path', return_value=forward):
                with self.assertRaisesRegex(ValueError, 'injected nft failure'):
                    gate.install()
                gate.remove()
                symbols['recover'].assert_called_once_with(gate.path, SCOPE)
            self.assertIn(('-f', '-'), calls)
