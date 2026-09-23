"""The candidate rollback gate stays bound to the authenticated private fixture."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'
spec = importlib.util.spec_from_file_location('test_nixos_rollback_gate', HELPERS / 'rollback_transport_gate.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
OWNER = '01234567-89ab-4def-8123-456789abcdef'
SCOPE = {'schema': 'cybex.james.nixos-isolated-scope.v1', 'owner': OWNER,
         'bridge': 'jnq0123456789', 'manage_origin': 'https://manage.cybex.net',
         'subnet': '10.249.217.1/24'}
TARGET = {'owner': OWNER, 'bridge': SCOPE['bridge'], 'origin': SCOPE['manage_origin'],
          'peer_ipv4': '10.249.217.1', 'certificate_sha256': 'a' * 64}
MAC = '02:11:22:33:44:55'


def fixture(state, scope=SCOPE):
    return types.SimpleNamespace(state=state, scope=scope, tap=scope['bridge'] + 'a', hardware={'mac': MAC})


def node():
    return {'appliance_network': {'interfaces': [{'address': MAC, 'addr_info': [
        {'family': 'inet', 'scope': 'global', 'local': '10.249.217.2'}]}]}}


class RollbackTransportGateTests(unittest.TestCase):
    def test_isolated_target_uses_only_authenticated_private_peer(self):
        rpc = Mock(return_value=TARGET)
        with patch.dict(sys.modules, {'isolated_manage_rpc': types.SimpleNamespace(request=rpc)}), \
             patch.object(G.socket, 'getaddrinfo', side_effect=AssertionError('public DNS used')):
            self.assertEqual(G.target(fixture(Path('/private'))), {
                'owner': OWNER, 'bridge': SCOPE['bridge'], 'origin': SCOPE['manage_origin'],
                'destinations': ['10.249.217.1'], 'certificate_sha256': 'a' * 64})
        rpc.assert_called_once_with(Path('/private'), 'rollback_gate_target')

    def test_isolated_target_rejects_substituted_owner_peer_or_certificate(self):
        for changed in ({'owner': '11234567-89ab-4def-8123-456789abcdef'},
                        {'peer_ipv4': '8.8.8.8'}, {'certificate_sha256': 'bad'}):
            with self.subTest(changed=changed), \
                 patch.dict(sys.modules, {'isolated_manage_rpc': types.SimpleNamespace(
                     request=Mock(return_value=TARGET | changed))}), \
                 self.assertRaises(ValueError):
                G.target(fixture(Path('/private')))
        with self.assertRaisesRegex(ValueError, 'known owned scope'):
            G.target(fixture(Path('/private'), SCOPE | {'schema': 'unknown'}))

    def test_install_places_exact_gate_before_slow_owner_revalidation(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            selected = {'destinations': ['10.249.217.1']}
            with patch.object(G, 'target', return_value=selected) as target:
                gate = G.Gate(fixture(state), node())
                target.return_value = {'destinations': ['10.249.217.9']}
                scope_verify = Mock(return_value=(SCOPE, {}))
                link = [{'ifname': gate.tap, 'ifalias': OWNER, 'master': SCOPE['bridge']}]
                with patch.object(G, 'tables', return_value=set()), \
                     patch.object(G.runpy, 'run_path', return_value={'verify': scope_verify}), \
                     patch.object(G.subprocess, 'check_output', return_value=json.dumps(link)), \
                     patch.object(G, 'command') as command:
                    gate.install()
                self.assertTrue((state / G.RECEIPT).exists())
                command.assert_called_once_with('-f', '-', data=gate.script)
                scope_verify.assert_called_once_with(state, SCOPE['manage_origin'], SCOPE['bridge'],
                                                      require_forwarding=False, require_isolation=False)
                with patch.object(G, 'tables', return_value={gate.table}), \
                     self.assertRaisesRegex(ValueError, 'target changed'):
                    gate.revalidate()
                self.assertEqual(target.call_count, 2)

    def test_install_rejects_changed_owned_bridge_before_writing_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with patch.object(G, 'target', return_value={'destinations': ['10.249.217.1']}):
                gate = G.Gate(fixture(state), node())
            with patch.object(G, 'tables', return_value=set()), \
                 patch.object(G.runpy, 'run_path', return_value={'verify': Mock(return_value=(SCOPE | {'owner': 'changed'}, {}))}), \
                 patch.object(G, 'save_intent') as save, patch.object(G, 'command') as command, \
                 self.assertRaisesRegex(ValueError, 'scope changed'):
                gate.install()
            save.assert_not_called()
            command.assert_not_called()
            self.assertFalse((state / G.RECEIPT).exists())

    def test_revalidation_failure_removes_exact_owned_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary); state.chmod(0o700)
            with patch.object(G, 'target', side_effect=[{'destinations': ['10.249.217.1']},
                                                         {'destinations': ['10.249.217.9']}]):
                gate = G.Gate(fixture(state), node())
                present = set()
                def command(*args, data=None):
                    if args[:2] == ('-f', '-'):
                        present.add(gate.table)
                    elif args[:3] == ('delete', 'table', 'inet'):
                        present.remove(gate.table)
                link = [{'ifname': gate.tap, 'ifalias': OWNER, 'master': SCOPE['bridge']}]
                with patch.object(G, 'tables', side_effect=lambda: set(present)), \
                     patch.object(G.runpy, 'run_path', return_value={'verify': Mock(return_value=(SCOPE, {}))}), \
                     patch.object(G.subprocess, 'check_output', return_value=json.dumps(link)), \
                     patch.object(G, 'command', side_effect=command), patch.object(G, 'inspect'):
                    gate.install()
                    with self.assertRaisesRegex(ValueError, 'target changed'):
                        gate.revalidate()
                    gate.remove()
                self.assertFalse(present)
                self.assertFalse((state / G.RECEIPT).exists())

    def test_recover_deletes_only_exact_receipted_table(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary); state.chmod(0o700)
            destinations = ['10.249.217.1']
            table, script = G.specification(SCOPE, SCOPE['bridge'] + 'a', MAC,
                                             '10.249.217.2', destinations)
            G.save_intent(state, G.intent(SCOPE, SCOPE['bridge'] + 'a', MAC,
                                          '10.249.217.2', destinations, script))
            with patch.object(G, 'tables', side_effect=[{table}, set()]), \
                 patch.object(G, 'inspect') as inspect, patch.object(G, 'command') as command:
                G.recover(state, SCOPE)
            inspect.assert_called_once()
            command.assert_called_once_with('delete', 'table', 'inet', table)
            self.assertFalse((state / G.RECEIPT).exists())

    def test_recover_refuses_table_without_receipt_and_changed_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with patch.object(G, 'tables', return_value={G.name(SCOPE)}), \
                 self.assertRaisesRegex(ValueError, 'without an ownership receipt'):
                G.recover(state, SCOPE)
            (state / G.RECEIPT).write_text(json.dumps({'owner': OWNER, 'bridge': SCOPE['bridge']}))
            (state / G.RECEIPT).chmod(0o600)
            with patch.object(G, 'command') as command, \
                 self.assertRaisesRegex(ValueError, 'receipt differs'):
                G.recover(state, SCOPE)
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
