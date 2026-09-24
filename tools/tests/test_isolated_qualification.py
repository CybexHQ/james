import copy
import datetime
import importlib.util
from pathlib import Path
import socket
import sys
import tempfile
import threading
import json
import unittest

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'
sys.path.insert(0, str(HELPERS))


def load(name):
    spec = importlib.util.spec_from_file_location(name, HELPERS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixture = load('isolated_fixture')
workstation = load('workstation_lifecycle')


class QualificationTests(unittest.TestCase):
    def test_qmp_keeps_asynchronous_reset_while_waiting_for_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'qmp.sock'
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path))
            server.listen()

            def respond():
                with server.accept()[0] as connection:
                    connection.sendall(b'{"QMP":{}}\n')
                    command = json.loads(connection.makefile('rb').readline())
                    body = json.dumps({'return': {}, 'id': command['id']}).encode()
                    connection.sendall(b'{"event":"RESET"}\n' + body + b'\n{"event":"RESET","data":{"second":true}}\n')

            thread = threading.Thread(target=respond)
            thread.start()
            monitor = fixture.QMP(path)
            self.assertEqual(monitor.pending, [{'event': 'RESET'}, {'event': 'RESET', 'data': {'second': True}}])
            monitor.socket.close()
            thread.join()
            server.close()



    def test_workstation_acceptance_requires_booted_exact_runtime_and_fresh_compliance(self):
        descriptor = {'runtime_version': '1.0.67', 'manage_source_revision': 'b' * 40,
            'components': {name: {'sha256': 'a' * 64, 'size_bytes': 1}
                           for name in ('bzImage', 'initrd', 'nix-store.squashfs')}}
        blueprint = {'current_revision_id': 'revision'}
        verified = datetime.datetime(2026, 9, 19, 14, tzinfo=datetime.timezone.utc)
        before = {'device_id': 'device', 'public_key_fingerprint': 'key'}
        device = before | {'device_kind': 'workstation', 'health_status': 'online',
            'configuration_status': 'compliant', 'desired_blueprint_revision_id': 'revision',
            'applied_blueprint_revision_id': 'revision', 'desired_config_hash': 'a' * 64,
            'reported_config_hash': 'a' * 64, 'applied_config_hash': 'a' * 64,
            'configuration_verified_at': '2026-09-19T14:01:00Z', 'facts_json': {
                'boot_id': '668c1504-558f-4b4c-b4bb-8132600df97b',
                'workstation_runtime': {'runtime_version': '1.0.67', 'manage_source_revision': 'b' * 40,
                    'descriptor_sha256': workstation.descriptor_digest(descriptor)},
                'blueprint_generation': {k: '/nix/store/exact-system'
                    for k in ('current_system', 'system_profile', 'booted_system')}}}
        workstation.require_workstation(device, descriptor, blueprint, before, verified)
        for key, value in [('applied_blueprint_revision_id', 'old'), ('reported_config_hash', None),
                           ('configuration_status', 'pending_reboot'), ('public_key_fingerprint', 'other'),
                           ('configuration_verified_at', '2026-09-19T13:59:00Z')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                workstation.require_workstation(device | {key: value}, descriptor, blueprint, before, verified)
        for section, key, value in [('workstation_runtime', 'descriptor_sha256', 'c' * 64),
                                    ('blueprint_generation', 'booted_system', '/nix/store/old-system')]:
            bad = copy.deepcopy(device)
            bad['facts_json'][section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                workstation.require_workstation(bad, descriptor, blueprint, before, verified)

    def test_managed_reboot_requests_one_fresh_probe_only_after_observed_return(self):
        before = {'facts_json': {'boot_id': 'old'}}
        calls = []
        completed = False

        def api(path, body=None):
            if body:
                calls.append(body['command_type'])
                return {'id': 'command'}
            return {'commands': [{'id': 'command', 'status': 'completed' if completed else 'dispatched'}]}

        def wait_for(label, read, accept, timeout):
            nonlocal completed
            after = {'facts_json': {'boot_id': 'new'}, 'last_seen_at': workstation.now().isoformat()}
            self.assertFalse(accept(after))
            completed = True
            self.assertFalse(accept(after | {'facts_json': {'boot_id': 'old'}}))
            self.assertFalse(accept(after | {'last_seen_at': '2020-01-01T00:00:00Z'}))
            self.assertTrue(accept(after))
            self.assertEqual(calls, ['reboot', 'verify_blueprint'])
            return after

        result = workstation.managed_reboot(api, '/v1/devices/owned', before, wait_for, lambda: None)
        self.assertEqual(result['facts_json']['boot_id'], 'new')
        self.assertEqual(calls, ['reboot', 'verify_blueprint'])

    def test_descriptor_digest_is_independent_of_incoming_json_key_order(self):
        descriptor = {'runtime_version': '1.0.67', 'components': {
            name: {'sha256': 'a' * 64, 'size_bytes': 1}
            for name in ('bzImage', 'initrd', 'nix-store.squashfs')}}
        reordered = json.loads(json.dumps(descriptor, sort_keys=True))
        self.assertEqual(workstation.descriptor_digest(descriptor), workstation.descriptor_digest(reordered))


if __name__ == '__main__':
    unittest.main()
