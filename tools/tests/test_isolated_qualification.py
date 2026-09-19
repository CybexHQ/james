import copy
import importlib.util
from pathlib import Path
import socket
import sys
import tempfile
import threading
import json
import unittest

HELPERS = Path(__file__).resolve().parents[2] / 'ubuntu-appliance/qualification'


def load(name):
    spec = importlib.util.spec_from_file_location(name, HELPERS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixture = load('isolated_fixture')
rollback = load('rollback_lifecycle')


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
                    connection.sendall(b'{"event":"RESET"}\n' + body + b'\n')

            thread = threading.Thread(target=respond)
            thread.start()
            monitor = fixture.QMP(path)
            self.assertEqual(monitor.pending, [{'event': 'RESET'}])
            monitor.socket.close()
            thread.join()
            server.close()

    def test_roll_back_rejects_replaced_identity_and_false_terminal_receipts(self):
        before = {'device_id': 'device', 'hostname': 'fixture', 'public_base_url': 'http://10.62.57.2',
            'cache_public_key_fingerprint': 'a' * 64, 'cache_base_url': 'http://10.62.57.2/cache',
            'appliance_release': '0.2.1-dev.29', 'ubuntu_snapshot_id': '20260901T000000Z',
            'appliance_network': {'managed_interface_id': 'nic0', 'interfaces': [{'ifname': 'enp1s0', 'address': '52:54:00:c7:be:01'}]}}
        after = copy.deepcopy(before) | {'update_status': 'rolled_back', 'update_attempt_id': 'attempt',
            'update_target_version': '0.2.2', 'root_generation': '0', 'appliance_secure_boot': True,
            'network_fallback_active': False, 'appliance_local_health': {'status': 'healthy'},
            'appliance_package_update': {'status': 'rolled_back', 'attempt_id': 'attempt', 'target_release': '0.2.2',
                'resulting_root_generation': '0', 'rollback_reason': 'candidate_boot_failed'}}
        rollback.verify_rollback(before, after, 'attempt', '0.2.2')
        for field, invalid in [('device_id', 'other'), ('root_generation', '1'),
                               ('update_attempt_id', 'other'), ('appliance_release', '0.2.2'),
                               ('appliance_secure_boot', False), ('network_fallback_active', True)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                rollback.verify_rollback(before, after | {field: invalid}, 'attempt', '0.2.2')

    def test_runtime_rollback_evidence_rejects_unconverged_runtime(self):
        descriptor = dict(compatibility_epoch=1, runtime_version='1.0.61', bundle_sha256='a' * 64,
                          architecture='x86_64-linux', manage_source_revision='b' * 40)
        self.assertEqual(rollback.runtime_identity({'state': 'ready', 'active': descriptor, 'desired': descriptor}), descriptor)
        with self.assertRaises(ValueError):
            rollback.runtime_identity({'state': 'ready', 'active': descriptor,
                                       'desired': descriptor | {'bundle_sha256': 'c' * 64}})


if __name__ == '__main__':
    unittest.main()
