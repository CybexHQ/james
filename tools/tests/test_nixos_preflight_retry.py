"""Q03 changes transport bytes only and must prove disk/identity-safe retry."""
from argparse import Namespace
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / 'nixos-appliance/qualification'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HELPERS / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


F = load('q03_fixture', 'isolated_fixture.py')
with patch.dict(sys.modules, {'isolated_fixture': F}):
    R = load('q03_retry', 'preflight_retry.py')
S = load('q03_server', 'serve-faulted-closure.py')


class ResponseFaultTests(unittest.TestCase):
    def test_one_response_byte_changes_and_original_and_clean_response_stay_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'signed.tar.zst'
            original = bytes(range(256)) * 8192
            source.write_bytes(original)
            before = source.stat()
            verified = S.VerifiedFile(source, hashlib.sha256(original).hexdigest(), len(original))
            try:
                corrupt = b''.join(verified.chunks('corrupt'))
                self.assertEqual(len(corrupt), len(original))
                self.assertEqual(sum(a != b for a, b in zip(original, corrupt)), 1)
                self.assertEqual(b''.join(verified.chunks('clean')), original)
                self.assertEqual(source.read_bytes(), original)
                self.assertEqual(source.stat().st_mtime_ns, before.st_mtime_ns)
            finally: verified.close()

    def test_original_is_verified_before_any_fault_is_possible(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'signed'; path.write_bytes(b'original')
            for digest, size in [('a' * 64, 8), (hashlib.sha256(b'original').hexdigest(), 9)]:
                with self.assertRaises(ValueError): S.VerifiedFile(path, digest, size)
            link = Path(temporary) / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError): S.VerifiedFile(link, hashlib.sha256(b'original').hexdigest(), 8)

    def test_detects_original_mutation_after_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'signed'; path.write_bytes(b'original')
            verified = S.VerifiedFile(path, hashlib.sha256(b'original').hexdigest(), 8)
            try:
                path.write_bytes(b'changed!')
                with self.assertRaises(ValueError): list(verified.chunks('corrupt'))
            finally: verified.close()

    def test_mode_requires_private_explicit_control(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'control'; path.write_text('corrupt\n'); path.chmod(0o600)
            self.assertEqual(S.private_control(path), 'corrupt')
            path.write_text('clean\n'); self.assertEqual(S.private_control(path), 'clean')
            path.write_text('unknown\n')
            with self.assertRaises(ValueError): S.private_control(path)
            path.write_text('clean\n'); path.chmod(0o644)
            with self.assertRaises(ValueError): S.private_control(path)


class RetryBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.initial = {'id': 'session', 'state': 'approved', 'release_version': '1.2.3',
                        'reserved_device_id': 'dev_' + 'a' * 32, 'inventory_sha256': 'b' * 64,
                        'install_plan': {'id': 'old-plan', 'plan_revision': 1,
                            'schema': 'cybex.james.install-plan.v3', 'session_id': 'session',
                            'target_disk_id': 'exact-disk', 'target_disk': {'serial': 'owned'},
                            'hardware_digest': 'c' * 64, 'network_interface': {'mac': '02:00:00:00:00:01'},
                            'package_delivery': 'system-closure-v1', 'package_transport_url': 'private-fixture',
                            'appliance_release': {'system_closure': {'sha256': 'd' * 64, 'size_bytes': 100}}}}
        self.failed = {**deepcopy(self.initial), 'state': 'failed', 'session_revision': 4,
                       'failure_code': 'system_closure_verification_failed', 'progress': [
                           {'sequence': 1, 'stage': 'system_closure_verification_failed', 'status': 'failed'}]}
        self.responses = [{'mode': 'corrupt', 'complete': True, 'bytes': 100,
                           'original_sha256': 'd' * 64, 'response_sha256': 'e' * 64}]

    def test_exact_safe_failure_is_required(self):
        self.assertEqual(R.failed_before_writes(self.failed, self.initial, 'disk', 'disk', self.responses), self.responses[0])
        for change in ({'destructive_started_at': 'now'}, {'state': 'installing'}, {'reserved_device_id': 'other'},
                       {'inventory_sha256': 'different'}, {'failure_code': 'network_preflight_failed'}, {'progress': []}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                R.failed_before_writes({**self.failed, **change}, self.initial, 'disk', 'disk', self.responses)
        with self.assertRaises(ValueError): R.failed_before_writes(self.failed, self.initial, 'before', 'changed', self.responses)
        for change in ({'complete': False}, {'mode': 'clean'}, {'bytes': 99}, {'response_sha256': 'd' * 64}):
            with self.assertRaises(ValueError):
                R.failed_before_writes(self.failed, self.initial, 'disk', 'disk', [{**self.responses[0], **change}])

    def test_reapproval_requires_new_plan_but_identical_disk_identity_and_delivery(self):
        approved = deepcopy(self.initial); approved['install_plan'].update(id='new-plan', plan_revision=2)
        R.validate_new_plan(approved, self.initial)
        for key in ('target_disk_id', 'target_disk', 'hardware_digest', 'network_interface',
                    'appliance_release', 'package_delivery', 'package_transport_url'):
            changed = deepcopy(approved); changed['install_plan'][key] = 'other'
            with self.subTest(key=key), self.assertRaises(ValueError): R.validate_new_plan(changed, self.initial)
        with self.assertRaises(ValueError): R.validate_new_plan(self.initial, self.initial)

    def test_fresh_authenticated_heartbeat_proves_restart_without_revision_increment(self):
        # Manage only increments a repeated claim revision when inventory changes.
        waiting = {'id': 'session', 'state': 'awaiting_approval', 'session_revision': 5,
                   'heartbeat_at': '2026-09-21T10:00:00Z'}
        fresh = {**waiting, 'heartbeat_at': '2026-09-21T10:00:02Z'}
        api = Mock(side_effect=[waiting, fresh])
        with patch.object(R.time, 'sleep'):
            self.assertEqual(R.wait_session(api, 'session', 'awaiting_approval',
                             heartbeat_after='2026-09-21T10:00:01Z'), fresh)
        self.assertEqual(api.call_count, 2)
        self.assertEqual(fresh['session_revision'], waiting['session_revision'])

    def test_approve_accepts_unchanged_revision_and_flat_device_detail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = {'retry_revision': 5, 'personalized_iso_sha256': 'iso', 'disk_digest_before': 'disk',
                       'device_id': self.initial['reserved_device_id'], 'provisioning_key_fingerprint': 'f' * 64}
            fresh = {**deepcopy(self.initial), 'state': 'awaiting_approval', 'session_revision': 5,
                     'heartbeat_at': '2026-09-21T10:00:02Z'}
            approved = deepcopy(self.initial); approved['install_plan'].update(id='new', plan_revision=2)
            approval_body = {'target_disk_id': 'exact-disk', 'session_revision': 3}
            args = Namespace(initial=root / 'initial', receipt=root / 'receipt', session_id='session',
                             qmp=root / 'qmp', iso=root / 'iso', disk=root / 'disk', approval=root / 'approval',
                             reapproved=root / 'reapproved', control=root / 'control',
                             restarted_at='2026-09-21T10:00:01Z')
            api = Mock(side_effect=[{'device_id': receipt['device_id'], 'public_key_fingerprint': 'f' * 64}, approved])
            monitor = Mock(); monitor.call.side_effect = [{}, {'running': False}, {}, {'running': True}]
            with patch.object(R, 'read', side_effect=[self.initial, receipt, approval_body]), \
                    patch.object(R, 'wait_session', return_value=fresh) as wait, \
                    patch.object(R, 'QMP', return_value=monitor), patch.object(R, 'sha256', return_value='iso'), \
                    patch.object(R, 'fingerprint', return_value='disk'):
                R.approve(args, api)
            self.assertEqual(wait.call_args.kwargs['heartbeat_after'], args.restarted_at)
            self.assertEqual(api.call_args.args[1]['session_revision'], 5)
            proof = json.loads(args.reapproved.read_bytes())
            self.assertEqual(proof['_qualification_restart']['heartbeat_at'], fresh['heartbeat_at'])
            self.assertEqual(args.control.read_text(), 'clean\n')

    def test_retry_uses_fresh_console_revision_only_after_stopped_disk_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); responses = root / 'responses'
            responses.write_text('\n'.join(map(json.dumps, self.responses)))
            args = Namespace(initial=root / 'initial', session_id='session', qmp=root / 'qmp',
                             disk=root / 'disk', disk_digest='before', responses=responses,
                             receipt=root / 'receipt', iso=root / 'iso')
            retry = {**self.initial, 'state': 'awaiting_approval', 'install_plan': None, 'progress': [], 'session_revision': 5}
            api = Mock(side_effect=[self.failed, {'device_id': self.initial['reserved_device_id'], 'public_key_fingerprint': 'f' * 64}, retry])
            monitor = Mock(); monitor.call.side_effect = [{}, {'running': False}]
            with patch.object(R, 'read', return_value=self.initial), patch.object(R, 'wait_session', return_value=self.failed), \
                    patch.object(R, 'QMP', return_value=monitor), patch.object(R, 'fingerprint', return_value='before'), \
                    patch.object(R, 'sha256', return_value='iso-sha'):
                R.begin(args, api)
            self.assertEqual(api.call_args_list[-1].args, ('/v1/james/provisioning-sessions/session/retry', {'session_revision': 4}))
            receipt = json.loads(args.receipt.read_bytes())
            self.assertEqual(receipt['disk_digest_before'], receipt['disk_digest_after_failure'])
            self.assertNotIn('ok', receipt)
            self.assertEqual(monitor.call.call_args_list[0].args, ('stop',))

    def test_complete_requires_ready_lifecycle_and_restored_transport(self):
        for ready, clean in [(False, True), (True, False), (True, True)]:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(ready=ready, clean=clean):
                root = Path(temporary)
                receipt = {'device_id': self.initial['reserved_device_id'], 'session_id': 'session',
                           'personalized_iso_sha256': 'iso', 'provisioning_key_fingerprint': 'f' * 64}
                approved = deepcopy(self.initial)
                approved['install_plan'].update(id='new', plan_sha256='a' * 64)
                approved['_qualification_restart'] = {'started_at': '2026-09-21T10:00:01Z',
                                                       'heartbeat_at': '2026-09-21T10:00:02Z'}
                lifecycle = {'ok': True, 'final_state': 'ready' if ready else 'failed',
                             'device_id': receipt['device_id'], 'session_id': 'session', 'personalized_sha256': 'iso',
                             'qualified_manifest_sha256': 'manifest', 'system_toplevel': 'toplevel',
                             'system_generation': '1', 'harness_revision': 'harness'}
                responses = root / 'responses'
                rows = self.responses + ([{'mode': 'clean', 'complete': True, 'bytes': 100,
                        'original_sha256': 'd' * 64, 'response_sha256': 'd' * 64}] if clean else [])
                responses.write_text('\n'.join(map(json.dumps, rows)))
                args = Namespace(receipt=root / 'attempt', reapproved=root / 'approved',
                                 lifecycle=root / 'lifecycle', responses=responses, output=root / 'q03', session_id='session')
                api = Mock(side_effect=[{**approved, 'state': 'ready'}, {'device_id': self.initial['reserved_device_id'], 'public_key_fingerprint': '1' * 64}])
                with patch.object(R, 'read', side_effect=[receipt, approved, lifecycle]), patch.object(R, 'sha256', return_value='tool'):
                    if ready and clean:
                        R.complete(args, api)
                        proof = json.loads(args.output.read_bytes())
                        self.assertTrue(proof['ok'])
                        self.assertTrue(proof['signed_transport_restored'])
                        self.assertEqual(proof['new_plan_id'], 'new')
                    else:
                        with self.assertRaises(ValueError): R.complete(args, api)
                        self.assertFalse(args.output.exists())


if __name__ == '__main__': unittest.main()
