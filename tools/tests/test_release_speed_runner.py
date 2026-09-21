"""Nonprivileged whole-CLI fixtures; no VM, network or deployment commands."""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

BEAST = Path(__file__).resolve().parents[2] / 'release/beast'
sys.path.insert(0, str(BEAST))
import release_speed as S
import release_speed_io as I
import release_speed_resources as R
import release_speed_timing as T


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.context = dict(source_sha256='a' * 64, manifest_sha256='b' * 64, profile_sha256='c' * 64)
        self.output = self.root / 'timing'

    def run_child(self, script, **kwargs):
        return T.measure([sys.executable, '-B', '-c', script], self.output, 'warm', self.context, 5, **kwargs)

    def test_private_diagnostics_and_allowlisted_sidecar(self):
        self.run_child("import sys; print('secret-origin customer command'); print('secret-token', file=sys.stderr)")
        summary = I.load(self.output / 'timing.json')
        self.assertEqual(summary['status'], 'completed')
        self.assertNotIn('secret', (self.output / 'timing.json').read_text())
        for name in ('stdout.log', 'stderr.log', 'timing.json'):
            self.assertEqual((self.output / name).stat().st_mode & 0o777, 0o600)
        self.assertIn('secret-token', (self.output / 'stderr.log').read_text())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)

    def test_exact_failure_status_and_signal_status(self):
        with self.assertRaises(T.RunFailed) as failure:
            self.run_child('raise SystemExit(23)')
        self.assertEqual(failure.exception.code, 23)
        self.output = self.root / 'signalled'
        with self.assertRaises(T.RunFailed) as failure:
            self.run_child('import os, signal; os.kill(os.getpid(), signal.SIGTERM)')
        self.assertEqual(failure.exception.code, -signal.SIGTERM)
        self.assertEqual(I.load(self.output / 'timing.json')['cleanup'], 'unproven')

    def test_signal_exit_is_real_signal(self):
        command = [sys.executable, '-B', '-c',
            'import sys; sys.path.insert(0, sys.argv[1]); import release_speed_timing as t; t.exit_status(-15)', str(BEAST)]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, -15)

    def test_cancel_waits_for_child_cleanup_and_preserves_signal(self):
        ready = self.root / 'ready'
        cleaned = self.root / 'cleaned'
        script = f'''import signal, time
from pathlib import Path
def cleanup(number, frame):
    time.sleep(0.1)
    Path({str(cleaned)!r}).write_text('cleaned')
    raise SystemExit(0)
signal.signal(signal.SIGTERM, cleanup)
Path({str(ready)!r}).write_text('ready')
while True: time.sleep(0.01)
'''
        def cancel():
            until = time.monotonic() + 4
            while not ready.exists() and time.monotonic() < until:
                time.sleep(0.01)
            if ready.exists():
                os.kill(os.getpid(), signal.SIGTERM)
        thread = threading.Thread(target=cancel)
        thread.start()
        try:
            with self.assertRaises(T.RunFailed) as failure:
                self.run_child(script, grace=2)
            self.assertEqual(failure.exception.code, -signal.SIGTERM)
            self.assertTrue(cleaned.exists())
            self.assertFalse(I.load(self.output / 'timing.json')['forced'])
        finally:
            thread.join()

    def test_deadline_forced_child_is_never_cleanup_success(self):
        with self.assertRaises(T.RunFailed):
            T.measure([sys.executable, '-B', '-c',
                'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(20)'],
                self.output, 'warm', self.context, 0.2, grace=0.2)
        summary = I.load(self.output / 'timing.json')
        self.assertTrue(summary['forced'])
        self.assertEqual(summary['reason'], 'deadline')
        self.assertEqual(summary['cleanup'], 'unproven')

    def test_acceptance_failure_overrides_zero_exit(self):
        def reject(*_):
            raise ValueError('missing receipt')
        with self.assertRaises(T.RunFailed) as failure:
            self.run_child('pass', accept=reject)
        self.assertEqual(failure.exception.code, 65)
        self.assertEqual(I.load(self.output / 'timing.json')['reason'], 'acceptance_failure')

    def test_unallowlisted_context_and_stale_output_rejected(self):
        with self.assertRaises(ValueError):
            T.measure([], self.output, 'warm', self.context | {'origin': 'private'}, 1)
        self.output.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            self.run_child('pass')

    def args(self, phase='warm'):
        return SimpleNamespace(run='fixture', candidate_dir=self.root / 'candidate', evidence_dir=self.root / 'evidence',
            trusted_public_key='public-key', manage_origin='https://dev.example.test', token_file=self.root / 'session',
            subnet='192.0.2.1/24', state_root=self.root / 'state', allow_device_helper=self.root / 'helper',
            manage_checkout=self.root / 'checkout', predecessor_dir=self.root / 'previous', phase=phase,
            source='a' * 40, candidate_manifest_sha256='b' * 64, predecessor_manifest_sha256='c' * 64)

    def test_complete_runner_delegation_preserves_all_options_and_serial_scenarios(self):
        args = self.args()
        command = S.delegate(args)
        self.assertEqual(command[:3], [sys.executable, '-B', str(S.HELPERS / 'run-production-qualification.py')])
        self.assertNotIn('--published-cold', command)
        for field in ('run', 'candidate_dir', 'evidence_dir', 'trusted_public_key', 'manage_origin', 'token_file',
                      'subnet', 'state_root', 'allow_device_helper', 'manage_checkout', 'predecessor_dir'):
            index = command.index('--' + field.replace('_', '-'))
            self.assertEqual(command[index + 1], str(getattr(args, field)))
        args.phase = 'cold'
        self.assertEqual(S.delegate(args)[-1], '--published-cold')
        self.assertNotIn('--predecessor-dir', S.delegate(args))
        # No replacement phase body or optional scenario flags are introduced.
        source = (S.HELPERS / 'run-production-qualification.py').read_text()
        self.assertIn("phases = ['update', 'rollback', 'fresh']", source)
        self.assertIn("phases = ['cold']", source)

    def test_missing_mixed_duplicate_output_and_wrong_manifest_refused(self):
        args = self.args()
        args.evidence_dir.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'inventory'):
            S.acceptance(args, None, None)
        for name in S.WARM:
            I.write(args.evidence_dir / name, b'{}')
        I.write(args.evidence_dir / 'cybex-james-unexpected.json', b'{}')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            S.acceptance(args, None, None)
        (args.evidence_dir / 'cybex-james-unexpected.json').unlink()
        (args.evidence_dir / S.WARM[0]).write_bytes(b'{"ok":true,"ok":false}')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            S.acceptance(args, None, None)

    def test_cold_acceptance_invokes_current_validator_with_both_members(self):
        args = self.args('cold')
        args.evidence_dir.mkdir(mode=0o700)
        args.candidate_dir.mkdir(mode=0o700)
        I.write(args.candidate_dir / 'cybex-james-release.json', b'{}')
        args.candidate_manifest_sha256 = I.digest(b'{}')
        for name in S.COLD:
            I.write(args.evidence_dir / name, b'{}')
        with patch.object(S.subprocess, 'run') as run:
            S.acceptance(args, None, None)
        command = run.call_args.args[0]
        self.assertIn(str(S.HELPERS / 'release_acceptance.py'), command)
        self.assertEqual(command[command.index('--phase') + 1], 'cold')
        self.assertEqual(command[command.index('--workstation') + 1], str(args.evidence_dir / S.COLD[1]))

    def test_plan_and_candidate_only_never_launch_runner(self):
        args = self.args()
        args.command = 'plan'
        args.candidate_only = True
        args.offline_artifacts = True
        with patch.object(S, 'parser') as parser, patch.object(S, 'metadata', return_value={}), \
                patch.object(S.timing, 'measure') as measure, patch.object(S.resources, 'admission') as admit:
            parser.return_value.parse_args.return_value = args
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                S.main([])
            self.assertFalse(json.loads(output.getvalue())['execution_ready'])
            args.command = 'run'
            with self.assertRaisesRegex(ValueError, 'no-fetch'):
                S.main([])
            measure.assert_not_called()
            admit.assert_not_called()

    def test_warm_inventory_delegates_all_three_real_acceptance_phases(self):
        args = self.args()
        args.evidence_dir.mkdir(mode=0o700)
        args.candidate_dir.mkdir(mode=0o700)
        args.predecessor_dir.mkdir(mode=0o700)
        I.write(args.candidate_dir / 'cybex-james-release.json', b'{}')
        args.candidate_manifest_sha256 = I.digest(b'{}')
        previous = b'{"version":"1.0.0"}\n'
        args.predecessor_manifest_sha256 = I.digest(previous)
        for name in S.WARM:
            I.write(args.evidence_dir / name, previous if name == S.WARM[4] else b'{}\n')
        with patch.object(S.cache, 'verifier') as verifier, patch.object(S.subprocess, 'run') as run:
            verifier.return_value.verify_pair_snapshot.return_value = {'manifest_body': previous, 'manifest': {}}
            verifier.return_value.identity.return_value = {}
            verifier.return_value.canonical = I.canonical
            S.acceptance(args, None, None)
            self.assertEqual([c.args[0][c.args[0].index('--phase') + 1] for c in run.call_args_list],
                             ['prepublication', 'update', 'rollback'])
            run.side_effect = subprocess.CalledProcessError(1, 'validator')
            with self.assertRaises(subprocess.CalledProcessError):
                S.acceptance(args, None, None)

    def test_cache_sidecar_drops_unallowlisted_worker_fields(self):
        with self.assertRaises(T.RunFailed) as failure:
            self.run_child('pass', facts=lambda: {'cache': 'hit', 'bytes': 1, 'origin': 'private'})
        self.assertEqual(failure.exception.code, 65)
        self.assertNotIn('private', (self.output / 'timing.json').read_text())
        self.assertEqual(I.load(self.output / 'timing.json')['reason'], 'acceptance_failure')

    def test_spawn_failure_emits_bounded_failure(self):
        with self.assertRaises(T.RunFailed) as failure:
            T.measure(['/nonexistent/fixture-runner'], self.output, 'warm', self.context, 1)
        self.assertEqual(failure.exception.code, 70)
        summary = I.load(self.output / 'timing.json')
        self.assertEqual(summary['reason'], 'wrapper_error')
        self.assertNotIn('nonexistent', (self.output / 'timing.json').read_text())


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.value = dict(schema='cybex.james.serial-resources.v1', memory_gib=28, disk_gib=240, cpus=8,
                          subnet='192.0.2.1/24', lease_root=str(self.root), disk_root=str(self.root))
        self.identity = {k: 'a' * 64 for k in ('run_sha256', 'source_sha256', 'manifest_sha256', 'profile_sha256')}
        self.available = dict(memory=44 * R.GIB, disk=340 * R.GIB, cpus=16, load=0)

    def test_headroom_memory_disk_cpu_load_refusal(self):
        R.check(self.value, self.available)
        for name, value in [('memory', 44 * R.GIB - 1), ('disk', 340 * R.GIB - 1), ('cpus', 9), ('load', 7)]:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'headroom'):
                R.check(self.value, self.available | {name: value})

    def test_profile_minima_and_explicit_single_subnet(self):
        path = self.root / 'profile.json'
        I.write(path, I.canonical(self.value))
        self.assertEqual(R.profile(path, 'warm'), self.value)
        for update in ({'memory_gib': 27}, {'cpus': 32}, {'subnet': '192.0.2.1/25'}, {'subnet': '192.0.2.0/24'}):
            path.write_bytes(I.canonical(self.value | update))
            with self.assertRaises(ValueError):
                R.profile(path, 'warm')
        path.write_bytes(I.canonical(self.value))
        with self.assertRaises(ValueError):
            R.profile(path, 'cold')

    def test_host_lock_and_failed_lease_block_later_admission(self):
        host = self.root / 'host.lock'
        with patch.object(R, 'HOST_LOCK', host), patch.object(R, 'availability', return_value=self.available):
            with I.lock(host):
                with self.assertRaises(BlockingIOError), R.admission(self.value, self.identity):
                    self.fail('must not admit')
            with R.admission(self.value, self.identity):
                self.assertTrue((self.root / 'active.json').exists())
            self.assertFalse((self.root / 'active.json').exists())
            with self.assertRaises(RuntimeError), R.admission(self.value, self.identity):
                raise RuntimeError('cleanup unproven')
            with self.assertRaisesRegex(ValueError, 'ownership'), R.admission(self.value, self.identity):
                self.fail('must not readmit')

    def test_low_headroom_creates_no_lease(self):
        with patch.object(R, 'HOST_LOCK', self.root / 'host.lock'), patch.object(R, 'availability',
                return_value=self.available | {'memory': 0}):
            with self.assertRaises(ValueError), R.admission(self.value, self.identity):
                self.fail('must not admit')
        self.assertFalse((self.root / 'active.json').exists())


if __name__ == '__main__':
    unittest.main()
