"""Private fake-runner regression fixtures; no services, VMs or network."""
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'release/beast'))
import release_speed as S
import release_speed_io as I
import release_speed_resources as R


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('candidate', 'previous', 'state', 'disk', 'lease'):
            (self.root / name).mkdir(mode=0o700)
        self.value = dict(schema='cybex.james.serial-resources.v1', memory_gib=28,
            disk_gib=240, cpus=8, subnet='192.0.2.1/24',
            disk_root=str(self.root / 'disk'), lease_root=str(self.root / 'lease'))
        I.write(self.root / 'profile.json', I.canonical(self.value))
        self.args = SimpleNamespace(command='run', phase='warm', candidate_only=False,
            offline_artifacts=False, candidate_dir=self.root / 'candidate',
            predecessor_dir=self.root / 'previous', state_root=self.root / 'state',
            evidence_dir=self.root / 'evidence', timing_dir=self.root / 'timing',
            profile=self.root / 'profile.json', source='a' * 40, run='fixture', attempt='1',
            candidate_manifest_sha256='b' * 64, predecessor_manifest_sha256='c' * 64,
            trusted_public_key='fixture-key', manage_origin='https://dev.example.test',
            subnet='192.0.2.1/24', token_file=self.root / 'session',
            allow_device_helper=self.root / 'helper', manage_checkout=self.root / 'checkout', timeout=5)
        self.available = dict(memory=44 * R.GIB, disk=340 * R.GIB, cpus=16, load=0)

    def invoke(self, script='pass', accept=None, availability=None):
        # Model only the wrapper's root prerequisite; private-path checks and
        # subprocess timing execute under the fixture owner's actual UID.
        with patch.object(S, 'parser') as parser, \
                patch.object(S, 'metadata', return_value=self.value) as metadata, \
                patch.object(S, 'os', SimpleNamespace(geteuid=lambda: 0, environ=os.environ, devnull=os.devnull)), \
                patch.object(R, 'HOST_LOCK', self.root / 'host.lock'), \
                patch.object(R, 'availability', side_effect=availability or (lambda _: self.available)), \
                patch.object(S, 'delegate', return_value=[sys.executable, '-B', '-c', script]) as delegate, \
                patch.object(S, 'acceptance', side_effect=accept) as acceptance, \
                contextlib.redirect_stdout(io.StringIO()):
            parser.return_value.parse_args.return_value = self.args
            S.main([])
            metadata.assert_called_once_with(self.args)
            delegate.assert_called_once_with(self.args)
            acceptance.assert_called_once()

    def test_sudo_child_keeps_private_owner_through_acceptance(self):
        # Reproduce the unchanged runner's SUDO_UID/GID ownership branch without
        # chown privileges: record the requested owner if that branch is reached.
        output = self.args.evidence_dir
        script = f'''import os
from pathlib import Path
p = Path({str(output)!r})
if 'SUDO_UID' in os.environ and 'SUDO_GID' in os.environ:
    (p / 'transferred-owner').write_text('wrong-owner')
(p / 'receipt.json').write_text('{{}}')
(p / 'receipt.json').chmod(0o644)
assert os.environ['FIXTURE_AUTH'] == 'synthetic'
'''
        def accept(*_):
            self.assertFalse((output / 'transferred-owner').exists())
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual(I.load(output / 'receipt.json'), {})
        with patch.dict(os.environ, SUDO_UID='12345', SUDO_GID='12345', FIXTURE_AUTH='synthetic'):
            self.invoke(script, accept)
            self.assertEqual(os.environ['SUDO_UID'], '12345')
        self.assertFalse((self.root / 'lease/active.json').exists())
        self.assertEqual(I.load(self.args.timing_dir / 'timing.json')['status'], 'completed')

    def test_candidate_only_warm_runs_normal_admission_and_acceptance(self):
        self.args.candidate_only = True
        self.invoke()
        self.assertFalse((self.root / 'lease/active.json').exists())

    def test_actual_state_storage_not_roomy_profile_disk_controls_admission(self):
        checked = []
        def availability(path):
            checked.append(Path(path))
            return self.available | {'disk': 0 if Path(path) == self.args.state_root else 340 * R.GIB}
        with self.assertRaisesRegex(ValueError, 'headroom'):
            self.invoke(availability=availability)
        self.assertEqual(checked, [self.args.state_root])
        self.assertFalse(self.args.evidence_dir.exists())
        self.assertFalse((self.root / 'lease/active.json').exists())

    def test_candidate_only_preserves_private_path_rejection(self):
        self.args.candidate_only = True
        self.args.state_root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'Private directory'):
            self.invoke()
        self.assertFalse(self.args.evidence_dir.exists())

    def test_offline_run_refused_independently(self):
        for candidate_only in (False, True):
            with self.subTest(candidate_only=candidate_only):
                self.args.candidate_only = candidate_only
                self.args.offline_artifacts = True
                with self.assertRaisesRegex(ValueError, 'no-fetch'):
                    self.invoke()
                self.assertFalse(self.args.evidence_dir.exists())

    def test_candidate_only_still_requires_exact_clean_source(self):
        self.args.candidate_only = True
        with patch.object(S.subprocess, 'check_output', return_value='d' * 40), \
                self.assertRaisesRegex(ValueError, 'Exact clean source'):
            S.metadata(self.args)

    def test_candidate_only_cold_cannot_claim_published_proof(self):
        self.args.phase = 'cold'
        self.args.candidate_only = True
        self.args.predecessor_dir = None
        body = b'{}'
        self.args.candidate_manifest_sha256 = I.digest(body)
        with patch.object(S.subprocess, 'check_output', side_effect=[self.args.source, '']), \
                patch.object(R, 'profile', return_value=self.value), patch.object(S.cache, 'verifier') as verifier:
            verifier.return_value.verify_pair_snapshot.return_value = dict(manifest_body=body, manifest={
                'appliance_release_v1': {'source_revision': self.args.source},
                'installer_iso_template_v3': {'manage_origin': self.args.manage_origin}})
            with self.assertRaisesRegex(ValueError, 'independent published-download'):
                S.metadata(self.args)


if __name__ == '__main__':
    unittest.main()
