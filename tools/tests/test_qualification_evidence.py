"""Retries cannot consume old evidence or strand sudo-owned runner output."""
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / 'nixos-appliance/qualification'
with patch.object(sys, 'path', [str(HELPERS), *sys.path]):
    spec = importlib.util.spec_from_file_location('qualification_runner', HELPERS / 'run-production-qualification.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)


class QualificationEvidenceTests(unittest.TestCase):
    def invoke(self, evidence, candidate, failure=None):
        state_root = Mock()
        state_root.is_symlink.return_value = False
        state_root.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        args = SimpleNamespace(run='release-42-2', manage_origin='https://dev.example.com',
            token_file=Path('/unused-session'), subnet='10.249.217.1/24', state_root=state_root,
            isolated_manage_config=None, allow_device_helper=None, manage_checkout=None,
            candidate_dir=candidate, evidence_dir=evidence, trusted_public_key='test-key')
        with patch.object(runner.argparse.ArgumentParser, 'parse_args', return_value=args), \
                patch.object(runner.os, 'geteuid', return_value=0), \
                patch.object(runner.os, 'umask'), patch.object(runner.signal, 'signal'), \
                patch.dict(os.environ, {'SUDO_UID': '1000', 'SUDO_GID': '1000'}), \
                patch.object(runner.os, 'chown') as chown, \
                patch.object(runner, 'verify_candidate', side_effect=failure) as verify:
            try:
                runner.main()
            finally:
                self.chown_calls = chown.call_args_list
                self.verify_calls = verify.call_args_list

    def test_old_success_is_rejected_before_candidate_checks_and_never_modified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / 'evidence'
            evidence.mkdir(mode=0o700)
            old = evidence / 'cybex-james-nixos-update-qualification.json'
            old.write_text('{"candidate_release":"0.2.19","ok":true}')
            before = old.read_bytes()
            with self.assertRaisesRegex(ValueError, 'new run/attempt directory'):
                self.invoke(evidence, root)
            self.assertEqual(old.read_bytes(), before)
            self.assertEqual(self.verify_calls, [])
            self.assertEqual(self.chown_calls, [])

    def test_existing_empty_directory_and_symlink_are_not_claimed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / 'existing'
            existing.mkdir(mode=0o755)
            existing.chmod(0o755)
            link = root / 'link'
            link.symlink_to(existing)
            for path in (existing, link):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'already exists'):
                    self.invoke(path, root)
                self.assertEqual(self.chown_calls, [])
                self.assertEqual(self.verify_calls, [])
            self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o755)

    def test_candidate_failure_or_interruption_returns_directory_without_publishing_files(self):
        for error in (ValueError('invalid candidate'), KeyboardInterrupt('canceled')):
            with self.subTest(error=type(error)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = root / 'evidence'
                def fail(*_args):
                    private = evidence / 'cybex-james-partial.json'
                    private.write_text('private partial diagnostic')
                    private.chmod(0o600)
                    raise error
                with self.assertRaises(type(error)) as caught:
                    self.invoke(evidence, root, fail)
                self.assertIs(caught.exception, error)
                self.assertEqual(len(self.chown_calls), 1)
                self.assertEqual(self.chown_calls[0].args, (evidence, 1000, 1000))
                self.assertEqual(self.chown_calls[0].kwargs, {'follow_symlinks': False})
                self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((evidence / 'cybex-james-partial.json').stat().st_mode), 0o600)

    def test_success_also_returns_directory_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / 'evidence'
            with patch.object(runner, 'qualify') as qualify:
                self.invoke(evidence, root)
            qualify.assert_called_once()
            self.assertEqual(self.chown_calls[0].args, (evidence, 1000, 1000))


if __name__ == '__main__':
    unittest.main()
