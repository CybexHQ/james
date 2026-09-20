import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('candidate', ROOT / 'tools/local-candidate.py')
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class LocalCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.store = self.path / 'store'
        self.source = self.path / 'dist'
        self.source.mkdir()
        (self.source / 'manifest.json').write_text('signed immutable manifest')
        (self.source / 'payload').write_bytes(b'large payload represented by small test data')
        self.expected = candidate.identity('42', 'a' * 40, 'v0.2.8')
        self.proof = self.path / 'receipt.json'

    def seal(self):
        candidate.seal(self.store, self.expected, self.source, self.proof)

    def test_retry_restores_identical_bytes_and_never_mutates_store(self):
        self.assertFalse(candidate.select(self.store, self.expected, 1))
        self.seal()
        self.assertTrue(candidate.select(self.store, self.expected, 2))
        self.seal()  # Lost upload response can retry without signing again.
        target = self.path / 'restored'
        candidate.restore(self.store, self.expected, target, self.proof)
        self.assertEqual(candidate.inventory(target), candidate.inventory(self.source))
        self.assertLess(self.proof.stat().st_size, 2048)
        (target / 'payload').chmod(0o600)
        (target / 'payload').write_bytes(b'consumer mutation')
        self.assertTrue(candidate.select(self.store, self.expected, 2))

    def test_retry_without_retained_bytes_cannot_rebuild(self):
        with self.assertRaisesRegex(ValueError, 'never rebuild'):
            candidate.select(self.store, self.expected, 2)

    def test_changed_local_bytes_or_remote_receipt_prevents_restore(self):
        self.seal()
        wrong = json.loads(self.proof.read_text())
        wrong['files']['payload']['sha256'] = 'b' * 64
        self.proof.write_text(json.dumps(wrong))
        with self.assertRaisesRegex(ValueError, 'differs'):
            candidate.restore(self.store, self.expected, self.path / 'bad', self.proof)
        (self.store / '42/files/payload').chmod(0o600)
        (self.store / '42/files/payload').write_bytes(b'corrupted disk bytes')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            candidate.select(self.store, self.expected, 2)

    def test_seal_refuses_replacement_or_unsafe_inventory(self):
        self.seal()
        (self.source / 'payload').write_bytes(b'different signed candidate')
        with self.assertRaisesRegex(ValueError, 'overwrite'):
            self.seal()
        (self.source / 'link').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'regular release files'):
            candidate.inventory(self.source)
        for key, value in [('run', '43'), ('source', 'b' * 40), ('tag', 'v0.2.9')]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'different run'):
                candidate.receipt(self.proof, self.expected | {key: value})

    def test_receipt_download_checks_zip_digest_and_workflow_identity(self):
        self.seal()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('candidate.json', self.proof.read_bytes())
        body = stream.getvalue()
        sha = hashlib.sha256(body).hexdigest()
        metadata = {'expired': False, 'size_in_bytes': len(body),
                    'name': 'cybex-james-release-candidate-42', 'digest': 'sha256:' + sha,
                    'workflow_run': {'id': 42, 'head_sha': 'a' * 40}}
        output = self.path / 'downloaded.json'
        with patch.object(candidate.subprocess, 'check_output', side_effect=[json.dumps(metadata), body]):
            candidate.download_receipt(self.expected, '123', sha, output)
        self.assertEqual(output.read_bytes(), self.proof.read_bytes())
        with patch.object(candidate.subprocess, 'check_output', side_effect=[json.dumps(metadata), body + b'changed']):
            with self.assertRaisesRegex(ValueError, 'download digest'):
                candidate.download_receipt(self.expected, '123', sha, output)
        for override in ({'expired': True}, {'size_in_bytes': 4 * 1024**3},
                         {'workflow_run': {'id': 43, 'head_sha': 'a' * 40}}):
            with self.subTest(override=override), patch.object(candidate.subprocess, 'check_output',
                    return_value=json.dumps(metadata | override)) as api:
                with self.assertRaisesRegex(ValueError, 'provenance'):
                    candidate.download_receipt(self.expected, '123', sha, output)
                self.assertEqual(api.call_count, 1)

    def test_cold_download_never_uses_local_candidate_files(self):
        self.seal()
        target = self.path / 'cold'
        arguments = ['local-candidate.py', 'published', '--run', '42', '--source', 'a' * 40,
                     '--tag', 'v0.2.8', '--receipt', str(self.proof), '--directory', str(target),
                     '--root', str(self.path / 'nonexistent-local-store')]

        def download(args, check):
            self.assertEqual(args[:3], ['gh', 'release', 'download'])
            name = args[args.index('--pattern') + 1]
            (target / name).write_bytes((self.source / name).read_bytes())

        with patch.object(sys, 'argv', arguments), patch.object(candidate.subprocess, 'run', side_effect=download):
            candidate.main()
        self.assertEqual(candidate.inventory(target), candidate.inventory(self.source))
        self.assertFalse((self.path / 'nonexistent-local-store').exists())

    def test_retention_prunes_only_expired_recognized_candidates(self):
        import os
        self.seal()
        unrelated = self.store / 'operator-notes'
        unrelated.write_text('retain')
        candidate.prune(self.store)
        self.assertTrue((self.store / '42').exists())
        os.utime(self.store / '42', (1, 1))
        candidate.prune(self.store)
        self.assertFalse((self.store / '42').exists())
        self.assertEqual(unrelated.read_text(), 'retain')


if __name__ == '__main__':
    unittest.main()
