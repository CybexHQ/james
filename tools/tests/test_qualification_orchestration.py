import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HELPERS = Path(__file__).resolve().parents[2] / 'ubuntu-appliance/qualification'
sys.path.insert(0, str(HELPERS))
spec = importlib.util.spec_from_file_location('production_reuse', HELPERS / 'run-production-qualification.py')
production = importlib.util.module_from_spec(spec)
spec.loader.exec_module(production)


class ProductionReuseTests(unittest.TestCase):
    def exercise(self, root, fail_update=False, cold=False):
        candidate, predecessor, state = (root / name for name in ['candidate', 'predecessor', 'state'])
        for path in [candidate, predecessor, state]:
            path.mkdir()
        (candidate / production.predecessor.MANIFEST).write_text(json.dumps({
            'version': '0.2.11', 'appliance_release_v1': {'source_revision': 'source'}}))
        (candidate / 'cybex-james-build-predecessor.json').write_text('{}')
        (predecessor / production.predecessor.COMPATIBILITY).write_text(json.dumps({
            'release_manifest': {'url': 'https://example.test/predecessor'}}))
        args = argparse.Namespace(run='owned', candidate_dir=candidate, predecessor_dir=predecessor,
                                  evidence_dir=root / 'evidence', trusted_public_key='key', published_cold=cold)
        executions, scopes = [], []
        def execute(*command):
            executions.append(command)
            if 'prepare' in command:
                folder = state / command[-3] if command[-2] == '--manifest-url' else None
                folder.mkdir()
                (folder / 'isolation.json').write_text('{}')
        def scoped(name, *arguments, **kwargs):
            scopes.append((name, arguments))
            if fail_update and name.endswith('-update'):
                raise ValueError('rollback failed')
        with contextlib.ExitStack() as stack:
            for target, value in [('STATE', state), ('execute', execute), ('scoped', scoped)]:
                stack.enter_context(patch.object(production, target, value))
            stack.enter_context(patch.object(argparse.ArgumentParser, 'parse_args', return_value=args))
            stack.enter_context(patch.object(production.os, 'geteuid', return_value=0))
            stack.enter_context(patch.dict(production.os.environ, {}, clear=True))
            stack.enter_context(patch.object(production.subprocess, 'check_output', return_value='source'))
            stack.enter_context(patch.object(production.predecessor, 'verify_pair'))
            stack.enter_context(patch.object(production.predecessor, 'checked_json', return_value=({'update_contract': 'selective_roots_v2', 'release_manifest_sha256': 'hash'}, None)))
            stack.enter_context(patch.object(production.predecessor, 'sha', return_value='hash'))
            stack.enter_context(patch.object(production.fcntl, 'flock'))
            stack.enter_context(patch.object(production.signal, 'signal'))
            stack.enter_context(patch.object(production, 'open', return_value=io.StringIO(), create=True))
            if fail_update:
                with self.assertRaisesRegex(ValueError, 'rollback failed'):
                    production.main()
            else:
                production.main()
        return executions, scopes

    def test_one_predecessor_install_covers_both_update_paths_and_fresh_remains(self):
        with tempfile.TemporaryDirectory() as directory:
            executions, scopes = self.exercise(Path(directory))
            self.assertEqual([name for name, _ in scopes], ['owned-upgrade-install', 'owned-upgrade-update', 'owned-fresh-install'])
            update = scopes[1][1]
            self.assertIn('--rollback-output', update)
            self.assertEqual(update[update.index('--rollback-output') + 1].name, 'cybex-james-ubuntu-rollback-qualification.json')
            self.assertIn('--prepublication-candidate', scopes[2][1])
            self.assertEqual(len([c for c in executions if 'cleanup' in c]), 2)

    def test_failed_update_cleans_owned_fixture_and_never_runs_fresh(self):
        with tempfile.TemporaryDirectory() as directory:
            executions, scopes = self.exercise(Path(directory), fail_update=True)
            self.assertEqual([name for name, _ in scopes], ['owned-upgrade-install', 'owned-upgrade-update'])
            self.assertEqual(len([c for c in executions if 'cleanup' in c]), 1)

    def test_published_cold_install_and_workstation_acceptance_remain_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            executions, scopes = self.exercise(Path(directory), cold=True)
            self.assertEqual([name for name, _ in scopes], ['owned-cold-install', 'owned-cold-workstation'])
            self.assertIn('--require-candidate-runtime', scopes[0][1])
            self.assertEqual(len([c for c in executions if 'cleanup' in c]), 1)


if __name__ == '__main__':
    unittest.main()
