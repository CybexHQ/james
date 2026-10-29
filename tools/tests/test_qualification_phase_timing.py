"""Independent fixtures share input bytes, never lifecycle success or live state."""
import contextlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'


def load(name):
    spec = importlib.util.spec_from_file_location('timing_test_' + name, HELPERS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'path', [str(HELPERS), *sys.path]):
        spec.loader.exec_module(module)
    return module


class QualificationPhaseTests(unittest.TestCase):
    def run_fixture(self, root, *, cold=False, failure=None):
        runner = load('run-production-qualification')
        fixture = load('production_fixture')
        for name in ('candidate', 'predecessor', 'evidence', 'state'):
            (root / name).mkdir(mode=0o700)
        manifest = {'version': '0.2.10', 'installer_iso_template_v3': {
                    'manage_origin': 'https://manage.cybex.net'}}
        for name in ('candidate', 'predecessor'):
            (root / name / runner.predecessor.MANIFEST).write_text(json.dumps(manifest))
            (root / name / 'payload').write_bytes(name.encode())
        args = SimpleNamespace(run='release-123-1', published_cold=cold,
            candidate_dir=root / 'candidate', predecessor_dir=None if cold else root / 'predecessor',
            evidence_dir=root / 'evidence', state_root=root / 'state', trusted_public_key='public',
            manage_origin='https://manage.cybex.net', isolated_manage_config=root / 'config',
            subnet='10.99.1.1/24', allow_device_helper=None, manage_checkout=None)
        entries, exits, owners, commands, input_paths = [], [], [], [], []

        @contextlib.contextmanager
        def owned(state, config, candidate, predecessor, phase, **kwargs):
            # Exercise separate retained owners with one read-only source copy.
            entries.append(phase)
            input_paths.append((candidate, predecessor))
            self.assertEqual((candidate / 'payload').read_bytes(), b'candidate')
            self.assertEqual((predecessor / 'payload').read_bytes(), b'candidate' if cold else b'predecessor')
            (root / 'candidate' / 'payload').write_bytes(b'changed producer workspace')
            owner = Mock()
            owner.verify.return_value = {'manage_origin': args.manage_origin,
                'source_revision': 'a' * 40, 'owner': 'owner-' + phase}
            owners.append(owner)
            try:
                yield owner
            finally:
                exits.append(phase)

        def execute(*command, **kwargs):
            commands.append(command)
            if failure and 'run-isolated-update.py' in str(command[2]):
                raise failure
            if '--output' in command:
                Path(command[command.index('--output') + 1]).write_text('{}')

        def scope(args):
            args.state_dir.mkdir(mode=0o700)

        with patch.object(runner, 'verify_candidate', return_value=manifest), \
             patch.object(runner.predecessor, 'qualify', return_value={'release_id': '0.2.9'}), \
             patch.dict(runner.SCOPE, {'prepare': scope,
                 'read_scope': lambda state: {'bridge': state.name}}), \
             patch.object(runner, 'execute', side_effect=execute), \
             patch.object(fixture, 'fixture', side_effect=owned), \
             patch.object(fixture, 'stage_artifacts', wraps=fixture.stage_artifacts) as stage, \
             patch.dict(sys.modules, {'production_fixture': fixture}):
            error = None
            try:
                runner.qualify(args)
            except BaseException as caught:
                error = caught
            self.assertEqual(stage.call_count, 1 if cold else 2)
        self.assertFalse(list(args.state_root.glob('jnq-inputs-*')))
        self.assertEqual(entries, exits)
        timing = json.loads((args.evidence_dir / 'tiaris-nest-qualification-timing.json').read_text())
        return args, entries, owners, commands, input_paths, timing, error

    def test_warm_stages_inputs_once_but_creates_and_cleans_three_independent_fixtures(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, entries, owners, commands, paths, timing, error = self.run_fixture(Path(temporary))
            self.assertIsNone(error)
            self.assertEqual(entries, ['update', 'rollback', 'fresh'])
            self.assertEqual(len({id(owner) for owner in owners}), 3)
            self.assertEqual(len(set(paths)), 1)
            self.assertEqual(sum('run-isolated-lifecycle.py' in str(c[2]) for c in commands), 3)
            self.assertEqual(sum('run-isolated-update.py' in str(c[2]) for c in commands), 2)
            for owner in owners:
                owner.verify.assert_called_once()
            for owner in owners[:2]:
                owner.select_release.assert_called_once_with('candidate')
            self.assertEqual(timing['parallelism'], 1)
            self.assertEqual(timing['stages'][0]['status'], 'passed')
            for phase in entries:
                stages = [s for s in timing['stages'] if s['phase'] == phase]
                self.assertEqual(stages[0]['stage'], 'total')
                self.assertEqual(stages[-1]['stage'], 'cleanup')
                self.assertTrue(all(s['status'] == 'passed' and s['elapsedSeconds'] >= 0 for s in stages))
            self.assertEqual((args.evidence_dir / 'tiaris-nest-qualification-timing.json').stat().st_mode & 0o777, 0o644)

    def test_failed_or_interrupted_transition_persists_timing_and_cleans_before_stopping(self):
        for failure, status in ((ValueError('private token=not-for-export'), 'failed'),
                                (KeyboardInterrupt('private secret'), 'interrupted')):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                _, entries, _, commands, _, timing, error = self.run_fixture(Path(temporary), failure=failure)
                self.assertIs(error, failure)
                self.assertEqual(entries, ['update'])
                self.assertEqual(timing['stages'][0]['status'], status)
                self.assertEqual(next(s for s in timing['stages'] if s['stage'] == 'transition')['status'], status)
                self.assertEqual(timing['stages'][-1]['stage'], 'cleanup')
                self.assertEqual(timing['stages'][-1]['status'], 'passed')
                self.assertIn('development-scope.py', str(commands[-1][2]))
                self.assertNotIn('private', json.dumps(timing))
                self.assertNotIn('not-for-export', json.dumps(timing))

    def test_cold_uses_only_one_independent_published_snapshot_and_one_workstation_sequence(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, entries, _, commands, paths, timing, error = self.run_fixture(Path(temporary), cold=True)
            self.assertIsNone(error)
            self.assertEqual(entries, ['cold'])
            self.assertEqual(paths[0][0], paths[0][1])
            self.assertFalse(any('run-isolated-update.py' in str(c[2]) for c in commands))
            self.assertEqual(sum('run-isolated-workstation.py' in str(c[2]) for c in commands), 1)
            self.assertEqual(sum(s['stage'] == 'workstation' for s in timing['stages']), 1)

    def test_timing_is_durable_before_stage_runs_and_keeps_prior_attempt(self):
        module = load('phase_timing')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            timing = module.Timing(root, 'release-123-1', False)
            with timing.measure('fresh', 'lifecycle'):
                current = json.loads(timing.path.read_text())
                self.assertEqual(current['stages'][0]['status'], 'running')
                self.assertNotIn('elapsedSeconds', current['stages'][0])
            completed = timing.path.read_bytes()
            with self.assertRaisesRegex(ValueError, 'already exists'):
                module.Timing(root, 'release-123-1', False)
            self.assertEqual(timing.path.read_bytes(), completed)
            with self.assertRaisesRegex(ValueError, 'Unknown'):
                with timing.measure('fresh', 'token=hidden'):
                    pass

    def test_timing_disk_failure_never_skips_mandatory_cleanup(self):
        module = load('phase_timing')
        with tempfile.TemporaryDirectory() as temporary:
            timing = module.Timing(Path(temporary), 'release-123-1', False)
            cleanup = Mock()
            with patch.object(timing, '_save', side_effect=OSError('private path unavailable')), \
                 patch.object(module.sys, 'stderr'):
                with timing.measure('fresh', 'cleanup'):
                    cleanup()
            cleanup.assert_called_once()
            self.assertEqual(timing.document['persistenceFailures'], 2)
            self.assertEqual(timing.document['stages'][0]['status'], 'passed')


if __name__ == '__main__':
    unittest.main()
