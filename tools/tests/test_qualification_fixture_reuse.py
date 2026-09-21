import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

HELPERS = Path(__file__).resolve().parents[2] / 'ubuntu-appliance/qualification'
sys.path.insert(0, str(HELPERS))
spec = importlib.util.spec_from_file_location('isolated_update_reuse', HELPERS / 'run-isolated-update.py')
update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update)


class FixtureReuseTests(unittest.TestCase):
    def run_paths(self, root, fixture, **mode):
        update.qualify_paths(Mock(), fixture, root / 'manifest', root / 'predecessor',
                             'http://fixture/package', root / 'upgrade.json',
                             root / 'temporary', root / 'session', **mode)

    def test_same_live_fixture_rolls_back_before_the_unchanged_upgrade_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = Mock(device='owned-device')
            order = []
            fixture.wait_ready.side_effect = lambda api: order.append('ready')
            with patch.object(update.rollback_lifecycle, 'run') as rollback, \
                 patch.object(update.subprocess, 'run') as execute:
                def complete_rollback(api, actual, manifest, evidence, transport, output):
                    self.assertIs(actual, fixture)
                    self.assertEqual(evidence, root / 'predecessor')
                    self.assertEqual(output, root / 'rollback.json')
                    order.append('rollback')
                rollback.side_effect = complete_rollback
                execute.side_effect = lambda *args, **kwargs: order.append('upgrade')
                self.run_paths(root, fixture, rollback_output=root / 'rollback.json')
                self.assertEqual(order, ['ready', 'rollback', 'upgrade'])
                args, kwargs = execute.call_args
                command = args[0]
                self.assertEqual(command[:2], ['bash', str(HELPERS / 'run-update-lifecycle.sh')])
                self.assertEqual(command[command.index('--predecessor-evidence') + 1], str(root / 'predecessor'))
                self.assertEqual(command[command.index('--server-device-id') + 1], fixture.device)
                self.assertEqual(command[command.index('--output') + 1], str(root / 'upgrade.json'))
                self.assertTrue(kwargs['check'])

    def test_failed_rollback_never_attempts_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(update.rollback_lifecycle, 'run', side_effect=ValueError('identity mismatch')), \
                 patch.object(update.subprocess, 'run') as execute:
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    self.run_paths(Path(directory), Mock(), rollback_output=Path(directory) / 'rollback.json')
                execute.assert_not_called()

    def test_standalone_modes_preserve_separate_lifecycle_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(update.rollback_lifecycle, 'run') as rollback, \
                 patch.object(update.subprocess, 'run') as execute:
                self.run_paths(root, Mock(), rollback_only=True)
                self.assertEqual(rollback.call_args.args[-1], root / 'upgrade.json')
                execute.assert_not_called()
                rollback.reset_mock()
                self.run_paths(root, Mock())
                rollback.assert_not_called()
                execute.assert_called_once()

    def test_conflicting_modes_fail_before_touching_fixture(self):
        fixture = Mock()
        with self.assertRaises(ValueError):
            self.run_paths(Path('/unused'), fixture, rollback_only=True, rollback_output=Path('/unused/rollback'))
        fixture.wait_ready.assert_not_called()


if __name__ == '__main__':
    unittest.main()
