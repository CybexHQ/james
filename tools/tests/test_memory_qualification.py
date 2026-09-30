"""Exercise qualification result semantics without running a disposable VM."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'qualify_memory', Path(__file__).resolve().parents[1] / 'qualify-memory.py')
MEMORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MEMORY)


class MemoryQualificationTests(unittest.TestCase):
    def execute(self, hours=None, elapsed=510):
        row = {'seconds': 100, 'served_bytes': 1000000, 'traffic_seconds': 100,
               'path_p95_seconds': {'cache': .01, 'file': .01, 'ipxe': .01}}
        result = {'elapsed_seconds': elapsed, 'runs': [row] * 5}
        argv = ['qualify-memory.py', '--output', '/unused/results.json']
        if hours is not None:
            argv += ['--soak-hours', str(hours)]
        self.writes = []
        with patch('sys.argv', argv), \
                patch.object(Path, 'read_text', return_value='disposable component fixture\n'), \
                patch.object(MEMORY, 'prepare'), \
                patch.object(MEMORY, 'run', return_value='fixture'), \
                patch.object(MEMORY, 'trial', return_value=result) as trial, \
                patch.object(MEMORY, 'write_evidence', side_effect=lambda p, e: self.writes.append(copy.deepcopy(e))):
            MEMORY.main()
            return self.writes[-1], trial.call_args_list

    def test_default_bounded_comparison_does_not_claim_a_soak(self):
        evidence, calls = self.execute()
        self.assertTrue(evidence['performance_pass'])
        self.assertEqual(evidence['component_soak_hours'], 0)
        self.assertFalse(evidence['soak_complete'])
        self.assertEqual([call.args[:3] for call in calls],
                         [('baseline', 5, 0), ('candidate', 5, 0)])

    def test_optional_duration_uses_the_requested_hours(self):
        evidence, _ = self.execute(hours=1, elapsed=3601)
        self.assertTrue(evidence['soak_complete'])
        self.assertEqual(evidence['component_soak_hours'], 1)

    def test_incomplete_requested_soak_fails_and_preserves_evidence(self):
        with self.assertRaisesRegex(RuntimeError, 'optional soak duration'):
            self.execute(hours=1, elapsed=3599)
        self.assertFalse(self.writes[-1]['soak_complete'])


if __name__ == '__main__':
    unittest.main()
