"""Exercise candidate admission before any network or VM operation."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
HARNESS = REPOSITORY / "nixos-appliance/qualification/run-lifecycle.sh"
WORKFLOW = REPOSITORY / ".github/workflows/release.yml"


class CandidateSourceContractTests(unittest.TestCase):
    def test_workflow_signs_the_checked_out_james_revision(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        manifest_command = workflow.split(
            "python3 tools/james-release.py manifest \\\n", 1
        )[1].split("python3 tools/james-release.py compatibility", 1)[0]
        self.assertIn(
            '--appliance-source-revision "$(git rev-parse HEAD)"',
            manifest_command,
        )

    def test_candidate_requires_nixos_v3_exact_clean_source_before_artifact_checks(self):
        import importlib.util
        from unittest.mock import Mock, patch
        helpers = REPOSITORY / 'nixos-appliance/qualification'
        with patch.object(sys, 'path', [str(helpers), *sys.path]):
            spec = importlib.util.spec_from_file_location('candidate_runner', helpers / 'run-production-qualification.py')
            runner = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(runner)
        source = 'a' * 40
        artifact = {'url': 'https://github.com/example/asset', 'sha256': 'b' * 64, 'size_bytes': 1}
        manifest = {'appliance_release_v1': {'schema': 'cybex.james.appliance-release.v3',
                    'source_revision': source, 'system_closure': artifact},
                    'installer_iso_template_v3': {**artifact, 'template_sha256': 'b' * 64,
                                                 'manage_origin': 'https://manage.cybex.net'},
                    'workstation_netboot': artifact}
        for schema, revision in [('cybex.james.appliance-release.v2', source),
                                  ('cybex.james.appliance-release.v3', 'c' * 40)]:
            candidate = {**manifest, 'appliance_release_v1': {**manifest['appliance_release_v1'],
                         'schema': schema, 'source_revision': revision}}
            with patch.object(runner.predecessor, 'verify_pair', return_value=candidate), \
                    patch.object(runner.subprocess, 'check_output', return_value=source), \
                    patch.object(runner.predecessor, 'check_file') as artifact_check:
                with self.assertRaises(ValueError):
                    runner.verify_candidate(Path('/candidate'), 'key', 'https://manage.cybex.net')
                artifact_check.assert_not_called()
        with patch.object(runner.predecessor, 'verify_pair', return_value=manifest), \
                patch.object(runner.subprocess, 'check_output', side_effect=[source, 'dirty']), \
                patch.object(runner.predecessor, 'check_file') as artifact_check:
            with self.assertRaisesRegex(ValueError, 'clean'):
                runner.verify_candidate(Path('/candidate'), 'key', 'https://manage.cybex.net')
            artifact_check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
