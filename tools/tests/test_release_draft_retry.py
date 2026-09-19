"""Exercise the actual draft cleanup shell with a private, fake GitHub API."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
REVISION = '2' * 40
BUNDLE = 'cybex-workstation-netboot-1.0.67-9bc0d5862bc1-x86_64-linux.tar.zst'
ASSETS = [
    'cybex-james-x86_64-linux',
    'cybex-james-appliance-template-0.2.2-x86_64-linux.iso',
    'cybex-james-appliance-packages-0.2.2-x86_64-linux.tar.zst',
    BUNDLE, 'cybex-james-release.json', 'cybex-james-release-compatibility.json',
    'SHA256SUMS', 'cybex-james-ubuntu-qualification.json',
    'cybex-james-build-predecessor.json', 'cybex-james-ubuntu-update-qualification.json',
    'cybex-james-ubuntu-rollback-qualification.json',
]
BODY = '\n'.join([
    'Cybex-Release-Workflow: https://github.com/CybexHQ/james/actions/runs/42',
    'Cybex-Candidate-Artifact-ID: 100',
    'Cybex-Candidate-Artifact-SHA256: ' + 'a' * 64,
])
FAKE_GH = """#!/usr/bin/env python3
import json, os, pathlib, sys
data = json.loads(pathlib.Path(os.environ['TEST_API']).read_text())
arguments = sys.argv[1:]
if 'repos/CybexHQ/james/commits/v0.2.2' in arguments:
    print(data['revision'])
elif 'repos/CybexHQ/james/releases?per_page=100' in arguments:
    print(json.dumps([[data['release']]]))
elif 'repos/CybexHQ/james/releases/123/assets?per_page=100' in arguments:
    print(json.dumps(data['assets']))
elif 'repos/CybexHQ/james/releases/123' in arguments and 'DELETE' in arguments:
    pathlib.Path(os.environ['TEST_DELETED']).write_text('123')
else:
    raise SystemExit('Unexpected fake GitHub endpoint')
"""


class DraftRetryTests(unittest.TestCase):
    def setUp(self):
        self.data = {'revision': REVISION,
            'release': {'id': 123, 'tag_name': 'v0.2.2', 'draft': True,
                'immutable': False, 'name': 'Cybex James v0.2.2', 'body': BODY},
            'assets': [{'name': name} for name in ASSETS]}

    def cleanup(self, data):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        step = workflow.split('      - name: Remove only a stale draft for this exact tag\n', 1)[1]
        step = step.split('\n      - name:', 1)[0]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'gh').write_text(FAKE_GH)
            (root / 'gh').chmod(0o755)
            (root / 'api.json').write_text(json.dumps(data))
            result = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                    'TEST_API': str(root / 'api.json'), 'TEST_DELETED': str(root / 'deleted'),
                    'RUNNER_TEMP': str(root), 'GITHUB_SHA': REVISION,
                    'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_REPOSITORY': 'CybexHQ/james',
                    'GITHUB_REF_NAME': 'v0.2.2', 'GITHUB_RUN_ID': '42',
                    'CYBEX_JAMES_RELEASE_VERSION': '0.2.2',
                    'CYBEX_JAMES_RELEASE_ARTIFACT_ID': '100',
                    'CYBEX_JAMES_RELEASE_ARTIFACT_DIGEST': 'a' * 64,
                    'CYBEX_JAMES_WORKSTATION_BUNDLE_NAME': BUNDLE})
            return result, (root / 'deleted').exists()

    def test_owned_complete_or_partial_draft_can_be_retried(self):
        for assets in (self.data['assets'], self.data['assets'][-1:], []):
            with self.subTest(assets=len(assets)):
                data = copy.deepcopy(self.data)
                data['assets'] = assets
                result, deleted = self.cleanup(data)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(deleted)

    def test_unexpected_or_duplicate_asset_prevents_deletion(self):
        for assets in (self.data['assets'] + [{'name': 'unrelated'}],
                       [{'name': 'unrelated'}], [self.data['assets'][0]] * 2):
            with self.subTest(assets=assets):
                data = copy.deepcopy(self.data)
                data['assets'] = assets
                result, deleted = self.cleanup(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(deleted)

    def test_other_or_published_release_is_never_deleted(self):
        for field, value in [('draft', False), ('immutable', True),
                             ('body', BODY + '\nother run'),
                             ('name', 'Some other release')]:
            with self.subTest(field=field):
                data = copy.deepcopy(self.data)
                data['release'][field] = value
                result, deleted = self.cleanup(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(deleted)

    def test_other_tag_is_ignored(self):
        self.data['release']['tag_name'] = 'v0.2.3'
        result, deleted = self.cleanup(self.data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(deleted)

    def test_moved_tag_is_never_deleted(self):
        self.data['revision'] = '3' * 40
        result, deleted = self.cleanup(self.data)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(deleted)


if __name__ == '__main__':
    unittest.main()
