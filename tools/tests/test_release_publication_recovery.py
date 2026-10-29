"""Execute publication recovery with private fake GitHub metadata and commands."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from test_release_draft_retry import ASSETS, BODY, BUNDLE, REVISION

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'tools/release-publication.py'
SPEC = importlib.util.spec_from_file_location('release_publication', HELPER)
publication = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publication)

FAKE_GH = r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, sys
path = pathlib.Path(os.environ['TEST_API'])
data = json.loads(path.read_text())
arguments = sys.argv[1:]
data.setdefault('commands', []).append(arguments)
data.setdefault('mutations', [])
status, output, error = 0, '', ''
if arguments[0] == 'api':
    endpoint = next(value for value in arguments if value.startswith('repos/'))
    if endpoint == 'repos/CybexHQ/james/commits/v0.2.2':
        output = data['revision'] if '--jq' in arguments else json.dumps({'sha': data['revision']})
    elif endpoint == 'repos/CybexHQ/james/releases?per_page=100':
        output = json.dumps([[data['release']] if data['release'] else []])
    elif endpoint == 'repos/CybexHQ/james/releases/123/assets?per_page=100':
        output = json.dumps(data['assets'])
    elif endpoint == 'repos/CybexHQ/james/releases/tags/v0.2.2':
        output = json.dumps(data['release'])
    elif endpoint == 'repos/CybexHQ/james/releases/123' and 'DELETE' in arguments:
        data['mutations'].append('delete')
        data['release'] = None
    else:
        status, error = 9, 'Unexpected fake GitHub endpoint'
elif arguments[:2] == ['release', 'create']:
    data['mutations'].append('create')
    data['release'] = {'id': 123, 'tag_name': 'v0.2.2', 'draft': True,
        'immutable': False, 'prerelease': True,
        'target_commitish': arguments[arguments.index('--target') + 1],
        'name': arguments[arguments.index('--title') + 1],
        'body': arguments[arguments.index('--notes') + 1]}
elif arguments[:2] == ['release', 'upload']:
    data['mutations'].append('upload')
    data['assets'] = []
    for filename in arguments[3:]:
        asset = pathlib.Path(filename)
        data['assets'].append({'name': asset.name, 'state': 'uploaded',
            'size': asset.stat().st_size,
            'digest': 'sha256:' + hashlib.sha256(asset.read_bytes()).hexdigest()})
elif arguments[:2] == ['release', 'view']:
    output = str(data['release']['draft']).lower()
elif arguments[:2] == ['release', 'edit']:
    data['mutations'].append('publish')
    data['release'].update(draft=False, immutable=True)
elif arguments[:2] == ['release', 'verify']:
    count = data.get('verify_calls', 0)
    data['verify_calls'] = count + 1
    responses = data.get('attestations', ['success'])
    response = responses[min(count, len(responses) - 1)]
    if response == 'success':
        output = 'Exact release attestation verified'
    elif response == 'missing':
        status, error = 1, 'no attestations for tag v0.2.2 (sha1:' + data['revision'] + ')'
    elif response == 'invalid':
        status, error = 1, 'attestation signature verification failed'
    else:
        status, error = 1, response
elif arguments[:2] == ['release', 'verify-asset']:
    asset = pathlib.Path(arguments[3])
    expected = next(value for value in data['assets'] if value['name'] == asset.name)
    if expected['digest'] != 'sha256:' + hashlib.sha256(asset.read_bytes()).hexdigest():
        status, error = 1, 'Asset verification failed'
else:
    status, error = 9, 'Unexpected fake GitHub command'
path.write_text(json.dumps(data))
if output:
    print(output)
if error:
    print(error, file=sys.stderr)
raise SystemExit(status)
'''

FAKE_PYTHON = '''#!{python}
import json, os, pathlib, sys
if 'nixos-appliance/qualification/release_predecessor.py' in sys.argv:
    path = pathlib.Path(os.environ['TEST_API'])
    data = json.loads(path.read_text())
    data['predecessor_arguments'] = sys.argv[1:]
    path.write_text(json.dumps(data))
    raise SystemExit(data.get('predecessor_status', 0))
os.execv({python!r}, [{python!r}, *sys.argv[1:]])
'''


def step(name):
    workflow = (ROOT / '.github/workflows/release.yml').read_text()
    return workflow.split('      - name: ' + name + '\n', 1)[1].split('\n      - name:', 1)[0]


def script(name):
    body = step(name).split('        run: ', 1)[1]
    return textwrap.dedent(body[2:]) if body.startswith('|\n') else body.splitlines()[0] + '\n'


class PublicationRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(temporary)
        self.api_path = self.root / 'api.json'
        self.data = {'revision': REVISION, 'release': {
            'id': 123, 'tag_name': 'v0.2.2', 'draft': False, 'immutable': True,
            'prerelease': True, 'target_commitish': REVISION,
            'name': 'Tiaris Nest v0.2.2', 'body': BODY}, 'assets': []}
        for name in ASSETS:
            directory = 'qualification' if name.startswith(('tiaris-nest-nixos-', 'tiaris-nest-qualified-')) else 'dist'
            path = self.root / directory / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(('exact bytes for ' + name).encode())
            self.data['assets'].append({'name': name, 'state': 'uploaded',
                'size': path.stat().st_size,
                'digest': 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()})
        (self.root / 'tools').mkdir()
        (self.root / 'tools/release-publication.py').symlink_to(HELPER)
        binary = self.root / 'bin'
        binary.mkdir()
        for name, body in [('gh', FAKE_GH), ('python3', FAKE_PYTHON.format(python=sys.executable))]:
            path = binary / name
            path.write_text(body)
            path.chmod(0o755)
        self.environment = {**os.environ,
            'PATH': str(binary) + os.pathsep + os.environ['PATH'],
            'TEST_API': str(self.api_path), 'RUNNER_TEMP': str(self.root),
            'GITHUB_OUTPUT': str(self.root / 'output'),
            'GITHUB_SHA': REVISION, 'GITHUB_SERVER_URL': 'https://github.com',
            'GITHUB_REPOSITORY': 'CybexHQ/james', 'GITHUB_REF_NAME': 'v0.2.2',
            'GITHUB_RUN_ID': '42', 'GITHUB_RUN_ATTEMPT': '2',
            'TIARIS_NEST_RELEASE_VERSION': '0.2.2',
            'TIARIS_NEST_RELEASE_ARTIFACT_ID': '100',
            'TIARIS_NEST_RELEASE_ARTIFACT_DIGEST': 'a' * 64,
            'TIARIS_NEST_WORKSTATION_BUNDLE_NAME': BUNDLE,
            'TIARIS_NEST_HAS_PREDECESSOR': 'true',
            'TIARIS_NEST_UPDATE_TRUSTED_PUBLIC_KEY': 'test-key'}

    def save(self):
        self.api_path.write_text(json.dumps(self.data))

    def load(self):
        self.data = json.loads(self.api_path.read_text())

    def run_step(self, name, **extra):
        return subprocess.run(['bash', '-c', script(name)], cwd=self.root,
            env={**self.environment, **extra}, capture_output=True, text=True, timeout=30)

    def pipeline(self, after_inspection=None):
        self.save()
        result = self.run_step('Inspect exact immutable publication recovery')
        if result.returncode:
            self.load()
            return result
        release_id = (self.root / 'output').read_text().strip().split('=', 1)[1]
        self.load()
        if after_inspection:
            after_inspection(self.data)
            self.save()
        guarded = ['Attest exact release assets', 'Attest exact NixOS update and rollback qualification',
                   'Remove only a stale draft for this exact tag', 'Create draft and attach exact assets']
        for name in guarded:
            self.assertIn("if: steps.publication-recovery.outputs.immutable_release_id == ''", step(name))
        if not release_id:
            for name in guarded[-2:]:
                result = self.run_step(name)
                if result.returncode:
                    self.load()
                    return result
        result = self.run_step('Verify remote draft assets and publish immutably', REATTACH_RELEASE_ID=release_id)
        self.load()
        return result

    def test_exact_immutable_release_reattaches_without_any_mutation(self):
        result = self.pipeline()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.data['mutations'], [])
        self.assertEqual(self.data['verify_calls'], 1)
        self.assertEqual(len([c for c in self.data['commands'] if c[:2] == ['release', 'verify-asset']]), len(ASSETS))
        self.assertIn('--expected-identity', self.data['predecessor_arguments'])

    def test_metadata_mismatch_refuses_immutable_reuse_without_mutation(self):
        for field, value in [('body', BODY.replace('/42', '/43')),
                ('body', BODY.replace('ID: 100', 'ID: 101')),
                ('body', BODY.replace('a' * 64, 'b' * 64)),
                ('body', BODY.rsplit('\n', 1)[0]), ('name', 'Other release'),
                ('target_commitish', '3' * 40), ('prerelease', False),
                ('immutable', False), ('draft', True)]:
            with self.subTest(field=field, value=value):
                original = copy.deepcopy(self.data)
                self.data['release'][field] = value
                result = self.pipeline()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.data.get('mutations', []), [])
                self.data = original

    def test_asset_mismatch_refuses_immutable_reuse_without_mutation(self):
        originals = copy.deepcopy(self.data['assets'])
        alternatives = [originals[:-1], originals + [originals[0]],
            [dict(value, digest='sha256:' + '0' * 64) if index == 0 else value for index, value in enumerate(originals)],
            [dict(value, size=value['size'] + 1) if index == 0 else value for index, value in enumerate(originals)],
            [dict(value, name='unexpected') if index == 0 else value for index, value in enumerate(originals)]]
        for assets in alternatives:
            with self.subTest(assets=assets):
                self.data['assets'] = assets
                result = self.pipeline()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.data.get('mutations', []), [])

    def test_later_metadata_change_is_refused_before_acceptance(self):
        result = self.pipeline(lambda data: data['release'].update(body=BODY + '\nchanged'))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.data['mutations'], [])
        self.assertNotIn('verify_calls', self.data)

    def test_current_predecessor_failure_still_blocks_immutable_reattach(self):
        self.data['predecessor_status'] = 7
        result = self.pipeline()
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(self.data['mutations'], [])
        self.assertNotIn('verify_calls', self.data)

    def test_owned_partial_draft_is_recreated_and_published(self):
        self.data['release'].update(draft=True, immutable=False)
        self.data['assets'] = self.data['assets'][:1]
        result = self.pipeline()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.data['mutations'], ['delete', 'create', 'upload', 'publish'])
        self.assertTrue(self.data['release']['immutable'])

    def test_new_release_is_published_then_verified(self):
        self.data['release'] = None
        self.data['assets'] = []
        result = self.pipeline()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.data['mutations'], ['create', 'upload', 'publish'])

    def attestation(self, responses):
        self.data['attestations'] = responses
        self.save()
        elapsed, sleeps = [0], []
        def sleep(seconds):
            sleeps.append(seconds)
            elapsed[0] += seconds
        with patch.dict(os.environ, self.environment), patch.object(publication, 'WAIT_SECONDS', 6), \
                patch.object(publication.time, 'monotonic', side_effect=lambda: elapsed[0]), \
                patch.object(publication.time, 'sleep', side_effect=sleep):
            error = None
            try:
                publication.verify_attestation()
            except ValueError as caught:
                error = caught
        self.load()
        self.assertEqual(self.data['mutations'], [])
        return error, sleeps

    def test_delayed_attestation_is_retried_read_only(self):
        error, sleeps = self.attestation(['missing', 'success'])
        self.assertIsNone(error)
        self.assertEqual(sleeps, [3])
        self.assertEqual(self.data['verify_calls'], 2)

    def test_missing_attestation_times_out_at_visibility_bound(self):
        error, sleeps = self.attestation(['missing'])
        self.assertIn('visibility bound', str(error))
        self.assertEqual(sleeps, [3, 3])
        self.assertEqual(self.data['verify_calls'], 2)

    def test_invalid_or_other_verification_failure_is_never_retried(self):
        for response in ('invalid', 'HTTP 503', 'no attestations for tag v0.2.3 (sha1:' + REVISION + ')',
                         'no attestations for tag v0.2.2 (sha1:' + '3' * 40 + ')'):
            with self.subTest(response=response):
                self.data.pop('verify_calls', None)
                error, sleeps = self.attestation([response])
                self.assertIn('no retry', str(error))
                self.assertEqual(sleeps, [])
                self.assertEqual(self.data['verify_calls'], 1)


if __name__ == '__main__':
    unittest.main()
