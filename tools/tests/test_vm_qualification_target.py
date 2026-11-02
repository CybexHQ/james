"""On-demand VM qualification binds one exact immutable release and its build-once receipt."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('vm_qualification_target', ROOT / 'tools/vm-qualification-target.py')
target = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(target)
sys.path.insert(0, str(ROOT / 'nixos-appliance/qualification'))
import release_acceptance as acceptance  # noqa: E402

SOURCE = '7' * 40
BUNDLE = 'tiaris-workstation-netboot-1.0.123-7da7628834d9-x86_64-linux.tar.zst'


def fixture():
    release = {'tag_name': 'v0.2.80', 'draft': False, 'immutable': True, 'prerelease': False,
               'target_commitish': SOURCE,
               'body': '\n'.join(['Tiaris-Release-Workflow: https://github.com/CybexHQ/james/actions/runs/42',
                                  'Tiaris-Candidate-Artifact-ID: 66', 'Tiaris-Candidate-Artifact-SHA256: ' + 'f' * 64,
                                  'Tiaris-VM-Qualification: nightly', 'Tiaris-Public-Closure: passed']),
               'assets': [{'name': name} for name in (
                   'tiaris-nest-release.json', 'tiaris-nest-release-compatibility.json', BUNDLE,
                   'tiaris-nest-build-predecessor.json')]}
    return {'repos/CybexHQ/james/releases/latest': release,
            'repos/CybexHQ/james/releases/tags/v0.2.80': release,
            'repos/CybexHQ/james/commits/v0.2.80': {'sha': SOURCE},
            'repos/CybexHQ/james/actions/runs/42': {'path': '.github/workflows/release.yml', 'event': 'push',
                                                    'head_branch': 'v0.2.80', 'head_sha': SOURCE},
            'repos/CybexHQ/james/actions/artifacts/66': {
                'name': 'tiaris-nest-release-candidate-42', 'expired': False,
                'workflow_run': {'id': 42, 'head_sha': SOURCE}, 'digest': 'sha256:' + 'f' * 64}}


class VmQualificationTargetTests(unittest.TestCase):
    def resolve(self, data, tag=''):
        return target.resolve('CybexHQ/james', tag, lambda path: data[path])

    def test_latest_and_exact_tag_resolve_the_same_release_run_and_receipt(self):
        expected = {'tag': 'v0.2.80', 'version': '0.2.80', 'source': SOURCE, 'run': '42',
                    'candidate_id': '66', 'candidate_digest': 'f' * 64,
                    'workstation_bundle_name': BUNDLE, 'has_predecessor': 'true'}
        self.assertEqual(self.resolve(fixture()), expected)
        self.assertEqual(self.resolve(fixture(), 'v0.2.80'), expected)

    def test_owner_waived_legacy_release_remains_qualifiable(self):
        data = fixture()
        release = data['repos/CybexHQ/james/releases/latest']
        release['body'] = '\n'.join(release['body'].splitlines()[:3] + [
            'Tiaris-Cold-Qualification: required', '', 'Cold qualification waived by owner (John).'])
        release['assets'] = release['assets'][:3]
        self.assertEqual(self.resolve(data)['has_predecessor'], 'false')

    def test_mutable_moved_or_foreign_releases_are_rejected(self):
        changes = [
            ('repos/CybexHQ/james/releases/latest', 'immutable', False),
            ('repos/CybexHQ/james/releases/latest', 'draft', True),
            ('repos/CybexHQ/james/releases/latest', 'target_commitish', '8' * 40),
            ('repos/CybexHQ/james/releases/latest', 'tag_name', 'v0.2.80-dev.1'),
            ('repos/CybexHQ/james/commits/v0.2.80', 'sha', '8' * 40),
            ('repos/CybexHQ/james/actions/runs/42', 'path', '.github/workflows/nest-vm-qualification.yml'),
            ('repos/CybexHQ/james/actions/runs/42', 'event', 'workflow_dispatch'),
            ('repos/CybexHQ/james/actions/runs/42', 'head_sha', '8' * 40),
            ('repos/CybexHQ/james/actions/artifacts/66', 'expired', True),
            ('repos/CybexHQ/james/actions/artifacts/66', 'name', 'tiaris-nest-release-candidate-43'),
            ('repos/CybexHQ/james/actions/artifacts/66', 'digest', 'sha256:' + '0' * 64),
            ('repos/CybexHQ/james/actions/artifacts/66', 'workflow_run', {'id': 43, 'head_sha': SOURCE}),
        ]
        for path, field, value in changes:
            with self.subTest(path=path, field=field):
                data = copy.deepcopy(fixture())
                data[path][field] = value
                with self.assertRaises(ValueError):
                    self.resolve(data)

    def test_release_notes_and_assets_must_identify_one_candidate(self):
        lines = fixture()['repos/CybexHQ/james/releases/latest']['body'].splitlines()
        for body in ('\n'.join(lines[1:]), '\n'.join(lines + lines[:1]),
                     '\n'.join([lines[0].replace('/42', '/x')] + lines[1:]),
                     '\n'.join(lines[:2] + ['Tiaris-Candidate-Artifact-SHA256: short'] + lines[3:])):
            with self.subTest(body=body):
                data = fixture()
                data['repos/CybexHQ/james/releases/latest']['body'] = body
                with self.assertRaises(ValueError):
                    self.resolve(data)
        for assets in ([], [{'name': BUNDLE}, {'name': BUNDLE.replace('7da7628834d9', '000000000000')}],
                       [{'name': BUNDLE}, {'name': BUNDLE}]):
            with self.subTest(assets=assets):
                data = fixture()
                data['repos/CybexHQ/james/releases/latest']['assets'] = assets
                with self.assertRaises(ValueError):
                    self.resolve(data)
        with self.assertRaises(ValueError):
            self.resolve(fixture(), 'latest')

    def test_github_output_lines_match_workflow_outputs(self):
        workflow = (ROOT / '.github/workflows/nest-vm-qualification.yml').read_text()
        job = workflow.split('  release_candidate:\n', 1)[1].split('\n  release_qualify:\n', 1)[0]
        outputs = job.split('    outputs:\n', 1)[1].split('    steps:\n', 1)[0]
        names = [line.strip().split(':', 1)[0] for line in outputs.splitlines() if line.strip()]
        self.assertEqual(names, list(self.resolve(fixture())))
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'output'
            with mock.patch.object(target, 'gh_api', side_effect=lambda path: fixture()[path]), \
                    mock.patch.object(sys, 'argv', ['target', '--repository', 'CybexHQ/james',
                                                    '--github-output', str(output)]), \
                    mock.patch('builtins.print'):
                target.main()
            self.assertEqual(dict(line.split('=', 1) for line in output.read_text().splitlines()),
                             self.resolve(fixture()))


class PublicClosureAcceptancePhaseTests(unittest.TestCase):
    def test_public_closure_phase_takes_only_its_own_exact_evidence(self):
        manifest = {'version': '0.2.80', 'appliance_release_v1': {'source_revision': SOURCE, 'system_closure': {
            'url': 'https://github.com/CybexHQ/james/releases/download/v0.2.80/closure', 'sha256': 'c' * 64,
            'size_bytes': 9}}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = root / 'tiaris-nest-release.json'
            manifest_path.write_text(json.dumps(manifest))
            evidence = {'schema': 'tiaris.nest.public-closure-qualification.v1', 'ok': True,
                        'source_revision': SOURCE, 'tag': 'v0.2.80', 'release_version': '0.2.80',
                        'manifest_sha256': hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                        'closure_url': manifest['appliance_release_v1']['system_closure']['url'],
                        'closure_sha256': 'c' * 64, 'closure_size_bytes': 9, 'archive_verified': True}
            evidence_path = root / 'evidence.json'
            evidence_path.write_text(json.dumps(evidence))
            command = ['acceptance', '--phase', 'public-closure', '--manifest', str(manifest_path),
                       '--evidence', str(evidence_path), '--source', SOURCE]
            with mock.patch.object(sys, 'argv', command), mock.patch('builtins.print') as printed:
                acceptance.main()
            printed.assert_called_once_with('Exact public-closure acceptance verified')
            for extra in (['--workstation', str(evidence_path)], ['--public-closure', str(evidence_path)],
                          ['--predecessor-manifest', str(manifest_path)]):
                with self.subTest(extra=extra), mock.patch.object(sys, 'argv', command + extra), \
                        self.assertRaisesRegex(ValueError, 'only its own evidence'):
                    acceptance.main()
            for field, value in (('manifest_sha256', '0' * 64), ('archive_verified', False), ('tag', 'v0.2.79')):
                evidence_path.write_text(json.dumps(evidence | {field: value}))
                with self.subTest(field=field), mock.patch.object(sys, 'argv', command), \
                        self.assertRaisesRegex(ValueError, 'Public closure transport'):
                    acceptance.main()
            evidence_path.write_text(json.dumps(evidence))
            with mock.patch.object(sys, 'argv', command[:-1] + ['8' * 40]), \
                    self.assertRaisesRegex(ValueError, 'Public closure transport'):
                acceptance.main()


if __name__ == '__main__':
    unittest.main()
