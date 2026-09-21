import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import textwrap
import unittest

module = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'coordinated-release.py'))
ROOT = Path(__file__).resolve().parents[2]


def workflow_job(name):
    return (ROOT / '.github/workflows/release.yml').read_text().split('  ' + name + ':\n', 1)[1].split('\n  release_', 1)[0]


def step_script(job, name):
    step = workflow_job(job).split('      - name: ' + name + '\n', 1)[1].split('\n      - name:', 1)[0]
    return textwrap.dedent(step.split('        run: |\n', 1)[1])


QUALIFICATION_INPUTS = {
    'MANAGE_ORIGIN': 'https://dev.example.test',
    'TOKEN_FILE': '/private qualification/session',
    'SUBNET': '192.168.246.1/24',
    'STATE_ROOT': '/private qualification/state',
    'ALLOW_DEVICE_HELPER': '/private qualification/admit',
    'MANAGE_CHECKOUT': '/development checkout',
}


class DevelopmentQualificationWorkflowTests(unittest.TestCase):
    def environment(self):
        return {**os.environ,
            **{'CYBEX_JAMES_QUALIFICATION_' + k: v for k, v in QUALIFICATION_INPUTS.items()},
            'CYBEX_JAMES_BUILD_MANAGE_ORIGIN': QUALIFICATION_INPUTS['MANAGE_ORIGIN']}

    def test_actual_scope_guards_require_all_inputs_and_matching_development_origin(self):
        for job in ('release_qualify', 'release_cold_qualify'):
            script = step_script(job, 'Require explicit development qualification scope')
            result = subprocess.run(['bash', '-c', script], cwd=ROOT, env=self.environment(), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            invalid = [{k: v for k, v in self.environment().items() if k != 'CYBEX_JAMES_QUALIFICATION_' + name}
                       for name in QUALIFICATION_INPUTS]
            for value in ('https://console.example.com', 'https://dev.example.test/', 'http://dev.example.test'):
                invalid.append({**self.environment(), 'CYBEX_JAMES_QUALIFICATION_MANAGE_ORIGIN': value,
                                'CYBEX_JAMES_BUILD_MANAGE_ORIGIN': value})
            invalid.append({**self.environment(), 'CYBEX_JAMES_BUILD_MANAGE_ORIGIN': 'https://console.example.com'})
            invalid.append({**self.environment(), 'CYBEX_JAMES_QUALIFICATION_TOKEN_FILE': 'relative/session'})
            for environment in invalid:
                with self.subTest(job=job, changed={k: v for k, v in environment.items() if self.environment().get(k) != v}):
                    rejected = subprocess.run(['bash', '-c', script], cwd=ROOT, env=environment, capture_output=True, text=True)
                    self.assertNotEqual(rejected.returncode, 0)

    def test_both_sudo_commands_pass_explicit_scope_without_environment_preservation(self):
        for job, name in (('release_qualify', 'Qualify fresh installation, real upgrade and automatic rollback'),
                          ('release_cold_qualify', 'Require exact published bytes and cold runtime convergence')):
            script = step_script(job, name)
            lines = script[script.index('sudo -n python3'):].splitlines()
            command = []
            for line in lines:
                command.append(line)
                if not line.endswith('\\'): break
            with self.subTest(job=job), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fake_sudo = root / 'sudo'
                fake_sudo.write_text('#!/usr/bin/env python3\nimport json,os,sys\n'
                    'assert sys.argv[1:4] == ["-n", "python3", "-B"]\n'
                    'assert "-E" not in sys.argv\n'
                    'print(json.dumps(sys.argv[4:]))\n')
                fake_sudo.chmod(0o755)
                environment = {**self.environment(), 'PATH': temporary + os.pathsep + os.environ['PATH'],
                    'GITHUB_RUN_ID': '42', 'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_WORKSPACE': '/workspace',
                    'RUNNER_TEMP': '/run temporary', 'CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY': 'test-public-key', 'TRUSTED_KEY': 'test-public-key'}
                result = subprocess.run(['bash', '-c', '\n'.join(command)], env=environment, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = json.loads(result.stdout)
                self.assertEqual(arguments[0], 'nixos-appliance/qualification/run-production-qualification.py')
                for key, value in QUALIFICATION_INPUTS.items():
                    self.assertEqual(arguments[arguments.index('--' + key.lower().replace('_', '-')) + 1], value)
                self.assertEqual(arguments[arguments.index('--candidate-dir') + 1], '/workspace/dist')
                self.assertEqual('--published-cold' in arguments, job == 'release_cold_qualify')
                self.assertEqual('--predecessor-dir' in arguments, job == 'release_qualify')

    def test_publish_and_promote_reject_development_candidates_before_actions(self):
        for job in ('release_publish', 'release_promote'):
            script = step_script(job, 'Require production-bound artifacts for publication')
            for origin, accepted in [('', False), ('https://dev.example.test', False),
                                     ('https://manage.cybex.net/', False), ('https://manage.cybex.net', True)]:
                with self.subTest(job=job, origin=origin):
                    result = subprocess.run(['bash', '-c', script], env={**os.environ,
                        'CYBEX_JAMES_BUILD_MANAGE_ORIGIN': origin}, text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
            self.assertLess(workflow_job(job).index('Require production-bound artifacts'), workflow_job(job).index('uses: actions/checkout'))

    def test_new_environment_and_nixos_consumer_paths_keep_legacy_helpers_available(self):
        for job in ('release_qualify', 'release_cold_qualify'):
            body = workflow_job(job)
            self.assertIn('environment: james-nixos-development-qualification', body)
            self.assertIn('group: james-nixos-development-qualification', body)
            for key in QUALIFICATION_INPUTS:
                self.assertIn('${{ vars.CYBEX_JAMES_QUALIFICATION_' + key + ' }}', body)
            self.assertLess(body.index('Require explicit development qualification scope'), body.index('Download '))
        approval = (ROOT / '.github/workflows/approve-coordinated-release.yml').read_text()
        self.assertIn('nixos-appliance/qualification/promote-production-release.py', approval)
        self.assertNotIn('ubuntu-appliance/qualification/', approval)
        self.assertTrue((ROOT / 'ubuntu-appliance/qualification/promote-production-release.py').is_file())


class CoordinatedReleaseTests(unittest.TestCase):
    def test_pins_development_and_requires_explicit_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'release').mkdir()
            (root / 'Cargo.toml').write_text('[package]\nname="cybex-james"\nversion = "0.2.5"\n')
            (root / 'Cargo.lock').write_text('[[package]]\nname = "cybex-james"\nversion = "0.2.5"\n')
            self.assertFalse(module['validate'](root))
            module['pin'](root, 'a' * 40, '1.0.68', '0.2.6', '20260920T120000Z')
            self.assertTrue(module['validate'](root))
            marker = json.loads((root / 'release/coordinated.json').read_text())
            self.assertEqual(marker['ubuntu_snapshot_id'], '20260920T120000Z')
            pin = root / 'release/workstation-netboot-source.json'
            self.assertEqual(json.loads(pin.read_text())['repository'], 'CybexHQ/development')
            self.assertIn('version = "0.2.6"', (root / 'Cargo.lock').read_text())
            pin.write_text(pin.read_text().replace('a' * 40, 'b' * 40))
            with self.assertRaises(ValueError):
                module['validate'](root)

    def test_rejects_invalid_snapshot_cutoffs(self):
        for snapshot in ['latest', '20260230T000000Z', '20260920T250000Z', '20260920T120000Z\nINJECT=1']:
            with self.subTest(snapshot=snapshot), self.assertRaises(ValueError):
                module['validate_snapshot'](snapshot)

    def test_workflow_binds_nixos_build_to_the_pinned_sources(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/release.yml').read_text()
        self.assertIn('test "$nixpkgs_revision" = 74cc63f702f7d60a557e152a57b40fb1fd0f72ac', workflow)
        self.assertIn('--source-revision "$(git rev-parse HEAD)"', workflow)
        self.assertIn('--manage-source-revision "$BUILD_MANAGE_REVISION"', workflow)
        self.assertIn('[[ "$repository" = "CybexHQ/development" ]]', workflow)
        self.assertNotIn('CYBEX_JAMES_UBUNTU_SNAPSHOT_ID', workflow)
