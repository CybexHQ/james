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
    'MANAGE_ORIGIN': 'https://manage.cybex.net',
    'CONFIG': '/private qualification/config.json',
    'SUBNET': '192.168.246.1/24',
    'STATE_ROOT': '/private qualification/state',
}


class ProductionQualificationWorkflowTests(unittest.TestCase):
    def environment(self):
        return {**os.environ, **{'CYBEX_JAMES_QUALIFICATION_' + k: v for k, v in QUALIFICATION_INPUTS.items()},
                'CYBEX_JAMES_BUILD_MANAGE_ORIGIN': QUALIFICATION_INPUTS['MANAGE_ORIGIN']}

    def test_scope_guards_reject_missing_inputs_and_nonproduction_origins(self):
        with tempfile.TemporaryDirectory() as temporary:
            sudo = Path(temporary) / 'sudo'
            sudo.write_text('#!/bin/sh\nexit 0\n')
            sudo.chmod(0o755)
            environment = {**self.environment(), 'PATH': temporary + os.pathsep + os.environ['PATH']}
            for job in ('release_qualify', 'release_cold_qualify'):
                script = step_script(job, 'Require isolated NixOS production qualification')
                result = subprocess.run(['bash', '-c', script], env=environment, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                invalid = [{k: v for k, v in environment.items() if k != 'CYBEX_JAMES_QUALIFICATION_' + name}
                           for name in QUALIFICATION_INPUTS]
                invalid += [{**environment, 'CYBEX_JAMES_BUILD_MANAGE_ORIGIN': origin}
                            for origin in ('https://dev.example.test', 'https://manage.cybex.net/', '')]
                invalid.append({**environment, 'CYBEX_JAMES_QUALIFICATION_CONFIG': 'relative/config'})
                for changed in invalid:
                    self.assertNotEqual(subprocess.run(['bash', '-c', script], env=changed,
                                                       capture_output=True).returncode, 0)

    def test_runner_receives_fixture_config_without_external_session_or_environment_preservation(self):
        for job, name in (('release_qualify', 'Qualify fresh installation, real upgrade and automatic rollback'),
                          ('release_cold_qualify', 'Require exact published bytes and cold runtime convergence')):
            script = step_script(job, name)
            start = script.index('sudo -n python3 -B nixos-appliance/qualification/run-production-qualification.py')
            lines = script[start:].splitlines()
            command = []
            for line in lines:
                command.append(line)
                if not line.endswith('\\'):
                    break
            with tempfile.TemporaryDirectory() as temporary:
                sudo = Path(temporary) / 'sudo'
                sudo.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[4:]))\n')
                sudo.chmod(0o755)
                environment = {**self.environment(), 'PATH': temporary + os.pathsep + os.environ['PATH'],
                    'GITHUB_RUN_ID': '42', 'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_WORKSPACE': '/workspace',
                    'RUNNER_TEMP': '/run temporary', 'CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY': 'test-key',
                    'TRUSTED_KEY': 'test-key', 'fixture_directory': '/private fixture'}
                result = subprocess.run(['bash', '-c', '\n'.join(command)], env=environment,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = json.loads(result.stdout)
                self.assertEqual(arguments[arguments.index('--isolated-manage-config') + 1], '/private fixture/config.json')
                self.assertNotIn('--token-file', arguments)
                self.assertNotIn('--allow-device-helper', arguments)
                self.assertEqual('--published-cold' in arguments, job == 'release_cold_qualify')
                self.assertEqual('--predecessor-dir' in arguments, job == 'release_qualify')

    def test_protected_nixos_chain_preserves_production_and_immutable_approval_gates(self):
        for job in ('release_publish', 'release_promote'):
            script = step_script(job, 'Require production-bound artifacts for publication')
            for origin, accepted in [('', False), ('https://dev.example.test', False),
                                     ('https://manage.cybex.net/', False), ('https://manage.cybex.net', True)]:
                result = subprocess.run(['bash', '-c', script], env={**os.environ,
                    'CYBEX_JAMES_BUILD_MANAGE_ORIGIN': origin}, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted)
        for job in ('release_qualify', 'release_cold_qualify'):
            body = workflow_job(job)
            self.assertIn('environment: production-release-qualification', body)
            self.assertIn('group: james-nixos-production-qualification', body)
            self.assertNotIn('ubuntu-appliance/', body)
        approval = (ROOT / '.github/workflows/approve-coordinated-release.yml').read_text()
        self.assertIn('nixos-appliance/qualification/promote-production-release.py', approval)
        self.assertNotIn('ubuntu-appliance/qualification/', approval)


class CoordinatedReleaseTests(unittest.TestCase):
    def test_pins_development_and_requires_explicit_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'release').mkdir()
            (root / 'Cargo.toml').write_text('[package]\nname="cybex-james"\nversion = "0.2.5"\n')
            (root / 'Cargo.lock').write_text('[[package]]\nname = "cybex-james"\nversion = "0.2.5"\n')
            self.assertFalse(module['validate'](root))
            module['pin'](root, 'a' * 40, '1.0.68', '0.2.6')
            self.assertTrue(module['validate'](root))
            marker = json.loads((root / 'release/coordinated.json').read_text())
            self.assertEqual(marker['appliance_family'], 'nixos')
            self.assertNotIn('ubuntu_snapshot_id', marker)
            pin = root / 'release/workstation-netboot-source.json'
            self.assertEqual(json.loads(pin.read_text())['repository'], 'CybexHQ/development')
            self.assertIn('version = "0.2.6"', (root / 'Cargo.lock').read_text())
            pin.write_text(pin.read_text().replace('a' * 40, 'b' * 40))
            with self.assertRaises(ValueError):
                module['validate'](root)

    def test_rejects_retired_ubuntu_coordinated_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'release').mkdir()
            (root / 'release/coordinated.json').write_text(json.dumps({
                'schema': 'cybex.coordinated-release.v1', 'manage_revision': 'a' * 40,
                'ubuntu_snapshot_id': '20260920T120000Z'}))
            (root / 'release/workstation-netboot-source.json').write_text(json.dumps({
                'repository': 'CybexHQ/development', 'revision': 'a' * 40}))
            with self.assertRaises(ValueError):
                module['validate'](root)

    def test_workflow_binds_nixos_build_to_the_pinned_sources(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/release.yml').read_text()
        self.assertIn('test "$nixpkgs_revision" = 74cc63f702f7d60a557e152a57b40fb1fd0f72ac', workflow)
        self.assertIn('--source-revision "$(git rev-parse HEAD)"', workflow)
        self.assertIn('--manage-source-revision "$BUILD_MANAGE_REVISION"', workflow)
        self.assertIn('[[ "$repository" = "CybexHQ/development" ]]', workflow)
        self.assertNotIn('CYBEX_JAMES_UBUNTU_SNAPSHOT_ID', workflow)
