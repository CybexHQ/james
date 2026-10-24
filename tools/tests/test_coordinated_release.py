import json
import os
import re
from pathlib import Path
import runpy
import subprocess
import tempfile
import textwrap
import tomllib
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
        return {**os.environ, **{'TIARIS_NEST_QUALIFICATION_' + k: v for k, v in QUALIFICATION_INPUTS.items()},
                'TIARIS_NEST_BUILD_MANAGE_ORIGIN': QUALIFICATION_INPUTS['MANAGE_ORIGIN']}

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
                invalid = [{k: v for k, v in environment.items() if k != 'TIARIS_NEST_QUALIFICATION_' + name}
                           for name in QUALIFICATION_INPUTS]
                invalid += [{**environment, 'TIARIS_NEST_BUILD_MANAGE_ORIGIN': origin}
                            for origin in ('https://dev.example.test', 'https://manage.cybex.net/', '')]
                invalid.append({**environment, 'TIARIS_NEST_QUALIFICATION_CONFIG': 'relative/config'})
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
                    'RUNNER_TEMP': '/run temporary', 'TIARIS_NEST_UPDATE_TRUSTED_PUBLIC_KEY': 'test-key',
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

    def test_evidence_paths_isolate_runs_and_attempts_and_match_uploads(self):
        for job, name, prefix in (
            ('release_qualify', 'Qualify fresh installation, real upgrade and automatic rollback', 'tiaris-nest-evidence'),
            ('release_cold_qualify', 'Require exact published bytes and cold runtime convergence', 'tiaris-nest-cold-evidence'),
        ):
            script = step_script(job, name)
            start = script.index('sudo -n python3 -B nixos-appliance/qualification/run-production-qualification.py')
            command = []
            for line in script[start:].splitlines():
                command.append(line)
                if not line.endswith('\\'):
                    break
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                sudo = root / 'sudo'
                sudo.write_text('#!/usr/bin/env python3\nimport json,sys\n'
                    'from pathlib import Path\n'
                    'args=sys.argv[4:]\n'
                    'evidence=Path(args[args.index("--evidence-dir")+1])\n'
                    'evidence.mkdir(mode=0o700)\n'
                    '(evidence/"receipt.json").write_text("completed")\n'
                    'print(json.dumps(str(evidence)))\n')
                sudo.chmod(0o755)
                paths = []
                for run_id, attempt in (('42', '1'), ('42', '2'), ('43', '1')):
                    environment = {**self.environment(), 'PATH': temporary + os.pathsep + os.environ['PATH'],
                        'GITHUB_RUN_ID': run_id, 'GITHUB_RUN_ATTEMPT': attempt, 'GITHUB_WORKSPACE': '/workspace',
                        'RUNNER_TEMP': temporary, 'TIARIS_NEST_UPDATE_TRUSTED_PUBLIC_KEY': 'test-key',
                        'TRUSTED_KEY': 'test-key', 'fixture_directory': '/private fixture'}
                    result = subprocess.run(['bash', '-c', '\n'.join(command)], env=environment,
                                            text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    path = Path(json.loads(result.stdout))
                    self.assertEqual(path, root / f'{prefix}-{run_id}-{attempt}')
                    paths.append(path)
                    uploads = [line.strip().removeprefix('path: ') for line in workflow_job(job).splitlines()
                               if '${{ runner.temp }}/' + prefix in line]
                    self.assertTrue(uploads)
                    for upload in uploads:
                        resolved = upload.replace('${{ runner.temp }}', temporary).replace(
                            '${{ github.run_id }}', run_id).replace('${{ github.run_attempt }}', attempt)
                        if resolved.endswith('/tiaris-nest-*-diagnostics.json'):
                            # Listener diagnostics belong to individual fixture
                            # phases within this run's private evidence root.
                            phase = 'published' if job == 'release_cold_qualify' else 'release'
                            self.assertEqual(Path(resolved), path /
                                f'{phase}-{run_id}-{attempt}-*' / 'tiaris-nest-*-diagnostics.json')
                        else:
                            self.assertEqual(Path(resolved).parent, path)
                self.assertEqual(len(set(paths)), 3)
                self.assertTrue(all((path / 'receipt.json').read_text() == 'completed' for path in paths))
            if job == 'release_cold_qualify':
                acceptance = script.split('qualification/release_acceptance.py', 1)[1]
                expected = '$RUNNER_TEMP/' + prefix + '-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT/'
                self.assertIn('--evidence "' + expected, acceptance)
                self.assertIn('--workstation "' + expected, acceptance)

    def test_protected_nixos_chain_preserves_production_and_immutable_approval_gates(self):
        for job in ('release_publish', 'release_promote'):
            script = step_script(job, 'Require production-bound artifacts for publication')
            for origin, accepted in [('', False), ('https://dev.example.test', False),
                                     ('https://manage.cybex.net/', False), ('https://manage.cybex.net', True)]:
                result = subprocess.run(['bash', '-c', script], env={**os.environ,
                    'TIARIS_NEST_BUILD_MANAGE_ORIGIN': origin}, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted)
        for job in ('release_qualify', 'release_cold_qualify'):
            body = workflow_job(job)
            self.assertIn('environment: production-release-qualification', body)
            self.assertIn('group: nest-nixos-production-qualification', body)
            self.assertNotIn('ubuntu-appliance/', body)
        approval = (ROOT / '.github/workflows/approve-coordinated-release.yml').read_text()
        self.assertIn('nixos-appliance/qualification/promote-production-release.py', approval)
        self.assertNotIn('ubuntu-appliance/qualification/', approval)


class CoordinatedReleaseTests(unittest.TestCase):
    def test_stable_candidate_can_advance_a_development_prerelease(self):
        for candidate in ('0.2.48', '0.2.49'):
            with self.subTest(candidate=candidate), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'release').mkdir()
                (root / 'Cargo.toml').write_text('[package]\nname="tiaris-nest"\nversion = "0.2.48-dev.tiaris.1"\n')
                (root / 'Cargo.lock').write_text('[[package]]\nname = "tiaris-nest"\nversion = "0.2.48-dev.tiaris.1"\n')
                module['pin'](root, 'a' * 40, '1.0.89', candidate)
                self.assertTrue(module['validate'](root))
                self.assertIn('version = "' + candidate + '"', (root / 'Cargo.lock').read_text())

    def test_candidate_rejects_same_stable_version_and_prerelease_downgrade(self):
        for previous, candidate in (('0.2.48+build.1', '0.2.48'),
                                    ('0.2.48-dev.tiaris.1', '0.2.47')):
            with self.subTest(previous=previous), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'release').mkdir()
                manifest = '[package]\nname="tiaris-nest"\nversion = "' + previous + '"\n'
                (root / 'Cargo.toml').write_text(manifest)
                with self.assertRaises(ValueError):
                    module['pin'](root, 'a' * 40, '1.0.89', candidate)
                self.assertEqual((root / 'Cargo.toml').read_text(), manifest)

    def pinned_root(self, directory, previous):
        root = Path(directory)
        (root / 'release').mkdir()
        (root / 'Cargo.toml').write_text('[package]\nname="tiaris-nest"\nversion = "' + previous + '"\n')
        (root / 'Cargo.lock').write_text('[[package]]\nname = "tiaris-nest"\nversion = "' + previous + '"\n')
        return root

    def test_development_candidate_uses_dev_prerelease_with_semver_precedence(self):
        for previous, candidate in (('0.2.48-dev.tiaris.1', '0.2.58-dev.1'),
                                    ('0.2.58-dev.1', '0.2.58-dev.2'),
                                    ('0.2.58-dev.9', '0.2.58-dev.10'),
                                    ('0.2.57', '0.2.58-dev.1'),
                                    ('0.2.58-dev.3', '0.2.58')):
            with self.subTest(previous=previous, candidate=candidate), tempfile.TemporaryDirectory() as directory:
                root = self.pinned_root(directory, previous)
                module['pin'](root, 'a' * 40, '1.0.108', candidate)
                self.assertTrue(module['validate'](root))
                self.assertIn('version = "' + candidate + '"', (root / 'Cargo.toml').read_text())
                self.assertIn('version = "' + candidate + '"', (root / 'Cargo.lock').read_text())
                pin = json.loads((root / 'release/workstation-netboot-source.json').read_text())
                self.assertEqual(pin, {'repository': 'CybexHQ/development', 'revision': 'a' * 40,
                                       'runtime_version': '1.0.108'})

    def test_development_candidate_rejects_other_prereleases_and_non_advancing_versions(self):
        for previous, candidate, runtime in (('0.2.57', '0.2.58-rc.1', '1.0.108'),
                                             ('0.2.57', '0.2.58-dev', '1.0.108'),
                                             ('0.2.57', '0.2.58-dev.0', '1.0.108'),
                                             ('0.2.57', '0.2.58-dev.01', '1.0.108'),
                                             ('0.2.57', '0.2.58-dev.1+build.1', '1.0.108'),
                                             ('0.2.57', '0.2.58-dev.1', '1.0.108-dev.1'),
                                             ('0.2.58-dev.1', '0.2.58-dev.1', '1.0.108'),
                                             ('0.2.58', '0.2.58-dev.4', '1.0.108'),
                                             ('0.2.48-dev.tiaris.1', '0.2.48-dev.1', '1.0.108')):
            with self.subTest(previous=previous, candidate=candidate), tempfile.TemporaryDirectory() as directory:
                root = self.pinned_root(directory, previous)
                manifest = (root / 'Cargo.toml').read_text()
                with self.assertRaises(ValueError):
                    module['pin'](root, 'a' * 40, runtime, candidate)
                self.assertEqual((root / 'Cargo.toml').read_text(), manifest)
                self.assertFalse((root / 'release/coordinated.json').exists())

    def test_main_runtime_pin_is_informational_and_never_builds(self):
        pin = json.loads((ROOT / 'release/workstation-netboot-source.json').read_text())
        self.assertEqual(pin['repository'], 'CybexHQ/development')
        if 'informational' not in pin:
            # A vX.Y.Z tag or release/dev-nest-* branch carries `pin` output instead of
            # main's informational copy; that source must build as checked out.
            self.assertTrue(module['validate'](ROOT))
            pin = {**pin, 'informational': 'Last pin merged to main, not a release pin.'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'release').mkdir()
            (root / 'release/workstation-netboot-source.json').write_text(json.dumps(pin, indent=2) + '\n')
            (root / 'release/coordinated.json').write_bytes((ROOT / 'release/coordinated.json').read_bytes())
            with self.assertRaises(ValueError):
                module['validate'](root)
            for name in ('Cargo.toml', 'Cargo.lock'):
                (root / name).write_bytes((ROOT / name).read_bytes())
            version = tomllib.loads((root / 'Cargo.toml').read_text())['package']['version']
            major, minor, patch = module['version_core'](version)
            module['pin'](root, 'a' * 40, '1.0.108', f'{major}.{minor}.{patch + 1}-dev.1')
            pinned = json.loads((root / 'release/workstation-netboot-source.json').read_text())
            self.assertNotIn('informational', pinned)
            self.assertTrue(module['validate'](root))

    def test_workstation_expression_accepts_only_the_development_source(self):
        expression = (ROOT / 'release/workstation-netboot.nix').read_text()
        self.assertIn('assert sourcePin.repository == "CybexHQ/development";', expression)
        self.assertNotIn('CybexHQ/manage', expression)

    def test_pins_development_and_requires_explicit_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'release').mkdir()
            (root / 'Cargo.toml').write_text('[package]\nname="tiaris-nest"\nversion = "0.2.5"\n')
            (root / 'Cargo.lock').write_text('[[package]]\nname = "tiaris-nest"\nversion = "0.2.5"\n')
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
                'schema': 'tiaris.coordinated-release.v1', 'manage_revision': 'a' * 40,
                'ubuntu_snapshot_id': '20260920T120000Z'}))
            (root / 'release/workstation-netboot-source.json').write_text(json.dumps({
                'repository': 'CybexHQ/development', 'revision': 'a' * 40}))
            with self.assertRaises(ValueError):
                module['validate'](root)

    def test_workflow_binds_nixos_build_to_the_pinned_sources(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/release.yml').read_text()
        pin = (root / 'release/nixpkgs.nix').read_text()
        revision = re.search(r'^  revision = "([0-9a-f]{40})";$', pin, re.M).group(1)
        self.assertIn("nixpkgs_revision=\"$(sed -n 's/^[[:space:]]*revision = ", workflow)
        self.assertIn('[[ "$nixpkgs_revision" =~ ^[0-9a-f]{40}$ ]]', workflow)
        self.assertIn(f'  url = "https://github.com/NixOS/nixpkgs/archive/{revision}.tar.gz";', pin.splitlines())
        self.assertNotIn(revision, workflow)
        self.assertIn('--source-revision "$(git rev-parse HEAD)"', workflow)
        self.assertIn('--manage-source-revision "$BUILD_MANAGE_REVISION"', workflow)
        self.assertIn('[[ "$repository" = "CybexHQ/development" ]]', workflow)
        self.assertNotIn('TIARIS_NEST_UBUNTU_SNAPSHOT_ID', workflow)
