from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
BUILDER = REPOSITORY / 'ubuntu-appliance/build-packages.sh'
PINS = {'linux-generic': '7.0.0-30.30', 'linux-firmware': '20260319.git217ca6e4.1ubuntu',
        'nix-bin': '2.34.3+dfsg-1', 'python3': '3.14.3-0ubuntu2'}


class ApplianceDependencyPinTests(unittest.TestCase):
    def test_package_requires_exact_snapshot_os_anchors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'; source.mkdir()
            tool = runpy.run_path(str(REPOSITORY / 'tools/james-release.py'))
            for name in tool['MANAGE_SOURCE_INSTALLER_REQUIRED_PATHS']:
                path = source / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('test source archive fixture' + chr(10))
            subprocess.run(['git', 'init', '-q', str(source)], check=True)
            subprocess.run(['git', '-C', str(source), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(source), '-c', 'user.name=Test',
                            '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
            revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
            binary = root / 'binary'; binary.write_text('#!/bin/sh' + chr(10) + 'exit 0' + chr(10)); binary.chmod(0o755)
            public = '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='
            args = ['bash', str(BUILDER), '--output', str(root / 'out'),
                    '--james-binary', str(binary), '--bootstrap-binary', str(binary),
                    '--version', '1.2.3', '--ubuntu-snapshot-id', '20260901T000000Z',
                    '--manage-source-dir', str(source), '--manage-source-revision', revision,
                    '--release-public-key', public, '--provisioning-public-key', public]
            for name, version in PINS.items(): args += ['--dependency-version', name + '=' + version]
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            package = root / 'out/cybex-james-appliance_1.2.3-1_amd64.deb'
            dependencies = subprocess.check_output(['dpkg-deb', '-f', str(package), 'Depends'], text=True)
            for name, version in PINS.items():
                self.assertIn(name + ' (= ' + version + ')', dependencies)

    def test_missing_unknown_unsafe_or_duplicate_pins_fail_closed(self):
        for args in [[], ['--dependency-version', 'unexpected=1.0'],
                     ['--dependency-version', 'linux-generic=unsafe version'],
                     ['--dependency-version', 'linux-generic=7.0', '--dependency-version', 'linux-generic=8.0']]:
            result = subprocess.run(['bash', str(BUILDER), *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)

    def test_resolution_follows_authentication_and_precedes_package_build(self):
        script = (REPOSITORY / 'ubuntu-appliance/build-offline-repo.sh').read_text()
        self.assertLess(script.index('apt-get "${apt_options[@]}" update'), script.index('LC_ALL=C apt-cache'))
        self.assertLess(script.index('LC_ALL=C apt-cache'), script.index('"$repository_root/ubuntu-appliance/build-packages.sh"'))
        self.assertIn('"${dependency_version_arguments[@]}"', script)


if __name__ == '__main__':
    unittest.main()
