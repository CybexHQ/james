"""Static contracts for release-speed wiring in the protected release workflow."""
from pathlib import Path
import re
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/release.yml'


def job(body, name, following=None):
    start = body.index(f'  {name}:\n')
    end = body.index(f'  {following}:\n', start) if following else len(body)
    return body[start:end]


def step_script(body, name):
    match = re.search(rf'      - name: {re.escape(name)}\n.*?\n        run: \|\n(.*?)(?=\n      - name:)',
                      body, re.DOTALL)
    if match is None:
        raise AssertionError(f'missing workflow step: {name}')
    return textwrap.dedent(match.group(1))


class ReleaseSpeedWorkflowTests(unittest.TestCase):
    def test_failure_diagnostics_upload_without_admitting_failed_qualification(self):
        for body, name, success_name in (
                (self.warm, 'Retain qualification failure diagnostics', 'Upload bounded qualification evidence'),
                (self.cold, 'Retain cold qualification failure diagnostics',
                 'Retain published cold-install qualification evidence')):
            with self.subTest(name=name):
                diagnostic = body.split('      - name: ' + name + '\n', 1)[1].split('      - name:', 1)[0]
                self.assertIn('if: always()', diagnostic)
                self.assertIn('tiaris-nest-*-diagnostics.json', diagnostic)
                self.assertIn('github.run_attempt', diagnostic)
                self.assertIn('if-no-files-found: ignore', diagnostic)
                self.assertNotIn('config.json', diagnostic)
                acceptance = body.split('      - name: ' + success_name + '\n', 1)[1].split('      - name:', 1)[0]
                self.assertNotIn('if: always()', acceptance)
                self.assertIn('if-no-files-found: error', acceptance)


    @classmethod
    def setUpClass(cls):
        cls.body = WORKFLOW.read_text()
        cls.warm = job(cls.body, 'release_qualify', 'release_publish')
        cls.cold = job(cls.body, 'release_cold_qualify', 'release_promote')

    def test_cache_is_only_the_explicit_authenticated_warm_branch(self):
        branch = re.search(
            r'if \[ "\$TIARIS_NEST_HAS_PREDECESSOR" = true \].*?\n          else\n(.*?)\n          fi',
            self.warm, re.DOTALL)
        self.assertIsNotNone(branch)
        cached = self.warm[self.warm.index('if [ "$TIARIS_NEST_HAS_PREDECESSOR" = true ]',
                                            self.warm.index('Resolve exact predecessor media')):
                           branch.start(1)]
        for value in ('"$explicit_fixture" = true',
                      '"$TIARIS_NEST_QUALIFICATION_PREDECESSOR_CACHE_ROOT"',
                      'release/beast/release_speed.py cache', '--mode github-warm',
                      '--expected-identity dist/tiaris-nest-build-predecessor.json',
                      '--authorization release/recovery-adoption.json',
                      '--predecessor-manifest-sha256'):
            self.assertIn(value, cached)
        self.assertIn('nixos-appliance/qualification/release_predecessor.py', branch.group(1))
        self.assertIn('--download-media "${arguments[@]}"', branch.group(1))

    def test_enabled_cache_uses_private_snapshot_parent_with_runner_temp_0755(self):
        script = step_script(self.warm, 'Resolve exact predecessor media for disposable fixtures')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner_temp = root / 'runner-temp'
            runner_temp.mkdir(mode=0o755)
            runner_temp.chmod(0o755)
            tools = root / 'tools'
            tools.mkdir()
            predecessor_input = root / 'private-predecessor'
            predecessor_input.mkdir(mode=0o700)
            cache_root = root / 'private-cache'
            cache_root.mkdir(mode=0o700)
            argv = root / 'argv'
            fake_python = tools / 'python3'
            fake_python.write_text(textwrap.dedent('''\
                #!/bin/bash
                set -euo pipefail
                printf '%s\\n' "$@" > "$FAKE_ARGV"
                while [ "$#" -gt 0 ]; do
                  if [ "$1" = --directory ]; then
                    directory="$2"
                    break
                  fi
                  shift
                done
                test -n "${directory:-}"
                parent="$(dirname "$directory")"
                test "$(stat -c %a "$parent")" = 700
                test "$(stat -c %u "$parent")" = "$(id -u)"
                install -d -m 0700 "$directory"
                printf '%s\\n' '{"appliance_release_v1":{"schema":"tiaris.nest.appliance-release.v3"}}' > "$directory/tiaris-nest-release.json"
            '''))
            fake_python.chmod(0o755)
            fake_jq = tools / 'jq'
            fake_jq.write_text("#!/bin/sh\nprintf '%s\\n' tiaris.nest.appliance-release.v3\n")
            fake_jq.chmod(0o755)
            environment = {
                **os.environ,
                'PATH': f'{tools}:{os.environ["PATH"]}',
                'FAKE_ARGV': str(argv),
                'RUNNER_TEMP': str(runner_temp),
                'GITHUB_RUN_ID': '123',
                'GITHUB_RUN_ATTEMPT': '2',
                'GITHUB_REPOSITORY': 'example/nest',
                'TIARIS_NEST_HAS_PREDECESSOR': 'true',
                'TIARIS_NEST_NIXOS_QUALIFICATION_PREDECESSOR_DIR': str(predecessor_input),
                'TIARIS_NEST_NIXOS_QUALIFICATION_PREDECESSOR_MANIFEST_SHA256': 'a' * 64,
                'TIARIS_NEST_QUALIFICATION_PREDECESSOR_CACHE_ROOT': str(cache_root),
                'TIARIS_NEST_RELEASE_VERSION': '0.2.11',
                'TIARIS_NEST_UPDATE_TRUSTED_PUBLIC_KEY': 'synthetic-public-key',
            }
            subprocess.run(['bash', '-n'], input=script, text=True, check=True)
            subprocess.run(['bash'], input=script, text=True, cwd=ROOT, env=environment, check=True)
            snapshot_parent = runner_temp / 'tiaris-nest-predecessor-snapshot-123-2'
            self.assertEqual(stat.S_IMODE(snapshot_parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(runner_temp.stat().st_mode), 0o755)
            arguments = argv.read_text().splitlines()
            destination = arguments[arguments.index('--directory') + 1]
            self.assertEqual(Path(destination), snapshot_parent / 'predecessor')
            self.assertIn('--mode', arguments)
            self.assertEqual(arguments[arguments.index('--mode') + 1], 'github-warm')

    def test_current_serial_runner_and_lane_contract_are_unchanged(self):
        self.assertIn('group: nest-nixos-production-qualification', self.warm)
        self.assertIn('environment: production-release-qualification', self.warm)
        self.assertEqual(self.warm.count('run-production-qualification.py'), 1)
        self.assertNotIn('release_speed.py run', self.warm)
        self.assertNotIn('strategy:', self.warm)
        self.assertNotIn('matrix:', self.warm)

    def test_acceptance_and_timing_artifacts_are_separate_and_exact(self):
        acceptance = self.warm[self.warm.index('      - name: Upload bounded qualification evidence'):]
        warm_names = re.findall(
            r'\$\{\{ runner\.temp \}\}/tiaris-nest-evidence-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/(tiaris-nest-[a-z0-9-]+\.json)',
            acceptance)
        self.assertEqual(set(warm_names), {
            'tiaris-nest-nixos-qualification.json',
            'tiaris-nest-nixos-update-qualification.json',
            'tiaris-nest-nixos-rollback-qualification.json',
            'tiaris-nest-qualified-predecessor.json',
            'tiaris-nest-qualified-predecessor-release.json',
        })
        timing = re.search(r'- name: Upload bounded predecessor-cache timing\n(.*?)\n\n      - name:',
                           self.warm, re.DOTALL).group(1)
        self.assertIn('${{ github.run_id }}-${{ github.run_attempt }}', timing)
        self.assertEqual(timing.count('timing.json'), 1)
        self.assertNotIn('stdout.log', timing)
        self.assertNotIn('stderr.log', timing)
        self.assertNotIn('tiaris-nest-evidence', timing)

    def test_failure_diagnostic_upload_is_always_exact_and_separate_from_acceptance(self):
        diagnostic = self.warm.split('      - name: Retain bounded rollback failure diagnostic\n', 1)[1].split('\n      - name:', 1)[0]
        self.assertIn('if: always()', diagnostic)
        self.assertIn('if-no-files-found: ignore', diagnostic)
        self.assertIn('tiaris-nest-rollback-diagnostic-${{ github.run_id }}-${{ github.run_attempt }}', diagnostic)
        self.assertEqual(diagnostic.count('path:'), 1)
        self.assertEqual(diagnostic.count('tiaris-nest-nixos-rollback-failure.json'), 1)
        self.assertNotIn('*', diagnostic)
        self.assertNotIn('.log', diagnostic)

    def test_cold_still_downloads_published_bytes_without_warm_cache(self):
        self.assertIn('needs: [release_build, release_publish]', self.cold)
        self.assertIn('tools/local-candidate.py published', self.cold)
        self.assertIn('tiaris-nest-published-manifest.json', self.cold)
        self.assertIn('cargo run --release --locked --bin tiaris-nest-qualify-public-closure', self.cold)
        self.assertIn('--public-closure "$RUNNER_TEMP/tiaris-nest-cold-evidence-', self.cold)
        self.assertNotIn('release_speed.py cache', self.cold)
        self.assertNotIn('PREDECESSOR_CACHE_ROOT', self.cold)
        cold_names = re.findall(
            r'\$\{\{ runner\.temp \}\}/tiaris-nest-cold-evidence-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/(tiaris-nest-[a-z0-9-]+\.json)',
            self.cold)
        self.assertEqual(set(cold_names), {
            'tiaris-nest-published-cold-qualification.json',
            'tiaris-nest-published-workstation-qualification.json',
            'tiaris-nest-public-closure-qualification.json',
        })

    def test_protected_chain_and_cold_name_remain_fail_closed(self):
        self.assertIn('needs: [release_build, release_qualify]', job(self.body, 'release_publish', 'release_cold_qualify'))
        self.assertIn('name: Verify published NixOS release in an isolated fixture', self.cold)
        self.assertIn('environment: production-release-qualification', self.cold)
        promotion = job(self.body, 'release_promote')
        self.assertIn('needs: [release_build, release_cold_qualify]', promotion)
        self.assertIn('environment: production-release', promotion)


if __name__ == '__main__':
    unittest.main()
