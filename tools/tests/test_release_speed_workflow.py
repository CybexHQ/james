"""Static contracts for release-speed wiring in the protected release workflow."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/release.yml'


def job(body, name, following=None):
    start = body.index(f'  {name}:\n')
    end = body.index(f'  {following}:\n', start) if following else len(body)
    return body[start:end]


class ReleaseSpeedWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = WORKFLOW.read_text()
        cls.warm = job(cls.body, 'release_qualify', 'release_publish')
        cls.cold = job(cls.body, 'release_cold_qualify', 'release_promote')

    def test_cache_is_only_the_explicit_authenticated_warm_branch(self):
        branch = re.search(
            r'if \[ "\$CYBEX_JAMES_HAS_PREDECESSOR" = true \].*?\n          else\n(.*?)\n          fi',
            self.warm, re.DOTALL)
        self.assertIsNotNone(branch)
        cached = self.warm[self.warm.index('if [ "$CYBEX_JAMES_HAS_PREDECESSOR" = true ]',
                                            self.warm.index('Resolve exact predecessor media')):
                           branch.start(1)]
        for value in ('"$explicit_fixture" = true',
                      '"$CYBEX_JAMES_QUALIFICATION_PREDECESSOR_CACHE_ROOT"',
                      'release/beast/release_speed.py cache', '--mode github-warm',
                      '--expected-identity dist/cybex-james-build-predecessor.json',
                      '--authorization release/recovery-adoption.json',
                      '--predecessor-manifest-sha256'):
            self.assertIn(value, cached)
        self.assertIn('nixos-appliance/qualification/release_predecessor.py', branch.group(1))
        self.assertIn('--download-media "${arguments[@]}"', branch.group(1))

    def test_current_serial_runner_and_lane_contract_are_unchanged(self):
        self.assertIn('group: james-nixos-development-qualification', self.warm)
        self.assertIn('environment: james-nixos-development-qualification', self.warm)
        self.assertEqual(self.warm.count('run-production-qualification.py'), 1)
        self.assertNotIn('release_speed.py run', self.warm)
        self.assertNotIn('strategy:', self.warm)
        self.assertNotIn('matrix:', self.warm)

    def test_acceptance_and_timing_artifacts_are_separate_and_exact(self):
        warm_names = re.findall(
            r'\$\{\{ runner\.temp \}\}/cybex-james-evidence/(cybex-james-[a-z0-9-]+\.json)',
            self.warm)
        self.assertEqual(set(warm_names), {
            'cybex-james-nixos-qualification.json',
            'cybex-james-nixos-update-qualification.json',
            'cybex-james-nixos-rollback-qualification.json',
            'cybex-james-qualified-predecessor.json',
            'cybex-james-qualified-predecessor-release.json',
        })
        timing = re.search(r'- name: Upload bounded predecessor-cache timing\n(.*?)\n\n      - name:',
                           self.warm, re.DOTALL).group(1)
        self.assertIn('${{ github.run_id }}-${{ github.run_attempt }}', timing)
        self.assertEqual(timing.count('timing.json'), 1)
        self.assertNotIn('stdout.log', timing)
        self.assertNotIn('stderr.log', timing)
        self.assertNotIn('cybex-james-evidence', timing)

    def test_cold_still_downloads_published_bytes_without_warm_cache(self):
        self.assertIn('needs: [release_build, release_publish]', self.cold)
        self.assertIn('tools/local-candidate.py published', self.cold)
        self.assertIn('cybex-james-published-manifest.json', self.cold)
        self.assertNotIn('release_speed.py cache', self.cold)
        self.assertNotIn('PREDECESSOR_CACHE_ROOT', self.cold)
        cold_names = re.findall(
            r'\$\{\{ runner\.temp \}\}/cybex-james-cold-evidence/(cybex-james-[a-z0-9-]+\.json)',
            self.cold)
        self.assertEqual(set(cold_names), {
            'cybex-james-published-cold-qualification.json',
            'cybex-james-published-workstation-qualification.json',
        })

    def test_protected_chain_and_cold_name_remain_fail_closed(self):
        self.assertIn('needs: [release_build, release_qualify]', job(self.body, 'release_publish', 'release_cold_qualify'))
        self.assertIn('name: Verify published release on a cold development fixture', self.cold)
        self.assertIn('environment: james-nixos-development-qualification', self.cold)
        promotion = job(self.body, 'release_promote')
        self.assertIn('needs: [release_build, release_cold_qualify]', promotion)
        self.assertIn('environment: production-release', promotion)


if __name__ == '__main__':
    unittest.main()
