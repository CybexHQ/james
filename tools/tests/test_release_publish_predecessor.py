"""Exercise the predecessor download setup in the final publish step."""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]


def publish_predecessor_script():
    workflow = (ROOT / '.github/workflows/release.yml').read_text()
    step = workflow.split('      - name: Verify remote draft assets and publish immutably\n', 1)[1]
    step = step.split('\n      - name:', 1)[0]
    script = textwrap.dedent(step.split('        run: |\n', 1)[1])
    start = script.index('predecessor="')
    end = script.index('"${arguments[@]}"', start) + len('"${arguments[@]}"')
    return 'set -Eeuo pipefail\n' + script[start:end] + '\n'


class PublishPredecessorTests(unittest.TestCase):
    def test_stale_runner_directory_is_never_reused(self):
        script = publish_predecessor_script()
        subprocess.run(['bash', '-n'], input=script, text=True, check=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stale = root / 'cybex-james-publish-predecessor'
            stale.mkdir()
            (stale / 'cybex-james-release.json').write_text('stale release')
            fake_bin = root / 'bin'
            fake_bin.mkdir()
            fake_python = fake_bin / 'python3'
            fake_python.write_text('''#!/bin/sh
printf '%s\\n' "$@" > "$TEST_ARGUMENTS"
while [ "$#" -gt 0 ]; do
    if [ "$1" = --directory ]; then
        test -d "$2" && test "$(stat -c %a "$2")" = 700 || exit 1
        exit "${TEST_PYTHON_STATUS:-0}"
    fi
    shift
done
exit 1
''')
            fake_python.chmod(0o755)
            seen = []
            for attempt in ('1', '2', '3'):
                arguments = root / f'arguments-{attempt}'
                environment = {**os.environ,
                    'PATH': f'{fake_bin}:{os.environ["PATH"]}',
                    'RUNNER_TEMP': str(root), 'GITHUB_RUN_ID': '42',
                    'GITHUB_RUN_ATTEMPT': attempt, 'GITHUB_REPOSITORY': 'CybexHQ/james',
                    'CYBEX_JAMES_HAS_PREDECESSOR': 'true',
                    'CYBEX_JAMES_RELEASE_VERSION': '0.2.28',
                    'CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY': 'test-key',
                    'TEST_ARGUMENTS': str(arguments),
                    'TEST_PYTHON_STATUS': '7' if attempt == '3' else '0'}
                result = subprocess.run(['bash'], input=script, text=True,
                    cwd=ROOT, env=environment, capture_output=True)
                self.assertEqual(result.returncode, 7 if attempt == '3' else 0, result.stderr)
                argv = arguments.read_text().splitlines()
                directory = Path(argv[argv.index('--directory') + 1])
                seen.append(directory)
                self.assertEqual(directory, Path(argv[argv.index('--output') + 1]).parent)
                self.assertTrue(directory.name.startswith(f'cybex-james-publish-predecessor-42-{attempt}.'))
                self.assertIn('--expected-identity', argv)
                self.assertEqual(argv[argv.index('--expected-identity') + 1],
                                 'dist/cybex-james-build-predecessor.json')
                self.assertFalse(directory.exists(), 'temporary predecessor must be removed')
                self.assertEqual((stale / 'cybex-james-release.json').read_text(), 'stale release')
            self.assertNotEqual(seen[0], seen[1])


if __name__ == '__main__':
    unittest.main()
