import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'tools' / 'ci-host-reservation.sh'
WORKFLOW = (ROOT / '.github' / 'workflows' / 'release.yml').read_text()

# Prints one admission line, then holds until stdin closes, like ci-platform.
FAKE = """#!/usr/bin/env python3
import json, os, sys
log = os.environ['FAKE_LOG']
with open(log, 'a') as stream:
    stream.write('args ' + json.dumps(sys.argv[1:]) + '\\n')
if os.environ.get('FAKE_FAIL'):
    sys.exit(1)
print(json.dumps({'reservation': 'ci-job-' + 'a' * 32}), flush=True)
while sys.stdin.read(65536):
    pass
with open(log, 'a') as stream:
    stream.write('released\\n')
"""


def step_script(job, name):
    start = WORKFLOW.index(f'  {job}:\n')
    step = WORKFLOW.index(f'      - name: {name}\n', start)
    run = WORKFLOW.index('        run: |\n', step) + len('        run: |\n')
    lines = []
    for line in WORKFLOW[run:].splitlines():
        if line and not line.startswith('          '):
            break
        lines.append(line[10:])
    return '\n'.join(lines)


class CiHostReservationTests(unittest.TestCase):
    def run_helper(self, body, **environment):
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / 'ci-platform'
            fake.write_text(FAKE)
            fake.chmod(0o755)
            log = Path(temporary) / 'log'
            env = {**os.environ, 'PATH': temporary + os.pathsep + os.environ['PATH'],
                   'FAKE_LOG': str(log), **environment}
            script = f'set -Eeuo pipefail\nsource {HELPER}\n{body}'
            result = subprocess.run(['bash', '-c', script], env=env, text=True, capture_output=True)
            for _ in range(50):
                if not log.exists() or 'released' in log.read_text() or environment.get('FAKE_FAIL'):
                    break
                time.sleep(0.05)
            return result, log.read_text() if log.exists() else ''

    def test_reservation_is_held_while_the_step_runs_and_released_when_it_ends(self):
        result, log = self.run_helper(
            'reserve_ci_host_capacity "Nest qualification 7-1" 32 12\n'
            'grep -q released "$FAKE_LOG" && exit 9\n'
            'echo step-body-ran\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Reserved CI host capacity: {"reservation": "ci-job-', result.stdout)
        self.assertIn('step-body-ran', result.stdout)
        self.assertIn('["reserve", "--purpose", "Nest qualification 7-1", "--memory-gib", "32", '
                      '"--cpus", "12", "--wait-seconds", "7200"]', log)
        self.assertTrue(log.endswith('released\n'))

    def test_failing_step_still_releases_the_reservation(self):
        result, log = self.run_helper('reserve_ci_host_capacity "Nest build 7-1" 48 12\nfalse\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(log.endswith('released\n'))

    def test_admission_failure_stops_the_step_before_heavy_work(self):
        result, _ = self.run_helper('reserve_ci_host_capacity "Nest build 7-1" 48 12\necho heavy-work\n',
                                    FAKE_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('heavy-work', result.stdout)
        self.assertIn('CI host capacity reservation failed: Nest build 7-1', result.stderr)

    def test_host_side_heavy_steps_reserve_before_starting_work(self):
        for job, name, heavy, size in (
                ('release_build', 'Build exact binaries, appliance media, and workstation runtime',
                 'python3 tools/beast-build.py', '48 12'),
                ('release_qualify', 'Qualify fresh installation, real upgrade and automatic rollback',
                 'sudo -n python3 -B nixos-appliance/qualification/prepare-fixture-config.py', '32 12'),
                ('release_cold_qualify', 'Require exact published bytes and cold runtime convergence',
                 'sudo -n python3 -B nixos-appliance/qualification/prepare-fixture-config.py', '32 12')):
            with self.subTest(job=job):
                script = step_script(job, name)
                reserve = script.index('reserve_ci_host_capacity ')
                self.assertLess(script.index('source tools/ci-host-reservation.sh'), reserve)
                self.assertLess(reserve, script.index(heavy))
                self.assertIn('$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" ' + size + '\n', script)
                self.assertNotIn('sudo -n ci-platform', script)


if __name__ == '__main__':
    unittest.main()
