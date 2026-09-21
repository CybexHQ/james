from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'ubuntu-appliance/rootfs/usr/lib/cybex-james/cybex-james-appliance-update-window'


class ApplianceUpdateScheduleTests(unittest.TestCase):
    def check_window(self, mode, *, day=0, hour=16, minute=0, start='02:00', duration=120, signed_state='legacy'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / 'plan.json'
            plan.write_text(json.dumps({'maintenance_window': {
                'timezone': 'UTC', 'weekday': 0, 'start': start,
                'duration_minutes': duration,
            }}))
            date = root / 'date'
            date.write_text(f'''#!/bin/sh
case "$1" in
  +%w) echo {day} ;;
  +%H) echo {hour:02d} ;;
  +%M) echo {minute:02d} ;;
  *) exit 1 ;;
esac
''')
            date.chmod(0o755)
            verifier = root / 'cybex-james'
            verifier.write_text('#!/bin/sh\necho ' + signed_state + '\n')
            verifier.chmod(0o755)
            helper = root / 'window'
            helper.write_text(HELPER.read_text().replace('/usr/bin/cybex-james', str(verifier)))
            env = dict(os.environ, PATH=f'{root}:' + os.environ['PATH'])
            env.pop('CYBEX_JAMES_APPLIANCE_UPDATE_SCHEDULE', None)
            if mode is not None:
                env['CYBEX_JAMES_APPLIANCE_UPDATE_SCHEDULE'] = mode
            return subprocess.run(['bash', str(helper), str(plan)], env=env,
                                  capture_output=True, text=True).returncode

    def test_approved_updates_default_to_immediate_outside_weekly_window(self):
        self.assertEqual(self.check_window(None), 0)
        self.assertEqual(self.check_window('immediate', day=3), 0)

    def test_explicit_window_waits_outside_and_at_end(self):
        self.assertEqual(self.check_window('maintenance_window'), 75)
        self.assertEqual(self.check_window('maintenance_window', hour=4), 75)

    def test_explicit_window_admits_start_and_inside(self):
        self.assertEqual(self.check_window('maintenance_window', hour=2), 0)
        self.assertEqual(self.check_window('maintenance_window', hour=3, minute=59), 0)

    def test_window_crosses_midnight(self):
        self.assertEqual(self.check_window('maintenance_window', start='23:00', day=1, hour=0), 0)
        self.assertEqual(self.check_window('maintenance_window', start='23:00', day=1, hour=1), 75)

    def test_signed_policy_takes_precedence_over_local_legacy_defaults(self):
        self.assertEqual(self.check_window('immediate', signed_state='waiting'), 75)
        self.assertEqual(self.check_window('maintenance_window', signed_state='ready'), 0)
        self.assertEqual(self.check_window('immediate', signed_state='invalid'), 1)

    def test_invalid_policy_fails_closed(self):
        self.assertEqual(self.check_window('unexpected'), 1)
        self.assertEqual(self.check_window('maintenance_window', duration=0), 1)
        self.assertEqual(self.check_window('maintenance_window', start='broken'), 1)


if __name__ == '__main__':
    unittest.main()
