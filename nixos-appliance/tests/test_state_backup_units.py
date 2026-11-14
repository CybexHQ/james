"""The automatic state backup timer and service (module.nix)."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StateBackupUnits(unittest.TestCase):
    module = (ROOT / 'module.nix').read_text()

    def timer(self):
        match = re.search(r'systemd\.timers\.tiaris-nest-state-backup = (.*?);\n', self.module)
        self.assertIsNotNone(match, 'state backup timer not found')
        return match.group(1)

    def test_the_timer_runs_daily_spread_out_and_catches_up(self):
        timer = self.timer()
        self.assertIn('wantedBy = [ "timers.target" ]', timer)
        self.assertIn('OnCalendar = "daily"', timer)
        self.assertIn('RandomizedDelaySec = "4h"', timer)
        self.assertIn('Persistent = true', timer)

    def test_the_service_needs_the_public_key_and_never_makes_one(self):
        block = self.module.split('systemd.services.tiaris-nest-state-backup = {', 1)[1].split('\n    };', 1)[0]
        self.assertIn('ConditionPathExists = "/var/lib/tiaris-nest/state/backup/recipient.pub"', block)
        self.assertIn('tiaris-nest scheduled-state-backup"', block)
        self.assertNotIn('generate-state-backup-key', self.module)
        self.assertNotIn('wantedBy', block)

    @unittest.skipUnless(shutil.which('nix-instantiate'), 'requires Nix for real module evaluation')
    def test_evaluated_units(self):
        result = subprocess.run(
            ['nix-instantiate', '--eval', '--read-write-mode', '--strict', '--json', '--expr',
             'import ./nixos-appliance/tests/state-backup-evaluation.nix {}'],
            cwd=ROOT.parent, capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        checks = json.loads(result.stdout)
        self.assertEqual(set(checks), {
            'timerIsEnabled', 'timerRunsDaily', 'timerCatchesUpAfterDowntime', 'timerSpreadsNestsOut',
            'serviceRunsOnlyWithABackupKey', 'serviceIsAOneshot', 'serviceRunsTheScheduledBackup',
            'serviceRunsAsRoot', 'serviceWritesOnlyItsPaths', 'serviceIsNotStartedAtBoot',
            'backupFolderIsReadableByTheNest'})
        self.assertTrue(all(value is True for value in checks.values()), checks)


if __name__ == '__main__':
    unittest.main()
