"""Real pinned NixOS evaluation of durable installed QGA; no builds or signing."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstalledGuestAgent(unittest.TestCase):
    @unittest.skipUnless(shutil.which("nix-instantiate"), "requires Nix for real module evaluation")
    def test_installed_system_has_channel_activated_guest_agent(self):
        result = subprocess.run(
            ["nix-instantiate", "--eval", "--strict", "--json", "--expr",
             "import ./nixos-appliance/tests/guest-agent-evaluation.nix {}"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        checks = json.loads(result.stdout)
        self.assertTrue(checks["installedGuestAgentEnabled"])
        self.assertTrue(checks["guestAgentActivatedOnlyByVirtioChannel"])
        self.assertTrue(all(checks.values()), checks)


if __name__ == "__main__":
    unittest.main()
