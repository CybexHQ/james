"""The tty1 screens are the native kiosk fed by bounded status projections.

The readiness rules of the retired `tiaris-nest-console` shell script now live
in Rust (`src/console_status.rs`) with unit tests; the setup projection lives
in `src/provisioning/setup_status.rs`. These checks keep the Nix wiring, the
Rust writers and the kiosk's documented defaults on the same paths without
evaluating Nix.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
APPLIANCE = ROOT / "nixos-appliance"


def rust_constant(path, name):
    match = re.search(rf'pub const {name}: &str = "([^"]+)";', (ROOT / path).read_text())
    if not match:
        raise AssertionError(f"{name} is missing from {path}")
    return match.group(1)


class ConsoleWiring(unittest.TestCase):
    def test_retired_shell_console_is_not_packaged(self):
        self.assertFalse((APPLIANCE / "runtime/tiaris-nest-console").exists())
        self.assertNotIn('command "console"', (APPLIANCE / "module.nix").read_text())

    def test_setup_iso_runs_the_setup_kiosk_on_its_status(self):
        iso = (APPLIANCE / "iso.nix").read_text()
        path = rust_constant("src/provisioning/setup_status.rs", "SETUP_STATUS_PATH")
        self.assertEqual(path, "/run/tiaris-nest-setup/status.json")
        self.assertIn(f'setupStatus = "{path}";', iso)
        self.assertIn("/bin/tiaris-installer-kiosk --nest-setup", iso)
        self.assertIn('RuntimeDirectory = "tiaris-nest-setup"; RuntimeDirectoryMode = "0755"; RuntimeDirectoryPreserve = "yes";', iso)
        self.assertNotIn("Continue in Tiaris.", iso)

    def test_appliance_runs_the_appliance_kiosk_on_daemon_status(self):
        module = (APPLIANCE / "module.nix").read_text()
        path = rust_constant("src/console_status.rs", "CONSOLE_STATUS_PATH")
        self.assertEqual(path, "/run/tiaris-nest/console-status.json")
        self.assertIn(f'TIARIS_NEST_CONSOLE_STATUS = "{path}";', module)
        self.assertIn("/bin/tiaris-installer-kiosk --appliance", module)
        self.assertIn('RuntimeDirectory = "tiaris-nest"; RuntimeDirectoryMode = "0755"; RuntimeDirectoryPreserve = "yes";', module)
        self.assertIn('"/run/tiaris-nest" ]', module)

    def test_both_screens_keep_the_text_fallback_on_tty1(self):
        for name in ("iso.nix", "module.nix"):
            source = (APPLIANCE / name).read_text()
            unit = source[source.index("/bin/tiaris-installer-kiosk"):]
            unit = unit[:unit.index("};")]
            for setting in ('StandardOutput = "tty"', 'TTYPath = "/dev/tty1"', 'Restart = "always"'):
                self.assertIn(setting, unit, name)
            self.assertIn('systemd.services."getty@tty1".enable = false;', source)
            self.assertIn('systemd.services."autovt@tty1".enable = false;', source)

    def test_schemas_match_the_kiosk_contract(self):
        self.assertEqual(
            rust_constant("src/provisioning/setup_status.rs", "SETUP_STATUS_SCHEMA"),
            "tiaris.nest-setup-status.v1",
        )
        self.assertEqual(
            rust_constant("src/console_status.rs", "CONSOLE_STATUS_SCHEMA"),
            "tiaris.nest-console-status.v1",
        )


if __name__ == "__main__":
    unittest.main()
