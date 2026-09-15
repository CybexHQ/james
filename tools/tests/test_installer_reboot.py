"""Exercise ISO boot configuration and automatic-reboot qualification without a VM."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
TEMPLATE = REPOSITORY / "ubuntu-appliance/build-template.sh"
LIFECYCLE = REPOSITORY / "ubuntu-appliance/qualification/run-lifecycle.sh"


class InstallerRebootTests(unittest.TestCase):
    def test_every_installer_boot_entry_suppresses_casper_console_wait(self):
        source = TEMPLATE.read_text()
        start = source.index("kernel_arguments=")
        end = source.index("\n\n", start)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("grub.cfg", "loopback.cfg", "txt.cfg"):
                (root / name).write_text(
                    "linux /casper/vmlinuz ---\n"
                    "linux /casper/vmlinuz quiet ---\n"
                )
            subprocess.run(
                ["bash", "-eu", "-c", source[start:end]],
                env={**os.environ, "iso_tree": directory},
                check=True,
                capture_output=True,
            )
            for config in root.iterdir():
                for entry in config.read_text().splitlines():
                    with self.subTest(config=config.name, entry=entry):
                        arguments = entry.split()
                        # Ubuntu's casper-stop otherwise reads /dev/console at
                        # shutdown, including when completed media boots again.
                        self.assertIn("noprompt", arguments)
                        self.assertLess(arguments.index("noprompt"), arguments.index("---"))
                        self.assertIn("autoinstall", arguments)
                        self.assertIn("console=tty0", arguments)

    def run_transition(self, root, *, ready_after=0, serial=True):
        source = LIFECYCLE.read_text()
        start = source.index("ready=false\n")
        end = source.index('test "$ready" = true', start) + len('test "$ready" = true')
        if serial:
            console = root / "serial.log"
            console.write_text("Rebooting into the managed appliance\n")
            os.utime(console, (1, 1))
        # Simulate a stalled VM that would become ready only if the harness
        # cold-started it. Advancing shell SECONDS avoids a real five-minute wait.
        setup = r'''
set -Eeuo pipefail
session="$work_dir/session.json"
session_id=fixture
qemu_pid=fixture
qemu_restart_count=0
cold_restart_deadline=0
pre_destructive_deadline=0
SECONDS=0
api() {
  local count=0
  if [[ -f "$work_dir/polls" ]]; then read -r count < "$work_dir/polls"; fi
  count=$((count + 1))
  echo "$count" > "$work_dir/polls"
  if [[ -f "$work_dir/recovery" ]] || ((ready_after > 0 && count >= ready_after)); then
    echo '{"state":"ready"}'
  else
    echo '{"state":"rebooting"}'
  fi
}
kill() { :; }
wait() { :; }
start_qemu() { echo "$*" > "$work_dir/recovery"; }
sleep() { SECONDS=$((SECONDS + 60)); }
'''
        return subprocess.run(
            ["bash", "-c", setup + source[start:end]],
            env={**os.environ, "work_dir": str(root), "ready_after": str(ready_after)},
            capture_output=True,
            text=True,
            timeout=5,
        )

    def test_stalled_reboot_fails_without_recovery_even_with_no_console(self):
        for serial in (True, False):
            with self.subTest(serial=serial), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result = self.run_transition(root, serial=serial)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("did not complete its automatic reboot", result.stderr)
                self.assertFalse((root / "recovery").exists())
                self.assertLessEqual(int((root / "polls").read_text()), 7)

    def test_automatic_transition_to_ready_succeeds_without_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.run_transition(root, ready_after=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "recovery").exists())


if __name__ == "__main__":
    unittest.main()
