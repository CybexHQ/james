"""A status console must recover when VT/graphics initialization clears it."""
from pathlib import Path
import subprocess
import unittest

CONSOLE = Path(__file__).resolve().parents[1] / "runtime/cybex-james-console"


class ConsoleRedraw(unittest.TestCase):
    def test_unchanged_status_is_redrawn_after_terminal_clear(self):
        result = subprocess.run(["bash", "-c", '''
            source "$1"
            trusted_device_name() { :; }
            render_screen
            printf '\\033c'
            render_screen
        ''', "console-test", str(CONSOLE)], check=True, capture_output=True)
        before, after = result.stdout.split(b"\x1bc")
        self.assertIn(b"Starting", before)
        self.assertIn(b"Starting", after)
        self.assertIn(b"Managed by Cybex Manage", after)


if __name__ == "__main__":
    unittest.main()
