"""The real installer must supply the DNS probe used before disk preparation."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which("nix-instantiate"), "Nix module evaluation requires Nix")
class IsoPreflight(unittest.TestCase):
    def test_static_network_dns_probe_is_available_to_the_bootstrap(self):
        expression = Path(__file__).with_name("iso-preflight-evaluation.nix")
        result = subprocess.run(
            ["nix-instantiate", "--eval", "--strict", "--json", "--expr",
             "import (builtins.toPath " + json.dumps(str(expression)) + ") {}"],
            text=True, capture_output=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        checks = json.loads(result.stdout)
        self.assertTrue(checks["isoHasDnsProbe"], "The signed ISO omits dig")
        self.assertTrue(checks["bootstrapHasDnsProbe"], "Bootstrap PATH omits dig")


if __name__ == "__main__":
    unittest.main()
