"""Exercise the installer's actual route collision check in a private namespace."""
import json
import os
from pathlib import Path
import subprocess
import unittest


@unittest.skipUnless(os.environ.get("CI") == "true", "requires disposable CI guest")
class StaticNetworkPreflight(unittest.TestCase):
    def test_unused_and_occupied_kernel_route_namespaces(self):
        virtualization = subprocess.check_output(
            ["systemd-detect-virt", "--vm"], text=True, timeout=5,
        ).strip()
        self.assertIn(virtualization, {"qemu", "kvm"}, "requires disposable QEMU guest")
        repository = Path(__file__).resolve().parents[2]
        build = subprocess.run(
            ["cargo", "test", "--locked", "--lib",
             "static_preflight_namespace_checks_real_kernel_tables", "--no-run", "--message-format=json"],
            cwd=repository, text=True, capture_output=True, timeout=600,
        )
        self.assertEqual(build.returncode, 0, build.stderr)
        artifacts = [json.loads(line) for line in build.stdout.splitlines()]
        executables = [row["executable"] for row in artifacts
                       if row.get("reason") == "compiler-artifact" and row.get("executable")
                       and row["profile"].get("test")]
        self.assertEqual(len(executables), 1, "must select one real Rust test executable")
        # The network namespace belongs to this process and disappears even
        # after assertion failures. The test also requires root and only lo.
        result = subprocess.run(
            ["sudo", "-n", "unshare", "--net", "--", "env", "CI=true",
             "TIARIS_DISPOSABLE_NETWORK_QUALIFICATION=1", executables[0],
             "provisioning::inventory::tests::static_preflight_namespace_checks_real_kernel_tables",
             "--exact", "--ignored", "--nocapture"],
            cwd=repository, text=True, capture_output=True, timeout=60,
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("1 passed; 0 failed", output, "empty selections cannot qualify preflight")


if __name__ == "__main__":
    unittest.main()
