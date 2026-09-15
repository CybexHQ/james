"""Exercise candidate admission before any network or VM operation."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
HARNESS = REPOSITORY / "ubuntu-appliance/qualification/run-lifecycle.sh"
WORKFLOW = REPOSITORY / ".github/workflows/release.yml"


class CandidateSourceContractTests(unittest.TestCase):
    def test_workflow_signs_the_checked_out_james_revision(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        manifest_command = workflow.split(
            "python3 tools/james-release.py manifest \\\n", 1
        )[1].split("python3 tools/james-release.py compatibility", 1)[0]
        self.assertIn(
            '--appliance-source-revision "$(git rev-parse HEAD)"',
            manifest_command,
        )

    def test_lifecycle_requires_v2_bound_to_its_exact_checkout(self):
        revision = subprocess.check_output(
            ["git", "-C", str(REPOSITORY), "rev-parse", "HEAD"], text=True
        ).strip()
        cases = (
            ("current", "cybex.james.appliance-release.v2", revision, True),
            ("legacy", "cybex.james.appliance-release.v1", None, False),
            ("missing-source", "cybex.james.appliance-release.v2", None, False),
            ("wrong-source", "cybex.james.appliance-release.v2", "0" * 40, False),
            ("malformed-source", "cybex.james.appliance-release.v2", "HEAD", False),
            ("unknown-schema", "cybex.james.appliance-release.v3", revision, False),
        )
        for name, schema, source, accepted in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binaries = root / "bin"
                binaries.mkdir()
                reached = root / "network-preflight"
                forbidden = root / "unexpected-operation"
                # The first network probe is our boundary. Return no addresses so
                # the real harness stops before serving packages or creating a VM.
                (binaries / "ip").write_text(
                    '#!/bin/sh\n: > "$TEST_NETWORK_PREFLIGHT"\n', encoding="utf-8"
                )
                for command in ("curl", "qemu-system-x86_64"):
                    (binaries / command).write_text(
                        '#!/bin/sh\n: > "$TEST_UNEXPECTED_OPERATION"\nexit 99\n',
                        encoding="utf-8",
                    )
                for binary in binaries.iterdir():
                    binary.chmod(0o755)
                package = root / "cybex-james-appliance-packages-0.2.1-test-x86_64-linux.tar.zst"
                package.write_bytes(b"fixture package")
                descriptor = {
                    "schema": schema,
                    "ubuntu_snapshot_id": "20260805T000000Z",
                    "cybex_repository_snapshot": {
                        "url": "https://manage.example/" + package.name,
                        "sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                        "size_bytes": package.stat().st_size,
                    },
                }
                if source is not None:
                    descriptor["source_revision"] = source
                manifest = root / "release.json"
                manifest.write_text(json.dumps({
                    "version": "0.2.1-test",
                    "installer_iso_template_v2": {
                        "manage_origin": "https://manage.example",
                        "package_delivery": "network-snapshot-v1",
                    },
                    "appliance_release_v1": descriptor,
                }), encoding="utf-8")
                template = root / "template.iso"
                template.touch()
                token = root / "token"
                token.write_text("fixture-token", encoding="utf-8")
                environment = {
                    key: value for key, value in os.environ.items()
                    if not key.startswith("CYBEX_JAMES_")
                }
                environment.update({
                    "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
                    "CYBEX_JAMES_QUALIFICATION_BRIDGE": "fixturebr0",
                    "CYBEX_JAMES_QUALIFICATION_MANAGEMENT_CIDR": "192.0.2.0/24",
                    "CYBEX_JAMES_HAS_PREDECESSOR": "true",
                    "TEST_NETWORK_PREFLIGHT": str(reached),
                    "TEST_UNEXPECTED_OPERATION": str(forbidden),
                })
                result = subprocess.run([
                    "bash", str(HARNESS), "--template", str(template),
                    "--manifest", str(manifest), "--manage-origin", "https://manage.example",
                    "--token-file", str(token), "--output", str(root / "evidence.json"),
                ], env=environment, capture_output=True, text=True, timeout=15)
                self.assertFalse(forbidden.exists(), result.stderr)
                self.assertEqual(reached.exists(), accepted, result.stderr)
                self.assertNotEqual(result.returncode, 0)
                if accepted:
                    self.assertIn("has no private IPv4 address", result.stderr)


if __name__ == "__main__":
    unittest.main()
