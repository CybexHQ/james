"""Exercise candidate admission before any network or VM operation."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
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
                policy_checked = root / "policy-checked"
                catalog_checked = root / "catalog-checked"
                forbidden = root / "unexpected-operation"
                # Admit only the new read-only policy/catalog checks. Invalid
                # source identities must stop before either check is reached.
                admission_stub = f"#!{sys.executable}\n" + textwrap.dedent('''\
                    import json
                    import os
                    from pathlib import Path
                    import sys

                    args = sys.argv[1:]
                    if Path(sys.argv[0]).name == "curl":
                        if ("--request" in args
                                and args[args.index("--request") + 1] == "GET"
                                and args[-1] == "https://manage.example/v1/james/delivery-policy"):
                            Path(os.environ["TEST_POLICY_CHECKED"]).touch()
                            print(json.dumps({"allow_james_source_builds": False,
                                              "source_builds_allowed": False}))
                        else:
                            Path(os.environ["TEST_UNEXPECTED_OPERATION"]).touch()
                            raise SystemExit(99)
                    elif args[:2] == ["-B", os.environ["TEST_CATALOG_HELPER"]]:
                        Path(os.environ["TEST_CATALOG_CHECKED"]).touch()
                        print(json.dumps({"schema": "cybex.james.qualification-blueprints.v1",
                                          "blueprints": []}))
                    else:
                        os.execv(sys.executable, [sys.executable, *args])
                    ''')
                for command in ("curl", "python3"):
                    (binaries / command).write_text(admission_stub, encoding="utf-8")
                # Return no bridge addresses so the real harness stops before
                # serving packages, mutating the organization, or creating a VM.
                (binaries / "ip").write_text(
                    '#!/bin/sh\n: > "$TEST_NETWORK_PREFLIGHT"\n', encoding="utf-8"
                )
                (binaries / "qemu-system-x86_64").write_text(
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
                    "TEST_POLICY_CHECKED": str(policy_checked),
                    "TEST_CATALOG_CHECKED": str(catalog_checked),
                    "TEST_CATALOG_HELPER": str(
                        REPOSITORY / "ubuntu-appliance/qualification/blueprint-catalog.py"
                    ),
                    "TEST_UNEXPECTED_OPERATION": str(forbidden),
                })
                result = subprocess.run([
                    "bash", str(HARNESS), "--template", str(template),
                    "--manifest", str(manifest), "--manage-origin", "https://manage.example",
                    "--token-file", str(token), "--output", str(root / "evidence.json"),
                ], env=environment, capture_output=True, text=True, timeout=15)
                self.assertFalse(forbidden.exists(), result.stderr)
                self.assertEqual(policy_checked.exists(), accepted, result.stderr)
                self.assertEqual(catalog_checked.exists(), accepted, result.stderr)
                self.assertEqual(reached.exists(), accepted, result.stderr)
                self.assertNotEqual(result.returncode, 0)
                if accepted:
                    self.assertIn("has no private IPv4 address", result.stderr)


if __name__ == "__main__":
    unittest.main()
