from __future__ import annotations

import base64
import contextlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
TOOL = REPOSITORY / "tools" / "software-base.py"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def scan(*entries: tuple[str, list[str], dict[str, float]]) -> list[dict[str, object]]:
    return [
        {"name": f"{name}-1", "pname": name, "affected_by": affected, "cvssv3_basescore": scores}
        for name, affected, scores in entries
    ]


class SoftwareBaseToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.private_key = self.directory / "release-key.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private_key)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.private_key.chmod(0o600)
        public_der = subprocess.run(
            ["openssl", "pkey", "-in", str(self.private_key), "-pubout", "-outform", "DER"],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.public_key = base64.b64encode(public_der[-32:]).decode("ascii")
        self.module = runpy.run_path(str(TOOL))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_tool(self, *arguments: str) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = self.module["main"](list(arguments))
        return status, output.getvalue()

    def draft(self) -> Path:
        previous = self.directory / "previous.json"
        current = self.directory / "current.json"
        previous.write_text(json.dumps(scan(
            ("linux", ["CVE-2026-40112", "CVE-2026-40031"], {"CVE-2026-40112": 7.8, "CVE-2026-40031": 3.3}),
            ("firefox", ["CVE-2026-40287"], {"CVE-2026-40287": 9.6}),
            ("curl", ["CVE-2026-39020"], {}),
        )))
        current.write_text(json.dumps(scan(("curl", ["CVE-2026-39020"], {}))))
        status, output = self.run_tool(
            "draft", "--commit", COMMIT, "--base-id", "nixos-26.05-2026-10-23",
            "--title", "Security update · 23 October", "--captured-at", "2026-10-23T06:00:00Z",
            "--approved-at", "2026-10-26T09:00:00Z", "--support-ends-at", "2026-12-31T23:59:59Z",
            "--kernel-version", "6.12.53", "--previous-kernel", "6.12.48",
            "--previous-vulnix", str(previous), "--vulnix", str(current),
            "--supersedes", "nixos-26.05-2026-10-16",
        )
        self.assertEqual(status, 0)
        path = self.directory / "draft.json"
        path.write_text(output)
        return path

    def test_draft_lists_only_fixed_advisories_by_severity(self) -> None:
        document = json.loads(self.draft().read_text())
        self.assertEqual(document["kind"], "security")
        self.assertEqual(document["severity"], "critical")
        self.assertEqual(
            [advisory["id"] for advisory in document["advisories"]],
            ["CVE-2026-40287", "CVE-2026-40112", "CVE-2026-40031"],
        )
        self.assertEqual(document["advisories"][0]["component"], "Firefox")
        self.assertEqual(document["highlights"][0]["to"], "6.12.53")
        self.assertNotIn("signature", document)

    def test_signs_publishes_and_verifies_a_feed(self) -> None:
        draft = self.draft()
        signed_dir = self.directory / "signed"
        status, _ = self.run_tool(
            "sign", "--private-key", str(self.private_key), "--trusted-public-key", self.public_key,
            "--output-dir", str(signed_dir), str(draft),
        )
        self.assertEqual(status, 0)
        signed = signed_dir / "nixos-26.05-2026-10-23.json"
        feed = self.directory / "tiaris-software-bases.json"
        self.assertEqual(self.run_tool("feed", "--output", str(feed), str(signed))[0], 0)
        status, output = self.run_tool("verify", "--trusted-public-key", self.public_key, str(feed))
        self.assertEqual(status, 0, output)
        # The signed bytes are exactly what Manage verifies.
        document = json.loads(signed.read_text())
        payload = self.module["payload"](document)
        self.assertTrue(payload.startswith(b"TIARIS-SOFTWARE-BASE-V1\n{\"advisories\":"))
        tampered = json.loads(feed.read_text())
        tampered["bases"][0]["kernel_version"] = "6.12.54"
        feed.write_text(json.dumps(tampered))
        self.assertEqual(self.run_tool("verify", "--trusted-public-key", self.public_key, str(feed))[0], 1)

    def test_refuses_another_key_and_duplicate_bases(self) -> None:
        draft = self.draft()
        other = base64.b64encode(bytes(range(1, 33))).decode("ascii")
        status, _ = self.run_tool(
            "sign", "--private-key", str(self.private_key), "--trusted-public-key", other,
            "--output-dir", str(self.directory / "signed"), str(draft),
        )
        self.assertEqual(status, 1)
        self.run_tool(
            "sign", "--private-key", str(self.private_key), "--trusted-public-key", self.public_key,
            "--output-dir", str(self.directory / "signed"), str(draft),
        )
        signed = self.directory / "signed" / "nixos-26.05-2026-10-23.json"
        status, _ = self.run_tool("feed", "--output", str(self.directory / "feed.json"), str(signed), str(signed))
        self.assertEqual(status, 1)


if __name__ == "__main__":
    unittest.main()
