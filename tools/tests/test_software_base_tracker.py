from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[2]
TOOL = REPOSITORY / "tools" / "software-base-tracker.py"
PIN = "74cc63f702f7d60a557e152a57b40fb1fd0f72ac"
NEW = "6f06d204d8f2d8761d9da78778745974a3216381"
PUBLISHED = "0123456789abcdef0123456789abcdef01234567"


def load_tool():
    spec = importlib.util.spec_from_file_location("software_base_tracker_under_test", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package(attr: str, version: str, commit: str) -> dict[str, str]:
    pname = "linux" if attr == "linuxPackages.kernel" else attr.rsplit(".", 1)[-1]
    digest = commit[:8] * 4
    return {
        "attr": attr,
        "pname": pname,
        "version": version,
        "drv": f"/nix/store/{digest}-{pname}-{version}.drv",
        "out": f"/nix/store/{digest}-{pname}-{version}",
    }


def finding(pname: str, advisories: dict[str, float], derivation: str) -> dict[str, object]:
    return {
        "name": f"{pname}-1",
        "pname": pname,
        "derivation": derivation,
        "affected_by": list(advisories),
        "cvssv3_basescore": advisories,
    }


class SoftwareBaseTrackerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.tool = load_tool()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self, feed: Path | None = None) -> argparse.Namespace:
        return argparse.Namespace(
            channel="nixos-26.05",
            feed=feed,
            vulnix="vulnix",
            vulnix_cache_dir=None,
            output_dir=self.directory / "out",
        )

    def feed(self, *bases: dict[str, str]) -> Path:
        path = self.directory / "tiaris-software-bases.json"
        path.write_text(json.dumps({"schema": "tiaris.software-base-feed.v1", "bases": list(bases)}))
        return path

    def evaluations(self) -> dict[str, dict[str, dict[str, str]]]:
        versions = {
            PIN: {"linuxPackages.kernel": "6.18.38", "firefox": "152.0.5", "thunderbird-unwrapped": "152.0.1"},
            NEW: {"linuxPackages.kernel": "6.18.59", "firefox": "159.0", "thunderbird-unwrapped": "158.0"},
        }
        evaluations = {}
        for commit, changed in versions.items():
            evaluations[commit] = {
                attr: package(attr, changed.get(attr, "1.0"), commit) for attr in self.tool.REFERENCE
            }
        return evaluations

    def run_check(self, *, feed: Path | None = None, uncached: tuple[str, ...] = ()) -> tuple[dict, list[list[str]]]:
        evaluations = self.evaluations()
        scanned: list[list[str]] = []

        def scan(_vulnix, drvs, _closure):
            scanned.append(drvs)
            if any(PIN[:8] in drv for drv in drvs):
                return [
                    finding("firefox", {"CVE-2026-16349": 9.8, "CVE-2026-16350": 8.1}, drvs[0]),
                    finding("unbound", {"CVE-2026-33001": 7.5}, drvs[0]),
                    finding("openssh", {"CVE-2026-20001": 5.0, "CVE-2026-20002": 4.2}, drvs[0]),
                ]
            return [finding("openssh", {"CVE-2026-20002": 4.2}, drvs[0])]

        uncached_outs = {evaluations[NEW][attr]["out"] for attr in uncached}
        with mock.patch.object(self.tool, "channel_commit", return_value=NEW), \
                mock.patch.object(self.tool, "evaluate", side_effect=lambda commit, _attrs: evaluations[commit]), \
                mock.patch.object(self.tool, "cached", side_effect=lambda out: out not in uncached_outs), \
                mock.patch.object(self.tool, "runtime_closure", return_value=set()), \
                mock.patch.object(self.tool, "scan", side_effect=scan):
            status = self.tool.check(self.arguments(feed))
        return status, scanned

    def test_current_when_the_channel_commit_is_already_a_base(self) -> None:
        with mock.patch.object(self.tool, "channel_commit", return_value=PIN), \
                mock.patch.object(self.tool, "evaluate") as evaluate:
            status = self.tool.check(self.arguments())
        self.assertEqual(status, {"state": "current", "channel": "nixos-26.05", "nixpkgs_commit": PIN})
        evaluate.assert_not_called()

    def test_new_commit_drafts_a_security_base_against_the_builtin_base(self) -> None:
        status, _ = self.run_check()
        draft = json.loads((self.directory / "out" / "draft.json").read_text())
        self.assertEqual(status["state"], "new")
        self.assertEqual(status["previous_base_id"], "nixos-26.05-2026-07-08")
        self.assertEqual(draft["supersedes"], ["nixos-26.05-2026-07-08"])
        self.assertEqual(draft["nixpkgs_commit"], NEW)
        self.assertEqual((draft["kind"], draft["severity"]), ("security", "critical"))
        self.assertEqual(
            [advisory["id"] for advisory in draft["advisories"]],
            ["CVE-2026-16349", "CVE-2026-16350", "CVE-2026-33001", "CVE-2026-20001"],
        )
        self.assertEqual(draft["kernel_version"], "6.18.59")
        self.assertEqual(draft["support_ends_at"], "2026-12-31T23:59:59Z")
        self.assertTrue(draft["title"].startswith("Security update · "))
        self.assertEqual(draft["summary"], "Fixes in Firefox, unbound and OpenSSH.")
        self.assertIn(
            {"package": "thunderbird-unwrapped", "component": "Thunderbird", "from": "152.0.1", "to": "158.0"},
            draft["highlights"],
        )
        self.tool.base_tool.validate(draft, signed=False)
        summary = (self.directory / "out" / "summary.md").read_text()
        self.assertIn("**Critical security update**", summary)
        self.assertIn("| Firefox | 2 | critical |", summary)
        self.assertIn("1 remain open", summary)

    def test_new_commit_supersedes_the_latest_published_base(self) -> None:
        today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
        feed = self.feed(
            {"base_id": "nixos-26.05-2026-09-01", "nixpkgs_commit": PUBLISHED, "channel": "nixos-26.05", "captured_at": "2026-09-01T06:00:00Z"},
            {"base_id": f"nixos-26.05-{today}", "nixpkgs_commit": PIN, "channel": "nixos-26.05", "captured_at": "2026-07-08T00:00:00Z"},
            {"base_id": "nixos-25.11-2026-09-02", "nixpkgs_commit": "f" * 40, "channel": "nixos-25.11", "captured_at": "2026-09-02T06:00:00Z"},
        )
        evaluations = self.evaluations()
        evaluations[PUBLISHED] = evaluations.pop(PIN)
        with mock.patch.object(self.tool, "channel_commit", return_value=NEW), \
                mock.patch.object(self.tool, "evaluate", side_effect=lambda commit, _attrs: evaluations[commit]) as evaluate, \
                mock.patch.object(self.tool, "cached", return_value=True), \
                mock.patch.object(self.tool, "runtime_closure", return_value=set()), \
                mock.patch.object(self.tool, "scan", return_value=[]):
            status = self.tool.check(self.arguments(feed))
        self.assertEqual(evaluate.call_args_list[0].args[0], PUBLISHED)
        self.assertEqual(status["previous_base_id"], "nixos-26.05-2026-09-01")
        self.assertEqual((status["kind"], status["severity"]), ("routine", "none"))
        # A base already uses today's id, so the new one carries its commit.
        self.assertEqual(status["base_id"], f"nixos-26.05-{today}-{NEW[:7]}")
        draft = json.loads((self.directory / "out" / "draft.json").read_text())
        self.assertTrue(draft["summary"].startswith("Newer versions of Linux kernel, Firefox"))

    def test_packages_missing_from_the_cache_are_left_out_of_both_scans(self) -> None:
        status, scanned = self.run_check(uncached=("chromium",))
        self.assertEqual(status["uncached"], ["chromium"])
        self.assertEqual(len(scanned), 2)
        for drvs in scanned:
            self.assertFalse(any("-chromium-" in drv for drv in drvs))
            self.assertEqual(len(drvs), len(self.tool.REFERENCE) - 1)
        self.assertIn("`chromium`", (self.directory / "out" / "summary.md").read_text())

    def test_scan_keeps_only_findings_in_the_runtime_closure(self) -> None:
        runtime = "/nix/store/" + "a" * 32 + "-openssh-10.3p1"
        build_only = "/nix/store/" + "b" * 32 + "-gcc-15.1.0"
        findings = [
            finding("openssh", {"CVE-2026-20001": 5.0}, "/nix/store/" + "c" * 32 + "-openssh-10.3p1.drv"),
            finding("gcc", {"CVE-2026-20003": 7.0}, "/nix/store/" + "d" * 32 + "-gcc-15.1.0.drv"),
        ]
        outputs = {findings[0]["derivation"]: {runtime}, findings[1]["derivation"]: {build_only}}
        with mock.patch.object(self.tool, "run", return_value=json.dumps(findings)) as run, \
                mock.patch.object(self.tool, "derivation_outputs", return_value=outputs):
            kept = self.tool.scan(["vulnix"], ["/nix/store/x.drv"], {runtime})
        self.assertEqual([entry["pname"] for entry in kept], ["openssh"])
        self.assertEqual(run.call_args.kwargs["accept"], (0, 1, 2))

    def test_derivation_outputs_accepts_full_paths_and_store_names(self) -> None:
        old_style = {"/nix/store/aaa-x.drv": {"outputs": {"out": {"path": "/nix/store/aaa-x"}}}}
        new_style = {"bbb-y.drv": {"outputs": {"out": {"path": "bbb-y"}, "doc": {"path": "bbb-y-doc"}}}}
        for shown, expected in (
            (old_style, {"/nix/store/aaa-x.drv": {"/nix/store/aaa-x"}}),
            (new_style, {"/nix/store/bbb-y.drv": {"/nix/store/bbb-y", "/nix/store/bbb-y-doc"}}),
        ):
            with mock.patch.object(self.tool, "run", return_value=json.dumps(shown)):
                self.assertEqual(self.tool.derivation_outputs(["unused"]), expected)

    def test_support_ends_with_the_nixos_release(self) -> None:
        self.assertEqual(self.tool.support_ends_at("26.05"), "2026-12-31T23:59:59Z")
        self.assertEqual(self.tool.support_ends_at("26.11"), "2027-06-30T23:59:59Z")

    def test_main_writes_status_and_reports_errors(self) -> None:
        output = self.directory / "out"
        with mock.patch.object(self.tool, "channel_commit", return_value=PIN), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.tool.main(["check", "--output-dir", str(output)]), 0)
        self.assertEqual(json.loads((output / "status.json").read_text())["state"], "current")
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(self.tool.main(["check", "--channel", "unstable", "--output-dir", str(output)]), 1)
        self.assertIn("channel must look like nixos-26.05", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
