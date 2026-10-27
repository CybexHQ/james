#!/usr/bin/env python3
"""Draft, sign and publish Tiaris workstation software bases.

A software base is one reviewed nixpkgs commit that Nest can build
workstation closures on. Tiaris Manage offers it as a software update once a
signed `tiaris.software-base.v1` document names it and every builder Nest of
an organization reports its commit.

  software-base.py draft --commit C --base-id ID --title T --support-ends-at TS \\
      [--previous-vulnix PREV.json --vulnix NEW.json] [--previous-kernel V] \\
      [--kernel-version V | --evaluate-kernel] [--supersedes ID]... > UNSIGNED.json
  software-base.py sign --private-key KEY --trusted-public-key B64 UNSIGNED.json... --output-dir DIR
  software-base.py feed SIGNED.json... --output tiaris-software-bases.json
  software-base.py verify --trusted-public-key B64 tiaris-software-bases.json

`draft` derives the security fixes a base brings from two `vulnix --json`
scans of the same reference closure: advisories present on the previous base
and absent on the new one. Review the draft, then sign it with the release
key and publish the feed as the `tiaris-software-bases.json` release asset.
The signed bytes are `TIARIS-SOFTWARE-BASE-V1\\n` followed by the canonical
JSON of the document without `signature`.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

SCHEMA = "tiaris.software-base.v1"
FEED_SCHEMA = "tiaris.software-base-feed.v1"
SIGNATURE_DOMAIN = "TIARIS-SOFTWARE-BASE-V1"
FEED_ASSET = "tiaris-software-bases.json"
MAX_FEED_BYTES = 1024 * 1024
MAX_ADVISORIES = 500
BASE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{2,63}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
CVE = re.compile(r"^(CVE|GHSA)-[0-9A-Za-z-]{4,40}$")
SEVERITY_RANK = {"none": 0, "low": 1, "moderate": 2, "important": 3, "critical": 4}
# Friendly names for packages people recognise; others use the package name.
COMPONENTS = {
    "linux": "Linux kernel",
    "firefox": "Firefox",
    "firefox-esr": "Firefox ESR",
    "chromium": "Chromium",
    "thunderbird": "Thunderbird",
    "libreoffice": "LibreOffice",
    "openssl": "OpenSSL",
    "openssh": "OpenSSH",
    "glibc": "C library",
    "systemd": "systemd",
    "mesa": "Graphics drivers",
    "curl": "curl",
    "libxml2": "libxml2",
    "sudo": "sudo",
}


def _release_tool():
    path = Path(__file__).with_name("nest-release.py")
    spec = importlib.util.spec_from_file_location("tiaris_nest_release_tool", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = _release_tool()
ReleaseError = release.ReleaseError


def fail(message: str):
    raise ReleaseError(message)


def utc(value: str, label: str) -> str:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} must be an RFC 3339 timestamp")
    if parsed.tzinfo is None:
        fail(f"{label} must include a time zone")
    return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def severity_for_score(score: float | None) -> str:
    if score is None:
        return "moderate"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "important"
    if score >= 4.0:
        return "moderate"
    return "low"


def vulnix_advisories(scan: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    """Advisory id -> advisory, from `vulnix --json` output."""
    found: dict[str, dict[str, str]] = {}
    for entry in scan:
        package = str(entry.get("pname") or entry.get("name") or "").strip()
        if not package:
            continue
        scores = entry.get("cvssv3_basescore") or {}
        for advisory in entry.get("affected_by") or []:
            advisory = str(advisory)
            if not CVE.match(advisory) or advisory in found:
                continue
            score = scores.get(advisory)
            found[advisory] = {
                "id": advisory,
                "package": package,
                "component": COMPONENTS.get(package, package),
                "severity": severity_for_score(float(score) if score is not None else None),
                "summary": f"Fixed in {COMPONENTS.get(package, package)}.",
                "url": f"https://nvd.nist.gov/vuln/detail/{advisory}",
            }
    return found


def fixed_advisories(previous: list[dict[str, Any]], current: list[dict[str, Any]]) -> list[dict[str, str]]:
    before = vulnix_advisories(previous)
    after = vulnix_advisories(current)
    fixed = [advisory for key, advisory in before.items() if key not in after]
    fixed.sort(key=lambda advisory: (-SEVERITY_RANK[advisory["severity"]], advisory["component"], advisory["id"]))
    return fixed[:MAX_ADVISORIES]


def evaluate_kernel(commit: str) -> str:
    result = subprocess.run(
        ["nix", "eval", "--raw", f"github:NixOS/nixpkgs/{commit}#linuxPackages.kernel.version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if result.returncode != 0 or not re.match(r"^[0-9][0-9A-Za-z.+_-]{0,63}$", result.stdout.strip()):
        fail("nix could not evaluate the kernel version of this commit")
    return result.stdout.strip()


def load_json(path: Path, label: str) -> Any:
    try:
        body = path.read_bytes()
    except OSError:
        fail(f"could not read {label}")
    if len(body) > MAX_FEED_BYTES * 16:
        fail(f"{label} is too large")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        fail(f"{label} is not JSON")


def draft(arguments: argparse.Namespace) -> dict[str, Any]:
    if not COMMIT.match(arguments.commit):
        fail("commit must be a lowercase 40-hex nixpkgs commit")
    if not BASE_ID.match(arguments.base_id):
        fail("base_id must match ^[a-z0-9][a-z0-9.-]{2,63}$")
    release_name = arguments.nixos_release
    if not re.match(r"^[0-9]{2}\.(05|11)$", release_name):
        fail("nixos-release must look like 26.05")
    kernel = arguments.kernel_version or (evaluate_kernel(arguments.commit) if arguments.evaluate_kernel else None)
    advisories: list[dict[str, str]] = []
    if arguments.vulnix or arguments.previous_vulnix:
        if not (arguments.vulnix and arguments.previous_vulnix):
            fail("use --previous-vulnix and --vulnix together")
        advisories = fixed_advisories(
            load_json(arguments.previous_vulnix, "the previous vulnix scan"),
            load_json(arguments.vulnix, "the vulnix scan"),
        )
    severity = max((advisory["severity"] for advisory in advisories), key=SEVERITY_RANK.get, default="none")
    highlights = []
    if kernel and arguments.previous_kernel and kernel != arguments.previous_kernel:
        highlights.append({"package": "linux", "component": "Linux kernel", "from": arguments.previous_kernel, "to": kernel})
    captured = utc(arguments.captured_at, "captured-at")
    approved = utc(arguments.approved_at or dt.datetime.now(dt.timezone.utc).isoformat(), "approved-at")
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "base_id": arguments.base_id,
        "title": arguments.title,
        "nixos_release": release_name,
        "channel": f"nixos-{release_name}",
        "nixpkgs_commit": arguments.commit,
        "captured_at": captured,
        "approved_at": approved,
        "support_ends_at": utc(arguments.support_ends_at, "support-ends-at"),
        "kind": "security" if advisories else "routine",
        "severity": severity,
        "summary": arguments.summary or "",
        "supersedes": sorted(set(arguments.supersedes or [])),
        "default": bool(arguments.default),
        "advisories": advisories,
        "highlights": highlights,
    }
    if kernel:
        document["kernel_version"] = kernel
    if arguments.minimum_nest_version:
        release._validate_version(arguments.minimum_nest_version)
        document["minimum_nest_version"] = arguments.minimum_nest_version
    validate(document, signed=False)
    return document


def validate(document: dict[str, Any], *, signed: bool) -> None:
    required = {
        "schema", "base_id", "title", "nixos_release", "channel", "nixpkgs_commit",
        "captured_at", "approved_at", "support_ends_at", "kind", "severity",
    }
    allowed = required | {
        "summary", "kernel_version", "supersedes", "default", "minimum_nest_version",
        "advisories", "highlights", "signature",
    }
    keys = set(document)
    if not required <= keys or not keys <= allowed:
        fail("the software base document has missing or unknown fields")
    if signed != ("signature" in document):
        fail("the software base document must be signed" if signed else "the draft is already signed")
    if document["schema"] != SCHEMA or not BASE_ID.match(str(document["base_id"])):
        fail("the software base schema or base_id is invalid")
    if not COMMIT.match(str(document["nixpkgs_commit"])):
        fail("the nixpkgs commit is invalid")
    if document["channel"] != f"nixos-{document['nixos_release']}":
        fail("the channel must be nixos-<nixos_release>")
    if document["kind"] not in ("security", "routine") or document["severity"] not in SEVERITY_RANK:
        fail("kind or severity is invalid")
    if document["support_ends_at"] <= document["captured_at"]:
        fail("support must end after the commit was captured")
    title = str(document["title"])
    if not title.strip() or len(title) > 128 or any(ord(char) < 32 for char in title):
        fail("title must be 1 to 128 characters of plain text")
    advisories = document.get("advisories", [])
    if len(advisories) > MAX_ADVISORIES:
        fail("too many advisories")
    worst = max((SEVERITY_RANK.get(advisory.get("severity"), 99) for advisory in advisories), default=0)
    if worst > SEVERITY_RANK[document["severity"]]:
        fail("severity must cover the highest advisory severity")


def payload(document: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    body = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return f"{SIGNATURE_DOMAIN}\n".encode("ascii") + body.encode("utf-8")


def sign(arguments: argparse.Namespace) -> None:
    trusted = release._trusted_public_key(arguments.trusted_public_key)
    private_fd = release._open_regular(Path(arguments.private_key), "private key", private=True)
    try:
        identity = release._private_key_identity(private_fd)
        public_der = release._public_der(private_fd)
        if public_der[len(release.ED25519_PUBLIC_DER_PREFIX):] != trusted:
            fail("the private key is not the trusted release key")
        arguments.output_dir.mkdir(parents=True, exist_ok=True)
        for path in arguments.documents:
            document = load_json(path, "the draft")
            validate(document, signed=False)
            message = payload(document)
            signature = release._sign(private_fd, message)
            release._self_verify(public_der, signature, message)
            release._require_stable_private_key(private_fd, identity)
            signed = {**document, "signature": base64.b64encode(signature).decode("ascii")}
            output = arguments.output_dir / f"{document['base_id']}.json"
            release._atomic_write(output, (json.dumps(signed, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            print(output)
    finally:
        os.close(private_fd)


def verify_signed(document: dict[str, Any], trusted: bytes) -> None:
    validate(document, signed=True)
    signature = release._canonical_base64(document["signature"], "signature", expected_bytes=64)
    release._self_verify(release.ED25519_PUBLIC_DER_PREFIX + trusted, signature, payload(document))


def feed(arguments: argparse.Namespace) -> None:
    bases = [load_json(path, "a signed base") for path in arguments.documents]
    seen: set[str] = set()
    for base in bases:
        validate(base, signed=True)
        for key in (base["base_id"], base["nixpkgs_commit"]):
            if key in seen:
                fail(f"{key} appears twice in the feed")
            seen.add(key)
    bases.sort(key=lambda base: (base["captured_at"], base["base_id"]))
    body = (json.dumps({"schema": FEED_SCHEMA, "bases": bases}, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(body) > MAX_FEED_BYTES:
        fail("the software base feed is larger than 1 MiB")
    release._atomic_write(arguments.output, body)


def verify(arguments: argparse.Namespace) -> None:
    trusted = release._trusted_public_key(arguments.trusted_public_key)
    document = load_json(arguments.feed, "the software base feed")
    if not isinstance(document, dict) or document.get("schema") != FEED_SCHEMA or set(document) != {"schema", "bases"}:
        fail("the software base feed is invalid")
    for base in document["bases"]:
        verify_signed(base, trusted)
    print(f"verified {len(document['bases'])} software base(s)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    drafting = commands.add_parser("draft")
    drafting.add_argument("--commit", required=True)
    drafting.add_argument("--base-id", required=True)
    drafting.add_argument("--title", required=True)
    drafting.add_argument("--nixos-release", default="26.05")
    drafting.add_argument("--captured-at", required=True)
    drafting.add_argument("--approved-at")
    drafting.add_argument("--support-ends-at", required=True)
    drafting.add_argument("--summary")
    drafting.add_argument("--kernel-version")
    drafting.add_argument("--evaluate-kernel", action="store_true")
    drafting.add_argument("--previous-kernel")
    drafting.add_argument("--previous-vulnix", type=Path)
    drafting.add_argument("--vulnix", type=Path)
    drafting.add_argument("--supersedes", action="append")
    drafting.add_argument("--minimum-nest-version")
    drafting.add_argument("--default", action="store_true", help="Make it the default base for new Blueprints")
    signing = commands.add_parser("sign")
    signing.add_argument("--private-key", required=True)
    signing.add_argument("--trusted-public-key", required=True)
    signing.add_argument("--output-dir", required=True, type=Path)
    signing.add_argument("documents", nargs="+", type=Path)
    publishing = commands.add_parser("feed")
    publishing.add_argument("--output", required=True, type=Path)
    publishing.add_argument("documents", nargs="+", type=Path)
    verifying = commands.add_parser("verify")
    verifying.add_argument("--trusted-public-key", required=True)
    verifying.add_argument("feed", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "draft":
            json.dump(draft(arguments), sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
            print()
        elif arguments.command == "sign":
            sign(arguments)
        elif arguments.command == "feed":
            feed(arguments)
        else:
            verify(arguments)
    except ReleaseError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
