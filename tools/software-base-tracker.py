#!/usr/bin/env python3
"""Watch a NixOS channel and draft the next workstation software base.

  software-base-tracker.py check --output-dir DIR [--channel nixos-26.05] \\
      [--feed tiaris-software-bases.json] [--vulnix PATH]

`check` reads the channel's current nixpkgs commit. When no known base
carries it, it evaluates a reference set of workstation packages at the
previous base and at the channel commit, takes their runtime closures from
cache.nixos.org metadata (nothing is downloaded), scans both closures with
vulnix in the same run and writes to DIR:

  status.json  {"state": "current"} or {"state": "new", ...}
  draft.json   the unsigned tiaris.software-base.v1 draft (state "new" only)
  summary.md   review notes for the Cybex reviewer (state "new" only)

The draft lists the advisories the channel commit fixes in that runtime
closure, so its kind and severity say whether it is a security update.
Approval stays a human step: review the commit as
docs/workstation-software-bases.md describes, then sign the draft with
software-base.py.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any
import urllib.error
import urllib.request


def _base_tool():
    path = Path(__file__).with_name("software-base.py")
    spec = importlib.util.spec_from_file_location("tiaris_software_base_tool", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base_tool = _base_tool()
ReleaseError = base_tool.ReleaseError
fail = base_tool.fail

CHANNELS = "https://channels.nixos.org"
CACHE = "https://cache.nixos.org"
CHANNEL = re.compile(r"^nixos-([0-9]{2}\.(05|11))$")
STORE_PATH = re.compile(r"^/nix/store/([0-9a-df-np-sv-z]{32})-[^/]+$")
# Manage seeds this built-in base for the commit Nest was released with
# (migrations/0264_software_bases.sql); the first new base supersedes it.
BUILTIN_BASE = ("74cc63f702f7d60a557e152a57b40fb1fd0f72ac", "nixos-26.05-2026-07-08")
# Workstation packages whose runtime closures stand for a Tiaris workstation:
# the kernel, the desktops, the common apps and the system services. Advisories
# found only in build tools are not on a workstation and are not counted.
REFERENCE = (
    "linuxPackages.kernel",
    "firefox",
    "chromium",
    "libreoffice",
    "thunderbird-unwrapped",
    "gnome-shell",
    "nautilus",
    "kdePackages.plasma-workspace",
    "hyprland",
    "systemd",
    "networkmanager",
    "pipewire",
    "cups",
    "openssh",
    "sudo",
    "polkit",
    "openssl",
    "curl",
    "glibc",
    "mesa",
    "libxml2",
)
MAX_TABLE_ROWS = 40
EVALUATION = r"""
{ commit, attrsJson }:
let
  source = builtins.fetchTarball "https://github.com/NixOS/nixpkgs/archive/${commit}.tar.gz";
  pkgs = import source { system = "x86_64-linux"; config = { }; overlays = [ ]; };
  inherit (pkgs) lib;
in
map (attr:
  let package = lib.attrByPath (lib.splitString "." attr) null pkgs;
  in {
    inherit attr;
    pname = package.pname or (lib.getName package);
    version = package.version or "";
    drv = package.drvPath;
    out = package.outPath;
  }) (builtins.fromJSON attrsJson)
"""


def run(command: list[str], label: str, *, accept: tuple[int, ...] = (0,)) -> str:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode not in accept:
        detail = result.stderr.strip().splitlines()[-1:] or [f"exit {result.returncode}"]
        fail(f"{label} failed: {detail[0]}")
    return result.stdout


def fetch(url: str, label: str) -> str | None:
    """Body of `url`, or None when it does not exist."""
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            return response.read(1024 * 1024).decode("utf-8")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        fail(f"{label} returned HTTP {error.code}")
    except (urllib.error.URLError, TimeoutError) as error:
        fail(f"could not reach {label}: {error}")


def channel_commit(channel: str) -> str:
    body = fetch(f"{CHANNELS}/{channel}/git-revision", f"the {channel} channel")
    commit = (body or "").strip()
    if not base_tool.COMMIT.match(commit):
        fail(f"the {channel} channel did not name a nixpkgs commit")
    return commit


def known_bases(feed: dict[str, Any] | None, channel: str) -> list[dict[str, Any]]:
    """Bases of `channel` that Manage already knows, oldest first."""
    bases = [{"base_id": BUILTIN_BASE[1], "nixpkgs_commit": BUILTIN_BASE[0], "captured_at": ""}]
    if feed is not None:
        if not isinstance(feed, dict) or feed.get("schema") != base_tool.FEED_SCHEMA:
            fail("the software base feed is invalid")
        for base in feed.get("bases") or []:
            if base.get("channel") == channel:
                bases.append(base)
    return sorted(bases, key=lambda base: (base["captured_at"], base["base_id"]))


def evaluate(commit: str, attrs: tuple[str, ...]) -> dict[str, dict[str, str]]:
    """Reference packages at `commit`, keyed by attribute path. Writes their
    derivations to the local store so vulnix can read them."""
    output = run(
        [
            "nix-instantiate", "--eval", "--strict", "--json", "--read-write-mode",
            "--expr", EVALUATION, "--argstr", "commit", commit, "--argstr", "attrsJson", json.dumps(list(attrs)),
        ],
        f"evaluating nixpkgs {commit[:12]}",
    )
    packages = {package["attr"]: package for package in json.loads(output)}
    for package in packages.values():
        if not STORE_PATH.match(package["out"]) or not package["drv"].endswith(".drv"):
            fail(f"{package['attr']} did not evaluate to a store path")
    return packages


def cached(out: str) -> bool:
    digest = STORE_PATH.match(out).group(1)
    return fetch(f"{CACHE}/{digest}.narinfo", "cache.nixos.org") is not None


def runtime_closure(outs: list[str]) -> set[str]:
    """Runtime closure of cached outputs, from cache.nixos.org narinfo files."""
    if not outs:
        return set()
    output = run(
        ["nix", "--extra-experimental-features", "nix-command", "path-info", "--recursive", "--json", "--store", CACHE, *outs],
        "reading runtime closures from cache.nixos.org",
    )
    info = json.loads(output)
    paths = info.keys() if isinstance(info, dict) else [entry["path"] for entry in info]
    return set(paths)


def derivation_outputs(drvs: list[str]) -> dict[str, set[str]]:
    if not drvs:
        return {}
    shown = json.loads(run(
        ["nix", "--extra-experimental-features", "nix-command", "derivation", "show", *drvs],
        "reading derivation outputs",
    ))
    outputs: dict[str, set[str]] = {}
    for key, derivation in shown.items():
        drv = key if key.startswith("/") else f"/nix/store/{key}"
        paths = set()
        for output in (derivation.get("outputs") or {}).values():
            path = output.get("path") or ""
            if path:
                paths.add(path if path.startswith("/") else f"/nix/store/{path}")
        outputs[drv] = paths
    return outputs


def scan(vulnix: list[str], drvs: list[str], closure: set[str]) -> list[dict[str, Any]]:
    """vulnix findings for the derivation graph of `drvs`, kept only for
    derivations whose outputs are in the runtime `closure`."""
    # vulnix exits 2 when it finds vulnerable derivations.
    findings = json.loads(run([*vulnix, "--json", *drvs], "vulnix", accept=(0, 1, 2)) or "[]")
    outputs = derivation_outputs(sorted({entry["derivation"] for entry in findings}))
    return [entry for entry in findings if outputs.get(entry["derivation"], set()) & closure]


def support_ends_at(nixos_release: str) -> str:
    year, month = nixos_release.split(".")
    if month == "05":
        return f"20{year}-12-31T23:59:59Z"
    return f"20{int(year) + 1:02d}-06-30T23:59:59Z"


def component(package: dict[str, str]) -> str:
    name = package["pname"].removesuffix("-unwrapped")
    return base_tool.COMPONENTS.get(name, name)


def by_component(advisories: list[dict[str, str]]) -> list[tuple[str, list[dict[str, str]]]]:
    """Advisories grouped by component, worst and most affected first."""
    groups: dict[str, list[dict[str, str]]] = {}
    for advisory in advisories:
        groups.setdefault(advisory["component"], []).append(advisory)
    return sorted(groups.items(), key=lambda item: (
        -max(base_tool.SEVERITY_RANK[advisory["severity"]] for advisory in item[1]), -len(item[1]), item[0]))


def highlights(previous: dict[str, dict[str, str]], current: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    changed = []
    for attr in REFERENCE:
        before, after = previous.get(attr), current.get(attr)
        if before and after and before["version"] and after["version"] and before["version"] != after["version"]:
            changed.append({"package": after["pname"], "component": component(after), "from": before["version"], "to": after["version"]})
    return changed[:50]


def listing(names: list[str]) -> str:
    if len(names) < 2:
        return "".join(names)
    return f"{', '.join(names[:-1])} and {names[-1]}"


def summary_line(advisories: list[dict[str, str]], changed: list[dict[str, str]]) -> str:
    if advisories:
        components = [name for name, _ in by_component(advisories)]
        return f"Fixes in {listing(components if len(components) <= 3 else components[:3] + ['other components'])}."
    if changed:
        return f"Newer versions of {listing([change['component'] for change in changed[:3]])}."
    return ""


def draft_document(
    *,
    channel: str,
    commit: str,
    captured: dt.datetime,
    taken_ids: set[str],
    previous_base_id: str,
    advisories: list[dict[str, str]],
    changed: list[dict[str, str]],
    kernel: str | None,
) -> dict[str, Any]:
    nixos_release = CHANNEL.match(channel).group(1)
    base_id = f"{channel}-{captured:%Y-%m-%d}"
    if base_id in taken_ids:
        base_id = f"{base_id}-{commit[:7]}"
    severity = max((advisory["severity"] for advisory in advisories), key=base_tool.SEVERITY_RANK.get, default="none")
    stamp = captured.strftime("%Y-%m-%dT%H:%M:%SZ")
    document: dict[str, Any] = {
        "schema": base_tool.SCHEMA,
        "base_id": base_id,
        "title": f"{'Security' if advisories else 'Software'} update · {captured.day} {captured:%B}",
        "nixos_release": nixos_release,
        "channel": channel,
        "nixpkgs_commit": commit,
        "captured_at": stamp,
        # The reviewer sets this when signing; a draft is not an approval.
        "approved_at": stamp,
        "support_ends_at": support_ends_at(nixos_release),
        "kind": "security" if advisories else "routine",
        "severity": severity,
        "summary": summary_line(advisories, changed),
        "supersedes": [previous_base_id],
        "default": False,
        "advisories": advisories,
        "highlights": changed,
    }
    if kernel:
        document["kernel_version"] = kernel
    base_tool.validate(document, signed=False)
    return document


def summary_markdown(
    document: dict[str, Any],
    previous: dict[str, Any],
    uncached: list[str],
    remaining: int,
) -> str:
    advisories = document["advisories"]
    counts = {severity: 0 for severity in ("critical", "important", "moderate", "low")}
    for advisory in advisories:
        counts[advisory["severity"]] = counts.get(advisory["severity"], 0) + 1
    severity = document["severity"]
    heading = f"{severity.capitalize()} security update" if document["kind"] == "security" else "Routine software update"
    lines = [
        f"**{heading}**: `{document['channel']}` moved to `{document['nixpkgs_commit']}`.",
        "",
        f"Compared with `{previous['base_id']}` (`{previous['nixpkgs_commit'][:12]}`), the workstation runtime closure "
        f"no longer has {len(advisories)} known vulnerabilities "
        f"({', '.join(f'{count} {name}' for name, count in counts.items() if count) or 'none'}); "
        f"{remaining} remain open on the new commit.",
        "",
    ]
    if advisories:
        groups = by_component(advisories)
        lines += ["| Component | Fixed | Worst | Examples |", "| --- | --- | --- | --- |"]
        for name, fixed in groups[:MAX_TABLE_ROWS]:
            examples = ", ".join(f"[{advisory['id']}]({advisory['url']})" for advisory in fixed[:3])
            lines.append(f"| {name} | {len(fixed)} | {fixed[0]['severity']} | {examples} |")
        if len(groups) > MAX_TABLE_ROWS:
            lines.append(f"| {len(groups) - MAX_TABLE_ROWS} more components | | | see the draft |")
        lines.append("")
    if document["highlights"]:
        lines.append("Version changes: " + ", ".join(
            f"{change['component']} {change['from']} → {change['to']}" for change in document["highlights"]) + ".")
        lines.append("")
    if uncached:
        lines.append("Not on cache.nixos.org at this commit, so left out of both scans: " + ", ".join(f"`{attr}`" for attr in uncached) + ".")
        lines.append("")
    lines += [
        "vulnix matches by package name and version, so review the advisories before approving.",
        "",
        "To offer this base: review the commit as `docs/workstation-software-bases.md` describes, set `approved_at`, "
        "sign the attached `draft.json` with `tools/software-base.py sign` and publish it with the next Nest release. "
        "Manage offers it only once every builder Nest reports the commit.",
        "",
    ]
    return "\n".join(lines)


def check(arguments: argparse.Namespace) -> dict[str, Any]:
    match = CHANNEL.match(arguments.channel)
    if not match:
        fail("channel must look like nixos-26.05")
    feed = base_tool.load_json(arguments.feed, "the software base feed") if arguments.feed else None
    bases = known_bases(feed, arguments.channel)
    commit = channel_commit(arguments.channel)
    if commit in {base["nixpkgs_commit"] for base in bases}:
        return {"state": "current", "channel": arguments.channel, "nixpkgs_commit": commit}
    previous = bases[-1]
    captured = dt.datetime.now(dt.timezone.utc)

    before = evaluate(previous["nixpkgs_commit"], REFERENCE)
    after = evaluate(commit, REFERENCE)
    # Compare like with like: a package missing from the cache on either
    # commit would otherwise look like a fix or a new vulnerability.
    uncached = [attr for attr in REFERENCE if not (cached(before[attr]["out"]) and cached(after[attr]["out"]))]
    scanned = [attr for attr in REFERENCE if attr not in uncached]
    vulnix = [arguments.vulnix] + (["--cache-dir", str(arguments.vulnix_cache_dir)] if arguments.vulnix_cache_dir else [])
    previous_scan = scan(vulnix, [before[attr]["drv"] for attr in scanned], runtime_closure([before[attr]["out"] for attr in scanned]))
    current_scan = scan(vulnix, [after[attr]["drv"] for attr in scanned], runtime_closure([after[attr]["out"] for attr in scanned]))

    advisories = base_tool.fixed_advisories(previous_scan, current_scan)
    kernel = after.get("linuxPackages.kernel", {}).get("version") or None
    document = draft_document(
        channel=arguments.channel,
        commit=commit,
        captured=captured,
        taken_ids={base["base_id"] for base in bases},
        previous_base_id=previous["base_id"],
        advisories=advisories,
        changed=highlights(before, after),
        kernel=kernel,
    )
    remaining = len(base_tool.vulnix_advisories(current_scan))
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    (arguments.output_dir / "draft.json").write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    (arguments.output_dir / "summary.md").write_text(summary_markdown(document, previous, uncached, remaining))
    return {
        "state": "new",
        "channel": arguments.channel,
        "nixpkgs_commit": commit,
        "previous_base_id": previous["base_id"],
        "base_id": document["base_id"],
        "title": document["title"],
        "kind": document["kind"],
        "severity": document["severity"],
        "fixed_advisories": len(advisories),
        "uncached": uncached,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    checking = commands.add_parser("check")
    checking.add_argument("--channel", default="nixos-26.05")
    checking.add_argument("--feed", type=Path, help="The published tiaris-software-bases.json")
    checking.add_argument("--vulnix", default="vulnix")
    checking.add_argument("--vulnix-cache-dir", type=Path)
    checking.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        status = check(arguments)
        arguments.output_dir.mkdir(parents=True, exist_ok=True)
        (arguments.output_dir / "status.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
        json.dump(status, sys.stdout, indent=2, sort_keys=True)
        print()
    except ReleaseError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
