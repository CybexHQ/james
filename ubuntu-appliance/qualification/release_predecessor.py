#!/usr/bin/env python3
"""Resolve a signed predecessor, including an exact, one-release recovery adoption.

The recovery authorization authenticates both the historical GitHub authority and
the independently recovered fleet release. It never edits either release, grants
general trust to the historical key, or substitutes a first-release declaration.
Every publication resolves again under the workflow's repository-wide lock.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "cybex-james-release.json"
COMPATIBILITY = "cybex-james-release-compatibility.json"
DOMAIN = b"CYBEX-JAMES-RECOVERY-ADOPTION-V1\n"
SCHEMA = "cybex.james.recovery-adoption.v1"
IDENTITY_SCHEMA = "cybex.james.recovery-appliance-predecessor.v1"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


release = module("james_release", ROOT / "tools/james-release.py")
gate = module("legacy_bridge_gate", Path(__file__).with_name("legacy-bridge-gate.py"))


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checked_json(path, limit=1024 * 1024):
    value, body = release._load_bounded_json(path, "predecessor input", maximum_bytes=limit)
    return value, body


def authorization(path, trusted_key, candidate_version, repository):
    value, body = checked_json(path)
    fields = {"schema", "repository", "successor_version", "published", "recovery", "reason", "public_key", "signature"}
    if set(value) != fields or value["schema"] != SCHEMA or body != canonical(value):
        raise ValueError("Invalid canonical recovery authorization")
    if value["public_key"] != trusted_key or value["repository"] != repository:
        raise ValueError("Recovery authorization is not for this production authority/repository")
    signature = release._canonical_base64(value["signature"], "recovery signature", expected_bytes=64)
    payload = {k: v for k, v in value.items() if k != "signature"}
    release._self_verify(release.ED25519_PUBLIC_DER_PREFIX + release._trusted_public_key(trusted_key), signature, DOMAIN + canonical(payload))
    if value["successor_version"] != candidate_version:
        raise ValueError("Recovery adoption is authorized for exactly one successor version")
    published = value["published"]
    if set(published) != {"github_release_id", "tag_name", "target_commitish", "public_key", "manifest_sha256", "compatibility_sha256"}:
        raise ValueError("Invalid historical GitHub identity")
    recovery = value["recovery"]
    if set(recovery) != {"release_id", "manifest_url", "manifest_sha256", "compatibility_url", "compatibility_sha256"}:
        raise ValueError("Invalid recovered fleet identity")
    for item in [published, recovery]:
        for key in ["manifest_sha256", "compatibility_sha256"]:
            release._require_sha256(item[key], key)
    release._validate_version(recovery["release_id"])
    release._validate_version(candidate_version)
    if release._compare_semver(candidate_version, recovery["release_id"]) <= 0:
        raise ValueError("Recovery successor must advance the installed release")
    for field, name in [("manifest_url", MANIFEST), ("compatibility_url", COMPATIBILITY)]:
        expected = f"https://manage.cybex.net/james-dev-artifacts/{recovery['release_id']}/{name}"
        if recovery[field] != expected:
            raise ValueError("Recovery URL is outside the exact production retention namespace")
    return value


def latest(releases, candidate_tag):
    candidates = []
    for value in releases:
        # An immutable prerelease is staged for cold acceptance, not a usable
        # predecessor. Historical prereleases without this marker keep their
        # original resolution behavior and exact recovery authorization.
        if value.get('prerelease') and 'Cybex-Cold-Qualification: required' in (value.get('body') or ''):
            continue
        names = [a["name"] for a in value["assets"]]
        if not value["draft"] and value["tag_name"] != candidate_tag and MANIFEST in names and COMPATIBILITY in names:
            if any(names.count(name) != 1 for name in (MANIFEST, COMPATIBILITY)):
                raise ValueError("Published release has ambiguous signed assets")
            candidates.append(value)
    return max(candidates, key=lambda v: (v.get("published_at") or v["created_at"], v["id"]), default=None)


def github(repository, path):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid GitHub repository")
    result = subprocess.run(["gh", "api", "--paginate", f"repos/{repository}/{path}"], capture_output=True, check=True)
    # gh < 2.48 has pagination but no --slurp. Decode its concatenated JSON
    # pages so qualification uses the same resolver on supported Debian hosts.
    remaining = result.stdout.decode().strip()
    pages = []
    while remaining:
        value, end = json.JSONDecoder().raw_decode(remaining)
        pages.append(value)
        remaining = remaining[end:].lstrip()
    if not pages:
        raise ValueError("GitHub returned no response")
    return [v for page in pages for v in page] if isinstance(pages[0], list) else pages[0]


def fetch(url, target, expected_sha=None, expected_size=None, maximum=4 * 1024**3):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc not in {"github.com", "manage.cybex.net", "dev.cybex.net"}
            or parsed.query or parsed.fragment or target.is_symlink()):
        raise ValueError("Unexpected predecessor transport")
    if not target.exists():
        part = target.with_name(target.name + ".download")
        try:
            subprocess.run(["curl", "-4", "--fail", "--silent", "--show-error", "--location", "--proto", "=https",
                            "--proto-redir", "=https", "--connect-timeout", "30", "--max-time", "1800",
                            "--max-filesize", str(maximum), "--output", str(part), url], check=True)
            if not 0 < part.stat().st_size <= maximum:
                raise ValueError("Predecessor object exceeds its bound")
            if expected_size is not None and part.stat().st_size != expected_size:
                raise ValueError("Predecessor object size changed")
            if expected_sha is not None and sha(part) != expected_sha:
                raise ValueError("Predecessor object digest changed")
            part.replace(target)
        finally:
            part.unlink(missing_ok=True)
    if not target.is_file() or not 0 < target.stat().st_size <= maximum:
        raise ValueError("Invalid predecessor file")
    if expected_size is not None and target.stat().st_size != expected_size:
        raise ValueError("Cached predecessor size changed")
    if expected_sha is not None and sha(target) != expected_sha:
        raise ValueError("Cached predecessor digest changed")
    return target


def verify_pair(directory, trusted_key, manifest_url):
    asset, _ = checked_json(directory / COMPATIBILITY)
    with tempfile.TemporaryDirectory(prefix="james-predecessor-contract-") as temporary:
        contract = Path(temporary) / "compatibility.json"
        contract.write_bytes(canonical(asset["compatibility"]))
        release._verify_release_compatibility_command(argparse.Namespace(
            asset=directory / COMPATIBILITY, manifest=directory / MANIFEST,
            manifest_url=manifest_url, compatibility=contract, trusted_public_key=trusted_key))
    return json.loads((directory / MANIFEST).read_bytes())


def inspect_package(directory, manifest, retain_to=None):
    descriptor = manifest["appliance_release_v1"]
    package = descriptor["cybex_repository_snapshot"]
    name = urlsplit(package["url"]).path.rsplit("/", 1)[-1]
    if name != f"cybex-james-appliance-packages-{manifest['version']}-x86_64-linux.tar.zst":
        raise ValueError("Predecessor package filename is not release-bound")
    path = fetch(package["url"], directory / name, package["sha256"], package["size_bytes"])
    with tempfile.TemporaryDirectory(prefix="james-predecessor-package-") as temporary:
        tree = Path(temporary)
        gate.extract_repository_snapshot(path, tree)
        gate.validate_repository_checksums(tree)
        if (tree / "UBUNTU-SNAPSHOT-ID").read_bytes() != (descriptor["ubuntu_snapshot_id"] + "\n").encode():
            raise ValueError("Predecessor snapshot marker changed")
        contract, updater, packaged_release = gate.packaged_updater_identity(
            tree, expected_release=manifest["version"], expected_snapshot=descriptor["ubuntu_snapshot_id"])
        if retain_to is not None:
            workstation = manifest["workstation_netboot"]
            retained = tree / "retained-manage-source"
            source = release._inspect_packaged_manage_source(
                path, manifest["version"], workstation["manage_source_revision"], retain_to=retained)
            if "manage_source_sha256" in workstation and (
                    source["sha256"] != workstation["manage_source_sha256"]
                    or source["size_bytes"] != workstation["manage_source_size_bytes"]):
                raise ValueError("Retained Manage source differs from the signed workstation descriptor")
            # copytree refuses an existing destination, including a symlink.
            shutil.copytree(retained, retain_to)
    return {"release_id": manifest["version"], "ubuntu_snapshot_id": descriptor["ubuntu_snapshot_id"],
            "release_manifest_sha256": sha(directory / MANIFEST), "release_compatibility_sha256": sha(directory / COMPATIBILITY),
            "package_snapshot_sha256": package["sha256"], "package_snapshot_size_bytes": package["size_bytes"],
            "update_contract": contract, "appliance_updater_sha256": updater, "packaged_release_sha256": packaged_release}


def resolve(repository, candidate, trusted_key, directory, recovery_path, retain_to=None):
    directory.mkdir(parents=True, exist_ok=True)
    previous = latest(github(repository, "releases?per_page=100"), "v" + candidate)
    if previous is None:
        if recovery_path.exists():
            raise ValueError("Expected historical publication is absent; refusing to call this a first release")
        return None
    tag = previous["tag_name"]
    gate.text_field(tag, "published tag", gate.TAG_RE)
    commit = github(repository, "commits/" + tag)["sha"]
    if previous["target_commitish"] != commit:
        raise ValueError("Published tag moved or is not bound to its source commit")
    publication = directory / "publication"
    publication.mkdir(exist_ok=True)
    base = f"https://github.com/{repository}/releases/download/{tag}/"
    for name in (MANIFEST, COMPATIBILITY):
        assets = [a for a in previous["assets"] if a["name"] == name]
        if len(assets) != 1 or assets[0]["browser_download_url"] != base + name:
            raise ValueError("Published asset URL does not bind this repository/tag")
        digest = assets[0].get("digest")
        if digest and not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("Invalid GitHub asset digest")
        fetch(base + name, publication / name, digest[7:] if digest else None, assets[0]["size"], maximum=1024**2)
    # Only a current-authority-signed authorization can admit this exact older
    # publication. A different or later publication takes the ordinary path.
    adoption = None
    if recovery_path.exists():
        raw, _ = checked_json(recovery_path)
        if previous["id"] == raw.get("published", {}).get("github_release_id"):
            adoption = authorization(recovery_path, trusted_key, candidate, repository)
    if adoption:
        old = adoption["published"]
        if any(previous[k] != old[m] for k, m in [("id", "github_release_id"), ("tag_name", "tag_name"), ("target_commitish", "target_commitish")]):
            raise ValueError("Historical GitHub publication changed")
        if sha(publication / MANIFEST) != old["manifest_sha256"] or sha(publication / COMPATIBILITY) != old["compatibility_sha256"]:
            raise ValueError("Historical signed publication bytes changed")
        gate.verify_published_predecessor_descriptors(compatibility_path=publication / COMPATIBILITY,
            manifest_path=publication / MANIFEST, trusted_public_key=old["public_key"],
            release_verifier=ROOT / "tools/james-release.py", github_release_id=previous["id"], tag_name=tag)
        recovered = adoption["recovery"]
        for name, prefix in [(MANIFEST, "manifest"), (COMPATIBILITY, "compatibility")]:
            fetch(recovered[prefix + "_url"], directory / name, recovered[prefix + "_sha256"], maximum=1024**2)
        manifest = verify_pair(directory, trusted_key, recovered["manifest_url"])
        if manifest["version"] != recovered["release_id"] or manifest["installer_iso_template_v2"]["manage_origin"] != "https://manage.cybex.net":
            raise ValueError("Recovered fleet release/origin changed")
        identity = {"schema": IDENTITY_SCHEMA, "authorization_sha256": sha(recovery_path),
                    "published": old, **inspect_package(directory, manifest, retain_to)}
    else:
        gate.verify_published_predecessor_descriptors(compatibility_path=publication / COMPATIBILITY,
            manifest_path=publication / MANIFEST, trusted_public_key=trusted_key,
            release_verifier=ROOT / "tools/james-release.py", github_release_id=previous["id"], tag_name=tag)
        for name in (MANIFEST, COMPATIBILITY):
            (directory / name).write_bytes((publication / name).read_bytes())
        manifest = verify_pair(directory, trusted_key, base + MANIFEST)
        identity = {"schema": gate.PREDECESSOR_SCHEMA, "github_release_id": previous["id"],
                    "tag_name": tag, **inspect_package(directory, manifest, retain_to)}
        gate.validate_predecessor_identity(identity)
    if release._compare_semver(candidate, identity["release_id"]) <= 0:
        raise ValueError("Candidate does not advance the authenticated predecessor")
    return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--candidate-version", required=True)
    parser.add_argument("--trusted-public-key", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, default=ROOT / "release/recovery-adoption.json")
    parser.add_argument("--expected-identity", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--download-media", action="store_true")
    parser.add_argument("--retain-manage-source-to", type=Path,
                        help="export all verified predecessor source archives for the next package")
    args = parser.parse_args()
    release._validate_version(args.candidate_version)
    identity = resolve(args.repository, args.candidate_version, args.trusted_public_key,
                       args.directory, args.authorization, args.retain_manage_source_to)
    if args.expected_identity:
        expected, body = checked_json(args.expected_identity)
        if identity != expected or body != canonical(expected):
            raise ValueError("Authenticated predecessor changed after candidate build/qualification")
    if identity is not None:
        if args.output.exists() and args.output.read_bytes() != canonical(identity):
            raise ValueError("Refusing to replace a different predecessor identity")
        args.output.write_bytes(canonical(identity))
    if args.download_media and identity:
        manifest = json.loads((args.directory / MANIFEST).read_bytes())
        iso = manifest["installer_iso_template_v2"]
        fetch(iso["url"], args.directory / urlsplit(iso["url"]).path.rsplit("/", 1)[-1], iso["template_sha256"], iso["size_bytes"], maximum=16 * 1024**3)
    if args.github_output:
        values = {"exists": str(identity is not None).lower()}
        if identity:
            values.update(identity_b64=base64.b64encode(canonical(identity)).decode(), identity_sha256=hashlib.sha256(canonical(identity)).hexdigest(),
                          release_id=identity["release_id"], snapshot_id=identity["ubuntu_snapshot_id"], update_contract=identity["update_contract"])
        with args.github_output.open("a") as stream:
            stream.write("".join(f"{k}={v}\n" for k, v in values.items()))
    print("Authenticated predecessor: " + (identity["release_id"] if identity else "first release"))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, release.ReleaseError, gate.GateError, subprocess.CalledProcessError) as error:
        raise SystemExit("Predecessor admission failed: " + str(error)) from None
