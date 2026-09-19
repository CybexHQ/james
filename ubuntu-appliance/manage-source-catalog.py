#!/usr/bin/env python3
"""Carry authenticated predecessor sources into the next immutable Debian package.

release_predecessor.py supplies the retained directory only after authenticating
the signed manifest and exact package snapshot. This build helper revalidates
every source pair, deduplicates exact revisions, and never prunes old sources.
"""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re
import shutil
import stat

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("james_release", ROOT / "tools/james-release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def inspect(directory):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755:
        raise ValueError("Manage source catalog must be a regular mode-0755 directory")
    pairs = {}
    total = 0
    for path in directory.iterdir():
        match = re.fullmatch(r"([0-9a-f]{40})\.(tar|json)", path.name)
        info = path.lstat()
        if (match is None or not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1):
            raise ValueError("Manage source catalog has an unexpected or unsafe entry")
        revision, kind = match.groups()
        pairs.setdefault(revision, {})[kind] = path
        if len(pairs) > release.MANAGE_SOURCE_CATALOG_MAX_REVISIONS:
            raise ValueError("Manage source catalog exceeds its revision bound")
        maximum = (release.MANAGE_SOURCE_ARCHIVE_MAX_BYTES if kind == "tar"
                   else release.MANAGE_SOURCE_METADATA_MAX_BYTES)
        if not 0 < info.st_size <= maximum:
            raise ValueError("Manage source entry exceeds its size bound")
        if kind == "tar":
            total += info.st_size
            if total > release.MANAGE_SOURCE_CATALOG_MAX_BYTES:
                raise ValueError("Manage source catalog exceeds its total byte bound")
    if not pairs or any(set(pair) != {"tar", "json"} for pair in pairs.values()):
        raise ValueError("Manage source catalog omits a complete archive pair")
    result = {}
    for revision, pair in sorted(pairs.items()):
        digest, size = release._inspect_artifact(
            pair["tar"], "retained Manage source", maximum_bytes=release.MANAGE_SOURCE_ARCHIVE_MAX_BYTES)
        _, body = release._load_bounded_json(
            pair["json"], "retained Manage source metadata",
            maximum_bytes=release.MANAGE_SOURCE_METADATA_MAX_BYTES)
        release._verify_manage_source_pair(pair["tar"], body, revision, digest, size)
        result[revision] = (pair["tar"], body, size)
    return result


def merge(output, retained=None, verify_only=False):
    current = inspect(output)
    inherited = inspect(retained) if retained is not None else {}
    for revision in current.keys() & inherited.keys():
        if current[revision][1:] != inherited[revision][1:]:
            raise ValueError("Manage source revision has conflicting archive bytes")
    combined = inherited | current
    if verify_only and inherited.keys() - current.keys():
        raise ValueError("Packaged Manage source catalog omitted a retained revision")
    if len(combined) > release.MANAGE_SOURCE_CATALOG_MAX_REVISIONS:
        raise ValueError("Combined Manage source catalog exceeds its revision bound")
    if sum(pair[2] for pair in combined.values()) > release.MANAGE_SOURCE_CATALOG_MAX_BYTES:
        raise ValueError("Combined Manage source catalog exceeds its total byte bound")
    for revision in sorted(inherited.keys() - current.keys()):
        archive, metadata, _ = inherited[revision]
        target = output / f"{revision}.tar"
        with archive.open("rb") as source, target.open("xb") as destination:
            shutil.copyfileobj(source, destination)
        target.chmod(0o444)
        target = output / f"{revision}.json"
        with target.open("xb") as destination:
            destination.write(metadata)
        target.chmod(0o444)
    verified = inspect(output)
    if {k: v[1:] for k, v in verified.items()} != {k: v[1:] for k, v in combined.items()}:
        raise ValueError("Manage source catalog changed during packaging")
    return len(verified)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--retained-source-dir", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    count = merge(args.output_dir, args.retained_source_dir, args.verify_only)
    print(f"Verified immutable Manage source catalog: {count} revisions")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, release.ReleaseError) as error:
        raise SystemExit("Manage source retention failed: " + str(error)) from None
