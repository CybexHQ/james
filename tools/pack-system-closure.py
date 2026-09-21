#!/usr/bin/env python3
"""Sign an unsigned Nix cache outside the store and pack one verified candidate."""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace

API = SimpleNamespace(**runpy.run_path(str(Path(__file__).with_name("james-release.py"))))
CLOSURE = API.system_closure


def stage_cache(source, destination):
    """Copy only bounded ordinary members into private signing staging."""
    total, count = 0, 0
    if not source.is_dir():
        API._fail("unsigned closure cache is not a directory")
    for directory, names, files in os.walk(source, followlinks=False):
        for name in names:
            item = Path(directory) / name
            if item.is_symlink() or item.relative_to(source).as_posix() != "nar":
                API._fail("unsigned closure contains an unexpected directory")
            (destination / "nar").mkdir(mode=0o700)
        for name in files:
            item = Path(directory) / name
            relative = item.relative_to(source)
            fd = API._open_regular(item, "unsigned closure member")
            try:
                before = os.fstat(fd)
                count += 1
                total += before.st_size
                if count > CLOSURE.MAX_MEMBERS or total > CLOSURE.MAX_TAR:
                    API._fail("unsigned closure exceeds the archive bounds")
                with (destination / relative).open("xb") as output:
                    copied = 0
                    while block := os.read(fd, 1024**2):
                        copied += len(block)
                        if copied > before.st_size:
                            API._fail("unsigned closure member grew during staging")
                        output.write(block)
                after = os.fstat(fd)
                if copied != before.st_size or any(getattr(before, f) != getattr(after, f) for f in ("st_size", "st_mtime_ns", "st_ctime_ns")):
                    API._fail("unsigned closure member changed during staging")
            finally:
                os.close(fd)


def pack(cache, output):
    """Canonical USTAR: manifest, cache metadata, NARInfos, then NAR payloads."""
    members = [cache / "manifest.json", cache / "nix-cache-info"]
    members += sorted(cache.glob("*.narinfo"))
    members += sorted((cache / "nar").glob("*.nar.zst"))
    with output.open("xb") as target:
        process = subprocess.Popen(["zstd", "-q", "-T1", "-10", "--long=27", "-c"],
                                   stdin=subprocess.PIPE, stdout=target, stderr=subprocess.PIPE)
        try:
            with tarfile.open(fileobj=process.stdin, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for member in members:
                    name = member.relative_to(cache).as_posix()
                    if len(name) > 100:
                        API._fail("closure member cannot fit the canonical USTAR name field")
                    info = tarfile.TarInfo(name)
                    info.size = member.stat().st_size
                    info.mode, info.uid, info.gid, info.mtime = 0o444, 0, 0, 0
                    with member.open("rb") as source:
                        archive.addfile(info, source)
            process.stdin.close()
            if process.wait() != 0:
                API._fail("closure archive compression failed")
            target.flush()
            os.fsync(target.fileno())
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for option in ("cache", "build-metadata", "private-key", "output", "metadata-output"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args()
    cache, output, metadata_output = Path(args.cache), Path(args.output), Path(args.metadata_output)
    metadata, _ = API._load_bounded_json(Path(args.build_metadata), "unsigned closure metadata", maximum_bytes=256 * 1024)
    metadata_fields = CLOSURE.MANIFEST_FIELDS - {"store_paths", "total_nar_bytes"} | {"manage_origin"}
    API.appliance_v3.exact(metadata, metadata_fields, "unsigned closure build metadata")
    if metadata["schema"] != "cybex.james.appliance-closure-build.v1":
        API._fail("unsigned closure build metadata schema is invalid")
    API._validate_manage_origin(metadata["manage_origin"])
    if output.name != API.appliance_v3.archive_name(metadata["release_id"]):
        API._fail("closure output filename must bind its release version")
    protected = [(Path(args.private_key), "private key"), (Path(args.build_metadata), "build metadata"), (cache, "cache")]
    API._validate_output(output, protected)
    API._validate_output(metadata_output, protected + [(output, "closure output")])
    if output.exists() or metadata_output.exists():
        API._fail("refusing to replace an existing closure candidate")
    descriptor = {key: metadata[key] for key in (
        "release_id", "base_os", "base_os_version", "source_revision", "manage_source_revision",
        "nixpkgs_revision", "system_toplevel", "required_system_versions", "sqlite_migrations_sha256",
    )}
    descriptor.update(schema=API.appliance_v3.SCHEMA, minimum_protocol=4, minimum_state_schema=3,
                      rollback_compatible=True, release_notes="https://releases.example.invalid/notes",
                      system_closure={"url": "https://releases.example.invalid/" + output.name, "sha256": "0" * 64, "size_bytes": 1})
    API.appliance_v3.validate_descriptor(descriptor, signed=False)
    private_fd = API._open_regular(Path(args.private_key), "private key", private=True)
    try:
        identity = API._private_key_identity(private_fd)
        public_der = API._public_der(private_fd)
        public_key = base64.b64encode(public_der[len(API.ED25519_PUBLIC_DER_PREFIX):]).decode()
        API._trusted_public_key(public_key)
        if metadata["nix_signing_public_key"] != "cybex-james-appliance-1:" + public_key:
            API._fail("closure signing key differs from its compiled release authority")
        with tempfile.TemporaryDirectory(prefix=".closure-sign-", dir=output.parent) as directory:
            staging = Path(directory) / "cache"
            staging.mkdir(mode=0o700)
            stage_cache(cache, staging)
            manifest, infos = CLOSURE.verify_directory(staging, descriptor, public_key, API, signed=False)
            expected = {k: v for k, v in metadata.items() if k not in {"schema", "manage_origin"}}
            if any(manifest[k] != value for k, value in expected.items()):
                API._fail("unsigned cache and build metadata identities disagree")
            for name, info in infos.items():
                message = CLOSURE.fingerprint(info)
                signature = API._sign(private_fd, message)
                API._self_verify(public_der, signature, message)
                with (staging / name).open("ab") as stream:
                    stream.write(b"Sig: cybex-james-appliance-1:" + base64.b64encode(signature) + b"\n")
            API._require_stable_private_key(private_fd, identity)
            candidate = Path(directory) / output.name
            pack(staging, candidate)
            digest, size = API._inspect_artifact(candidate, "signed closure", maximum_bytes=2 * 1024**3 - 1)
            descriptor["system_closure"].update(sha256=digest, size_bytes=size)
            CLOSURE.verify_archive(candidate, descriptor, public_key, API)
            result = {**metadata, "filename": output.name, "sha256": digest, "size_bytes": size}
            os.chmod(candidate, 0o644)
            os.link(candidate, output)
            API._atomic_write(metadata_output, API.appliance_v3.canonical(result) + b"\n")
            parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
    finally:
        os.close(private_fd)
    print(f"verified signed system closure: {output.name} sha256={digest} size_bytes={size}")


if __name__ == "__main__":
    try:
        main()
    except (API.ReleaseError, API.appliance_v3.ContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
    except OSError:
        print("error: closure signing operation could not be completed", file=sys.stderr)
        raise SystemExit(2)
