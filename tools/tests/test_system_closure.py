from copy import deepcopy
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
API = SimpleNamespace(**runpy.run_path(str(ROOT / "tools/james-release.py")))
C = API.system_closure
PACK = SimpleNamespace(**runpy.run_path(str(ROOT / "tools/pack-system-closure.py")))


def string(body):
    return struct.pack("<Q", len(body)) + body + bytes((-len(body)) % 8)


def regular_nar(body):
    return b"".join(string(value) for value in (b"nix-archive-1", b"(", b"type", b"regular", b"contents", body, b")"))


@unittest.skipUnless(shutil.which("zstd") and shutil.which("openssl") and shutil.which("git"), "release tools required")
class SystemClosureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        (self.cache / "nar").mkdir(parents=True)
        self.key = self.root / "key.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.key)], check=True, capture_output=True)
        self.key.chmod(0o600)
        self.key_fd = API._open_regular(self.key, "key", private=True)
        self.addCleanup(os.close, self.key_fd)
        self.public = base64.b64encode(API._public_der(self.key_fd)[len(API.ED25519_PUBLIC_DER_PREFIX):]).decode()
        source_root = self.root / "source"
        source_root.mkdir()
        for name in API.MANAGE_SOURCE_INSTALLER_REQUIRED_PATHS:
            file = source_root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("test source\n")
        def git(*args):
            return subprocess.run(["git", "-C", str(source_root), *args], check=True, capture_output=True).stdout
        git("init", "-q")
        git("add", ".")
        git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
        revision = git("rev-parse", "HEAD").decode().strip()
        source = git("-c", "tar.umask=0022", "archive", "--format=tar", "HEAD")
        fixture = json.loads((ROOT / "protocol/fixtures/james-appliance-v3.json").read_text())
        self.descriptor = {k: v for k, v in fixture["appliance_release"].items() if k != "signature"}
        self.source_path = "/nix/store/" + "1" * 32 + "-manage-source.tar"
        self.top = "/nix/store/" + "2" * 32 + "-nixos-system"
        self.descriptor.update(manage_source_revision=revision, system_toplevel=self.top)
        self.manifest = {k: self.descriptor[k] for k in (
            "release_id", "base_os", "base_os_version", "source_revision", "manage_source_revision", "nixpkgs_revision",
            "system_toplevel", "required_system_versions", "sqlite_migrations_sha256")}
        self.manifest.update(schema="cybex.james.system-closure.v1", nix_signing_public_key="cybex-james-appliance-1:" + self.public,
            manage_source={"revision": revision, "sha256": hashlib.sha256(source).hexdigest(), "size_bytes": len(source), "store_path": self.source_path},
            microcode_versions={"intel": "2026", "amd": "2026"}, store_paths=[], total_nar_bytes=0)
        self.add_nar(self.source_path, regular_nar(source), [])
        self.add_nar(self.top, regular_nar(self.source_path.encode()), [self.source_path])
        self.write_manifest()
        (self.cache / "nix-cache-info").write_text("StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n")

    def add_nar(self, path, nar, refs):
        name = path.split("/")[-1][:32]
        compressed = subprocess.run(["zstd", "-q", "-c"], input=nar, capture_output=True, check=True).stdout
        (self.cache / "nar" / (name + ".nar.zst")).write_bytes(compressed)
        info = {"StorePath": path, "URL": "nar/" + name + ".nar.zst", "Compression": "zstd",
                "FileHash": "sha256:" + C.nix_base32(hashlib.sha256(compressed).digest()), "FileSize": str(len(compressed)),
                "NarHash": "sha256:" + C.nix_base32(hashlib.sha256(nar).digest()), "NarSize": str(len(nar)),
                "References": " ".join(p.split("/")[-1] for p in refs)}
        signature = API._sign(self.key_fd, C.fingerprint({**info, "references": refs}))
        info["Sig"] = "cybex-james-appliance-1:" + base64.b64encode(signature).decode()
        (self.cache / (name + ".narinfo")).write_text("".join(k + ": " + v + "\n" for k, v in info.items()))
        self.manifest["store_paths"] = [row for row in self.manifest["store_paths"] if row["path"] != path]
        self.manifest["store_paths"].append({"path": path, "nar_hash": info["NarHash"], "nar_size": len(nar), "references": refs, "narinfo": name + ".narinfo"})
        self.manifest["store_paths"].sort(key=lambda row: row["path"])

    def write_manifest(self):
        self.manifest["total_nar_bytes"] = sum(row["nar_size"] for row in self.manifest["store_paths"])
        (self.cache / "manifest.json").write_bytes(API.appliance_v3.canonical(self.manifest) + b"\n")

    def archive(self):
        output = self.root / API.appliance_v3.archive_name(self.descriptor["release_id"])
        output.unlink(missing_ok=True)
        PACK.pack(self.cache, output)
        self.bind(output)
        return output

    def bind(self, output):
        self.descriptor["system_closure"].update(sha256=hashlib.sha256(output.read_bytes()).hexdigest(), size_bytes=output.stat().st_size)

    def verify(self, output):
        return C.verify_archive(output, self.descriptor, self.public, API)

    def test_complete_signed_closure_and_source_verify(self):
        self.assertEqual(self.verify(self.archive()), self.manifest)

    def test_external_signer_roundtrip_and_wrong_key_rejected(self):
        metadata = {k: v for k, v in self.manifest.items() if k not in {"store_paths", "total_nar_bytes"}}
        metadata.update(schema="cybex.james.appliance-closure-build.v1", manage_origin="https://console.example.invalid")
        build = self.root / "build.json"
        build.write_text(json.dumps(metadata))
        for path in self.cache.glob("*.narinfo"):
            path.write_text("\n".join(line for line in path.read_text().splitlines() if not line.startswith("Sig:")) + "\n")
        output = self.root / API.appliance_v3.archive_name(self.descriptor["release_id"])
        args = ["python3", "-B", str(ROOT / "tools/pack-system-closure.py"), "--cache", str(self.cache), "--build-metadata", str(build),
                "--private-key", str(self.key), "--output", str(output), "--metadata-output", str(self.root / "result.json")]
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.bind(output)
        self.verify(output)
        output.unlink()
        (self.root / "result.json").unlink()
        metadata["nix_signing_public_key"] = "cybex-james-appliance-1:" + base64.b64encode(bytes(32)).decode()
        build.write_text(json.dumps(metadata))
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

    def test_nar_integrity_reference_and_source_failures(self):
        mutations = ("hash", "reference", "signature", "source", "duplicate_field")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as backup:
                saved = Path(backup) / "cache"
                shutil.copytree(self.cache, saved)
                original = deepcopy(self.manifest)
                info = self.cache / ("2" * 32 + ".narinfo")
                if mutation == "hash":
                    nar = self.cache / "nar" / ("2" * 32 + ".nar.zst")
                    nar.write_bytes(nar.read_bytes()[:-1] + b"x")
                elif mutation == "reference":
                    self.add_nar(self.top, regular_nar(b"top"), ["/nix/store/" + "3" * 32 + "-missing"])
                    self.write_manifest()
                elif mutation == "signature":
                    info.write_text(info.read_text().replace("Sig: cybex-james-appliance-1:", "Sig: wrong-authority:"))
                elif mutation == "source":
                    self.manifest["manage_source"]["sha256"] = "0" * 64
                    self.write_manifest()
                else:
                    info.write_text(info.read_text() + "Compression: zstd\n")
                with self.assertRaises((API.ReleaseError, API.appliance_v3.ContractError)):
                    self.verify(self.archive())
                shutil.rmtree(self.cache)
                shutil.copytree(saved, self.cache)
                self.manifest = original

    def test_signed_malformed_nar_is_rejected(self):
        self.add_nar(self.top, regular_nar(b"body") + b"trailing", [self.source_path])
        self.write_manifest()
        with self.assertRaisesRegex(API.ReleaseError, "trailing"):
            self.verify(self.archive())

    def test_archive_inode_replacement_fails_closed(self):
        output = self.archive()
        extract = C.extract_ustar
        def replace_then_extract(*args, **kwargs):
            replacement = self.root / "replacement"
            replacement.write_bytes(output.read_bytes())
            os.replace(replacement, output)
            return extract(*args, **kwargs)
        with patch.object(C, "extract_ustar", replace_then_extract), self.assertRaisesRegex(API.ReleaseError, "changed"):
            self.verify(output)

    def test_ustar_hostile_members_and_order_are_rejected(self):
        for name, kind, first in (("../escape", tarfile.REGTYPE, False), ("manifest.json", tarfile.SYMTYPE, True),
                                  ("manifest.json", tarfile.REGTYPE, False), ("nix-cache-info", tarfile.REGTYPE, True)):
            with self.subTest(name=name, kind=kind, first=first):
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    if not first:
                        info = tarfile.TarInfo("manifest.json")
                        info.size = 2
                        archive.addfile(info, io.BytesIO(b"{}"))
                    info = tarfile.TarInfo(name)
                    info.type, info.size = kind, 2
                    if kind == tarfile.SYMTYPE:
                        info.linkname = "/etc/passwd"
                    archive.addfile(info, io.BytesIO(b"{}"))
                output = self.root / "hostile.zst"
                output.write_bytes(subprocess.run(["zstd", "-q", "-c"], input=raw.getvalue(), capture_output=True, check=True).stdout)
                self.bind(output)
                with self.assertRaises(API.ReleaseError):
                    self.verify(output)

    def test_zstd_multiple_frames_and_expansion_limit_rejected(self):
        output = self.archive()
        output.write_bytes(output.read_bytes() * 2)
        self.bind(output)
        with self.assertRaisesRegex(API.ReleaseError, "one dictionary-free"):
            self.verify(output)
        output = self.archive()
        with patch.object(C, "MAX_TAR", 1024), self.assertRaisesRegex(API.ReleaseError, "expansion"):
            self.verify(output)


if __name__ == "__main__":
    unittest.main()
