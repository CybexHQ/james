"""Real package upgrades must preserve the sources for installed runtimes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import nullcontext
from unittest import mock

from test_appliance_contract import create_manage_source_fixture

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


C = module("manage_source_catalog", ROOT / "ubuntu-appliance/manage-source-catalog.py")
P = module("release_predecessor", ROOT / "ubuntu-appliance/qualification/release_predecessor.py")
R = C.release
KEY = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
SNAPSHOT = "20260805T000000Z"


def run(*args, **kwargs):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, **kwargs)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    return result


def snapshot(directory, version, packages):
    path = directory / f"cybex-james-appliance-packages-{version}-x86_64-linux.tar"
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for package in packages:
            entry = tarfile.TarInfo(package.name)
            entry.mode, entry.size = 0o644, package.stat().st_size
            with package.open("rb") as stream:
                archive.addfile(entry, stream)
    run("zstd", "-q", str(path), "-o", str(path) + ".zst")
    path.unlink()
    return Path(str(path) + ".zst")


@unittest.skipUnless(all(shutil.which(tool) for tool in ("git", "jq", "dpkg", "dpkg-deb", "zstd")),
                     "native package and source tools are required")
class RetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.source, cls.old_revision = create_manage_source_fixture(cls.root)
        cls.binary = cls.root / "fixture-binary"
        cls.binary.write_bytes(b"test binary\n")
        cls.binary.chmod(0o755)
        cls.old = cls.build("old", "1.2.3", cls.old_revision)
        cls.old_snapshot = snapshot(cls.root, "1.2.3", [cls.old])
        cls.retained = cls.root / "retained"
        R._inspect_packaged_manage_source(cls.old_snapshot, "1.2.3", retain_to=cls.retained)
        (cls.source / "new-version").write_text("second revision\n")
        run("git", "-C", cls.source, "add", ".")
        run("git", "-C", cls.source, "commit", "-qm", "next version")
        cls.new_revision = run("git", "-C", cls.source, "rev-parse", "HEAD").stdout.decode().strip()
        cls.new = cls.build("new", "1.2.4", cls.new_revision, cls.retained)
        cls.new_snapshot = snapshot(cls.root, "1.2.4", [cls.new])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def build(cls, name, version, revision, retained=None):
        output = cls.root / name
        arguments = [ROOT / "ubuntu-appliance/build-packages.sh", "--output", output,
                     "--james-binary", cls.binary, "--bootstrap-binary", cls.binary,
                     "--version", version, "--ubuntu-snapshot-id", SNAPSHOT,
                     "--manage-source-dir", cls.source, "--manage-source-revision", revision,
                     "--release-public-key", KEY, "--provisioning-public-key", KEY]
        for dependency in ("linux-generic=7.0.0-29.29", "linux-firmware=20260319.git217ca6e4.1ubuntu",
                           "nix-bin=2.34.3+dfsg-1", "python3=3.14.3-0ubuntu2"):
            arguments.extend(["--dependency-version", dependency])
        if retained:
            arguments.extend(["--retained-manage-source-dir", retained])
        run(*arguments)
        return output / f"cybex-james_{version}-1_amd64.deb"

    def test_real_dpkg_upgrade_preserves_old_runtime_source_and_new_source(self):
        privileged = []
        if os.geteuid() != 0:
            if not shutil.which("sudo") or subprocess.run(
                    ["sudo", "-n", "true"], capture_output=True).returncode:
                self.skipTest("root or noninteractive sudo required for immutable-file dpkg upgrade")
            privileged = ["sudo", "-n"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            try:
                for package in (self.old, self.new):
                    run(*privileged, "dpkg", "--root", root, "--log", root / "dpkg.log",
                        "--force-depends", "--install", package,
                        env={**os.environ, "PATH": "/usr/sbin:/sbin:" + os.environ["PATH"]})
                catalog = root / "usr/share/cybex-james/manage-source"
                self.assertEqual(set(C.inspect(catalog)), {self.old_revision, self.new_revision})
                for suffix in ("tar", "json"):
                    retained = catalog / f"{self.old_revision}.{suffix}"
                    self.assertEqual(retained.stat().st_uid, 0)
                    self.assertEqual(retained.stat().st_gid, 0)
                    self.assertEqual(retained.read_bytes(),
                                     (self.retained / retained.name).read_bytes())
                installed = run("dpkg-query", "--admindir", root / "var/lib/dpkg", "--show",
                                "--showformat=${Version}", "cybex-james")
                self.assertEqual(installed.stdout, b"1.2.4-1")
            finally:
                if privileged:
                    run(*privileged, "chown", "-R", f"{os.getuid()}:{os.getgid()}", root)

    def test_inherited_catalog_is_transitive_deduplicated_and_byte_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary:
            retained = Path(temporary) / "retained"
            result = R._inspect_packaged_manage_source(self.new_snapshot, "1.2.4", self.new_revision,
                                                       retain_to=retained)
            self.assertEqual(result["revision"], self.new_revision)
            self.assertEqual(set(C.inspect(retained)), {self.old_revision, self.new_revision})
            repeated = self.build("repeated", "1.2.4", self.new_revision, retained)
            self.assertEqual(self.new.read_bytes(), repeated.read_bytes())
            with self.assertRaisesRegex(R.ReleaseError, "exact selected revision"):
                R._inspect_packaged_manage_source(self.new_snapshot, "1.2.4")
            with self.assertRaisesRegex(R.ReleaseError, "selected Manage source revision"):
                R._inspect_packaged_manage_source(self.new_snapshot, "1.2.4", "0" * 40)

    def test_source_tampering_links_incomplete_pairs_and_bounds_fail_closed(self):
        for mutation in ("tamper", "symlink", "hardlink", "missing", "permissions", "revision-bound", "byte-bound"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                catalog = Path(temporary) / "catalog"
                shutil.copytree(self.retained, catalog)
                archive = catalog / f"{self.old_revision}.tar"
                metadata = catalog / f"{self.old_revision}.json"
                patches = {}
                if mutation == "tamper":
                    archive.chmod(0o644)
                    with archive.open("ab") as stream:
                        stream.write(b"changed")
                    archive.chmod(0o444)
                elif mutation == "symlink":
                    archive.unlink()
                    archive.symlink_to(self.retained / archive.name)
                elif mutation == "hardlink":
                    archive.unlink()
                    os.link(self.retained / archive.name, archive)
                elif mutation == "missing":
                    metadata.unlink()
                elif mutation == "permissions":
                    archive.chmod(0o644)
                else:
                    patches["MANAGE_SOURCE_CATALOG_MAX_REVISIONS" if mutation == "revision-bound"
                            else "MANAGE_SOURCE_CATALOG_MAX_BYTES"] = 0
                with mock.patch.multiple(R, **patches) if patches else nullcontext():
                    with self.assertRaises((ValueError, R.ReleaseError)):
                        C.inspect(catalog)

    def test_same_revision_with_valid_but_different_tar_bytes_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            conflicting = Path(temporary) / "conflicting"
            output = Path(temporary) / "output"
            shutil.copytree(self.retained, conflicting)
            shutil.copytree(self.retained, output)
            archive = conflicting / f"{self.old_revision}.tar"
            body = bytearray(archive.read_bytes())
            old = b"pub fn collect() {}\n"
            self.assertIn(old, body)
            body[body.index(old):body.index(old) + len(old)] = b"pub fn collect(){} \n"
            archive.chmod(0o644)
            archive.write_bytes(body)
            archive.chmod(0o444)
            metadata = conflicting / f"{self.old_revision}.json"
            value = json.loads(metadata.read_bytes())
            value["sha256"] = hashlib.sha256(body).hexdigest()
            metadata.chmod(0o644)
            metadata.write_bytes(P.canonical(value))
            metadata.chmod(0o444)
            C.inspect(conflicting)
            with self.assertRaisesRegex(ValueError, "conflicting archive bytes"):
                C.merge(output, conflicting)

    def test_packaged_inherited_archive_is_verified_even_when_not_selected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package_root = root / "unpacked"
            run("dpkg-deb", "--raw-extract", self.new, package_root)
            archive = package_root / f"usr/share/cybex-james/manage-source/{self.old_revision}.tar"
            archive.chmod(0o644)
            archive.write_bytes(b"invalid inherited archive")
            archive.chmod(0o444)
            package = root / self.new.name
            run("dpkg-deb", "--root-owner-group", "--build", package_root, package)
            bundle = snapshot(root, "1.2.4", [package])
            with self.assertRaises(R.ReleaseError):
                R._inspect_packaged_manage_source(bundle, "1.2.4", self.new_revision,
                                                  retain_to=root / "must-not-exist")
            self.assertFalse((root / "must-not-exist").exists())

    def test_packaged_catalog_cannot_omit_an_inherited_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            catalog = Path(temporary) / "catalog"
            R._inspect_packaged_manage_source(self.new_snapshot, "1.2.4", self.new_revision, retain_to=catalog)
            with self.assertRaisesRegex(ValueError, "omitted a retained revision"):
                C.merge(self.retained, catalog, verify_only=True)

    def test_predecessor_export_is_bound_to_snapshot_and_workstation_source_digests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            for package in self.old.parent.glob("*.deb"):
                shutil.copyfile(package, repository / package.name)
            for name in ("Packages", "Packages.gz", "Release"):
                (repository / name).write_bytes(b"repository fixture\n")
            governed = sorted(repository.iterdir())
            (repository / "SHA256SUMS").write_text("".join(
                f"{P.sha(path)}  {path.name}\n" for path in governed))
            (repository / "UBUNTU-SNAPSHOT-ID").write_text(SNAPSHOT + "\n")
            bundle = snapshot(root, "1.2.3", sorted(repository.iterdir()))
            source = json.loads((self.retained / f"{self.old_revision}.json").read_bytes())
            manifest = {"version": "1.2.3", "appliance_release_v1": {
                "ubuntu_snapshot_id": SNAPSHOT, "cybex_repository_snapshot": {
                    "url": "https://github.com/CybexHQ/james/releases/download/v1.2.3/" + bundle.name,
                    "sha256": P.sha(bundle), "size_bytes": bundle.stat().st_size}},
                "workstation_netboot": {"manage_source_revision": self.old_revision,
                    "manage_source_sha256": source["sha256"], "manage_source_size_bytes": source["size_bytes"]}}
            # inspect_package runs after descriptor authentication in resolve;
            # its file digests are still part of the returned predecessor identity.
            (root / P.MANIFEST).write_bytes(P.canonical(manifest))
            (root / P.COMPATIBILITY).write_bytes(b"{}\n")
            exported = root / "exported"
            identity = P.inspect_package(root, manifest, exported)
            self.assertEqual(identity["release_id"], "1.2.3")
            self.assertEqual(set(C.inspect(exported)), {self.old_revision})
            rejected = root / "rejected"
            manifest["workstation_netboot"]["manage_source_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "signed workstation descriptor"):
                P.inspect_package(root, manifest, rejected)
            self.assertFalse(rejected.exists())
            with bundle.open("ab") as stream:
                stream.write(b"changed")
            with self.assertRaisesRegex(ValueError, "size changed"):
                P.inspect_package(root, manifest, rejected)
            self.assertFalse(rejected.exists())


if __name__ == "__main__":
    unittest.main()
