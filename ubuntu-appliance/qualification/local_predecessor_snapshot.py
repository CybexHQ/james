"""Private immutable qualification snapshots of historical served releases.

The served tree is never modified. A snapshot is usable only with a matching
live origin index and bytes; it is not an alternate publication origin.
"""

from contextlib import contextmanager
from functools import cmp_to_key
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from types import SimpleNamespace


SCHEMA = "cybex.james.local-predecessor-snapshot.v1"


class Snapshot:
    def __init__(self, gate, arguments, prefix):
        self.g = SimpleNamespace(**gate)
        self.args = arguments
        self.root = arguments.artifact_root
        self.output = arguments.prepared_release
        self.prefix = prefix

    def owned(self, path, *, directory=False, sealed=False):
        g = self.g
        if not path.is_absolute() or path.resolve(strict=True) != path:
            g.fail("predecessor path must be absolute without symlinks")
        info = path.lstat()
        kind = stat.S_ISDIR if directory else stat.S_ISREG
        if not kind(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            g.fail("predecessor path ownership or permissions are unsafe")
        if sealed and (stat.S_IMODE(info.st_mode) != (0o555 if directory else 0o444)
                       or (not directory and info.st_nlink != 1)):
            g.fail("prepared predecessor metadata is not immutable")
        return info

    @contextmanager
    def lock(self, exclusive=False):
        self.owned(self.root, directory=True)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            if self.g.stable_file_identity(os.fstat(fd)) != self.g.stable_file_identity(self.root.stat()):
                self.g.fail("predecessor root changed while locking")
            yield
        finally:
            os.close(fd)

    def index(self):
        g = self.g
        before = self.owned(self.root, directory=True)
        names = os.listdir(self.root)
        if len(names) > g.MAX_LOCAL_RELEASE_ROOT_ENTRIES:
            g.fail("local predecessor origin has too many entries")
        entries, candidates = [], []
        for name in sorted(names):
            if not g.SEMVER_RE.fullmatch(name):
                continue
            observation, info, children = g.observe_local_semver_entry(self.root / name, name)
            package = f"cybex-james-appliance-packages-{name}-x86_64-linux.tar.zst"
            if children == {package} and stat.S_IMODE(info.st_mode) == 0o555:
                journal, package_hash = g.load_local_stage_journal(
                    artifact_root=self.root, state_directory=self.args.staging_state_dir,
                    served_prefix=self.prefix, release_id=name,
                    release_directory=self.root / name)
                observation["owned_stage"] = [journal, package_hash]
            else:
                candidates.append(name)
            entries.append(observation)
        if not candidates or len(candidates) > g.MAX_LOCAL_PUBLISHED_RELEASES:
            g.fail("local predecessor origin has no bounded release candidates")
        candidates.sort(key=cmp_to_key(lambda a, b: g.semver_compare(
            g.semver_parts(a, "origin release"), g.semver_parts(b, "origin release"))))
        for a, b in zip(candidates, candidates[1:]):
            if g.semver_compare(g.semver_parts(a, "origin release"),
                                g.semver_parts(b, "origin release")) == 0:
                g.fail("local predecessor origin has ambiguous release precedence")
        if set(names) != set(os.listdir(self.root)) or g.stable_file_identity(before) != g.stable_file_identity(self.root.stat()):
            g.fail("local predecessor origin changed during discovery")
        digest = g.sha256_bytes(g.canonical_json({
            "artifact_root": str(self.root), "served_prefix": self.prefix, "entries": entries}))
        return candidates[-1], digest

    def paths(self, directory, release):
        g = self.g
        manifest, _body = g.load_json(directory / g.RELEASE_MANIFEST_FILENAME,
                                      "snapshot manifest", g.MAX_MANIFEST_BYTES)
        runtime = manifest.get("workstation_netboot")
        if not isinstance(runtime, dict) or not isinstance(runtime.get("url"), str):
            g.fail("snapshot manifest has no workstation descriptor")
        runtime_name = runtime["url"].rsplit("/", 1)[-1]
        fixed = [
            "cybex-james-x86_64-linux",
            f"cybex-james-appliance-template-{release}-x86_64-linux.iso",
            f"cybex-james-appliance-packages-{release}-x86_64-linux.tar.zst",
            runtime_name, g.RELEASE_MANIFEST_FILENAME, g.RELEASE_COMPATIBILITY_FILENAME]
        # Reuse the canonical filename grammar and exact six-artifact layout.
        g.local_release_filenames(release, set(fixed) | {"SHA256SUMS"})
        runtime_url = g.require_local_runtime_url(runtime["url"], self.prefix, release, runtime_name)
        return {name: (self.root / release / name) for name in fixed if name != runtime_name} | {
            runtime_name: self.root / runtime_url[len(self.prefix) + 1:]}

    def authenticate(self, directory, release):
        g = self.g
        compatibility, _body = g.load_json(directory / g.RELEASE_COMPATIBILITY_FILENAME,
                                           "snapshot compatibility", g.MAX_QUALIFICATION_BYTES)
        contract = compatibility.get("compatibility")
        if not isinstance(contract, dict):
            g.fail("snapshot compatibility contract is missing")
        with tempfile.TemporaryDirectory(prefix="cybex-predecessor-contract-") as temporary:
            path = Path(temporary) / "compatibility.json"
            path.write_bytes(g.canonical_json(contract))
            g.run_bounded([
                g.sys.executable, "-B", str(self.args.release_verifier), "verify-compatibility",
                "--asset", str(directory / g.RELEASE_COMPATIBILITY_FILENAME),
                "--manifest", str(directory / g.RELEASE_MANIFEST_FILENAME),
                "--manifest-url", g.local_asset_url(self.prefix, release, g.RELEASE_MANIFEST_FILENAME),
                "--compatibility", str(path), "--trusted-public-key", self.args.trusted_public_key,
            ], "historical predecessor signature verification")

    def copy(self, source, target):
        g = self.g
        self.owned(source.parent, directory=True)
        before = self.owned(source)
        maximum = g.local_artifact_maximum(target.name)
        if before.st_size <= 0 or before.st_size > maximum:
            g.fail("historical predecessor artifact size is outside its bound")
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if g.stable_file_identity(os.fstat(fd)) != g.stable_file_identity(before):
                g.fail("historical predecessor artifact changed before copying")
            digest, size = hashlib.sha256(), 0
            with target.open("xb") as destination:
                while chunk := os.read(fd, 1024 * 1024):
                    size += len(chunk)
                    if size > maximum:
                        g.fail("historical predecessor artifact exceeds its bound")
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fchmod(destination.fileno(), 0o555 if target.name == "cybex-james-x86_64-linux" else 0o444)
                os.fsync(destination.fileno())
            if size != before.st_size or g.stable_file_identity(os.fstat(fd)) != g.stable_file_identity(before):
                g.fail("historical predecessor artifact changed while copying")
            return digest.hexdigest()
        finally:
            os.close(fd)

    def sources(self, selected, checksum):
        g = self.g
        sources = self.paths(selected["directory"], selected["release_id"])
        for record in selected["artifacts"]:
            name = record["filename"]
            expected = record
            if name == "SHA256SUMS":
                source = self.root / selected["release_id"] / name
                expected = checksum
            else:
                source = sources[name]
            self.owned(source.parent, directory=True)
            self.owned(source)
            digest, size, _prefix = g.hash_regular(source, "historical predecessor artifact",
                                                   g.local_artifact_maximum(name))
            if digest != expected["sha256"] or size != expected["size_bytes"]:
                g.fail("historical predecessor bytes differ from the immutable snapshot")
        body = g.open_regular(self.root / selected["release_id"] / "SHA256SUMS",
                              "historical checksum index", g.MAX_CHECKSUM_INDEX_BYTES)
        order, runtime = g.local_release_filenames(selected["release_id"], set(sources) | {"SHA256SUMS"})
        # Older releases list five local files when their runtime is reused
        # from an older signed URL; no referenced artifact escapes hashing.
        if len(body.splitlines()) == 5 and sources[runtime].parent.name != selected["release_id"]:
            order.remove(runtime)
        normalized = re.sub(rb"(?m)^([0-9a-f]{64})  ", rb"\1 *", body)
        listed = g.parse_local_checksum_index(normalized, order)
        expected = {record["filename"]: record["sha256"] for record in selected["artifacts"]}
        if any(value != expected[name] for name, value in listed.items()):
            g.fail("historical checksum index does not match the signed artifacts")

    def stream(self, selected, checksum):
        sources = self.paths(selected["directory"], selected["release_id"])
        for record in selected["artifacts"]:
            name = record["filename"]
            source = sources.get(name, self.root / selected["release_id"] / name)
            expected = checksum if name == "SHA256SUMS" else record
            self.g.stream_https_artifact(
                self.prefix + "/" + source.relative_to(self.root).as_posix(),
                expected_sha256=expected["sha256"], expected_size=expected["size_bytes"],
                label="historical predecessor artifact")

    def prepare(self):
        g = self.g
        self.owned(self.output.parent, directory=True)
        if not self.output.is_absolute() or self.output == self.root or self.root in self.output.parents:
            g.fail("prepared predecessor must be outside the served artifact tree")
        if self.output.exists() or self.output.is_symlink():
            g.fail("prepared predecessor output already exists; do not overwrite it")
        with self.lock(exclusive=True):
            release, origin_index = self.index()
            source = self.root / release
            self.owned(source, directory=True)
            self.output.mkdir(mode=0o700)
            complete = False
            try:
                directory = self.output / release
                directory.mkdir(mode=0o700)
                hashes = {}
                for name in (g.RELEASE_MANIFEST_FILENAME, g.RELEASE_COMPATIBILITY_FILENAME):
                    hashes[name] = self.copy(source / name, directory / name)
                self.authenticate(directory, release)
                paths = self.paths(directory, release)
                for name, path in paths.items():
                    if name not in hashes:
                        hashes[name] = self.copy(path, directory / name)
                order, _runtime = g.local_release_filenames(release, set(paths) | {"SHA256SUMS"})
                g.write_exclusive(directory / "SHA256SUMS", "".join(
                    f"{hashes[name]} *{name}\n" for name in order).encode("ascii"))
                (directory / "SHA256SUMS").chmod(0o444)
                directory.chmod(0o555)
                selected = g.inspect_local_release_set(directory, release, verify_all_bytes=True)
                g.verify_local_predecessor_descriptors(
                    release_set=selected, served_prefix=self.prefix,
                    trusted_public_key=self.args.trusted_public_key,
                    release_verifier=self.args.release_verifier)
                self.owned(source / "SHA256SUMS")
                digest, size, _prefix = g.hash_regular(source / "SHA256SUMS",
                    "historical checksum index", g.MAX_CHECKSUM_INDEX_BYTES)
                checksum = {"sha256": digest, "size_bytes": size}
                self.sources(selected, checksum)
                self.stream(selected, checksum)
                if self.index() != (release, origin_index):
                    g.fail("historical predecessor origin changed during preparation")
                receipt = {
                    "schema": SCHEMA, "artifact_root": str(self.root), "served_prefix": self.prefix,
                    "release_id": release, "source_index_sha256": origin_index,
                    "release_set_sha256": selected["release_set_sha256"], "origin_checksum": checksum}
                g.write_exclusive(self.output / "origin.json", g.canonical_json(receipt))
                (self.output / "origin.json").chmod(0o444)
                self.output.chmod(0o555)
                for path in (directory / "SHA256SUMS", self.output / "origin.json"):
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                for path in (directory, self.output, self.output.parent):
                    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                complete = True
            finally:
                if not complete:
                    for path in (self.output, self.output / release):
                        if path.is_dir():
                            path.chmod(0o700)
                    shutil.rmtree(self.output)

    def load(self):
        g = self.g
        with self.lock():
            self.owned(self.output, directory=True, sealed=True)
            receipt_path = self.output / "origin.json"
            self.owned(receipt_path, sealed=True)
            receipt, body = g.load_json(receipt_path, "prepared predecessor origin", g.MAX_POLICY_BYTES)
            g.exact_keys(receipt, {"schema", "artifact_root", "served_prefix", "release_id",
                                  "source_index_sha256", "release_set_sha256", "origin_checksum"},
                         "prepared predecessor origin")
            if (body != g.canonical_json(receipt) or receipt["schema"] != SCHEMA
                or receipt["artifact_root"] != str(self.root) or receipt["served_prefix"] != self.prefix):
                g.fail("prepared predecessor origin does not match this release source")
            release, origin_index = self.index()
            if (receipt["release_id"], receipt["source_index_sha256"]) != (release, origin_index):
                g.fail("historical predecessor origin changed after preparation")
            if set(os.listdir(self.output)) != {"origin.json", release}:
                g.fail("prepared predecessor directory contains unexpected entries")
            selected = g.inspect_local_release_set(self.output / release, release, verify_all_bytes=True)
            if selected is None or selected["release_set_sha256"] != receipt["release_set_sha256"]:
                g.fail("prepared predecessor immutable release set changed")
            g.verify_local_predecessor_descriptors(
                release_set=selected, served_prefix=self.prefix,
                trusted_public_key=self.args.trusted_public_key,
                release_verifier=self.args.release_verifier)
            checksum = receipt["origin_checksum"]
            if not isinstance(checksum, dict):
                g.fail("prepared predecessor checksum binding is invalid")
            g.exact_keys(checksum, {"sha256", "size_bytes"}, "origin checksum binding")
            g.sha256_field(checksum["sha256"], "origin checksum")
            size = checksum["size_bytes"]
            if type(size) is not int or not 0 < size <= g.MAX_CHECKSUM_INDEX_BYTES:
                g.fail("prepared predecessor checksum size is invalid")
            self.sources(selected, checksum)
            if self.index() != (release, origin_index):
                g.fail("historical predecessor origin changed during inspection")
            selected["origin_checksum"] = checksum
            return [selected], origin_index
