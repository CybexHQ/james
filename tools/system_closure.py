"""Bounded, independent local-cache and USTAR validation for appliance releases."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile


BASE32 = "0123456789abcdfghijklmnpqrsvwxyz"
MAX_TAR = 8 * 1024**3
MAX_NAR = 32 * 1024**3
MAX_MEMBERS = 65536
MAX_WINDOW = 128 * 1024**2
MANIFEST_FIELDS = {
    "schema", "release_id", "base_os", "base_os_version", "source_revision",
    "manage_source_revision", "nixpkgs_revision", "system_toplevel", "required_system_versions",
    "sqlite_migrations_sha256", "nix_signing_public_key", "manage_source", "microcode_versions",
    "store_paths", "total_nar_bytes",
}
ENTRY_FIELDS = {"path", "nar_hash", "nar_size", "references", "narinfo"}
NARINFO_FIELDS = {"StorePath", "URL", "Compression", "FileHash", "FileSize", "NarHash", "NarSize", "References"}


def nix_base32(body):
    result = []
    for index in range((len(body) * 8 - 1) // 5, -1, -1):
        bit = index * 5
        offset, shift = divmod(bit, 8)
        value = body[offset] >> shift
        if offset + 1 < len(body):
            value |= body[offset + 1] << (8 - shift)
        result.append(BASE32[value & 31])
    return "".join(result)


def read_regular(path, maximum, fail):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            fail("closure metadata is not a bounded regular file")
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(fd, min(1024**2, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(fd)
        if (len(data) != before.st_size or len(data) > maximum
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            fail("closure metadata changed while being read")
        return bytes(data)
    finally:
        os.close(fd)


def single_zstd_frame(path, fail, *, pass_fds=()):
    result = subprocess.run(["zstd", "--list", "-v", "-f", str(path)],
                            capture_output=True, text=True, pass_fds=pass_fds,
                            env={**os.environ, "LC_ALL": "C"})
    listing = result.stdout + result.stderr
    frames = re.findall(r"^# Zstandard Frames: ([0-9]+)$", listing, re.M)
    windows = re.findall(r"^Window Size:.*\(([0-9]+) B\)$", listing, re.M)
    if (result.returncode or frames != ["1"] or len(windows) != 1
            or int(windows[0]) > MAX_WINDOW or "Skippable" in listing
            or not re.search(r"^DictID: 0$", listing, re.M)):
        fail("closure zstd input must be one dictionary-free frame within the 128 MiB window bound")


def hash_nar(path, fail, *, source_output=None):
    single_zstd_frame(path, fail)
    process = subprocess.Popen(["zstd", "-q", "-f", "-d", "-c", "--memory=128MB", str(path)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    reader = NarReader(process.stdout, fail)
    try:
        reader.expect(b"nix-archive-1")
        reader.node(source_output=source_output)
        if process.stdout.read(1):
            fail("closure NAR has trailing bytes")
        if process.wait() != 0:
            fail("closure NAR decompression failed")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()
    return "sha256:" + nix_base32(reader.digest.digest()), reader.size


class NarReader:
    """Validate NAR grammar while hashing, without materializing store contents."""
    def __init__(self, stream, fail):
        self.stream, self.fail = stream, fail
        self.digest, self.size, self.nodes = hashlib.sha256(), 0, 0

    def read(self, count):
        result = bytearray()
        while len(result) < count:
            block = self.stream.read(count - len(result))
            if not block:
                self.fail("closure NAR is truncated")
            result.extend(block)
        self.size += count
        if self.size > MAX_NAR:
            self.fail("closure NAR expansion exceeds its bound")
        self.digest.update(result)
        return bytes(result)

    def length(self):
        return struct.unpack("<Q", self.read(8))[0]

    def padding(self, size):
        if any(self.read((-size) % 8)):
            self.fail("closure NAR padding is nonzero")

    def string(self, maximum=4096):
        size = self.length()
        if size > maximum:
            self.fail("closure NAR string exceeds its bound")
        result = self.read(size)
        self.padding(size)
        return result

    def expect(self, value):
        if self.string() != value:
            self.fail("closure NAR grammar is invalid")

    def node(self, depth=0, source_output=None):
        self.nodes += 1
        if depth > 256 or self.nodes > 2_000_000:
            self.fail("closure NAR tree exceeds its bound")
        self.expect(b"(")
        self.expect(b"type")
        kind = self.string()
        if source_output is not None and kind != b"regular":
            self.fail("embedded Manage source store path must be a regular file")
        if kind == b"regular":
            field = self.string()
            if field == b"executable":
                self.expect(b"")
                field = self.string()
            if field != b"contents":
                self.fail("closure regular NAR has invalid fields")
            size = self.length()
            if size > MAX_NAR or source_output is not None and size > 256 * 1024**2:
                self.fail("closure NAR file exceeds its bound")
            remaining = size
            while remaining:
                block = self.read(min(1024**2, remaining))
                if source_output is not None:
                    source_output.write(block)
                remaining -= len(block)
            self.padding(size)
            self.expect(b")")
        elif kind == b"symlink":
            self.expect(b"target")
            target = self.string()
            if not target or b"\0" in target:
                self.fail("closure NAR symlink target is invalid")
            self.expect(b")")
        elif kind == b"directory":
            previous = b""
            while True:
                field = self.string()
                if field == b")":
                    break
                if field != b"entry":
                    self.fail("closure directory NAR has invalid fields")
                self.expect(b"(")
                self.expect(b"name")
                name = self.string(255)
                if name <= previous or name in (b".", b"..") or b"/" in name or b"\0" in name:
                    self.fail("closure NAR directory entries are unsafe or unordered")
                previous = name
                self.expect(b"node")
                self.node(depth + 1)
                self.expect(b")")
        else:
            self.fail("closure NAR type is unsupported")


def file_hash(path, fail):
    digest, size = hashlib.sha256(), 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_TAR:
            fail("closure NAR is not a bounded regular file")
        while block := os.read(fd, 1024**2):
            size += len(block)
            if size > MAX_TAR:
                fail("closure compressed NAR exceeds its bound")
            digest.update(block)
        after = os.fstat(fd)
        if (size != before.st_size or (before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_mtime_ns, after.st_ctime_ns)):
            fail("closure NAR changed while being read")
    finally:
        os.close(fd)
    return "sha256:" + nix_base32(digest.digest()), size


def narinfo(path, contract, fail, *, signed):
    body = read_regular(path, 1024**2, fail)
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError:
        fail("closure NARInfo is not ASCII")
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition(": ")
        if not separator or key in fields:
            fail("closure NARInfo has duplicate or malformed fields")
        fields[key] = value
    allowed = NARINFO_FIELDS | ({"Sig"} if signed else set())
    # Nix exports optional derivation provenance; it is never a reference or a
    # source of trust. It must still be an ordinary store basename.
    if "Deriver" in fields:
        allowed.add("Deriver")
        if fields["Deriver"] != "unknown-deriver":
            contract.store_path("/nix/store/" + fields["Deriver"])
    if set(fields) != allowed or fields["Compression"] != "zstd":
        fail("closure NARInfo fields or compression are incompatible")
    contract.store_path(fields["StorePath"])
    if not re.fullmatch(r"nar/[A-Za-z0-9+._=-]{1,160}\.nar\.zst", fields["URL"]):
        fail("closure NARInfo URL is not a local NAR member")
    for field in ("NarHash", "FileHash"):
        if not re.fullmatch("sha256:[" + BASE32 + "]{52}", fields[field]):
            fail("closure NARInfo hash is not canonical Nix-base32 SHA-256")
    for field in ("NarSize", "FileSize"):
        if not re.fullmatch(r"[1-9][0-9]{0,10}", fields[field]):
            fail("closure NARInfo size is not canonical")
    references = fields["References"].split() if fields["References"] else []
    if references != sorted(set(references)):
        fail("closure NARInfo references must be sorted and unique")
    fields["references"] = [contract.store_path("/nix/store/" + reference) for reference in references]
    return fields


def fingerprint(info):
    return ("1;" + info["StorePath"] + ";" + info["NarHash"] + ";" + info["NarSize"]
            + ";" + ",".join(info["references"])).encode()


def verify_directory(root, descriptor, public_key, api, *, signed=True):
    root = Path(root)
    contract, fail = api.appliance_v3, api._fail
    body = read_regular(root / "manifest.json", 16 * 1024**2, fail)
    try:
        manifest = json.loads(body, object_pairs_hook=contract.unique_object)
    except (ValueError, UnicodeDecodeError):
        fail("closure manifest is invalid JSON")
    contract.exact(manifest, MANIFEST_FIELDS, "system closure manifest")
    if body != contract.canonical(manifest) + b"\n" or manifest["schema"] != "cybex.james.system-closure.v1":
        fail("system closure manifest is not canonical")
    for field in ("release_id", "base_os", "base_os_version", "source_revision", "manage_source_revision",
                  "nixpkgs_revision", "system_toplevel", "required_system_versions", "sqlite_migrations_sha256"):
        if manifest[field] != descriptor[field]:
            fail("system closure manifest disagrees with signed release identity")
    raw_key = api._trusted_public_key(public_key)
    named_key = "cybex-james-appliance-1:" + base64.b64encode(raw_key).decode()
    if manifest["nix_signing_public_key"] != named_key:
        fail("closure NAR key is not the independently trusted release authority")
    cache_info = read_regular(root / "nix-cache-info", 4096, fail).decode("ascii")
    if cache_info not in ("StoreDir: /nix/store\n", "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"):
        fail("closure cache must use the standard Nix store")
    source = contract.exact(manifest["manage_source"], {"revision", "sha256", "size_bytes", "store_path"}, "closure Manage source")
    if source["revision"] != descriptor["manage_source_revision"]:
        fail("closure embedded source revision disagrees")
    contract.hex_value(source["sha256"], 64, "embedded source hash")
    contract.integer(source["size_bytes"], 1, 256 * 1024**2, "embedded source size")
    contract.store_path(source["store_path"])
    contract.exact(manifest["microcode_versions"], {"intel", "amd"}, "microcode versions")
    for value in manifest["microcode_versions"].values():
        contract.token(value, "microcode version")
    entries = manifest["store_paths"]
    if not isinstance(entries, list) or not 1 <= len(entries) < MAX_MEMBERS // 2:
        fail("closure store graph exceeds its bound")
    graph, members, total, infos = {}, {"manifest.json", "nix-cache-info"}, 0, {}
    prior = ""
    for entry in entries:
        contract.exact(entry, ENTRY_FIELDS, "closure store path")
        path = contract.store_path(entry["path"])
        if path <= prior:
            fail("closure store graph must be sorted and unique")
        prior = path
        name = path.split("/")[-1].split("-", 1)[0] + ".narinfo"
        if entry["narinfo"] != name:
            fail("closure NARInfo filename does not match store identity")
        info = narinfo(root / name, contract, fail, signed=signed)
        if (info["StorePath"] != path or entry["nar_hash"] != info["NarHash"]
                or type(entry["nar_size"]) is not int or entry["nar_size"] != int(info["NarSize"])
                or entry["references"] != info["references"]):
            fail("closure graph disagrees with NARInfo")
        total += entry["nar_size"]
        if total > MAX_NAR or entry["nar_size"] < 1:
            fail("closure NAR payload exceeds its bound")
        if signed:
            name_key, separator, signature = info["Sig"].partition(":")
            if separator != ":" or name_key != "cybex-james-appliance-1":
                fail("closure NAR signature authority is invalid")
            api._self_verify(api.ED25519_PUBLIC_DER_PREFIX + raw_key,
                             contract.base64_bytes(signature, 64, "NAR signature"), fingerprint(info))
        nar_path = root / info["URL"]
        if file_hash(nar_path, fail) != (info["FileHash"], int(info["FileSize"])):
            fail("compressed closure NAR integrity mismatch")
        if path == source["store_path"]:
            with tempfile.TemporaryDirectory(prefix="cybex-closure-source-") as source_dir:
                source_file = Path(source_dir) / "source.tar"
                with source_file.open("wb") as output:
                    actual_nar = hash_nar(nar_path, fail, source_output=output)
                source_hash, source_size = api._inspect_artifact(source_file, "embedded Manage source", maximum_bytes=256 * 1024**2)
                if (source_hash, source_size) != (source["sha256"], source["size_bytes"]):
                    fail("embedded Manage source bytes disagree with their signed identity")
                api._verify_manage_source_git_archive(source_file, source["revision"])
        else:
            actual_nar = hash_nar(nar_path, fail)
        if actual_nar != (info["NarHash"], int(info["NarSize"])):
            fail("uncompressed closure NAR integrity mismatch")
        members.update((name, info["URL"]))
        graph[path] = entry["references"]
        infos[name] = info
    if type(manifest["total_nar_bytes"]) is not int or total != manifest["total_nar_bytes"]:
        fail("closure total NAR size disagrees")
    reachable, queue = set(), [descriptor["system_toplevel"]]
    while queue:
        path = queue.pop()
        if path in reachable:
            continue
        if path not in graph:
            fail("closure has an incomplete toplevel reference graph")
        reachable.add(path)
        queue.extend(graph[path])
    if reachable != set(graph) or source["store_path"] not in graph:
        fail("closure contains unreachable paths or omits its embedded Manage source")
    actual = set()
    for directory, names, files in os.walk(root, followlinks=False):
        for name in names:
            item = Path(directory) / name
            if item.is_symlink() or item.relative_to(root).as_posix() != "nar":
                fail("closure cache contains an unexpected directory")
        for name in files:
            item = Path(directory) / name
            if not stat.S_ISREG(item.lstat().st_mode):
                fail("closure cache contains an unsafe member")
            actual.add(item.relative_to(root).as_posix())
    if actual != members:
        fail("closure cache member set differs from its verified graph")
    return manifest, infos


def extract_ustar(path, destination, fail, *, pass_fds=()):
    """Extract a single bounded canonical stream; reject tar parser extensions."""
    single_zstd_frame(path, fail, pass_fds=pass_fds)
    process = subprocess.Popen(["zstd", "-q", "-f", "-d", "-c", "--memory=128MB", str(path)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=pass_fds)
    stream, total, names, payload_started = process.stdout, 0, set(), False
    def read(size):
        nonlocal total
        data = bytearray()
        while len(data) < size:
            block = stream.read(size - len(data))
            if not block:
                fail("closure USTAR stream is truncated")
            data.extend(block)
        total += size
        if total > MAX_TAR:
            fail("closure tar expansion exceeds its bound")
        return bytes(data)
    def number(raw):
        if not re.fullmatch(b"[0-7]+(?:\x00 ?| )?", raw):
            fail("closure tar contains a noncanonical numeric header")
        return int(raw.strip(b" \x00") or b"0", 8)
    try:
        while True:
            header = read(512)
            if not any(header):
                if any(read(512)):
                    fail("closure tar end marker is malformed")
                tail = stream.read(10241)
                if len(tail) > 10240 or any(tail):
                    fail("closure tar has trailing data")
                break
            if (header[257:265] != b"ustar\x0000" or any(header[345:500])
                    or number(header[148:156]) != sum(header[:148] + b" " * 8 + header[156:])
                    or number(header[108:116]) != 0 or number(header[116:124]) != 0):
                fail("closure tar is not canonical root-owned USTAR")
            try:
                name = header[:100].split(b"\0", 1)[0].decode("ascii")
            except UnicodeDecodeError:
                fail("closure tar member name is invalid")
            valid = (name in {"manifest.json", "nix-cache-info", "nar/"}
                     or re.fullmatch("[" + BASE32 + "]{32}\\.narinfo", name)
                     or re.fullmatch(r"nar/[A-Za-z0-9+._=-]{1,160}\.nar\.zst", name))
            if not valid or name in names or len(names) >= MAX_MEMBERS:
                fail("closure tar member name, count or uniqueness is invalid")
            if not names and name != "manifest.json":
                fail("closure tar must begin with its manifest")
            if name.startswith("nar/"):
                payload_started = True
            elif payload_started:
                fail("closure metadata must precede every NAR payload")
            names.add(name)
            size, kind = number(header[124:136]), header[156:157]
            if name == "nar/":
                if size or kind != b"5":
                    fail("closure nar directory header is invalid")
                (destination / "nar").mkdir(exist_ok=True, mode=0o700)
                continue
            if kind not in (b"0", b"\0") or any(header[157:257]) or size <= 0:
                fail("closure tar member must be a nonempty regular file")
            maximum = (16 * 1024**2 if name == "manifest.json" else 1024**2 if name.endswith(".narinfo")
                       else 4096 if name == "nix-cache-info" else MAX_TAR)
            if size > maximum:
                fail("closure tar member exceeds its size bound")
            target = destination / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                remaining = size
                while remaining:
                    block = read(min(1024**2, remaining))
                    view = memoryview(block)
                    while view:
                        view = view[os.write(fd, view):]
                    remaining -= len(block)
            finally:
                os.close(fd)
            padding = (-size) % 512
            if padding and any(read(padding)):
                fail("closure tar padding is nonzero")
        if process.wait() != 0:
            fail("closure archive decompression failed")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()


def verify_archive(path, descriptor, public_key, api):
    fd = api._open_regular(Path(path), "NixOS closure")
    try:
        before = os.fstat(fd)
        if not 0 < before.st_size <= 4 * 1024**3:
            api._fail("NixOS closure size is outside its bound")
        digest, size = hashlib.sha256(), 0
        while block := os.read(fd, 1024**2):
            size += len(block)
            if size > 4 * 1024**3:
                api._fail("NixOS closure grew beyond its bound")
            digest.update(block)
        if (digest.hexdigest(), size) != (descriptor["system_closure"]["sha256"], descriptor["system_closure"]["size_bytes"]):
            api._fail("NixOS closure does not match signed size/digest")
        os.lseek(fd, 0, os.SEEK_SET)
        with tempfile.TemporaryDirectory(prefix="cybex-closure-verify-") as directory:
            root = Path(directory)
            extract_ustar(Path(f"/proc/self/fd/{fd}"), root, api._fail, pass_fds=(fd,))
            manifest, _ = verify_directory(root, descriptor, public_key, api)
        after = os.fstat(fd)
        current = Path(path).lstat()
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) or getattr(before, field) != getattr(current, field) for field in fields):
            api._fail("NixOS closure changed during verification")
        return manifest
    finally:
        os.close(fd)
