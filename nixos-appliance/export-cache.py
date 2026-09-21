#!/usr/bin/env python3
"""Produce an unsigned local binary cache without a daemon or private signing key."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"


def nix32(raw):
    number = int.from_bytes(raw, "little")
    return "".join(ALPHABET[(number >> (5 * n)) & 31] for n in reversed(range((len(raw) * 8 + 4) // 5)))


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def main():
    graph_file, metadata_file, destination = sys.argv[1:]
    graph = json.loads(Path(graph_file).read_text())["closure"]
    metadata = json.loads(Path(metadata_file).read_text())
    output = Path(destination)
    (output / "nar").mkdir(parents=True)
    (output / "nix-cache-info").write_text("StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n")
    rows = []
    total = 0
    for item in sorted(graph, key=lambda row: row["path"]):
        path = item["path"]
        store_hash = Path(path).name.split("-", 1)[0]
        archive = output / "nar" / (store_hash + ".nar.zst")
        with archive.open("wb") as target:
            dump = subprocess.Popen(["nix-store", "--dump", path], stdout=subprocess.PIPE)
            compression = subprocess.run(["zstd", "-q", "-T1", "-10", "--long=27"], stdin=dump.stdout, stdout=target)
            dump.stdout.close()
            if dump.wait() or compression.returncode:
                raise RuntimeError("NAR export failed")
        with archive.open("rb") as stream:
            file_hash = "sha256:" + nix32(hashlib.file_digest(stream, "sha256").digest())
        nar_hash = item["narHash"]
        if nar_hash.startswith("sha256-"):
            import base64
            nar_hash = "sha256:" + nix32(base64.b64decode(nar_hash[7:]))
        references = sorted(item["references"])
        narinfo = store_hash + ".narinfo"
        (output / narinfo).write_text(
            f"StorePath: {path}\nURL: nar/{archive.name}\nCompression: zstd\n"
            f"FileHash: {file_hash}\nFileSize: {archive.stat().st_size}\n"
            f"NarHash: {nar_hash}\nNarSize: {item['narSize']}\n"
            f"References: {' '.join(Path(ref).name for ref in references)}\n")
        rows.append({"path": path, "nar_hash": nar_hash, "nar_size": item["narSize"],
                     "references": references, "narinfo": narinfo})
        total += item["narSize"]
    if total > 32 * 1024 ** 3 or len(rows) * 2 + 3 > 65536:
        raise ValueError("system closure exceeds appliance limits")
    metadata.pop("manage_origin")
    metadata["schema"] = "cybex.james.system-closure.v1"
    metadata["store_paths"] = rows
    metadata["total_nar_bytes"] = total
    (output / "manifest.json").write_bytes(canonical(metadata))


if __name__ == "__main__":
    main()
