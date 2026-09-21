#!/usr/bin/env python3
"""Deterministic, secret-free build metadata; executable within a Nix sandbox."""
import hashlib
import json
from pathlib import Path
import sys


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def digest(path, algorithm="sha256"):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def migrations(directory):
    rows = []
    for path in sorted(Path(directory).glob("*.sql")):
        rows.append({"filename": path.name, "version": int(path.name.split("_", 1)[0]),
                     "sha256": digest(path), "sqlx_checksum": digest(path, "sha384")})
    if not rows or len({r["version"] for r in rows}) != len(rows):
        raise ValueError("invalid or empty SQLx migration inventory")
    return {"schema": "cybex.james.sqlite-migrations.v1", "migrations": rows}


def main():
    mode, *args = sys.argv[1:]
    if mode == "migrations":
        directory, output = args
        result = migrations(directory)
    elif mode == "source":
        source, revision, output = args
        result = {"schema": "cybex.james.manage-source.v1", "revision": revision,
                  "filename": revision + ".tar", "sha256": digest(source),
                  "size_bytes": Path(source).stat().st_size}
    elif mode == "build":
        base, inventory, source, output = args
        result = json.loads(Path(base).read_text())
        result["sqlite_migrations_sha256"] = digest(inventory)
        result["manage_source"]["size_bytes"] = Path(source).stat().st_size
    else:
        raise ValueError("unknown metadata operation")
    Path(output).write_bytes(canonical(result))


if __name__ == "__main__":
    main()
