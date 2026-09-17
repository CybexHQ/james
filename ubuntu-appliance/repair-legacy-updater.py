#!/usr/bin/env python3
"""Repair the exact frozen updater's APT source-directory bug on existing James.

Default is inspection only. --apply requires root, the updater lock and an exact
known predecessor. It preserves signed-package verification, maintenance windows,
rollback, and every other byte of the installed updater. No update is started.
"""
import argparse
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

BEFORE = "efe7a184a4295d8988b152afab010f6a1012d68ad4e3279725db1c84142bcdd1"
AFTER = "413681546e086b1cf51d17d3497f9af6bad5884d118d5a4c2fec7333ff76f059"
UPDATER = Path("/usr/lib/cybex-james/cybex-james-appliance-update")
BACKUP = Path("/var/lib/cybex-james/control/maintenance-repairs/apt-sourceparts-v1")
LOCK = Path("/run/lock/cybex-james/appliance-update.lock")


class RepairError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise RepairError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def repaired_bytes(original):
    identity = digest(original)
    if identity == AFTER:
        return original
    require(identity == BEFORE, "Unrecognized updater; automatic repair refused")
    old_directory = b'  "$solver_root" "$solver_root/lists" "$solver_root/archives"\n'
    new_directory = (
        b'  "$solver_root" "$solver_root/lists" "$solver_root/archives" \\\n'
        b'  "$solver_root/sources.list.d"\n'
    )
    old_option = b"-o Dir::Etc::sourceparts=-\n"
    new_option = b"-o Dir::Etc::sourceparts=/run/cybex-update-apt/sources.list.d\n"
    require(original.count(old_directory) == original.count(old_option) == 1,
            "Unexpected repair anchors")
    updated = original.replace(old_directory, new_directory).replace(old_option, new_option)
    require(digest(updated) == AFTER, "Unexpected repaired updater identity")
    return updated


def check_directory(path):
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
            and metadata.st_mode & 0o022 == 0, "Unsafe repair directory")


def read_regular(path, *, executable=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and metadata.st_uid == os.geteuid() and metadata.st_mode & 0o022 == 0,
                "Unsafe repair file")
        if executable:
            require(stat.S_IMODE(metadata.st_mode) in (0o700, 0o750, 0o755), "Unexpected updater permissions")
        contents = stream.read(128 * 1024 + 1)
        require(len(contents) <= 128 * 1024, "Repair file is too large")
        return contents, metadata


def durable_new_file(path, contents):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def repair(updater, backup, *, apply=False):
    check_directory(updater.parent)
    original, metadata = read_regular(updater, executable=True)
    updated = repaired_bytes(original)
    receipt = {"schema": "cybex.james.updater-repair.v1", "before_sha256": digest(original),
               "after_sha256": digest(updated), "changed": False, "update_started": False}
    if not apply or original == updated:
        return receipt
    check_directory(backup.parent)
    backup.mkdir(mode=0o700, exist_ok=True)
    check_directory(backup)
    saved = backup / "updater.before"
    if saved.exists() or saved.is_symlink():
        require(read_regular(saved)[0] == original, "Existing backup differs; repair refused")
    else:
        durable_new_file(saved, original)
    sync_directory(backup)
    sync_directory(backup.parent)
    fd, name = tempfile.mkstemp(dir=updater.parent, prefix=".updater-repair-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(updated)
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            stream.flush()
            os.fsync(stream.fileno())
        current, current_metadata = read_regular(updater, executable=True)
        require(current == original and (current_metadata.st_dev, current_metadata.st_ino)
                == (metadata.st_dev, metadata.st_ino), "Updater changed concurrently")
        os.replace(name, updater)
        sync_directory(updater.parent)
        receipt["changed"] = True
        receipt_path = backup / "receipt.json"
        if not receipt_path.exists():
            durable_new_file(receipt_path, (json.dumps(receipt, sort_keys=True) + "\n").encode())
        sync_directory(backup)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--apply", action="store_true", help="apply this exact repair without starting an update")
    args = parser.parse_args()
    require(os.geteuid() == 0, "Run as root on the James appliance")
    if not args.apply:
        print(json.dumps(repair(UPDATER, BACKUP), sort_keys=True))
        return
    check_directory(LOCK.parent)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o640)
    try:
        metadata = os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                and metadata.st_nlink == 1 and metadata.st_mode & 0o022 == 0,
                "Unsafe updater lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fchown(fd, 0, grp.getgrnam("cybex-james").gr_gid)
        os.fchmod(fd, 0o640)
        if args.apply:
            check_directory(BACKUP.parent.parent)
            BACKUP.parent.mkdir(mode=0o700, exist_ok=True)
        print(json.dumps(repair(UPDATER, BACKUP, apply=args.apply), sort_keys=True))
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except (RepairError, OSError) as error:
        print(str(error) if isinstance(error, RepairError) else "Repair file or lock unavailable", file=__import__("sys").stderr)
        raise SystemExit(2)
