#!/usr/bin/env python3
"""Preserve the secure source verifier's ordinary-file ownership and link contract."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


def copy_source(source, destination):
    source, destination = Path(source), Path(destination)
    destination.mkdir(mode=0o755, parents=True, exist_ok=True)
    meta = destination.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) != 0o755:
        raise ValueError('unsafe source destination directory')
    for metadata in sorted(source.glob('*.json')):
        revision = metadata.stem
        if not re.fullmatch('[0-9a-f]{40}', revision):
            raise ValueError('invalid source revision')
        raw = metadata.read_bytes()
        value = json.loads(raw)
        archive = source / (revision + '.tar')
        with archive.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if (value['schema'] != 'cybex.james.manage-source.v1' or value['revision'] != revision
                or value['filename'] != archive.name or value['sha256'] != digest
                or value['size_bytes'] != archive.stat().st_size or not 0 < value['size_bytes'] <= 256 * 1024 ** 2):
            raise ValueError('source archive identity mismatch')
        for original in (archive, metadata):
            target = destination / original.name
            if target.exists() or target.is_symlink():
                info = target.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o444:
                    raise ValueError('unsafe existing source projection')
                with target.open('rb') as existing, original.open('rb') as expected:
                    if hashlib.file_digest(existing, 'sha256').digest() != hashlib.file_digest(expected, 'sha256').digest():
                        raise ValueError('conflicting immutable source revision')
                continue
            fd, name = tempfile.mkstemp(dir=destination, prefix='.source-')
            try:
                with os.fdopen(fd, 'wb') as output, original.open('rb') as input_file:
                    while block := input_file.read(1024 * 1024):
                        output.write(block)
                    output.flush()
                    os.fchmod(output.fileno(), 0o444)
                    os.fchown(output.fileno(), 0, 0)
                    os.fsync(output.fileno())
                os.replace(name, target)
                directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                Path(name).unlink(missing_ok=True)


if __name__ == '__main__':
    copy_source(*sys.argv[1:])
