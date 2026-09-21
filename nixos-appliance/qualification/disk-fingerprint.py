#!/usr/bin/env python3
"""Fingerprint all allocated raw-disk extents, including writes past its header."""
import argparse
import errno
import hashlib
import os
from pathlib import Path
import stat
import struct


def fingerprint(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Expected an ordinary owned raw VM disk')
        result = hashlib.sha256(struct.pack('<Q', info.st_size))
        offset = 0
        while offset < info.st_size:
            try:
                start = os.lseek(fd, offset, os.SEEK_DATA)
            except OSError as error:
                if error.errno == errno.ENXIO:
                    break
                raise
            end = min(os.lseek(fd, start, os.SEEK_HOLE), info.st_size)
            result.update(struct.pack('<QQ', start, end))
            os.lseek(fd, start, os.SEEK_SET)
            remaining = end - start
            while remaining:
                body = os.read(fd, min(1024**2, remaining))
                if not body:
                    raise ValueError('VM disk changed during fingerprinting')
                result.update(body)
                remaining -= len(body)
            offset = end
        after = os.fstat(fd)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (info.st_size, info.st_mtime_ns, info.st_ctime_ns):
            raise ValueError('VM disk changed during fingerprinting')
        return result.hexdigest()
    finally:
        os.close(fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('disk', type=Path)
    print(fingerprint(parser.parse_args().disk))
