"""Private, no-follow files for transport snapshots and diagnostic output."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(body):
    return hashlib.sha256(body).hexdigest()


def directory(path, private=True):
    path = Path(os.path.abspath(path))
    current = Path('/')
    protected = False
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}
                or (info.st_mode & 0o022 and not protected and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
            raise ValueError('Unsafe directory')
        protected = protected or (info.st_uid == os.geteuid() and not info.st_mode & 0o077)
    if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('Private directory required')
    return path


@contextmanager
def opened(path):
    directory(Path(path).parent, private=False)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o022):
            raise ValueError('Unsafe input file')
        yield stream
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Input changed')


def read(path, limit=1024**2):
    with opened(path) as stream:
        body = stream.read(limit + 1)
    if len(body) > limit:
        raise ValueError('Oversized input')
    return body


def load(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate JSON member')
            value[key] = item
        return value
    return json.loads(read(path), object_pairs_hook=unique)


def write(path, body, mode=0o600):
    directory(Path(path).parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def copy(source, target, expected=None, size=None):
    directory(Path(target).parent)
    count, hasher = 0, hashlib.sha256()
    with opened(source) as incoming:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'wb') as outgoing:
            while chunk := incoming.read(1024**2):
                count += len(chunk)
                if size is not None and count > size:
                    raise ValueError('Blob size changed')
                hasher.update(chunk)
                outgoing.write(chunk)
            outgoing.flush()
            os.fchmod(outgoing.fileno(), 0o400)
            os.fsync(outgoing.fileno())
    if (size is not None and count != size) or (expected is not None and hasher.hexdigest() != expected):
        raise ValueError('Blob identity changed')


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def lock(path, blocking=True):
    directory(Path(path).parent, private=False)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise ValueError('Unsafe lock')
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield
    finally:
        os.close(fd)


def publish(source, destination):
    """Linux atomic no-replace publication, including concurrent output writers."""
    import ctypes
    library = ctypes.CDLL(None, use_errno=True)
    result = library.renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    if result != 0:
        raise OSError(ctypes.get_errno(), 'Atomic publication refused')


@contextmanager
def append(path):
    directory(Path(path).parent)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'ab') as stream:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('Unsafe private log')
        yield stream
