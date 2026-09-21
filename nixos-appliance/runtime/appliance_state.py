"""Privileged state primitives shared by first boot and generation supervision."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

STATE = Path('/var/lib/cybex-james/state')
CONTROL = Path('/var/lib/cybex-james/control')
STATUS = Path('/var/lib/cybex-james/status')
INBOX = STATE / 'inbox'
PROFILE = Path('/nix/var/nix/profiles/system')
UID = GID = 985


def run(*arguments, **kwargs):
    return subprocess.run([str(a) for a in arguments], check=True, text=True, capture_output=True, timeout=kwargs.pop('timeout', 60), **kwargs).stdout.strip()


def read(path, maximum=1024 * 1024, owner=0):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner or info.st_mode & 0o022 or info.st_size > maximum:
            raise ValueError('unsafe appliance state file: ' + str(path))
        body = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(body) > maximum or len(body) != info.st_size or (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('appliance state changed during read')
    return body


def load(path, **kwargs):
    return json.loads(read(path, **kwargs))


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n').encode()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write(path, body, mode=0o640, owner=0, group=GID):
    path = Path(path)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name + '.')
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), owner, group)
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        sync_dir(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


def save(path, value):
    write(path, canonical(value))


def remove(path):
    path.unlink(missing_ok=True)
    sync_dir(path.parent)


def directory(path, mode, uid=0, gid=GID):
    path = Path(path)
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid):
        raise ValueError('unsafe state directory')
    os.chown(path, uid, gid, follow_symlinks=False)
    os.chmod(path, mode, follow_symlinks=False)


@contextlib.contextmanager
def maintenance_lock():
    path = Path('/run/lock/cybex-james/maintenance.lock')
    fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != GID or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o660:
            raise ValueError('unsafe maintenance lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def generation_for(toplevel):
    matches = []
    for link in PROFILE.parent.glob('system-*-link'):
        match = re.fullmatch('system-([1-9][0-9]*)-link', link.name)
        if match and link.is_symlink() and str(link.resolve()) == toplevel:
            matches.append(int(match.group(1)))
    if not matches:
        raise ValueError('booted system has no profile generation')
    return str(max(matches))


def current():
    toplevel = str(Path('/run/current-system').resolve(strict=True))
    if not re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+', toplevel):
        raise ValueError('invalid booted system identity')
    entries = json.loads(run('bootctl', '--json=short', 'list'))
    selected = [entry for entry in entries if entry.get('isSelected') is True]
    if len(selected) != 1:
        raise ValueError('firmware did not report one selected boot entry')
    match = re.fullmatch(r'nixos-generation-([1-9][0-9]*)\.conf', selected[0].get('id', ''))
    if not match:
        raise ValueError('booted loader entry is not an appliance generation')
    generation = match.group(1)
    if str((PROFILE.parent / ('system-' + generation + '-link')).resolve(strict=True)) != toplevel:
        raise ValueError('selected loader entry differs from booted system')
    return {'system_generation': generation, 'system_toplevel': toplevel,
            'loader_entry': 'nixos-generation-' + generation + '.conf'}


def set_default(entry):
    run('bootctl', 'set-default', entry)
    entries = json.loads(run('bootctl', '--json=short', 'list'))
    if not any(item.get('id') == entry and item.get('isDefault') is True for item in entries):
        raise RuntimeError('firmware default did not select known entry')


def emit_status(receipt, status, stage, reason='', resulting=''):
    import datetime
    value = {key: receipt[key] for key in ('attempt_id', 'target_release', 'source_revision', 'system_closure_sha256', 'system_toplevel') if key in receipt}
    value.update(status=status, stage=stage, rollback_reason=reason, progress_percent=100 if status in ('succeeded', 'failed', 'rolled_back') else 50,
                 reported_at=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
    for key, generation in (('candidate_system_generation', receipt.get('candidate_generation')), ('resulting_system_generation', resulting)):
        if generation:
            if not re.fullmatch('[1-9][0-9]*', generation):
                raise ValueError('invalid status generation')
            value[key] = generation
    save(STATUS / 'appliance-update-status.json', value)
