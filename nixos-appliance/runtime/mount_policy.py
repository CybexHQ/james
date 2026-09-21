"""Exact mount checks for protected appliance paths."""
import json
from pathlib import Path
import stat
import subprocess


def _mount(path):
    path = Path(path)
    result = subprocess.run(
        ['findmnt', '--json', '--mountpoint', str(path), '--output', 'TARGET,OPTIONS'],
        check=False, text=True, capture_output=True, timeout=10)
    if result.returncode != 0 or len(result.stdout) > 64 * 1024:
        raise ValueError('missing protected appliance mount: ' + str(path))
    try:
        rows = json.loads(result.stdout)['filesystems']
    except (KeyError, TypeError, ValueError):
        raise ValueError('invalid protected appliance mount metadata: ' + str(path)) from None
    if len(rows) != 1 or rows[0].get('target') != str(path):
        raise ValueError('ambiguous protected appliance mount: ' + str(path))
    options = rows[0].get('options')
    if not isinstance(options, str):
        raise ValueError('invalid protected appliance mount options: ' + str(path))
    return set(options.split(','))


def _directory(path):
    info = Path(path).lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('protected appliance mount is not a directory: ' + str(path))
    return info


def require_mount(path, required=(), forbidden=()):
    path = Path(path)
    _directory(path)
    options = _mount(path)
    if not set(required) <= options or set(forbidden) & options:
        raise ValueError('unsafe protected appliance mount options: ' + str(path))


def require_bind_mount(path, source, required=(), forbidden=(), root_searchable=False):
    path, source = Path(path), Path(source)
    if not path.is_absolute() or not source.is_absolute():
        raise ValueError('protected appliance bind mount paths must be absolute')
    require_mount(path, required=required, forbidden=forbidden)
    mounted, backing = _directory(path), _directory(source)
    if (mounted.st_dev, mounted.st_ino) != (backing.st_dev, backing.st_ino):
        raise ValueError('protected appliance bind mount has the wrong source: ' + str(path))
    if root_searchable:
        current = source
        while True:
            info = _directory(current)
            if (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022
                    or not info.st_mode & stat.S_IXOTH):
                raise ValueError('unsafe installed Nix path permissions: ' + str(current))
            if current == Path('/'):
                break
            current = current.parent
