"""Trust this Nest's own cache signing key for its self-substituter.

The Nest daemon (user tiaris-nest) generates its cache key pair and signs
every closure it exports to /var/cache/tiaris-nest/www/cache. Nix's daemon
lists that export first, so a rebuild after garbage collection takes paths
the Nest already holds from its own disk instead of the internet. Only this
root unit writes the nix.conf include, and only one validated
`extra-trusted-public-keys` line: the service user can change which key is
trusted, never any other Nix option.
"""
import base64
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from appliance_state import UID, read, sync_dir

# The appliance configuration pins the key to the agent state directory; the
# Ubuntu-to-NixOS bridge kept it one level up (src/config.rs).
PUBLIC_KEYS = (
    Path('/var/lib/tiaris-nest/state/agent/cache-public.pem'),
    Path('/var/lib/tiaris-nest/state/cache-public.pem'),
)
INCLUDE = Path('/etc/tiaris-nest/nix-self-cache.conf')
KEY = re.compile(r'tiaris-nest-cache:[A-Za-z0-9+/]{43}=')


def public_key(paths=PUBLIC_KEYS, owner=UID):
    """The Nest's own cache public key, or None before it exists."""
    for path in paths:
        try:
            body = read(path, maximum=512, owner=owner)
        except FileNotFoundError:
            continue
        text = body.decode('ascii').strip()
        if not KEY.fullmatch(text) or len(base64.b64decode(text.split(':', 1)[1], validate=True)) != 32:
            raise ValueError('invalid Nest cache public key: ' + str(path))
        return text
    return None


def render(key):
    return '' if key is None else 'extra-trusted-public-keys = ' + key + '\n'


def apply(include=INCLUDE, paths=PUBLIC_KEYS, owner=UID, restart=None):
    """Write the include; restart the Nix daemon when it changed. Any invalid
    key leaves no trust at all: the self-substituter is then simply unused."""
    try:
        content = render(public_key(paths, owner))
        valid = True
    except (OSError, ValueError, UnicodeDecodeError):
        content, valid = '', False
    try:
        info = os.lstat(include)
        current = include.read_text() if stat.S_ISREG(info.st_mode) else None
    except FileNotFoundError:
        current = None
    if current != content:
        fd, name = tempfile.mkstemp(dir=include.parent, prefix='.' + include.name + '.')
        try:
            with os.fdopen(fd, 'w') as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, include)
            sync_dir(include.parent)
        finally:
            Path(name).unlink(missing_ok=True)
        # Running builds keep their connection; new ones read the new trust.
        (restart or (lambda: subprocess.run(['systemctl', 'try-restart', 'nix-daemon.service'], check=True, timeout=60)))()
    if not valid:
        raise ValueError('Nest cache public key is invalid; its self-substituter stays untrusted')
    return current != content
