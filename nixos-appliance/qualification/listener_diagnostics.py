"""Bounded, credential-redacted evidence for owned qualification listeners."""
import json
import os
from pathlib import Path
import re
import threading
import time

LIMIT = 8192
LINE_LIMIT = 4096


def redact(text):
    text = re.sub(r'-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|$)',
                  '[PEM data redacted]', text, flags=re.DOTALL)
    text = re.sub(r'(?i)\b(Bearer|Basic)\s+[^\s\"\']+', r'\1 [redacted]', text)
    text = re.sub(r'(?i)(https?://)[^/\s@]+@', r'\1[redacted]@', text)
    text = re.sub(r'(?i)([?&][^=\s]+)=([^&\s]+)', r'\1=[redacted]', text)
    text = re.sub(
        r'(?i)((?:[\w-]*(?:token|secret|password|credential|authorization|cookie|challenge)[\w-]*)'
        r'[\"\']?\s*[:=]\s*)(?:\"[^\"]*\"|\'[^\']*\'|[^\s,;]+)',
        r'\1[redacted]', text)
    return ''.join(character for character in text if character in '\n\t' or ord(character) >= 32)


class Output:
    """Drain a pipe continuously so verbose children cannot block or exhaust memory."""
    def __init__(self, pipe):
        self.pipe = pipe
        self.tail = b''
        self.truncated = False
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _append(self, body):
        with self.lock:
            self.truncated |= len(self.tail) + len(body) > LIMIT
            self.tail = (self.tail + body)[-LIMIT:]

    def _read(self):
        private_key = False
        try:
            while line := self.pipe.readline(LINE_LIMIT + 1):
                if b'-----BEGIN ' in line:
                    private_key = True
                    self._append(b'[PEM data redacted]\n')
                if len(line) > LINE_LIMIT:
                    # Do not retain a partial secret whose key was in a discarded prefix.
                    while not line.endswith(b'\n'):
                        line = self.pipe.readline(LINE_LIMIT + 1)
                        if b'-----END ' in line:
                            private_key = False
                        if not line:
                            break
                    self.truncated = True
                    self._append(b'[oversized diagnostic line omitted]\n')
                    continue
                if private_key:
                    if b'-----END ' in line:
                        private_key = False
                    continue
                self._append(redact(line.decode('utf-8', 'replace')).encode())
        finally:
            self.pipe.close()

    def finish(self):
        self.thread.join(timeout=2)

    def snapshot(self):
        with self.lock:
            # A byte-bound tail can start inside a multibyte character.
            return {'output': self.tail.decode('utf-8', 'ignore'), 'truncated': self.truncated}


def save_failure(directory, phase, run, error, listeners):
    """Publish only sanitized listener evidence, never fixture config or credentials."""
    if phase not in {'update', 'rollback', 'fresh', 'cold'}:
        raise ValueError('invalid qualification diagnostic phase')
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}', run):
        raise ValueError('invalid qualification diagnostic run')
    parent = Path(directory)
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError('qualification evidence directory must be ordinary')
    # Self-hosted runners reuse their temp root. Never mix an earlier attempt's
    # failure with this run or overwrite retained evidence on an accidental retry.
    directory = parent / run
    directory.mkdir(mode=0o700)
    path = directory / f'tiaris-nest-{phase}-diagnostics.json'
    value = {'schema': 'tiaris.nest.qualification-diagnostics.v1', 'phase': phase,
             'run': run, 'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
             'error': redact(str(error))[-LIMIT:], 'listeners': listeners}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        # Qualification runs under sudo; the upload runner needs access even on failure.
        if os.geteuid() == 0 and 'SUDO_UID' in os.environ and 'SUDO_GID' in os.environ:
            uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
            os.fchown(stream.fileno(), uid, gid)
            os.chown(directory, uid, gid)
            os.chown(parent, uid, gid)
    return path
