"""Bounded progress observations; timings never substitute for acceptance evidence."""
from contextlib import contextmanager
import datetime
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
import time


class Timing:
    def __init__(self, directory, run, published_cold):
        if not re.fullmatch('[a-z0-9][a-z0-9-]{0,22}', run):
            raise ValueError('Timing requires a bounded qualification run identity')
        self.path = Path(directory) / 'tiaris-nest-qualification-timing.json'
        if self.path.exists() or self.path.is_symlink():
            raise ValueError('Qualification timing already exists; use a new attempt')
        self.document = {'schema': 'tiaris.nest.qualification-phase-timing.v1',
                         'run': run, 'publishedCold': bool(published_cold),
                         'parallelism': 1, 'stages': []}

    def save(self):
        try:
            self._save()
        except OSError:
            # Observability must never prevent fixture cleanup or interrupt
            # between resource creation and its owning teardown handler.
            self.document['persistenceFailures'] = self.document.get('persistenceFailures', 0) + 1
            print('Qualification timing could not be persisted; fixture cleanup remains mandatory',
                  file=sys.stderr, flush=True)

    def _save(self):
        # Only fixed stage names, status and clocks enter this export. Paths,
        # commands, credentials, origins and raw exception text stay private.
        body = (json.dumps(self.document, sort_keys=True, separators=(',', ':'),
                           allow_nan=False) + '\n').encode()
        if len(body) > 32768:
            raise ValueError('Qualification timing exceeded its bound')
        with tempfile.NamedTemporaryFile(prefix='.timing-', dir=self.path.parent,
                                         delete=False) as stream:
            temporary = Path(stream.name)
            try:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o644)
                os.replace(temporary, self.path)
                fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                temporary.unlink(missing_ok=True)

    @contextmanager
    def measure(self, phase, stage):
        if (phase not in {'run', 'inputs', 'update', 'rollback', 'fresh', 'cold'}
                or stage not in {'total', 'verify-candidate', 'verify-predecessor',
                                 'stage-inputs', 'scope', 'fixture', 'lifecycle',
                                 'transition', 'workstation', 'verify-owner', 'cleanup'}
                or len(self.document['stages']) >= 40):
            raise ValueError('Unknown or excessive qualification timing stage')
        start = time.monotonic()
        record = {'phase': phase, 'stage': stage, 'status': 'running',
                  'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        self.document['stages'].append(record)
        self.save()
        try:
            yield
        except BaseException as error:
            record['status'] = 'interrupted' if isinstance(error, (KeyboardInterrupt, SystemExit)) else 'failed'
            raise
        else:
            record['status'] = 'passed'
        finally:
            elapsed = time.monotonic() - start
            if not math.isfinite(elapsed) or elapsed < 0:
                record['elapsedSeconds'] = None
                record['clockStatus'] = 'invalid'
            else:
                record['elapsedSeconds'] = round(elapsed, 6)
            record['completedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.save()
