"""Conservative singleton admission, not enforcement of daemon descendants."""
from contextlib import contextmanager
import ipaddress
import os
import re
from pathlib import Path
import shutil

import release_speed_io as io

HOST_LOCK = Path('/run/lock/cybex-james-production-qualification.lock')
GIB = 1024**3


def profile(path, phase):
    value = io.load(path)
    fields = {'schema', 'memory_gib', 'disk_gib', 'cpus', 'subnet', 'lease_root', 'disk_root'}
    if set(value) != fields or value['schema'] != 'cybex.james.serial-resources.v1':
        raise ValueError('Explicit resource profile required')
    minimum = (28, 240, 8) if phase == 'warm' else (38, 320, 12)
    for name, floor, ceiling in zip(('memory_gib', 'disk_gib', 'cpus'), minimum, (96, 4096, 24)):
        if type(value[name]) is not int or not floor <= value[name] <= ceiling:
            raise ValueError('Resource profile below conservative minimum or above policy')
    network = ipaddress.ip_interface(value['subnet'])
    if (network.version != 4 or network.network.prefixlen != 24
            or str(network) != value['subnet'] or network.ip in {network.network.network_address, network.network.broadcast_address}):
        raise ValueError('Explicit bridge interface /24 required')
    for name in ('lease_root', 'disk_root'):
        if not Path(value[name]).is_absolute():
            raise ValueError('Absolute resource paths required')
        io.directory(value[name])
    return value


def availability(path):
    values = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    return {'memory': int(values['MemAvailable'].split()[0]) * 1024,
            'disk': shutil.disk_usage(path).free, 'cpus': len(os.sched_getaffinity(0)),
            'load': os.getloadavg()[0]}


def check(value, available):
    if (available['memory'] < (value['memory_gib'] + 16) * GIB
            or available['disk'] < (value['disk_gib'] + 100) * GIB
            or available['cpus'] < value['cpus'] + 2
            or available['load'] + value['cpus'] > available['cpus'] - 2):
        raise ValueError('Insufficient live headroom')


@contextmanager
def admission(value, identity, state_root):
    if (set(identity) != {'run_sha256', 'source_sha256', 'manifest_sha256', 'profile_sha256'}
            or any(not re.fullmatch('[0-9a-f]{64}', v) for v in identity.values())):
        raise ValueError('Exact run identity required')
    # Preserve historical host exclusion. Current runner still owns its stricter
    # singleton network check; this is not a multi-scope capability or Docker cap.
    with io.lock(HOST_LOCK, blocking=False):
        root = io.directory(value['lease_root'])
        with io.lock(root / 'serial.lock', blocking=False):
            marker = root / 'active.json'
            if marker.exists() or marker.is_symlink():
                raise ValueError('Unresolved prior ownership requires operator cleanup proof')
            # The runner allocates every phase's fixture beneath state_root.
            # disk_root remains a validated profile field for compatibility,
            # but its filesystem's free space cannot authorize these writes.
            check(value, availability(io.directory(state_root)))
            io.write(marker, io.canonical({'schema': 'cybex.james.serial-lease.v1',
                'identity': identity, 'pid': os.getpid(), 'process_start': Path('/proc/self/stat').read_text().split(') ', 1)[1].split()[19]}))
            io.sync(root)
            try:
                yield
            except BaseException:
                # Never turn missing cleanup attestation into a new admission.
                raise
            else:
                marker.unlink()
                io.sync(root)
