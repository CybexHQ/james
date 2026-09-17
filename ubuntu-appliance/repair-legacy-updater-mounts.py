#!/usr/bin/env python3
"""Repair the exact APT-isolated predecessor's candidate chroot mount layout.

Inspection only unless --apply. Retains the original under a separate repair
backup, uses the updater lock, and never starts an update or changes its window.
"""
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('base_updater_repair', Path(__file__).with_name('repair-legacy-updater.py'))
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)
BEFORE = base.AFTER
AFTER = '98b3c6a5ebb85b91f289276b441a6472743edc4b4dd0c3ccecd79529fcfc688f'
CHANGES = [
    (b'      "$candidate_path/dev"\n', b'      "$candidate_path/dev/pts" \\\n+      "$candidate_path/dev" \\\n+      "$candidate_path"\n'),
    (b'candidate_created=true\n', b'candidate_created=true\n'
     b'mount -t btrfs -o "subvol=/.cybex-root-generations/$candidate" "UUID=$root_uuid" "$candidate_path"\n'),
    (b'mount --bind /dev "$candidate_path/dev"\n', b'mount --bind /dev "$candidate_path/dev"\n'
     b'mount --bind /dev/pts "$candidate_path/dev/pts"\n'),
]

def repaired_bytes(original):
    if base.digest(original) == AFTER:
        return original
    base.require(base.digest(original) == BEFORE, 'Unknown updater for candidate-mount repair')
    updated = original
    for old, new in CHANGES:
        base.require(updated.count(old) == 1, 'Unexpected candidate-mount repair anchor')
        updated = updated.replace(old, new, 1)
    base.require(base.digest(updated) == AFTER, 'Unexpected candidate-mount repair result')
    return updated

if __name__ == '__main__':
    base.repaired_bytes = repaired_bytes
    base.BACKUP = Path('/var/lib/cybex-james/control/maintenance-repairs/candidate-mount-v1')
    base.main()
