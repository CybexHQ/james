#!/usr/bin/env python3
"""Pin a coordinated candidate; its tag builds a prerelease, never auto-promotes.

Production tags use a stable X.Y.Z Nest version. Development-signed candidates use
X.Y.Z-dev.N on a release/dev-nest-* branch, which is never tagged here.
"""
import argparse
import json
from pathlib import Path
import re
import tomllib

STABLE = r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
DEVELOPMENT = STABLE + r'-dev\.[1-9][0-9]*'


def version_core(value):
    match = re.fullmatch(STABLE + r'(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?'
                         r'(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?', value)
    if not match:
        raise ValueError('The Nest source version is not a semantic version')
    return tuple(map(int, match.groups()))


def precedence(value):
    """SemVer precedence key; build metadata is ignored."""
    core = version_core(value)
    prerelease = value.split('+', 1)[0].partition('-')[2]
    if not prerelease:
        return core, (1,)
    return core, (0, tuple((0, int(part)) if part.isdigit() else (1, part)
                           for part in prerelease.split('.')))


def validate(root):
    marker = root / 'release/coordinated.json'
    if not marker.exists():
        return False
    value = json.loads(marker.read_text())
    pin = json.loads((root / 'release/workstation-netboot-source.json').read_text())
    if (value.get('schema') != 'tiaris.coordinated-release.v2'
            or value.get('appliance_family') != 'nixos'
            or set(value) != {'schema', 'appliance_family', 'manage_revision'}
            or value.get('manage_revision') != pin['revision']
            # main's copy carries an `informational` note; only `pin` output builds.
            or set(pin) != {'repository', 'revision', 'runtime_version'}
            or pin['repository'] != 'CybexHQ/development'
            or not re.fullmatch('[0-9a-f]{40}', pin['revision'])):
        raise ValueError('Invalid coordinated release source; automatic promotion is forbidden')
    return True


def pin(root, revision, runtime, version):
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('An immutable development revision is required')
    if not re.fullmatch(STABLE, runtime):
        raise ValueError('A stable workstation runtime version is required')
    if not (re.fullmatch(STABLE, version) or re.fullmatch(DEVELOPMENT, version)):
        raise ValueError('A stable X.Y.Z or development X.Y.Z-dev.N Nest version is required')
    manifest = root / 'Cargo.toml'
    old = tomllib.loads(manifest.read_text())['package']['version']
    if precedence(version) <= precedence(old):
        raise ValueError('The candidate must advance the Nest source version')
    manifest.write_text(manifest.read_text().replace(f'version = "{old}"', f'version = "{version}"', 1))
    lock = root / 'Cargo.lock'
    before = f'name = "tiaris-nest"\nversion = "{old}"'
    if lock.read_text().count(before) != 1:
        raise ValueError('The Nest lockfile package identity is ambiguous')
    lock.write_text(lock.read_text().replace(before, f'name = "tiaris-nest"\nversion = "{version}"'))
    (root / 'release/workstation-netboot-source.json').write_text(json.dumps({
        'repository': 'CybexHQ/development', 'revision': revision, 'runtime_version': runtime,
    }, indent=2) + '\n')
    (root / 'release/coordinated.json').write_text(json.dumps({
        'schema': 'tiaris.coordinated-release.v2', 'manage_revision': revision,
        'appliance_family': 'nixos',
    }, indent=2) + '\n')
    validate(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['pin', 'validate'])
    parser.add_argument('--revision')
    parser.add_argument('--runtime')
    parser.add_argument('--version')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.action == 'pin':
        pin(root, args.revision or '', args.runtime or '', args.version or '')
    else:
        print('coordinated=' + str(validate(root)).lower())


if __name__ == '__main__':
    main()
