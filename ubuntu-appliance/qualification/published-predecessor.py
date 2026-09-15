#!/usr/bin/env python3
"""Admit historical media only through authenticated immutable local publication."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def match_manifest(identity, manifest):
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != identity['release_manifest_sha256']:
        raise ValueError('Historical media must use the exact authenticated predecessor manifest')
    value = json.loads(manifest.read_text())
    if (value['version'] != identity['release_id'] or
            value['appliance_release_v1']['ubuntu_snapshot_id'] != identity['ubuntu_snapshot_id']):
        raise ValueError('Historical release/snapshot differs from authenticated predecessor')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    value = json.loads(args.inputs.read_text())
    fields = {'qualified_identity', 'artifact_root', 'prepared_release', 'staging_state_dir',
              'served_prefix', 'trusted_public_key'}
    if set(value) != fields or not all(isinstance(v, str) and v for v in value.values()):
        raise ValueError('Invalid historical predecessor inputs')
    root = Path(__file__).resolve().parents[2]
    command = ['python3', '-B', str(Path(__file__).with_name('legacy-bridge-gate.py')),
               'recheck-local-predecessor']
    for key, item in value.items():
        command += ['--' + key.replace('_', '-'), item]
    command += ['--release-verifier', str(root / 'tools/james-release.py')]
    subprocess.run(command, check=True)
    identity = json.loads(Path(value['qualified_identity']).read_text())
    match_manifest(identity, args.manifest)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit('Historical predecessor admission failed: ' + str(error)) from None
