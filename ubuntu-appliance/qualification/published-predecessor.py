#!/usr/bin/env python3
"""Admit historical media only through authenticated immutable local publication."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import importlib.util

_spec = importlib.util.spec_from_file_location('release_predecessor', Path(__file__).with_name('release_predecessor.py'))
predecessor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(predecessor)


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
    if value.get('schema') == 'cybex.james.resolved-predecessor-fixture.v1':
        fields = {'schema', 'identity', 'directory', 'trusted_public_key', 'candidate_version', 'repository', 'authorization'}
        if set(value) != fields or not all(isinstance(v, str) and v for v in value.values()):
            raise ValueError('Invalid resolved predecessor fixture inputs')
        identity_path = Path(value['identity'])
        identity, body = predecessor.checked_json(identity_path)
        if body != predecessor.canonical(identity):
            raise ValueError('Predecessor identity is not canonical')
        directory = Path(value['directory'])
        if args.manifest.resolve() != (directory / predecessor.MANIFEST).resolve():
            raise ValueError('Historical fixture must use the authenticated manifest path')
        match_manifest(identity, args.manifest)
        if identity['schema'] == predecessor.IDENTITY_SCHEMA:
            anchor_path = Path(value['authorization'])
            anchor = predecessor.authorization(anchor_path, value['trusted_public_key'], value['candidate_version'], value['repository'])
            if (identity['authorization_sha256'] != predecessor.sha(anchor_path)
                    or identity['published'] != anchor['published']
                    or identity['release_manifest_sha256'] != anchor['recovery']['manifest_sha256']
                    or identity['release_compatibility_sha256'] != anchor['recovery']['compatibility_sha256']):
                raise ValueError('Historical fixture differs from the signed recovery adoption')
            manifest_url = anchor['recovery']['manifest_url']
        elif identity['schema'] == predecessor.gate.PREDECESSOR_SCHEMA:
            predecessor.gate.validate_predecessor_identity(identity)
            manifest_url = f"https://github.com/{value['repository']}/releases/download/{identity['tag_name']}/{predecessor.MANIFEST}"
            predecessor.gate.verify_published_predecessor_descriptors(
                compatibility_path=directory / predecessor.COMPATIBILITY, manifest_path=args.manifest,
                trusted_public_key=value['trusted_public_key'], release_verifier=predecessor.ROOT / 'tools/james-release.py',
                github_release_id=identity['github_release_id'], tag_name=identity['tag_name'])
        else:
            raise ValueError('Unsupported authenticated predecessor identity')
        manifest = predecessor.verify_pair(directory, value['trusted_public_key'], manifest_url)
        actual = predecessor.inspect_package(directory, manifest)
        if any(identity[k] != v for k, v in actual.items()):
            raise ValueError('Historical package/updater identity changed before installation')
        return
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
