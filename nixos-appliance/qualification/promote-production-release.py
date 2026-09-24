#!/usr/bin/env python3
"""Promote an immutable prerelease only after authenticated cold acceptance."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

import release_acceptance as acceptance
import release_predecessor as predecessor

FILES = {'cybex-james-published-cold-qualification.json',
         'cybex-james-published-workstation-qualification.json',
         'cybex-james-public-closure-qualification.json'}


def canonical_artifact_digest(value):
    # upload-artifact outputs bare hex; GitHub's REST artifact metadata uses
    # sha256:hex. Normalize only these two exact encodings of the same digest.
    if not isinstance(value, str) or not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', value):
        raise ValueError('Invalid cold artifact SHA-256 digest')
    return 'sha256:' + value.removeprefix('sha256:')


def artifact_evidence(body, metadata, expected_digest, run, source):
    expected_digest = canonical_artifact_digest(expected_digest)
    if (metadata.get('expired') is not False
            or metadata.get('workflow_run', {}).get('id') != run
            or metadata.get('workflow_run', {}).get('head_sha') != source
            or metadata.get('name') != f'cybex-james-published-cold-{run}'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest)
            or metadata.get('digest') != expected_digest
            or 'sha256:' + hashlib.sha256(body).hexdigest() != expected_digest):
        raise ValueError('Cold acceptance artifact provenance or digest changed')
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        if len(archive.namelist()) != len(FILES) or set(archive.namelist()) != FILES:
            raise ValueError('Cold acceptance archive inventory changed')
        if any(i.file_size > 1024 * 1024 for i in archive.infolist()):
            raise ValueError('Cold acceptance exceeded its evidence bound')
        return {name: json.loads(archive.read(name)) for name in FILES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-only', action='store_true', help='Validate the exact candidate without promoting it')
    parser.add_argument('--repository', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--run', type=int, required=True)
    parser.add_argument('--artifact-id', type=int, required=True)
    parser.add_argument('--artifact-digest', required=True)
    parser.add_argument('--candidate-id', type=int, required=True)
    parser.add_argument('--candidate-digest', required=True)
    parser.add_argument('--trusted-public-key', required=True)
    args = parser.parse_args()
    args.artifact_digest = canonical_artifact_digest(args.artifact_digest)
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository)
            or not re.fullmatch(r'v[0-9A-Za-z.+-]+', args.tag)
            or not re.fullmatch(r'[0-9a-f]{40}', args.source)):
        raise ValueError('Invalid release identity')

    def api(path):
        return predecessor.github(args.repository, path)

    workflow = api(f'actions/runs/{args.run}')
    if (workflow['head_sha'] != args.source or workflow['head_branch'] != args.tag
            or workflow['event'] != 'push' or workflow['path'] != '.github/workflows/release.yml'
            or api('commits/' + args.tag)['sha'] != args.source):
        raise ValueError('Acceptance must belong to the exact unchanged tagged workflow')
    jobs = api(f'actions/runs/{args.run}/jobs?per_page=100')['jobs']
    cold_jobs = [j for j in jobs if j['name'] == 'Verify published NixOS release in an isolated fixture']
    if len(cold_jobs) != 1 or cold_jobs[0]['conclusion'] != 'success':
        raise ValueError('Cold qualification job has not passed')
    metadata = api(f'actions/artifacts/{args.artifact_id}')
    if metadata['size_in_bytes'] > 2 * 1024 * 1024:
        raise ValueError('Cold artifact is not bounded public evidence')
    archive = subprocess.check_output(['gh', 'api',
        f'repos/{args.repository}/actions/artifacts/{args.artifact_id}/zip'])
    receipts = artifact_evidence(archive, metadata, args.artifact_digest, args.run, args.source)
    staged = api('releases/tags/' + args.tag)
    owner = f'Cybex-Release-Workflow: https://github.com/{args.repository}/actions/runs/{args.run}'
    markers = [owner, f'Cybex-Candidate-Artifact-ID: {args.candidate_id}',
               f'Cybex-Candidate-Artifact-SHA256: {args.candidate_digest}']
    if (staged.get('immutable') is not True or staged['draft']
            or staged['target_commitish'] != args.source
            or any(marker not in (staged.get('body') or '').splitlines() for marker in markers)):
        raise ValueError('Immutable staged release does not belong to this candidate')
    base = f'https://github.com/{args.repository}/releases/download/{args.tag}/'
    with tempfile.TemporaryDirectory(prefix='james-stable-promotion-') as temporary:
        directory = Path(temporary)
        names = [predecessor.MANIFEST, predecessor.COMPATIBILITY]
        if any(a['name'] == 'cybex-james-build-predecessor.json' for a in staged['assets']):
            names.append('cybex-james-build-predecessor.json')
        for name in names:
            matches = [a for a in staged['assets'] if a['name'] == name]
            if len(matches) != 1 or matches[0]['browser_download_url'] != base + name:
                raise ValueError('Staged signed asset identity changed')
            asset = matches[0]
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', asset.get('digest') or ''):
                raise ValueError('Staged asset lacks its immutable digest')
            predecessor.fetch(base + name, directory / name, asset['digest'][7:],
                              asset['size'], maximum=1024 * 1024)
        manifest = predecessor.verify_pair(directory, args.trusted_public_key, base + predecessor.MANIFEST)
        if manifest['version'] != args.tag[1:]:
            raise ValueError('Staged manifest does not bind its tag')
        if manifest.get('installer_iso_template_v3', {}).get('manage_origin') != 'https://manage.cybex.net':
            raise ValueError('Development qualification artifacts cannot be promoted as production releases')
        cold = receipts['cybex-james-published-cold-qualification.json']
        acceptance.validate_lifecycle(manifest, predecessor.sha(directory / predecessor.MANIFEST),
                                      cold, args.source, 'cold')
        acceptance.validate_public_closure(manifest, predecessor.sha(directory / predecessor.MANIFEST),
                                           receipts['cybex-james-public-closure-qualification.json'], args.source)
        acceptance.validate_workstation(manifest, cold,
            receipts['cybex-james-published-workstation-qualification.json'])
        # Repeat predecessor admission under the same publication concurrency
        # lock: another completed release must not reverse the lineage while
        # this candidate spends time in real cold/workstation qualification.
        current = predecessor.resolve(args.repository, manifest['version'], args.trusted_public_key,
            directory / 'predecessor', predecessor.ROOT / 'release/recovery-adoption.json')
        receipt = directory / 'cybex-james-build-predecessor.json'
        expected = predecessor.checked_json(receipt)[0] if receipt.exists() else None
        if current != expected:
            raise ValueError('Predecessor changed while the prerelease was qualifying')
        passed = ['Cybex-Cold-Qualification: passed', f'Cybex-Cold-Artifact-ID: {args.artifact_id}',
                  f'Cybex-Cold-Artifact-SHA256: {args.artifact_digest}']
        body = staged.get('body') or ''
        if not staged['prerelease']:
            if all(marker in body.splitlines() for marker in passed):
                print('Exact cold-qualified release is already stable')
                return
            raise ValueError('Existing stable release lacks this exact acceptance provenance')
        if body.splitlines().count('Cybex-Cold-Qualification: required') != 1:
            raise ValueError('Staged release lacks its pending cold-qualification marker')
        if args.verify_only:
            print('Exact immutable candidate passed cold qualification; production approval is still required')
            return
        notes = directory / 'notes.md'
        notes.write_text(body.replace('Cybex-Cold-Qualification: required', '\n'.join(passed)) + '\n')
        subprocess.run(['gh', 'release', 'edit', args.tag, '--repo', args.repository,
                        '--prerelease=false', '--latest', '--notes-file', str(notes)], check=True)
    promoted = api('releases/tags/' + args.tag)
    inventory = lambda release: sorted((a['id'], a['name'], a['digest'], a['size']) for a in release['assets'])
    if (promoted['id'] != staged['id'] or not promoted.get('immutable') or promoted['draft']
            or promoted['prerelease'] or inventory(promoted) != inventory(staged)
            or api('releases/latest')['id'] != promoted['id']):
        raise ValueError('Stable promotion did not preserve immutable release identity')
    print('Immutable release promoted after exact cold James and workstation acceptance')


if __name__ == '__main__':
    main()
