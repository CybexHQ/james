#!/usr/bin/env python3
"""Promote an immutable prerelease after its exact public-closure acceptance.

Release policy fast-v1 (2026-11-02): a production Nest release needs the
release contracts, the Rust production gate, a reproducible signed build,
attestation, immutable publication, published-bytes verification and the
public closure qualified through the candidate downloader. Warm and cold VM
qualification are not on the release path; they run on demand from
`.github/workflows/nest-vm-qualification.yml` for the owner's nightly. The
release notes record that explicitly as `Tiaris-VM-Qualification: nightly`;
promotion never claims VM evidence it did not check.
"""
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

EVIDENCE = 'tiaris-nest-public-closure-qualification.json'
FILES = {EVIDENCE}
CLOSURE_JOB = 'Verify published closure through the candidate downloader'
POLICY = 'Tiaris-VM-Qualification: nightly'
PENDING = 'Tiaris-Public-Closure: required'


def canonical_artifact_digest(value):
    # upload-artifact outputs bare hex; GitHub's REST artifact metadata uses
    # sha256:hex. Normalize only these two exact encodings of the same digest.
    if not isinstance(value, str) or not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', value):
        raise ValueError('Invalid public closure artifact SHA-256 digest')
    return 'sha256:' + value.removeprefix('sha256:')


def artifact_evidence(body, metadata, expected_digest, run, source):
    expected_digest = canonical_artifact_digest(expected_digest)
    if (metadata.get('expired') is not False
            or metadata.get('workflow_run', {}).get('id') != run
            or metadata.get('workflow_run', {}).get('head_sha') != source
            or metadata.get('name') != f'tiaris-nest-public-closure-{run}'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest)
            or metadata.get('digest') != expected_digest
            or 'sha256:' + hashlib.sha256(body).hexdigest() != expected_digest):
        raise ValueError('Public closure artifact provenance or digest changed')
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        if len(archive.namelist()) != len(FILES) or set(archive.namelist()) != FILES:
            raise ValueError('Public closure archive inventory changed')
        if any(i.file_size > 1024 * 1024 for i in archive.infolist()):
            raise ValueError('Public closure evidence exceeded its bound')
        return {name: json.loads(archive.read(name)) for name in FILES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-only', action='store_true', help='Validate the exact candidate without promoting it')
    parser.add_argument('--repository', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--run', type=int, required=True)
    parser.add_argument('--artifact-id', type=int, required=True, help='Public closure evidence artifact')
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
    closure_jobs = [j for j in jobs if j['name'] == CLOSURE_JOB]
    if len(closure_jobs) != 1 or closure_jobs[0]['conclusion'] != 'success':
        raise ValueError('Public closure qualification job has not passed')
    metadata = api(f'actions/artifacts/{args.artifact_id}')
    if metadata['size_in_bytes'] > 2 * 1024 * 1024:
        raise ValueError('Public closure artifact is not bounded public evidence')
    archive = subprocess.check_output(['gh', 'api',
        f'repos/{args.repository}/actions/artifacts/{args.artifact_id}/zip'])
    receipts = artifact_evidence(archive, metadata, args.artifact_digest, args.run, args.source)
    staged = api('releases/tags/' + args.tag)
    owner = f'Tiaris-Release-Workflow: https://github.com/{args.repository}/actions/runs/{args.run}'
    markers = [owner, f'Tiaris-Candidate-Artifact-ID: {args.candidate_id}',
               f'Tiaris-Candidate-Artifact-SHA256: {args.candidate_digest}', POLICY]
    if (staged.get('immutable') is not True or staged['draft']
            or staged['target_commitish'] != args.source
            or any(marker not in (staged.get('body') or '').splitlines() for marker in markers)):
        raise ValueError('Immutable staged release does not belong to this candidate and release policy')
    base = f'https://github.com/{args.repository}/releases/download/{args.tag}/'
    with tempfile.TemporaryDirectory(prefix='nest-stable-promotion-') as temporary:
        directory = Path(temporary)
        names = [predecessor.MANIFEST, predecessor.COMPATIBILITY]
        if any(a['name'] == 'tiaris-nest-build-predecessor.json' for a in staged['assets']):
            names.append('tiaris-nest-build-predecessor.json')
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
        if not acceptance.production_origins.is_production(
                manifest.get('installer_iso_template_v3', {}).get('manage_origin')):
            raise ValueError('Development-origin artifacts cannot be promoted as production releases')
        acceptance.validate_public_closure(manifest, predecessor.sha(directory / predecessor.MANIFEST),
                                           receipts[EVIDENCE], args.source)
        # Repeat predecessor admission under the same publication concurrency
        # lock: another completed release must not reverse the lineage while
        # this candidate waits for approval.
        current = predecessor.resolve(args.repository, manifest['version'], args.trusted_public_key,
            directory / 'predecessor', predecessor.ROOT / 'release/recovery-adoption.json')
        receipt = directory / 'tiaris-nest-build-predecessor.json'
        expected = predecessor.checked_json(receipt)[0] if receipt.exists() else None
        if current != expected:
            raise ValueError('Predecessor changed while the prerelease awaited promotion')
        passed = ['Tiaris-Public-Closure: passed', f'Tiaris-Public-Closure-Artifact-ID: {args.artifact_id}',
                  f'Tiaris-Public-Closure-Artifact-SHA256: {args.artifact_digest}']
        body = staged.get('body') or ''
        if not staged['prerelease']:
            if all(marker in body.splitlines() for marker in passed):
                print('Exact public-closure-qualified release is already stable')
                return
            raise ValueError('Existing stable release lacks this exact acceptance provenance')
        if body.splitlines().count(PENDING) != 1:
            raise ValueError('Staged release lacks its pending public-closure marker')
        if args.verify_only:
            print('Exact immutable candidate passed public closure qualification '
                  '(VM qualification: nightly); production approval is still required')
            return
        notes = directory / 'notes.md'
        notes.write_text(body.replace(PENDING, '\n'.join(passed)) + '\n')
        subprocess.run(['gh', 'release', 'edit', args.tag, '--repo', args.repository,
                        '--prerelease=false', '--latest', '--notes-file', str(notes)], check=True)
    promoted = api('releases/tags/' + args.tag)
    inventory = lambda release: sorted((a['id'], a['name'], a['digest'], a['size']) for a in release['assets'])
    if (promoted['id'] != staged['id'] or not promoted.get('immutable') or promoted['draft']
            or promoted['prerelease'] or inventory(promoted) != inventory(staged)
            or POLICY not in (promoted.get('body') or '').splitlines()
            or api('releases/latest')['id'] != promoted['id']):
        raise ValueError('Stable promotion did not preserve immutable release identity')
    print('Immutable release promoted after exact public closure acceptance (VM qualification: nightly)')


if __name__ == '__main__':
    main()
