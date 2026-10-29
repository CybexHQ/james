#!/usr/bin/env python3
"""Read-only admission and bounded attestation visibility for Nest publication."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

WAIT_SECONDS = 300
RETRY_SECONDS = 3


def gh(*arguments, timeout=60):
    return subprocess.run(['gh', *arguments], capture_output=True, text=True,
                          timeout=timeout, check=False)


def api(path, *, pages=False):
    arguments = ['api', '-H', 'Accept: application/vnd.github+json',
                 '-H', 'X-GitHub-Api-Version: 2026-03-10']
    if pages:
        arguments += ['--paginate', '--slurp']
    result = gh(*arguments, path)
    if result.returncode:
        raise ValueError('GitHub publication metadata could not be read')
    return json.loads(result.stdout)


def identity():
    values = {key: os.environ[key] for key in (
        'GITHUB_SERVER_URL', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_SHA',
        'GITHUB_REF_NAME', 'TIARIS_NEST_RELEASE_VERSION',
        'TIARIS_NEST_RELEASE_ARTIFACT_ID', 'TIARIS_NEST_RELEASE_ARTIFACT_DIGEST')}
    if (not re.fullmatch(r'[0-9a-fA-F]{40}', values['GITHUB_SHA'])
            or values['GITHUB_REF_NAME'] != 'v' + values['TIARIS_NEST_RELEASE_VERSION']
            or not re.fullmatch(r'[1-9][0-9]*', values['GITHUB_RUN_ID'])
            or not re.fullmatch(r'[1-9][0-9]*', values['TIARIS_NEST_RELEASE_ARTIFACT_ID'])
            or not re.fullmatch(r'[0-9a-f]{64}', values['TIARIS_NEST_RELEASE_ARTIFACT_DIGEST'])):
        raise ValueError('Publication identity is invalid')
    return values


def asset_paths(values):
    version = values['TIARIS_NEST_RELEASE_VERSION']
    bundle = os.environ['TIARIS_NEST_WORKSTATION_BUNDLE_NAME']
    if Path(bundle).name != bundle or not bundle:
        raise ValueError('Workstation bundle name must be a filename')
    files = [Path('dist') / name for name in (
        'tiaris-nest-x86_64-linux',
        f'tiaris-nest-appliance-template-{version}-x86_64-linux.iso',
        f'tiaris-nest-appliance-closure-{version}-x86_64-linux.tar.zst',
        bundle, 'tiaris-nest-release.json', 'tiaris-nest-release-compatibility.json', 'SHA256SUMS')]
    files += [Path('qualification') / name for name in (
        'tiaris-nest-nixos-qualification.json', 'tiaris-nest-nixos-update-qualification.json',
        'tiaris-nest-nixos-rollback-qualification.json', 'tiaris-nest-qualified-predecessor.json',
        'tiaris-nest-qualified-predecessor-release.json')]
    predecessor = os.environ['TIARIS_NEST_HAS_PREDECESSOR']
    if predecessor not in {'true', 'false'}:
        raise ValueError('Publication predecessor identity is invalid')
    if predecessor == 'true':
        files.append(Path('dist/tiaris-nest-build-predecessor.json'))
    return files


def inspect(expected_immutable_id=None):
    """An immutable retry is read-only and bound to every original publication byte."""
    values = identity()
    repository, tag = values['GITHUB_REPOSITORY'], values['GITHUB_REF_NAME']
    commit = api(f'repos/{repository}/commits/{tag}')
    if commit.get('sha', '').lower() != values['GITHUB_SHA'].lower():
        raise ValueError('Publication tag does not point to the exact candidate source')
    pages = api(f'repos/{repository}/releases?per_page=100', pages=True)
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise ValueError('Publication release discovery is invalid')
    matches = [release for page in pages for release in page if release.get('tag_name') == tag]
    if len(matches) > 1 or (expected_immutable_id is not None and len(matches) != 1):
        raise ValueError('Publication requires one exact owned release')
    if not matches:
        return None
    release = matches[0]
    expected_body = '\n'.join((
        f'Tiaris-Release-Workflow: {values["GITHUB_SERVER_URL"]}/{repository}/actions/runs/{values["GITHUB_RUN_ID"]}',
        f'Tiaris-Candidate-Artifact-ID: {values["TIARIS_NEST_RELEASE_ARTIFACT_ID"]}',
        f'Tiaris-Candidate-Artifact-SHA256: {values["TIARIS_NEST_RELEASE_ARTIFACT_DIGEST"]}',
        'Tiaris-Cold-Qualification: required'))
    if (type(release.get('id')) is not int or release['id'] <= 0
            or release.get('name') != f'Tiaris Nest {tag}'
            or release.get('body') != expected_body
            or release.get('target_commitish', '').lower() != values['GITHUB_SHA'].lower()
            or release.get('prerelease') is not True):
        raise ValueError('Existing release does not belong to the exact publication candidate')
    if release.get('draft') is True and release.get('immutable') is False:
        if expected_immutable_id is not None:
            raise ValueError('Retained immutable publication changed')
        return None  # Existing guarded draft cleanup still owns partial draft recovery.
    if (release.get('draft') is not False or release.get('immutable') is not True
            or (expected_immutable_id is not None and release['id'] != expected_immutable_id)):
        raise ValueError('Existing publication is not the exact immutable prerelease')
    assets = api(f'repos/{repository}/releases/{release["id"]}/assets?per_page=100')
    files = asset_paths(values)
    if (not isinstance(assets, list) or len(assets) != len(files)
            or len({asset.get('name') for asset in assets}) != len(files)):
        raise ValueError('Immutable publication asset set changed')
    by_name = {asset['name']: asset for asset in assets}
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError('Exact locally verified publication asset is unavailable')
        with path.open('rb') as stream:
            digest = 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()
        asset = by_name.get(path.name, {})
        if (asset.get('state') != 'uploaded' or type(asset.get('size')) is not int
                or asset['size'] != path.stat().st_size or asset.get('digest') != digest):
            raise ValueError('Immutable publication assets differ from the exact candidate bytes')
    return release['id']


def verify_attestation():
    """Wait only for the known missing-attestation response, never invalid proof."""
    values = identity()
    tag, source = values['GITHUB_REF_NAME'], values['GITHUB_SHA'].lower()
    missing = f'no attestations for tag {tag} (sha1:{source})'
    resolved = f'Resolved tag {tag} to sha1:{source}'
    deadline = time.monotonic() + WAIT_SECONDS
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('GitHub release attestation remained unavailable within the visibility bound')
        result = gh('release', 'verify', tag, '--repo', values['GITHUB_REPOSITORY'],
                    timeout=min(30, remaining))
        if result.returncode == 0:
            print(result.stdout, end='')
            return
        if result.stderr.strip() != missing or result.stdout.strip() not in {'', resolved}:
            raise ValueError('GitHub release attestation verification failed; no retry is permitted')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('GitHub release attestation remained unavailable within the visibility bound')
        print('Release attestation is not visible yet; waiting for GitHub publication.', file=sys.stderr)
        time.sleep(min(RETRY_SECONDS, remaining))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'verify-attestation'))
    parser.add_argument('--expected-immutable-id', type=int)
    arguments = parser.parse_args()
    if arguments.action == 'inspect':
        release_id = inspect(arguments.expected_immutable_id)
        print('immutable_release_id=' + (str(release_id) if release_id is not None else ''))
    else:
        if arguments.expected_immutable_id is not None:
            parser.error('--expected-immutable-id is only valid with inspect')
        verify_attestation()


if __name__ == '__main__':
    try:
        main()
    except (KeyError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f'Publication verification failed: {error}', file=sys.stderr)
        raise SystemExit(1) from None
