#!/usr/bin/env python3
"""Resolve the exact published Nest release that on-demand VM qualification tests.

Release policy fast-v1 publishes and promotes Nest releases without warm or
cold VM qualification. The VM harness stays available through
`.github/workflows/nest-vm-qualification.yml` (for the owner's nightly). This
helper binds that workflow to one immutable release, its exact `release.yml`
push run and its build-once candidate receipt. It is read-only: it never
changes a release, and its result grants no publication or promotion.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

RELEASE_WORKFLOW = '.github/workflows/release.yml'
BUNDLE = re.compile(r'tiaris-workstation-netboot-[0-9A-Za-z.+-]+-x86_64-linux\.tar\.zst')


def gh_api(path):
    result = subprocess.run(['gh', 'api', '-H', 'Accept: application/vnd.github+json',
                             '-H', 'X-GitHub-Api-Version: 2026-03-10', path],
                            capture_output=True, text=True, timeout=60, check=False)
    if result.returncode:
        raise ValueError('GitHub metadata could not be read: ' + path)
    return json.loads(result.stdout)


def marker(lines, name):
    values = [line[len(name) + 2:] for line in lines if line.startswith(name + ': ')]
    if len(values) != 1:
        raise ValueError(f'Release notes must carry exactly one {name} marker')
    return values[0]


def resolve(repository, tag, api, ref):
    """`ref` is the workflow's own `GITHUB_REF`; it must be the release tag.

    The protected `production-release-qualification` environment admits only
    `v*` tag refs, and that ref (not the checked-out source) is what GitHub
    evaluates. Refuse any other ref before a VM job waits on a rejected
    deployment.
    """
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid repository')
    dispatched = ref.removeprefix('refs/tags/') if ref.startswith('refs/tags/') else ''
    tag = tag or dispatched
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
        raise ValueError('VM qualification needs an exact production tag vX.Y.Z')
    if dispatched != tag:
        raise ValueError(f'Run this workflow at the release tag: gh workflow run nest-vm-qualification.yml '
                         f'--repo {repository} --ref {tag} -f tag={tag}')
    release = api(f'repos/{repository}/releases/tags/{tag}')
    if release.get('tag_name') != tag:
        raise ValueError('The selected release has no exact production tag')
    if release.get('draft') is not False or release.get('immutable') is not True:
        raise ValueError('Only an immutable published release can be VM-qualified')
    source = api(f'repos/{repository}/commits/{tag}').get('sha', '')
    if not re.fullmatch(r'[0-9a-f]{40}', source) or release.get('target_commitish') != source:
        raise ValueError('The release tag moved or lacks its exact source commit')
    lines = (release.get('body') or '').splitlines()
    owner = marker(lines, 'Tiaris-Release-Workflow')
    match = re.fullmatch(rf'https://github\.com/{re.escape(repository)}/actions/runs/([1-9][0-9]*)', owner)
    if not match:
        raise ValueError('The release does not name its exact release workflow run')
    run_id = match.group(1)
    candidate_id = marker(lines, 'Tiaris-Candidate-Artifact-ID')
    candidate_digest = marker(lines, 'Tiaris-Candidate-Artifact-SHA256')
    if (not re.fullmatch(r'[1-9][0-9]*', candidate_id)
            or not re.fullmatch(r'[0-9a-f]{64}', candidate_digest)):
        raise ValueError('The release candidate markers are invalid')
    run = api(f'repos/{repository}/actions/runs/{run_id}')
    if (run.get('path') != RELEASE_WORKFLOW or run.get('event') != 'push'
            or run.get('head_branch') != tag or run.get('head_sha') != source):
        raise ValueError('The named run is not the exact release.yml push of this tag')
    artifact = api(f'repos/{repository}/actions/artifacts/{candidate_id}')
    if (artifact.get('name') != f'tiaris-nest-release-candidate-{run_id}'
            or artifact.get('expired') is not False
            or artifact.get('workflow_run', {}).get('id') != int(run_id)
            or artifact.get('workflow_run', {}).get('head_sha') != source
            or artifact.get('digest') != 'sha256:' + candidate_digest):
        raise ValueError('The candidate receipt is unavailable or does not belong to this release')
    names = [asset.get('name') for asset in release.get('assets', [])]
    bundles = [name for name in names if BUNDLE.fullmatch(name or '')]
    if len(bundles) != 1 or len(names) != len(set(names)):
        raise ValueError('The release must publish exactly one workstation bundle')
    return {'tag': tag, 'version': tag[1:], 'source': source, 'run': run_id,
            'candidate_id': candidate_id, 'candidate_digest': candidate_digest,
            'workstation_bundle_name': bundles[0],
            'has_predecessor': str('tiaris-nest-build-predecessor.json' in names).lower()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--tag', default='', help='Exact tag; empty selects the tag this workflow runs at')
    parser.add_argument('--ref', required=True, help='The workflow run ref (GITHUB_REF); must be refs/tags/TAG')
    parser.add_argument('--github-output', type=Path)
    args = parser.parse_args()
    value = resolve(args.repository, args.tag, gh_api, args.ref)
    lines = ''.join(f'{key}={item}\n' for key, item in value.items())
    if args.github_output:
        with args.github_output.open('a') as stream:
            stream.write(lines)
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit('VM qualification target rejected: ' + str(error)) from None
