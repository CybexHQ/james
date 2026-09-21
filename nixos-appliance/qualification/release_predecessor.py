#!/usr/bin/env python3
"""Authenticate published ancestry separately from a NixOS upgrade fixture."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = 'cybex-james-release.json'
COMPATIBILITY = 'cybex-james-release-compatibility.json'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


release = module('james_release', ROOT / 'tools/james-release.py')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked_json(path, limit=1024 * 1024):
    return release._load_bounded_json(path, 'predecessor input', maximum_bytes=limit)


def latest(releases, candidate_tag):
    candidates = []
    for value in releases:
        if value.get('prerelease') and 'Cybex-Cold-Qualification: required' in (value.get('body') or ''):
            continue
        names = [a['name'] for a in value['assets']]
        if not value['draft'] and value['tag_name'] != candidate_tag and {MANIFEST, COMPATIBILITY} <= set(names):
            if any(names.count(name) != 1 for name in (MANIFEST, COMPATIBILITY)):
                raise ValueError('Published release has ambiguous signed assets')
            candidates.append(value)
    return max(candidates, key=lambda v: (v.get('published_at') or v['created_at'], v['id']), default=None)


def github(repository, path):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid GitHub repository')
    result = subprocess.run(['gh', 'api', '--paginate', f'repos/{repository}/{path}'], capture_output=True, check=True)
    remaining, pages = result.stdout.decode().strip(), []
    while remaining:
        value, end = json.JSONDecoder().raw_decode(remaining)
        pages.append(value)
        remaining = remaining[end:].lstrip()
    if not pages:
        raise ValueError('GitHub returned no response')
    return [v for page in pages for v in page] if isinstance(pages[0], list) else pages[0]


def fetch(url, target, expected_sha=None, expected_size=None, maximum=4 * 1024**3):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.username or parsed.password or parsed.query or parsed.fragment
            or not parsed.hostname or not (parsed.hostname == 'github.com' or parsed.hostname.startswith('dev.')
                                          or parsed.hostname.endswith('.test')) or target.is_symlink()):
        raise ValueError('Unexpected predecessor transport')
    if not target.exists():
        fd, name = tempfile.mkstemp(prefix='.download-', dir=target.parent)
        os.close(fd)
        part = Path(name)
        try:
            subprocess.run(['curl', '-4', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                '--proto-redir', '=https', '--connect-timeout', '30', '--max-time', '1800',
                '--max-filesize', str(maximum), '--output', str(part), url], check=True)
            check_file(part, expected_sha, expected_size, maximum)
            os.link(part, target)
        finally:
            part.unlink(missing_ok=True)
    check_file(target, expected_sha, expected_size, maximum)
    return target


def check_file(path, digest=None, size=None, maximum=4 * 1024**3):
    actual, length = release._inspect_artifact(path, 'predecessor artifact', maximum_bytes=maximum)
    if (digest is not None and actual != digest) or (size is not None and length != size):
        raise ValueError('Predecessor artifact differs from its signed size or digest')


def verify_pair(directory, trusted_key, manifest_url=None):
    asset, _ = checked_json(directory / COMPATIBILITY)
    url = manifest_url or asset['release_manifest']['url']
    with tempfile.TemporaryDirectory(prefix='james-predecessor-contract-') as temporary:
        contract = Path(temporary) / 'compatibility.json'
        contract.write_bytes(canonical(asset['compatibility']))
        release._verify_release_compatibility_command(argparse.Namespace(
            asset=directory / COMPATIBILITY, manifest=directory / MANIFEST, manifest_url=url,
            compatibility=contract, trusted_public_key=trusted_key))
    return checked_json(directory / MANIFEST)[0]


def advance(candidate, previous):
    release._validate_version(candidate)
    release._validate_version(previous)
    if release._compare_semver(candidate, previous) <= 0:
        raise ValueError('Candidate must strictly advance its authenticated predecessor')


def identity(directory, manifest, **fields):
    descriptor = manifest['appliance_release_v1']
    value = {'schema': 'cybex.james.published-predecessor.v3', 'release_id': manifest['version'],
        'manifest_sha256': sha(directory / MANIFEST), 'compatibility_sha256': sha(directory / COMPATIBILITY),
        'appliance_schema': descriptor['schema'], **fields}
    if descriptor['schema'] == release.appliance_v3.SCHEMA:
        value.update(system_closure_sha256=descriptor['system_closure']['sha256'],
            system_toplevel=descriptor['system_toplevel'], source_revision=descriptor['source_revision'],
            manage_source_revision=descriptor['manage_source_revision'], update_contract=release.appliance_v3.DELIVERY)
    else:
        value.update(update_contract='reinstall-only')
    return value


def historical_authority(path, trusted_key, previous, directory, candidate, repository):
    """Admit only an exact historical publication under current-key authorization.

    The old recovery URL is never fetched and is not an upgrade fixture. Its
    signed authorization is retained solely as historical ancestry evidence.
    """
    if not path.exists():
        return trusted_key
    value, body = checked_json(path)
    old = value.get('published', {})
    if old.get('github_release_id') != previous['id']:
        return trusted_key
    if (value.get('schema') != 'cybex.james.recovery-adoption.v1' or body != canonical(value)
            or value.get('repository') != repository or value.get('successor_version') != candidate
            or value.get('public_key') != trusted_key):
        raise ValueError('Historical authority requires exact current-key authorization')
    signature = release._canonical_base64(value['signature'], 'historical authorization', expected_bytes=64)
    release._self_verify(release.ED25519_PUBLIC_DER_PREFIX + release._trusted_public_key(trusted_key), signature,
        b'CYBEX-JAMES-RECOVERY-ADOPTION-V1\n' + canonical({k: v for k, v in value.items() if k != 'signature'}))
    if (old['tag_name'] != previous['tag_name'] or old['target_commitish'] != previous['target_commitish']
            or old['manifest_sha256'] != sha(directory / MANIFEST)
            or old['compatibility_sha256'] != sha(directory / COMPATIBILITY)):
        raise ValueError('Historical signed publication changed')
    return old['public_key']


def resolve(repository, candidate, trusted_key, directory, authorization=None, retain_to=None):
    directory.mkdir(parents=True, exist_ok=True)
    previous = latest(github(repository, 'releases?per_page=100'), 'v' + candidate)
    if previous is None:
        if authorization and authorization.exists():
            raise ValueError('Expected historical publication is absent; refusing a first-release declaration')
        return None
    tag = previous['tag_name']
    if not re.fullmatch(r'v[0-9A-Za-z.+-]+', tag):
        raise ValueError('Invalid predecessor tag')
    commit = github(repository, 'commits/' + tag)['sha']
    if previous['target_commitish'] != commit:
        raise ValueError('Published tag moved or lacks its exact source commit')
    base = f'https://github.com/{repository}/releases/download/{tag}/'
    for name in (MANIFEST, COMPATIBILITY):
        assets = [a for a in previous['assets'] if a['name'] == name]
        if len(assets) != 1 or assets[0]['browser_download_url'] != base + name:
            raise ValueError('Published asset URL does not bind repository and tag')
        asset = assets[0]
        digest = asset.get('digest')
        if digest and not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('Invalid GitHub asset digest')
        fetch(base + name, directory / name, digest[7:] if digest else None, asset['size'], 1024**2)
    authority = historical_authority(authorization, trusted_key, previous, directory, candidate, repository) if authorization else trusted_key
    manifest = verify_pair(directory, authority, base + MANIFEST)
    source = manifest['appliance_release_v1'].get('source_revision')
    if manifest['version'] != tag[1:] or (source is not None and source != commit):
        raise ValueError('Published manifest does not bind its tag and source commit')
    advance(candidate, manifest['version'])
    # Historical GPL source remains available with its original signed release;
    # it is never copied into a new NixOS closure or treated as an update input.
    return identity(directory, manifest, github_release_id=previous['id'], tag_name=tag,
                    authority_public_key=authority)


def qualify(directory, candidate, trusted_key, source=None, expected_sha=None):
    if (source is None) != (expected_sha is None):
        raise ValueError('Qualification predecessor requires both directory and manifest digest')
    if source is not None:
        release._require_sha256(expected_sha, 'qualification predecessor manifest')
        check_file(source / MANIFEST, expected_sha, maximum=1024**2)
        for name in (MANIFEST, COMPATIBILITY):
            _, body = checked_json(source / name)
            target = directory / name
            if target.exists():
                if target.read_bytes() != body:
                    raise ValueError('Qualification directory contains different predecessor bytes')
            else:
                release._atomic_write(target, body)
    manifest = verify_pair(directory, trusted_key)
    if manifest['appliance_release_v1']['schema'] != release.appliance_v3.SCHEMA:
        raise ValueError('Ubuntu is reinstall-only; supply a separately signed NixOS qualification predecessor')
    advance(candidate, manifest['version'])
    descriptor, iso = manifest['appliance_release_v1'], manifest['installer_iso_template_v3']
    for artifact, digest in ((descriptor['system_closure'], 'sha256'), (iso, 'template_sha256')):
        maximum = release.INSTALLER_ISO_MAX_BYTES if digest == 'template_sha256' else 4 * 1024**3
        name = urlsplit(artifact['url']).path.rsplit('/', 1)[-1]
        target = directory / name
        if source and (source / name).exists() and not target.exists():
            check_file(source / name, artifact[digest], artifact['size_bytes'], maximum)
            shutil.copyfile(source / name, target, follow_symlinks=False)
        fetch(artifact['url'], target, artifact[digest], artifact['size_bytes'], maximum)
    closure = directory / release.appliance_v3.archive_name(manifest['version'])
    tree = release.system_closure.verify_archive(closure, descriptor, trusted_key, release)
    release._verify_nixos_source_identity(tree, manifest['workstation_netboot'])
    iso_path = directory / urlsplit(iso['url']).path.rsplit('/', 1)[-1]
    inputs = release._installer_iso_template_inputs(argparse.Namespace(
        installer_iso_template=iso_path, installer_iso_template_url=iso['url'],
        installer_iso_template_personalization_offset=iso['personalization_offset'],
        provisioning_public_key=iso['provisioning_public_keys'], installer_iso_template_package_delivery=release.appliance_v3.DELIVERY,
        expected_manage_origin=iso['manage_origin'], installer_iso_template_metadata=None), manifest['version'], require_build_metadata=False)
    inspected = release._inspect_installer_iso_template(inputs, manifest['version'], base_os_version=iso['base_os_version'])
    if inspected != {k: v for k, v in iso.items() if k != 'signature'}:
        raise ValueError('Predecessor ISO immutable identity changed')
    return identity(directory, manifest, schema='cybex.james.nixos-qualification-predecessor.v1')


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('repository', 'candidate-version', 'trusted-public-key'):
        parser.add_argument('--' + name, required=True)
    for name in ('directory', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('authorization', 'expected-identity', 'github-output', 'retain-manage-source-to', 'qualification-predecessor-dir'):
        parser.add_argument('--' + name, type=Path)
    parser.set_defaults(authorization=ROOT / 'release/recovery-adoption.json')
    parser.add_argument('--qualification-predecessor-manifest-sha256')
    parser.add_argument('--download-media', action='store_true')
    args = parser.parse_args()
    if args.retain_manage_source_to:
        parser.error('--retain-manage-source-to is retired; historical source stays with its signed release')
    args.directory.mkdir(parents=True, exist_ok=True)
    # Explicit upgrade fixtures may differ from published ancestry, but they do
    # not bypass reauthentication of the build's published predecessor receipt.
    with tempfile.TemporaryDirectory(prefix='james-ancestry-') as temporary:
        ancestry_dir = Path(temporary) if args.qualification_predecessor_dir else args.directory
        value = resolve(args.repository, args.candidate_version, args.trusted_public_key, ancestry_dir, args.authorization)
        if args.expected_identity:
            expected, body = checked_json(args.expected_identity)
            if value != expected or body != canonical(expected):
                raise ValueError('Published ancestry changed since the candidate build')
        if args.download_media:
            value = qualify(args.directory, args.candidate_version, args.trusted_public_key,
                args.qualification_predecessor_dir, args.qualification_predecessor_manifest_sha256)
    if value is not None:
        if args.output.exists() and args.output.read_bytes() != canonical(value):
            raise ValueError('Refusing to replace a different predecessor receipt')
        release._atomic_write(args.output, canonical(value))
    if args.github_output:
        values = {'exists': str(value is not None).lower()}
        if value:
            values.update(identity_b64=base64.b64encode(canonical(value)).decode(),
                identity_sha256=hashlib.sha256(canonical(value)).hexdigest(), release_id=value['release_id'],
                snapshot_id=value.get('system_closure_sha256', ''), system_closure_sha256=value.get('system_closure_sha256', ''),
                update_contract=value['update_contract'])
        with args.github_output.open('a') as stream:
            stream.write(''.join(f'{k}={v}\n' for k, v in values.items()))
    print('Authenticated predecessor: ' + (value['release_id'] if value else 'first release'))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, release.ReleaseError, subprocess.SubprocessError) as error:
        raise SystemExit('Predecessor admission failed: ' + str(error)) from None
