"""Exact signed historical admission for the James → Nest reinstall boundary.

Old bytes are authenticated under their original domain and filenames. They are
never relabelled as Nest media or admitted as an executable upgrade fixture.
"""
from __future__ import annotations

import hashlib

MANIFEST = 'cybex-james-release.json'
COMPATIBILITY = 'cybex-james-release-compatibility.json'
DOMAIN = b'TIARIS-NEST-NAMESPACE-TRANSITION-V1\n'


def authenticate(release, directory, authorization, trusted_key, repository, candidate, previous):
    canonical = release._canonical_json_body
    anchor, body = release._load_bounded_json(authorization, 'namespace transition', maximum_bytes=1024**2)
    if (body != canonical(anchor) or anchor.get('schema') != 'tiaris.nest.namespace-transition.v1'
            or anchor.get('repository') != repository or anchor.get('successor_version') != candidate
            or anchor.get('public_key') != trusted_key or anchor.get('operation') != 'reinstall-only'):
        raise ValueError('Namespace transition requires exact signed successor authorization')
    signature = release._canonical_base64(anchor['signature'], 'namespace authorization', expected_bytes=64)
    release._self_verify(release.ED25519_PUBLIC_DER_PREFIX + release._trusted_public_key(trusted_key),
        signature, DOMAIN + canonical({k: v for k, v in anchor.items() if k != 'signature'}))
    manifest, manifest_body = release._load_bounded_json(directory / MANIFEST, 'historical manifest', maximum_bytes=1024**2)
    asset, asset_body = release._load_bounded_json(directory / COMPATIBILITY, 'historical compatibility', maximum_bytes=1024**2)
    published = anchor['published']
    base = f'https://github.com/{repository}/releases/download/{previous["tag_name"]}/'
    if (published['github_release_id'] != previous['id'] or published['tag_name'] != previous['tag_name']
            or published['target_commitish'] != previous['target_commitish']
            or published['manifest_sha256'] != hashlib.sha256(manifest_body).hexdigest()
            or published['compatibility_sha256'] != hashlib.sha256(asset_body).hexdigest()
            or asset_body != canonical(asset)
            or asset.get('schema') != 'cybex.james.release-compatibility.v1'
            or manifest.get('schema') != 'cybex.james.release.v1'
            or asset.get('public_key') != published['public_key']
            or asset.get('release_manifest') != {'url': base + MANIFEST, 'sha256': published['manifest_sha256']}
            or manifest.get('version') != previous['tag_name'][1:]
            or asset.get('james_release_version') != manifest['version']
            or manifest['appliance_release_v1'].get('source_revision') != previous['target_commitish']
            or asset['compatibility_sha256'] != hashlib.sha256(canonical(asset['compatibility'])).hexdigest()
            or asset['artifacts']['appliance_iso_template'].get('manage_origin') != anchor['manage_origin']):
        raise ValueError('Historical publication differs from namespace authorization')
    # The original compatibility signature authenticates the exact manifest hash
    # and artifact identities, not a rewritten projection of either document.
    release._self_verify(release.ED25519_PUBLIC_DER_PREFIX + release._trusted_public_key(published['public_key']),
        release._canonical_base64(asset['signature'], 'historical compatibility', expected_bytes=64),
        b'CYBEX-JAMES-RELEASE-COMPATIBILITY-V1\n' + canonical({k: v for k, v in asset.items() if k != 'signature'}))
    if release._compare_semver(candidate, manifest['version']) <= 0:
        raise ValueError('Namespace successor must advance the historical release')
    return anchor, manifest, asset


def verify_successor(release, directory, authorization, trusted_key, repository, current_path):
    current, body = release._load_bounded_json(current_path, 'current compatibility', maximum_bytes=1024**2)
    current = release._verified_release_compatibility_payload(current, body, trusted_key)
    anchor, _ = release._load_bounded_json(authorization, 'namespace transition', maximum_bytes=1024**2)
    published = anchor['published']
    anchor, _manifest, previous = authenticate(release, directory, authorization, trusted_key, repository,
        current['nest_release_version'], {'id': published['github_release_id'], **published})
    old_runtime = previous['artifacts']['workstation_runtime']
    runtime = current['artifacts']['workstation_runtime']
    if (current['artifacts']['appliance_iso_template']['manage_origin'] != anchor['manage_origin']
            or release._compare_semver(runtime['runtime_version'], old_runtime['runtime_version']) <= 0
            or release._compare_semver(runtime['runtime_version'], anchor['minimum_runtime_version']) < 0
            or runtime['sha256'] == old_runtime['sha256']
            or current['compatibility']['workstation_runtime']['compatibility_epoch']
               < previous['compatibility']['workstation_runtime']['compatibility_epoch']
            or current['artifacts']['appliance_package_snapshot']['minimum_state_schema']
               < previous['artifacts']['appliance_package_snapshot']['minimum_state_schema']):
        raise ValueError('Namespace successor does not preserve origin and advance runtime identity')
