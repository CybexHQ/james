"""Validate the distinct appliance and cold-delivery release gates."""
import argparse
import hashlib
import json
from pathlib import Path
import re

LIFECYCLE_FLAGS = (
    'ok', 'secure_boot', 'no_disk_write_before_approval', 'identity_rotation',
    'installed_media_left_attached', 'appliance_projection_healthy',
    'two_phase_network_acknowledged', 'exact_principal_ssh_certificate',
)
DELIVERY_FLAGS = (
    'workstation_runtime_operational', 'workstation_runtime_converged',
    'builtin_blueprints_source_free', 'builtin_blueprints_deliverable',
    'builtin_blueprints_qualified_on_new_james',
)


def validate_lifecycle(manifest, manifest_sha256, evidence, source, phase):
    if phase not in {'prepublication', 'cold'}:
        raise ValueError('Unknown acceptance phase')
    cold = phase == 'cold'
    if (evidence.get('schema') != 'cybex.james.ubuntu-appliance-qualification.v1'
            or any(evidence.get(k) is not True for k in LIFECYCLE_FLAGS)
            or evidence.get('final_state') != 'ready'
            or evidence.get('qualification_kind') != 'candidate'
            or evidence.get('qualified_manifest_sha256') != manifest_sha256
            or evidence.get('harness_revision') != source
            or manifest['appliance_release_v1']['source_revision'] != source
            or evidence.get('release_version') != manifest['version']
            or evidence.get('ubuntu_snapshot_id') != manifest['appliance_release_v1']['ubuntu_snapshot_id']
            or evidence.get('template_sha256') != manifest['installer_iso_template_v2']['template_sha256']
            or str(evidence.get('root_generation')) != '0'
            or not re.fullmatch(r'dev_[0-9a-f]{32}', evidence.get('device_id', ''))):
        raise ValueError('Appliance evidence does not qualify the exact fresh candidate')
    if (any(evidence.get(k) is not cold for k in DELIVERY_FLAGS)
            or evidence.get('candidate_runtime_required') is not cold
            or evidence.get('workstation_runtime_prepublication_deferred') is not (not cold)
            or evidence.get('builtin_blueprints_prepublication_deferred') is not (not cold)):
        raise ValueError('Delivery evidence does not match its acceptance phase')
    catalog = evidence.get('qualified_blueprints', {})
    blueprints = catalog.get('blueprints', [])
    if (catalog.get('schema') != 'cybex.james.qualification-blueprints.v1'
            or len(blueprints) != 3
            or {b.get('desktop_profile') for b in blueprints} != {'taskbar', 'dock', 'tiling'}
            or len({b.get('id') for b in blueprints}) != 3
            or len({b.get('current_revision_id') for b in blueprints}) != 3):
        raise ValueError('The three distinct built-in profiles were not qualified')


def validate_workstation(manifest, cold, evidence):
    descriptor = manifest['workstation_netboot']
    # The installed runtime records the signed release-independent component
    # identity, using the same canonical vocabulary as the workstation harness.
    import workstation_lifecycle
    if (evidence.get('schema') != 'cybex.james.published-workstation-qualification.v1'
            or any(evidence.get(k) is not True for k in ('ok', 'pxe_boot_observed', 'fresh_install_completed'))
            or evidence.get('source_builds_allowed') is not False
            or evidence.get('release_version') != manifest['version']
            or evidence.get('runtime_version') != descriptor['runtime_version']
            or evidence.get('bundle_sha256') != descriptor['sha256']
            or evidence.get('manage_source_revision') != descriptor['manage_source_revision']
            or evidence.get('descriptor_sha256') != workstation_lifecycle.descriptor_digest(descriptor)
            or evidence.get('james_device_id') != cold['device_id']
            or not re.fullmatch(r'dev_[0-9a-f]{32}', evidence.get('workstation_device_id', ''))
            or evidence.get('workstation_device_id') == cold['device_id']):
        raise ValueError('Workstation evidence does not qualify the exact published runtime')
    expected = {(b['id'], b['current_revision_id'], b['slug'])
                for b in cold['qualified_blueprints']['blueprints']}
    profiles = evidence.get('blueprints', [])
    actual = {(b.get('blueprint_id'), b.get('revision_id'), b.get('slug')) for b in profiles}
    if len(profiles) != 3 or actual != expected:
        raise ValueError('Workstation profiles differ from the cold James catalog')
    for profile in profiles:
        if (profile.get('configuration_status') != 'compliant'
                or profile.get('managed_reboot_completed') is not True
                or profile.get('identity_preserved') is not True
                or not profile.get('boot_id_before') or not profile.get('boot_id_after')
                or profile['boot_id_before'] == profile['boot_id_after']
                or not str(profile.get('system', '')).startswith('/nix/store/')):
            raise ValueError('A workstation profile lacks a real reboot and exact compliance')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=['prepublication', 'cold'], required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--workstation', type=Path)
    parser.add_argument('--source', required=True)
    args = parser.parse_args()
    body = args.manifest.read_bytes()
    manifest = json.loads(body)
    evidence = json.loads(args.evidence.read_bytes())
    validate_lifecycle(manifest, hashlib.sha256(body).hexdigest(), evidence, args.source, args.phase)
    if args.phase == 'cold':
        if args.workstation is None:
            raise ValueError('Stable promotion requires real workstation acceptance')
        validate_workstation(manifest, evidence, json.loads(args.workstation.read_bytes()))
    elif args.workstation is not None:
        raise ValueError('Prepublication evidence cannot claim workstation acceptance')
    print('Exact ' + args.phase + ' acceptance verified')


if __name__ == '__main__':
    main()
