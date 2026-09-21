"""Validate the distinct appliance and cold-delivery release gates."""
import argparse
import hashlib
import json
from pathlib import Path
import re

LIFECYCLE_FLAGS = (
    'ok', 'no_disk_write_before_approval', 'identity_rotation',
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
    if (evidence.get('schema') != 'cybex.james.nixos-appliance-qualification.v1'
            or any(evidence.get(k) is not True for k in LIFECYCLE_FLAGS)
            or evidence.get('final_state') != 'ready'
            or evidence.get('qualification_kind') != 'candidate'
            or evidence.get('qualified_manifest_sha256') != manifest_sha256
            or evidence.get('harness_revision') != source
            or manifest['appliance_release_v1']['source_revision'] != source
            or evidence.get('release_version') != manifest['version']
            or evidence.get('base_os') != 'nixos'
            or evidence.get('system_closure_sha256') != manifest['appliance_release_v1']['system_closure']['sha256']
            or evidence.get('system_toplevel') != manifest['appliance_release_v1']['system_toplevel']
            or evidence.get('nixpkgs_revision') != manifest['appliance_release_v1']['nixpkgs_revision']
            or evidence.get('manage_source_revision') != manifest['appliance_release_v1']['manage_source_revision']
            or evidence.get('secure_boot') is not False
            or evidence.get('ssh_login_verified') is not True
            or evidence.get('ssh_root_rejected') is not True
            or evidence.get('ssh_password_rejected') is not True
            or evidence.get('template_sha256') != manifest['installer_iso_template_v3']['template_sha256']
            or not re.fullmatch(r'[1-9][0-9]*', str(evidence.get('system_generation', ''))) 
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



def validate_transition(manifest, digest, previous, previous_digest, evidence, source, phase):
    import release_predecessor
    release_predecessor.advance(manifest['version'], previous['version'])
    candidate, predecessor = manifest['appliance_release_v1'], previous['appliance_release_v1']
    if (candidate['schema'] != 'cybex.james.appliance-release.v3'
            or predecessor['schema'] != candidate['schema']
            or candidate['source_revision'] != source
            or manifest['installer_iso_template_v3']['manage_origin'] != previous['installer_iso_template_v3']['manage_origin']
            or evidence.get('schema') != f'cybex.james.nixos-appliance-{phase}-qualification.v1'
            or evidence.get('candidate_manifest_sha256') != digest
            or evidence.get('predecessor_manifest_sha256') != previous_digest
            or evidence.get('harness_revision') != source
            or evidence.get('candidate_release') != manifest['version']
            or evidence.get('predecessor_release') != previous['version']
            or evidence.get('secure_boot') is not False
            or any(evidence.get(k) is not True for k in ('ok', 'identity_preserved', 'candidate_reboot_observed', 'appliance_projection_healthy'))
            or not re.fullmatch(r'dev_[0-9a-f]{32}', evidence.get('server_device_id', ''))
            or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', evidence.get('attempt_id', ''))):
        raise ValueError('Transition evidence does not bind the exact signed NixOS releases')
    for prefix, release in (('candidate', candidate), ('predecessor', predecessor)):
        if (evidence.get(prefix + '_system_closure_sha256') != release['system_closure']['sha256']
                or evidence.get(prefix + '_system_toplevel') != release['system_toplevel']
                or evidence.get(prefix + '_source_revision') != release['source_revision']
                or evidence.get(prefix + '_manage_source_revision') != release['manage_source_revision']):
            raise ValueError('Transition closure/source identity changed')
    before, staged, result = [evidence.get(name) for name in
        ('source_system_generation', 'candidate_system_generation', 'resulting_system_generation')]
    if (any(not re.fullmatch(r'[1-9][0-9]*', str(v)) for v in (before, staged, result))
            or int(staged) <= int(before)):
        raise ValueError('Transition lacks distinct allocated Nix generations')
    rollback = phase == 'rollback'
    if (evidence.get('final_status') != ('rolled_back' if rollback else 'succeeded')
            or evidence.get('final_stage') != ('boot_fallback' if rollback else 'committed')
            or str(result) != str(before if rollback else staged)
            or evidence.get('resulting_system_toplevel') != (predecessor if rollback else candidate)['system_toplevel']
            or evidence.get('host_reset_used') is not False):
        raise ValueError('Transition did not reach the exact automatic terminal outcome')
    if rollback:
        if (evidence.get('automatic_rollback') is not True or evidence.get('fallback_reboot_observed') is not True
                or not evidence.get('rollback_reason') or not evidence.get('fault')):
            raise ValueError('Rollback requires appliance-initiated recovery with a reason')
    elif (evidence.get('fresh_health_successes', 0) < 3
            or evidence.get('authenticated_manage_contact') is not True):
        raise ValueError('Commit lacks repeated fresh health and permanent-identity contact')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=['prepublication', 'cold', 'update', 'rollback'], required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--workstation', type=Path)
    parser.add_argument('--predecessor-manifest', type=Path)
    parser.add_argument('--source', required=True)
    args = parser.parse_args()
    body = args.manifest.read_bytes()
    manifest = json.loads(body)
    evidence = json.loads(args.evidence.read_bytes())
    if args.phase in {'update', 'rollback'}:
        if args.predecessor_manifest is None or args.workstation is not None:
            raise ValueError('Update acceptance requires its exact predecessor manifest')
        previous_body = args.predecessor_manifest.read_bytes()
        validate_transition(manifest, hashlib.sha256(body).hexdigest(), json.loads(previous_body),
            hashlib.sha256(previous_body).hexdigest(), evidence, args.source, args.phase)
        print('Exact ' + args.phase + ' acceptance verified')
        return
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
