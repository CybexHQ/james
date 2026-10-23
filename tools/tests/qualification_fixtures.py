"""Complete public delivery evidence for deterministic transition tests."""
import uuid


def upgraded_delivery(manifest, device):
    runtime = manifest['workstation_netboot']
    return {'schema': 'tiaris.nest.upgraded-blueprint-delivery.v1',
        'nest_device_id': device, 'bundle_sha256': runtime['sha256'],
        'runtime_version': runtime['runtime_version'],
        'manage_source_revision': runtime['manage_source_revision'],
        'source_builds_allowed': False, 'local_builds_allowed': False,
        'source_free': True, 'deliverable': True,
        'job_ids': [str(uuid.uuid4()) for _ in range(3)],
        'qualified_blueprints': {'schema': 'tiaris.nest.qualification-blueprints.v1', 'blueprints': [
            {'id': str(uuid.uuid4()), 'current_revision_id': str(uuid.uuid4()),
             'desktop_profile': profile, 'slug': slug, 'current_revision': 1,
             'config_hash': 'c' * 64} for slug, profile in (
                ('standard_workstation', 'taskbar'), ('dock_workstation', 'dock'),
                ('qualification_dock', 'dock'))]}}
