"""Source-free current Blueprint delivery after an actual appliance upgrade.

The predecessor carries a different signed Manage module and binary cache.
Do not send current Blueprint inputs until the candidate's matching runtime
has converged. Fresh/cold lifecycle acceptance keeps its independent checks.
"""
import copy
from pathlib import Path
import re
import runpy
import time
import uuid

CATALOG = runpy.run_path(str(Path(__file__).with_name('blueprint-catalog.py')))


def read_catalog(api):
    rows = []
    while len(rows) < 10000:
        page = api('/v1/blueprints?platform=nixos&limit=100&offset=' + str(len(rows)))['blueprints']
        rows.extend(page)
        if len(page) < 100:
            break
    else:
        raise ValueError('Qualification catalog exceeds its bound')
    slugs = {*CATALOG['BUILTINS'], 'qualification_tiling'}
    configs = {row['slug']: api('/v1/blueprints/' + str(uuid.UUID(row['id'])) + '/config')
               for row in rows if row['slug'] in slugs}
    return CATALOG['catalog'](rows, configs, 'qualification_tiling')


def source_free_policy(api):
    policy = api('/v1/nest/delivery-policy')
    if (any(policy.get(field) is not False for field in
            ('allow_nest_source_builds', 'source_builds_allowed', 'allow_local_builds'))
            or policy.get('emergency_override_mode') is not None):
        raise ValueError('Upgraded Blueprint qualification requires the source-disabled policy')


def exact_runtime(status, manifest):
    expected = manifest['workstation_netboot']
    return (status.get('operational') is True and status.get('converged') is True
            and all(status.get(projection, {}).get('bundle_sha256') == expected['sha256']
                    and status[projection].get('runtime_version') == expected['runtime_version']
                    for projection in ('active', 'desired')))


def validate(manifest, device, receipt):
    expected = manifest['workstation_netboot']
    if (not isinstance(receipt, dict)
            or receipt.get('schema') != 'tiaris.nest.upgraded-blueprint-delivery.v1'
            or receipt.get('nest_device_id') != device
            or receipt.get('bundle_sha256') != expected['sha256']
            or receipt.get('runtime_version') != expected['runtime_version']
            or receipt.get('manage_source_revision') != expected['manage_source_revision']
            or receipt.get('source_builds_allowed') is not False
            or receipt.get('local_builds_allowed') is not False
            or receipt.get('source_free') is not True or receipt.get('deliverable') is not True):
        raise ValueError('Upgrade lacks source-free delivery on its exact candidate runtime')
    catalog = receipt.get('qualified_blueprints', {})
    rows = catalog.get('blueprints', [])
    jobs = receipt.get('job_ids', [])
    if (catalog.get('schema') != 'tiaris.nest.qualification-blueprints.v1' or len(rows) != 3
            or {row.get('desktop_profile') for row in rows} != {'taskbar', 'dock', 'tiling'}
            or len({row.get('id') for row in rows}) != 3
            or len({row.get('current_revision_id') for row in rows}) != 3
            or len(jobs) != 3 or len(set(jobs)) != 3
            or any(not isinstance(job, str) or not re.fullmatch(
                r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', job) for job in jobs)):
        raise ValueError('Upgrade lacks three distinct current Blueprint delivery proofs')


def qualify(api, device, manifest, catalog, *, clock=time.monotonic, sleep=time.sleep, timeout=3600):
    catalog = copy.deepcopy(catalog)
    deadline = clock() + timeout
    prefix = '/v1/nest/nodes/' + device
    admitted = {}
    source_free_policy(api)
    while clock() < deadline:
        if not exact_runtime(api(prefix + '/workstation-netboot'), manifest):
            sleep(5)
            continue
        source_free_policy(api)
        for blueprint in catalog['blueprints']:
            revision = blueprint['current_revision_id']
            if revision not in admitted:
                job = api(prefix + '/build/jobs', {'requested_artifact_type': 'nixos_closure',
                    'blueprint_id': blueprint['id'], 'blueprint_revision_id': revision,
                    'target': 'blueprint', 'system': 'x86_64-linux'})
                admitted[revision] = job['id']
        jobs = api(prefix + '/build/jobs?limit=200&offset=0')['jobs']
        selected = [job for job in jobs if job['id'] in admitted.values()]
        if any(job['status'] in {'failed', 'cancelled'} for job in selected):
            raise ValueError('Upgraded current Blueprint failed source-free delivery')
        if (len(selected) == 3 and all(job['status'] == 'succeeded' for job in selected)):
            cached = [api('/v1/blueprints/' + blueprint['id'] + '/nest-cache?revision_id='
                          + blueprint['current_revision_id']) for blueprint in catalog['blueprints']]
            if all(row.get('cached') is True and row.get('required_replicas', 0) > 0
                   and row.get('ready_replicas') == row['required_replicas'] for row in cached):
                if not exact_runtime(api(prefix + '/workstation-netboot'), manifest):
                    raise ValueError('Candidate runtime changed during Blueprint qualification')
                source_free_policy(api)
                receipt = {'schema': 'tiaris.nest.upgraded-blueprint-delivery.v1',
                    'nest_device_id': device, 'qualified_blueprints': catalog,
                    'job_ids': list(admitted.values()), 'source_builds_allowed': False,
                    'local_builds_allowed': False, 'source_free': True, 'deliverable': True,
                    'bundle_sha256': manifest['workstation_netboot']['sha256'],
                    'runtime_version': manifest['workstation_netboot']['runtime_version'],
                    'manage_source_revision': manifest['workstation_netboot']['manage_source_revision']}
                validate(manifest, device, receipt)
                return receipt
        sleep(5)
    raise ValueError('Upgraded source-free Blueprint delivery timed out')


def qualify_current(api, device, manifest):
    catalog = read_catalog(api)
    receipt = qualify(api, device, manifest, catalog)
    if read_catalog(api) != catalog:
        raise ValueError('Current Blueprint revisions changed during upgrade qualification')
    return receipt
