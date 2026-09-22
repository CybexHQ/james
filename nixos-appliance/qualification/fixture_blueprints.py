"""Prepare three real workstation profiles only inside a newly bootstrapped fixture."""


def prepare(owner):
    api = owner.api
    rows = api('/v1/blueprints?platform=nixos&limit=100&offset=0')['blueprints']
    if any(row['slug'] == 'qualification_tiling' for row in rows):
        raise ValueError('refusing to adopt an existing qualification Blueprint')
    for slug in ('standard_workstation', 'dock_workstation'):
        selected = [row for row in rows if row['slug'] == slug]
        if len(selected) != 1 or not selected[0]['current_revision_id']:
            raise ValueError('fresh fixture lacks a released built-in workstation profile')
    app = api('/v1/app-lists', {'name': 'Qualification Tiling Apps',
                              'description': 'Deno coverage inside the disposable qualification fixture.'})['app_list']
    detail = api('/v1/app-lists/' + app['id'])
    app = api('/v1/app-lists/' + app['id'] + '/publish', {
        'expected_version': detail['app_list']['version'],
        'config': {'items': [{'label': 'Deno', 'package_ref': 'deno'}]},
        'note': 'Isolated NixOS qualification coverage.'})['app_list']
    configuration = {'settings': {'desktop': {'profile': {'label': 'Desktop Experience', 'value': 'Tiling'}}},
                     'lists': {'app_lists': {'selected': {'label': 'App Lists', 'items': [
                         {'label': 'Essentials', 'app_list_slug': 'essentials'},
                         {'label': app['name'], 'app_list_slug': app['slug']}]}}}}
    blueprint = api('/v1/blueprints', {'name': 'Qualification Tiling', 'slug': 'qualification_tiling',
                    'description': 'Disposable isolated NixOS qualification profile.',
                    'platform': 'nixos', 'config': configuration})['blueprint']
    revisions = api('/v1/blueprints/' + blueprint['id'] + '/revisions?limit=100&offset=0')['revisions']
    if len(revisions) != 1 or blueprint['current_revision_id'] is not None:
        raise ValueError('fresh fixture Blueprint acquired an unexpected release')
    current = api('/v1/blueprints/' + blueprint['id'])
    current = current.get('blueprint', current)
    api('/v1/blueprint-revisions/' + revisions[0]['id'] + '/release', {
        'expected_version': current['version'],
        'unverified_reason': 'Disposable qualification profile; VM acceptance will establish verification.'})
    policy = api('/v1/james/delivery-policy')
    if policy['emergency_override_mode'] is not None:
        raise ValueError('fresh fixture unexpectedly has emergency policy overrides')
    fields = ('mode', 'approved_public_substituters', 'approved_public_keys', 'required_james_replicas',
              'rollback_window_days', 'max_concurrent_transfers_per_james')
    api('/v1/james/delivery-policy', {**{key: policy[key] for key in fields},
                                    'allow_james_source_builds': False, 'allow_local_builds': False})
    result = api('/v1/james/delivery-policy')
    if result['allow_james_source_builds'] or result['source_builds_allowed'] or result['allow_local_builds']:
        raise ValueError('fixture source-free delivery policy did not take effect')
