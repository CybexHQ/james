#!/usr/bin/env python3
"""Read-only lifecycle admission; pin current revisions without editing Blueprints."""
import argparse
import json
import re
from pathlib import Path
import runpy
import urllib.request
import uuid

BUILTINS = {'standard_workstation': 'taskbar', 'dock_workstation': 'dock'}
HTTP = runpy.run_path(str(Path(__file__).with_name('qualification_http.py')))


def catalog(rows, configs, tiling_slug):
    expected = {**BUILTINS, tiling_slug: 'tiling'}
    if tiling_slug in BUILTINS or len(expected) != 3:
        raise ValueError('Tiling coverage needs a separate qualification Blueprint')
    selected = [row for row in rows if row['slug'] in expected]
    if len(selected) != 3 or {row['slug'] for row in selected} != set(expected):
        raise ValueError('Required Standard, Dock, and explicit Tiling qualification Blueprints are missing or duplicated')
    result = []
    for row in selected:
        slug = row['slug']
        metadata = row['metadata_json']
        builtin = slug in BUILTINS
        if (metadata.get('built_in') is True) != builtin:
            raise ValueError('Qualification fixture must not masquerade as a built-in')
        if builtin and metadata.get('blueprint_type') != 'builtin_profile':
            raise ValueError('Unsupported built-in Blueprint contract')
        if type(row['current_revision']) is not int or row['current_revision'] <= 0:
            raise ValueError('Qualification requires a positive released current revision')
        for field in ('id', 'current_revision_id'):
            if str(uuid.UUID(row[field])) != row[field]:
                raise ValueError('Qualification requires canonical Blueprint/revision IDs')
        config = configs[slug]
        if (config['blueprint_id'] != row['id'] or
                config['blueprint_revision_id'] != row['current_revision_id']):
            raise ValueError('Blueprint revision changed while capturing qualification catalog')
        if not isinstance(config.get('config_hash'), str) or not re.fullmatch('[0-9a-f]{64}', config['config_hash']):
            raise ValueError('Qualification requires an exact effective configuration digest')
        checks = config['expected_state_json']['checks']
        profiles = {check['expected']['desktop_profile'] for check in checks
                    if check['id'] == 'desktop.profile'}
        if profiles != {expected[slug]}:
            raise ValueError('Qualification Blueprint does not cover its required desktop')
        if not builtin:
            apps = {app['package_ref'] for app in config['expected_state_json']['applications']}
            if 'deno' not in apps or 'nodejs' in apps:
                raise ValueError('Tiling qualification must retain Deno/source-free application coverage')
        result.append({key: row[key] for key in
                       ('id', 'slug', 'current_revision', 'current_revision_id')}
                      | {'desktop_profile': expected[slug], 'config_hash': config['config_hash']})
    return {'schema': 'cybex.james.qualification-blueprints.v1',
            'blueprints': sorted(result, key=lambda row: row['slug'])}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Qualification API redirect refused')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manage-origin', required=True)
    parser.add_argument('--token-file', type=Path, required=True)
    parser.add_argument('--tiling-blueprint', default='qualification_tiling')
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--state-dir', type=Path)
    args = parser.parse_args()
    origin = args.manage_origin
    parsed = urllib.parse.urlsplit(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
            parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise ValueError('Qualification requires a canonical HTTPS origin')
    if args.state_dir:
        from isolated_fixture import API
        api = API(args.state_dir)
        if api.origin != origin:
            raise ValueError('Blueprint origin differs from its owned fixture')
        get = api
    else:
        from isolated_fixture import SCOPE
        SCOPE['development_origin'](origin)
        token = args.token_file.read_text().strip()
        if not token or '\n' in token or '\r' in token:
            raise ValueError('Invalid private qualification session')
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

        def get(path):
            request = urllib.request.Request(origin + path, headers={'Authorization': 'Bearer ' + token,
                                                                      'User-Agent': 'cybex-dev-qualification/1'})
            return HTTP['request_json'](client, request, timeout=10,
                                        max_bytes=2 * 1024 * 1024)

    rows = []
    while True:
        page = get('/v1/blueprints?platform=nixos&limit=100&offset=' + str(len(rows)))['blueprints']
        rows.extend(page)
        if len(page) < 100:
            break
        if len(rows) >= 10000:
            raise ValueError('Qualification catalog exceeds the supported bound')
    configs = {row['slug']: get('/v1/blueprints/' + str(uuid.UUID(row['id'])) + '/config')
               for row in rows if row['slug'] in {*BUILTINS, args.tiling_blueprint}}
    value = catalog(rows, configs, args.tiling_blueprint)
    if args.baseline and value != json.loads(args.baseline.read_text()):
        raise ValueError('Qualification Blueprint revisions or effective configuration changed; restart admission')
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        raise SystemExit('Blueprint qualification admission failed: ' + str(error)) from None
