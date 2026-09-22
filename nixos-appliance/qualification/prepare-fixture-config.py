#!/usr/bin/env python3
"""Build the exact disposable Manage images for a signed NixOS candidate.

The root-private template supplies dedicated fixture credentials and pinned database
and TLS images. No live service environment or database is read.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import isolated_manage_config as config
import release_predecessor as predecessor


def run(*args):
    return subprocess.check_output([str(arg) for arg in args], text=True).strip()


def prepare(template, candidate_dir, predecessor_dir, directory):
    if os.geteuid() != 0:
        raise ValueError('fixture configuration requires root-private ownership')
    template = config.ordinary_path(template)
    info = template.parent.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('fixture template directory must be root-private')
    value = config.validate(json.loads(config.read_file(template)))
    if value['manage_origin'] != 'https://manage.cybex.net':
        raise ValueError('production fixture template must name the production artifact origin')
    # Validate dedicated secret material before performing builds. This does not
    # require stale template image IDs or a previous candidate source to exist.
    for field in ('tls_certificate', 'tls_private_key', 'provisioning_seed_file'):
        if config.ordinary_path(value[field]).parent != template.parent:
            raise ValueError('fixture credentials must be dedicated template inputs')
    material = config.key_material(config.read_file(value['provisioning_seed_file']).decode().strip(),
        config.read_file(value['tls_certificate'], private=False), config.read_file(value['tls_private_key']))
    candidate = predecessor.verify_pair_snapshot(candidate_dir, value['release_public_key'])
    previous = predecessor.verify_pair_snapshot(predecessor_dir or candidate_dir, value['release_public_key'])
    revision = candidate['manifest']['appliance_release_v1']['manage_source_revision']
    source = config.ordinary_path(value['manage_checkout'])
    if source == config.PRODUCTION or config.PRODUCTION in source.parents:
        raise ValueError('production checkout cannot supply qualification source')
    command = ['git', '-c', 'safe.directory=' + str(source), '-C', str(source)]
    if run(*command, 'remote', 'get-url', 'origin').removesuffix('.git') != config.SOURCE:
        raise ValueError('qualification source must be the development repository')
    run(*command, 'cat-file', '-e', revision + '^{commit}')
    directory = config.ordinary_path(directory.parent) / directory.name
    directory.mkdir(mode=0o700)  # No adoption or overwriting of an older preparation.
    checkout = directory / 'source'
    subprocess.run(['git', 'clone', '--quiet', '--no-checkout', str(source), str(checkout)], check=True)
    run('git', '-C', checkout, 'remote', 'set-url', 'origin', config.SOURCE)
    run('git', '-C', checkout, 'checkout', '--quiet', '--detach', revision)
    value.update(manage_checkout=str(checkout), manage_revision=revision, initial_release='candidate')
    # The reviewed current Manage source tests both authenticated appliance
    # versions, with each image bound to its corresponding compatibility pin.
    images = {}
    for role, snapshot in (('candidate', candidate), ('predecessor', previous)):
        manifest, asset = snapshot['manifest'], snapshot['compatibility']
        if (manifest['appliance_release_v1']['schema'] != 'cybex.james.appliance-release.v3'
                or manifest['installer_iso_template_v3']['manage_origin'] != value['manage_origin']
                or material['public_key'] not in manifest['installer_iso_template_v3']['provisioning_public_keys']):
            raise ValueError('fixture inputs must be exact-origin signed NixOS releases')
        projection = asset['compatibility_sha256']
        if role == 'predecessor' and projection == candidate['compatibility']['compatibility_sha256']:
            images[role] = images['candidate']
            continue
        tag = 'cybex/qualification-manage:' + revision[:12] + '-' + projection[:12]
        subprocess.run(['docker', 'build', '--build-arg', 'CYBEX_SOURCE_REVISION=' + revision,
            '--build-arg', 'CYBEX_SOURCE_DIRTY=false', '--build-arg', 'CYBEX_RELEASE_GIT_SHA=' + revision,
            '--build-arg', 'CYBEX_BUILD_JAMES_COMPATIBILITY_PROJECTION_SHA256=' + projection,
            '--label', 'org.opencontainers.image.revision=' + revision,
            '--label', 'org.opencontainers.image.source=' + config.SOURCE,
            '--label', 'net.cybex.manage.james-compatibility-projection-sha256=' + projection,
            '-t', tag, str(checkout)], check=True)
        images[role] = run('docker', 'image', 'inspect', '--format', '{{.Id}}', tag)
    value['app_images'] = images
    for field in ('tls_certificate', 'tls_private_key', 'provisioning_seed_file'):
        target = directory / field
        body = config.read_file(value[field], private=field != 'tls_certificate')
        with target.open('xb') as stream:
            stream.write(body)
        target.chmod(0o600)
        value[field] = str(target)
    path = directory / 'config.json'
    path.write_bytes(config.canonical(value))
    path.chmod(0o600)
    config.load(path)
    receipt = {'schema': 'cybex.james.fixture-config-owner.v1', 'directory': str(directory),
               'source_revision': revision,
               'files': {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                         for name in ('config.json', 'tls_certificate', 'tls_private_key', 'provisioning_seed_file')}}
    (directory / 'owner.json').write_bytes(config.canonical(receipt))
    (directory / 'owner.json').chmod(0o600)
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--candidate-dir', type=Path, required=True)
    parser.add_argument('--predecessor-dir', type=Path)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    print(prepare(args.template, args.candidate_dir, args.predecessor_dir, args.directory))
