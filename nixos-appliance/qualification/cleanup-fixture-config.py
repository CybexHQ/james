#!/usr/bin/env python3
"""Remove only an unchanged root-private completed fixture configuration checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import isolated_manage_config as config


def cleanup(directory):
    directory = config.ordinary_path(directory)
    if os.geteuid() != 0 or directory.stat().st_uid != 0 or directory.stat().st_mode & 0o077:
        raise ValueError('fixture config cleanup requires its root-private directory')
    owner = json.loads(config.read_file(directory / 'owner.json'))
    names = {'config.json', 'tls_certificate', 'tls_private_key', 'provisioning_seed_file'}
    if (set(owner) != {'schema', 'directory', 'source_revision', 'files'}
            or owner['schema'] != 'cybex.james.fixture-config-owner.v1'
            or owner['directory'] != str(directory) or set(owner['files']) != names
            or {p.name for p in directory.iterdir()} != names | {'owner.json', 'source'}):
        raise ValueError('fixture config cleanup receipt does not own these inputs')
    for name, digest in owner['files'].items():
        if hashlib.sha256(config.read_file(directory / name)).hexdigest() != digest:
            raise ValueError('fixture config input changed since preparation')
    source = config.ordinary_path(directory / 'source')
    git = ['git', '-C', str(source)]
    if (subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() != owner['source_revision']
            or subprocess.check_output(git + ['status', '--porcelain'])):
        raise ValueError('fixture source changed; retain it for investigation')
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        mount = line.split()[4].replace('\\040', ' ')
        if mount == str(directory) or mount.startswith(str(directory) + '/'):
            raise ValueError('fixture configuration is still mounted')
    shutil.rmtree(source)
    for name in names | {'owner.json'}:
        (directory / name).unlink()
    directory.rmdir()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--directory', type=Path, required=True)
    cleanup(parser.parse_args().directory)
