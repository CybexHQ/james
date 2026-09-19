#!/usr/bin/env python3
"""Qualify immutable release bytes using disposable production-image databases.

Each phase owns its database, sessions, VM disk and credentials. Production is
only a logical backup source. The official fresh-install and upgrade assertions
remain the publication gate; a separate real failure exercises root rollback.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

import release_predecessor as predecessor

HELPERS = Path(__file__).resolve().parent
OWNER = '/opt/cybex-james-qualification/isolated-manage.py'
STATE = Path('/var/lib/cybex-james-qualification')


def execute(*args):
    subprocess.run([str(a) for a in args], check=True)


def interrupted(_number, _frame):
    raise KeyboardInterrupt('Qualification interrupted; cleaning up its private state')


def scoped(name, *arguments):
    unit = 'cybex-james-' + name + '.scope'
    try:
        execute('systemd-run', '--scope', '--quiet', '--unit', unit,
                '-p', 'MemoryMax=35G', '-p', 'MemorySwapMax=0', sys.executable, '-B', *arguments)
    finally:
        # Stop this exact cgroup even if the runner receives cancellation while
        # a nested shell, QEMU, or package server owns another process group.
        subprocess.run(['systemctl', 'stop', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--candidate-dir', type=Path, required=True)
    parser.add_argument('--predecessor-dir', type=Path)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--trusted-public-key', required=True)
    parser.add_argument('--published-cold', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch('[a-z0-9][a-z0-9-]{0,39}', args.run):
        raise ValueError('Expected root and a bounded qualification run identity')
    args.candidate_dir = args.candidate_dir.resolve(strict=True)
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    args.evidence_dir = args.evidence_dir.resolve(strict=True)
    manifest_path = args.candidate_dir / predecessor.MANIFEST
    manifest = json.loads(manifest_path.read_bytes())
    candidate_url = f"https://github.com/CybexHQ/james/releases/download/v{manifest['version']}/{predecessor.MANIFEST}"
    predecessor.verify_pair(args.candidate_dir, args.trusted_public_key, candidate_url)
    if manifest['appliance_release_v1']['source_revision'] != subprocess.check_output(['git', '-C', str(HELPERS), 'rev-parse', 'HEAD'], text=True).strip():
        raise ValueError('Candidate must bind the exact qualification checkout')
    if not args.published_cold:
        if args.predecessor_dir is None:
            raise ValueError('This production fleet requires an authenticated predecessor')
        args.predecessor_dir = args.predecessor_dir.resolve(strict=True)
        identity_path = args.candidate_dir / 'cybex-james-build-predecessor.json'
        identity, _ = predecessor.checked_json(identity_path)
        if identity['update_contract'] != 'selective_roots_v2':
            raise ValueError('Disposable production updates require selective_roots_v2; legacy_all_debs still requires its canonical HTTPS package preflight and a separately qualified bridge')
        if predecessor.sha(args.predecessor_dir / predecessor.MANIFEST) != identity['release_manifest_sha256']:
            raise ValueError('Fixture media does not match the built predecessor identity')
        compatibility = json.loads((args.predecessor_dir / predecessor.COMPATIBILITY).read_bytes())
        selected_url = compatibility['release_manifest']['url']
        inputs = args.evidence_dir / 'predecessor-fixture-inputs.json'
        inputs.write_text(json.dumps({'schema': 'cybex.james.resolved-predecessor-fixture.v1',
            'identity': str(identity_path), 'directory': str(args.predecessor_dir),
            'trusted_public_key': args.trusted_public_key, 'candidate_version': manifest['version'],
            'repository': 'CybexHQ/james', 'authorization': str(predecessor.ROOT / 'release/recovery-adoption.json')}))
        execute(sys.executable, HELPERS / 'published-predecessor.py', '--inputs', inputs,
                '--manifest', args.predecessor_dir / predecessor.MANIFEST)
        shutil.copyfile(identity_path, args.evidence_dir / 'cybex-james-qualified-predecessor.json')
        phases = ['upgrade', 'rollback', 'fresh']
    else:
        selected_url = candidate_url
        phases = ['cold']
    lock = open('/run/lock/cybex-james-production-qualification.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    signal.signal(signal.SIGTERM, interrupted)
    for phase in phases:
        name = args.run + '-' + phase
        state = STATE / name
        if state.exists():
            raise ValueError('Prior qualification state requires its owned cleanup before retry')
        execute(sys.executable, '/opt/cybex-james-qualification/host-preflight.py')
        try:
            execute(sys.executable, OWNER, 'prepare', '--run', name, '--manifest-url', selected_url)
            fresh_output = args.evidence_dir / (f'predecessor-{phase}.json' if phase in {'upgrade', 'rollback'}
                else 'cybex-james-ubuntu-qualification.json' if phase == 'fresh' else 'cybex-james-published-cold-qualification.json')
            arguments = ['--state-dir', state, '--manifest',
                args.predecessor_dir / predecessor.MANIFEST if phase in {'upgrade', 'rollback'} else manifest_path,
                '--output', fresh_output]
            if phase in {'upgrade', 'rollback'}:
                arguments += ['--published-predecessor-inputs', inputs, '--retain-fixture', state / 'fixture']
            if phase == 'cold':
                arguments += ['--require-candidate-runtime']
            scoped(name + '-install', HELPERS / 'run-isolated-lifecycle.py', *arguments)
            if phase in {'upgrade', 'rollback'}:
                update_output = args.evidence_dir / ('cybex-james-ubuntu-update-qualification.json' if phase == 'upgrade'
                    else 'cybex-james-ubuntu-rollback-qualification.json')
                arguments = ['--state-dir', state, '--fixture', state / 'fixture',
                    '--predecessor-evidence', fresh_output, '--candidate-manifest', manifest_path, '--output', update_output]
                if phase == 'rollback':
                    arguments.append('--rollback')
                scoped(name + '-update', HELPERS / 'run-isolated-update.py', *arguments)
        finally:
            if (state / 'isolation.json').is_file():
                execute(sys.executable, OWNER, 'cleanup', '--run', name)
            elif state.exists():
                # prepare has not yet created containers without this receipt.
                shutil.rmtree(state)
    if not args.published_cold:
        inputs.unlink()
    print('All requested production qualification phases passed; private fixtures cleaned up')


if __name__ == '__main__':
    main()
