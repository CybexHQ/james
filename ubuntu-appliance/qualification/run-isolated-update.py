#!/usr/bin/env python3
"""Boot one owned predecessor fixture and qualify an exact signed update."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlsplit

from isolated_fixture import API, Fixture, HELPERS, enter_namespace, private_state, stop
import rollback_lifecycle


def qualify_paths(api, fixture, manifest, evidence, transport, output, temporary, session,
                  rollback_only=False, rollback_output=None):
    if rollback_only and rollback_output is not None:
        raise ValueError('Choose standalone rollback or rollback followed by upgrade')
    fixture.wait_ready(api)
    if rollback_only or rollback_output is not None:
        rollback_lifecycle.run(api, fixture, manifest, evidence, transport,
                               output if rollback_only else rollback_output)
        if rollback_only:
            return
        # run() returns only after checking the real fallback, restored generation
        # zero, identity, Secure Boot, health and retained runtime. The ordinary
        # upgrade harness independently rechecks that predecessor and must still
        # reach generation one; no disk, database or receipt is reset for reuse.
    command = ['bash', str(HELPERS / 'run-update-lifecycle.sh'), '--predecessor-evidence', str(evidence),
        '--candidate-manifest', str(manifest), '--qualification-package-transport-url', transport,
        '--manage-origin', 'https://manage.cybex.net', '--token-file', str(session),
        '--server-device-id', fixture.device, '--output', str(output)]
    temporary.mkdir(mode=0o700, exist_ok=True)
    subprocess.run(command, env={**os.environ, 'TMPDIR': str(temporary),
        'CYBEX_UPDATE_QUALIFICATION_TTL_SECONDS': '3600'}, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--predecessor-evidence', type=Path, required=True)
    parser.add_argument('--candidate-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--rollback', action='store_true')
    mode.add_argument('--rollback-output', type=Path, help='Qualify rollback first, then upgrade the restored fixture')
    parser.add_argument('--namespace', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    state = private_state(args.state_dir)
    enter_namespace(state, args.namespace)
    api = API(state)
    manifest = json.loads(args.candidate_manifest.read_bytes())
    descriptor = manifest['appliance_release_v1']['cybex_repository_snapshot']
    package = args.candidate_manifest.parent / urlsplit(descriptor['url']).path.rsplit('/', 1)[-1]
    with package.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if package.is_symlink() or package.stat().st_size != descriptor['size_bytes'] or digest != descriptor['sha256']:
        raise ValueError('Candidate package differs from signed descriptor')
    evidence = json.loads(args.predecessor_evidence.read_bytes())
    subprocess.run([sys.executable, '/opt/cybex-james-qualification/isolated-manage.py', 'allow-device',
                    '--run', state.name, '--device-id', evidence['device_id']], check=True)
    port_file = state / 'update-package.port'
    port_file.unlink(missing_ok=True)
    server = subprocess.Popen([sys.executable, str(HELPERS / 'serve-package-snapshot.py'),
        '--bind', '10.62.57.1', '--file', str(package), '--port-file', str(port_file)], start_new_session=True)
    try:
        for _ in range(100):
            if port_file.exists():
                break
            if server.poll() is not None:
                raise ValueError('Owned package server exited')
            time.sleep(.1)
        port = int(port_file.read_text().strip())
        transport = f'http://10.62.57.1:{port}/{package.name}'
        with Fixture(state, args.fixture, evidence) as fixture:
            qualify_paths(api, fixture, args.candidate_manifest, args.predecessor_evidence,
                          transport, args.output, state / 'temporary', state / 'session',
                          args.rollback, args.rollback_output)
    finally:
        stop(server)
        port_file.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
