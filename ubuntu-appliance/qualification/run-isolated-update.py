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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--predecessor-evidence', type=Path, required=True)
    parser.add_argument('--candidate-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rollback', action='store_true')
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
            fixture.wait_ready(api)
            if args.rollback:
                rollback_lifecycle.run(api, fixture, args.candidate_manifest, args.predecessor_evidence, transport, args.output)
            else:
                command = ['bash', str(HELPERS / 'run-update-lifecycle.sh'), '--predecessor-evidence', str(args.predecessor_evidence),
                    '--candidate-manifest', str(args.candidate_manifest), '--qualification-package-transport-url', transport,
                    '--manage-origin', 'https://manage.cybex.net', '--token-file', str(state / 'session'),
                    '--server-device-id', fixture.device, '--output', str(args.output)]
                temporary = state / 'temporary'
                temporary.mkdir(mode=0o700, exist_ok=True)
                subprocess.run(command, env={**os.environ, 'TMPDIR': str(temporary),
                    'CYBEX_UPDATE_QUALIFICATION_TTL_SECONDS': '3600'}, check=True)
    finally:
        stop(server)
        port_file.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
