#!/usr/bin/env python3
"""Qualify update or automatic rollback on one owned development NixOS fixture."""
import argparse
import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid

from isolated_fixture import API, Fixture, HELPERS, SCOPE, private_state, stop
import release_predecessor
import transition_lifecycle
from isolated_manage_rpc import request as fixture_request


def isolated_transport(state, bind, manifest_digest, filename):
    transports = fixture_request(state, 'installer_transports', manifest_sha256=manifest_digest)
    transport = transports['package_transport_url']
    if transport != f'http://{bind}:18082/{filename}':
        raise ValueError('Candidate closure transport differs from the owned verified guest listener')
    return transport


def execute(args):
    # This is the first operation, before admission, listening sockets, or QEMU.
    state = private_state(args.state_dir)
    scope = SCOPE['read_scope'](state)
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('Refusing to replace existing qualification evidence')
    if not args.output.parent.is_dir():
        raise ValueError('Qualification output directory must exist')
    candidate, candidate_body = release_predecessor.checked_json(args.candidate_manifest)
    previous, previous_body = release_predecessor.checked_json(args.predecessor_manifest)
    evidence, evidence_body = release_predecessor.checked_json(args.predecessor_evidence)
    source = subprocess.check_output(['git', '-C', str(HELPERS.parents[1]), 'rev-parse', 'HEAD'], text=True).strip()
    transition_lifecycle.validate_inputs(candidate, hashlib.sha256(candidate_body).hexdigest(), previous,
        hashlib.sha256(previous_body).hexdigest(), evidence, scope['manage_origin'], source)
    artifact = candidate['appliance_release_v1']['system_closure']
    filename = urlsplit(artifact['url']).path.rsplit('/', 1)[-1]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', filename):
        raise ValueError('Candidate system closure filename is unsafe')
    package = args.candidate_manifest.parent / filename
    release_predecessor.check_file(package, artifact['sha256'], artifact['size_bytes'])
    bind = ipaddress.ip_interface(scope['subnet']).ip
    if bind.version != 4 or not bind.is_private or bind.is_loopback:
        raise ValueError('Artifact server must use its owned private bridge address')
    # Constructing Fixture authenticates its disks and clean-install evidence
    # without starting QEMU. API construction validates the private session.
    fixture = Fixture(state, args.fixture, evidence)
    api = API(state)
    lock_fd = os.open(state / 'transition.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    server = None
    port_file = state / ('closure-' + uuid.uuid4().hex + '.port')
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if scope.get('schema') == SCOPE['ISOLATED_SCHEMA']:
            transport = isolated_transport(state, bind, hashlib.sha256(candidate_body).hexdigest(), filename)
        else:
            server = subprocess.Popen([sys.executable, str(HELPERS / 'serve-system-closure.py'),
                '--bind', str(bind), '--file', str(package.resolve()), '--port-file', str(port_file)], start_new_session=True)
            for _ in range(100):
                if port_file.exists():
                    break
                if server.poll() is not None:
                    raise ValueError('Owned system closure server exited')
                time.sleep(.1)
            port = int(port_file.read_text().strip())
            if not 1 <= port <= 65535:
                raise ValueError('Owned system closure server returned an invalid port')
            transport = f'http://{bind}:{port}/{filename}'
        with fixture:
            return transition_lifecycle.run(api, fixture, candidate, candidate_body, previous, previous_body,
                evidence, hashlib.sha256(evidence_body).hexdigest(), transport, args.output, source, args.rollback,
                exercise_admission=getattr(args, 'exercise_admission', False))
    finally:
        stop(server)
        port_file.unlink(missing_ok=True)
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('state-dir', 'fixture', 'predecessor-evidence', 'predecessor-manifest', 'candidate-manifest', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--rollback', action='store_true')
    parser.add_argument('--exercise-admission', action='store_true',
        help='exercise bounded Q07 schedule, hold, lease, and Update now policy')
    execute(parser.parse_args())


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, release_predecessor.release.ReleaseError) as error:
        # API response bodies and private file contents never enter public output.
        message = str(error)
        safe = (message.startswith('Terminal package identity differs: ') and
                message.split(': ', 1)[1] in {'attempt_id', 'target_release', 'status', 'stage',
                    'source_revision', 'system_closure_sha256', 'system_toplevel',
                    'resulting_system_generation'}) or message in {
                'Terminal candidate generation did not advance',
                'Terminal update projection differs', 'Terminal rollback reason differs',
                'Terminal success contains a rollback reason',
                'Terminal permanent identity differs',
                'Appliance report differs from the healthy exact NixOS closure',
                'Qualification preflight differs from the exact predecessor',
                'Permanent device incarnation changed during the transition'}
        detail = ': ' + message if safe else ''
        raise SystemExit('Isolated NixOS transition qualification failed' + detail +
                         '; no acceptance evidence was written') from None
