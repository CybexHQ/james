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
                evidence, hashlib.sha256(evidence_body).hexdigest(), transport, args.output, source, args.rollback)
    finally:
        stop(server)
        port_file.unlink(missing_ok=True)
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('state-dir', 'fixture', 'predecessor-evidence', 'predecessor-manifest', 'candidate-manifest', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--rollback', action='store_true')
    execute(parser.parse_args())


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, release_predecessor.release.ReleaseError):
        # API response bodies and private file contents never enter public output.
        raise SystemExit('Isolated NixOS transition qualification failed; no acceptance evidence was written') from None
