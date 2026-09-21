#!/usr/bin/env python3
"""Serial qualification admission/timing and warm predecessor transport cache.

Execution requires a separately scheduled disposable development fixture. This
wrapper grants no network, release, signing or publication authority.
"""
import argparse
import contextlib
import os
from pathlib import Path
import re
import subprocess
import sys

import release_speed_cache as cache
import release_speed_io as io
import release_speed_resources as resources
import release_speed_timing as timing

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / 'nixos-appliance/qualification'
WARM = ('cybex-james-nixos-qualification.json', 'cybex-james-nixos-update-qualification.json',
        'cybex-james-nixos-rollback-qualification.json', 'cybex-james-qualified-predecessor.json',
        'cybex-james-qualified-predecessor-release.json')
COLD = ('cybex-james-published-cold-qualification.json', 'cybex-james-published-workstation-qualification.json')


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError('Invalid arguments; consult --help')


def parser():
    result = Parser(description=__doc__, allow_abbrev=False)
    sub = result.add_subparsers(dest='command', required=True, parser_class=Parser)
    for command in ('plan', 'run'):
        p = sub.add_parser(command, allow_abbrev=False)
        for name in ('profile', 'candidate-dir', 'evidence-dir', 'timing-dir'):
            p.add_argument('--' + name, type=Path, required=True)
        p.add_argument('--predecessor-dir', type=Path)
        for name in ('candidate-manifest-sha256', 'source', 'run', 'attempt', 'trusted-public-key'):
            p.add_argument('--' + name, required=True)
        p.add_argument('--predecessor-manifest-sha256')
        p.add_argument('--phase', choices=('warm', 'cold'), required=True)
        p.add_argument('--candidate-only', action='store_true')
        p.add_argument('--offline-artifacts', action='store_true')
        p.add_argument('--parallelism', type=int, choices=(1,), default=1)
        p.add_argument('--timeout', type=int, default=14400)
        for name in ('manage-origin', 'subnet'):
            p.add_argument('--' + name, required=True)
        for name in ('token-file', 'state-root', 'allow-device-helper', 'manage-checkout'):
            p.add_argument('--' + name, type=Path, required=True)
    for command in ('cache', '_cache'):
        p = sub.add_parser(command, allow_abbrev=False)
        p.add_argument('--mode', choices=('github-warm', 'candidate-only'), required=True)
        for name in ('cache-root', 'directory', 'predecessor-dir', 'expected-identity', 'authorization', 'timing-dir'):
            p.add_argument('--' + name, type=Path, required=True)
        for name in ('repository', 'candidate-version', 'trusted-public-key', 'predecessor-manifest-sha256'):
            p.add_argument('--' + name, required=True)
        p.add_argument('--max-bytes', type=int, default=32 * 1024**3)
    return result


def metadata(args):
    if (not re.fullmatch('[0-9a-f]{40}', args.source)
            or not re.fullmatch('[a-z0-9][a-z0-9-]{0,22}', args.run)
            or not re.fullmatch('[1-9][0-9]{0,8}', args.attempt)
            or not 1 <= args.timeout <= 28800):
        raise ValueError('Invalid immutable run identity')
    source = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    if source != args.source or subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True).strip():
        raise ValueError('Exact clean source required')
    value = resources.profile(args.profile, args.phase)
    if args.subnet != value['subnet']:
        raise ValueError('Subnet is outside the explicit resource profile')
    p = cache.verifier()
    candidate = p.verify_pair_snapshot(args.candidate_dir, args.trusted_public_key)
    if (io.digest(candidate['manifest_body']) != args.candidate_manifest_sha256
            or candidate['manifest']['appliance_release_v1']['source_revision'] != args.source
            or candidate['manifest']['installer_iso_template_v3']['manage_origin'] != args.manage_origin):
        raise ValueError('Candidate identity changed')
    # Do not infer development permission from a manifest or profile.
    from urllib.parse import urlsplit
    origin = urlsplit(args.manage_origin)
    if (origin.scheme != 'https' or not origin.hostname or not origin.hostname.startswith('dev.')
            or args.manage_origin != 'https://' + origin.hostname):
        raise ValueError('Explicit canonical development origin required')
    if args.phase == 'warm':
        if args.predecessor_dir is None or args.predecessor_manifest_sha256 is None:
            raise ValueError('Warm qualification requires an exact predecessor')
        previous = p.verify_pair_snapshot(args.predecessor_dir, args.trusted_public_key)
        if (io.digest(previous['manifest_body']) != args.predecessor_manifest_sha256
                or previous['manifest']['installer_iso_template_v3']['manage_origin'] != args.manage_origin):
            raise ValueError('Predecessor identity changed')
        p.advance(candidate['manifest']['version'], previous['manifest']['version'])
    elif args.predecessor_dir is not None or args.candidate_only:
        raise ValueError('Cold mode requires the independent published-download workflow')
    return value


def delegate(args):
    command = [sys.executable, '-B', str(HELPERS / 'run-production-qualification.py')]
    for name in ('run', 'candidate_dir', 'evidence_dir', 'trusted_public_key', 'manage_origin',
                 'token_file', 'subnet', 'state_root', 'allow_device_helper', 'manage_checkout'):
        command += ['--' + name.replace('_', '-'), str(getattr(args, name))]
    command += (['--predecessor-dir', str(args.predecessor_dir)] if args.phase == 'warm' else ['--published-cold'])
    return command


def acceptance(args, stdout, stderr):
    required = WARM if args.phase == 'warm' else COLD
    actual = {p.name for p in args.evidence_dir.glob('cybex-james-*.json')}
    if actual != set(required):
        raise ValueError('Incomplete or mixed output inventory')
    for name in required:
        io.load(args.evidence_dir / name)  # bounded, no links or duplicate members
    if io.digest(io.read(args.candidate_dir / 'cybex-james-release.json')) != args.candidate_manifest_sha256:
        raise ValueError('Candidate changed during execution')
    base = [sys.executable, '-B', str(HELPERS / 'release_acceptance.py'), '--source', args.source,
            '--manifest', str(args.candidate_dir / 'cybex-james-release.json')]
    commands = []
    if args.phase == 'warm':
        p = cache.verifier()
        previous_path = args.evidence_dir / WARM[4]
        if io.digest(io.read(previous_path)) != args.predecessor_manifest_sha256:
            raise ValueError('Predecessor output changed')
        snap = p.verify_pair_snapshot(args.predecessor_dir, args.trusted_public_key)
        if io.digest(snap['manifest_body']) != args.predecessor_manifest_sha256:
            raise ValueError('Predecessor input changed')
        identity = p.identity(args.predecessor_dir, snap['manifest'], schema='cybex.james.nixos-qualification-predecessor.v1')
        if io.read(args.evidence_dir / WARM[3]) != p.canonical(identity):
            raise ValueError('Predecessor receipt changed')
        commands.append(base + ['--phase', 'prepublication', '--evidence', str(args.evidence_dir / WARM[0])])
        for phase, name in zip(('update', 'rollback'), WARM[1:3]):
            commands.append(base + ['--phase', phase, '--evidence', str(args.evidence_dir / name),
                                    '--predecessor-manifest', str(previous_path)])
    else:
        commands.append(base + ['--phase', 'cold', '--evidence', str(args.evidence_dir / COLD[0]),
                                '--workstation', str(args.evidence_dir / COLD[1])])
    for command in commands:
        subprocess.run(command, check=True, stdout=stdout, stderr=stderr)


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command in {'cache', '_cache'}:
        if args.mode != 'github-warm':
            raise ValueError('Candidate-only cache execution lacks a no-fetch facade')
        if args.command == '_cache':
            facts = cache.warm(args)
            io.write(args.timing_dir / 'cache-result.json', io.canonical(facts))
            return
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '_cache', *(argv or sys.argv[1:])[1:]]
        timing.measure(command, args.timing_dir, 'cache', {
            'source_sha256': cache.source_digest(), 'manifest_sha256': args.predecessor_manifest_sha256,
            'profile_sha256': io.digest(io.canonical({'max_bytes': args.max_bytes}))}, 7200,
            facts=lambda: io.load(args.timing_dir / 'cache-result.json'))
        print('Warm transport snapshot verified')
        return
    with open(os.devnull, 'w') as quiet, contextlib.redirect_stdout(quiet):
        value = metadata(args)
    if args.command == 'plan':
        # Metadata admission is not payload verification, scheduling or approval.
        print(io.canonical({'execution_ready': False, 'phase': args.phase, 'parallelism': 1,
            'scenario_order': ['update', 'rollback', 'fresh'] if args.phase == 'warm' else ['cold', 'workstation'],
            'reason': 'requires_scheduled_execution_and_full_runner_admission'}).decode(), end='')
        return
    if args.offline_artifacts:
        raise ValueError('Current runner cannot guarantee no-fetch artifact admission')
    if os.geteuid() != 0:
        raise ValueError('Existing qualification runner requires root')
    for path in (args.candidate_dir, args.state_root, args.evidence_dir.parent, args.timing_dir.parent):
        io.directory(path)
    if args.phase == 'warm':
        io.directory(args.predecessor_dir)
    if args.evidence_dir.exists() or args.evidence_dir.is_symlink():
        raise ValueError('Fresh evidence directory required')
    identity = {'source_sha256': io.digest(args.source.encode()),
        'manifest_sha256': args.candidate_manifest_sha256,
        'profile_sha256': io.digest(io.read(args.profile)),
        'run_sha256': io.digest(io.canonical({'run': args.run, 'attempt': args.attempt}))}
    # The unchanged runner uses SUDO_UID/GID to hand output to its caller.
    # This wrapper owns acceptance: retain its private evidence directory until
    # acceptance finishes. Any later artifact export is a separate operation.
    environment = dict(os.environ)
    environment.pop('SUDO_UID', None)
    environment.pop('SUDO_GID', None)
    with resources.admission(value, identity, args.state_root):
        args.evidence_dir.mkdir(mode=0o700)
        timing.measure(delegate(args), args.timing_dir, args.phase, identity, args.timeout,
            accept=lambda out, err: acceptance(args, out, err), env=environment)
    print('Serial runner and mandatory acceptance completed')


if __name__ == '__main__':
    try:
        main()
    except timing.RunFailed as error:
        timing.exit_status(error.code)
    except Exception:
        # Raw diagnostics, origins and argument values never reach public output.
        print('Release-speed admission or verification failed', file=sys.stderr)
        raise SystemExit(65) from None
