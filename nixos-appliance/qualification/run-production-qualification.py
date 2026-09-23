#!/usr/bin/env python3
"""Qualify signed releases on newly owned development VMs.

The filename preserves the workflow interface. This runner never reads a
production database, adopts a lab VM, or infers permission from a release URL.
Development runs require explicit credentials and scope. Production-bound artifacts
require the retained isolated Manage owner; live production is never a target.
"""
import argparse
import contextlib
import tempfile
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys

import release_predecessor as predecessor
from isolated_fixture import API, SCOPE
from owned_manage_cleanup import (retry_retire_owned, save_cleanup_receipt,
                                  session_receipt, write_teardown_receipt)

HELPERS = Path(__file__).resolve().parent


def execute(*args, **kwargs):
    child = subprocess.Popen([str(a) for a in args], **kwargs)
    try:
        code = child.wait()
        if code:
            raise subprocess.CalledProcessError(code, str(args[0]))
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=45)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def interrupted(_number, _frame):
    raise KeyboardInterrupt('Qualification interrupted; owned child cleanup remains active')


def copy_private(source, destination):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077
                or not 0 < info.st_size <= 16384 or info.st_uid not in {0, os.geteuid()}):
            raise ValueError('Qualification session must be an owned private ordinary file')
        body = os.read(fd, 16385)
        if len(body) != info.st_size:
            raise ValueError('Qualification session changed during inspection')
        with destination.open('xb') as stream:
            stream.write(body)
        destination.chmod(0o600)
    finally:
        os.close(fd)


def verify_candidate(directory, public_key, origin):
    manifest = predecessor.verify_pair(directory, public_key)
    descriptor = manifest['appliance_release_v1']
    iso = manifest['installer_iso_template_v3']
    if descriptor['schema'] != predecessor.release.appliance_v3.SCHEMA or iso['manage_origin'] != origin:
        raise ValueError('Candidate must be NixOS V3 for this explicit development origin')
    source = subprocess.check_output(['git', '-C', str(HELPERS), 'rev-parse', 'HEAD'], text=True).strip()
    if descriptor['source_revision'] != source:
        raise ValueError('Candidate must bind the exact qualification checkout')
    if subprocess.check_output(['git', '-C', str(HELPERS), 'status', '--porcelain'], text=True).strip():
        raise ValueError('Qualification checkout must be clean and committed')
    for artifact, field in ((descriptor['system_closure'], 'sha256'), (iso, 'template_sha256'),
                            (manifest['workstation_netboot'], 'sha256')):
        name = artifact['url'].rsplit('/', 1)[-1]
        predecessor.check_file(directory / name, artifact[field], artifact['size_bytes'],
                               predecessor.release.INSTALLER_ISO_MAX_BYTES)
    closure = predecessor.release.system_closure.verify_archive(
        directory / predecessor.release.appliance_v3.archive_name(manifest['version']), descriptor,
        public_key, predecessor.release)
    predecessor.release._verify_nixos_source_identity(closure, manifest['workstation_netboot'])
    return manifest


def write_release_inputs(state, selected, manage_checkout, origin):
    """Bind selected fixture bytes separately from the reviewed running harness."""
    manifest, body = predecessor.checked_json(selected)
    descriptor = manifest['appliance_release_v1']
    james_checkout = HELPERS.parents[1]
    inputs = {'schema': 'cybex.qualification-release-inputs.v2',
              'james_repository': str(james_checkout),
              'manage_repository': str(manage_checkout),
              'version': manifest['version'], 'manage_origin': origin,
              'candidate_manifest': str(selected),
              'candidate_manifest_sha256': hashlib.sha256(body).hexdigest(),
              'release_source_revision': descriptor['source_revision'],
              'manage_source_revision': descriptor['manage_source_revision'],
              'nixpkgs_revision': descriptor['nixpkgs_revision'],
              'system_toplevel': descriptor['system_toplevel'],
              'system_closure_sha256': descriptor['system_closure']['sha256']}
    for component in ('james', 'manage'):
        inputs[component + '_revision'] = subprocess.check_output(
            ['git', '-C', inputs[component + '_repository'], 'rev-parse', 'HEAD'], text=True).strip()
    with (state / 'release-inputs.json').open('xb') as stream:
        stream.write(predecessor.canonical(inputs))
        stream.flush()
        os.fsync(stream.fileno())
    (state / 'release-inputs.json').chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--run', required=True)
    parser.add_argument('--candidate-dir', type=Path, required=True)
    parser.add_argument('--predecessor-dir', type=Path)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--trusted-public-key', required=True)
    parser.add_argument('--published-cold', action='store_true')
    parser.add_argument('--isolated-manage-config', type=Path)
    parser.add_argument('--manage-origin', default=os.environ.get('CYBEX_JAMES_QUALIFICATION_MANAGE_ORIGIN'))
    parser.add_argument('--token-file', type=Path, default=os.environ.get('CYBEX_JAMES_QUALIFICATION_TOKEN_FILE'))
    parser.add_argument('--subnet', default=os.environ.get('CYBEX_JAMES_QUALIFICATION_SUBNET'))
    parser.add_argument('--state-root', type=Path, default=os.environ.get('CYBEX_JAMES_QUALIFICATION_STATE_ROOT'))
    parser.add_argument('--allow-device-helper', type=Path, default=os.environ.get('CYBEX_JAMES_QUALIFICATION_ALLOW_DEVICE_HELPER'))
    parser.add_argument('--manage-checkout', type=Path, default=os.environ.get('CYBEX_JAMES_QUALIFICATION_MANAGE_CHECKOUT'))
    args = parser.parse_args()
    if (os.geteuid() != 0 or not re.fullmatch('[a-z0-9][a-z0-9-]{0,22}', args.run)
            or not all((args.manage_origin, args.subnet, args.state_root))
            or not (args.token_file or args.isolated_manage_config)):
        raise ValueError('Root, bounded run ID and explicit development origin/session/subnet/state-root are required')
    if args.isolated_manage_config:
        import isolated_manage_config
        config, _ = isolated_manage_config.load(args.isolated_manage_config)
        if args.manage_origin != 'https://manage.cybex.net' or config['manage_origin'] != args.manage_origin:
            raise ValueError('Production qualification config must bind the exact artifact origin')
        if args.token_file or args.allow_device_helper:
            raise ValueError('Isolated qualification cannot accept an external session or device helper')
    else:
        SCOPE['development_origin'](args.manage_origin)
    if args.allow_device_helper and args.manage_checkout is None:
        raise ValueError('Device admission requires the explicit reviewed development Manage checkout')
    if args.manage_checkout:
        args.manage_checkout = args.manage_checkout.resolve(strict=True)
    os.umask(0o077)
    args.state_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = args.state_root.lstat()
    if (args.state_root.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('Qualification state root must be a root-owned 0700 directory')
    args.candidate_dir = args.candidate_dir.resolve(strict=True)
    signal.signal(signal.SIGTERM, interrupted)
    # A retry must never consume or replace acceptance evidence from another run.
    try:
        args.evidence_dir.mkdir(parents=True, mode=0o700)
    except FileExistsError:
        raise ValueError('Qualification evidence directory already exists; use a new run/attempt directory') from None
    try:
        qualify(args)
    finally:
        # A failed/canceled sudo invocation must not strand a root-owned 0700
        # directory in RUNNER_TEMP. Private files stay private; directory ownership
        # lets the runner remove them without publishing partial acceptance evidence.
        if 'SUDO_UID' in os.environ and 'SUDO_GID' in os.environ:
            os.chown(args.evidence_dir, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']),
                     follow_symlinks=False)


def qualify(args):
    manifest = verify_candidate(args.candidate_dir, args.trusted_public_key, args.manage_origin)
    candidate_manifest = args.candidate_dir / predecessor.MANIFEST
    if not args.published_cold:
        if args.predecessor_dir is None:
            raise ValueError('Every NixOS release needs a separate authenticated NixOS update predecessor')
        args.predecessor_dir = args.predecessor_dir.resolve(strict=True)
        previous = predecessor.qualify(args.predecessor_dir, manifest['version'], args.trusted_public_key)
        previous_manifest = predecessor.checked_json(args.predecessor_dir / predecessor.MANIFEST)[0]
        if previous_manifest['installer_iso_template_v3']['manage_origin'] != args.manage_origin:
            raise ValueError('Predecessor origin must equal the development candidate origin')
        (args.evidence_dir / 'cybex-james-qualified-predecessor.json').write_bytes(predecessor.canonical(previous))
        shutil.copyfile(args.predecessor_dir / predecessor.MANIFEST,
                        args.evidence_dir / 'cybex-james-qualified-predecessor-release.json')
        phases = ['update', 'rollback', 'fresh']
    else:
        phases = ['cold']
    for phase in phases:
        state = args.state_root / (args.run + '-' + phase)
        scope_args = argparse.Namespace(run=state.name, state_dir=state, subnet=args.subnet, manage_origin=args.manage_origin,
                                        isolated_manage=bool(args.isolated_manage_config))
        SCOPE['prepare'](scope_args)
        scope = SCOPE['read_scope'](state)
        successful = False
        resources = contextlib.ExitStack()
        owner = None
        try:
            if args.isolated_manage_config:
                from production_fixture import fixture, stage_artifacts
                staged = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix='jnq-inputs-', dir=args.state_root)))
                candidate_dir = stage_artifacts(args.candidate_dir, staged / 'candidate')
                predecessor_dir = stage_artifacts(args.predecessor_dir, staged / 'predecessor') if not args.published_cold else candidate_dir
                owner = resources.enter_context(fixture(state, args.isolated_manage_config, candidate_dir, predecessor_dir, phase))
            else:
                copy_private(args.token_file, state / 'session')
            environment = dict(os.environ)
            if args.allow_device_helper:
                helper_info = args.allow_device_helper.lstat()
                if (not stat.S_ISREG(helper_info.st_mode) or helper_info.st_uid != 0
                        or helper_info.st_mode & 0o022 or not helper_info.st_mode & 0o100):
                    raise ValueError('Device-admission helper must be an ordinary root-owned protected executable')
                environment['CYBEX_JAMES_QUALIFICATION_ALLOW_DEVICE_HELPER'] = str(args.allow_device_helper)
            selected = args.predecessor_dir / predecessor.MANIFEST if phase in {'update', 'rollback'} else candidate_manifest
            if args.allow_device_helper:
                write_release_inputs(state, selected, args.manage_checkout, args.manage_origin)
            fresh = args.evidence_dir / (f'predecessor-{phase}.json' if phase in {'update', 'rollback'} else
                'cybex-james-nixos-qualification.json' if phase == 'fresh' else 'cybex-james-published-cold-qualification.json')
            command = [sys.executable, '-B', HELPERS / 'run-isolated-lifecycle.py', '--state-dir', state,
                       '--manifest', selected, '--output', fresh]
            if phase in {'update', 'rollback', 'cold'}:
                command += ['--retain-fixture', state / 'fixture']
            if phase in {'update', 'rollback'}:
                (state / 'predecessor-identity.json').write_bytes(predecessor.canonical(previous))
                command += ['--predecessor-identity', state / 'predecessor-identity.json']
            # Isolated fixtures stage authenticated runtime bundles before public
            # publication, so require real delivery against the selected manifest.
            if args.isolated_manage_config or phase == 'cold':
                command += ['--require-candidate-runtime']
            else:
                command += ['--prepublication-candidate']
            execute(*command, env=environment)
            if phase in {'update', 'rollback'}:
                if owner:
                    owner.select_release('candidate')
                command = [sys.executable, '-B', HELPERS / 'run-isolated-update.py', '--state-dir', state,
                    '--fixture', state / 'fixture', '--predecessor-evidence', fresh,
                    '--predecessor-manifest', selected, '--candidate-manifest', candidate_manifest,
                    '--output', args.evidence_dir / f'cybex-james-nixos-{phase}-qualification.json']
                if phase == 'rollback':
                    command += ['--rollback']
                execute(*command, env=environment)
            elif phase == 'cold':
                execute(sys.executable, '-B', HELPERS / 'run-isolated-workstation.py', '--state-dir', state,
                    '--fixture', state / 'fixture', '--james-evidence', fresh, '--manifest', candidate_manifest,
                    '--output', args.evidence_dir / 'cybex-james-published-workstation-qualification.json', env=environment)
            if owner:
                receipt = owner.verify()
                scope_proof = {'schema': 'cybex.james.isolated-qualification.v1',
                               'manage_origin': receipt['manage_origin'],
                               'manage_revision': receipt['source_revision'],
                               'owner': receipt['owner'], 'live_production_access': False}
                evidence_paths = [fresh]
                if phase == 'cold':
                    evidence_paths.append(args.evidence_dir / 'cybex-james-published-workstation-qualification.json')
                for evidence_path in evidence_paths:
                    document = predecessor.checked_json(evidence_path)[0]
                    document['qualification_scope'] = scope_proof
                    evidence_path.write_bytes(predecessor.canonical(document))
            successful = True
        finally:
            if args.isolated_manage_config:
                release_phase(resources, state, args.manage_origin, scope['bridge'])
            else:
                try:
                    resources.close()
                finally:
                    cleanup_phase(state, scope, args.manage_origin, args.allow_device_helper,
                                  manifest['version'] if phase in {'fresh', 'cold'} else previous['release_id'])
            if successful:
                for fixture in (state / 'fixture', state / 'workstation'):
                    if fixture.exists() and not fixture.is_symlink():
                        shutil.rmtree(fixture)
    # Only bounded acceptance documents are made readable to the artifact runner.
    for path in args.evidence_dir.glob('cybex-james-*.json'):
        path.chmod(0o644)
    print('Requested NixOS qualification phases passed; owned VM disks and networks cleaned')


def release_phase(resources, state, origin, bridge):
    try:
        resources.close()
    finally:
        (state / 'session').unlink(missing_ok=True)
        # Exact gate recovery and bridge cleanup must still run if the retained
        # Owner has already failed or gone away during its own cleanup.
        execute(sys.executable, '-B', HELPERS / 'development-scope.py', 'cleanup', '--state-dir', state,
                '--manage-origin', origin, '--bridge', bridge)


def cleanup_phase(state, scope, origin, allow_device_helper, version):
    """Retire only proven external-development identities after owned VM teardown."""
    has_receipt = (state / 'lifecycle-session.json').exists()
    complete = False
    try:
        try:
            if allow_device_helper and (state / 'qualification-allowlist.json').exists():
                execute(allow_device_helper, '--cleanup', '--state-dir', state,
                        '--session-id', session_receipt(state))
            api = API(state) if has_receipt else None
        finally:
            if has_receipt:
                write_teardown_receipt(state, scope, version)
            execute(sys.executable, '-B', HELPERS / 'development-scope.py', 'cleanup', '--state-dir', state,
                    '--manage-origin', origin, '--bridge', scope['bridge'])
        if api is not None:
            receipt = retry_retire_owned(state, scope, version, api)
            save_cleanup_receipt(state, receipt)
        complete = True
    finally:
        # A failed API call retains private auth for the guarded retry command.
        if complete or not has_receipt:
            (state / 'session').unlink(missing_ok=True)


if __name__ == '__main__':
    main()
