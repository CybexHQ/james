"""Private Q03 assertions around the ordinary retry and disk-approval API."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import time

from isolated_fixture import API, QMP, private_state, SCOPE

HELPERS = Path(__file__).resolve().parent
fingerprint = runpy.run_path(str(HELPERS / 'disk-fingerprint.py'))['fingerprint']


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 1024 * 1024):
            raise ValueError('Q03 input must be a private owned ordinary file')
        return json.loads(stream.read(1024 * 1024 + 1))


def save(path, value):
    body = json.dumps(value, sort_keys=True).encode() + b'\n'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body); stream.flush(); os.fsync(stream.fileno())


def timestamp(value):
    parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Q03 timestamps must include a timezone')
    return parsed


def wait_session(api, session_id, desired, timeout=300, heartbeat_after=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        session = api('/v1/james/provisioning-sessions/' + session_id)
        if session.get('id') != session_id:
            raise ValueError('Q03 observed a different provisioning session')
        fresh = heartbeat_after is None or (session.get('heartbeat_at') is not None
                and timestamp(session['heartbeat_at']) > timestamp(heartbeat_after))
        if session.get('state') == desired and fresh: return session
        if session.get('state') in {'revoked', 'expired', 'ready'} or session.get('destructive_started_at'):
            raise ValueError('Q03 passed the expected nondestructive boundary')
        time.sleep(1)
    raise ValueError('Q03 expected session state was not observed')


def unchanged_session(session, initial):
    for field in ('id', 'release_version', 'reserved_device_id', 'inventory_sha256'):
        if session.get(field) != initial.get(field):
            raise ValueError('Q03 session, reserved identity or hardware inventory changed')
    if session.get('destructive_started_at') is not None:
        raise ValueError('Q03 failure occurred after destructive work')


def failed_before_writes(session, initial, expected_disk, actual_disk, responses):
    unchanged_session(session, initial)
    progress = session.get('progress', [])
    if (session.get('state') != 'failed' or session.get('failure_code') != 'system_closure_verification_failed'
            or session.get('install_plan', {}).get('id') != initial['install_plan']['id']
            or expected_disk != actual_disk or len(progress) != 1
            or progress[0].get('sequence') != 1 or progress[0].get('status') != 'failed'
            or progress[0].get('stage') != 'system_closure_verification_failed'):
        raise ValueError('Q03 did not prove the induced closure failure before all disk writes')
    valid = [r for r in responses if r.get('mode') == 'corrupt' and r.get('complete') is True
             and r.get('bytes') == initial['install_plan']['appliance_release']['system_closure']['size_bytes']
             and r.get('original_sha256') == initial['install_plan']['appliance_release']['system_closure']['sha256']
             and r.get('response_sha256') != r.get('original_sha256')]
    if not valid: raise ValueError('Q03 has no complete corrupted response from the exact original artifact')
    return valid[-1]


def validate_new_plan(session, initial):
    unchanged_session(session, initial)
    before, after = initial['install_plan'], session.get('install_plan') or {}
    if session.get('state') != 'approved' or before['id'] == after.get('id'):
        raise ValueError('Q03 retry did not allocate a new approved plan')
    for field in ('session_id', 'reserved_device_id', 'inventory_sha256', 'hardware_digest',
                  'target_disk_id', 'target_disk', 'network_interface', 'release_version',
                  'package_delivery', 'appliance_release', 'package_transport_url'):
        if before.get(field) != after.get(field):
            raise ValueError('Q03 retry altered approved hardware, identity or signed delivery')
    if after.get('schema') != 'cybex.james.install-plan.v3' or after.get('plan_revision', 0) <= before['plan_revision']:
        raise ValueError('Q03 retry did not advance the exact V3 attempt')


def begin(args, api):
    initial = read(args.initial)
    session = wait_session(api, args.session_id, 'failed')
    monitor = QMP(args.qmp)
    try:
        monitor.call('stop')
        if monitor.call('query-status')['running']:
            raise ValueError('Q03 disk inspection requires a stopped guest')
        actual_disk = fingerprint(args.disk)
        # Re-fetch while paused to fence a retry or other operator change.
        session = api('/v1/james/provisioning-sessions/' + args.session_id)
        responses = [json.loads(line) for line in args.responses.read_text().splitlines()]
        corruption = failed_before_writes(session, initial, args.disk_digest, actual_disk, responses)
        device = api('/v1/devices/' + session['reserved_device_id'])
        key = device['public_key_fingerprint']
        if not re.fullmatch('[0-9a-f]{64}', key): raise ValueError('Q03 provisioning identity fingerprint invalid')
        retry = api('/v1/james/provisioning-sessions/' + args.session_id + '/retry',
                    {'session_revision': session['session_revision']})
        unchanged_session(retry, initial)
        if (retry.get('state') != 'awaiting_approval' or retry.get('install_plan') is not None
                or retry.get('progress') != [] or retry['session_revision'] <= session['session_revision']):
            raise ValueError('Console retry failed to retire the old attempt safely')
        save(args.receipt, {'schema': 'cybex.james.nixos-preflight-retry-attempt.v1',
             'session_id': args.session_id, 'device_id': session['reserved_device_id'],
             'old_plan_id': initial['install_plan']['id'], 'failure_revision': session['session_revision'],
             'retry_revision': retry['session_revision'], 'provisioning_key_fingerprint': key,
             'disk_digest_before': args.disk_digest, 'disk_digest_after_failure': actual_disk,
             'personalized_iso_sha256': sha256(args.iso), 'corrupt_response': corruption,
             'failure_code': session['failure_code']})
        # The shell now kills this exact paused QEMU process, preserves the ISO,
        # disk and firmware variables, and boots the same hardware afresh.
    finally:
        monitor.socket.close()


def approve(args, api):
    initial = read(args.initial); receipt = read(args.receipt)
    session = wait_session(api, args.session_id, 'awaiting_approval', heartbeat_after=args.restarted_at)
    unchanged_session(session, initial)
    if (session['session_revision'] != receipt['retry_revision']
            or sha256(args.iso) != receipt['personalized_iso_sha256']
            or fingerprint(args.disk) != receipt['disk_digest_before']):
        raise ValueError('Q03 fresh same-ISO heartbeat changed its revision, media or disk')
    device = api('/v1/devices/' + receipt['device_id'])
    if device['public_key_fingerprint'] != receipt['provisioning_key_fingerprint']:
        raise ValueError('Q03 provisioning key changed during retry')
    body = read(args.approval)
    body['session_revision'] = session['session_revision']
    body['inventory_sha256'] = session['inventory_sha256']
    if body.get('recover_device_id') is not None or body['target_disk_id'] != initial['install_plan']['target_disk_id']:
        raise ValueError('Q03 reapproval cannot recover or substitute a device/disk')
    monitor = QMP(args.qmp)
    try:
        monitor.call('stop')
        if monitor.call('query-status')['running']: raise ValueError('Q03 reapproval requires a paused guest')
        approved = api('/v1/james/provisioning-sessions/' + args.session_id + '/approve', body)
        validate_new_plan(approved, initial)
        save(args.reapproved, {**approved, '_qualification_restart': {
            'started_at': args.restarted_at, 'heartbeat_at': session['heartbeat_at']}})
        # Initial root callback already owns this same reserved ID. A retry
        # neither allocates nor appends a second allowlist ID.
        args.control.write_text('clean\n')
        monitor.call('cont')
        if not monitor.call('query-status')['running']: raise ValueError('Q03 retry guest did not resume')
    finally:
        monitor.socket.close()


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''): digest.update(block)
    return digest.hexdigest()


def complete(args, api):
    receipt, approved, lifecycle = read(args.receipt), read(args.reapproved), read(args.lifecycle)
    session = api('/v1/james/provisioning-sessions/' + args.session_id)
    device = api('/v1/devices/' + receipt['device_id'])
    if (session.get('state') != 'ready' or session.get('reserved_device_id') != receipt['device_id']
            or session.get('install_plan', {}).get('id') != approved['install_plan']['id']
            or lifecycle.get('ok') is not True or lifecycle.get('final_state') != 'ready'
            or lifecycle.get('device_id') != receipt['device_id'] or lifecycle.get('session_id') != args.session_id
            or lifecycle.get('personalized_sha256') != receipt['personalized_iso_sha256']
            or not re.fullmatch('[0-9a-f]{64}', device['public_key_fingerprint'])
            or device['public_key_fingerprint'] == receipt['provisioning_key_fingerprint']):
        raise ValueError('Q03 retry did not reach Ready on the same media and reserved device')
    responses = [json.loads(line) for line in args.responses.read_text().splitlines()]
    restart = approved['_qualification_restart']
    if timestamp(restart['heartbeat_at']) <= timestamp(restart['started_at']):
        raise ValueError('Q03 authenticated heartbeat did not follow the owned same-ISO restart')
    closure = approved['install_plan']['appliance_release']['system_closure']
    if not any(r.get('mode') == 'clean' and r.get('complete') is True and r.get('bytes') == closure['size_bytes']
               and r.get('response_sha256') == closure['sha256'] == r.get('original_sha256') for r in responses):
        raise ValueError('Q03 did not restore and serve the exact signed closure')
    save(args.output, {**receipt, 'schema': 'cybex.james.nixos-preflight-retry-qualification.v1', 'ok': True,
         'new_plan_id': approved['install_plan']['id'], 'new_plan_sha256': approved['install_plan']['plan_sha256'],
         'permanent_key_fingerprint': device['public_key_fingerprint'], 'same_iso_restarted': True,
         'restart_started_at': restart['started_at'], 'post_restart_heartbeat_at': restart['heartbeat_at'],
         'disk_unchanged_after_failure': True, 'same_reserved_device': True, 'new_disk_approval': True,
         'signed_transport_restored': True, 'qualified_manifest_sha256': lifecycle['qualified_manifest_sha256'],
         'system_closure_sha256': closure['sha256'], 'system_toplevel': lifecycle['system_toplevel'],
         'system_generation': lifecycle['system_generation'], 'harness_revision': lifecycle['harness_revision'],
         'fault_helper_sha256': sha256(Path(__file__)), 'fault_server_sha256': sha256(HELPERS / 'serve-faulted-closure.py'),
         'lifecycle_helper_sha256': sha256(HELPERS / 'run-lifecycle.sh'),
         'final_state': 'ready'})


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('action', choices=['begin', 'approve', 'complete'])
    for name in ('state-dir', 'session-id'):
        parser.add_argument('--' + name, required=True, type=Path if name == 'state-dir' else str)
    for name in ('initial', 'qmp', 'disk', 'iso', 'responses', 'receipt', 'approval', 'reapproved', 'control', 'lifecycle', 'output'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--disk-digest')
    parser.add_argument('--restarted-at')
    args = parser.parse_args()
    required = {'begin': ['initial', 'qmp', 'disk', 'iso', 'responses', 'receipt', 'disk_digest'],
                'approve': ['initial', 'qmp', 'disk', 'iso', 'receipt', 'approval', 'reapproved', 'control', 'restarted_at'],
                'complete': ['receipt', 'reapproved', 'lifecycle', 'responses', 'output']}[args.action]
    if any(getattr(args, key) is None for key in required): parser.error('missing action-specific arguments')
    state = private_state(args.state_dir)
    if read(state / 'lifecycle-session.json') != {'session_id': args.session_id}:
        raise ValueError('Q03 session is not owned by this private scope')
    for key in required:
        path = getattr(args, key)
        if key == 'lifecycle':
            # Read-only private evidence may be in the runner's separate output
            # directory; complete binds its exact session/device/media identities.
            continue
        if isinstance(path, Path) and (path.is_symlink() or not path.resolve().is_relative_to(state)):
            raise ValueError('Q03 paths must remain inside the owned private scope')
    api = API(state)
    {'begin': begin, 'approve': approve, 'complete': complete}[args.action](args, api)


if __name__ == '__main__': main()
