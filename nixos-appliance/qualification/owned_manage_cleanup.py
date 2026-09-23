"""Retire only the Manage identities created by one stopped qualification run."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import urllib.request
import uuid

from isolated_fixture import API, HTTP, SCOPE

TEARDOWN_SCHEMA = 'cybex.james.qualification-manage-teardown.v1'


def private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or not 0 < info.st_size <= 4096):
            raise ValueError('qualification ownership receipt is not private and owned')
        body = os.read(fd, 4097)
        if len(body) != info.st_size:
            raise ValueError('qualification ownership receipt changed during inspection')
    finally:
        os.close(fd)
    return json.loads(body)


def session_receipt(state):
    receipt = private_json(state / 'lifecycle-session.json')
    if not isinstance(receipt, dict) or set(receipt) != {'session_id'}:
        raise ValueError('qualification session receipt has unexpected fields')
    try:
        session_id = str(uuid.UUID(receipt['session_id']))
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError('qualification session receipt has invalid identity') from error
    if receipt['session_id'] != session_id:
        raise ValueError('qualification session receipt is not canonical')
    return session_id


def write_teardown_receipt(state, scope, version):
    if SCOPE['read_scope'](state) != scope or not isinstance(version, str) or not version:
        raise ValueError('Manage teardown intent differs from the owned run')
    receipt = {'schema': TEARDOWN_SCHEMA, 'scope': scope, 'version': version,
               'session_id': session_receipt(state)}
    path = state / 'manage-teardown.json'
    body = (json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if path.exists() or path.is_symlink():
        raise ValueError('Manage teardown receipt already exists')
    temporary = state / ('manage-teardown.' + uuid.uuid4().hex)
    try:
        with temporary.open('xb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
        directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def read_teardown_receipt(state):
    scope = SCOPE['read_scope'](state)
    receipt = private_json(state / 'manage-teardown.json')
    if (not isinstance(receipt, dict) or set(receipt) != {'schema', 'scope', 'version', 'session_id'}
            or receipt['schema'] != TEARDOWN_SCHEMA or receipt['scope'] != scope
            or receipt['session_id'] != session_receipt(state)
            or not isinstance(receipt['version'], str) or not receipt['version']):
        raise ValueError('Manage teardown receipt differs from the owned run')
    networks = json.loads(SCOPE['incus']('network', 'list', '--format=json'))
    if any(network.get('name') == scope['bridge'] for network in networks):
        raise ValueError('owned bridge still exists or its name was reused')
    return scope, receipt['version']


class PostTeardownAPI(API):
    """Use retained private auth only with a verified, retired network receipt."""
    def __init__(self, state):
        scope, self.version = read_teardown_receipt(state)
        self.scope = scope
        self.origin = scope['manage_origin']
        self.isolated_state = None

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError('Private credential-bearing redirect refused')

        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        token_file = state / 'session'
        fd = os.open(token_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077 or not 0 < info.st_size <= 16384):
                raise ValueError('retained qualification credential is not private and owned')
            self.token = os.read(fd, 16385).decode().strip()
            if not self.token:
                raise ValueError('retained qualification credential is empty')
        finally:
            os.close(fd)


def retry_retire_owned(state, scope, version, api, attempts=3):
    for attempt in range(attempts):
        try:
            return retire_owned(state, scope, version, api)
        except Exception as error:
            if attempt + 1 == attempts or not HTTP['_transient'](error):
                raise


def retry_after_teardown(state):
    api = PostTeardownAPI(state)
    receipt = retry_retire_owned(state, api.scope, api.version, api)
    save_cleanup_receipt(state, receipt)
    (state / 'session').unlink()
    return receipt


def save_cleanup_receipt(state, receipt):
    path = state / 'manage-cleanup.json'
    if path.exists() or path.is_symlink():
        previous = private_json(path)
        if (previous.get('session_id') != receipt.get('session_id')
                or previous.get('device_id') != receipt.get('device_id')
                or previous.get('action') not in {'revoked', 'decommissioned', 'already_terminal'}):
            raise ValueError('existing Manage cleanup receipt differs from owned identity')
        return
    temporary = state / ('manage-cleanup.' + uuid.uuid4().hex)
    try:
        with temporary.open('xb') as stream:
            stream.write((json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def verify_fixture(state, scope, device_id):
    fixture = state / 'fixture'
    if not fixture.exists() and not fixture.is_symlink():
        return
    if fixture.is_symlink() or not fixture.is_dir() or fixture.stat().st_uid != os.geteuid():
        raise ValueError('qualification fixture directory is not owned')
    path = fixture / 'fixture.json'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or not 0 < info.st_size <= 4096):
            raise ValueError('qualification fixture receipt is not private and owned')
        body = os.read(fd, 4097)
        if len(body) != info.st_size:
            raise ValueError('qualification fixture receipt changed during inspection')
    finally:
        os.close(fd)
    identity = json.loads(body)
    hardware = SCOPE['hardware_identity'](scope, 'appliance')
    if (identity.get('schema') != 'cybex.james.qualification-fixture.v1'
            or identity.get('device_id') != device_id
            or identity.get('bridge') != scope['bridge']
            or any(identity.get(key) != value for key, value in hardware.items())):
        raise ValueError('qualification fixture differs from owned run or device')


def retire_owned(state, scope, version, api):
    """Call the ordinary API only after the owned VM and network are gone."""
    if SCOPE['read_scope'](state) != scope:
        raise ValueError('qualification run ownership changed before Manage cleanup')
    session_id = session_receipt(state)
    session = api('/v1/james/provisioning-sessions/' + session_id)
    expected_mac = SCOPE['hardware_identity'](scope, 'appliance')['mac']
    if (session.get('id') != session_id or session.get('label') != 'release qualification'
            or session.get('release_version') != version
            or session.get('recovery_device') is not None):
        raise ValueError('qualification session does not prove the owned fixture')
    inventory = session.get('inventory')
    if inventory is None:
        if session.get('state') != 'created':
            raise ValueError('claimed qualification session lacks owned hardware inventory')
    else:
        interfaces = inventory.get('ethernet_interfaces') or []
        if (not isinstance(interfaces, list) or len(interfaces) != 1
                or interfaces[0].get('mac') != expected_mac):
            raise ValueError('qualification session MAC differs from owned fixture')
    device_id = session.get('reserved_device_id')
    verify_fixture(state, scope, device_id)
    if device_id is None:
        if session.get('state') in {'created', 'claimed', 'awaiting_approval', 'approved', 'failed'}:
            if session.get('destructive_started_at') is not None:
                raise ValueError('unreserved qualification session started destructive work')
            revoked = api('/v1/james/provisioning-sessions/' + session_id + '/revoke', {})
            if revoked.get('id') != session_id or revoked.get('state') != 'revoked':
                raise ValueError('owned provisioning session revocation was not confirmed')
            return {'session_id': session_id, 'action': 'revoked'}
        if session.get('state') in {'revoked', 'expired'}:
            return {'session_id': session_id, 'action': 'already_terminal'}
        raise ValueError('unreserved qualification session has unexpected state')
    if not re.fullmatch(r'dev_[0-9a-f]{32}', device_id):
        raise ValueError('qualification device identity is invalid')
    if session.get('state') == 'revoked':
        return {'session_id': session_id, 'device_id': device_id, 'action': 'already_terminal'}
    plan = session.get('install_plan') or {}
    if (plan.get('session_id') != session_id or plan.get('reserved_device_id') != device_id
            or plan.get('network_interface', {}).get('mac') != expected_mac
            or plan.get('release_version') != version):
        raise ValueError('qualification install plan does not bind the owned device and MAC')
    device = api('/v1/devices/' + device_id)
    if (device.get('device_id') != device_id or device.get('device_kind') != 'cybex-james'
            or device.get('enrollment_id') != 'jamesprov_' + uuid.UUID(session_id).hex
            or device.get('hostname') != 'james-' + uuid.UUID(session_id).hex[:12]
            or device.get('display_name') != plan.get('display_name')):
        raise ValueError('qualification device does not prove this provisioning session')
    result = api('/v1/devices/' + device_id + '/decommission', {})
    if result != {'status': 'decommissioned'}:
        raise ValueError('owned device decommission was not confirmed')
    revoked = api('/v1/james/provisioning-sessions/' + session_id)
    if (revoked.get('id') != session_id or revoked.get('reserved_device_id') != device_id
            or revoked.get('state') != 'revoked'):
        raise ValueError('owned provisioning session was not revoked with device')
    return {'session_id': session_id, 'device_id': device_id, 'action': 'decommissioned'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('retry',))
    parser.add_argument('--state-dir', required=True, type=Path)
    args = parser.parse_args()
    retry_after_teardown(args.state_dir)
    print('Verified exact owned Manage identity cleanup; retained credential removed')
