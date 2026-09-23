"""Retire only the Manage identities created by one stopped qualification run."""
import json
import os
from pathlib import Path
import re
import stat
import uuid

from isolated_fixture import SCOPE


def session_receipt(state):
    path = state / 'lifecycle-session.json'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or not 0 < info.st_size <= 4096):
            raise ValueError('qualification session receipt is not private and owned')
        body = os.read(fd, 4097)
        if len(body) != info.st_size:
            raise ValueError('qualification session receipt changed during inspection')
    finally:
        os.close(fd)
    receipt = json.loads(body)
    if not isinstance(receipt, dict) or set(receipt) != {'session_id'}:
        raise ValueError('qualification session receipt has unexpected fields')
    try:
        session_id = str(uuid.UUID(receipt['session_id']))
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError('qualification session receipt has invalid identity') from error
    if receipt['session_id'] != session_id:
        raise ValueError('qualification session receipt is not canonical')
    return session_id


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
