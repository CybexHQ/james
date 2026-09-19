"""Exercise automatic rollback after losing the candidate's managed network."""
import base64
import datetime
import hashlib
import json
import time
import uuid


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(node):
    network = node['appliance_network']
    return {k: node[k] for k in ('device_id', 'hostname', 'public_base_url', 'cache_public_key_fingerprint', 'cache_base_url')} | {
        'managed_interface_id': network['managed_interface_id'],
        'macs': sorted(v['address'].lower() for v in network['interfaces'] if v['ifname'] != 'lo')}


def runtime_identity(runtime):
    fields = ('compatibility_epoch', 'runtime_version', 'bundle_sha256', 'architecture', 'manage_source_revision')
    active = {k: runtime['active'][k] for k in fields}
    if runtime['state'] != 'ready' or active != {k: runtime['desired'][k] for k in fields}:
        raise ValueError('Predecessor runtime is not ready and converged')
    return active


def verify_rollback(before, after, attempt, candidate):
    package = after['appliance_package_update']
    if (after['update_status'] != 'rolled_back' or after['update_attempt_id'] != attempt
            or after['update_target_version'] != candidate
            or after['appliance_release'] != before['appliance_release']
            or after['ubuntu_snapshot_id'] != before['ubuntu_snapshot_id']
            or str(after['root_generation']) != '0'
            or package['status'] != 'rolled_back' or package['attempt_id'] != attempt
            or package['target_release'] != candidate or str(package['resulting_root_generation']) != '0'
            or package['rollback_reason'] != 'candidate_boot_failed'
            or after['appliance_local_health']['status'] != 'healthy'
            or after['appliance_secure_boot'] is not True
            or after['network_fallback_active'] is not False
            or identity(before) != identity(after)):
        raise ValueError('Rollback did not preserve the healthy signed predecessor and device identity')


def run(api, fixture, manifest_path, evidence_path, transport_url, output):
    manifest = json.loads(manifest_path.read_bytes())
    before = fixture.wait_ready(api)
    device = fixture.device
    prefix = f'/v1/james/nodes/{device}'
    preflight = api(prefix + '/qualification-updates')
    runtime = runtime_identity(api(prefix + '/workstation-netboot'))
    expected = {k: preflight[k] for k in ('device_incarnation_id', 'current_release', 'ubuntu_snapshot_id', 'root_generation')}
    expected['root_generation'] = str(expected['root_generation'])
    if expected['root_generation'] != '0' or expected['current_release'] != before['appliance_release']:
        raise ValueError('Rollback test requires an unchanged clean predecessor')
    request_id = str(uuid.uuid4())
    expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    request = {'request_id': request_id, 'expires_at': expires, 'expected': expected, 'candidate': {
        'release_manifest_json_b64': base64.b64encode(manifest_path.read_bytes()).decode(),
        'release_manifest_sha256': sha(manifest_path), 'package_transport_url': transport_url}}
    admission = api(prefix + '/qualification-updates', request)
    attempt = admission['attempt_id']
    if admission['manifest_sha256'] != sha(manifest_path) or admission['request_id'] != request_id:
        raise ValueError('Exact rollback candidate admission changed')
    deadline = time.monotonic() + 3600
    disconnected_at = None
    restored_at = None
    observations = []
    last = None
    try:
        while time.monotonic() < deadline:
            if fixture.process.poll() is not None:
                raise ValueError('Rollback fixture unexpectedly exited')
            for event in fixture.monitor.events():
                if event.get('event') != 'RESET':
                    continue
                if disconnected_at is None:
                    fixture.monitor.call('set_link', {'name': 'nic0', 'up': False})
                    disconnected_at = time.monotonic()
                    print('Candidate reboot observed; disconnected only the disposable fixture NIC', flush=True)
                elif restored_at is None:
                    if time.monotonic() - disconnected_at < 180:
                        raise ValueError('Unexpected reboot before candidate health deadline')
                    fixture.monitor.call('set_link', {'name': 'nic0', 'up': True})
                    restored_at = time.monotonic()
                    print('Automatic fallback reboot observed; restored fixture NIC', flush=True)
            node = api(prefix)['node']
            observed = {k: node.get(k) for k in ('update_status', 'update_stage', 'root_generation', 'appliance_release')}
            if observed != last:
                observations.append(observed)
                print(json.dumps(observed), flush=True)
                last = observed
            if node['update_status'] in {'succeeded', 'failed', 'unsupported'}:
                raise ValueError('Candidate did not enter the required automatic rollback path')
            if restored_at is not None and node['update_status'] == 'rolled_back' and node['appliance_local_health']['status'] == 'healthy':
                verify_rollback(before, node, attempt, manifest['version'])
                if runtime_identity(api(prefix + '/workstation-netboot')) != runtime:
                    raise ValueError('Rollback changed the retained runtime identity')
                receipt = {'schema': 'cybex.james.ubuntu-appliance-rollback-qualification.v1', 'ok': True,
                    'candidate_manifest_sha256': sha(manifest_path), 'candidate_release': manifest['version'],
                    'predecessor_release': before['appliance_release'], 'predecessor_evidence_sha256': sha(evidence_path),
                    'server_device_id': device, 'attempt_id': attempt, 'automatic_rollback': True,
                    'fault': 'isolated_candidate_nic_disconnected_until_automatic_fallback',
                    'candidate_reboot_observed': True, 'fallback_reboot_observed': True,
                    'identity_preserved': True, 'runtime_preserved': True, 'secure_boot': True,
                    'root_generation': '0', 'stage_history': observations,
                    'completed_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
                output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
                output.chmod(0o644)
                return
            time.sleep(1)
        raise ValueError('Automatic rollback qualification timed out')
    finally:
        if disconnected_at is not None and restored_at is None and fixture.process.poll() is None:
            fixture.monitor.call('set_link', {'name': 'nic0', 'up': True})
