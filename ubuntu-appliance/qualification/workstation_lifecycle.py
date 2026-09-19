"""Real PXE, installation and Blueprint/reboot checks on an owned empty disk."""
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from isolated_fixture import QMP, stop

MAC = '52:54:00:c7:be:02'


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def fresh(value, started):
    try:
        return datetime.datetime.fromisoformat(value.replace('Z', '+00:00')) >= started
    except (AttributeError, TypeError, ValueError):
        return False


def descriptor_digest(descriptor):
    # Same field order and absent-option handling as the signed Rust descriptor.
    fields = ('schema', 'runtime_version', 'manage_source_revision', 'nixpkgs_revision',
              'manage_source_sha256', 'manage_source_size_bytes', 'architecture', 'format',
              'required_james_protocol', 'url', 'sha256', 'size_bytes', 'manifest_sha256',
              'components', 'signature')
    value = {k: descriptor[k] for k in fields if k in descriptor}
    value['components'] = {name: {k: descriptor['components'][name][k] for k in ('sha256', 'size_bytes')}
                           for name in ('bzImage', 'initrd', 'nix-store.squashfs')}
    return hashlib.sha256(json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def require_runtime(status, descriptor):
    if status.get('state') != 'ready' or not status.get('operational') or not status.get('converged'):
        raise ValueError('Private James runtime is not ready and converged')
    for field in ('active', 'desired'):
        runtime = status.get(field) or {}
        if (runtime.get('bundle_sha256') != descriptor['sha256']
                or runtime.get('runtime_version') != descriptor['runtime_version']
                or runtime.get('manage_source_revision') != descriptor['manage_source_revision']
                or runtime.get('compatibility_epoch') != 1):
            raise ValueError('Private James is not serving the exact signed runtime')


def require_workstation(device, descriptor, blueprint, previous=None, verified_after=None):
    facts = device.get('facts_json') or {}
    runtime = facts.get('workstation_runtime') or {}
    generation = facts.get('blueprint_generation') or {}
    current = generation.get('current_system')
    if (device.get('device_kind') == 'nixos-installer' or device.get('health_status') != 'online'
            or device.get('configuration_status') != 'compliant'
            or device.get('desired_blueprint_revision_id') != blueprint['current_revision_id']
            or device.get('applied_blueprint_revision_id') != blueprint['current_revision_id']
            or not device.get('desired_config_hash')
            or device.get('reported_config_hash') != device['desired_config_hash']
            or device.get('applied_config_hash') != device['desired_config_hash']
            or runtime.get('runtime_version') != descriptor['runtime_version']
            or runtime.get('manage_source_revision') != descriptor['manage_source_revision']
            or runtime.get('descriptor_sha256') != descriptor_digest(descriptor)
            or not isinstance(current, str) or not current.startswith('/nix/store/')
            or any(generation.get(k) != current for k in ('system_profile', 'booted_system'))):
        raise ValueError('Workstation has not proved the exact booted runtime and Blueprint')
    uuid.UUID(facts['boot_id'])
    if verified_after and not fresh(device.get('configuration_verified_at'), verified_after):
        raise ValueError('Blueprint report is stale after the managed reboot')
    if previous and (device['device_id'] != previous['device_id']
                     or device['public_key_fingerprint'] != previous['public_key_fingerprint']):
        raise ValueError('Blueprint activation changed the installed workstation identity')


class Workstation:
    def __init__(self, state):
        self.directory = state / 'workstation'
        self.process = None
        self.monitor = None

    def __enter__(self):
        available = int(next(v.split()[1] for v in Path('/proc/meminfo').read_text().splitlines()
                             if v.startswith('MemAvailable:'))) * 1024
        if available < 10 * 1024**3:
            raise ValueError('Disposable workstation needs 10 GiB additional available RAM')
        self.directory.mkdir(mode=0o700)
        d = self.directory
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', d / 'OVMF_VARS.fd')
        with (d / 'workstation.raw').open('xb') as disk:
            disk.truncate(80 * 1024**3)
        qmp = d / 'qmp.sock'
        self.process = subprocess.Popen(['qemu-system-x86_64', '-enable-kvm', '-machine', 'q35',
            '-cpu', 'host', '-smp', '4', '-m', '8192',
            '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
            '-drive', f'if=pflash,format=raw,unit=1,file={d}/OVMF_VARS.fd',
            '-drive', f'if=none,id=system,format=raw,file={d}/workstation.raw,cache=none',
            '-device', 'virtio-blk-pci,drive=system,serial=CYBEXQUALWORKSTATION,bootindex=2',
            '-netdev', 'bridge,id=net0,br=jamesqual0',
            '-device', f'virtio-net-pci,netdev=net0,mac={MAC},bootindex=1',
            '-display', 'none', '-serial', f'file:{d}/serial.log',
            '-qmp', f'unix:{qmp},server=on,wait=off'], start_new_session=True)
        try:
            for _ in range(100):
                self.alive()
                if qmp.exists():
                    self.monitor = QMP(qmp)
                    return self
                time.sleep(.1)
            raise ValueError('Workstation monitor unavailable')
        except BaseException:
            stop(self.process)
            raise

    def alive(self):
        if self.process.poll() is not None:
            raise ValueError('Disposable workstation exited unexpectedly')

    def __exit__(self, *args):
        stop(self.process)
        if self.monitor:
            self.monitor.socket.close()


def run(api, state, james, manifest, catalog, output):
    descriptor = manifest['workstation_netboot']
    runtime_path = f'/v1/james/nodes/{james.device}/workstation-netboot'
    require_runtime(api(runtime_path), descriptor)
    policy = api('/v1/james/delivery-policy')
    if policy['allow_james_source_builds'] or policy['source_builds_allowed']:
        raise ValueError('Workstation qualification requires the source-free delivery policy')
    blueprints = {v['slug']: v for v in catalog['blueprints']}
    first = blueprints['standard_workstation']
    boot_base = f'/v1/boot/servers/{james.device}'
    profiles = api(boot_base + '/profiles?limit=100&offset=0')
    enabled = [v for v in profiles['profiles'] if v['enabled'] and v['profile_type'] == 'james_installer']
    if profiles['total'] > 100 or len(enabled) != 1:
        raise ValueError('New private James must have exactly one enabled installer profile')
    started = now()
    checks = []
    with Workstation(state) as workstation:
        def wait_for(label, read, accept, timeout):
            deadline = time.monotonic() + timeout
            last = None
            while time.monotonic() < deadline:
                workstation.alive()
                require_runtime(api(runtime_path), descriptor)
                value = read()
                if accept(value):
                    print(label + ' passed', flush=True)
                    return value
                if isinstance(value, dict):
                    observation = {k: value.get(k) for k in ('device_kind', 'health_status',
                        'configuration_status', 'installer_target_preparation_state', 'active_command_type',
                        'active_command_status', 'active_command_progress') if k in value}
                    if observation and observation != last:
                        print(json.dumps({'phase': label, **observation}), flush=True)
                        last = observation
                time.sleep(5)
            raise ValueError(label + ' timed out')

        def pending():
            rows = api('/v1/enrollments?status=pending&limit=100&offset=0')
            if rows['total'] > 100:
                raise ValueError('Private pending enrollment inventory exceeded its bound')
            matches = [v for v in rows['enrollments'] if v.get('device_kind') == 'nixos-installer'
                       and str(v.get('facts_json', {}).get('primary_mac', '')).lower() == MAC
                       and fresh(v.get('first_seen_at'), started)]
            if len(matches) > 1:
                raise ValueError('Duplicate private workstation enrollment')
            events = api(boot_base + '/events?limit=100&offset=0')['events']
            booted = any(str(v.get('mac', '')).lower() == MAC
                         and v.get('selected_profile_id') == enabled[0]['id']
                         and fresh(v.get('created_at'), started) for v in events)
            return matches[0] if matches and booted else None

        enrollment = wait_for('PXE and fresh installer enrollment', pending, bool, 900)
        disks = [v for v in enrollment['facts_json']['block_devices'] if v.get('removable') is not True
                 and v.get('size_bytes', 0) >= 32 * 1024**3
                 and str(v.get('preferred_path') or v.get('path') or '').startswith('/dev/')]
        if len(disks) != 1:
            raise ValueError('Owned empty workstation must report exactly one installation disk')
        disk = disks[0].get('preferred_path') or disks[0]['path']
        enrollment_path = '/v1/enrollments/' + enrollment['enrollment_id']
        preflight_body = {'blueprint_id': first['id'], 'target_disk': disk}
        wait_for('Installation preflight', lambda: api(enrollment_path + '/deployment-preflight', preflight_body),
                 lambda v: v.get('ready') is True, 900)
        adopted = api(enrollment_path + '/adopt', {**preflight_body, 'start_install': True,
            'display_name': 'Disposable published-runtime workstation', 'room': 'Private release qualification'})
        device_id = adopted['device_id']
        prefix = '/v1/devices/' + device_id

        def device():
            return api(prefix)

        def reboot(before):
            old_boot = before['facts_json']['boot_id']
            request_time = now()
            command = api(prefix + '/commands', {'command_type': 'reboot', 'payload': {}})
            def returned(value):
                commands = api(prefix + '/commands?limit=100&offset=0')['commands']
                completed = any(v['id'] == command['id'] and v['status'] == 'completed' for v in commands)
                return (completed and fresh(value.get('last_seen_at'), request_time)
                        and value.get('facts_json', {}).get('boot_id') not in (None, old_boot))
            return wait_for('Managed workstation reboot', device, returned, 900)

        def converge(blueprint, previous=None, verified_after=None):
            reboot_requested = False
            def accepted(value):
                nonlocal reboot_requested
                operation = value.get('active_operation') or {}
                if operation.get('state') == 'failed':
                    raise ValueError('Private workstation operation failed: ' + str(operation.get('reason_code')))
                if value.get('configuration_status') == 'pending_reboot' and not reboot_requested:
                    # A new boot can arrive before its read-only attestation.
                    # Wait for that report instead of repeatedly rebooting it.
                    reboot_requested = True
                    reboot(value)
                    return False
                try:
                    require_workstation(value, descriptor, blueprint, previous, verified_after)
                    return True
                except (KeyError, ValueError):
                    return False
            return wait_for('Compliant ' + blueprint['slug'], device, accepted, 3600)

        installed = converge(first)
        for blueprint in (first, blueprints['dock_workstation'],
                          next(v for v in catalog['blueprints'] if v['desktop_profile'] == 'tiling')):
            if blueprint != first:
                api(prefix + '/operations/apply-blueprint', {'request_id': str(uuid.uuid4()),
                    'blueprint_id': blueprint['id'], 'blueprint_revision_id': blueprint['current_revision_id']})
                converge(blueprint, installed)
            before = device()
            requested = now()
            reboot(before)
            after = converge(blueprint, installed, requested)
            checks.append({'blueprint_id': blueprint['id'], 'revision_id': blueprint['current_revision_id'],
                'slug': blueprint['slug'], 'configuration_status': 'compliant',
                'managed_reboot_completed': True, 'identity_preserved': True,
                'boot_id_before': before['facts_json']['boot_id'], 'boot_id_after': after['facts_json']['boot_id'],
                'system': after['facts_json']['blueprint_generation']['booted_system']})
        require_runtime(api(runtime_path), descriptor)
        policy = api('/v1/james/delivery-policy')
        if policy['allow_james_source_builds'] or policy['source_builds_allowed']:
            raise ValueError('Source-free delivery policy changed during workstation qualification')
    output.write_text(json.dumps({'schema': 'cybex.james.published-workstation-qualification.v1', 'ok': True,
        'release_version': manifest['version'], 'runtime_version': descriptor['runtime_version'],
        'bundle_sha256': descriptor['sha256'], 'descriptor_sha256': descriptor_digest(descriptor),
        'manage_source_revision': descriptor['manage_source_revision'], 'james_device_id': james.device,
        'workstation_device_id': device_id, 'pxe_boot_observed': True, 'fresh_install_completed': True,
        'source_builds_allowed': False, 'blueprints': checks, 'completed_at': now().isoformat()}, indent=2) + '\n')
    output.chmod(0o644)
