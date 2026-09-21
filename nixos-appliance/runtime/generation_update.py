"""Crash-recoverable NixOS profile update; protected STATE owns every decision."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from appliance_state import (CONTROL, STATUS, INBOX, STATE, PROFILE, UID, canonical,
    current, directory, emit_status, generation_for, load, maintenance_lock, read,
    remove, run, save, set_default, sync_dir)

PENDING = CONTROL / 'pending-system-generation.json'
PREPARE = CONTROL / 'system-prepare-intent.json'
COMMIT = CONTROL / 'system-commit-intent.json'
ROLLBACK = CONTROL / 'system-rollback-intent.json'
INSTALLED = CONTROL / 'appliance-release.json'
KNOWN = CONTROL / 'known-good-system.json'
REQUEST = INBOX / 'appliance-update-request.json'
ROOTS = Path('/nix/var/nix/gcroots/cybex-appliance')
STAGING = Path('/var/cache/cybex-james/appliance-updates')


def file_digest(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        if not 0 < size <= 512 * 1024 ** 2:
            raise ValueError('invalid boot payload size')
        observed = 0
        while block := stream.read(1024 * 1024):
            observed += len(block)
            if observed > size:
                raise ValueError('boot payload changed during validation')
            digest.update(block)
        if observed != size:
            raise ValueError('boot payload changed during validation')
    return digest.digest()


def verify_boot_entry(entry, toplevel, boot=Path('/boot')):
    if not re.fullmatch(r'nixos-generation-[1-9][0-9]*\.conf', entry):
        raise ValueError('invalid boot entry identity')
    fields = {}
    for line in read(boot / 'loader/entries' / entry, maximum=64 * 1024).decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        name, value = line.split(maxsplit=1)
        fields.setdefault(name, []).append(value.strip())
    if (len(fields.get('linux', [])) != 1 or not 1 <= len(fields.get('initrd', [])) <= 4
            or len(fields.get('options', [])) != 1 or 'efi' in fields
            or ('init=' + toplevel + '/init') not in fields['options'][0].split()):
        raise ValueError('boot entry does not select the exact signed system')
    def payload(value):
        relative = Path(value)
        if not value.startswith('/EFI/nixos/') or '..' in relative.parts or '.' in relative.parts:
            raise ValueError('unsafe boot payload path')
        result = boot / value.lstrip('/')
        if not result.is_file() or result.resolve() != result.absolute():
            raise ValueError('boot payload is missing or linked outside ESP')
        return file_digest(result)
    if payload(fields['linux'][0]) != file_digest(Path(toplevel) / 'kernel'):
        raise ValueError('boot kernel differs from signed system')
    initrds = [payload(value) for value in fields['initrd']]
    if file_digest(Path(toplevel) / 'initrd') not in initrds:
        raise ValueError('boot initrd differs from signed system')


def firmware_entry(name):
    path = Path('/sys/firmware/efi/efivars') / (name + '-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f')
    body = read(path, maximum=1024)
    if len(body) < 6 or len(body) % 2:
        raise ValueError('invalid loader EFI variable')
    return body[4:].decode('utf-16-le').rstrip('\0')


def observed_system_versions():
    bootctl = run('/run/current-system/sw/bin/bootctl', '--version').splitlines()[0].split()
    if len(bootctl) < 2 or bootctl[0] != 'systemd':
        raise ValueError('unknown bootloader version output')
    package = bootctl[2].strip('()') if len(bootctl) >= 3 else ''
    boot_version = package if re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', package) else bootctl[1]
    return {'kernel': run('uname', '-r'), 'systemd-boot': boot_version,
        'nix': run('/run/current-system/sw/bin/nix', '--version').split()[-1],
        'cybex-james': run('/run/current-system/sw/bin/cybex-james', '--version').split()[-1]}


def verify_observed_versions(expected):
    for field, value in observed_system_versions().items():
        if value != expected[field]:
            raise ValueError('booted ' + field + ' version differs from signed system')


def safe_attempt(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value):
        raise ValueError('invalid attempt identity')
    return value


def pin(toplevel, name):
    directory(ROOTS, 0o755, gid=0)
    path = ROOTS / name
    if path.is_symlink():
        if str(path.resolve()) != toplevel:
            raise ValueError('conflicting protected store root')
    elif path.exists():
        raise ValueError('unsafe protected store root')
    else:
        path.symlink_to(toplevel)
        sync_dir(ROOTS)


def restore_source(receipt):
    set_default(receipt['source_loader_entry'])
    run('bootctl', 'set-oneshot', '')
    run('nix-env', '--profile', PROFILE, '--switch-generation', receipt['source_generation'])
    if str(PROFILE.resolve()) != receipt['source_toplevel']:
        raise ValueError('source profile restore failed')


def prune_candidate(receipt):
    generation = receipt.get('candidate_generation')
    if generation:
        if generation == current()['system_generation']:
            raise ValueError('refusing to delete booted generation')
        run('nix-env', '--profile', PROFILE, '--delete-generations', generation)
        entry = Path('/boot/loader/entries') / receipt['candidate_loader_entry']
        entry.unlink(missing_ok=True)
        sync_dir(entry.parent)
    (ROOTS / ('pending-' + safe_attempt(receipt['attempt_id']))).unlink(missing_ok=True)
    if generation:
        (ROOTS / ('good-' + generation)).unlink(missing_ok=True)
    if ROOTS.exists():
        sync_dir(ROOTS)


def terminal_matches(receipt):
    try:
        status = load(STATUS / 'appliance-update-status.json')
    except FileNotFoundError:
        return False
    return (status.get('status') == 'succeeded' and status.get('stage') == 'committed'
            and all(status.get(key) == receipt.get(key) for key in ('attempt_id', 'target_release', 'source_revision', 'system_closure_sha256', 'system_toplevel'))
            and status.get('resulting_system_generation') == receipt.get('candidate_generation'))


def cleanup(receipt):
    attempt = safe_attempt(receipt['attempt_id'])
    try:
        request = load(REQUEST, owner=UID)
    except FileNotFoundError:
        request = None
    if request and request.get('attempt_id') != attempt:
        raise ValueError('inbox changed before terminal cleanup')
    if request:
        remove(REQUEST)
    bundle = STAGING / 'inbox' / (attempt + '.tar.zst')
    bundle.unlink(missing_ok=True) # unlink the exact untrusted basename, never follow it
    if bundle.parent.exists():
        sync_dir(bundle.parent)
    for staging in (STAGING / 'private' / attempt, CONTROL / 'appliance-updates' / attempt):
        if staging.exists():
            if staging.is_symlink() or staging.stat().st_uid != 0:
                raise ValueError('unsafe root staging cleanup')
            shutil.rmtree(staging)
            sync_dir(staging.parent)


def clear_transaction(receipt):
    # Keep the sealed authority until every auxiliary intent and root is gone.
    # A crash during cleanup can then always replay the durable terminal result.
    for path in (PREPARE, COMMIT, ROLLBACK):
        remove(path)
    (ROOTS / ('pending-' + safe_attempt(receipt['attempt_id']))).unlink(missing_ok=True)
    if ROOTS.exists():
        sync_dir(ROOTS)
    remove(PENDING)


def known_good(identity, installed):
    return {**identity, 'release': installed['release'], 'system_closure_sha256': installed['system_closure_sha256']}


def recover_boot():
    booted = current()
    if not PENDING.exists():
        if PREPARE.exists():
            receipt = load(PREPARE)
            if booted['system_toplevel'] != receipt['source_toplevel']:
                raise ValueError('unsealed candidate boot is forbidden')
            if not receipt.get('candidate_generation'):
                # A crash may occur after profile creation but before its number
                # reaches the intent. Discover only the exact sealed target.
                try:
                    candidate = generation_for(receipt['system_toplevel'])
                except ValueError:
                    candidate = None
                if candidate and candidate != receipt['source_generation']:
                    receipt.update(candidate_generation=candidate, candidate_loader_entry='nixos-generation-' + candidate + '.conf')
            restore_source(receipt)
            prune_candidate(receipt)
            emit_status(receipt, 'failed', 'interrupted_preparation', 'preparation_interrupted', booted['system_generation'])
            cleanup(receipt)
            remove(PREPARE)
        if not KNOWN.exists():
            installed = load(INSTALLED)
            if installed['system_toplevel'] != booted['system_toplevel']:
                raise ValueError('initial installed system receipt differs from boot')
            set_default(booted['loader_entry'])
            save(KNOWN, {'schema': 'cybex.james.known-good-system.v3', 'generations': [known_good(booted, installed)]})
            pin(booted['system_toplevel'], 'good-' + booted['system_generation'])
        return
    receipt = load(PENDING)
    if receipt['schema'] != 'cybex.james.pending-system-generation.v3':
        raise ValueError('unknown pending generation schema')
    safe_attempt(receipt['attempt_id'])
    if terminal_matches(receipt):
        # Completed durable success wins over a later manual retained boot.
        set_default(receipt['candidate_loader_entry'])
        cleanup(receipt)
        clear_transaction(receipt)
        return
    if booted['system_toplevel'] == receipt['system_toplevel']:
        if booted['system_generation'] != receipt['candidate_generation']:
            raise ValueError('candidate profile identity differs')
        emit_status(receipt, 'health_checking', 'booted_candidate')
        return
    if booted['system_toplevel'] != receipt['source_toplevel']:
        raise ValueError('booted neither sealed candidate nor predecessor')
    reason = 'candidate_boot_failed'
    if ROLLBACK.exists():
        intent = load(ROLLBACK)
        if intent.get('pending_sha256') != hashlib.sha256(read(PENDING)).hexdigest():
            raise ValueError('rollback intent differs from pending seal')
        reason = intent['reason']
    restore_source(receipt)
    save(INSTALLED, receipt['source_installed'])
    save(KNOWN, receipt['source_known_good'])
    prune_candidate(receipt)
    emit_status(receipt, 'rolled_back', 'boot_fallback', reason, booted['system_generation'])
    cleanup(receipt)
    clear_transaction(receipt)


def free_space(verified):
    usage = shutil.disk_usage('/nix/store')
    # Root verification accounted staging and imported paths on their actual
    # filesystems. Staging is allocated now; reserve only still-missing NARs.
    needed = verified['missing_nar_bytes'] + 23 * 1024 ** 3
    if usage.free < needed:
        raise ValueError('insufficient_store_space')
    if shutil.disk_usage('/boot').free < 256 * 1024 ** 2:
        raise ValueError('insufficient_esp_space')


def still_waiting_for_window():
    """Reuse protected identity only to defer; opening the window re-verifies all bytes."""
    try:
        body = read(REQUEST, owner=UID, maximum=256 * 1024)
        attempt = safe_attempt(json.loads(body)['attempt_id'])
        verified = load(CONTROL / 'appliance-updates' / attempt / 'verified-update.json')
        source = current()
        if (verified['schema'] != 'cybex.james.verified-appliance-update.v3'
                or verified['attempt_id'] != attempt
                or verified['request_sha256'] != hashlib.sha256(body).hexdigest()
                or verified['source_system_generation'] != source['system_generation']
                or verified['source_system_toplevel'] != source['system_toplevel']):
            return False
    except (OSError, ValueError, KeyError, TypeError):
        return False
    policy = subprocess.run(['/usr/lib/cybex-james/cybex-james-appliance-update-window', str(CONTROL / 'install-plan.json')], timeout=30)
    if policy.returncode == 75 and read(REQUEST, owner=UID, maximum=256 * 1024) == body:
        emit_status(verified, 'waiting_window', 'maintenance_window')
        return True
    return False


def stage():
    if not REQUEST.exists():
        return
    with maintenance_lock():
        if any(path.exists() for path in (PENDING, PREPARE, COMMIT, ROLLBACK)):
            raise ValueError('pending generation transaction requires recovery')
        if still_waiting_for_window():
            return
        # Root verifier revalidates signature, exact inbox inode/archive, complete
        # NAR graph, live SQLite and signed policy before yielding private cache.
        cache = Path(run('/usr/bin/cybex-james', 'verify-appliance-update', timeout=4 * 3600))
        attempt = safe_attempt(cache.parent.name)
        if cache != STAGING / 'private' / attempt / 'cache':
            raise ValueError('invalid verified update cache path')
        verified = load(CONTROL / 'appliance-updates' / attempt / 'verified-update.json')
        attempt = safe_attempt(verified['attempt_id'])
        if (verified['schema'] != 'cybex.james.verified-appliance-update.v3'
                or cache != STAGING / 'private' / attempt / 'cache'
                or verified['cache_path'] != str(cache)):
            raise ValueError('invalid verified update receipt')
        receipt = dict(verified)
        try:
            policy = subprocess.run(['/usr/lib/cybex-james/cybex-james-appliance-update-window', str(CONTROL / 'install-plan.json')], timeout=30)
            if policy.returncode == 75:
                emit_status(receipt, 'waiting_window', 'maintenance_window')
                return
            if policy.returncode:
                raise ValueError('invalid update policy')
            free_space(verified)
            emit_status(receipt, 'preparing', 'importing_closure')
            run('nix', '--extra-experimental-features', 'nix-command', 'copy', '--from', 'file://' + str(cache),
                '--option', 'substituters', '', '--option', 'require-sigs', 'true', verified['system_toplevel'], timeout=4 * 3600)
            if verified['database_backup'] != str(cache.parent / 'database-compatibility.sqlite'):
                raise ValueError('unexpected database compatibility backup')
            run(verified['system_toplevel'] + '/sw/bin/cybex-james', 'verify-appliance-database',
                '--database', verified['database_backup'], timeout=60)
            pin(verified['system_toplevel'], 'pending-' + attempt)
            source = current()
            receipt.update(schema='cybex.james.system-prepare-intent.v3', source_generation=source['system_generation'],
                source_toplevel=source['system_toplevel'], source_loader_entry=source['loader_entry'], source_installed=load(INSTALLED), source_known_good=load(KNOWN))
            save(PREPARE, receipt)
            # Persistent EFI override protects the source before Nix rewrites loader.conf.
            set_default(source['loader_entry'])
            run('nix-env', '--profile', PROFILE, '--set', verified['system_toplevel'], timeout=300)
            generation = generation_for(verified['system_toplevel'])
            if generation == source['system_generation']:
                raise ValueError('candidate generation did not advance')
            receipt.update(candidate_generation=generation, candidate_loader_entry='nixos-generation-' + generation + '.conf')
            save(PREPARE, receipt)
            run(verified['system_toplevel'] + '/bin/switch-to-configuration', 'boot', timeout=300)
            set_default(source['loader_entry'])
            verify_boot_entry(receipt['source_loader_entry'], receipt['source_toplevel'])
            verify_boot_entry(receipt['candidate_loader_entry'], receipt['system_toplevel'])
            receipt['schema'] = 'cybex.james.pending-system-generation.v3'
            receipt['prepared_boot_id'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            receipt['prepared_at'] = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            save(PENDING, receipt)
            run('bootctl', 'set-oneshot', receipt['candidate_loader_entry'])
            if (firmware_entry('LoaderEntryOneShot') != receipt['candidate_loader_entry']
                    or firmware_entry('LoaderEntryDefault') != receipt['source_loader_entry']):
                raise ValueError('firmware one-shot candidate/source default readback differs')
            emit_status(receipt, 'rebooting', 'reboot_pending')
            os.sync()
            run('systemctl', '--no-block', 'reboot')
        except Exception:
            if PENDING.exists():
                # Once sealed, source boot owns terminal rollback and candidate cleanup.
                restore_source(receipt)
                emit_status(receipt, 'failed', 'arming_failed', 'candidate_arm_failed')
                recover_boot()
            elif PREPARE.exists():
                restore_source(receipt)
                prune_candidate(receipt)
                emit_status(receipt, 'failed', 'preparation_failed', 'candidate_prepare_failed', current()['system_generation'])
                cleanup(receipt)
                remove(PREPARE)
            else:
                emit_status(receipt, 'failed', 'verification_failed', 'closure_import_failed', current()['system_generation'])
                cleanup(receipt)
            raise


def contact_ready(receipt):
    value = load(STATE / 'agent/manage-contact.json', owner=UID, maximum=16384)
    identity = load(STATE / 'agent/manage-state.json', owner=UID)
    plan = load(CONTROL / 'provisioning-state.json')
    timestamp = datetime.datetime.fromisoformat(value['reported_at'].replace('Z', '+00:00'))
    age = (datetime.datetime.now(datetime.timezone.utc) - timestamp).total_seconds()
    return (value['schema'] == 'cybex.james.manage-contact.v1'
        and value['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        and value['device_id'] == identity['device_id']
        and value['public_key_fingerprint'] == identity['public_key_fingerprint']
        and value['manage_origin'] == plan['manage_origin'] and 0 <= age <= 90)


def health_ready(receipt):
    for unit in ('cybex-james', 'cybex-james-first-boot', 'cybex-james-firewall', 'nginx', 'tftpd-hpa', 'nix-daemon', 'sshd'):
        if subprocess.run(['systemctl', 'is-active', '--quiet', unit], timeout=5).returncode:
            return False
    run('curl', '--fail', '--silent', '--show-error', '--noproxy', '*', '--max-time', '10',
        'http://127.0.0.1:8080/healthz?cybex_fresh=1', timeout=12)
    return contact_ready(receipt)


def retain(receipt, installed):
    rows = load(KNOWN)['generations']
    selected = known_good(current(), installed)
    rows = [selected] + [row for row in rows if row['system_generation'] != selected['system_generation']]
    keep, obsolete = rows[:3], rows[3:]
    save(KNOWN, {'schema': 'cybex.james.known-good-system.v3', 'generations': keep})
    for row in keep:
        pin(row['system_toplevel'], 'good-' + row['system_generation'])
    return obsolete


def prune_obsolete(obsolete):
    for row in obsolete:
        run('nix-env', '--profile', PROFILE, '--delete-generations', row['system_generation'])
        entry = Path('/boot/loader/entries') / row['loader_entry']
        entry.unlink(missing_ok=True)
        (ROOTS / ('good-' + row['system_generation'])).unlink(missing_ok=True)


def commit():
    if not PENDING.exists():
        return
    with maintenance_lock():
        receipt = load(PENDING)
        if current()['system_toplevel'] != receipt['system_toplevel']:
            recover_boot()
            return
        try:
            inputs = load(Path('/usr/share/cybex-james/appliance-release.json'))
            for field in ('source_revision', 'nixpkgs_revision', 'manage_source_revision', 'release_id', 'base_os', 'base_os_version'):
                if inputs[field] != receipt['release'][field]:
                    raise ValueError('booted immutable release inputs differ')
            if hashlib.sha256(read(Path('/usr/share/cybex-james/sqlite-migrations.json'))).hexdigest() != receipt['sqlite_migrations_sha256']:
                raise ValueError('booted migration inventory differs')
            verify_observed_versions(receipt['release']['required_system_versions'])
            verify_boot_entry(receipt['candidate_loader_entry'], receipt['system_toplevel'])
            deadline, successes = time.monotonic() + 210, 0
            while time.monotonic() < deadline:
                try:
                    ready = health_ready(receipt)
                except Exception:
                    ready = False
                successes = successes + 1 if ready else 0
                if successes >= 3:
                    break
                time.sleep(5)
            else:
                raise RuntimeError('candidate health deadline expired')
            save(COMMIT, {'schema': 'cybex.james.system-commit-intent.v3', 'pending_sha256': hashlib.sha256(read(PENDING)).hexdigest(), 'attempt_id': receipt['attempt_id']})
            set_default(receipt['candidate_loader_entry'])
            installed = {'schema': 'cybex.james.installed-appliance.v3', 'release': receipt['release'],
                'system_generation': receipt['candidate_generation'], 'system_toplevel': receipt['system_toplevel'],
                'system_closure_sha256': receipt['system_closure_sha256'], 'at_rest_protection': 'none',
                'base_os': 'nixos', 'base_os_version': receipt['release']['base_os_version']}
            save(INSTALLED, installed)
            obsolete = retain(receipt, installed)
            emit_status(receipt, 'succeeded', 'committed', resulting=receipt['candidate_generation'])
            cleanup(receipt)
            clear_transaction(receipt)
            try:
                prune_obsolete(obsolete)
            except Exception as error:
                # Success is already durable; pruning is separate maintenance.
                print('Committed generation needs retained-generation cleanup: ' + type(error).__name__, flush=True)
        except Exception:
            if terminal_matches(receipt):
                raise # durable success must never be rewritten as rollback
            save(ROLLBACK, {'schema': 'cybex.james.system-rollback-intent.v3',
                'pending_sha256': hashlib.sha256(read(PENDING)).hexdigest(), 'reason': 'local_health_failed', 'attempt_id': receipt['attempt_id']})
            restore_source(receipt)
            emit_status(receipt, 'health_checking', 'rollback_pending', 'local_health_failed')
            os.sync()
            run('systemctl', '--no-block', 'reboot')
            raise


def gc():
    with maintenance_lock():
        if PENDING.exists() or PREPARE.exists():
            return
        for row in load(KNOWN)['generations']:
            pin(row['system_toplevel'], 'good-' + row['system_generation'])
        run('nix-store', '--gc', timeout=3600)
