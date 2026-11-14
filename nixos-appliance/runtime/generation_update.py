"""Crash-recoverable NixOS profile update; protected STATE owns every decision."""
import base64
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
ROOTS = Path('/nix/var/nix/gcroots/tiaris-appliance')
STAGING = Path('/var/cache/tiaris-nest/appliance-updates')


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
        'tiaris-nest': run('/run/current-system/sw/bin/tiaris-nest', '--version').split()[-1]}


def verify_observed_versions(expected):
    for field, value in observed_system_versions().items():
        if value != expected[field]:
            raise ValueError('booted ' + field + ' version differs from signed system')


NIX32 = '0123456789abcdfghijklmnpqrsvwxyz'


def nar_hash_bytes(value):
    """A NAR SHA-256 in SRI, hex or Nix base32 form, as its 32 raw bytes."""
    if value.startswith('sha256-'):
        raw = base64.b64decode(value[len('sha256-'):], validate=True)
    elif value.startswith('sha256:') and re.fullmatch(r'[0-9a-f]{64}', value[len('sha256:'):]):
        raw = bytes.fromhex(value[len('sha256:'):])
    elif value.startswith('sha256:') and len(value) == len('sha256:') + 52:
        decoded = bytearray(32)
        for n, char in enumerate(reversed(value[len('sha256:'):])):
            digit = NIX32.index(char)
            i, j = divmod(n * 5, 8)
            decoded[i] |= (digit << j) & 0xff
            if i < 31:
                decoded[i + 1] |= digit >> (8 - j)
            elif digit >> (8 - j):
                raise ValueError('invalid Nix base32 NAR hash')
        raw = bytes(decoded)
    else:
        raise ValueError('unsupported NAR hash')
    if len(raw) != 32:
        raise ValueError('NAR hash is not SHA-256')
    return raw


def release_nar_hashes(cache):
    """StorePath -> NarHash of every narinfo in the root-verified release cache."""
    hashes = {}
    for path in cache.glob('*.narinfo'):
        fields = {}
        for line in read(path, maximum=1024 * 1024).decode().splitlines():
            key, separator, value = line.partition(': ')
            if separator:
                fields[key] = value
        hashes[fields['StorePath']] = nar_hash_bytes(fields['NarHash'])
    return hashes


def verify_store_closure(cache, toplevel):
    """Only the release key decides what the appliance activates. `nix copy`
    skips a closure member that is already valid in the store, whoever put
    it there: Nix's daemon also trusts the Nest's own cache key (its
    self-substituter), which the tiaris-nest service user holds. Refuse the
    candidate unless every installed member's content is the release's."""
    expected = release_nar_hashes(cache)
    listed = json.loads(run('nix', '--extra-experimental-features', 'nix-command', 'path-info',
                            '--json', '--recursive', '--offline', toplevel, timeout=600))
    rows = listed.items() if isinstance(listed, dict) else ((row.get('path'), row) for row in listed)
    members = set()
    for path, info in rows:
        if isinstance(path, str) and not path.startswith('/'):
            path = '/nix/store/' + path
        if path not in expected or not info or nar_hash_bytes(info['narHash']) != expected[path]:
            raise ValueError('installed closure member differs from the signed release: ' + str(path))
        members.add(path)
    if toplevel not in members:
        raise ValueError('installed closure does not contain the signed release toplevel')


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
            save(KNOWN, {'schema': 'tiaris.nest.known-good-system.v3', 'generations': [known_good(booted, installed)]})
            pin(booted['system_toplevel'], 'good-' + booted['system_generation'])
        return
    receipt = load(PENDING)
    if receipt['schema'] != 'tiaris.nest.pending-system-generation.v3':
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


SOURCE_NEST = Path('/run/current-system/sw/bin/tiaris-nest')
INVENTORY = Path('/usr/share/tiaris-nest/sqlite-migrations.json')
PROFILES = Path('/nix/var/nix/profiles')
ENTRIES = Path('/boot/loader/entries')


class DatabaseIncompatible(ValueError):
    """The candidate's schema would strand a release that must keep running."""


def schema_changes(verified):
    """Whether the candidate carries another SQLite migration inventory."""
    installed = hashlib.sha256(read(INVENTORY, maximum=16 * 1024 ** 2)).hexdigest()
    return installed != verified['sqlite_migrations_sha256']


def opens_rollback(binary, database):
    """Whether one release still runs on the rehearsed database (exit 0).
    A release older than schema evolution does not know the option: no."""
    try:
        result = subprocess.run([str(binary), 'verify-appliance-database', '--database', str(database),
                                 '--rollback-target'], capture_output=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def rehearse_database(verified, cache):
    """A schema-changing candidate first migrates a private copy of the root
    snapshot; the running release must then still start, read and write on
    that copy, because a rollback after the candidate's first boot runs it on
    the migrated live database (docs/sqlite-schema-evolution.md). Returns the
    other retained generations that could not: they must leave the boot menu
    before the candidate touches the live database."""
    backup = cache.parent / 'database-compatibility.sqlite'
    rehearsal = cache.parent / 'database-rehearsal.sqlite'
    candidate = Path(verified['system_toplevel']) / 'sw/bin/tiaris-nest'
    try:
        run(candidate, 'rehearse-appliance-database', '--database', backup, '--output', rehearsal, timeout=600)
    except subprocess.CalledProcessError:
        raise DatabaseIncompatible('candidate cannot migrate a copy of the database') from None
    if not opens_rollback(SOURCE_NEST, rehearsal):
        raise DatabaseIncompatible('running release cannot run on the migrated copy')
    source = current()['system_generation']
    retire = [row for row in load(KNOWN)['generations'] if row['system_generation'] != source
              and not opens_rollback(Path(row['system_toplevel']) / 'sw/bin/tiaris-nest', rehearsal)]
    rehearsal.unlink()
    sync_dir(rehearsal.parent)
    return retire


def retire_generations(rows):
    """Remove retained generations that cannot run on the new schema. Pruning
    first keeps this idempotent: a crash before the receipt update repeats the
    same removal, and a crash after it leaves nothing bootable behind."""
    if not rows:
        return
    source = current()['system_generation']
    for row in rows:
        generation = row['system_generation']
        if generation == source or not re.fullmatch('[1-9][0-9]*', generation):
            raise ValueError('refusing to retire the booted or an invalid generation')
        if (PROFILES / ('system-' + generation + '-link')).is_symlink():
            run('nix-env', '--profile', PROFILE, '--delete-generations', generation)
        entry = ENTRIES / row['loader_entry']
        entry.unlink(missing_ok=True)
        sync_dir(entry.parent)
        (ROOTS / ('good-' + generation)).unlink(missing_ok=True)
    retired = {row['system_generation'] for row in rows}
    known = load(KNOWN)
    save(KNOWN, {'schema': known['schema'],
                 'generations': [row for row in known['generations'] if row['system_generation'] not in retired]})
    print('Retired generations that cannot run on the candidate schema: ' + ', '.join(sorted(retired)), flush=True)


def free_space(verified):
    usage = shutil.disk_usage('/nix/store')
    # Root verification accounted staging and imported paths on their actual
    # filesystems. Staging is allocated now; reserve only still-missing NARs.
    needed = verified['missing_nar_bytes'] + 23 * 1024 ** 3
    if usage.free < needed:
        raise ValueError('insufficient_store_space')
    if shutil.disk_usage('/boot').free < 256 * 1024 ** 2:
        raise ValueError('insufficient_esp_space')


WINDOW = '/usr/lib/tiaris-nest/tiaris-nest-appliance-update-window'
PREPARED_SCHEMA = 'tiaris.nest.prepared-appliance-update.v1'
WAITING_STAGES = ('maintenance_window', 'nest_busy')


def prepared_receipt_path(attempt):
    return CONTROL / 'appliance-updates' / safe_attempt(attempt) / 'prepared-update.json'


def waiting_for():
    """None when the signed policy lets the update start now, else the stage
    it waits in: the maintenance window, or the Nest being busy."""
    result = subprocess.run([WINDOW, str(CONTROL / 'install-plan.json')], timeout=30,
                            capture_output=True, text=True)
    if result.returncode == 0:
        return None
    if result.returncode != 75:
        raise ValueError('invalid update policy')
    reason = result.stdout.strip()
    return reason if reason in WAITING_STAGES else 'maintenance_window'


def prepared_update():
    """The prepared receipt of the exact current request on the exact running
    system, with its imported closure still rooted; else None. Activation
    checks the imported closure against the signed release again."""
    try:
        body = read(REQUEST, owner=UID, maximum=256 * 1024)
        attempt = safe_attempt(json.loads(body)['attempt_id'])
        prepared = load(prepared_receipt_path(attempt))
        source = current()
        root = ROOTS / ('pending-' + attempt)
        if (prepared['schema'] != PREPARED_SCHEMA
                or prepared['attempt_id'] != attempt
                or prepared['request_sha256'] != hashlib.sha256(body).hexdigest()
                or prepared['source_system_generation'] != source['system_generation']
                or prepared['source_system_toplevel'] != source['system_toplevel']
                or prepared['cache_path'] != str(STAGING / 'private' / attempt / 'cache')
                or not root.is_symlink() or str(root.resolve()) != prepared['system_toplevel']
                or not Path(prepared['system_toplevel']).is_dir()
                or not isinstance(prepared['retire_generations'], list)):
            return None
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return prepared


def started(attempt):
    """Whether this attempt already reported activation. Reports only move
    forward, so after a crash it never goes back to waiting."""
    try:
        status = load(STATUS / 'appliance-update-status.json')
    except (OSError, ValueError):
        return False
    return status.get('attempt_id') == attempt and status.get('status') == 'preparing'


def request_identity(request):
    """Status fields of the untrusted request, only to report progress."""
    release = request['release']
    return {'attempt_id': safe_attempt(request['attempt_id']), 'target_release': release['release_id'],
            'source_revision': release['source_revision'], 'system_closure_sha256': release['system_closure']['sha256'],
            'system_toplevel': release['system_toplevel']}


def prepare():
    """Everything slow happens while the running release keeps serving:
    verify the signed bundle, import and root its closure, check it against
    the release and rehearse the database. Nothing here touches boot state."""
    identity = request_identity(load(REQUEST, owner=UID, maximum=256 * 1024))
    if not started(identity['attempt_id']):
        emit_status(identity, 'waiting_window', 'preparing_ahead')
    # Root verifier revalidates signature, exact inbox inode/archive, complete
    # NAR graph, live SQLite and signed policy before yielding private cache.
    cache = Path(run('/usr/bin/tiaris-nest', 'verify-appliance-update', timeout=4 * 3600))
    attempt = safe_attempt(cache.parent.name)
    if cache != STAGING / 'private' / attempt / 'cache':
        raise ValueError('invalid verified update cache path')
    verified = load(CONTROL / 'appliance-updates' / attempt / 'verified-update.json')
    attempt = safe_attempt(verified['attempt_id'])
    if (verified['schema'] != 'tiaris.nest.verified-appliance-update.v3'
            or cache != STAGING / 'private' / attempt / 'cache'
            or verified['cache_path'] != str(cache)):
        raise ValueError('invalid verified update receipt')
    receipt = dict(verified)
    try:
        free_space(verified)
        run('nix', '--extra-experimental-features', 'nix-command', 'copy', '--from', 'file://' + str(cache),
            '--option', 'substituters', '', '--option', 'require-sigs', 'true', verified['system_toplevel'], timeout=4 * 3600)
        # Root the closure first so garbage collection cannot swap a
        # checked member, then check it before running anything from it.
        pin(verified['system_toplevel'], 'pending-' + attempt)
        try:
            verify_store_closure(cache, verified['system_toplevel'])
            if verified['database_backup'] != str(cache.parent / 'database-compatibility.sqlite'):
                raise ValueError('unexpected database compatibility backup')
            run(verified['system_toplevel'] + '/sw/bin/tiaris-nest', 'verify-appliance-database',
                '--database', verified['database_backup'], timeout=60)
            # Retirement waits for activation: an update that never starts
            # must not cost the boot menu its older generations.
            retire = rehearse_database(verified, cache) if schema_changes(verified) else []
        except Exception:
            (ROOTS / ('pending-' + attempt)).unlink(missing_ok=True)
            raise
    except Exception as error:
        reason = 'rollback_database_incompatible' if isinstance(error, DatabaseIncompatible) else 'closure_import_failed'
        emit_status(receipt, 'failed', 'verification_failed', reason, current()['system_generation'])
        cleanup(receipt)
        raise
    prepared = {**verified, 'schema': PREPARED_SCHEMA, 'retire_generations': retire,
                'prepared_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
    save(prepared_receipt_path(attempt), prepared)
    return prepared


def activate(prepared):
    """The short part: recheck the rooted closure, then arm the candidate as
    a one-shot boot and restart into it. The source stays the default."""
    attempt = safe_attempt(prepared['attempt_id'])
    cache = Path(prepared['cache_path'])
    receipt = {key: value for key, value in prepared.items() if key not in ('retire_generations', 'prepared_at')}
    receipt['schema'] = 'tiaris.nest.verified-appliance-update.v3'
    try:
        emit_status(receipt, 'preparing', 'activating')
        verify_store_closure(cache, receipt['system_toplevel'])
        if shutil.disk_usage('/boot').free < 256 * 1024 ** 2:
            raise ValueError('insufficient_esp_space')
        retire_generations(prepared['retire_generations'])
    except Exception:
        (ROOTS / ('pending-' + attempt)).unlink(missing_ok=True)
        emit_status(receipt, 'failed', 'verification_failed', 'closure_import_failed', current()['system_generation'])
        cleanup(receipt)
        raise
    try:
        source = current()
        receipt.update(schema='tiaris.nest.system-prepare-intent.v3', source_generation=source['system_generation'],
            source_toplevel=source['system_toplevel'], source_loader_entry=source['loader_entry'], source_installed=load(INSTALLED), source_known_good=load(KNOWN))
        save(PREPARE, receipt)
        # Persistent EFI override protects the source before Nix rewrites loader.conf.
        set_default(source['loader_entry'])
        run('nix-env', '--profile', PROFILE, '--set', receipt['system_toplevel'], timeout=300)
        generation = generation_for(receipt['system_toplevel'])
        if generation == source['system_generation']:
            raise ValueError('candidate generation did not advance')
        receipt.update(candidate_generation=generation, candidate_loader_entry='nixos-generation-' + generation + '.conf')
        save(PREPARE, receipt)
        run(receipt['system_toplevel'] + '/bin/switch-to-configuration', 'boot', timeout=300)
        set_default(source['loader_entry'])
        verify_boot_entry(receipt['source_loader_entry'], receipt['source_toplevel'])
        verify_boot_entry(receipt['candidate_loader_entry'], receipt['system_toplevel'])
        receipt['schema'] = 'tiaris.nest.pending-system-generation.v3'
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
            (ROOTS / ('pending-' + attempt)).unlink(missing_ok=True)
            emit_status(receipt, 'failed', 'preparation_failed', 'candidate_prepare_failed', current()['system_generation'])
            cleanup(receipt)
        raise


def stage():
    """Prepare as soon as an update arrives, wait for what the signed policy
    names (Update now, the Nest being idle, or the window), then switch."""
    if not REQUEST.exists():
        return
    with maintenance_lock():
        if any(path.exists() for path in (PENDING, PREPARE, COMMIT, ROLLBACK)):
            raise ValueError('pending generation transaction requires recovery')
        prepared = prepared_update() or prepare()
        waiting = None if started(prepared['attempt_id']) else waiting_for()
        if waiting:
            emit_status(prepared, 'waiting_window', waiting)
            return
        activate(prepared)


BOOTSTRAP = '/usr/lib/tiaris-nest/tiaris-nest-bootstrap'


def effective_manage_origin(stored):
    """The origin the booted build serves for a recorded one: its own, or its
    single compiled legacy name (manage.cybex.net -> manage.tiaris.com)."""
    if not isinstance(stored, str) or not stored:
        return None
    result = subprocess.run([BOOTSTRAP, 'effective-manage-origin', stored],
                            text=True, capture_output=True, timeout=10)
    if result.returncode:
        return None
    return result.stdout.strip() or None


def contact_ready(receipt):
    value = load(STATE / 'agent/manage-contact.json', owner=UID, maximum=16384)
    identity = load(STATE / 'agent/manage-state.json', owner=UID)
    plan = load(CONTROL / 'provisioning-state.json')
    timestamp = datetime.datetime.fromisoformat(value['reported_at'].replace('Z', '+00:00'))
    age = (datetime.datetime.now(datetime.timezone.utc) - timestamp).total_seconds()
    return (value['schema'] == 'tiaris.nest.manage-contact.v1'
        and value['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        and value['device_id'] == identity['device_id']
        and value['public_key_fingerprint'] == identity['public_key_fingerprint']
        and value['manage_origin'] == effective_manage_origin(plan['manage_origin'])
        and 0 <= age <= 90)


def health_ready(receipt):
    for unit in ('tiaris-nest', 'tiaris-nest-first-boot', 'tiaris-nest-firewall', 'nginx', 'tftpd-hpa', 'nix-daemon', 'sshd'):
        if subprocess.run(['systemctl', 'is-active', '--quiet', unit], timeout=5).returncode:
            return False
    run('curl', '--fail', '--silent', '--show-error', '--noproxy', '*', '--max-time', '10',
        'http://127.0.0.1:8080/healthz?tiaris_fresh=1', timeout=12)
    return contact_ready(receipt)


def retain(receipt, installed):
    rows = load(KNOWN)['generations']
    selected = known_good(current(), installed)
    rows = [selected] + [row for row in rows if row['system_generation'] != selected['system_generation']]
    keep, obsolete = rows[:3], rows[3:]
    save(KNOWN, {'schema': 'tiaris.nest.known-good-system.v3', 'generations': keep})
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
            inputs = load(Path('/usr/share/tiaris-nest/appliance-release.json'))
            for field in ('source_revision', 'nixpkgs_revision', 'manage_source_revision', 'release_id', 'base_os', 'base_os_version'):
                if inputs[field] != receipt['release'][field]:
                    raise ValueError('booted immutable release inputs differ')
            if hashlib.sha256(read(Path('/usr/share/tiaris-nest/sqlite-migrations.json'))).hexdigest() != receipt['sqlite_migrations_sha256']:
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
            save(COMMIT, {'schema': 'tiaris.nest.system-commit-intent.v3', 'pending_sha256': hashlib.sha256(read(PENDING)).hexdigest(), 'attempt_id': receipt['attempt_id']})
            set_default(receipt['candidate_loader_entry'])
            installed = {'schema': 'tiaris.nest.installed-appliance.v3', 'release': receipt['release'],
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
            save(ROLLBACK, {'schema': 'tiaris.nest.system-rollback-intent.v3',
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
