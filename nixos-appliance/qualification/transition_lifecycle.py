"""Observe appliance-owned NixOS transitions through authenticated Manage reports."""
import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import time
import uuid

import release_acceptance
import release_predecessor
import rollback_transport_gate

try:
    import schedule_admission
except ModuleNotFoundError as error:
    if error.name != 'schedule_admission':
        raise
    # Some unit tests load this file directly without placing its sibling
    # directory on sys.path. Load the same reviewed helper by exact path.
    _spec = importlib.util.spec_from_file_location(
        'transition_schedule_admission', Path(__file__).with_name('schedule_admission.py'))
    schedule_admission = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(schedule_admission)

UTC = datetime.timezone.utc
EXPECTED_FIELDS = ('device_incarnation_id', 'current_release', 'nixpkgs_revision',
                   'system_toplevel', 'system_closure_sha256', 'system_generation')


def generation(value):
    if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]*', value):
        raise ValueError('Nix generation must be a positive canonical decimal string')
    return value


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('Accepted report timestamp is absent')
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Accepted report timestamp must include its timezone')
    return result


def canonical_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
        raise ValueError('Qualification identity is not a canonical nonzero UUID')
    return value


def identity(node):
    fields = ('device_id', 'hostname', 'cache_public_key_fingerprint', 'cache_base_url')
    result = {k: node[k] for k in fields}
    if any(not isinstance(v, str) or not v for v in result.values()):
        raise ValueError('Appliance permanent identity projection is incomplete')
    # Desired URL is optional for DHCP appliances; retain it for exact before/after
    # comparison without mistaking an unset administrator override for lost identity.
    desired_url = node.get('public_base_url')
    if desired_url is not None and not isinstance(desired_url, str):
        raise ValueError('Appliance desired URL projection is invalid')
    result['public_base_url'] = desired_url
    network = node['appliance_network']
    result['managed_interface_id'] = network.get('managed_interface_id')
    result['macs'] = sorted(v['address'].lower() for v in network['interfaces'] if v['ifname'] != 'lo')
    if not result['macs'] or any(not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', m) for m in result['macs']):
        raise ValueError('Appliance wired identity is incomplete')
    return result


def verify_projection(node, descriptor, expected_generation):
    expected = {'appliance_release': descriptor['release_id'], 'appliance_base_os': 'nixos',
        'appliance_base_os_version': descriptor['base_os_version'], 'nixpkgs_revision': descriptor['nixpkgs_revision'],
        'system_toplevel': descriptor['system_toplevel'], 'system_generation': generation(expected_generation),
        'system_closure_sha256': descriptor['system_closure']['sha256'],
        'sqlite_migrations_sha256': descriptor['sqlite_migrations_sha256'], 'state_schema': 3,
        'appliance_boot_mode': 'uefi'}
    if (any(node.get(k) != v for k, v in expected.items())
            or node.get('appliance_secure_boot') is not False
            or node.get('network_fallback_active') is not False
            or node.get('appliance_local_health', {}).get('status') != 'healthy'):
        raise ValueError('Appliance report differs from the healthy exact NixOS closure')


def verify_preflight(preflight, node, descriptor, expected_generation):
    expected = {'current_release': descriptor['release_id'], 'nixpkgs_revision': descriptor['nixpkgs_revision'],
        'system_toplevel': descriptor['system_toplevel'], 'system_closure_sha256': descriptor['system_closure']['sha256'],
        'system_generation': generation(expected_generation)}
    canonical_uuid(preflight.get('device_incarnation_id'))
    if any(preflight.get(k) != v for k, v in expected.items()):
        raise ValueError('Qualification preflight differs from the exact predecessor')
    verify_projection(node, descriptor, expected_generation)
    return {k: preflight[k] for k in EXPECTED_FIELDS}


def verify_admission(admission, request, candidate, device):
    canonical_uuid(admission.get('attempt_id'))
    expected = {'request_id': request['request_id'], 'release_version': candidate['version'],
        'manifest_sha256': request['candidate']['release_manifest_sha256'],
        'system_closure_sha256': candidate['appliance_release_v1']['system_closure']['sha256'],
        'package_transport_url_sha256': hashlib.sha256(request['candidate']['package_transport_url'].encode()).hexdigest()}
    if (any(admission.get(k) != v for k, v in expected.items())
            or timestamp(admission.get('expires_at')) != timestamp(request['expires_at'])
            or admission.get('node', {}).get('device_id') != device):
        raise ValueError('Qualification admission changed the exact candidate or device')
    return admission['attempt_id']


def validate_inputs(candidate, candidate_digest, previous, previous_digest, evidence, origin, source):
    release_predecessor.advance(candidate['version'], previous['version'])
    for manifest in (candidate, previous):
        descriptor = manifest['appliance_release_v1']
        if (descriptor['schema'] != 'cybex.james.appliance-release.v3'
                or descriptor['release_id'] != manifest['version'] or descriptor['base_os'] != 'nixos'
                or manifest['installer_iso_template_v3']['manage_origin'] != origin):
            raise ValueError('Transition manifests must bind this development NixOS scope')
    descriptor = previous['appliance_release_v1']
    generation(evidence.get('system_generation'))
    if (candidate['appliance_release_v1']['source_revision'] != source
            or not re.fullmatch(r'[0-9a-f]{64}', candidate_digest)
            or evidence.get('schema') != 'cybex.james.nixos-appliance-qualification.v1'
            or evidence.get('qualified_manifest_sha256') != previous_digest
            or evidence.get('release_version') != previous['version']
            or evidence.get('base_os') != 'nixos' or evidence.get('secure_boot') is not False
            or evidence.get('system_toplevel') != descriptor['system_toplevel']
            or evidence.get('system_closure_sha256') != descriptor['system_closure']['sha256']
            or evidence.get('nixpkgs_revision') != descriptor['nixpkgs_revision']
            or evidence.get('manage_source_revision') != descriptor['manage_source_revision']
            or evidence.get('final_state') != 'ready'
            or any(evidence.get(k) is not True for k in ('ok', 'identity_rotation', 'appliance_projection_healthy'))
            or not re.fullmatch(r'dev_[0-9a-f]{32}', evidence.get('device_id', ''))):
        raise ValueError('Predecessor fixture evidence or current harness identity differs')


def verify_terminal(before, node, attempt, candidate, previous, rollback):
    package = node['appliance_package_update']
    descriptor = candidate['appliance_release_v1']
    status, stage = ('rolled_back', 'boot_fallback') if rollback else ('succeeded', 'committed')
    candidate_generation = generation(package.get('candidate_system_generation'))
    source_generation = generation(before['system_generation'])
    result_generation = source_generation if rollback else candidate_generation
    expected = {'attempt_id': attempt, 'target_release': candidate['version'], 'status': status, 'stage': stage,
        'source_revision': descriptor['source_revision'], 'system_closure_sha256': descriptor['system_closure']['sha256'],
        'system_toplevel': descriptor['system_toplevel'], 'resulting_system_generation': result_generation}
    if int(candidate_generation) <= int(source_generation):
        raise ValueError('Terminal candidate generation did not advance')
    for key, value in expected.items():
        if package.get(key) != value:
            raise ValueError('Terminal package identity differs: ' + key)
    if (node.get('update_status') != status or node.get('update_stage') != stage
            or node.get('update_attempt_id') != attempt or node.get('update_target_version') != candidate['version']):
        raise ValueError('Terminal update projection differs')
    if (rollback and package.get('rollback_reason') != 'local_health_failed'):
        raise ValueError('Terminal rollback reason differs')
    if not rollback and package.get('rollback_reason') not in (None, ''):
        raise ValueError('Terminal success contains a rollback reason')
    if identity(before) != identity(node):
        raise ValueError('Terminal permanent identity differs')
    verify_projection(node, (previous if rollback else candidate)['appliance_release_v1'], result_generation)
    return candidate_generation


def write_evidence(output, evidence):
    if output.exists() or output.is_symlink():
        raise ValueError('Refusing to replace existing qualification evidence')
    fd, name = tempfile.mkstemp(prefix='.transition-', dir=output.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(evidence, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        # Publish without overwriting an old success, including concurrent runs.
        os.link(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def initialize_schedule(api, prefix):
    """Sign the installed fixture window; the NixOS updater rejects unsigned defaults."""
    path = prefix + '/update-schedule'
    current = api(path)
    if current.get('supported') is not True:
        raise ValueError('Fixture does not support signed maintenance policy')
    if current['revision'] != 0:
        return  # Preserve an explicitly configured policy, including closed windows.
    if current.get('run_now_attempt_id') is not None:
        raise ValueError('Unsigned fixture policy unexpectedly contains an immediate update')
    saved = api(path, {'expected_revision': 0, 'schedule': current['schedule']})
    if (saved.get('revision') != 1 or saved.get('schedule') != current['schedule']
            or saved.get('run_now_attempt_id') is not None):
        raise ValueError('Fixture maintenance policy was not saved exactly')


def run(api, fixture, candidate, candidate_body, previous, previous_body, evidence,
        evidence_digest, transport_url, output, source, rollback=False, *, clock=time.monotonic,
        sleep=time.sleep, now=lambda: datetime.datetime.now(UTC), timeout=3600,
        exercise_admission=False):
    before = fixture.wait_ready(api)
    if before.get('device_id') != evidence['device_id'] or fixture.device != evidence['device_id']:
        raise ValueError('Running predecessor identity differs from its fixture')
    # A full accepted report is signed by the permanent device identity. Neither
    # heartbeats nor a cached local response advance james_reported_at.
    seen_before = timestamp(before['james_reported_at'])
    gate = rollback_transport_gate.Gate(fixture, before) if rollback else None
    prefix = f'/v1/james/nodes/{fixture.device}'
    admission = (schedule_admission.AdmissionExercise(api, fixture.device, clock=clock,
        sleep=sleep, now=now, timeout=min(timeout, 300)) if exercise_admission else None)
    try:
        expected = verify_preflight(api(prefix + '/qualification-updates'), before,
            previous['appliance_release_v1'], evidence['system_generation'])
        preserved_identity = identity(before)
        request = {'request_id': str(uuid.uuid4()), 'expires_at': (now() + datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'expected': expected, 'candidate': {'release_manifest_json_b64': base64.b64encode(candidate_body).decode(),
            'release_manifest_sha256': hashlib.sha256(candidate_body).hexdigest(), 'package_transport_url': transport_url}}
        if admission:
            admission.prepare(request)
        else:
            initialize_schedule(api, prefix)
        started = now()
        if admission:
            admission.mark_queue_started()
        attempt = verify_admission(api(prefix + '/qualification-updates', request), request, candidate, fixture.device)
        admission_evidence = (admission.activate(attempt, expected, candidate['version'],
            candidate['appliance_release_v1']['system_closure']['sha256'], started) if admission else None)
    except BaseException:
        if admission:
            admission.cleanup(False)
        raise
    deadline = clock() + timeout
    first_reset = fallback_reset = None
    reset_reports_after = None
    fresh_health = set()
    observations = []
    candidate_started_at = None
    gate_counts = None
    gate_install_latency_seconds = None
    failure_stage = 'admitted'
    try:
        while clock() < deadline:
            if fixture.process.poll() is not None:
                raise ValueError('Owned transition fixture exited unexpectedly')
            for event in fixture.monitor.events():
                if event.get('event') != 'RESET':
                    continue
                if event.get('data', {}).get('guest') is not True:
                    raise ValueError('Reset was not initiated by the appliance guest')
                if first_reset is None:
                    first_reset = clock()
                    reset_reports_after = now()
                    if rollback:
                        stamp = event.get('timestamp', {})
                        if not (isinstance(stamp, dict) and type(stamp.get('seconds')) is int
                                and type(stamp.get('microseconds')) is int
                                and 0 <= stamp['microseconds'] < 1000000):
                            raise ValueError('Rollback reset lacks QMP event timestamp')
                        candidate_started_at = datetime.datetime.fromtimestamp(
                            stamp['seconds'] + stamp['microseconds'] / 1000000, UTC)
                        failure_stage = 'candidate_reset_seen'
                        gate.install()
                        gate_install_latency_seconds = (now() - candidate_started_at).total_seconds()
                        if not 0 <= gate_install_latency_seconds <= 10:
                            raise ValueError('Rollback gate missed the candidate reset installation window')
                        failure_stage = 'candidate_gate_installed'
                    print('Observed appliance candidate reboot', flush=True)
                elif rollback and fallback_reset is None:
                    if clock() - first_reset < 180:
                        raise ValueError('Fallback reboot preceded the candidate health deadline')
                    gate_counts = gate.counters()
                    if (gate_counts['first'] != 1 or gate_counts['retained'] < 2
                            or gate_counts['finished'] < 1
                            or gate_counts['blocked'] + gate_counts['blocked_other'] < 1):
                        raise ValueError('Rollback gate did not prove completed guard flow and denied later contact')
                    gate.remove()
                    failure_stage = 'fallback_gate_removed'
                    fallback_reset = clock()
                    reset_reports_after = now()
                    print('Observed appliance automatic fallback reboot', flush=True)
                else:
                    raise ValueError('Unexpected additional appliance reboot')
            node = api(prefix)['node']
            seen = timestamp(node.get('james_reported_at'))
            if seen > now() + datetime.timedelta(seconds=30):
                raise ValueError('Accepted report timestamp is unexpectedly in the future')
            if rollback and first_reset is not None and fallback_reset is None and seen > candidate_started_at:
                raise ValueError('Candidate agent contact was accepted despite rollback gate')
            # Old terminal outcomes from another attempt must neither fail nor
            # satisfy this run while the newly admitted request reaches James.
            if node.get('update_attempt_id') != attempt:
                sleep(1)
                continue
            observation = {k: node.get(k) for k in ('update_status', 'update_stage', 'system_generation', 'appliance_release')}
            if not observations or observations[-1] != observation:
                if len(observations) >= 256:
                    raise ValueError('Transition exceeded its bounded stage history')
                observations.append(observation)
                print(json.dumps(observation, sort_keys=True), flush=True)
            wanted = 'rolled_back' if rollback else 'succeeded'
            if node.get('update_status') in {'failed', 'unsupported', 'cancelled', 'rolled_back', 'succeeded'} - {wanted}:
                raise ValueError('Candidate reached an unexpected terminal outcome')
            if node.get('update_status') != wanted:
                sleep(1)
                continue
            if first_reset is None or (rollback and fallback_reset is None):
                raise ValueError('Terminal report lacks appliance-emitted reset evidence')
            if seen <= max(seen_before, started, reset_reports_after):
                sleep(1)
                continue
            # The first accepted rollback report may arrive before the restored
            # appliance's network and local health projections settle. Require a
            # later fresh, healthy report; never relax the exact identity checks.
            if rollback and (node.get('network_fallback_active') is not False
                    or node.get('appliance_local_health', {}).get('status') != 'healthy'):
                sleep(1)
                continue
            candidate_generation = verify_terminal(before, node, attempt, candidate, previous, rollback)
            fresh_health.add(seen)
            if not rollback and len(fresh_health) < 3:
                sleep(1)
                continue
            final_preflight = api(prefix + '/qualification-updates')
            verify_preflight(final_preflight, node, (previous if rollback else candidate)['appliance_release_v1'], node['system_generation'])
            if final_preflight['device_incarnation_id'] != expected['device_incarnation_id'] or identity(node) != preserved_identity:
                raise ValueError('Permanent device incarnation changed during the transition')
            phase = 'rollback' if rollback else 'update'
            result = {'schema': f'cybex.james.nixos-appliance-{phase}-qualification.v1', 'ok': True,
                'candidate_manifest_sha256': hashlib.sha256(candidate_body).hexdigest(),
                'predecessor_manifest_sha256': hashlib.sha256(previous_body).hexdigest(),
                'predecessor_evidence_sha256': evidence_digest, 'harness_revision': source,
                'candidate_release': candidate['version'], 'predecessor_release': previous['version'],
                'secure_boot': node['appliance_secure_boot'], 'server_device_id': fixture.device,
                'attempt_id': attempt, 'identity_preserved': True, 'candidate_reboot_observed': True,
                'appliance_projection_healthy': True, 'host_reset_used': False,
                'source_system_generation': before['system_generation'], 'candidate_system_generation': candidate_generation,
                'resulting_system_generation': node['system_generation'], 'resulting_system_toplevel': node['system_toplevel'],
                'final_status': node['update_status'], 'final_stage': node['update_stage'], 'stage_history': observations,
                'completed_at': now().isoformat()}
            for name, descriptor in (('candidate', candidate['appliance_release_v1']), ('predecessor', previous['appliance_release_v1'])):
                result[name + '_system_closure_sha256'] = descriptor['system_closure']['sha256']
                for field in ('system_toplevel', 'source_revision', 'manage_source_revision'):
                    result[name + '_' + field] = descriptor[field]
            if rollback:
                result.update(automatic_rollback=True, fallback_reboot_observed=True,
                    rollback_reason=node['appliance_package_update']['rollback_reason'],
                    fault='owned_candidate_manage_transport_gate_until_automatic_fallback',
                    transport_gate=gate_counts,
                    gate_install_latency_seconds=gate_install_latency_seconds)
            else:
                result.update(fresh_health_successes=len(fresh_health), authenticated_manage_contact=True)
            if admission:
                result['q07_admission'] = admission_evidence
            release_acceptance.validate_transition(candidate, result['candidate_manifest_sha256'], previous,
                result['predecessor_manifest_sha256'], result, source, phase)
            if admission:
                admission.mark_terminal()
                admission.cleanup(True)
                admission = None
            write_evidence(output, result)
            return result
        raise ValueError('Appliance transition qualification timed out')
    except BaseException:
        if rollback:
            print('Rollback qualification failed at ' + failure_stage, flush=True)
        raise
    finally:
        if gate:
            gate.remove()
        if admission:
            admission.cleanup(False)
