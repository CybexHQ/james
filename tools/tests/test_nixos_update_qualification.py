"""Exercise NixOS transition qualification with deterministic API/QMP boundaries."""
from copy import deepcopy
from contextlib import redirect_stdout
import datetime
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / 'nixos-appliance/qualification'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HELPERS / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


# These command-line helpers use sibling imports. Load their exact NixOS
# siblings only within this test's context: the retained Ubuntu suite uses
# the same module basenames in the same unittest discovery process.
P = module('transition_nixos_predecessor', 'release_predecessor.py')
A = module('transition_nixos_acceptance', 'release_acceptance.py')
F = module('transition_nixos_fixture', 'isolated_fixture.py')
RPC = module('transition_nixos_rpc', 'isolated_manage_rpc.py')
G = module('transition_nixos_gate', 'rollback_transport_gate.py')
IMPORTS = {'release_predecessor': P, 'release_acceptance': A, 'isolated_fixture': F,
           'isolated_manage_rpc': RPC, 'rollback_transport_gate': G}
with patch.dict(sys.modules, IMPORTS):
    T = module('transition_nixos_lifecycle', 'transition_lifecycle.py')
    with patch.dict(sys.modules, {'transition_lifecycle': T}):
        R = module('isolated_nixos_update', 'run-isolated-update.py')

SOURCE = 'a' * 40
DEVICE = 'dev_' + 'c' * 32
INCARNATION = '97f1d0d9-9b57-4dde-8fdf-ab9c5ecb4820'
ATTEMPT = 'e2972dcf-d1bc-48d7-9a69-f55c6445a9a4'
ORIGIN = 'https://dev.example.test'


def manifest(version, letter):
    return {'version': version, 'installer_iso_template_v3': {'manage_origin': ORIGIN},
        'appliance_release_v1': {'schema': 'cybex.james.appliance-release.v3', 'release_id': version,
        'base_os': 'nixos', 'base_os_version': '26.05', 'source_revision': SOURCE,
        'manage_source_revision': letter * 40, 'nixpkgs_revision': 'd' * 40,
        'system_toplevel': '/nix/store/' + letter * 32 + '-nixos-system-james',
        'system_closure': {'sha256': letter * 64, 'size_bytes': 3,
            'url': f'https://releases.example.test/{version}.tar.zst'}, 'sqlite_migrations_sha256': 'b' * 64}}


def node(release, generation, when):
    d = release['appliance_release_v1']
    return {'device_id': DEVICE, 'hostname': 'james-owned', 'public_base_url': 'http://192.0.2.2:8080',
        'cache_base_url': 'http://192.0.2.2:8080/cache', 'cache_public_key_fingerprint': '3' * 64,
        'appliance_network': {'interfaces': [{'ifname': 'eth0', 'address': '52:54:00:c7:be:01'}]},
        'appliance_release': release['version'], 'appliance_base_os': 'nixos', 'appliance_base_os_version': '26.05',
        'nixpkgs_revision': d['nixpkgs_revision'], 'system_toplevel': d['system_toplevel'],
        'system_generation': generation, 'system_closure_sha256': d['system_closure']['sha256'],
        'sqlite_migrations_sha256': d['sqlite_migrations_sha256'], 'state_schema': 3,
        'appliance_boot_mode': 'uefi', 'appliance_secure_boot': False, 'network_fallback_active': False,
        'appliance_local_health': {'status': 'healthy'}, 'james_reported_at': when.isoformat(),
        'update_status': 'idle', 'update_attempt_id': '', 'update_stage': 'idle', 'appliance_package_update': {'status': 'idle'}}


def preflight(value):
    return {**{k: value[k] for k in ('nixpkgs_revision', 'system_toplevel', 'system_closure_sha256', 'system_generation')},
            'current_release': value['appliance_release'], 'device_incarnation_id': INCARNATION}


class Clock:
    def __init__(self): self.t = 0
    def __call__(self): return self.t
    def sleep(self, seconds): self.t += seconds
    def now(self): return datetime.datetime(2026, 9, 21, tzinfo=T.UTC) + datetime.timedelta(seconds=self.t)


class Run:
    def __init__(self, rollback=False):
        self.clock = Clock()
        self.previous, self.candidate = manifest('1.2.3', 'e'), manifest('1.2.4', 'f')
        self.previous_body, self.candidate_body = [json.dumps(v).encode() for v in (self.previous, self.candidate)]
        self.before = node(self.previous, '7', self.clock.now() - datetime.timedelta(seconds=1))
        self.current = self.before
        self.rollback = rollback
        self.events = [(1, True)] + ([(212, True)] if rollback else [])
        self.calls = []
        self.schedule = {'revision': 0, 'supported': True, 'run_now_attempt_id': None,
            'schedule': {'timezone': 'UTC', 'weekdays': [1], 'start': '00:00', 'duration_minutes': 240}}
        self.nics = []
        self.nic_times = []
        self.gate = Mock()
        self.gate.counters.return_value = {'first': 1, 'retained': 3, 'finished': 1,
                                           'blocked': 2, 'blocked_other': 0}
        self.candidate_contact = False
        self.admission_mutation = lambda a: a
        self.node_mutation = lambda n: n
        self.stale = False
        self.api_error = False
        self.fixture = types.SimpleNamespace(device=DEVICE, process=Mock(), monitor=Mock())
        self.fixture.process.poll.return_value = None
        self.fixture.wait_ready = lambda api: deepcopy(self.before)
        self.fixture.monitor.events = self.qmp_events
        self.fixture.monitor.call = lambda cmd, args: (self.nics.append((cmd, args)), self.nic_times.append(self.clock.t))
        self.evidence = {'schema': 'cybex.james.nixos-appliance-qualification.v1', 'ok': True,
            'qualified_manifest_sha256': hashlib.sha256(self.previous_body).hexdigest(),
            'release_version': self.previous['version'], 'base_os': 'nixos', 'secure_boot': False,
            **{k: self.before[k] for k in ('system_toplevel', 'system_generation', 'system_closure_sha256', 'nixpkgs_revision')},
            'manage_source_revision': self.previous['appliance_release_v1']['manage_source_revision'],
            'final_state': 'ready', 'identity_rotation': True, 'appliance_projection_healthy': True, 'device_id': DEVICE,
            'workstation_runtime_prepublication_deferred': True}

    def qmp_events(self):
        events = []
        while self.events and self.events[0][0] <= self.clock.t:
            at, guest = self.events.pop(0)
            stamp = self.clock.now() - datetime.timedelta(seconds=self.clock.t - at)
            events.append({'event': 'RESET', 'data': {'guest': guest, 'reason': 'guest-reset' if guest else 'host-qmp-system-reset'},
                           'timestamp': {'seconds': int(stamp.timestamp()), 'microseconds': 0}})
        return events

    def terminal(self):
        value = node(self.previous if self.rollback else self.candidate, '7' if self.rollback else '11', self.clock.now())
        if self.stale: value['james_reported_at'] = self.before['james_reported_at']
        value.update(update_attempt_id=ATTEMPT, update_status='rolled_back' if self.rollback else 'succeeded',
            update_stage='boot_fallback' if self.rollback else 'committed', update_target_version=self.candidate['version'])
        d = self.candidate['appliance_release_v1']
        value['appliance_package_update'] = {'attempt_id': ATTEMPT, 'target_release': self.candidate['version'],
            'source_revision': SOURCE, 'system_closure_sha256': d['system_closure']['sha256'],
            'system_toplevel': d['system_toplevel'], 'candidate_system_generation': '11',
            'resulting_system_generation': value['system_generation'], 'status': value['update_status'],
            'stage': value['update_stage'], 'rollback_reason': 'local_health_failed' if self.rollback else ''}
        return self.node_mutation(value)

    def api(self, path, body=None):
        self.calls.append((path, body))
        if path.endswith('/update-schedule'):
            if body:
                assert body['expected_revision'] == self.schedule['revision']
                self.schedule = {**self.schedule, 'revision': self.schedule['revision'] + 1, 'schedule': body['schedule']}
            return deepcopy(self.schedule)
        if body:
            self.request = body
            return self.admission_mutation({'attempt_id': ATTEMPT, 'request_id': body['request_id'],
                'release_version': self.candidate['version'], 'manifest_sha256': hashlib.sha256(self.candidate_body).hexdigest(),
                'system_closure_sha256': self.candidate['appliance_release_v1']['system_closure']['sha256'],
                'package_transport_url_sha256': hashlib.sha256(body['candidate']['package_transport_url'].encode()).hexdigest(),
                'expires_at': body['expires_at'], 'node': {'device_id': DEVICE}})
        if path.endswith('/qualification-updates'):
            return preflight(self.current)
        if self.api_error and self.clock.t >= 4: raise OSError('private response must not be logged')
        if self.rollback and self.candidate_contact and 3 <= self.clock.t < 214:
            self.current = node(self.candidate, '11', self.clock.now())
            self.current.update(update_status='health_checking', update_attempt_id=ATTEMPT,
                update_stage='booted_candidate')
        elif self.clock.t < (214 if self.rollback else 3):
            self.current = deepcopy(self.before)
            self.current.update(update_status='restarting', update_attempt_id=ATTEMPT, update_stage='reboot_pending')
        else:
            self.current = self.terminal()
        return {'node': self.current}

    def execute(self, output, timeout=225):
        with patch.object(T.rollback_transport_gate, 'Gate', return_value=self.gate) as gate_class:
            result = T.run(self.api, self.fixture, self.candidate, self.candidate_body, self.previous,
                self.previous_body, self.evidence, 'a' * 64, 'http://192.0.2.1:12345/closure.tar.zst', output, SOURCE,
                self.rollback, clock=self.clock, sleep=self.clock.sleep, now=self.clock.now, timeout=timeout)
            if self.rollback: gate_class.assert_called_once_with(self.fixture, self.before)
            else: gate_class.assert_not_called()
            return result


class TransitionTests(unittest.TestCase):
    def setUp(self):
        # Acceptance deliberately imports predecessor on demand as well.
        self.enterContext(patch.dict(sys.modules, IMPORTS))

    def test_transition_signs_initial_window_before_admitting_update(self):
        run = Run()
        with tempfile.TemporaryDirectory() as temporary:
            run.execute(Path(temporary) / 'result.json')
        writes = [(path, body) for path, body in run.calls if body]
        self.assertTrue(writes[0][0].endswith('/update-schedule'))
        self.assertEqual(writes[0][1], {'expected_revision': 0, 'schedule': run.schedule['schedule']})
        self.assertTrue(writes[1][0].endswith('/qualification-updates'))

    def test_initialization_preserves_existing_policy_and_rejects_unsupported_or_changed_receipt(self):
        api = Mock(return_value={'revision': 4, 'supported': True})
        T.initialize_schedule(api, '/node')
        api.assert_called_once_with('/node/update-schedule')
        with self.assertRaises(ValueError):
            T.initialize_schedule(Mock(return_value={'supported': False}), '/node')
        initial = Run().schedule
        for changed in ({'revision': 2}, {'schedule': {}}, {'run_now_attempt_id': ATTEMPT}):
            api = Mock(side_effect=[initial, {**initial, 'revision': 1, **changed}])
            with self.assertRaises(ValueError):
                T.initialize_schedule(api, '/node')

    def test_dhcp_identity_preserves_unset_desired_url(self):
        value = node(manifest('0.2.2', 'a'), '1', datetime.datetime.now(T.UTC))
        for desired in (None, ''):
            before = T.identity(value | {'public_base_url': desired})
            self.assertEqual(before['public_base_url'], desired)
            self.assertNotEqual(before, T.identity(value))
        with self.assertRaises(ValueError):
            T.identity(value | {'cache_public_key_fingerprint': ''})
        with self.assertRaises(ValueError):
            T.identity(value | {'public_base_url': 42})

    def test_exact_commit_observes_guest_reset_and_three_distinct_accepted_reports(self):
        run = Run()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'result.json'
            result = run.execute(output)
            self.assertEqual(result, json.loads(output.read_bytes()))
            self.assertEqual(result['fresh_health_successes'], 3)
            self.assertEqual(result['candidate_system_generation'], '11') # allocated generations may skip
            self.assertEqual(result['source_system_generation'], '7')
            self.assertFalse(result['host_reset_used'])
            self.assertEqual(run.nics, [])
            self.assertEqual(run.request['expected']['system_generation'], '7')

    def test_rollback_gates_candidate_transport_until_guest_fallback(self):
        run = Run(True)
        with tempfile.TemporaryDirectory() as temporary:
            result = run.execute(Path(temporary) / 'result.json')
        self.assertEqual(result['rollback_reason'], 'local_health_failed')
        self.assertEqual(result['resulting_system_generation'], '7')
        self.assertEqual(result['candidate_system_generation'], '11')
        self.assertEqual(result['final_stage'], 'boot_fallback')
        self.assertEqual(run.nics, [])
        self.assertEqual(result['transport_gate'], run.gate.counters.return_value)
        self.assertEqual(result['gate_install_latency_seconds'], 0)
        run.gate.install.assert_called_once_with()
        run.gate.revalidate.assert_called_once_with()
        run.gate.remove.assert_called()

    def test_rollback_waits_for_fresh_healthy_restored_report(self):
        run = Run(True)
        reports = 0
        def settle(value):
            nonlocal reports
            reports += 1
            if reports <= 2:
                value['appliance_local_health']['status'] = 'recovering'
            return value
        run.node_mutation = settle
        with tempfile.TemporaryDirectory() as temporary:
            result = run.execute(Path(temporary) / 'result.json')
        self.assertEqual(result['final_status'], 'rolled_back')
        self.assertGreaterEqual(reports, 3)

    def test_stale_reports_cannot_satisfy_repeated_fresh_health(self):
        run = Run(); run.stale = True
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'result.json'
            with self.assertRaisesRegex(ValueError, 'timed out'): run.execute(output, timeout=10)
            self.assertFalse(output.exists())

    def test_cached_same_fresh_report_counts_once(self):
        run = Run()
        run.node_mutation = lambda n: {**n, 'james_reported_at': datetime.datetime(2026,9,21,0,0,3,tzinfo=T.UTC).isoformat()}
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(ValueError, 'timed out'):
            run.execute(Path(temporary) / 'result.json', timeout=10)

    def test_no_reset_host_reset_and_early_fallback_are_rejected(self):
        for rollback, events, message in [(False, [], 'reset evidence'), (False, [(1, False)], 'not initiated'),
                                          (True, [(1, True), (2, True)], 'health deadline')]:
            with self.subTest(events=events), tempfile.TemporaryDirectory() as temporary:
                run = Run(rollback); run.events = events
                with self.assertRaisesRegex(ValueError, message): run.execute(Path(temporary) / 'result.json')
                if rollback: self.assertEqual(run.nics, [])

    def test_exact_candidate_fields_and_identity_cannot_be_substituted(self):
        mutations = [lambda n: n.update(system_generation='12'), lambda n: n.update(system_toplevel='/nix/store/wrong'),
            lambda n: n.update(cache_public_key_fingerprint='4' * 64), lambda n: n.update(appliance_secure_boot=True),
            lambda n: n['appliance_package_update'].update(system_closure_sha256='0' * 64),
            lambda n: n['appliance_package_update'].update(candidate_system_generation='7'),
            lambda n: n['appliance_package_update'].update(candidate_system_generation='011'),
            lambda n: n['appliance_package_update'].update(source_revision='b' * 40)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                run = Run()
                run.node_mutation = lambda n: (mutation(n), n)[1]
                with self.assertRaises(ValueError): run.execute(Path(temporary) / 'result.json')

    def test_rollback_requires_exact_reason_and_predecessor_closure(self):
        for mutation in (lambda n: n['appliance_package_update'].update(rollback_reason='candidate_boot_failed'),
                         lambda n: n.update(system_closure_sha256='f' * 64)):
            with tempfile.TemporaryDirectory() as temporary:
                run = Run(True); run.node_mutation = lambda n: (mutation(n), n)[1]
                with self.assertRaises(ValueError): run.execute(Path(temporary) / 'result.json')

    def test_api_failure_and_timeout_remove_transport_gate(self):
        for failure in (True, False):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                run = Run(True); run.api_error = failure; run.events = [(1, True)]
                with self.assertRaises((OSError, ValueError)): run.execute(Path(temporary) / 'result.json', timeout=5)
                run.gate.remove.assert_called_once_with()

    def test_candidate_contact_and_missing_guard_flow_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = Run(True); run.candidate_contact = True
            with self.assertRaisesRegex(ValueError, 'Candidate agent contact'):
                run.execute(Path(temporary) / 'result.json')
            run.gate.remove.assert_called_once_with()
        with tempfile.TemporaryDirectory() as temporary:
            run = Run(True); run.gate.counters.return_value['finished'] = 0
            with self.assertRaisesRegex(ValueError, 'completed guard flow'):
                run.execute(Path(temporary) / 'result.json')
            run.gate.remove.assert_called_once_with()

    def test_gate_install_must_follow_timestamped_reset_within_ten_seconds(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = Run(True)
            run.gate.install.side_effect = lambda: run.clock.sleep(11)
            with self.assertRaisesRegex(ValueError, 'installation window'):
                run.execute(Path(temporary) / 'result.json')
            run.gate.revalidate.assert_not_called()
            run.gate.remove.assert_called_once_with()

    def test_slow_full_revalidation_does_not_extend_gate_placement_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = Run(True)
            run.gate.revalidate.side_effect = lambda: run.clock.sleep(11)
            result = run.execute(Path(temporary) / 'result.json')
        self.assertEqual(result['gate_install_latency_seconds'], 0)
        self.assertEqual(result['gate_stage_seconds'], {'install': 0, 'revalidate': 11})
        run.gate.revalidate.assert_called_once_with()

    def test_full_revalidation_failure_cleans_gate_and_reports_safe_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = Run(True)
            run.gate.revalidate.side_effect = ValueError('private fixture detail')
            output = Path(temporary) / 'result.json'
            diagnostics = io.StringIO()
            with redirect_stdout(diagnostics), self.assertRaisesRegex(ValueError, 'private fixture detail'):
                run.execute(output)
            self.assertFalse(output.exists())
        self.assertIn('"stage": "candidate_gate_revalidate"', diagnostics.getvalue())
        self.assertIn('"error_type": "ValueError"', diagnostics.getvalue())
        self.assertNotIn('private fixture detail', diagnostics.getvalue())
        run.gate.remove.assert_called_once_with()

    def test_gate_install_failure_reports_install_category_and_cleans(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = Run(True)
            run.gate.install.side_effect = ValueError('private install detail')
            diagnostics = io.StringIO()
            with redirect_stdout(diagnostics), self.assertRaisesRegex(ValueError, 'private install detail'):
                run.execute(Path(temporary) / 'result.json')
        self.assertIn('"stage": "candidate_gate_install"', diagnostics.getvalue())
        self.assertNotIn('private install detail', diagnostics.getvalue())
        run.gate.revalidate.assert_not_called()
        run.gate.remove.assert_called_once_with()

    def test_exact_preflight_and_admission_are_required_before_waiting_for_reset(self):
        run = Run()
        wrong = preflight(run.before); wrong['system_generation'] = '8'
        with self.assertRaises(ValueError): T.verify_preflight(wrong, run.before, run.previous['appliance_release_v1'], '7')
        for field, wrong in [('manifest_sha256', '0' * 64), ('release_version', '2.0.0'), ('request_id', INCARNATION),
                             ('system_closure_sha256', '0' * 64), ('package_transport_url_sha256', '0' * 64),
                             ('attempt_id', 'not-a-uuid'), ('node', {'device_id': 'dev_' + 'a' * 32})]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                run = Run(); run.admission_mutation = lambda a: {**a, field: wrong}
                with self.assertRaises(ValueError): run.execute(Path(temporary) / 'result.json')
                self.assertEqual(run.nics, [])
                self.assertEqual(run.clock.t, 0)

    def test_inputs_require_distinct_semver_exact_scope_and_clean_predecessor(self):
        run = Run()
        def validate():
            T.validate_inputs(run.candidate, hashlib.sha256(run.candidate_body).hexdigest(), run.previous,
                hashlib.sha256(run.previous_body).hexdigest(), run.evidence, ORIGIN, SOURCE)
        validate() # runtime may remain prepublication-deferred
        mutations = [lambda: run.candidate.update(version='1.2.3'),
            lambda: run.candidate['installer_iso_template_v3'].update(manage_origin='https://console.example.com'),
            lambda: run.evidence.update(system_generation='0'), lambda: run.evidence.update(secure_boot=True),
            lambda: run.evidence.update(qualified_manifest_sha256='0' * 64)]
        for mutation in mutations:
            run = Run(); mutation()
            with self.assertRaises(ValueError): validate()

    def test_invalid_scope_precedes_api_fixture_server_and_files(self):
        with patch.object(R, 'private_state', side_effect=ValueError('scope denied')), patch.object(R, 'API') as api, \
             patch.object(R, 'Fixture') as fixture, patch.object(R.subprocess, 'Popen') as server, \
             patch.object(R.release_predecessor, 'checked_json') as read:
            with self.assertRaisesRegex(ValueError, 'scope denied'):
                R.execute(types.SimpleNamespace(state_dir=Path('/not-a-scope')))
            for mutation in (api, fixture, server, read): mutation.assert_not_called()

    def test_isolated_upgrade_uses_manifest_bound_verified_listener(self):
        url = 'http://192.168.123.1:18082/candidate.tar.zst'
        with patch.object(R, 'fixture_request', return_value={'package_transport_url': url}) as rpc:
            self.assertEqual(R.isolated_transport(Path('/private'), '192.168.123.1', 'a' * 64,
                                                 'candidate.tar.zst'), url)
            rpc.assert_called_once_with(Path('/private'), 'installer_transports', manifest_sha256='a' * 64)
        for wrong in (url.replace('18082', '23456'), url.replace('192.168.123.1', '127.0.0.1'),
                      url.replace('candidate.tar.zst', 'other.tar.zst')):
            with patch.object(R, 'fixture_request', return_value={'package_transport_url': wrong}), \
                    self.assertRaises(ValueError):
                R.isolated_transport(Path('/private'), '192.168.123.1', 'a' * 64, 'candidate.tar.zst')
        with patch.object(R, 'fixture_request', side_effect=ValueError('manifest differs')), \
                self.assertRaisesRegex(ValueError, 'manifest differs'):
            R.isolated_transport(Path('/private'), '192.168.123.1', 'a' * 64, 'candidate.tar.zst')

    def test_runner_stops_owned_server_and_fixture_on_transition_failure(self):
        run = Run()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run.candidate['appliance_release_v1']['system_closure']['sha256'] = hashlib.sha256(b'abc').hexdigest()
            candidate = root / 'candidate.json'; candidate.write_text(json.dumps(run.candidate))
            previous = root / 'previous.json'; previous.write_bytes(run.previous_body)
            evidence = root / 'evidence.json'; evidence.write_text(json.dumps(run.evidence))
            (root / '1.2.4.tar.zst').write_bytes(b'abc')
            args = types.SimpleNamespace(state_dir=root, fixture=root / 'fixture', candidate_manifest=candidate,
                predecessor_manifest=previous, predecessor_evidence=evidence, output=root / 'result.json', rollback=False)
            process = Mock(); process.poll.return_value = None
            fixture = Mock(); fixture.__enter__ = Mock(return_value=fixture); fixture.__exit__ = Mock(return_value=False)
            def start(command, **kwargs):
                self.assertTrue(kwargs['start_new_session'])
                self.assertEqual(command[command.index('--bind') + 1], '192.168.123.1')
                Path(command[command.index('--port-file') + 1]).write_text('23456')
                return process
            with patch.object(R, 'private_state', return_value=root), \
                 patch.dict(R.SCOPE, read_scope=lambda _: {'manage_origin': ORIGIN, 'subnet': '192.168.123.1/24'}), \
                 patch.object(R.subprocess, 'check_output', return_value=SOURCE), \
                 patch.object(R.subprocess, 'Popen', side_effect=start), patch.object(R, 'stop') as stop, \
                 patch.object(R, 'Fixture', return_value=fixture), patch.object(R, 'API'), \
                 patch.object(T, 'run', side_effect=OSError('injected transition failure')):
                with self.assertRaisesRegex(OSError, 'injected transition failure'): R.execute(args)
                stop.assert_called_once_with(process)
                fixture.__exit__.assert_called_once()
            self.assertEqual(list(root.glob('closure-*.port')), [])
            self.assertFalse(args.output.exists())

    def test_output_is_private_and_never_overwrites_an_old_success_or_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'result.json'
            T.write_evidence(output, {'ok': True})
            self.assertEqual(output.stat().st_mode & 0o077, 0)
            with self.assertRaises(ValueError): T.write_evidence(output, {'ok': False})
            link = Path(temporary) / 'link'; link.symlink_to(output)
            with self.assertRaises(ValueError): T.write_evidence(link, {'ok': False})
            self.assertTrue(json.loads(output.read_text())['ok'])


if __name__ == '__main__': unittest.main()
