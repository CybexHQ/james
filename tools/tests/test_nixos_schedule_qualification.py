"""Policy and timestamp tests for the opt-in real-API Q07 exercise."""
from copy import deepcopy
import datetime
import importlib.util
import io
import json
from pathlib import Path
import urllib.error
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / 'nixos-appliance/qualification'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HELPERS / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


S = module('nixos_schedule_admission', 'schedule_admission.py')
DEVICE = 'dev_' + 'c' * 32
ATTEMPT = 'e2972dcf-d1bc-48d7-9a69-f55c6445a9a4'
INCARNATION = '97f1d0d9-9b57-4dde-8fdf-ab9c5ecb4820'
RELEASE = '1.2.4'
CLOSURE = 'f' * 64


def qualification_request(clock):
    return {'request_id': str(uuid.uuid4()),
        'expires_at': (clock.now() + datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'expected': {}, 'candidate': {'release_manifest_json_b64': 'e30=',
        'release_manifest_sha256': '0' * 64, 'package_transport_url': None}}


class Clock:
    def __init__(self):
        self.t = 0
        self.base = datetime.datetime(2026, 9, 21, 12, 34, tzinfo=S.UTC)

    def __call__(self): return self.t
    def sleep(self, seconds): self.t += seconds
    def now(self): return self.base + datetime.timedelta(seconds=self.t)


def conflict(message, diagnostic=None):
    value = {'error': message, 'error_code': 'conflict',
             'diagnostic_code': diagnostic, 'retryable': False,
             'retry_after_seconds': None}
    return urllib.error.HTTPError('https://dev.example.test/v1/private', 409,
        'Conflict', {}, io.BytesIO(json.dumps(value).encode()))


class FakeAPI:
    def __init__(self, clock):
        self.clock = clock
        self.node = {'device_id': DEVICE, 'display_name': 'Owned James',
            'failure_domain': 'default', 'ha_group': 'primary', 'update_hold': False,
            'maintenance_hold': False, 'maintenance_hold_lease_id': None,
            'maintenance_hold_reason': '', 'maintenance_hold_acquired_at': None,
            'system_generation': '7', 'system_toplevel': '/nix/store/' + 'e' * 32 + '-james',
            'system_closure_sha256': 'e' * 64, 'appliance_release': '1.2.3',
            'nixpkgs_revision': 'd' * 40, 'update_status': 'idle',
            'update_attempt_id': '', 'update_target_version': '',
            'appliance_package_update': {'status': 'idle'},
            'appliance_local_health': {'status': 'healthy',
                'update_schedule': {'revision': 4}},
            'james_reported_at': (clock.base - datetime.timedelta(seconds=1)).isoformat()}
        self.expected = {'device_incarnation_id': INCARNATION,
            'current_release': '1.2.3', 'nixpkgs_revision': 'd' * 40,
            'system_toplevel': self.node['system_toplevel'],
            'system_closure_sha256': self.node['system_closure_sha256'],
            'system_generation': '7'}
        self.schedule = {'revision': 4, 'applied_revision': 4, 'supported': True,
            'schedule': {'timezone': 'Europe/Amsterdam', 'weekdays': [0],
                         'start': '02:00', 'duration_minutes': 120},
            'run_now_attempt_id': None}
        self.calls = []
        self.queued = False
        self.build_bypass = False
        self.stale_reports = False
        self.identity_mutation_at = None

    def _waiting_node(self):
        value = deepcopy(self.node)
        if self.schedule['revision'] > 4:
            tick = max(1, int(self.clock.t))
            value['james_reported_at'] = (self.clock.base + datetime.timedelta(seconds=tick)).isoformat()
            value['appliance_local_health']['update_schedule']['revision'] = self.schedule['revision']
        if self.queued:
            tick = 1 + 30 * (max(self.clock.t - 1, 0) // 30)
            if self.stale_reports:
                tick = 1
            value['james_reported_at'] = (self.clock.base + datetime.timedelta(seconds=tick)).isoformat()
            value.update(update_status='waiting_window', update_stage='waiting_window',
                update_attempt_id=ATTEMPT, update_target_version=RELEASE)
            value['appliance_package_update'] = {'status': 'waiting_window',
                'stage': 'waiting_window', 'attempt_id': ATTEMPT,
                'target_release': RELEASE, 'system_closure_sha256': CLOSURE}
            if self.identity_mutation_at is not None and self.clock.t >= self.identity_mutation_at:
                value['system_generation'] = '8'
        return value

    def __call__(self, path, body=None):
        self.calls.append((path, deepcopy(body)))
        prefix = f'/v1/james/nodes/{DEVICE}'
        if path.startswith('/v1/blueprints?'):
            return {'blueprints': [{'id': '1ccedb1f-e880-4b02-92ba-e24142c54f47',
                'current_revision_id': '81d3d240-2b94-4e9c-b55f-7011e9dcd715'}]}
        if path == prefix:
            if body is None:
                return {'node': self._waiting_node()}
            if body.get('maintenance_hold') is True:
                self.node.update(maintenance_hold=True,
                    maintenance_hold_lease_id=body['maintenance_hold_lease_id'],
                    maintenance_hold_reason=body['maintenance_hold_reason'],
                    maintenance_hold_acquired_at=self.clock.now().isoformat())
            elif body.get('maintenance_hold') is False:
                if body['maintenance_hold_lease_id'] != self.node['maintenance_hold_lease_id']:
                    raise conflict('the active maintenance lease belongs to another request')
                self.node.update(maintenance_hold=False, maintenance_hold_lease_id=None,
                    maintenance_hold_reason='', maintenance_hold_acquired_at=None)
            if 'update_hold' in body:
                self.node['update_hold'] = body['update_hold']
            return deepcopy(self.node)
        if path == prefix + '/qualification-updates':
            if self.node['maintenance_hold']:
                raise conflict('James software updates are paused for operator maintenance')
            if body is not None:
                raise AssertionError('qualification admission belongs to the lifecycle runner')
            value = deepcopy(self.expected)
            if self.identity_mutation_at is not None and self.clock.t >= self.identity_mutation_at:
                value['system_generation'] = '8'
            return value
        if path == prefix + '/build/jobs':
            if self.node['maintenance_hold'] and not self.build_bypass:
                raise conflict('James build admission is paused for maintenance', 'james_maintenance_hold')
            return {'id': 'build-was-admitted'}
        if path == prefix + '/update-schedule':
            if body is None:
                return deepcopy(self.schedule)
            if body['expected_revision'] != self.schedule['revision']:
                raise conflict('James schedule changed; refresh before saving')
            self.schedule['revision'] += 1
            self.schedule['schedule'] = deepcopy(body['schedule'])
            self.schedule['run_now_attempt_id'] = None
            return deepcopy(self.schedule)
        if path == prefix + '/update-now':
            if self.node['update_hold']:
                raise conflict('The queued James update changed or is on hold; refresh before updating')
            if body != {'attempt_id': ATTEMPT, 'expected_revision': self.schedule['revision']}:
                raise conflict('James schedule changed; refresh before updating')
            self.schedule['revision'] += 1
            self.schedule['run_now_attempt_id'] = ATTEMPT
            return deepcopy(self.schedule)
        raise AssertionError((path, body))


class ScheduleAdmissionTests(unittest.TestCase):
    def exercise(self, **api_changes):
        clock = Clock()
        api = FakeAPI(clock)
        for name, value in api_changes.items(): setattr(api, name, value)
        exercise = S.AdmissionExercise(api, DEVICE, clock=clock, sleep=clock.sleep,
            now=clock.now, timeout=100)
        exercise.prepare(qualification_request(clock))
        api.queued = True
        exercise.mark_queue_started()
        evidence = exercise.activate(ATTEMPT, api.expected, RELEASE, CLOSURE, clock.now())
        return clock, api, exercise, evidence

    def test_closed_schedule_is_already_ended_and_cannot_open_for_six_days(self):
        now = datetime.datetime(2026, 9, 21, 0, 30, tzinfo=S.UTC)
        schedule = S.closed_schedule(now)
        self.assertEqual(schedule, {'timezone': 'UTC', 'weekdays': [0],
            'start': '22:30', 'duration_minutes': 15})

    def test_exact_lease_conflicts_stable_wait_and_exact_update_now_are_proven(self):
        clock, api, exercise, evidence = self.exercise()
        self.assertTrue(evidence['maintenance_lease_update_conflict'])
        self.assertTrue(evidence['maintenance_lease_attempt_unchanged'])
        self.assertTrue(evidence['maintenance_lease_build_conflict'])
        self.assertTrue(evidence['exact_attempt_update_hold_conflict'])
        self.assertTrue(evidence['exact_attempt_update_now_authorized'])
        self.assertGreaterEqual(evidence['waiting_window_fresh_reports'], 2)
        self.assertGreaterEqual(evidence['waiting_window_span_seconds'], 60)
        self.assertFalse(evidence['active_build_race_qualified'])
        self.assertFalse(evidence['space_pressure_qualified'])
        self.assertTrue(any(path == exercise.prefix + '/qualification-updates' and body is not None
                            for path, body in api.calls))
        self.assertEqual(clock.t, 61)
        self.assertFalse(api.node['maintenance_hold'])
        self.assertFalse(api.node['update_hold'])
        exercise.mark_terminal()
        exercise.cleanup(True)
        self.assertEqual(api.schedule['schedule']['timezone'], 'Europe/Amsterdam')
        self.assertIsNone(api.schedule['run_now_attempt_id'])

    def test_changed_generation_prevents_waiting_window_claim_and_restores_schedule(self):
        clock = Clock(); api = FakeAPI(clock)
        exercise = S.AdmissionExercise(api, DEVICE, clock=clock, sleep=clock.sleep,
            now=clock.now, timeout=100)
        exercise.prepare(qualification_request(clock)); api.queued = True
        exercise.mark_queue_started(); api.identity_mutation_at = 31
        with self.assertRaisesRegex(ValueError, 'identity'):
            exercise.activate(ATTEMPT, api.expected, RELEASE, CLOSURE, clock.now())
        self.assertNotIn('waiting_window_span_seconds', exercise.evidence)
        exercise.cleanup(False)
        self.assertEqual(api.schedule['schedule'], exercise.evidence['closed_schedule'])

    def test_repeated_accepted_timestamp_cannot_count_as_fresh_reports(self):
        clock = Clock(); api = FakeAPI(clock); api.stale_reports = True
        exercise = S.AdmissionExercise(api, DEVICE, clock=clock, sleep=clock.sleep,
            now=clock.now, timeout=65)
        exercise.prepare(qualification_request(clock)); api.queued = True; exercise.mark_queue_started()
        with self.assertRaisesRegex(ValueError, 'timed out'):
            exercise.activate(ATTEMPT, api.expected, RELEASE, CLOSURE, clock.now())
        self.assertNotIn('waiting_window_span_seconds', exercise.evidence)
        exercise.cleanup(False)

    def test_build_policy_bypass_is_fatal_and_exact_lease_is_still_released(self):
        clock = Clock(); api = FakeAPI(clock); api.build_bypass = True
        exercise = S.AdmissionExercise(api, DEVICE, clock=clock, sleep=clock.sleep, now=clock.now)
        with self.assertRaisesRegex(S.PolicyBypass, 'admitted'):
            exercise.prepare(qualification_request(clock))
        self.assertFalse(api.node['maintenance_hold'])
        self.assertEqual(api.schedule['schedule']['timezone'], 'Europe/Amsterdam')

    def test_maintenance_post_bypass_or_lost_commit_keeps_closed_policy_and_lease(self):
        class BrokenMaintenanceAPI(FakeAPI):
            def __init__(self, clock, lost):
                super().__init__(clock)
                self.lost = lost
            def __call__(self, path, body=None):
                prefix = f'/v1/james/nodes/{DEVICE}'
                if (path == prefix + '/qualification-updates' and body is not None
                        and self.node['maintenance_hold']):
                    self.calls.append((path, deepcopy(body)))
                    self.queued = True
                    if self.lost:
                        raise OSError('lost committed qualification response')
                    return {'attempt_id': ATTEMPT}
                return super().__call__(path, body)
        for lost in (False, True):
            with self.subTest(lost=lost):
                clock = Clock(); api = BrokenMaintenanceAPI(clock, lost)
                exercise = S.AdmissionExercise(api, DEVICE, clock=clock, sleep=clock.sleep,
                    now=clock.now, timeout=100)
                with self.assertRaises((S.PolicyBypass, OSError)):
                    exercise.prepare(qualification_request(clock))
                self.assertTrue(api.node['maintenance_hold'])
                self.assertTrue(exercise.lease_owned)
                self.assertTrue(exercise.maintenance_probe_pending)
                self.assertTrue(exercise.queue_started)
                self.assertEqual(api.schedule['schedule'], exercise.closed_schedule_value)
                schedule_set = next(index for index, (path, body) in enumerate(api.calls)
                    if path == exercise.prefix + '/update-schedule' and body is not None)
                admission_post = next(index for index, (path, body) in enumerate(api.calls)
                    if path == exercise.prefix + '/qualification-updates' and body is not None)
                self.assertLess(schedule_set, admission_post)
                with self.assertRaisesRegex(ValueError, 'restore all owned policy state'):
                    exercise.cleanup(True)
                self.assertTrue(api.node['maintenance_hold'])
                self.assertEqual(api.schedule['schedule'], exercise.closed_schedule_value)

    def test_timed_out_pending_maintenance_post_cannot_release_lease_after_empty_get(self):
        class DeferredAPI(FakeAPI):
            def __init__(self, clock):
                super().__init__(clock)
                self.deferred = False
            def __call__(self, path, body=None):
                prefix = f'/v1/james/nodes/{DEVICE}'
                if (path == prefix + '/qualification-updates' and body is not None
                        and self.node['maintenance_hold']):
                    self.calls.append((path, deepcopy(body)))
                    self.deferred = True
                    raise OSError('request is still pending behind its advisory lock')
                if (path == prefix and body and body.get('maintenance_hold') is False
                        and self.deferred):
                    # Models the delayed POST committing as soon as cleanup
                    # drops the lease which had contained it.
                    self.queued = True
                    self.deferred = False
                return super().__call__(path, body)
        clock = Clock(); api = DeferredAPI(clock)
        exercise = S.AdmissionExercise(api, DEVICE, clock=clock, sleep=clock.sleep,
            now=clock.now, timeout=100)
        with self.assertRaises(OSError):
            exercise.prepare(qualification_request(clock))
        # GET still shows the original attempt projection, but that is not
        # terminal evidence about the in-flight mutating request.
        self.assertEqual(S.attempt_projection(S._node(api, exercise.prefix)),
                         exercise.maintenance_probe_projection)
        exercise.cleanup(False)
        self.assertTrue(api.deferred)
        self.assertFalse(api.queued)
        self.assertTrue(api.node['maintenance_hold'])
        self.assertTrue(exercise.maintenance_probe_pending)
        self.assertTrue(exercise.queue_started)
        self.assertEqual(api.schedule['schedule'], exercise.closed_schedule_value)

    def test_newer_schedule_is_never_overwritten_during_cleanup(self):
        _, api, exercise, _ = self.exercise()
        exercise.mark_terminal()
        api.schedule['revision'] += 1
        api.schedule['schedule'] = {'timezone': 'UTC', 'weekdays': [2],
            'start': '04:00', 'duration_minutes': 30}
        with self.assertRaisesRegex(ValueError, 'restore'):
            exercise.cleanup(True)
        self.assertEqual(api.schedule['schedule']['start'], '04:00')

    def test_foreign_update_hold_appearing_during_wait_is_never_claimed_or_cleared(self):
        clock = Clock(); api = FakeAPI(clock)
        exercise = S.AdmissionExercise(api, DEVICE, clock=clock, sleep=clock.sleep,
            now=clock.now, timeout=100)
        exercise.prepare(qualification_request(clock)); api.queued = True
        exercise.mark_queue_started(); api.node['update_hold'] = True
        with self.assertRaisesRegex(ValueError, 'changed before exact acquisition'):
            exercise.activate(ATTEMPT, api.expected, RELEASE, CLOSURE, clock.now())
        exercise.cleanup(False)
        self.assertTrue(api.node['update_hold'])
        self.assertIsNone(api.schedule['run_now_attempt_id'])
        self.assertEqual(api.schedule['schedule'], exercise.closed_schedule_value)

    def test_unexpected_held_update_now_is_withdrawn_before_owned_hold_release(self):
        class BrokenAPI(FakeAPI):
            def __init__(self, clock, lost):
                super().__init__(clock)
                self.lost = lost
            def __call__(self, path, body=None):
                prefix = f'/v1/james/nodes/{DEVICE}'
                if path == prefix + '/update-now' and self.node['update_hold']:
                    self.calls.append((path, deepcopy(body)))
                    self.schedule['revision'] += 1
                    self.schedule['run_now_attempt_id'] = body['attempt_id']
                    if self.lost:
                        raise OSError('lost committed response')
                    return deepcopy(self.schedule)
                return super().__call__(path, body)
        for lost in (False, True):
            with self.subTest(lost=lost):
                clock = Clock(); api = BrokenAPI(clock, lost)
                exercise = S.AdmissionExercise(api, DEVICE, clock=clock, sleep=clock.sleep,
                    now=clock.now, timeout=100)
                exercise.prepare(qualification_request(clock)); api.queued = True
                exercise.mark_queue_started()
                with self.assertRaises((S.PolicyBypass, OSError)):
                    exercise.activate(ATTEMPT, api.expected, RELEASE, CLOSURE, clock.now())
                exercise.cleanup(False)
                self.assertFalse(api.node['update_hold'])
                self.assertIsNone(api.schedule['run_now_attempt_id'])
                self.assertEqual(api.schedule['schedule'], exercise.closed_schedule_value)
                hold_release = next(index for index, (path, body) in enumerate(api.calls)
                    if path == exercise.prefix and body and body.get('update_hold') is False)
                withdrawal = next(index for index, (path, body) in enumerate(api.calls)
                    if path == exercise.prefix + '/update-schedule' and body
                    and body.get('expected_revision', 0) >= exercise.original_schedule_revision + 2)
                self.assertLess(withdrawal, hold_release)

    def test_newer_exact_authorization_retains_hold_when_containment_is_ambiguous(self):
        class NewerBrokenAPI(FakeAPI):
            def __call__(self, path, body=None):
                prefix = f'/v1/james/nodes/{DEVICE}'
                if path == prefix + '/update-now' and self.node['update_hold']:
                    self.calls.append((path, deepcopy(body)))
                    self.schedule['revision'] += 2
                    self.schedule['schedule'] = {'timezone': 'UTC', 'weekdays': [2],
                        'start': '04:00', 'duration_minutes': 30}
                    self.schedule['run_now_attempt_id'] = body['attempt_id']
                    raise OSError('lost newer committed response')
                return super().__call__(path, body)
        clock = Clock(); api = NewerBrokenAPI(clock)
        exercise = S.AdmissionExercise(api, DEVICE, clock=clock, sleep=clock.sleep,
            now=clock.now, timeout=100)
        exercise.prepare(qualification_request(clock)); api.queued = True
        exercise.mark_queue_started()
        with self.assertRaises(OSError):
            exercise.activate(ATTEMPT, api.expected, RELEASE, CLOSURE, clock.now())
        exercise.cleanup(False)
        self.assertTrue(api.node['update_hold'])
        self.assertTrue(exercise.hold_owned)
        self.assertEqual(api.schedule['schedule']['start'], '04:00')
        self.assertEqual(api.schedule['run_now_attempt_id'], ATTEMPT)
        with self.assertRaisesRegex(ValueError, 'restore all owned policy state'):
            exercise.cleanup(True)

    def test_timed_out_pending_update_now_is_revision_fenced_before_hold_release(self):
        class DeferredUpdateNowAPI(FakeAPI):
            def __init__(self, clock):
                super().__init__(clock)
                self.deferred = None
                self.deferred_rejected = False
            def __call__(self, path, body=None):
                prefix = f'/v1/james/nodes/{DEVICE}'
                if path == prefix + '/update-now' and self.node['update_hold']:
                    self.calls.append((path, deepcopy(body)))
                    self.deferred = deepcopy(body)
                    raise OSError('request is still pending before the schedule lock')
                if (path == prefix and body and body.get('update_hold') is False
                        and self.deferred is not None):
                    if self.deferred['expected_revision'] == self.schedule['revision']:
                        self.schedule['revision'] += 1
                        self.schedule['run_now_attempt_id'] = self.deferred['attempt_id']
                    else:
                        self.deferred_rejected = True
                    self.deferred = None
                return super().__call__(path, body)
        clock = Clock(); api = DeferredUpdateNowAPI(clock)
        exercise = S.AdmissionExercise(api, DEVICE, clock=clock, sleep=clock.sleep,
            now=clock.now, timeout=100)
        exercise.prepare(qualification_request(clock)); api.queued = True
        exercise.mark_queue_started()
        with self.assertRaises(OSError):
            exercise.activate(ATTEMPT, api.expected, RELEASE, CLOSURE, clock.now())
        exercise.cleanup(False)
        self.assertTrue(api.deferred_rejected)
        self.assertFalse(api.node['update_hold'])
        self.assertFalse(exercise.conflict_probe_pending)
        self.assertIsNone(api.schedule['run_now_attempt_id'])
        self.assertEqual(api.schedule['schedule'], exercise.closed_schedule_value)
        fence = next(index for index, (path, body) in enumerate(api.calls)
            if path == exercise.prefix + '/update-schedule' and body
            and body.get('expected_revision') == exercise.original_schedule_revision + 1)
        release = next(index for index, (path, body) in enumerate(api.calls)
            if path == exercise.prefix and body and body.get('update_hold') is False)
        self.assertLess(fence, release)


if __name__ == '__main__':
    unittest.main()
