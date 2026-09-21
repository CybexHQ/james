"""Bounded real-API proof for James schedule, hold, and admission policy.

The update-hold API exposes one Boolean rather than a lease or compare-and-set
identity. This exercise can reject a hold already visible before acquisition
and avoid clearing a hold after visible mutable-node changes, but it cannot
distinguish a concurrent operator writing the same Boolean value.
"""
import datetime
import json
import time
import urllib.error
import uuid


UTC = datetime.timezone.utc
MAINTENANCE_REASON = 'Owned NixOS Q07 qualification'
MUTABLE_NODE_FIELDS = ('display_name', 'failure_domain', 'ha_group',
                       'maintenance_hold_lease_id')


def _log(condition, **evidence):
    print(json.dumps({'q07_condition': condition, **evidence}, sort_keys=True), flush=True)


def _timestamp(value):
    if not isinstance(value, str):
        raise ValueError('Q07 accepted report timestamp is absent')
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Q07 accepted report timestamp has no timezone')
    return result


def _canonical_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
        raise ValueError('Q07 API returned a noncanonical identity')
    return value


def _node(api, prefix):
    response = api(prefix)
    node = response.get('node') if isinstance(response, dict) else None
    if not isinstance(node, dict):
        raise ValueError('Q07 James node response is malformed')
    return node


def _error_body(error):
    body = error.read(65537)
    if len(body) > 65536:
        raise ValueError('Q07 API error response exceeded its bound')
    try:
        value = json.loads(body)
    except (TypeError, ValueError):
        raise ValueError('Q07 API conflict response was not JSON') from None
    if not isinstance(value, dict):
        raise ValueError('Q07 API conflict response was malformed')
    return value


class PolicyBypass(ValueError):
    pass


def expect_conflict(api, path, body=None, *, message=None, diagnostic=None):
    try:
        api(path, body)
    except urllib.error.HTTPError as error:
        value = _error_body(error)
        if error.code != 409 or value.get('error_code') != 'conflict':
            raise ValueError('Q07 API did not return the required conflict') from None
        if message is not None and value.get('error') != message:
            raise ValueError('Q07 API returned a different conflict') from None
        if diagnostic is not None and value.get('diagnostic_code') != diagnostic:
            raise ValueError('Q07 API returned a different diagnostic conflict') from None
        return value
    raise PolicyBypass('Q07 mutation was admitted when policy required a conflict')


def closed_schedule(now):
    """Return a 15-minute UTC window which ended at least 105 minutes ago."""
    now = now.astimezone(UTC)
    start = now - datetime.timedelta(hours=2)
    # Manage uses Sunday=0 while datetime.weekday() uses Monday=0.
    return {'timezone': 'UTC', 'weekdays': [(start.weekday() + 1) % 7],
            'start': start.strftime('%H:%M'), 'duration_minutes': 15}


def select_build_probe(api):
    response = api('/v1/blueprints?platform=nixos&limit=100&offset=0')
    blueprints = response.get('blueprints') if isinstance(response, dict) else None
    if not isinstance(blueprints, list):
        raise ValueError('Q07 Blueprint response is malformed')
    probes = []
    for blueprint in blueprints:
        if not isinstance(blueprint, dict) or not blueprint.get('current_revision_id'):
            continue
        try:
            blueprint_id = str(uuid.UUID(blueprint['id']))
            revision_id = str(uuid.UUID(blueprint['current_revision_id']))
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
        probes.append({'requested_artifact_type': 'nixos_closure',
            'blueprint_id': blueprint_id, 'blueprint_revision_id': revision_id,
            'target': 'blueprint', 'system': 'x86_64-linux',
            'cache_metadata': {'source': 'nixos-q07-admission-probe'}})
    if not probes:
        raise ValueError('Q07 requires one real released NixOS Blueprint for build admission')
    return probes[:16]


def verify_waiting_identity(node, preflight, expected, attempt, release, closure):
    package = node.get('appliance_package_update', {})
    projection = {
        'device_incarnation_id': preflight.get('device_incarnation_id'),
        'system_generation': node.get('system_generation'),
        'system_toplevel': node.get('system_toplevel'),
        'system_closure_sha256': node.get('system_closure_sha256'),
    }
    wanted = {key: expected[key] for key in projection}
    if (projection != wanted
            or any(preflight.get(key) != expected[key] for key in expected)
            or node.get('update_attempt_id') != attempt
            or node.get('update_target_version') != release
            or package.get('attempt_id') != attempt
            or package.get('target_release') != release
            or package.get('system_closure_sha256') != closure
            or package.get('status') != 'waiting_window'):
        raise ValueError('Q07 waiting-window report changed exact attempt or predecessor identity')
    return projection


def attempt_projection(node):
    return {field: node.get(field) for field in
            ('update_attempt_id', 'update_status', 'update_target_version',
             'appliance_package_update')}


class AdmissionExercise:
    """Own and restore only the fixture mutations made by the Q07 exercise."""
    def __init__(self, api, device, *, clock=time.monotonic, sleep=time.sleep,
                 now=lambda: datetime.datetime.now(UTC), timeout=300):
        self.api = api
        self.device = device
        self.prefix = f'/v1/james/nodes/{device}'
        self.clock, self.sleep, self.now, self.timeout = clock, sleep, now, timeout
        self.lease_id = str(uuid.uuid4())
        self.lease_owned = False
        self.hold_owned = False
        self.hold_projection = None
        self.original_schedule = None
        self.original_schedule_revision = None
        self.closed_schedule_value = None
        self.schedule_revision = None
        self.run_now_owned = False
        self.run_now_pending = False
        self.conflict_probe_pending = False
        self.maintenance_probe_pending = False
        self.maintenance_probe_projection = None
        self.attempt = None
        self.queue_started = False
        self.terminal = False
        self.predecessor_projection = None
        self.evidence = {'schema': 'cybex.james.nixos-q07-admission.v1',
            'active_build_race_qualified': False, 'space_pressure_qualified': False}

    def _mutate_node(self, node, **fields):
        return self.api(self.prefix, {'display_name': node['display_name'], **fields})

    def _release_lease(self, required):
        node = _node(self.api, self.prefix)
        active = node.get('maintenance_hold_lease_id')
        if active is None:
            self.lease_owned = False
            return
        if active != self.lease_id:
            _log('cleanup_skipped_foreign_maintenance_lease')
            if required:
                raise ValueError('Q07 maintenance lease was replaced by newer state')
            return
        released = self._mutate_node(node, maintenance_hold=False,
            maintenance_hold_lease_id=self.lease_id)
        if (released.get('maintenance_hold') is not False
                or released.get('maintenance_hold_lease_id') is not None
                or released.get('maintenance_hold_reason') not in ('', None)
                or released.get('maintenance_hold_acquired_at') is not None):
            raise ValueError('Q07 exact maintenance lease was not released')
        self.lease_owned = False
        _log('exact_maintenance_lease_released')

    def prepare(self, qualification_request):
        try:
            if not isinstance(qualification_request, dict):
                raise ValueError('Q07 qualification admission request is absent')
            probes = select_build_probe(self.api)
            node = _node(self.api, self.prefix)
            if node.get('maintenance_hold') or node.get('maintenance_hold_lease_id') is not None:
                raise ValueError('Q07 fixture already has a maintenance lease')
            if node.get('update_hold') is not False:
                raise ValueError('Q07 fixture already has an update hold')
            self.predecessor_projection = {field: node.get(field) for field in
                ('system_generation', 'system_toplevel', 'system_closure_sha256')}

            # Close and observe the schedule before the mutating maintenance
            # probe. If a broken fence admits that POST or loses its response,
            # cleanup must leave this policy closed around the untracked run.
            state = self.api(self.prefix + '/update-schedule')
            if (not isinstance(state, dict) or state.get('supported') is not True
                    or state.get('run_now_attempt_id') is not None
                    or not isinstance(state.get('revision'), int)
                    or not isinstance(state.get('schedule'), dict)):
                raise ValueError('Q07 schedule is unsupported or already owns an attempt')
            self.original_schedule = dict(state['schedule'])
            self.original_schedule_revision = state['revision']
            schedule = closed_schedule(self.now())
            self.closed_schedule_value = schedule
            changed = self.api(self.prefix + '/update-schedule',
                {'expected_revision': state['revision'], 'schedule': schedule})
            if (changed.get('revision') != state['revision'] + 1
                    or changed.get('schedule') != schedule
                    or changed.get('run_now_attempt_id') is not None):
                raise ValueError('Q07 closed schedule did not preserve exact revision semantics')
            self.schedule_revision = changed['revision']
            self.evidence['closed_schedule'] = schedule
            self.evidence['closed_schedule_revision'] = self.schedule_revision
            _log('closed_schedule_set', revision=self.schedule_revision)
            applied_after = self.now()
            deadline = self.clock() + self.timeout
            while self.clock() < deadline:
                node = _node(self.api, self.prefix)
                observed = _timestamp(node.get('james_reported_at'))
                applied = node.get('appliance_local_health', {}).get('update_schedule', {})
                current = {field: node.get(field) for field in self.predecessor_projection}
                if (observed > applied_after
                        and observed <= self.now() + datetime.timedelta(seconds=30)
                        and applied.get('revision') == self.schedule_revision):
                    if current != self.predecessor_projection:
                        raise ValueError('Q07 predecessor changed while applying its closed schedule')
                    self.evidence['closed_schedule_applied_revision'] = self.schedule_revision
                    _log('closed_schedule_applied', revision=self.schedule_revision)
                    break
                self.sleep(1)
            else:
                raise ValueError('Q07 closed schedule was not applied before admission probes')

            node = _node(self.api, self.prefix)
            if node.get('maintenance_hold') or node.get('maintenance_hold_lease_id') is not None:
                raise ValueError('Q07 maintenance lease changed before exact acquisition')
            if node.get('update_hold') is not False:
                raise ValueError('Q07 update hold changed before maintenance probe')
            # A lost response can occur after the server commits. Mark the
            # UUID as potentially owned first; cleanup releases only this ID.
            self.lease_owned = True
            acquired = self._mutate_node(node, maintenance_hold=True,
                maintenance_hold_lease_id=self.lease_id,
                maintenance_hold_reason=MAINTENANCE_REASON)
            if (acquired.get('maintenance_hold') is not True
                    or acquired.get('maintenance_hold_lease_id') != self.lease_id
                    or acquired.get('maintenance_hold_reason') != MAINTENANCE_REASON
                    or not acquired.get('maintenance_hold_acquired_at')):
                raise ValueError('Q07 did not acquire its exact maintenance lease')
            _log('exact_maintenance_lease_acquired')

            admission_before = attempt_projection(acquired)
            self.maintenance_probe_projection = admission_before
            self.maintenance_probe_pending = True
            self.queue_started = True
            expect_conflict(self.api, self.prefix + '/qualification-updates', qualification_request,
                message='James software updates are paused for operator maintenance')
            admission_after_node = _node(self.api, self.prefix)
            admission_after = attempt_projection(admission_after_node)
            if admission_after != admission_before:
                raise PolicyBypass('Q07 maintenance lease admitted or changed an update attempt')
            self.maintenance_probe_pending = False
            self.queue_started = False
            self.evidence['maintenance_lease_update_conflict'] = True
            self.evidence['maintenance_lease_attempt_unchanged'] = True
            _log('maintenance_lease_update_conflict')

            build_conflict = False
            for probe in probes:
                try:
                    expect_conflict(self.api, self.prefix + '/build/jobs', probe,
                        diagnostic='james_maintenance_hold')
                    build_conflict = True
                    break
                except PolicyBypass:
                    raise
                except ValueError:
                    continue
            if not build_conflict:
                raise ValueError('Q07 could not reach the real build admission fence')
            self.evidence['maintenance_lease_build_conflict'] = True
            _log('maintenance_lease_build_conflict')
            self._release_lease(True)
            self.evidence['maintenance_lease_released'] = True
        except BaseException:
            self.cleanup(False)
            raise

    def activate(self, attempt, expected, release, closure, queued_at):
        self.attempt = _canonical_uuid(attempt)
        deadline = self.clock() + self.timeout
        reports = []
        seen = set()
        projection = None
        while self.clock() < deadline:
            node = _node(self.api, self.prefix)
            if node.get('update_attempt_id') != attempt:
                self.sleep(1)
                continue
            status = node.get('update_status')
            if status not in ('requested', 'waiting_window'):
                raise ValueError('Q07 update left the closed window before waiting proof completed')
            if status == 'requested':
                self.sleep(1)
                continue
            observed = _timestamp(node.get('james_reported_at'))
            if observed <= queued_at or observed > self.now() + datetime.timedelta(seconds=30):
                self.sleep(1)
                continue
            if observed not in seen:
                preflight = self.api(self.prefix + '/qualification-updates')
                current = verify_waiting_identity(node, preflight, expected, attempt, release, closure)
                if projection is not None and current != projection:
                    raise ValueError('Q07 predecessor identity changed between accepted reports')
                projection = current
                seen.add(observed)
                reports.append(observed)
                _log('fresh_waiting_window_report', ordinal=len(reports))
                if len(reports) >= 2 and (reports[-1] - reports[0]).total_seconds() >= 60:
                    break
            self.sleep(1)
        else:
            raise ValueError('Q07 timed out proving a closed maintenance window')
        span = int((reports[-1] - reports[0]).total_seconds())
        self.evidence.update(waiting_window_fresh_reports=len(reports),
            waiting_window_span_seconds=span, waiting_window_identity=projection,
            waiting_window_attempt_id=attempt)
        _log('waiting_window_stable', reports=len(reports), span_seconds=span)

        node = _node(self.api, self.prefix)
        if node.get('update_hold') is not False:
            raise ValueError('Q07 update hold changed before exact acquisition')
        # The fixture started without an update hold. Preserve the mutable
        # node projection so a failed response can still be cleaned up only
        # while no newer operator mutation is visible. The API has no hold
        # lease/CAS identity, so a concurrent same-value write is unobservable.
        self.hold_owned = True
        self.hold_projection = {field: node.get(field) for field in MUTABLE_NODE_FIELDS}
        held = self._mutate_node(node, update_hold=True)
        if held.get('update_hold') is not True:
            raise ValueError('Q07 update hold was not enabled')
        self.hold_projection = {field: held.get(field) for field in MUTABLE_NODE_FIELDS}
        schedule = self.api(self.prefix + '/update-schedule')
        if schedule.get('revision') != self.schedule_revision:
            raise ValueError('Q07 schedule changed before Update now conflict proof')
        request = {'attempt_id': attempt, 'expected_revision': self.schedule_revision}
        # A broken server or lost response may commit the mutation which is
        # required to conflict. Cleanup must reconcile it while our hold still
        # contains the waiting attempt.
        self.conflict_probe_pending = True
        expect_conflict(self.api, self.prefix + '/update-now', request,
            message='The queued James update changed or is on hold; refresh before updating')
        self.conflict_probe_pending = False
        self.evidence['exact_attempt_update_hold_conflict'] = True
        _log('exact_attempt_update_hold_conflict')

        node = _node(self.api, self.prefix)
        released = self._mutate_node(node, update_hold=False)
        if released.get('update_hold') is not False:
            raise ValueError('Q07 update hold was not released')
        self.hold_owned = False
        self.evidence['update_hold_released'] = True
        _log('owned_update_hold_released')
        self.run_now_pending = True
        authorized = self.api(self.prefix + '/update-now', request)
        if (authorized.get('revision') != self.schedule_revision + 1
                or authorized.get('run_now_attempt_id') != attempt
                or authorized.get('schedule') != self.evidence['closed_schedule']):
            raise ValueError('Q07 Update now did not bind the exact waiting attempt')
        self.schedule_revision = authorized['revision']
        self.run_now_owned = True
        self.run_now_pending = False
        self.evidence['update_now_revision'] = self.schedule_revision
        self.evidence['exact_attempt_update_now_authorized'] = True
        _log('exact_attempt_update_now_authorized', revision=self.schedule_revision)
        return dict(self.evidence)

    def mark_queue_started(self):
        # The POST may commit even when its response is lost. From this point,
        # keep the closed schedule on every nonterminal failure so cleanup
        # cannot accidentally start the still-owned attempt.
        self.queue_started = True

    def mark_terminal(self):
        self.terminal = True

    def _contain_conflict_probe(self):
        state = self.api(self.prefix + '/update-schedule')
        revision = state.get('revision')
        run_now = state.get('run_now_attempt_id')
        if revision == self.schedule_revision and run_now is None:
            # The timed-out handler may still hold an old expected revision.
            # Advance the closed policy by CAS before releasing our hold so a
            # delayed request cannot subsequently authorize the attempt.
            fenced = self.api(self.prefix + '/update-schedule',
                {'expected_revision': revision, 'schedule': self.closed_schedule_value})
            if (fenced.get('revision') != revision + 1
                    or fenced.get('schedule') != self.closed_schedule_value
                    or fenced.get('run_now_attempt_id') is not None):
                raise ValueError('Q07 delayed Update now revision fence failed')
            self.schedule_revision = fenced['revision']
            self.conflict_probe_pending = False
            _log('delayed_update_now_revision_fenced', revision=self.schedule_revision)
            return
        if (revision == self.schedule_revision + 1
                and state.get('schedule') == self.closed_schedule_value
                and run_now == self.attempt):
            # Withdraw only the exact unexpected authorization using the
            # revision it created. Saving the same closed policy clears the
            # run-now exception without opening the admitted attempt.
            withdrawn = self.api(self.prefix + '/update-schedule',
                {'expected_revision': revision, 'schedule': self.closed_schedule_value})
            if (withdrawn.get('revision') != revision + 1
                    or withdrawn.get('schedule') != self.closed_schedule_value
                    or withdrawn.get('run_now_attempt_id') is not None):
                raise ValueError('Q07 exact unexpected Update now withdrawal failed')
            self.schedule_revision = withdrawn['revision']
            self.conflict_probe_pending = False
            _log('unexpected_exact_update_now_withdrawn', revision=self.schedule_revision)
            return
        if run_now != self.attempt:
            # A newer exact schedule save already withdrew our exception, or
            # a foreign authorization replaced it. Never overwrite that state.
            self.conflict_probe_pending = False
            _log('unexpected_update_now_no_longer_current')
            return
        raise ValueError('Q07 cannot contain unexpected Update now without overwriting newer state')

    def cleanup(self, required):
        errors = []
        if self.maintenance_probe_pending:
            # A timed-out POST may still be waiting on its request-id lock and
            # commit after any subsequent GET. Only prepare's received 409 plus
            # unchanged projection proves rejection; every ambiguous response
            # retains both the exact lease and closed schedule.
            errors.append(ValueError('Q07 maintenance admission response remained ambiguous'))
            _log('maintenance_probe_containment_incomplete')
        if self.lease_owned and not self.maintenance_probe_pending:
            try:
                self._release_lease(required)
            except BaseException as error:
                errors.append(error)
        elif self.lease_owned:
            _log('exact_maintenance_lease_retained_for_incomplete_probe')
        if self.conflict_probe_pending:
            try:
                self._contain_conflict_probe()
            except BaseException as error:
                errors.append(error)
                _log('unexpected_update_now_containment_incomplete')
        if self.hold_owned and not self.conflict_probe_pending:
            try:
                node = _node(self.api, self.prefix)
                current = {field: node.get(field) for field in MUTABLE_NODE_FIELDS}
                if node.get('update_hold') is False:
                    self.hold_owned = False
                elif current == self.hold_projection:
                    released = self._mutate_node(node, update_hold=False)
                    if released.get('update_hold') is not False:
                        raise ValueError('Q07 owned update hold cleanup failed')
                    self.hold_owned = False
                    _log('owned_update_hold_cleanup')
                else:
                    _log('cleanup_skipped_newer_update_hold_state')
                    if required:
                        raise ValueError('Q07 update hold changed before cleanup')
            except BaseException as error:
                errors.append(error)
        elif self.hold_owned:
            _log('owned_update_hold_retained_for_incomplete_containment')
        if self.original_schedule is not None:
            try:
                state = self.api(self.prefix + '/update-schedule')
                if (self.schedule_revision is None
                        and state.get('revision') == self.original_schedule_revision + 1
                        and state.get('schedule') == self.closed_schedule_value
                        and state.get('run_now_attempt_id') is None):
                    # The closed-schedule response was lost after commit.
                    self.schedule_revision = state['revision']
                if (self.run_now_pending and self.schedule_revision is not None
                        and state.get('revision') == self.schedule_revision + 1
                        and state.get('schedule') == self.closed_schedule_value
                        and state.get('run_now_attempt_id') == self.attempt):
                    # The exact-attempt authorization response was lost after
                    # commit. Preserve it unless the transition is terminal.
                    self.schedule_revision = state['revision']
                    self.run_now_owned = True
                    self.run_now_pending = False
                safe = (state.get('revision') == self.schedule_revision
                    and (not self.queue_started or self.terminal)
                    and (not self.run_now_owned or self.terminal)
                    and state.get('run_now_attempt_id') in (None, self.attempt))
                if safe:
                    restored = self.api(self.prefix + '/update-schedule',
                        {'expected_revision': self.schedule_revision,
                         'schedule': self.original_schedule})
                    if (restored.get('revision') != self.schedule_revision + 1
                            or restored.get('schedule') != self.original_schedule
                            or restored.get('run_now_attempt_id') is not None):
                        raise ValueError('Q07 schedule restoration was not exact')
                    self.original_schedule = None
                    _log('owned_schedule_restored', revision=restored['revision'])
                else:
                    _log('cleanup_skipped_newer_or_active_schedule')
                    if required:
                        raise ValueError('Q07 schedule cannot be safely restored')
            except BaseException as error:
                errors.append(error)
        if errors and required:
            raise ValueError('Q07 could not restore all owned policy state') from errors[0]
        if errors:
            _log('best_effort_cleanup_incomplete', conditions=len(errors))
