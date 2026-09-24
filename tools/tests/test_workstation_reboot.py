"""Deterministic reboot/verification interleavings; no VM or API access."""
import datetime
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'
sys.path.insert(0, str(HELPERS))
import isolated_manage_transport as transport
import workstation_lifecycle as workstation

START = datetime.datetime(2026, 9, 25, tzinfo=datetime.timezone.utc)
VERIFY = 'cf05b8f8-f6f3-4d3a-b908-9d223fc509d8'


def rejection(message, status=409):
    response = mock.Mock(status=status)
    response.getheader.return_value = None
    response.read.return_value = json.dumps({'error': message}).encode()
    connection = mock.Mock()
    connection.getresponse.return_value = response
    try:
        transport.Transport.read(connection)
    except ValueError as error:
        return error
    raise AssertionError('expected an HTTP rejection')


def observation(second, *, configuration=None, verified=None, operation=None):
    device = {'facts_json': {'boot_id': 'new'},
              'last_seen_at': (START + datetime.timedelta(seconds=second)).isoformat(),
              'configuration_status': 'unknown', 'active_operation': operation}
    if verified is not None:
        device.update(configuration_status='compliant',
                      configuration_verified_at=(START + datetime.timedelta(seconds=verified)).isoformat())
    commands = [{'id': 'reboot', 'command_type': 'reboot', 'status': 'completed'}]
    if configuration:
        kind, status = configuration
        commands.append({'id': VERIFY, 'command_type': kind, 'status': status})
    return second, device, commands


class RebootTests(unittest.TestCase):
    def scenario(self, observations, *, conflict=None):
        calls = []
        clock = START
        commands = []
        before = {'facts_json': {'boot_id': 'old'}}

        def api(path, body=None):
            if body is None:
                return {'commands': commands}
            kind = body['command_type']
            calls.append(kind)
            if kind == 'verify_blueprint':
                if conflict is not None:
                    raise conflict
                if any(c['command_type'] in ('apply_blueprint', 'verify_blueprint')
                       and c['status'] in ('pending', 'dispatched') for c in commands):
                    raise rejection(f'configuration command {VERIFY} is already pending for this device')
            return {'id': kind}

        def wait_for(label, read, accept, timeout):
            nonlocal clock, commands
            self.assertLessEqual(timeout, 900)
            for second, device, commands in observations:
                clock = START + datetime.timedelta(seconds=second)
                if accept(device):
                    return device
            raise TimeoutError(label)

        with mock.patch.object(workstation, 'now', side_effect=lambda: clock):
            result = workstation.managed_reboot(api, '/v1/devices/owned', before, wait_for, lambda: None)
        return calls, result

    def test_reuses_active_post_reboot_verification(self):
        for status in ('pending', 'dispatched'):
            with self.subTest(status=status):
                calls, result = self.scenario([
                    observation(1, configuration=('verify_blueprint', status),
                                operation={'status': 'active', 'phase': 'verifying', 'active_attempt_id': VERIFY}),
                    observation(3, configuration=('verify_blueprint', 'completed'), verified=2),
                ])
                self.assertEqual(calls, ['reboot'])
                self.assertEqual(result['configuration_status'], 'compliant')

    def test_configuration_slot_won_between_read_and_post_is_reobserved(self):
        error = rejection(f'configuration command {VERIFY} is already dispatched for this device')
        calls, result = self.scenario([
            observation(1),
            observation(2, configuration=('verify_blueprint', 'dispatched')),
            observation(4, configuration=('verify_blueprint', 'completed'), verified=3),
        ], conflict=error)
        self.assertEqual(calls, ['reboot', 'verify_blueprint'])
        self.assertEqual(result['configuration_status'], 'compliant')

    def test_active_operation_without_configuration_command_does_not_block_probe(self):
        calls, _ = self.scenario([observation(1, operation={
            'status': 'active', 'phase': 'awaiting_restart', 'wait_code': '',
        })])
        self.assertEqual(calls, ['reboot', 'verify_blueprint'])

    def test_waits_for_apply_and_does_not_reuse_old_boot_compliance(self):
        calls, _ = self.scenario([
            observation(1, configuration=('apply_blueprint', 'dispatched'), verified=0),
            observation(3, configuration=('apply_blueprint', 'completed'), verified=0),
        ])
        self.assertEqual(calls, ['reboot', 'verify_blueprint'])

    def test_compliance_after_reboot_request_but_before_observed_return_is_not_reused(self):
        calls, _ = self.scenario([observation(3, verified=2)])
        self.assertEqual(calls, ['reboot', 'verify_blueprint'])

    def test_another_boot_while_waiting_requires_new_verification(self):
        second_return = observation(3, configuration=('verify_blueprint', 'completed'), verified=2)
        second_return[1]['facts_json']['boot_id'] = 'newer'
        calls, _ = self.scenario([
            observation(1, configuration=('verify_blueprint', 'pending')),
            second_return,
        ])
        self.assertEqual(calls, ['reboot', 'verify_blueprint'])

    def test_unrelated_http_conflicts_and_server_failures_remain_fatal(self):
        for status, message in [(409, 'apply the assigned Blueprint before requesting verification'),
                                (409, 'verify blueprint is unsupported by this device agent'),
                                (500, 'internal failure')]:
            error = rejection(message, status)
            with self.subTest(status=status, message=message), self.assertRaises(type(error)) as raised:
                self.scenario([observation(1), observation(2, verified=2)], conflict=error)
            self.assertIs(raised.exception, error)

    def test_busy_verification_cannot_succeed_without_fresh_evidence(self):
        with self.assertRaises(TimeoutError):
            self.scenario([observation(second, configuration=('verify_blueprint', 'pending'))
                           for second in (1, 2, 3)])

    def test_blocked_operation_uses_status_and_preserves_reason_or_wait_code(self):
        for field in ('reason_code', 'wait_code'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'configuration_drift'):
                workstation.require_operation_progress({'active_operation': {
                    'status': 'blocked', field: 'configuration_drift',
                }})
        workstation.require_operation_progress({'active_operation': {
            'status': 'active', 'phase': 'waiting_for_blueprint', 'wait_code': 'device_configuration_busy',
        }})


if __name__ == '__main__':
    unittest.main()
