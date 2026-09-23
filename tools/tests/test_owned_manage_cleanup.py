"""The qualification runner retires only its proven, stopped Manage fixture."""
from copy import deepcopy
import errno
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import Mock, call, patch

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'
sys.path.insert(0, str(HELPERS))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HELPERS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('qualification_owned_manage_cleanup', 'owned_manage_cleanup.py')
R = load('qualification_owned_manage_runner', 'run-production-qualification.py')


class OwnedManageCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        self.state.chmod(0o700)
        self.session_id = str(uuid.uuid4())
        self.device_id = 'dev_' + 'a' * 32
        self.mac = '02:01:02:03:04:05'
        self.version = '0.2.27-dev.4'
        self.scope = {'run': 'owned-cold', 'owner': str(uuid.uuid4()),
                      'bridge': 'jnqowned', 'manage_origin': 'https://dev.example.com'}
        self.receipt = self.state / 'lifecycle-session.json'
        self.receipt.write_text(json.dumps({'session_id': self.session_id}))
        self.receipt.chmod(0o600)
        self.session = {'id': self.session_id, 'label': 'release qualification',
                        'release_version': self.version, 'state': 'ready',
                        'recovery_device': None, 'reserved_device_id': self.device_id,
                        'inventory': {'ethernet_interfaces': [{'mac': self.mac}]},
                        'install_plan': {'session_id': self.session_id,
                                         'reserved_device_id': self.device_id,
                                         'network_interface': {'mac': self.mac},
                                         'release_version': self.version,
                                         'display_name': 'Owned James'}}
        self.device = {'device_id': self.device_id, 'device_kind': 'cybex-james',
                       'enrollment_id': 'jamesprov_' + uuid.UUID(self.session_id).hex,
                       'hostname': 'james-' + uuid.UUID(self.session_id).hex[:12],
                       'display_name': 'Owned James'}
        self.scope_patch = patch.dict(C.SCOPE, {
            'read_scope': Mock(return_value=self.scope),
            'hardware_identity': Mock(return_value={'mac': self.mac})})
        self.scope_patch.start()
        self.addCleanup(self.scope_patch.stop)

    def api(self, session=None, device=None):
        session = session or self.session
        device = device or self.device
        session_path = '/v1/james/provisioning-sessions/' + self.session_id
        device_path = '/v1/devices/' + self.device_id

        def request(path, body=None):
            if path == session_path and body is None:
                return ({**session, 'state': 'revoked'} if request.decommissioned else session)
            if path == device_path and body is None:
                return device
            if path == device_path + '/decommission' and body == {}:
                request.decommissioned = True
                return {'status': 'decommissioned'}
            if path == session_path + '/revoke' and body == {}:
                return {**session, 'state': 'revoked'}
            raise AssertionError((path, body))

        request.decommissioned = False
        return Mock(side_effect=request)

    def test_owned_ready_device_decommissions_then_confirms_session_revoked(self):
        api = self.api()
        self.assertEqual(C.retire_owned(self.state, self.scope, self.version, api)['action'],
                         'decommissioned')
        self.assertEqual(api.call_args_list, [
            call('/v1/james/provisioning-sessions/' + self.session_id),
            call('/v1/devices/' + self.device_id),
            call('/v1/devices/' + self.device_id + '/decommission', {}),
            call('/v1/james/provisioning-sessions/' + self.session_id)])

    def test_unreserved_created_session_is_revoked_without_device_write(self):
        session = {**self.session, 'state': 'created', 'reserved_device_id': None,
                   'inventory': None, 'install_plan': None}
        api = self.api(session=session)
        self.assertEqual(C.retire_owned(self.state, self.scope, self.version, api)['action'],
                         'revoked')
        self.assertEqual(api.call_args_list[-1],
                         call('/v1/james/provisioning-sessions/' + self.session_id + '/revoke', {}))

    def test_mismatched_or_unproven_ownership_never_mutates_manage(self):
        changes = [({'release_version': 'other'}, {}),
                   ({'recovery_device': {'device_id': self.device_id}}, {}),
                   ({'inventory': {'ethernet_interfaces': [{'mac': '02:ff:ff:ff:ff:ff'}]}}, {}),
                   ({'install_plan': {**self.session['install_plan'], 'session_id': str(uuid.uuid4())}}, {}),
                   ({}, {'enrollment_id': 'jamesprov_' + uuid.uuid4().hex}),
                   ({}, {'device_kind': 'workstation'}),
                   ({}, {'hostname': 'foreign'})]
        for session_changes, device_changes in changes:
            with self.subTest(session=session_changes, device=device_changes):
                api = self.api({**deepcopy(self.session), **session_changes},
                               {**self.device, **device_changes})
                with self.assertRaises(ValueError):
                    C.retire_owned(self.state, self.scope, self.version, api)
                self.assertFalse(any('/decommission' in c.args[0] or '/revoke' in c.args[0]
                                     for c in api.call_args_list))
        with patch.dict(C.SCOPE, {'read_scope': Mock(return_value={'owner': 'foreign'})}):
            api = self.api()
            with self.assertRaises(ValueError):
                C.retire_owned(self.state, self.scope, self.version, api)
            api.assert_not_called()

    def test_foreign_fixture_receipt_blocks_decommission(self):
        fixture = self.state / 'fixture'
        fixture.mkdir(mode=0o700)
        receipt = fixture / 'fixture.json'
        receipt.write_text(json.dumps({'schema': 'cybex.james.qualification-fixture.v1',
                                       'device_id': self.device_id, 'bridge': self.scope['bridge'],
                                       'mac': '02:ff:ff:ff:ff:ff'}))
        receipt.chmod(0o600)
        api = self.api()
        with self.assertRaisesRegex(ValueError, 'fixture differs'):
            C.retire_owned(self.state, self.scope, self.version, api)
        self.assertFalse(any('/decommission' in c.args[0] for c in api.call_args_list))

    def test_runner_retires_only_after_network_cleanup_and_keeps_receipt(self):
        (self.state / 'session').write_text('private token')
        events = []
        with patch.object(R, 'API', return_value=object()) as make_api, \
                patch.object(R, 'execute', side_effect=lambda *args, **kwargs: events.append('network')), \
                patch.object(R, 'write_teardown_receipt', side_effect=lambda *args: events.append('receipt')), \
                patch.object(R, 'retry_retire_owned', side_effect=lambda *args: events.append('manage') or
                             {'session_id': self.session_id, 'action': 'revoked'}):
            R.cleanup_phase(self.state, self.scope, self.scope['manage_origin'], None, self.version)
        self.assertEqual(events, ['receipt', 'network', 'manage'])
        make_api.assert_called_once_with(self.state)
        self.assertFalse((self.state / 'session').exists())
        self.assertEqual(json.loads((self.state / 'manage-cleanup.json').read_text())['action'], 'revoked')
        self.assertTrue(self.receipt.exists())

    def test_failed_network_cleanup_fences_manage_write_and_erases_token(self):
        (self.state / 'session').write_text('private token')
        with patch.object(R, 'API', return_value=object()), \
                patch.object(R, 'execute', side_effect=RuntimeError('network busy')), \
                patch.object(R, 'retry_retire_owned') as retire:
            with self.assertRaisesRegex(RuntimeError, 'network busy'):
                R.cleanup_phase(self.state, self.scope, self.scope['manage_origin'], None, self.version)
            retire.assert_not_called()
        self.assertTrue((self.state / 'session').exists())
        self.assertTrue((self.state / 'manage-teardown.json').exists())

    def test_admission_cleanup_precedes_network_and_its_failure_still_cleans_network(self):
        (self.state / 'session').write_text('private token')
        (self.state / 'qualification-allowlist.json').write_text('{}')
        events = []

        def execute(*args, **_kwargs):
            events.append('admission' if args[0] == Path('/owned/allow-helper') else 'network')
            if events[0] == 'admission' and len(events) == 1:
                raise RuntimeError('admission cleanup failed')

        with patch.object(R, 'execute', side_effect=execute), patch.object(R, 'API') as make_api, \
                patch.object(R, 'retry_retire_owned') as retire:
            with self.assertRaisesRegex(RuntimeError, 'admission cleanup failed'):
                R.cleanup_phase(self.state, self.scope, self.scope['manage_origin'],
                                Path('/owned/allow-helper'), self.version)
        self.assertEqual(events, ['admission', 'network'])
        make_api.assert_not_called()
        retire.assert_not_called()
        self.assertTrue((self.state / 'session').exists())

    def test_interruption_after_network_teardown_has_durable_retry_intent(self):
        token = self.state / 'session'
        token.write_text('private token')
        token.chmod(0o600)
        events = []

        def network_cleanup(*_args, **_kwargs):
            self.assertTrue((self.state / 'manage-teardown.json').exists())
            events.append('network_removed')
            raise KeyboardInterrupt('interrupted immediately after network cleanup')

        with patch.object(R, 'API', return_value=object()), \
                patch.object(R, 'execute', side_effect=network_cleanup), \
                patch.object(R, 'retry_retire_owned') as retire:
            with self.assertRaises(KeyboardInterrupt):
                R.cleanup_phase(self.state, self.scope, self.scope['manage_origin'], None,
                                self.version)
        self.assertEqual(events, ['network_removed'])
        retire.assert_not_called()
        self.assertTrue(token.exists())
        with patch.dict(C.SCOPE, {'incus': Mock(return_value='[]')}):
            post = C.PostTeardownAPI(self.state)
        self.assertEqual((post.scope, post.version, post.token),
                         (self.scope, self.version, 'private token'))
        api = self.api()
        api.scope, api.version = post.scope, post.version
        with patch.object(C, 'PostTeardownAPI', return_value=api):
            result = C.retry_after_teardown(self.state)
        self.assertEqual(result['action'], 'decommissioned')
        self.assertFalse(token.exists())

    def test_confirmation_timeout_retries_without_second_decommission(self):
        api = self.api()
        original = api.side_effect
        failures = 0

        def response(path, body=None):
            nonlocal failures
            if original.decommissioned and path == '/v1/james/provisioning-sessions/' + self.session_id and failures == 0:
                failures += 1
                raise OSError(errno.ETIMEDOUT, 'confirmation timed out')
            return original(path, body)

        api.side_effect = response
        result = C.retry_retire_owned(self.state, self.scope, self.version, api)
        self.assertEqual(result['action'], 'already_terminal')
        self.assertEqual(sum('/decommission' in c.args[0] for c in api.call_args_list), 1)

    def test_failed_api_preserves_token_then_guarded_retry_finishes(self):
        (self.state / 'session').write_text('private token')
        with patch.object(R, 'API', return_value=object()), \
                patch.object(R, 'execute'), \
                patch.object(R, 'write_teardown_receipt') as write_receipt, \
                patch.object(R, 'retry_retire_owned', side_effect=OSError(errno.ETIMEDOUT, 'offline')):
            with self.assertRaises(OSError):
                R.cleanup_phase(self.state, self.scope, self.scope['manage_origin'], None, self.version)
        write_receipt.assert_called_once()
        self.assertTrue((self.state / 'session').exists())
        self.assertFalse((self.state / 'manage-cleanup.json').exists())
        api = self.api()
        api.scope = self.scope
        api.version = self.version
        with patch.object(C, 'PostTeardownAPI', return_value=api):
            receipt = C.retry_after_teardown(self.state)
        self.assertEqual(receipt['action'], 'decommissioned')
        self.assertFalse((self.state / 'session').exists())
        self.assertTrue((self.state / 'manage-cleanup.json').exists())

    def test_post_teardown_api_requires_exact_receipt_and_absent_bridge(self):
        token = self.state / 'session'
        token.write_text('private token')
        token.chmod(0o600)
        C.write_teardown_receipt(self.state, self.scope, self.version)
        with patch.dict(C.SCOPE, {'incus': Mock(return_value='[]')}):
            api = C.PostTeardownAPI(self.state)
            self.assertEqual((api.scope, api.version, api.token),
                             (self.scope, self.version, 'private token'))
        request_json = Mock(return_value={'ok': True})
        with patch.dict(C.HTTP, {'request_json': request_json}):
            self.assertEqual(api('/v1/health'), {'ok': True})
        request = request_json.call_args.args[1]
        self.assertEqual(request.full_url, self.scope['manage_origin'] + '/v1/health')
        self.assertEqual(request.get_header('Authorization'), 'Bearer private token')
        with patch.dict(C.SCOPE, {'incus': Mock(return_value=json.dumps([
                {'name': self.scope['bridge']}]))}):
            with self.assertRaisesRegex(ValueError, 'bridge still exists'):
                C.PostTeardownAPI(self.state)
        receipt = self.state / 'manage-teardown.json'
        value = json.loads(receipt.read_text())
        value['scope']['owner'] = 'foreign'
        receipt.write_text(json.dumps(value))
        with patch.dict(C.SCOPE, {'incus': Mock(return_value='[]')}):
            with self.assertRaisesRegex(ValueError, 'differs from the owned run'):
                C.PostTeardownAPI(self.state)

    def test_decommission_accepted_but_confirmation_failed_is_retryable(self):
        token = self.state / 'session'
        token.write_text('private token')
        token.chmod(0o600)
        api = self.api()
        ordinary_response = api.side_effect

        def unavailable_confirmation(path, body=None):
            if ordinary_response.decommissioned and path == '/v1/james/provisioning-sessions/' + self.session_id:
                raise OSError(errno.ETIMEDOUT, 'confirmation unavailable')
            return ordinary_response(path, body)

        api.side_effect = unavailable_confirmation
        with patch.object(R, 'API', return_value=api), patch.object(R, 'execute'):
            with self.assertRaises(OSError):
                R.cleanup_phase(self.state, self.scope, self.scope['manage_origin'], None, self.version)
        self.assertTrue(token.exists())
        self.assertTrue((self.state / 'manage-teardown.json').exists())
        self.assertEqual(sum('/decommission' in c.args[0] for c in api.call_args_list), 1)
        api.side_effect = ordinary_response
        api.scope, api.version = self.scope, self.version
        with patch.object(C, 'PostTeardownAPI', return_value=api):
            result = C.retry_after_teardown(self.state)
        self.assertEqual(result['action'], 'already_terminal')
        self.assertFalse(token.exists())
        self.assertEqual(sum('/decommission' in c.args[0] for c in api.call_args_list), 1)

    def test_existing_exact_cleanup_receipt_allows_final_token_removal(self):
        token = self.state / 'session'
        token.write_text('private token')
        token.chmod(0o600)
        first = {'session_id': self.session_id, 'device_id': self.device_id,
                 'action': 'decommissioned'}
        C.save_cleanup_receipt(self.state, first)
        api = self.api({**self.session, 'state': 'revoked'})
        api.scope, api.version = self.scope, self.version
        with patch.object(C, 'PostTeardownAPI', return_value=api):
            result = C.retry_after_teardown(self.state)
        self.assertEqual(result['action'], 'already_terminal')
        self.assertEqual(json.loads((self.state / 'manage-cleanup.json').read_text()), first)
        self.assertFalse(token.exists())


if __name__ == '__main__':
    unittest.main()
