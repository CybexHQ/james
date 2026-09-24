"""Only safe HTTP metadata survives fixture transport and RPC failures."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'
sys.path.insert(0, str(HELPERS))
import isolated_manage_rpc as rpc
import isolated_manage_transport as transport

SECRET = 'private-session-and-signed-media-secret'
BUSY = 'configuration command cf05b8f8-f6f3-4d3a-b908-9d223fc509d8 is already pending for this device'


def connection(status, body, headers=None):
    response = mock.Mock(status=status)
    response.getheader.side_effect = (headers or {}).get
    response.read.return_value = body
    value = mock.Mock()
    value.getresponse.return_value = response
    return value


class HTTPErrorTests(unittest.TestCase):
    def test_only_exact_configuration_slot_rejections_are_retryable(self):
        for message in (BUSY, BUSY.replace('pending', 'dispatched'),
                        'a configuration command is already active for this device'):
            with self.subTest(message=message), self.assertRaises(transport.ManageHTTPError) as raised:
                transport.Transport.read(connection(409, json.dumps({'error': message}).encode()))
            self.assertEqual(transport.http_error_details(raised.exception), {
                'status': 409, 'classification': 'configuration_command_busy',
            })

    def test_other_errors_keep_status_without_server_text_or_unknown_codes(self):
        for status, message in ((409, 'apply the assigned Blueprint before requesting verification'),
                                (409, 'verify blueprint is unsupported by this device agent'),
                                (409, BUSY + '\n' + SECRET), (401, SECRET), (500, BUSY)):
            with self.subTest(status=status, message=message), self.assertRaises(transport.ManageHTTPError) as raised:
                transport.Transport.read(connection(status, json.dumps({
                    'error': message, 'diagnostic_code': SECRET, 'token': SECRET,
                }).encode()))
            self.assertEqual(transport.http_error_details(raised.exception), {
                'status': status, 'classification': 'http_error',
            })
            self.assertNotIn(SECRET, str(raised.exception))
            self.assertNotIn(message, str(raised.exception))

    def test_malformed_or_large_error_body_is_never_classified_as_busy(self):
        for body in (b'not-json', b'[]', b'\xff',
                     json.dumps({'error': BUSY, 'padding': 'x' * 8192}).encode()):
            with self.subTest(body_size=len(body)), self.assertRaises(transport.ManageHTTPError) as raised:
                transport.Transport.read(connection(409, body))
            self.assertEqual(raised.exception.classification, 'http_error')

    def test_redirect_encoded_and_oversized_responses_still_fail_closed(self):
        for headers in ({'Location': 'https://untrusted.example/' + SECRET},
                        {'Content-Encoding': 'gzip'}):
            with self.subTest(headers=headers), self.assertRaises(transport.ManageHTTPError) as raised:
                transport.Transport.read(connection(409, json.dumps({'error': BUSY}).encode(), headers))
            self.assertEqual(raised.exception.classification, 'response_refused')
            self.assertNotIn(SECRET, str(raised.exception))
        oversized = connection(200, b'x' * 17)
        with mock.patch.object(transport, 'MAXIMUM', 16), self.assertRaises(transport.ManageHTTPError) as raised:
            transport.Transport.read(oversized)
        oversized.getresponse.return_value.read.assert_called_once_with(17)
        self.assertEqual(transport.http_error_details(raised.exception), {
            'status': 200, 'classification': 'response_refused',
        })

    def test_http_metadata_survives_rpc_even_with_owner_sibling_module_loading(self):
        spec = importlib.util.spec_from_file_location('_james_transport_for_test', HELPERS / 'isolated_manage_transport.py')
        sibling = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sibling)
        original = sibling.ManageHTTPError.from_response(409, json.dumps({'error': BUSY, 'secret': SECRET}).encode())
        response = json.loads(json.dumps(rpc.failure_response(original)))
        self.assertNotIn(SECRET, json.dumps(response))
        self.assertNotIn('error', response)
        with self.assertRaises(transport.ManageHTTPError) as raised:
            rpc.response_value(response)
        self.assertEqual(transport.http_error_details(raised.exception), {
            'status': 409, 'classification': 'configuration_command_busy',
        })

    def test_unstructured_errors_and_invalid_rpc_metadata_never_echo_secrets(self):
        response = rpc.failure_response(ValueError(SECRET))
        self.assertEqual(response, {'ok': False, 'value': None})
        with self.assertRaises(ValueError) as raised:
            rpc.response_value(response)
        self.assertNotIn(SECRET, str(raised.exception))
        for status, classification in ((409, SECRET), (200, 'configuration_command_busy'),
                                       (500, 'configuration_command_busy'), (True, 'http_error')):
            with self.subTest(status=status, classification=classification), self.assertRaises(ValueError) as raised:
                rpc.response_value({'ok': False, 'http_error': {
                    'status': status, 'classification': classification,
                }})
            self.assertNotIn(SECRET, str(raised.exception))


if __name__ == '__main__':
    unittest.main()
