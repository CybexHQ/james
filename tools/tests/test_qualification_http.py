import http.client
import importlib.util
import io
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


HTTP = module('qualification_http_test', ROOT /
              'nixos-appliance/qualification/qualification_http.py')


class Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def read(self, size):
        return self.value[:size]


def request(method='GET'):
    return urllib.request.Request('https://dev.example.test/v1/qualification',
                                  method=method)


class QualificationHttpTests(unittest.TestCase):
    def test_readonly_transient_failures_retry_and_capture_a_fresh_response(self):
        expected = {'state': 'ready'}
        client = Mock()
        client.open.side_effect = [
            urllib.error.URLError(ssl.SSLEOFError('TLS peer closed unexpectedly')),
            urllib.error.URLError(TimeoutError('handshake timed out')),
            http.client.IncompleteRead(b'{"partial"'),
            Response(json.dumps(expected).encode()),
        ]
        sleep = Mock()

        self.assertEqual(HTTP.request_json(client, request(), timeout=10,
                                           max_bytes=1024, sleep=sleep), expected)
        self.assertEqual(client.open.call_count, HTTP.GET_ATTEMPTS)
        self.assertEqual(sleep.call_count, HTTP.GET_ATTEMPTS - 1)

    def test_only_selected_transient_http_statuses_are_retried(self):
        for status in (408, 429, 502, 503, 504):
            with self.subTest(status=status):
                client = Mock()
                error = urllib.error.HTTPError(
                    request().full_url, status, 'transient', {}, io.BytesIO())
                client.open.side_effect = [
                    error,
                    Response(b'{"ok":true}'),
                ]
                self.assertEqual(HTTP.request_json(client, request(), timeout=10,
                                                   max_bytes=1024, sleep=Mock()), {'ok': True})
                self.assertEqual(client.open.call_count, 2)
                self.assertTrue(error.fp.closed)

        client = Mock()
        client.open.side_effect = urllib.error.HTTPError(
            request().full_url, 500, 'not selected', {}, io.BytesIO())
        with self.assertRaises(urllib.error.HTTPError):
            HTTP.request_json(client, request(), timeout=10, max_bytes=1024)
        client.open.assert_called_once()

    def test_response_cap_is_not_retried(self):
        client = Mock()
        client.open.return_value = Response(b'123456')
        with self.assertRaisesRegex(ValueError, 'exceeded its bound'):
            HTTP.request_json(client, request(), timeout=10, max_bytes=4)
        client.open.assert_called_once()

    def test_transient_retry_count_is_bounded(self):
        client = Mock()
        client.open.side_effect = urllib.error.URLError(
            TimeoutError('handshake timed out'))
        sleep = Mock()
        with self.assertRaises(urllib.error.URLError):
            HTTP.request_json(client, request(), timeout=10,
                              max_bytes=1024, sleep=sleep)
        self.assertEqual(client.open.call_count, HTTP.GET_ATTEMPTS)
        self.assertEqual(sleep.call_count, HTTP.GET_ATTEMPTS - 1)

    def test_mutation_response_loss_is_not_retried(self):
        client = Mock()
        client.open.side_effect = http.client.IncompleteRead(b'{"accepted":true')
        with self.assertRaises(http.client.IncompleteRead):
            HTTP.request_json(client, request('POST'), timeout=10, max_bytes=1024)
        client.open.assert_called_once()

    def test_redirect_refusal_and_auth_failure_are_not_retried(self):
        failures = [
            ValueError('Qualification API redirect refused'),
            urllib.error.HTTPError(request().full_url, 403, 'forbidden', {}, io.BytesIO()),
        ]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                client = Mock()
                client.open.side_effect = failure
                with self.assertRaises(type(failure)):
                    HTTP.request_json(client, request(), timeout=10, max_bytes=1024)
                client.open.assert_called_once()

    def test_certificate_verification_failure_is_not_retried(self):
        client = Mock()
        client.open.side_effect = urllib.error.URLError(
            ssl.SSLCertVerificationError('certificate verify failed'))
        with self.assertRaises(urllib.error.URLError):
            HTTP.request_json(client, request(), timeout=10, max_bytes=1024)
        client.open.assert_called_once()

    def test_shell_api_propagates_curl_failure_from_conditional_call(self):
        script = (ROOT / 'nixos-appliance/qualification/run-lifecycle.sh').read_text()
        function = script[script.index('api() {'):script.index('\n}\n\ncheck_delivery_policy') + 2]
        with tempfile.TemporaryDirectory() as temporary:
            command = function + r'''
curl() {
  local previous='' output=''
  for argument in "$@"; do
    if [[ "$previous" = --output ]]; then output="$argument"; fi
    previous="$argument"
  done
  printf partial > "$output"
  return 56
}
sleep() { :; }
work_dir="$1"
token=private
manage_origin=https://dev.example.test
if api GET /v1/test; then exit 99; else status=$?; fi
[[ "$status" = 56 ]]
[[ ! -e "$work_dir/api-response.json" ]]
'''
            result = subprocess.run(['bash', '-c', command, 'test', temporary],
                                    capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')

    def test_shell_api_retries_only_selected_readonly_failures(self):
        script = (ROOT / 'nixos-appliance/qualification/run-lifecycle.sh').read_text()
        function = script[script.index('api() {'):script.index('\n}\n\ncheck_delivery_policy') + 2]
        with tempfile.TemporaryDirectory() as temporary:
            command = function + r'''
calls=0
curl() {
  local previous='' output='' calls
  calls="$(cat "$work_dir/calls" 2>/dev/null || printf 0)"
  ((calls += 1))
  printf '%s' "$calls" > "$work_dir/calls"
  for argument in "$@"; do
    if [[ "$previous" = --output ]]; then output="$argument"; fi
    previous="$argument"
  done
  if ((calls == 1)); then printf partial > "$output"; printf 503; return 22; fi
  printf '{"ok":true}' > "$output"; printf 200
}
sleep() { :; }
work_dir="$1"
token=private
manage_origin=https://dev.example.test
value="$(api GET /v1/test)"
[[ "$value" = '{"ok":true}' ]]
'''
            result = subprocess.run(['bash', '-c', command, 'test', temporary],
                                    capture_output=True, text=True, check=False)
            calls = (Path(temporary) / 'calls').read_text()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, '2')

        for code, http_code, expected in ((22, 403, 22), (22, 500, 22),
                                          (60, 0, 60), (0, 302, 22)):
            with tempfile.TemporaryDirectory() as temporary:
                command = function + f'''
calls=0
curl() {{
  local calls
  calls="$(cat "$work_dir/calls" 2>/dev/null || printf 0)"
  ((calls += 1))
  printf '%s' "$calls" > "$work_dir/calls"
  printf {http_code}
  return {code}
}}
sleep() {{ :; }}
work_dir="$1"
token=private
manage_origin=https://dev.example.test
if api GET /v1/test; then exit 99; else status=$?; fi
[[ "$status" = {expected} ]]
[[ "$(cat "$work_dir/calls")" = 1 ]]
'''
                result = subprocess.run(['bash', '-c', command, 'test', temporary],
                                        capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

        with tempfile.TemporaryDirectory() as temporary:
            command = function + r'''
curl() {
  local calls
  calls="$(cat "$work_dir/calls" 2>/dev/null || printf 0)"
  ((calls += 1))
  printf '%s' "$calls" > "$work_dir/calls"
  return 56
}
sleep() { :; }
work_dir="$1"
token=private
manage_origin=https://dev.example.test
if api POST /v1/test '{}'; then exit 99; else status=$?; fi
[[ "$status" = 56 ]]
[[ "$(cat "$work_dir/calls")" = 1 ]]
'''
            result = subprocess.run(['bash', '-c', command, 'test', temporary],
                                    capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
