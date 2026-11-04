"""Opt-in, non-mutating API smoke against the development deployment.

TIARIS_NEST_LIVE_ORIGIN=https://dev.tiaris.com python3 -B -m unittest discover \
    -s nixos-appliance/tests -p test_live_nest_cache.py -v
"""
import datetime
import json
import os
import unittest
import urllib.error
import urllib.request
import uuid


@unittest.skipUnless(os.environ.get('TIARIS_NEST_LIVE_ORIGIN'), 'opt-in development API smoke')
class LiveNestCache(unittest.TestCase):
    def request(self, path, data=None, headers=None):
        origin = os.environ['TIARIS_NEST_LIVE_ORIGIN']
        self.assertEqual(origin, 'https://dev.tiaris.com', 'live tests target development only')
        request = urllib.request.Request(origin + path,
            data=None if data is None else json.dumps(data).encode(),
            headers={'Accept': 'application/json', 'Content-Type': 'application/json',
                     'User-Agent': 'Tiaris-Nest-nightly/1.0', **(headers or {})})
        try:
            response = urllib.request.urlopen(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, json.loads(response.read())

    def test_development_health_contract(self):
        status, _, body = self.request('/v1/health')
        self.assertEqual(status, 200)
        self.assertEqual(body['status'], 'ok')
        self.assertEqual(body['environment'], 'development')
        self.assertIn('signed_device_requests_v1', body['capabilities'])

    def test_anonymous_cache_inventory_access_is_denied(self):
        for path in ('/v1/nest/nodes', '/v1/nest/nodes/nightly-unauthenticated/cache/artifacts'):
            with self.subTest(path=path):
                status, _, _ = self.request(path)
                self.assertEqual(status, 401)

    def test_an_unknown_nest_cannot_publish_egress_totals(self):
        device = 'nightly-nonexistent-' + uuid.uuid4().hex
        status, _, body = self.request('/v1/agent/devices/' + device + '/nest/report',
            data={'protocol_version': 5, 'cache': {'served_bytes_total': 9000000}},
            headers={'x-tiaris-device-id': device, 'x-tiaris-request-id': uuid.uuid4().hex,
                     'x-tiaris-timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     'x-tiaris-signature': 'A' * 86})
        self.assertEqual(status, 404)
        self.assertEqual(body['error'], 'device not found')


if __name__ == '__main__':
    unittest.main()
