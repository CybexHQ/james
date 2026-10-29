"""Exercise bounded Incus reads without host sockets, services or resources."""
import copy
import io
import json
from types import SimpleNamespace
import stat
import struct
import unittest
from unittest.mock import Mock, patch

from test_isolated_manage_network import Host, network


def connection(metadata=None, *, timeout_at=None, status=200, uid=0, pid=123):
    value = Mock()
    value.sock.getsockopt.return_value = struct.pack('3i', pid, uid, 0)
    response = value.getresponse.return_value
    response.status = status
    response.getheader.return_value = 'exact-network-revision'
    response.read.return_value = json.dumps({
        'type': 'sync', 'status_code': 200, 'metadata': metadata or {}}).encode()
    if timeout_at == 'body':
        response.read.side_effect = TimeoutError('private daemon details')
    elif timeout_at is not None:
        getattr(value, timeout_at).side_effect = TimeoutError('private daemon details')
    return value


class IncusReadTimeoutTests(unittest.TestCase):
    def setUp(self):
        self.socket = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
        self.stat = self.enterContext(patch.object(network.os, 'lstat', return_value=self.socket))
        self.factory = self.enterContext(patch.object(network, '_UnixHTTPConnection'))
        self.diagnostic = io.StringIO()
        self.enterContext(patch.object(network.sys, 'stderr', self.diagnostic))

    def test_timeout_retries_a_fresh_read_once_and_closes_every_connection(self):
        for phase in ('connect', 'request', 'getresponse', 'body'):
            with self.subTest(phase=phase):
                self.stat.reset_mock()
                stalled = connection(timeout_at=phase)
                healthy = connection({'fresh': True})
                self.factory.side_effect = [stalled, healthy]
                result = network.IncusAPI().get('owned fixture')
                self.assertEqual(result, ({'fresh': True}, 'exact-network-revision'))
                self.assertEqual(self.stat.call_count, 2)
                healthy.sock.getsockopt.assert_called_once()
                healthy.request.assert_called_once_with('GET',
                    '/1.0/networks/owned%20fixture?project=default',
                    body=None, headers={'Accept': 'application/json'})
                stalled.close.assert_called_once()
                healthy.close.assert_called_once()
        self.assertNotIn('private daemon details', self.diagnostic.getvalue())
        self.assertNotIn('owned fixture', self.diagnostic.getvalue())

    def test_repeated_timeout_fails_after_exactly_two_reads(self):
        first, second = connection(timeout_at='getresponse'), connection(timeout_at='getresponse')
        self.factory.side_effect = [first, second]
        with self.assertRaises(TimeoutError):
            network.IncusAPI().get('fixture')
        self.assertEqual(self.factory.call_count, 2)
        self.assertEqual(self.stat.call_count, 2)
        first.close.assert_called_once()
        second.close.assert_called_once()

    def test_socket_ownership_is_revalidated_before_retry(self):
        stalled = connection(timeout_at='getresponse')
        self.factory.side_effect = [stalled]
        foreign = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=1000)
        self.stat.side_effect = [self.socket, foreign]
        with self.assertRaisesRegex(ValueError, 'root-owned and private'):
            network.IncusAPI().get('fixture')
        self.assertEqual(self.factory.call_count, 1)
        stalled.close.assert_called_once()

    def test_peer_ownership_is_revalidated_and_failure_is_not_retried(self):
        stalled, foreign = connection(timeout_at='getresponse'), connection(uid=1000)
        self.factory.side_effect = [stalled, foreign]
        with self.assertRaisesRegex(ValueError, 'root daemon'):
            network.IncusAPI().get('fixture')
        self.assertEqual(self.factory.call_count, 2)
        foreign.request.assert_not_called()
        stalled.close.assert_called_once()
        foreign.close.assert_called_once()

    def test_invalid_http_json_and_exact_revision_never_retry(self):
        for invalid in ('http', 'json', 'response', 'metadata', 'etag'):
            with self.subTest(invalid=invalid):
                self.factory.reset_mock()
                current = connection(status=503 if invalid == 'http' else 200)
                if invalid == 'json':
                    current.getresponse.return_value.read.return_value = b'not json'
                elif invalid == 'response':
                    current.getresponse.return_value.read.return_value = b'{"type":"async","status_code":100}'
                elif invalid == 'metadata':
                    current.getresponse.return_value.read.return_value = b'{"type":"sync","status_code":200,"metadata":null}'
                elif invalid == 'etag':
                    current.getresponse.return_value.getheader.return_value = None
                self.factory.side_effect = [current]
                with self.assertRaises(ValueError):
                    network.IncusAPI().get('fixture')
                self.factory.assert_called_once()
                current.close.assert_called_once()

    def test_compare_and_swap_timeout_is_never_replayed(self):
        for phase in ('connect', 'request', 'getresponse', 'body'):
            with self.subTest(phase=phase):
                self.factory.reset_mock()
                current = connection(timeout_at=phase)
                self.factory.side_effect = [current]
                with self.assertRaises(TimeoutError):
                    network.IncusAPI().replace_config({'name': 'fixture'}, 'etag-1', {'exact': 'config'})
                self.factory.assert_called_once()
                current.close.assert_called_once()

    def test_other_transport_failures_are_not_retried(self):
        current = connection()
        current.getresponse.side_effect = ConnectionResetError('private daemon details')
        self.factory.side_effect = [current]
        with self.assertRaises(ConnectionResetError):
            network.IncusAPI().get('fixture')
        self.factory.assert_called_once()
        current.close.assert_called_once()
        self.assertEqual(self.diagnostic.getvalue(), '')

    def test_successful_retry_still_verifies_fresh_network_firewall_and_dns(self):
        for changed in ('none', 'guest', 'backend', 'firewall', 'dns'):
            with self.subTest(changed=changed):
                self.factory.reset_mock()
                host = Host()
                receipt = host.adapter.prepare(host.c)
                guest = copy.deepcopy(host.guest)
                if changed == 'guest':
                    guest['config']['user.tiaris.nixos-qualification'] = 'foreign'
                elif changed == 'backend':
                    host.backend['Internal'] = False
                elif changed == 'firewall':
                    host.live = None
                elif changed == 'dns':
                    host.dns_identity['argv'] = ['foreign-dns']
                stalled, fresh = connection(timeout_at='getresponse'), connection(guest)
                self.factory.side_effect = [stalled, fresh]
                host.adapter.incus = network.IncusAPI()
                if changed == 'none':
                    self.assertTrue(host.adapter.verify(host.c, receipt))
                else:
                    with self.assertRaises(ValueError):
                        host.adapter.verify(host.c, receipt)
                self.assertEqual(self.factory.call_count, 2)
                stalled.close.assert_called_once()
                fresh.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
