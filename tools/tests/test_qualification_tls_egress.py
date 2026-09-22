"""The fixture can fetch upstream Nix bytes without reaching public Manage."""
import importlib.util
import socket
import socketserver
import ssl
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'


def load(name):
    spec = importlib.util.spec_from_file_location(name, HELPERS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hello = load('tls_client_hello')
proxy = load('isolated_manage_tls_proxy')
rules = load('isolated_manage_network_rules')
artifacts = load('isolated_manage_artifacts')


def client_hello(host):
    outgoing = ssl.MemoryBIO()
    connection = ssl.create_default_context().wrap_bio(ssl.MemoryBIO(), outgoing,
                                                       server_hostname=host)
    try:
        connection.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class Stream:
    def __init__(self, data):
        self.data = data
    def settimeout(self, _timeout):
        pass
    def recv(self, size):
        # Exercise arbitrary TCP segmentation.
        size = min(size, 3)
        value, self.data = self.data[:size], self.data[size:]
        return value


class TLSRoutingTests(unittest.TestCase):
    def test_upstream_dns_keeps_all_traffic_on_existing_private_tls_listener(self):
        context = {'owner': '01234567-89ab-cdef-0123-456789abcdef', 'bridge': 'jnq0123456789',
                   'subnet': '10.99.16.1/24', 'manage_origin': 'https://manage.cybex.net',
                   'peer_ipv4': '10.99.16.1', 'network_id': 'a' * 64,
                   'backend_subnet': '10.99.17.0/28', 'egress_hosts': []}
        enabled = context | {'egress_hosts': list(hello.UPSTREAM_HOSTS)}
        self.assertEqual(rules.ruleset(context), rules.ruleset(enabled))
        dns = rules.dns_config(enabled)
        for host in ('manage.cybex.net', *hello.UPSTREAM_HOSTS):
            self.assertIn('host-record=' + host + ',10.99.16.1\n', dns)
        self.assertIn('no-resolv\nno-hosts\nlocal=/#/\n', dns)
        self.assertIsNone(rules.receipt(enabled)['proxy_url'])
        self.assertEqual(artifacts.normalize_scope(enabled), enabled)
        with self.assertRaises(ValueError):
            artifacts.normalize_scope(context | {'egress_hosts': ['evil.example']})

    def test_real_tls_client_hello_and_fragmented_records_preserve_bytes(self):
        wire = client_hello('github.com')
        self.assertEqual(hello.receive(Stream(wire)), ('github.com', wire))
        payload = wire[5:]
        fragments = [payload[:20], payload[20:]]
        wire = b''.join(b'\x16\x03\x01' + len(part).to_bytes(2, 'big') + part for part in fragments)
        self.assertEqual(hello.receive(Stream(wire)), ('github.com', wire))

    def test_malformed_or_missing_names_are_rejected(self):
        wire = client_hello('github.com')
        for malformed in (b'', b'GET / HTTP/1.1\r\n', wire[:-1],
                          b'\x17' + wire[1:], b'\x16\x03\x01\xff\xff',
                          wire[:5] + b'\x02' + wire[6:]):
            with self.subTest(wire=malformed[:10]), self.assertRaises(ValueError):
                hello.receive(Stream(malformed))
        body = wire[9:]
        with self.assertRaises(ValueError):
            hello.server_name(body.replace(b'github.com', b'github.co'))

    def test_exact_host_policy_and_public_only_resolution(self):
        hello.hosts(list(hello.UPSTREAM_HOSTS))
        for hosts in (['github.com'], ['manage.cybex.net'], list(reversed(hello.UPSTREAM_HOSTS))):
            with self.assertRaises(ValueError):
                hello.hosts(hosts)
        def answer(address):
            return (socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443))
        for address in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '192.168.1.1', '0.0.0.0', '224.0.0.1'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                hello.public_endpoint('github.com', hello.UPSTREAM_HOSTS,
                                      lambda *_args, **_kw: [answer('140.82.112.3'), answer(address)])
        with self.assertRaises(ValueError):
            hello.public_endpoint('manage.cybex.net', hello.UPSTREAM_HOSTS,
                                  lambda *_args, **_kw: [answer('140.82.112.3')])
        self.assertEqual(hello.public_endpoint('github.com', hello.UPSTREAM_HOSTS,
                         lambda *_args, **_kw: [answer('140.82.112.3')]), ('140.82.112.3', 443))

    def test_forwarder_routes_private_manage_without_public_dns_and_denies_other_hosts(self):
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(self.request.recv(65536))
        class Backend(socketserver.TCPServer):
            allow_reuse_address = True
        with Backend(('127.0.0.2', 8443), Echo) as backend:
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            routing = proxy.Proxy('127.0.0.3', '127.0.0.2', hostname='manage.cybex.net',
                                  upstream_hosts=hello.UPSTREAM_HOSTS, _test_port=0)
            try:
                with patch.object(proxy.egress, 'public_endpoint', side_effect=ValueError('not approved')) as external:
                    with socket.create_connection(routing.address, timeout=2) as client:
                        wire = client_hello('manage.cybex.net')
                        client.sendall(wire)
                        self.assertEqual(client.recv(65536), wire)
                    external.assert_not_called()
                    with socket.create_connection(routing.address, timeout=2) as client:
                        client.sendall(client_hello('evil.example'))
                        self.assertEqual(client.recv(65536), b'')
                    external.assert_called_once_with('evil.example', hello.UPSTREAM_HOSTS)
                with patch.object(proxy.egress, 'public_endpoint', return_value=('127.0.0.2', 8443)) as external:
                    with socket.create_connection(routing.address, timeout=2) as client:
                        wire = client_hello('cache.nixos.org')
                        client.sendall(wire)
                        self.assertEqual(client.recv(65536), wire)
                    external.assert_called_once_with('cache.nixos.org', hello.UPSTREAM_HOSTS)
                self.assertTrue(routing.verify('127.0.0.3', '127.0.0.2', hostname='manage.cybex.net',
                                               upstream_hosts=hello.UPSTREAM_HOSTS))
                with self.assertRaises(ValueError):
                    routing.verify('127.0.0.3', '127.0.0.2', hostname='other.example',
                                   upstream_hosts=hello.UPSTREAM_HOSTS)
            finally:
                routing.close()
                backend.shutdown()
                thread.join()


if __name__ == '__main__':
    unittest.main()
