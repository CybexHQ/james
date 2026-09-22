"""Production qualification must stay on a private exact-origin NixOS fixture."""
import importlib.util
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
import socket
import socketserver
import threading
from unittest.mock import Mock, patch

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'


def load(name):
    spec = importlib.util.spec_from_file_location('production_test_' + name, HELPERS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'path', [str(HELPERS), *sys.path]):
        spec.loader.exec_module(module)
    return module


class ProductionTests(unittest.TestCase):
    def test_tls_forwarder_preserves_bytes_and_closes_owned_connections(self):
        forwarding = load('isolated_manage_tls_proxy')
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(self.request.recv(1024))
        with socketserver.TCPServer(('127.0.0.2', 8443), Echo) as backend:
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            proxy = forwarding.Proxy('127.0.0.3', '127.0.0.2', _test_port=0)
            try:
                with socket.create_connection(proxy.address, timeout=2) as client:
                    payload = b'\x16\x03\x03opaque TLS bytes'
                    client.sendall(payload)
                    self.assertEqual(client.recv(1024), payload)
                self.assertTrue(proxy.verify('127.0.0.3', '127.0.0.2'))
                with self.assertRaises(ValueError):
                    proxy.verify('127.0.0.3', '127.0.0.4')
            finally:
                proxy.close()
                backend.shutdown()
                thread.join()
            with self.assertRaises(ValueError):
                proxy.verify('127.0.0.3', '127.0.0.2')
            with socket.socket() as probe:
                probe.bind(proxy.address)

    def test_staging_copies_bytes_and_rejects_symlinks(self):
        fixture = load('production_fixture')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            (source / 'artifact').write_bytes(b'signed artifact')
            target = fixture.stage_artifacts(source, root / 'staged')
            self.assertEqual((target / 'artifact').read_bytes(), b'signed artifact')
            self.assertEqual((target / 'artifact').stat().st_mode & 0o777, 0o600)
            (source / 'link').symlink_to(source / 'artifact')
            with self.assertRaises(ValueError):
                fixture.stage_artifacts(source, root / 'rejected')

    def test_live_production_is_rejected_by_development_scope(self):
        scope = runpy.run_path(str(HELPERS / 'development-scope.py'))
        with self.assertRaises(ValueError):
            scope['development_origin']('https://manage.cybex.net')
        with patch.object(sys, 'path', [str(HELPERS), *sys.path]):
            self.assertEqual(scope['scope_origin']('https://manage.cybex.net', scope['ISOLATED_SCHEMA']),
                             'https://manage.cybex.net')
        with self.assertRaises(ValueError):
            scope['scope_origin']('https://manage.cybex.net', scope['SCHEMA'])

    def test_production_evidence_must_bind_exact_fixture_and_source(self):
        acceptance = load('release_acceptance')
        manifest = {'installer_iso_template_v3': {'manage_origin': 'https://manage.cybex.net'},
                    'appliance_release_v1': {'manage_source_revision': 'a' * 40}}
        scope = {'schema': 'cybex.james.isolated-qualification.v1', 'manage_origin': 'https://manage.cybex.net',
                 'manage_revision': 'a' * 40, 'owner': '01234567-89ab-cdef-0123-456789abcdef',
                 'live_production_access': False}
        acceptance.validate_scope(manifest, {'qualification_scope': scope})
        for invalid in ({}, scope | {'manage_origin': 'https://dev.cybex.net'},
                        scope | {'manage_revision': 'b' * 40}, scope | {'live_production_access': True}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                acceptance.validate_scope(manifest, {'qualification_scope': invalid})

    def test_rpc_allows_only_bounded_operations(self):
        rpc = load('isolated_manage_rpc')
        owner = Mock()
        owner.api.return_value = {'status': 'ok'}
        server = object.__new__(rpc.Server)
        server.owner = owner
        self.assertEqual(server.dispatch({'operation': 'api', 'path': '/v1/health', 'body': None}), {'status': 'ok'})
        for invalid in ({'operation': 'shell', 'command': 'true'},
                        {'operation': 'api', 'path': '/v1/health', 'body': None, 'token': 'foreign'},
                        {'operation': 'personalize', 'path': 'https://manage.cybex.net', 'secret': 'test'}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                server.dispatch(invalid)
        self.assertEqual(owner.api.call_count, 1)
        owner.client.assert_not_called()

    @unittest.skipUnless(os.geteuid() == 0, 'root-private RPC transport uses real peer credentials')
    def test_rpc_roundtrip_uses_retained_owner_and_cleans_socket(self):
        rpc = load('isolated_manage_rpc')
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            state.chmod(0o700)
            owner = Mock(state=state)
            owner.api.return_value = {'status': 'ok'}
            with rpc.Server(owner):
                self.assertEqual(rpc.request(state, 'api', path='/v1/health', body=None), {'status': 'ok'})
                with self.assertRaises(ValueError):
                    rpc.request(state, 'unknown')
            self.assertFalse((state / 'manage.sock').exists())
            owner.api.assert_called_once_with('/v1/health', None)


if __name__ == '__main__':
    unittest.main()
