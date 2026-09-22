"""Temporary files and loopback sockets only; no fixture/network integration."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'nixos-appliance/qualification/verified_artifact_server.py'
spec = importlib.util.spec_from_file_location('verified_artifact_server', SOURCE)
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


class ArtifactServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cybex-artifact-server-test-')
        self.root = Path(self.temporary.name)
        self.body = bytes(range(256)) * 17
        self.source = self.root / 'bundle.tar.zst'
        self.source.write_bytes(self.body)
        self.source.chmod(0o600)
        self.config = self.root / 'config.json'
        self.value = {'schema': V.SCHEMA, 'scope_owner': str(uuid.uuid4()),
                      'bind': '127.0.0.1', 'port': 0,
                      'artifacts': [{'filename': self.source.name, 'path': str(self.source),
                                     'size_bytes': len(self.body),
                                     'sha256': hashlib.sha256(self.body).hexdigest()}]}
        self.write_config()
        self.server = None
        self.thread = None

    def write_config(self):
        self.config.write_bytes(V.canonical(self.value))
        self.config.chmod(0o600)

    def create(self):
        return V.ArtifactServer(self.config, _test_uid=os.geteuid(),
                                _test_anchor=self.root, _test_loopback=True)

    def start(self):
        self.server = self.create()
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': 0.01})
        self.thread.start()
        return self.server

    def request(self, path='/bundle.tar.zst', method='GET', headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=2)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def tearDown(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=2)
            self.assertFalse(self.thread.is_alive())
        self.temporary.cleanup()

    def test_sequential_phases_rebind_after_response_but_cannot_share_live_listener(self):
        self.start()
        port = self.server.server_port
        # Keep the client open until the HTTP/1.0 server closes first, leaving
        # the fixed fixture endpoint in TIME_WAIT after teardown.
        connection = socket.create_connection(('127.0.0.1', port), timeout=2)
        try:
            connection.sendall(b'GET /bundle.tar.zst HTTP/1.0\r\n\r\n')
            response = b''
            while chunk := connection.recv(65536):
                response += chunk
            self.assertTrue(response.endswith(self.body))
        finally:
            connection.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = None
        self.value['port'] = port
        self.write_config()
        self.start()
        self.assertEqual(self.request()[2], self.body)
        with self.assertRaises(OSError):
            other = self.create()
            other.server_close()

    def test_multiple_exact_artifacts_are_independent_but_readiness_checks_all(self):
        second = self.root / 'second.iso'
        second.write_bytes(b'second public artifact')
        second.chmod(0o600)
        self.value['artifacts'].append({'filename': second.name, 'path': str(second),
            'size_bytes': second.stat().st_size, 'sha256': hashlib.sha256(second.read_bytes()).hexdigest()})
        self.write_config()
        self.start()
        self.assertEqual(self.request('/second.iso')[0::2], (200, second.read_bytes()))
        second.write_bytes(b'changed')
        self.assertEqual(self.request()[0::2], (200, self.body))
        self.assertEqual(self.request('/second.iso')[0::2], (503, b''))
        self.assertEqual(self.request(self.server.challenge_path)[0], 503)

    def test_incomplete_request_workers_are_bounded(self):
        self.start()
        clients = []
        try:
            for _ in range(V.MAX_WORKERS):
                client = socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2)
                client.sendall(b'GET /bundle.tar.zst HTTP/1.1\r\n')
                clients.append(client)
            deadline = time.monotonic() + 2
            while len(self.server.sockets) != V.MAX_WORKERS and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(len(self.server.sockets), V.MAX_WORKERS)
            overflow = socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2)
            try:
                self.assertEqual(overflow.recv(1), b'')
            finally:
                overflow.close()
            self.assertEqual(len(self.server.sockets), V.MAX_WORKERS)
        finally:
            for client in clients: client.close()

    def test_exact_bytes_head_and_open_ended_ranges(self):
        self.start()
        status, headers, body = self.request()
        self.assertEqual((status, body), (200, self.body))
        self.assertEqual(headers['Content-Length'], str(len(self.body)))
        status, headers, body = self.request(method='HEAD')
        self.assertEqual((status, body), (200, b''))
        self.assertEqual(headers['Content-Length'], str(len(self.body)))
        for offset in (0, 13, len(self.body) - 1):
            for method in ('GET', 'HEAD'):
                status, headers, body = self.request(method=method, headers={'Range': f'bytes={offset}-'})
                self.assertEqual(status, 206)
                self.assertEqual(headers['Content-Range'], f'bytes {offset}-{len(self.body)-1}/{len(self.body)}')
                self.assertEqual(headers['Content-Length'], str(len(self.body) - offset))
                self.assertEqual(body, self.body[offset:] if method == 'GET' else b'')

    def test_concurrent_ranges_use_independent_fd_offsets(self):
        self.start()
        def fetch(offset):
            return self.request(headers={'Range': f'bytes={offset}-'})[2]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(fetch, range(1, 17)))
        self.assertEqual(results, [self.body[offset:] for offset in range(1, 17)])

    def test_only_exact_routes_and_methods_are_served(self):
        self.start()
        for path in ('/', '/bundle.tar.zst?x=1', '/bundle.tar.zst?', '/bundle.tar.zst#x',
                     '/%62undle.tar.zst', '//bundle.tar.zst', '/x/../bundle.tar.zst',
                     '/directory/bundle.tar.zst', 'http://127.0.0.1/bundle.tar.zst'):
            with self.subTest(path=path):
                status, _, body = self.request(path)
                self.assertEqual(status, 404)
                self.assertEqual(body, b'')
        for method in ('POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'):
            status, headers, body = self.request(method=method)
            self.assertEqual(status, 405)
            self.assertEqual(headers['Allow'], 'GET, HEAD')
            self.assertEqual(body, b'')

    def test_invalid_ranges_return_exact_416(self):
        self.start()
        for value in ('bytes=-10', 'bytes=1-2', 'bytes=0-,1-', 'bytes=00-',
                      f'bytes={len(self.body)}-', 'bytes=999999999999999999999999-', 'items=0-'):
            status, headers, body = self.request(headers={'Range': value})
            self.assertEqual(status, 416)
            self.assertEqual(headers['Content-Range'], f'bytes */{len(self.body)}')
            self.assertEqual((headers['Content-Length'], body), ('0', b''))
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=2)
        try:
            connection.putrequest('GET', '/bundle.tar.zst')
            connection.putheader('Range', 'bytes=0-')
            connection.putheader('Range', 'bytes=1-')
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 416)
            response.read()
        finally:
            connection.close()

    def test_same_bytes_replaced_inode_is_refused_before_serving(self):
        self.start()
        original_fd = self.server.artifacts[self.source.name].fd
        replacement = self.root / 'replacement'
        replacement.write_bytes(self.body)
        replacement.chmod(0o600)
        os.replace(replacement, self.source)
        self.assertEqual(os.pread(original_fd, len(self.body), 0), self.body)
        self.assertEqual(self.request()[0::2], (503, b''))
        self.assertEqual(self.request(self.server.challenge_path)[0], 503)

    def test_content_change_with_restored_mtime_is_refused(self):
        self.start()
        info = self.source.stat()
        self.source.write_bytes(b'x' * len(self.body))
        os.utime(self.source, ns=(info.st_atime_ns, info.st_mtime_ns))
        self.assertEqual(self.request()[0::2], (503, b''))

    def test_changed_config_cannot_pass_readiness(self):
        self.start()
        self.config.write_bytes(V.canonical(self.value) + b' ')
        self.assertEqual(self.request(self.server.challenge_path)[0], 503)
        with self.assertRaises(ValueError):
            V.verify_server(self.server.receipt, _test_loopback=True)

    def test_bad_hash_size_symlink_hardlink_and_permissions_refused_before_listen(self):
        original = deepcopy(self.value)
        for field, value in [('sha256', '0' * 64), ('size_bytes', len(self.body) + 1)]:
            self.value = deepcopy(original)
            self.value['artifacts'][0][field] = value
            self.write_config()
            with self.assertRaises(ValueError): self.create()
        self.value = original
        self.write_config()
        alternate = self.root / 'alternate'
        self.source.rename(alternate)
        self.source.symlink_to(alternate)
        with self.assertRaises(OSError): self.create()
        self.source.unlink()
        os.link(alternate, self.source)
        with self.assertRaises(ValueError): self.create()
        alternate.unlink()
        self.source.chmod(0o660)
        with self.assertRaises(ValueError): self.create()
        self.source.chmod(0o600)
        self.config.chmod(0o666)
        with self.assertRaises(ValueError): self.create()

    def test_unsafe_ancestor_and_noncanonical_source_paths_refused(self):
        nested = self.root / 'nested'
        nested.mkdir(mode=0o777)
        nested.chmod(0o777)
        source = nested / 'bundle.tar.zst'
        source.write_bytes(self.body)
        self.value['artifacts'][0]['path'] = str(source)
        self.write_config()
        with self.assertRaises(ValueError): self.create()
        for path in ('relative', str(self.root) + '/./bundle.tar.zst', str(self.root) + '/../bundle.tar.zst'):
            self.value['artifacts'][0]['path'] = path
            self.write_config()
            with self.assertRaises(ValueError): self.create()

    def test_cli_policy_has_no_loopback_or_ephemeral_port_exception(self):
        for address, port in [('127.0.0.1', 8000), ('0.0.0.0', 8000), ('8.8.8.8', 8000),
                              ('169.254.1.1', 8000), ('172.32.0.1', 8000), ('10.0.0.1', 0)]:
            with self.assertRaises(ValueError): V.endpoint(address, port)
        self.assertEqual(V.endpoint('192.168.1.1', 80), ('192.168.1.1', 80))
        if os.geteuid() != 0:
            with self.assertRaises((ValueError, OSError)):
                V.ArtifactServer(self.config)

    def test_readiness_and_no_replace_private_receipt_bind_actual_resources(self):
        self.start()
        path = self.root / 'receipt.json'
        V.publish_receipt(path, self.server.receipt, anchor=self.root)
        receipt = json.loads(path.read_bytes())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_uid, os.geteuid())
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(receipt['scope_owner'], self.value['scope_owner'])
        self.assertEqual(receipt['artifacts'][0]['metadata'], V.metadata(self.source.stat()))
        V.verify_server(receipt, _test_loopback=True)
        with self.assertRaises(FileExistsError):
            V.publish_receipt(path, {'wrong': True}, anchor=self.root)
        self.assertEqual(json.loads(path.read_bytes()), receipt)
        tampered = deepcopy(receipt)
        tampered['process']['start_ticks'] += 1
        with self.assertRaises(ValueError): V.verify_server(tampered, _test_loopback=True)
        tampered = deepcopy(receipt)
        tampered['challenge'] = '0' * 64
        with self.assertRaises(ValueError): V.verify_server(tampered, _test_loopback=True)

    def test_owned_child_cleanup_checks_identity_even_when_readiness_fails(self):
        receipt_path = self.root / 'child-receipt.json'
        code = '''
import importlib.util, os, signal, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('server', sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
server = m.ArtifactServer(sys.argv[2], _test_uid=os.geteuid(), _test_anchor=Path(sys.argv[2]).parent, _test_loopback=True)
def stop(*args): raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
try:
 m.publish_receipt(Path(sys.argv[3]), server.receipt, anchor=Path(sys.argv[2]).parent)
 server.serve_forever(poll_interval=0.01)
finally: server.server_close()
'''
        child = subprocess.Popen([sys.executable, '-c', code, str(SOURCE), str(self.config), str(receipt_path)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 3
            while not receipt_path.exists() and time.monotonic() < deadline:
                self.assertIsNone(child.poll())
                time.sleep(0.01)
            receipt = json.loads(receipt_path.read_bytes())
            V.verify_server(receipt, _test_loopback=True)
            altered = deepcopy(receipt)
            altered['process']['start_ticks'] += 1
            with self.assertRaises(ValueError):
                V.stop_owned_child(child, altered)
            self.assertIsNone(child.poll())
            self.source.write_bytes(b'broken')
            with self.assertRaises(ValueError):
                V.verify_server(receipt, _test_loopback=True)
            # Readiness failure must not strand the still-owned exact child.
            V.stop_owned_child(child, receipt)
            self.assertEqual(child.returncode, 0)
        finally:
            if child.poll() is None:
                child.terminate(); child.wait(timeout=3)
            child.stderr.close()


if __name__ == '__main__':
    unittest.main()
