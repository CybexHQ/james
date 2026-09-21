"""Temporary files and loopback child processes only; no host networking or APIs."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'nixos-appliance/qualification/isolated_manage_artifacts.py'
spec = importlib.util.spec_from_file_location('isolated_manage_artifacts_tests', SOURCE)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def free_ports(count):
    sockets, ports = [], []
    try:
        for _ in range(count):
            value = socket.socket()
            value.bind(('127.0.0.1', 0))
            sockets.append(value)
            ports.append(value.getsockname()[1])
        return ports
    finally:
        for value in sockets:
            value.close()


class FakeVerifier:
    MANIFEST = 'cybex-james-release.json'
    COMPATIBILITY = 'cybex-james-release-compatibility.json'

    def __init__(self, values):
        self.values = values
        self.verified = []
        self.advanced = []

    def verify_pair_snapshot(self, directory, trusted_key):
        self.verified.append((Path(directory), trusted_key))
        values = self.values[Path(directory)]
        return {'manifest': values['manifest'],
                'manifest_body': (Path(directory) / self.MANIFEST).read_bytes(),
                'compatibility': values['compatibility'],
                'compatibility_body': (Path(directory) / self.COMPATIBILITY).read_bytes()}

    def checked_json(self, path):
        value = self.values[Path(path).parent]['compatibility']
        return value, A.canonical(value)

    def advance(self, candidate, predecessor):
        self.advanced.append((candidate, predecessor))
        if candidate <= predecessor:
            raise ValueError('candidate did not advance')


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cybex-artifact-coordinator-')
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.owner = str(uuid.uuid4())
        self.scope = {'owner': self.owner, 'bridge': 'jnqtest0', 'subnet': '10.99.16.1/24',
                      'manage_origin': 'https://dev.example.test', 'peer_ipv4': '10.99.16.1',
                      'network_id': 'a' * 64, 'backend_subnet': '10.99.17.0/28',
                      'egress_hosts': []}
        ports = free_ports(3)
        self.endpoints = {name: ('127.0.0.1', port) for name, port in zip(A.LISTENERS, ports)}
        self.values, releases = {}, {}
        shared_workstation = b'shared signed workstation bundle'
        for role, version in (('predecessor', '1.2.2'), ('candidate', '1.2.3')):
            directory = self.root / role
            directory.mkdir(mode=0o700)
            bodies = {
                A.release_verifier.MANIFEST: ('signed manifest ' + role).encode(),
                f'cybex-james-appliance-template-{version}-x86_64-linux.iso': ('iso ' + role).encode(),
                f'cybex-james-appliance-closure-{version}-x86_64-linux.tar.zst': ('closure ' + role).encode(),
                'cybex-workstation-netboot-1.0.0-aaaaaaaaaaaa-x86_64-linux.tar.zst': shared_workstation,
            }
            for name, body in bodies.items():
                path = directory / name
                path.write_bytes(body)
                path.chmod(0o600)
            manifest_name = A.release_verifier.MANIFEST
            iso_name = f'cybex-james-appliance-template-{version}-x86_64-linux.iso'
            closure_name = f'cybex-james-appliance-closure-{version}-x86_64-linux.tar.zst'
            workstation_name = 'cybex-workstation-netboot-1.0.0-aaaaaaaaaaaa-x86_64-linux.tar.zst'
            manifest = {'version': version,
                        'installer_iso_template_v3': {
                            'url': 'https://releases.example/' + iso_name,
                            'template_sha256': sha(bodies[iso_name]), 'size_bytes': len(bodies[iso_name]),
                            'manage_origin': self.scope['manage_origin']},
                        'appliance_release_v1': {'system_closure': {
                            'url': 'https://releases.example/' + closure_name,
                            'sha256': sha(bodies[closure_name]), 'size_bytes': len(bodies[closure_name])}},
                        'workstation_netboot': {
                            'url': 'https://releases.example/' + workstation_name,
                            'sha256': sha(shared_workstation), 'size_bytes': len(shared_workstation)}}
            compatibility_sha = sha(('compatibility ' + role).encode())
            compatibility = {'james_release_version': version,
                             'compatibility_sha256': compatibility_sha,
                             'release_manifest': {'url': 'https://releases.example/' + manifest_name,
                                                  'sha256': sha(bodies[manifest_name])}}
            compatibility_path = directory / A.release_verifier.COMPATIBILITY
            compatibility_path.write_bytes(A.canonical(compatibility))
            compatibility_path.chmod(0o600)
            self.values[directory] = {'manifest': manifest, 'compatibility': compatibility}
            releases[role] = {'directory': directory, 'compatibility_sha256': compatibility_sha}
        self.releases = releases
        self.verifier = FakeVerifier(self.values)
        self.coordinator = None

    def create(self, *, endpoints=None, releases=None, coordinator=A.Coordinator):
        return coordinator(self.state, self.scope, releases or self.releases, 'trusted-key',
                           verifier=self.verifier, _test_uid=os.geteuid(),
                           _test_endpoints=endpoints or self.endpoints, _test_loopback=True,
                           _test_anchor=self.root)

    def tearDown(self):
        if self.coordinator is not None:
            try:
                self.coordinator.cleanup(self.scope, purge=True)
            except (OSError, ValueError):
                for child in self.coordinator.children.values():
                    if child.process.poll() is None:
                        child.process.terminate()
                        child.process.wait(timeout=3)
                    if child.pidfd is not None:
                        os.close(child.pidfd)
                        child.pidfd = None
        self.temporary.cleanup()

    def test_three_immutable_listeners_return_only_verified_transport_urls(self):
        self.coordinator = self.create()
        urls = self.coordinator.prepare(self.scope)
        self.assertEqual(self.verifier.advanced, [('1.2.3', '1.2.2')])
        self.assertEqual({path for path, _key in self.verifier.verified},
                         {self.root / 'predecessor', self.root / 'candidate'})
        predecessor = urls['releases']['predecessor']
        candidate = urls['releases']['candidate']
        self.assertEqual(predecessor['manifest_transport_url'],
                         f'http://127.0.0.1:{self.endpoints["predecessor-backend"][1]}/cybex-james-release.json')
        self.assertEqual(candidate['manifest_transport_url'],
                         f'http://127.0.0.1:{self.endpoints["candidate-backend"][1]}/cybex-james-release.json')
        self.assertIn(f':{self.endpoints["guest"][1]}/cybex-james-appliance-closure-1.2.2-',
                      predecessor['package_transport_url'])
        self.assertEqual(predecessor['bundle_transport_url'], candidate['bundle_transport_url'])
        guest = self.coordinator.receipt['listeners']['guest']['artifacts']
        shared = [value for value in guest if value['filename'].startswith('cybex-workstation-netboot-')]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0]['roles'], ['predecessor', 'candidate'])
        self.assertEqual(self.coordinator.verify(self.scope), urls)

    def test_mutated_source_and_wrong_compatibility_projection_fail_before_returning_urls(self):
        candidate = self.root / 'candidate'
        iso = next(candidate.glob('*.iso'))
        iso.write_bytes(b'mutated but still ordinary')
        self.coordinator = self.create()
        with self.assertRaisesRegex(ValueError, 'signed identity'):
            self.coordinator.prepare(self.scope)
        self.assertTrue(all(child.process.poll() is not None for child in self.coordinator.children.values()))
        self.assertFalse(self.coordinator.directory.exists())

        releases = {role: dict(value) for role, value in self.releases.items()}
        releases['candidate']['compatibility_sha256'] = '0' * 64
        self.coordinator = self.create(releases=releases)
        with self.assertRaisesRegex(ValueError, 'compatibility identity'):
            self.coordinator.prepare(self.scope)

    def test_each_signed_iso_origin_must_match_the_exact_fixture_scope(self):
        for role in A.ROLES:
            with self.subTest(role=role):
                descriptor = self.values[self.root / role]['manifest']['installer_iso_template_v3']
                expected = descriptor['manage_origin']
                descriptor['manage_origin'] = 'https://other.example.test'
                self.coordinator = self.create()
                with self.assertRaisesRegex(ValueError, 'origin differs'):
                    self.coordinator.prepare(self.scope)
                self.assertEqual(self.coordinator.children, {})
                self.assertFalse(self.coordinator.directory.exists())
                descriptor['manage_origin'] = expected

    def test_staged_manifest_comes_from_authenticated_snapshot_not_a_later_path_read(self):
        originals = {role: (self.root / role / A.release_verifier.MANIFEST).read_bytes()
                     for role in A.ROLES}
        verify = self.verifier.verify_pair_snapshot

        def replace_after_snapshot(directory, trusted_key):
            snapshot = verify(directory, trusted_key)
            Path(directory, A.release_verifier.MANIFEST).write_bytes(b'replaced after authentication')
            return snapshot

        self.verifier.verify_pair_snapshot = replace_after_snapshot
        self.coordinator = self.create()
        self.coordinator.prepare(self.scope)
        for role in A.ROLES:
            listener = self.coordinator.receipt['listeners'][role + '-backend']
            staged = next(value for value in listener['artifacts']
                          if value['filename'] == A.release_verifier.MANIFEST)
            self.assertEqual(Path(staged['path']).read_bytes(), originals[role])
            self.assertEqual((self.root / role / A.release_verifier.MANIFEST).read_bytes(),
                             b'replaced after authentication')

    def test_real_signature_verification_returns_exact_snapshots_and_rejects_replacement(self):
        directory = self.root / 'real-signed-release'
        directory.mkdir(mode=0o700)
        fixtures = ROOT / 'tools/tests/fixtures/recovery'
        manifest_path = directory / A.release_verifier.MANIFEST
        compatibility_path = directory / A.release_verifier.COMPATIBILITY
        originals = {
            manifest_path: (fixtures / 'recovery-manifest.json').read_bytes(),
            compatibility_path: (fixtures / 'recovery-compatibility.json').read_bytes(),
        }
        for path, body in originals.items():
            path.write_bytes(body)
            path.chmod(0o600)
        anchor = json.loads((ROOT / 'release/recovery-adoption.json').read_bytes())
        key, url = anchor['public_key'], anchor['recovery']['manifest_url']
        snapshot = A.release_verifier.verify_pair_snapshot(directory, key, url)
        self.assertEqual(snapshot['manifest_body'], originals[manifest_path])
        self.assertEqual(snapshot['compatibility_body'], originals[compatibility_path])

        real_verify = A.release_verifier.release._verify_release_compatibility_command
        for victim in (manifest_path, compatibility_path):
            with self.subTest(victim=victim.name):
                for path, body in originals.items():
                    path.write_bytes(body)
                    path.chmod(0o600)

                def verify_then_replace(arguments, victim=victim):
                    real_verify(arguments)
                    replacement = victim.with_name('.replacement-' + victim.name)
                    replacement.write_bytes(b'{}\n')
                    replacement.chmod(0o600)
                    os.replace(replacement, victim)

                with mock.patch.object(A.release_verifier.release,
                                       '_verify_release_compatibility_command',
                                       side_effect=verify_then_replace):
                    with self.assertRaisesRegex(ValueError, 'changed during authentication'):
                        A.release_verifier.verify_pair_snapshot(directory, key, url)

    def test_receipt_or_scope_mutation_fails_closed_but_owned_cleanup_still_works(self):
        self.coordinator = self.create()
        self.coordinator.prepare(self.scope)
        wrong_scope = dict(self.scope, network_id='b' * 64)
        with self.assertRaisesRegex(ValueError, 'scope changed'):
            self.coordinator.verify(wrong_scope)
        body = json.loads(self.coordinator.receipt_path.read_bytes())
        body['challenge'] = '0' * 64
        self.coordinator.receipt_path.write_bytes(A.canonical(body))
        self.coordinator.receipt_path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'receipt changed'):
            self.coordinator.verify(self.scope)
        pids = [child.process.pid for child in self.coordinator.children.values()]
        self.coordinator.cleanup(self.scope, purge=True)
        self.coordinator = None
        self.assertFalse((self.state / 'artifact-transport').exists())
        self.assertTrue(all(not (Path('/proc') / str(pid)).exists() for pid in pids))
        self.assertTrue((self.root / 'candidate' / A.release_verifier.MANIFEST).exists())

    def test_startup_failure_stops_every_direct_child_and_purges_partial_state(self):
        blocked = socket.socket()
        blocked.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        blocked.bind(self.endpoints['candidate-backend'])
        blocked.listen(1)
        try:
            self.coordinator = self.create()
            with self.assertRaisesRegex(ValueError, 'exited before publishing'):
                self.coordinator.prepare(self.scope)
            self.assertIn('predecessor-backend', self.coordinator.children)
            self.assertTrue(all(child.process.poll() is not None for child in self.coordinator.children.values()))
            self.assertFalse(self.coordinator.directory.exists())
        finally:
            blocked.close()

    def test_unpublished_and_malformed_receipts_cannot_strand_owned_children(self):
        class Unpublished(A.Coordinator):
            def _server_command(self, _config, _receipt):
                return [sys.executable, '-c', 'import time; time.sleep(60)']

        self.coordinator = self.create(coordinator=Unpublished)
        with mock.patch.object(A, 'START_TIMEOUT', 0.1):
            with self.assertRaisesRegex(TimeoutError, 'did not publish'):
                self.coordinator.prepare(self.scope)
        self.assertTrue(all(child.process.poll() is not None
                            for child in self.coordinator.children.values()))
        self.assertFalse(self.coordinator.directory.exists())

        class Malformed(A.Coordinator):
            def _server_command(self, config, receipt):
                command = super()._server_command(config, receipt)
                publish = ' m.publish_receipt(Path(sys.argv[3]),s.receipt,anchor=Path(sys.argv[4]))'
                malformed = '''
 s.receipt["process"]["start_ticks"]="malformed"
 unknown=Path(sys.argv[3]).with_name("unknown-same-uid-file")
 unknown.write_bytes(b"retain unknown bytes")
 unknown.chmod(0o600)
 m.publish_receipt(Path(sys.argv[3]),s.receipt,anchor=Path(sys.argv[4]))'''
                command[3] = command[3].replace(publish, malformed)
                return command

        self.coordinator = self.create(coordinator=Malformed)
        with self.assertRaisesRegex(ValueError, 'unknown or missing'):
            self.coordinator.prepare(self.scope)
        child = self.coordinator.children['predecessor-backend']
        self.assertIsNotNone(child.process.returncode)
        self.assertIsNone(child.pidfd)
        self.assertIsNone(child.receipt)
        unknown = self.coordinator.directory / 'predecessor-backend/unknown-same-uid-file'
        self.assertEqual(unknown.read_bytes(), b'retain unknown bytes')

    def test_delayed_receipt_uses_the_server_verification_budget(self):
        self.assertGreaterEqual(A.START_TIMEOUT, A.server.REQUEST_TIMEOUT)

        class Delayed(A.Coordinator):
            def _server_command(self, config, receipt):
                command = super()._server_command(config, receipt)
                publish = ' m.publish_receipt(Path(sys.argv[3]),s.receipt,anchor=Path(sys.argv[4]))'
                command[3] = command[3].replace(
                    publish, ' __import__("time").sleep(0.15)\n' + publish)
                return command

        self.coordinator = self.create(coordinator=Delayed)
        with mock.patch.object(A, 'START_TIMEOUT', 0.5):
            urls = self.coordinator.prepare(self.scope)
        self.assertEqual(urls, self.coordinator.verify(self.scope))

    def test_same_guest_filename_requires_equal_signed_identity(self):
        candidate = self.root / 'candidate'
        workstation = next(candidate.glob('cybex-workstation-netboot-*'))
        workstation.write_bytes(b'different candidate workstation')
        workstation.chmod(0o600)
        descriptor = self.values[candidate]['manifest']['workstation_netboot']
        descriptor['sha256'] = sha(workstation.read_bytes())
        descriptor['size_bytes'] = workstation.stat().st_size
        self.coordinator = self.create()
        with self.assertRaisesRegex(ValueError, 'different signed identities'):
            self.coordinator.prepare(self.scope)
        self.assertTrue(all(child.process.poll() is not None for child in self.coordinator.children.values()))

    def test_unknown_staged_path_is_never_deleted(self):
        self.coordinator = self.create()
        self.coordinator.prepare(self.scope)
        unknown = self.coordinator.directory / 'operator-notes'
        unknown.write_text('retain')
        unknown.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'unknown or missing'):
            self.coordinator.cleanup(self.scope, purge=True)
        self.assertTrue(unknown.exists())
        self.assertTrue(all(child.process.poll() is not None for child in self.coordinator.children.values()))
        unknown.unlink()

    def test_replaced_receipt_object_is_not_adopted_or_purged(self):
        self.coordinator = self.create()
        self.coordinator.prepare(self.scope)
        receipt = Path(self.coordinator.receipt['listeners']['guest']['receipt'])
        replacement = receipt.with_name('.replacement-receipt')
        replacement.write_bytes(receipt.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, receipt)
        with self.assertRaisesRegex(ValueError, 'listener receipt changed'):
            self.coordinator.verify(self.scope)
        with self.assertRaisesRegex(ValueError, 'unknown or missing'):
            self.coordinator.cleanup(self.scope, purge=True)
        self.assertTrue(receipt.exists())
        self.assertTrue(all(child.process.poll() is not None for child in self.coordinator.children.values()))
        self.coordinator = None

    def test_spawned_child_exits_when_its_direct_parent_dies(self):
        pid_file = self.root / 'parent-death.pid'
        code = '''
import importlib.util, os, pathlib, sys, time
spec=importlib.util.spec_from_file_location("coordinator",sys.argv[1])
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
child,pidfd=m.spawn_direct([sys.executable,"-c","import time; time.sleep(60)"])
pathlib.Path(sys.argv[2]).write_text(str(child.pid))
os._exit(0)
'''
        parent = subprocess.Popen([sys.executable, '-B', '-c', code, str(SOURCE), str(pid_file)])
        parent.wait(timeout=5)
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        child_pid = int(pid_file.read_text())
        process = Path('/proc') / str(child_pid)
        while process.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        if process.exists():
            os.kill(child_pid, signal.SIGKILL)
        self.assertFalse(process.exists())


if __name__ == '__main__':
    unittest.main()
