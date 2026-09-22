"""Fail-closed ancestry, fixture and release acceptance contracts."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / 'nixos-appliance/qualification'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


P = module('nixos_predecessor', HELPERS / 'release_predecessor.py')
A = module('nixos_acceptance', HELPERS / 'release_acceptance.py')
S = module('nixos_scope', HELPERS / 'development-scope.py')


class NixosQualificationTests(unittest.TestCase):
    @staticmethod
    def scope():
        return {'schema': S.SCHEMA, 'run': 'cleanup-test',
                'manage_origin': 'https://dev.example.com', 'bridge': 'jnqcleanup01',
                'owner': '01234567-89ab-4def-8123-456789abcdef',
                'subnet': '10.246.217.1/24'}

    @staticmethod
    def network(scope, owner=None):
        return {'name': scope['bridge'], 'type': 'bridge', 'managed': True, 'used_by': [],
                'config': {'user.cybex.nixos-qualification': owner or scope['owner'],
                           'ipv4.address': scope['subnet'], 'ipv4.nat': 'true',
                           'ipv6.address': 'none'}}

    def test_cleanup_removes_receipted_forwarding_when_bridge_is_absent(self):
        scope = self.scope()
        cleanup = Mock()
        with patch.object(S, 'read_scope', return_value=scope), \
                patch.object(S, 'incus', return_value='[]') as incus, \
                patch.dict(S.FORWARD, {'cleanup': cleanup}):
            S.cleanup(Path('/private'), scope['manage_origin'], scope['bridge'])
        cleanup.assert_called_once_with(Path('/private'), scope)
        incus.assert_called_once_with('network', 'list', '--format=json')

    def test_cleanup_removes_forwarding_but_retains_foreign_replacement_bridge(self):
        scope = self.scope()
        replacement = self.network(scope, '11111111-1111-4111-8111-111111111111')
        cleanup = Mock()
        with patch.object(S, 'read_scope', return_value=scope), \
                patch.object(S, 'incus', return_value=json.dumps([replacement])) as incus, \
                patch.dict(S.FORWARD, {'cleanup': cleanup}):
            S.cleanup(Path('/private'), scope['manage_origin'], scope['bridge'])
        cleanup.assert_called_once_with(Path('/private'), scope)
        incus.assert_called_once_with('network', 'list', '--format=json')

    def test_owned_bridge_live_client_precondition_precedes_forwarding_cleanup(self):
        scope = self.scope()
        network = self.network(scope)
        network['used_by'] = ['/1.0/instances/live-client']
        cleanup = Mock()
        with patch.object(S, 'read_scope', return_value=scope), \
                patch.object(S, 'incus', return_value=json.dumps([network])), \
                patch.dict(S.FORWARD, {'cleanup': cleanup}), \
                self.assertRaisesRegex(ValueError, 'attached instances'):
            S.cleanup(Path('/private'), scope['manage_origin'], scope['bridge'])
        cleanup.assert_not_called()

    def test_forwarding_preparation_failure_uses_bridge_independent_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / 'scope'
            args = SimpleNamespace(manage_origin='https://dev.example.com', run='failure-test',
                                   subnet='10.246.217.1/24', state_dir=state)
            incus = Mock(side_effect=['[]', '', '[]'])
            prepare = Mock(side_effect=ValueError('induced forwarding failure'))
            cleanup = Mock()
            with patch.object(S, 'incus', incus), \
                    patch.object(S, 'verify', return_value=({}, {})), \
                    patch.object(S.subprocess, 'check_output', return_value='[]'), \
                    patch.dict(S.FORWARD, {'prepare': prepare, 'cleanup': cleanup}), \
                    self.assertRaisesRegex(ValueError, 'induced forwarding failure'):
                S.prepare(args)
            actual_scope = S.read_scope(state)
            prepare.assert_called_once_with(state, actual_scope)
            cleanup.assert_called_once_with(state, actual_scope)
            self.assertEqual(incus.call_args_list[-1].args,
                             ('network', 'list', '--format=json'))

    def test_bridge_verification_uses_incus_json_api_and_checks_ownership(self):
        scope = {'schema': S.SCHEMA, 'manage_origin': 'https://dev.example.com', 'bridge': 'jnqtest',
                 'owner': 'owned-run', 'subnet': '10.246.217.1/24'}
        network = {'name': scope['bridge'], 'type': 'bridge', 'managed': True,
                   'config': {'user.cybex.nixos-qualification': scope['owner'],
                              'ipv4.address': scope['subnet'], 'ipv4.nat': 'true',
                              'ipv6.address': 'none'}}
        with patch.object(S, 'read_scope', return_value=scope), \
                patch.object(S, 'incus', return_value=json.dumps(network)) as incus, \
                patch.dict(S.FORWARD, {'verify': Mock()}) as forward:
            self.assertEqual(S.verify(Path('/private'), scope['manage_origin'], scope['bridge']),
                             (scope, network))
            incus.assert_called_once_with('query', '/1.0/networks/jnqtest')
            forward['verify'].assert_called_once_with(Path('/private'), scope)
            network['config']['user.cybex.nixos-qualification'] = 'another-run'
            incus.return_value = json.dumps(network)
            with self.assertRaisesRegex(ValueError, 'ownership receipt'):
                S.verify(Path('/private'), scope['manage_origin'], scope['bridge'])

    def test_hardware_is_unique_between_scopes_and_preserved_within_one(self):
        first = {'owner': '01234567-89ab-cdef-0123-456789abcdef'}
        second = {'owner': '11234567-89ab-cdef-0123-456789abcdef'}
        installed = S.hardware_identity(first, 'appliance')
        self.assertEqual(installed, S.hardware_identity(first, 'appliance'))
        for other in (S.hardware_identity(second, 'appliance'), S.hardware_identity(first, 'workstation')):
            for field in ('mac', 'serial', 'uuid'):
                self.assertNotEqual(installed[field], other[field])
        self.assertTrue(installed['mac'].startswith('02:'))
        self.assertLessEqual(len(installed['serial']), 20)  # QEMU SCSI device ID limit

    def test_callback_inputs_bind_predecessor_bytes_separately_from_harness(self):
        fixture = module('nixos_fixture_inputs', HELPERS / 'isolated_fixture.py')
        with patch.dict(sys.modules, {'release_predecessor': P, 'isolated_fixture': fixture}):
            runner = module('nixos_runner_inputs', HELPERS / 'run-production-qualification.py')
        manifest = {'version': '0.2.5', 'appliance_release_v1': {
            'source_revision': 'a' * 40, 'manage_source_revision': 'b' * 40,
            'nixpkgs_revision': 'c' * 40, 'system_toplevel': '/nix/store/' + 'd' * 32 + '-system',
            'system_closure': {'sha256': 'e' * 64}}}
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            selected = state / P.MANIFEST
            body = P.canonical(manifest)
            selected.write_bytes(body)
            with patch.object(runner.subprocess, 'check_output', side_effect=['f' * 40, '1' * 40]):
                runner.write_release_inputs(state, selected, Path('/reviewed/development'), 'https://dev.example.com')
            inputs = json.loads((state / 'release-inputs.json').read_bytes())
            self.assertEqual(inputs['james_revision'], 'f' * 40)
            self.assertEqual(inputs['release_source_revision'], 'a' * 40)
            self.assertEqual(inputs['manage_revision'], '1' * 40)
            self.assertEqual(inputs['manage_source_revision'], 'b' * 40)
            self.assertEqual(inputs['candidate_manifest_sha256'], hashlib.sha256(body).hexdigest())
            self.assertEqual(inputs['james_repository'], str(ROOT))
            self.assertEqual((state / 'release-inputs.json').stat().st_mode & 0o777, 0o600)

    def test_partial_tap_setup_releases_only_the_nonpersistent_owned_fd(self):
        scope = {'owner': 'owner'}
        with patch.object(S, 'verify', return_value=(scope, {})), \
                patch.object(S.subprocess, 'check_output', return_value='[]'), \
                patch.object(S.os, 'open', return_value=73), patch.object(S.os, 'close') as close, \
                patch.object(S.fcntl, 'ioctl') as ioctl, \
                patch.object(S.subprocess, 'run', side_effect=OSError('alias failed')) as run:
            with self.assertRaises(OSError):
                S.tap(Path('/unused'), 'https://dev.example.com', 'jnqtest', 'appliance', True)
            self.assertEqual(run.call_count, 1)
            close.assert_called_once_with(73)
            self.assertEqual(ioctl.call_count, 1)  # never made persistent
            self.assertEqual(S.struct.unpack('16sH', ioctl.call_args.args[2])[1], 0x9002)
        with patch.object(S, 'verify', return_value=(scope, {})), \
                patch.object(S.subprocess, 'check_output', return_value='[]'), \
                patch.object(S.os, 'open', return_value=73), patch.object(S.os, 'close') as close, \
                patch.object(S.fcntl, 'ioctl') as ioctl, patch.object(S.subprocess, 'run') as run:
            self.assertEqual(S.tap(Path('/unused'), 'https://dev.example.com', 'jnqtest', 'appliance', True), 'jnqtesta')
            self.assertEqual(run.call_count, 2)
            ioctl.assert_called_with(73, 0x400454cb, 1)
            close.assert_called_once_with(73)

    def test_interrupted_runner_waits_for_owned_child_cleanup(self):
        fixture = module('nixos_fixture_cleanup', HELPERS / 'isolated_fixture.py')
        with patch.dict(sys.modules, {'release_predecessor': P, 'isolated_fixture': fixture}):
            runner = module('nixos_runner_cleanup', HELPERS / 'run-production-qualification.py')
        child = Mock()
        child.wait.side_effect = [KeyboardInterrupt(), 0]
        child.poll.return_value = None
        with patch.object(runner.subprocess, 'Popen', return_value=child), self.assertRaises(KeyboardInterrupt):
            runner.execute('owned-child')
        child.terminate.assert_called_once()
        child.wait.assert_called_with(timeout=45)
        child.kill.assert_not_called()

    def test_qemu_spawn_failure_releases_the_owned_tap(self):
        fixture = module('nixos_fixture_spawn', HELPERS / 'isolated_fixture.py')
        with tempfile.TemporaryDirectory() as temporary:
            instance = fixture.Fixture.__new__(fixture.Fixture)
            instance.directory = Path(temporary)
            instance.state = Path('/private-run')
            instance.scope = {'manage_origin': 'https://dev.example.com', 'bridge': 'jnqtest'}
            instance.hardware = {'uuid': 'unused', 'serial': 'unused', 'mac': 'unused'}
            instance.process, instance.monitor, instance.tap = None, None, None
            tap = Mock(return_value='jnqtesta')
            with patch.dict(fixture.SCOPE, {'tap': tap}), \
                    patch.object(fixture.subprocess, 'Popen', side_effect=OSError('spawn failed')) as spawn:
                with self.assertRaises(OSError):
                    instance.__enter__()
            args = spawn.call_args.args[0]
            devices = [args[i + 1].split(',')[0] for i, arg in enumerate(args) if arg == '-device']
            self.assertEqual(devices, ['virtio-scsi-pci', 'scsi-hd', 'virtio-net-pci', 'i6300esb'])
            self.assertEqual(tap.call_count, 2)
            self.assertFalse(tap.call_args.args[-1])

    def test_disk_fingerprint_detects_writes_far_beyond_partition_header(self):
        disk = module('nixos_disk_fingerprint', HELPERS / 'disk-fingerprint.py')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'disk.raw'
            with path.open('wb') as stream:
                stream.truncate(128 * 1024**2)
            before = disk.fingerprint(path)
            with path.open('r+b') as stream:
                stream.seek(64 * 1024**2)
                stream.write(b'changed')
            self.assertNotEqual(before, disk.fingerprint(path))

    def test_production_and_noncanonical_origins_rejected_before_mutation(self):
        for value in ('https://console.example.com', 'http://dev.example.com', 'https://dev.example.com/',
                      'https://user@dev.example.com', 'https://DEV.example.com', 'https://dev.example.com?token=secret'):
            with self.subTest(origin=value), self.assertRaises(ValueError):
                S.development_origin(value)
        self.assertEqual(S.development_origin('https://dev.example.com'), 'https://dev.example.com')

    def test_scope_refuses_symlink_or_public_ownership_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scope = root / 'scope'
            scope.mkdir(mode=0o700)
            (scope / 'scope.json').write_text('{}')
            (scope / 'scope.json').chmod(0o644)
            with self.assertRaises(ValueError):
                S.read_scope(scope)
            link = root / 'link'
            link.symlink_to(scope)
            with self.assertRaises(ValueError):
                S.read_scope(link)

    def test_semver_requires_real_forward_transition(self):
        for previous in ('0.2.6', '0.2.7', '0.3.0'):
            with self.assertRaises(ValueError):
                P.advance('0.2.6', previous)
        P.advance('0.2.6', '0.2.5')

    def test_historical_authority_is_exact_and_not_general_key_trust(self):
        authorization = ROOT / 'release/recovery-adoption.json'
        value = json.loads(authorization.read_bytes())
        previous = ROOT / 'tools/tests/fixtures/recovery/github-compatibility.json'
        self.assertEqual(P.release._authorized_previous_key(previous, value['public_key'], '0.2.5', authorization),
                         value['published']['public_key'])
        for version, auth in [('0.2.6', authorization), ('0.2.5', None)]:
            with self.assertRaises(P.release.ReleaseError):
                P.release._authorized_previous_key(previous, value['public_key'], version, auth)
        with tempfile.TemporaryDirectory() as temporary:
            altered = Path(temporary) / 'compatibility.json'
            altered.write_bytes(previous.read_bytes() + b' ')
            with self.assertRaises(P.release.ReleaseError):
                P.release._authorized_previous_key(altered, value['public_key'], '0.2.5', authorization)

    def test_signed_v1_ancestry_does_not_become_nixos_update_fixture(self):
        authorization = ROOT / 'release/recovery-adoption.json'
        auth = json.loads(authorization.read_bytes())
        old = auth['published']
        base = f"https://github.com/CybexHQ/james/releases/download/{old['tag_name']}/"
        files = {P.MANIFEST: ROOT / 'tools/tests/fixtures/recovery/github-manifest.json',
                 P.COMPATIBILITY: ROOT / 'tools/tests/fixtures/recovery/github-compatibility.json'}
        published = dict(id=old['github_release_id'], tag_name=old['tag_name'], target_commitish=old['target_commitish'],
            draft=False, prerelease=False, created_at='2026-01-01T00:00:00Z',
            assets=[{'name': n, 'browser_download_url': base + n, 'size': p.stat().st_size} for n, p in files.items()])
        def github(_repo, path):
            return [published] if path.startswith('releases') else {'sha': old['target_commitish']}
        def fetch(_url, path, *_args):
            shutil.copyfile(files[path.name], path)
            return path
        with tempfile.TemporaryDirectory() as temporary, patch.object(P, 'github', github), patch.object(P, 'fetch', fetch):
            directory = Path(temporary)
            result = P.resolve('CybexHQ/james', '0.2.5', auth['public_key'], directory, authorization)
            self.assertEqual(result['update_contract'], 'reinstall-only')
            self.assertNotIn('system_toplevel', result)
            # The old signature may be inspected as history but never substituted
            # for an authenticated current-authority NixOS upgrade predecessor.
            with self.assertRaises((ValueError, P.release.ReleaseError)):
                P.qualify(directory, '0.2.5', auth['public_key'])

    def test_missing_historical_publication_is_not_first_release(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(P, 'github', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'first-release'):
                P.resolve('CybexHQ/james', '0.2.5', '', Path(temporary), ROOT / 'release/recovery-adoption.json')

    def transition(self):
        fixture = json.loads((ROOT / 'protocol/fixtures/james-appliance-v3.json').read_bytes())
        candidate = {'version': '0.2.6', 'appliance_release_v1': deepcopy(fixture['appliance_release']),
                     'installer_iso_template_v3': {'manage_origin': 'https://dev.example.com'}}
        previous = deepcopy(candidate)
        previous['version'] = '0.2.5'
        previous['appliance_release_v1']['system_toplevel'] = '/nix/store/' + '1' * 32 + '-previous'
        previous['appliance_release_v1']['system_closure']['sha256'] = '1' * 64
        source = candidate['appliance_release_v1']['source_revision']
        evidence = dict(schema='cybex.james.nixos-appliance-update-qualification.v1', ok=True,
            candidate_manifest_sha256='a' * 64, predecessor_manifest_sha256='b' * 64, harness_revision=source,
            candidate_release='0.2.6', predecessor_release='0.2.5', secure_boot=False,
            identity_preserved=True, candidate_reboot_observed=True, appliance_projection_healthy=True,
            server_device_id='dev_' + 'c' * 32, attempt_id='00000000-0000-4000-8000-000000000001',
            source_system_generation='1', candidate_system_generation='2', resulting_system_generation='2',
            resulting_system_toplevel=candidate['appliance_release_v1']['system_toplevel'],
            final_status='succeeded', final_stage='committed', host_reset_used=False,
            fresh_health_successes=3, authenticated_manage_contact=True)
        for prefix, manifest in [('candidate', candidate), ('predecessor', previous)]:
            release = manifest['appliance_release_v1']
            evidence.update({prefix + '_' + name: release[name] for name in
                             ('system_toplevel', 'source_revision', 'manage_source_revision')})
            evidence[prefix + '_system_closure_sha256'] = release['system_closure']['sha256']
        return candidate, previous, evidence, source

    def test_update_evidence_binds_generation_closure_source_and_observed_reboot(self):
        candidate, previous, evidence, source = self.transition()
        with patch.dict(sys.modules, {'release_predecessor': P}):
            A.validate_transition(candidate, 'a' * 64, previous, 'b' * 64, evidence, source, 'update')
            for key, value in [('candidate_system_closure_sha256', '0' * 64), ('candidate_reboot_observed', False),
                ('host_reset_used', True), ('resulting_system_generation', '1'), ('fresh_health_successes', 2),
                ('authenticated_manage_contact', False), ('candidate_source_revision', '0' * 40)]:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    A.validate_transition(candidate, 'a' * 64, previous, 'b' * 64, {**evidence, key: value}, source, 'update')

    def test_rollback_requires_automatic_source_boot_and_reason(self):
        candidate, previous, evidence, source = self.transition()
        evidence.update(schema='cybex.james.nixos-appliance-rollback-qualification.v1',
            automatic_rollback=True, fallback_reboot_observed=True, rollback_reason='health_deadline', fault='candidate_network',
            resulting_system_generation='1', resulting_system_toplevel=previous['appliance_release_v1']['system_toplevel'],
            final_status='rolled_back', final_stage='boot_fallback')
        with patch.dict(sys.modules, {'release_predecessor': P}):
            A.validate_transition(candidate, 'a' * 64, previous, 'b' * 64, evidence, source, 'rollback')
            for key, value in [('automatic_rollback', False), ('rollback_reason', ''), ('host_reset_used', True),
                               ('resulting_system_generation', '2'), ('fallback_reboot_observed', False)]:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    A.validate_transition(candidate, 'a' * 64, previous, 'b' * 64, {**evidence, key: value}, source, 'rollback')


if __name__ == '__main__':
    unittest.main()
