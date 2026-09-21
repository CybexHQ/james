"""Safety boundaries and durable recovery, without modifying the host runtime."""
import copy
import datetime
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

RUNTIME = Path(__file__).resolve().parents[1] / 'runtime'
sys.path.insert(0, str(RUNTIME))
import appliance_state as state
import generation_update as update


def script(name):
    loader = SourceFileLoader(name.removesuffix('.py').replace('-', '_'), str(RUNTIME / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


window = script('cybex-james-appliance-update-window')
network = script('cybex-james-netplan-activate')
firewall = script('cybex-james-firewall')
first_boot = script('cybex-james-first-boot')
source_copy = script('source-copy.py')


class ReadBoundary(unittest.TestCase):
    def test_rejects_links_writable_files_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt'
            path.write_text('{}')
            path.chmod(0o600)
            self.assertEqual(state.read(path, owner=os.getuid()), b'{}')
            with self.assertRaises(ValueError):
                state.read(path, owner=os.getuid(), maximum=1)
            path.chmod(0o666)
            with self.assertRaises(ValueError):
                state.read(path, owner=os.getuid())
            path.chmod(0o600)
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaises(OSError):
                state.read(link, owner=os.getuid())
            link.unlink()
            os.link(path, link)
            with self.assertRaises(ValueError):
                state.read(path, owner=os.getuid())

    def test_unknown_generations_are_omitted(self):
        with patch.object(state, 'save') as save:
            state.emit_status({'attempt_id': 'attempt'}, 'waiting_window', 'maintenance_window')
            value = save.call_args.args[1]
            self.assertNotIn('candidate_system_generation', value)
            self.assertNotIn('resulting_system_generation', value)
            with self.assertRaises(ValueError):
                state.emit_status({'candidate_generation': '0'}, 'failed', 'failed')


class MaintenancePolicy(unittest.TestCase):
    request = {'attempt_id': 'a', 'release': {'release_id': '1.2.3', 'system_closure': {'sha256': 'digest'}}}

    def policy(self, weekdays, start, duration, timezone='UTC'):
        return {'schedule': {'weekdays': weekdays, 'start': start, 'duration_minutes': duration, 'timezone': timezone}}

    def check(self, policy, timestamp):
        return window.allowed(policy, self.request, datetime.datetime.fromisoformat(timestamp))

    def test_saturday_window_crosses_sunday_boundary(self):
        policy = self.policy([6], '23:30', 120)
        self.assertTrue(self.check(policy, '2026-09-20T00:45:00+00:00'))
        self.assertFalse(self.check(policy, '2026-09-20T01:30:00+00:00'))
        self.assertFalse(self.check(policy, '2026-09-19T23:29:00+00:00'))

    def test_timezone_and_repeated_dst_hour(self):
        policy = self.policy([0], '02:15', 30, 'Europe/Amsterdam')
        self.assertTrue(self.check(policy, '2026-10-25T00:20:00+00:00'))
        self.assertTrue(self.check(policy, '2026-10-25T01:20:00+00:00'))
        self.assertFalse(self.check(policy, '2026-10-25T02:20:00+00:00'))

    def test_run_now_binds_attempt_release_and_closure(self):
        policy = self.policy([], '00:00', 60)
        policy['run_now'] = {'attempt_id': 'a', 'release_id': '1.2.3', 'system_closure_sha256': 'digest'}
        self.assertTrue(self.check(policy, '2026-09-20T12:00:00+00:00'))
        for key in policy['run_now']:
            changed = copy.deepcopy(policy)
            changed['run_now'][key] = 'different'
            self.assertFalse(self.check(changed, '2026-09-20T12:00:00+00:00'))

    def test_closed_window_reuses_only_verified_identity_and_open_window_reverifies(self):
        attempt = '11111111-1111-4111-8111-111111111111'
        body = state.canonical({'attempt_id': attempt})
        verified = {'schema': 'cybex.james.verified-appliance-update.v3', 'attempt_id': attempt,
                    'request_sha256': hashlib.sha256(body).hexdigest(),
                    'source_system_generation': '1', 'source_system_toplevel': '/source'}
        with patch.object(update, 'read', return_value=body), patch.object(update, 'load', return_value=verified), \
                patch.object(update, 'current', return_value={'system_generation': '1', 'system_toplevel': '/source'}), \
                patch.object(update.subprocess, 'run', return_value=SimpleNamespace(returncode=75)) as policy, \
                patch.object(update, 'emit_status') as status:
            self.assertTrue(update.still_waiting_for_window())
            status.assert_called_once_with(verified, 'waiting_window', 'maintenance_window')
            policy.return_value.returncode = 0
            self.assertFalse(update.still_waiting_for_window())
            policy.return_value.returncode = 75
            verified['request_sha256'] = 'different'
            self.assertFalse(update.still_waiting_for_window())


class NetworkPolicy(unittest.TestCase):
    def config(self):
        return {'network': {'version': 2, 'renderer': 'networkd', 'ethernets': {'cybex-james': {
            'set-name': 'enp1s0', 'match': {'macaddress': '02:00:00:00:00:42'}, 'dhcp4': False, 'dhcp6': False,
            'addresses': ['192.0.2.42/24'], 'routes': [{'to': 'default', 'via': '192.0.2.1'}],
            'nameservers': {'addresses': ['192.0.2.53']}}}}}

    def test_static_and_dhcp_emit_one_exact_networkd_match(self):
        value = self.config()
        name, output = network.render(value)
        self.assertEqual(name, 'enp1s0')
        self.assertIn(b'Address=192.0.2.42/24\nGateway=192.0.2.1\nDNS=192.0.2.53\n', output)
        interface = value['network']['ethernets']['cybex-james']
        interface['dhcp4'] = True
        name, output = network.render(value)
        self.assertIn(b'DHCP=ipv4\n', output)
        self.assertNotIn(b'\nAddress=', output)

    def test_rejects_multicast_mac_and_config_injection(self):
        for key, value in [('set-name', 'eth0\n[Network]'), ('set-name', 'lo'), ('dhcp4', 'true')]:
            config = self.config()
            config['network']['ethernets']['cybex-james'][key] = value
            with self.assertRaises(ValueError):
                network.render(config)
        config = self.config()
        config['network']['ethernets']['cybex-james']['match']['macaddress'] = '01:00:00:00:00:01'
        with self.assertRaises(ValueError):
            network.render(config)

    def test_atomic_firewall_preserves_other_ports_and_denies_other_ssh(self):
        rules = firewall.render('192.0.2.0/24\n2001:db8::/32\n', True)
        self.assertTrue(rules.startswith('delete table inet cybex_james\n'))
        self.assertIn('policy accept;', rules)
        self.assertIn('ip saddr { 192.0.2.0/24 } tcp dport 22 accept', rules)
        self.assertIn('ip6 saddr { 2001:db8::/32 } tcp dport 22 accept', rules)
        self.assertTrue(rules.endswith('tcp dport 22 drop\n}\n}\n'))
        with self.assertRaises(ValueError):
            firewall.render('192.0.2.0/24; accept', False)


class PermissionLayout(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.uid, self.gid = os.getuid(), os.getgid()

    def strict_umask(self):
        class Umask:
            def __enter__(_self):
                _self.previous = os.umask(0o077)

            def __exit__(_self, *_args):
                os.umask(_self.previous)

        return Umask()

    def test_first_boot_private_parent_and_public_leaves_ignore_service_umask(self):
        cache = self.root / 'cache'
        with self.strict_umask():
            first_boot.prepare_cache_directories(
                cache, self.uid, self.gid, self.uid, self.gid)
        self.assertEqual(cache.stat().st_mode & 0o777, 0o755)
        agent = cache / 'agent'
        self.assertEqual((agent.stat().st_uid, agent.stat().st_gid, agent.stat().st_mode & 0o777),
                         (self.uid, self.gid, 0o700))
        for name in ('home', 'cache', 'config', 'state', 'tmp'):
            child = agent / name
            self.assertEqual((child.stat().st_uid, child.stat().st_gid, child.stat().st_mode & 0o777),
                             (self.uid, self.gid, 0o700))
        self.assertEqual((cache / 'www').stat().st_mode & 0o777, 0o755)
        self.assertEqual((cache / 'tftp').stat().st_mode & 0o777, 0o755)

    def test_public_runtime_and_source_directories_repair_only_owned_ordinary_paths(self):
        runtime = self.root / 'run'
        source = self.root / 'source'
        source.mkdir()
        with self.strict_umask():
            runtime.mkdir()
            network.prepare_runtime_directory(runtime, self.uid, self.gid)
            destination = self.root / 'public-source'
            source_copy.copy_source(source, destination, owner=self.uid)
        for path in (runtime, runtime / 'systemd', runtime / 'systemd/network', destination):
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        unsafe = self.root / 'unsafe-run'
        unsafe.mkdir()
        (unsafe / 'systemd').symlink_to(runtime / 'systemd', target_is_directory=True)
        with self.assertRaises(ValueError):
            network.prepare_runtime_directory(unsafe, self.uid, self.gid)
        linked = self.root / 'linked-source'
        linked.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(ValueError):
            source_copy.copy_source(source, linked, owner=self.uid)

class Recovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.paths = {}
        for name in ('PENDING', 'PREPARE', 'COMMIT', 'ROLLBACK', 'INSTALLED', 'KNOWN'):
            path = self.directory / name
            self.paths[name] = path
            self.enterContext(patch.object(update, name, path))
        self.enterContext(patch.object(update, 'load', lambda path, **kw: json.loads(path.read_text())))
        self.enterContext(patch.object(update, 'save', lambda path, value: path.write_bytes(state.canonical(value))))
        self.enterContext(patch.object(update, 'remove', lambda path: path.unlink(missing_ok=True)))
        self.receipt = {'schema': 'cybex.james.pending-system-generation.v3',
            'attempt_id': '11111111-1111-4111-8111-111111111111', 'system_toplevel': '/candidate',
            'source_toplevel': '/source', 'candidate_generation': '2', 'source_generation': '1',
            'candidate_loader_entry': 'nixos-generation-2.conf', 'source_loader_entry': 'nixos-generation-1.conf',
            'source_installed': {'old': 'receipt'}, 'source_known_good': {'generations': [{'system_generation': '1'}]}}
        self.booted = {'system_toplevel': '/source', 'system_generation': '1'}
        self.enterContext(patch.object(update, 'current', lambda: self.booted))
        self.actions = {}
        for name in ('restore_source', 'prune_candidate', 'cleanup', 'emit_status', 'set_default'):
            self.actions[name] = self.enterContext(patch.object(update, name))
        self.enterContext(patch.object(update, 'terminal_matches', return_value=False))
        self.enterContext(patch.object(update, 'ROOTS', self.directory / 'roots'))

    def test_source_fallback_restores_receipt_and_known_history(self):
        self.paths['PENDING'].write_bytes(state.canonical(self.receipt))
        update.recover_boot()
        self.assertEqual(json.loads(self.paths['INSTALLED'].read_text()), self.receipt['source_installed'])
        self.assertEqual(json.loads(self.paths['KNOWN'].read_text()), self.receipt['source_known_good'])
        self.assertFalse(self.paths['PENDING'].exists())
        self.assertEqual(self.actions['emit_status'].call_args.args[1:], ('rolled_back', 'boot_fallback', 'candidate_boot_failed', '1'))

    def test_unsealed_profile_creation_is_discovered_and_removed(self):
        receipt = dict(self.receipt)
        receipt.pop('candidate_generation')
        receipt.pop('candidate_loader_entry')
        self.paths['PREPARE'].write_bytes(state.canonical(receipt))
        self.paths['KNOWN'].write_text('{}')
        with patch.object(update, 'generation_for', return_value='2'):
            update.recover_boot()
        recovered = self.actions['prune_candidate'].call_args.args[0]
        self.assertEqual(recovered['candidate_generation'], '2')
        self.assertFalse(self.paths['PREPARE'].exists())

    def test_unsealed_candidate_and_unknown_boot_fail_closed(self):
        self.paths['PREPARE'].write_bytes(state.canonical(self.receipt))
        self.booted = {'system_toplevel': '/candidate', 'system_generation': '2'}
        with self.assertRaisesRegex(ValueError, 'unsealed candidate'):
            update.recover_boot()
        self.actions['prune_candidate'].assert_not_called()
        self.paths['PREPARE'].unlink()
        self.paths['PENDING'].write_bytes(state.canonical(self.receipt))
        self.booted = {'system_toplevel': '/unknown', 'system_generation': '8'}
        with self.assertRaisesRegex(ValueError, 'neither sealed candidate'):
            update.recover_boot()

    def test_durable_success_survives_late_cleanup_failure(self):
        self.paths['PENDING'].write_bytes(state.canonical(self.receipt))
        with patch.object(update, 'terminal_matches', return_value=True):
            update.recover_boot()
        self.actions['set_default'].assert_called_once_with('nixos-generation-2.conf')
        self.actions['restore_source'].assert_not_called()
        self.actions['emit_status'].assert_not_called()

    def test_cleanup_keeps_pending_authority_until_auxiliary_intents_are_gone(self):
        removed = []
        with patch.object(update, 'remove', side_effect=lambda path: removed.append(path)):
            update.clear_transaction(self.receipt)
        self.assertEqual(removed[-1], self.paths['PENDING'])
        self.assertEqual(set(removed[:-1]), {self.paths[key] for key in ('PREPARE', 'COMMIT', 'ROLLBACK')})


class BootAnchors(unittest.TestCase):
    def test_missing_corrupt_or_wrong_system_boot_payload_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            boot, system = root / 'boot', root / 'system'
            (boot / 'loader/entries').mkdir(parents=True)
            (boot / 'EFI/nixos').mkdir(parents=True)
            system.mkdir()
            for name in ('kernel', 'initrd'):
                (system / name).write_bytes(name.encode() * 100)
                (boot / 'EFI/nixos' / name).write_bytes((system / name).read_bytes())
            entry = boot / 'loader/entries/nixos-generation-2.conf'
            valid = f'linux /EFI/nixos/kernel\ninitrd /EFI/nixos/initrd\noptions init={system}/init quiet\n'
            entry.write_text(valid)
            with patch.object(update, 'read', lambda path, **kw: path.read_bytes()):
                update.verify_boot_entry(entry.name, str(system), boot)
                (boot / 'EFI/nixos/kernel').write_bytes(b'corrupted')
                with self.assertRaisesRegex(ValueError, 'kernel differs'):
                    update.verify_boot_entry(entry.name, str(system), boot)
                (boot / 'EFI/nixos/kernel').write_bytes((system / 'kernel').read_bytes())
                (boot / 'EFI/nixos/initrd').unlink()
                with self.assertRaisesRegex(ValueError, 'missing or linked'):
                    update.verify_boot_entry(entry.name, str(system), boot)
                entry.write_text(valid.replace(str(system), '/different'))
                with self.assertRaisesRegex(ValueError, 'exact signed system'):
                    update.verify_boot_entry(entry.name, str(system), boot)

    def test_actual_kernel_mismatch_cannot_commit(self):
        expected = {'kernel': '6.18.38', 'nix': '2.34.7', 'systemd-boot': '260.2', 'cybex-james': '0.2.5'}
        with patch.object(update, 'observed_system_versions', return_value=expected):
            update.verify_observed_versions(expected)
        with patch.object(update, 'observed_system_versions', return_value={**expected, 'kernel': '6.18.37'}):
            with self.assertRaisesRegex(ValueError, 'kernel version differs'):
                update.verify_observed_versions(expected)


if __name__ == '__main__':
    unittest.main()
