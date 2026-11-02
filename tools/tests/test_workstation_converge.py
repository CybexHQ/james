"""Deterministic Blueprint convergence interleavings; no VM or API access."""
import copy
from pathlib import Path
import sys
import unittest

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'
sys.path.insert(0, str(HELPERS))
import workstation_lifecycle as workstation

DESCRIPTOR = {'runtime_version': '1.0.67', 'manage_source_revision': 'b' * 40,
              'components': {name: {'sha256': 'a' * 64, 'size_bytes': 1}
                             for name in ('bzImage', 'initrd', 'nix-store.squashfs')}}
BLUEPRINT = {'slug': 'dock_workstation', 'current_revision_id': 'dock-revision'}
INSTALLED = {'device_id': 'device', 'public_key_fingerprint': 'key'}
OLD_SYSTEM = '/nix/store/old-standard-system'
NEW_SYSTEM = '/nix/store/new-dock-system'
OLD_BOOT = '668c1504-558f-4b4c-b4bb-8132600df97b'
NEW_BOOT = '0b4a1c58-3f7e-4f0d-9d55-1f7f0f6a4b2e'


def observed(*, current, booted, profile=None, boot_id=OLD_BOOT, **fields):
    device = INSTALLED | {
        'device_kind': 'workstation', 'health_status': 'online', 'configuration_status': 'compliant',
        'desired_blueprint_revision_id': 'dock-revision', 'applied_blueprint_revision_id': 'dock-revision',
        'desired_config_hash': 'a' * 64, 'reported_config_hash': 'a' * 64, 'applied_config_hash': 'a' * 64,
        'configuration_verified_at': '2026-11-02T17:00:00Z', 'active_operation': None,
        'facts_json': {
            'boot_id': boot_id,
            'workstation_runtime': {'runtime_version': '1.0.67', 'manage_source_revision': 'b' * 40,
                                    'descriptor_sha256': workstation.descriptor_digest(DESCRIPTOR)},
            'blueprint_generation': {'current_system': current, 'booted_system': booted,
                                     'system_profile': profile or current}}}
    return device | fields


# The agent switched to the applied generation without a reboot and Manage
# correctly reports compliance: current/profile are new, the boot is still old.
LIVE_SWITCH = observed(current=NEW_SYSTEM, booted=OLD_SYSTEM)
# The managed reboot boots the generation that was switched to live.
REBOOTED = observed(current=NEW_SYSTEM, booted=NEW_SYSTEM, boot_id=NEW_BOOT)


class ConvergeTests(unittest.TestCase):
    def scenario(self, before_reboot, after_reboot=None, *, polls=8, after_apply=True, verified_after=None):
        """Poll a fake device that only changes when the harness reboots it."""
        reboots = []

        def reboot(value):
            reboots.append(copy.deepcopy(value))

        def read():
            source = after_reboot if reboots and after_reboot is not None else before_reboot
            return copy.deepcopy(source)

        def wait_for(label, read, accept, timeout):
            self.assertEqual(timeout, 3600)
            for _ in range(polls):
                value = read()
                if accept(value):
                    return value
            raise TimeoutError(label)

        try:
            result = workstation.converge_workstation(
                wait_for, read, reboot, DESCRIPTOR, BLUEPRINT, INSTALLED, verified_after,
                after_apply=after_apply)
        except TimeoutError:
            result = None
        return reboots, result

    def test_live_switch_after_apply_gets_one_managed_reboot_then_requires_booted_current(self):
        # Reproduces the v0.2.78 deadlock: compliant, booted != current, never pending_reboot.
        reboots, result = self.scenario(LIVE_SWITCH, REBOOTED)
        self.assertIsNotNone(result, 'converge deadlocked on a live-switched compliant workstation')
        self.assertEqual(len(reboots), 1)
        self.assertEqual(reboots[0]['facts_json']['boot_id'], OLD_BOOT)
        generation = result['facts_json']['blueprint_generation']
        self.assertEqual(generation['booted_system'], NEW_SYSTEM)
        self.assertEqual(generation['current_system'], NEW_SYSTEM)
        self.assertEqual(result['facts_json']['boot_id'], NEW_BOOT)

    def test_stale_read_before_new_generation_check_in_still_converges_without_reboot(self):
        # The v0.2.73 ordering: the read arrived before the new current_system check-in.
        stale = observed(current=OLD_SYSTEM, booted=OLD_SYSTEM)
        reboots, result = self.scenario(stale)
        self.assertEqual(reboots, [])
        self.assertEqual(result['facts_json']['blueprint_generation']['booted_system'], OLD_SYSTEM)

    def test_live_switch_reboots_only_once_when_boot_does_not_reach_current(self):
        still_old = observed(current=NEW_SYSTEM, booted=OLD_SYSTEM, boot_id=NEW_BOOT)
        reboots, result = self.scenario(LIVE_SWITCH, still_old, polls=20)
        self.assertEqual(len(reboots), 1)
        self.assertIsNone(result)

    def test_pending_reboot_and_live_switch_share_the_single_reboot(self):
        pending = observed(current=NEW_SYSTEM, booted=OLD_SYSTEM, configuration_status='pending_reboot')
        reboots, result = self.scenario(pending, LIVE_SWITCH | {'facts_json': copy.deepcopy(
            LIVE_SWITCH['facts_json']) | {'boot_id': NEW_BOOT}}, polls=20)
        self.assertEqual(len(reboots), 1)
        self.assertIsNone(result)

    def test_unproven_live_switch_is_not_rebooted(self):
        cases = {
            'applying': {'configuration_status': 'applying'},
            'old revision': {'applied_blueprint_revision_id': 'standard-revision'},
            'hash mismatch': {'reported_config_hash': 'c' * 64},
            'identity changed': {'public_key_fingerprint': 'other'},
            'offline': {'health_status': 'offline'},
        }
        for name, fields in cases.items():
            with self.subTest(name):
                reboots, result = self.scenario(LIVE_SWITCH | fields, REBOOTED)
                self.assertEqual(reboots, [])
                self.assertIsNone(result)
        for name, generation in {
            'profile not switched': observed(current=NEW_SYSTEM, booted=OLD_SYSTEM, profile=OLD_SYSTEM),
            'booted unknown': observed(current=NEW_SYSTEM, booted=None),
        }.items():
            with self.subTest(name):
                reboots, result = self.scenario(generation, REBOOTED)
                self.assertEqual(reboots, [])
                self.assertIsNone(result)

    def test_live_switch_reboot_is_limited_to_post_apply_convergence(self):
        # After an install or an explicit managed reboot, booted != current is a failure, not a live switch.
        reboots, result = self.scenario(LIVE_SWITCH, REBOOTED, after_apply=False)
        self.assertEqual(reboots, [])
        self.assertIsNone(result)

    def test_final_checks_still_reject_booted_mismatch_after_live_switch_reboot(self):
        for name, fields in {
            'profile diverged': observed(current=NEW_SYSTEM, booted=NEW_SYSTEM, profile=OLD_SYSTEM,
                                         boot_id=NEW_BOOT),
            'identity changed': REBOOTED | {'device_id': 'other'},
        }.items():
            with self.subTest(name):
                reboots, result = self.scenario(LIVE_SWITCH, fields)
                self.assertEqual(len(reboots), 1)
                self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
