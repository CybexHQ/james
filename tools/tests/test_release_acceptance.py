"""Reject missing delivery, substituted runtimes and unrelated artifact receipts."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
import zipfile

HELPERS = Path(__file__).resolve().parents[2] / 'ubuntu-appliance/qualification'
sys.path.insert(0, str(HELPERS))
import release_acceptance as acceptance
import workstation_lifecycle

SPEC = importlib.util.spec_from_file_location('promote_production_release', HELPERS / 'promote-production-release.py')
promotion = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(promotion)


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.source = 'a' * 40
        self.digest = 'b' * 64
        self.manifest = {'version': '0.2.3',
            'appliance_release_v1': {'source_revision': self.source, 'ubuntu_snapshot_id': '20260918T000000Z'},
            'installer_iso_template_v2': {'template_sha256': 'c' * 64},
            'workstation_netboot': {'runtime_version': '1.0.67', 'sha256': 'd' * 64,
                'manage_source_revision': 'e' * 40, 'components': {
                    name: {'sha256': str(i) * 64, 'size_bytes': 10}
                    for i, name in enumerate(('bzImage', 'initrd', 'nix-store.squashfs'), 1)}}}
        self.cold = {k: True for k in acceptance.LIFECYCLE_FLAGS + acceptance.DELIVERY_FLAGS}
        self.cold.update(schema='cybex.james.ubuntu-appliance-qualification.v1',
            final_state='ready', qualification_kind='candidate', qualified_manifest_sha256=self.digest,
            harness_revision=self.source, release_version='0.2.3', ubuntu_snapshot_id='20260918T000000Z',
            template_sha256='c' * 64, root_generation='0', device_id='dev_' + '1' * 32,
            candidate_runtime_required=True, workstation_runtime_prepublication_deferred=False,
            builtin_blueprints_prepublication_deferred=False,
            qualified_blueprints={'schema': 'cybex.james.qualification-blueprints.v1', 'blueprints': [
                {'id': profile, 'current_revision_id': profile + '-revision', 'slug': profile,
                 'desktop_profile': profile} for profile in ('taskbar', 'dock', 'tiling')]})
        self.workstation = dict(schema='cybex.james.published-workstation-qualification.v1', ok=True,
            pxe_boot_observed=True, fresh_install_completed=True, source_builds_allowed=False,
            release_version='0.2.3', runtime_version='1.0.67', bundle_sha256='d' * 64,
            manage_source_revision='e' * 40,
            descriptor_sha256=workstation_lifecycle.descriptor_digest(self.manifest['workstation_netboot']),
            james_device_id=self.cold['device_id'], workstation_device_id='dev_' + '2' * 32,
            blueprints=[{'blueprint_id': profile, 'revision_id': profile + '-revision', 'slug': profile,
                'configuration_status': 'compliant', 'managed_reboot_completed': True,
                'identity_preserved': True, 'boot_id_before': 'before', 'boot_id_after': 'after',
                'system': '/nix/store/exact-system'} for profile in ('taskbar', 'dock', 'tiling')])

    def validate(self, value, phase='cold'):
        acceptance.validate_lifecycle(self.manifest, self.digest, value, self.source, phase)

    def test_prepublication_absence_is_explicit_and_cannot_pass_cold_acceptance(self):
        pre = self.cold | {k: False for k in acceptance.DELIVERY_FLAGS}
        pre.update(candidate_runtime_required=False, workstation_runtime_prepublication_deferred=True,
                   builtin_blueprints_prepublication_deferred=True)
        self.validate(pre, 'prepublication')
        with self.assertRaisesRegex(ValueError, 'Delivery'):
            self.validate(pre)
        for field in acceptance.DELIVERY_FLAGS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(pre | {field: True}, 'prepublication')

    def test_cold_requires_each_appliance_and_source_free_delivery_proof(self):
        self.validate(self.cold)
        for field in acceptance.LIFECYCLE_FLAGS + acceptance.DELIVERY_FLAGS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(self.cold | {field: False})
        for field, value in [('harness_revision', 'f' * 40), ('qualified_manifest_sha256', 'f' * 64),
                             ('root_generation', '1'), ('candidate_runtime_required', False),
                             ('release_version', '0.2.1-dev.29')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(self.cold | {field: value})

    def test_old_runtime_and_partial_workstation_acceptance_cannot_promote(self):
        acceptance.validate_workstation(self.manifest, self.cold, self.workstation)
        for field, value in [('runtime_version', '1.0.61'), ('bundle_sha256', 'f' * 64),
                             ('descriptor_sha256', 'f' * 64), ('james_device_id', 'dev_' + '3' * 32),
                             ('source_builds_allowed', True), ('pxe_boot_observed', False)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                acceptance.validate_workstation(self.manifest, self.cold, self.workstation | {field: value})
        for field, value in [('identity_preserved', False), ('managed_reboot_completed', False),
                             ('boot_id_after', 'before'), ('configuration_status', 'pending_reboot'),
                             ('revision_id', 'another-revision')]:
            wrong = copy.deepcopy(self.workstation)
            wrong['blueprints'][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                acceptance.validate_workstation(self.manifest, self.cold, wrong)
        duplicate = self.workstation | {'blueprints': [self.workstation['blueprints'][0]] * 3}
        with self.assertRaises(ValueError):
            acceptance.validate_workstation(self.manifest, self.cold, duplicate)

    def test_archive_authentication_rejects_other_runs_digests_and_extra_files(self):
        def archive(extra=False):
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as package:
                for name in promotion.FILES:
                    package.writestr(name, json.dumps({'ok': True}))
                if extra:
                    package.writestr('../private-state', 'unrelated')
            return output.getvalue()
        body = archive()
        digest = 'sha256:' + hashlib.sha256(body).hexdigest()
        metadata = dict(expired=False, workflow_run={'id': 123, 'head_sha': self.source},
                        name='cybex-james-published-cold-123', digest=digest)
        self.assertEqual(set(promotion.artifact_evidence(body, metadata, digest, 123, self.source)), promotion.FILES)
        for change in [{'expired': True}, {'digest': 'sha256:' + '0' * 64},
                       {'workflow_run': {'id': 124, 'head_sha': self.source}}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                promotion.artifact_evidence(body, metadata | change, digest, 123, self.source)
        with self.assertRaises(ValueError):
            promotion.artifact_evidence(body + b'changed', metadata, digest, 123, self.source)
        extra = archive(True)
        extra_digest = 'sha256:' + hashlib.sha256(extra).hexdigest()
        with self.assertRaisesRegex(ValueError, 'inventory'):
            promotion.artifact_evidence(extra, metadata | {'digest': extra_digest}, extra_digest, 123, self.source)

    def test_conflicting_lifecycle_modes_stop_before_any_api_or_vm_operation(self):
        for extra in (['--require-candidate-runtime'], ['--published-predecessor-inputs', '/no-file']):
            result = subprocess.run(['bash', str(HELPERS / 'run-lifecycle.sh'),
                '--prepublication-candidate', *extra], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('prepublication deferral applies only', result.stderr)


if __name__ == '__main__':
    unittest.main()
