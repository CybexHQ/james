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
from unittest import mock
import zipfile

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'
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
            'appliance_release_v1': {'schema': 'cybex.james.appliance-release.v3',
                'source_revision': self.source, 'manage_source_revision': 'e' * 40,
                'system_closure': {'sha256': 'f' * 64}, 'system_toplevel': '/nix/store/exact-system',
                'nixpkgs_revision': '9' * 40},
            'installer_iso_template_v3': {'template_sha256': 'c' * 64, 'manage_origin': 'https://manage.cybex.net'},
            'workstation_netboot': {'runtime_version': '1.0.67', 'sha256': 'd' * 64,
                'manage_source_revision': 'e' * 40, 'components': {
                    name: {'sha256': str(i) * 64, 'size_bytes': 10}
                    for i, name in enumerate(('bzImage', 'initrd', 'nix-store.squashfs'), 1)}}}
        self.cold = {k: True for k in acceptance.LIFECYCLE_FLAGS + acceptance.DELIVERY_FLAGS}
        self.cold.update(schema='cybex.james.nixos-appliance-qualification.v1',
            final_state='ready', qualification_kind='candidate', qualified_manifest_sha256=self.digest,
            harness_revision=self.source, release_version='0.2.3', base_os='nixos', system_closure_sha256='f' * 64, system_toplevel='/nix/store/exact-system',
            nixpkgs_revision='9' * 40, manage_source_revision='e' * 40, secure_boot=False,
            ssh_login_verified=True, ssh_root_rejected=True, ssh_password_rejected=True,
            template_sha256='c' * 64, system_generation='1', device_id='dev_' + '1' * 32,
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

        scope = {'schema': 'cybex.james.isolated-qualification.v1',
                 'manage_origin': 'https://manage.cybex.net', 'manage_revision': 'e' * 40,
                 'owner': '01234567-89ab-cdef-0123-456789abcdef', 'live_production_access': False}
        self.cold['qualification_scope'] = scope
        self.workstation['qualification_scope'] = scope

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
                             ('system_generation', '0'), ('candidate_runtime_required', False),
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

    def test_upload_action_digest_matches_prefixed_api_digest(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as package:
            for name in promotion.FILES:
                package.writestr(name, json.dumps({'ok': True}))
        body = output.getvalue()
        # upload-artifact@v4 returns bare hex; the REST API prefixes sha256:.
        action_digest = hashlib.sha256(body).hexdigest()
        metadata = dict(expired=False, workflow_run={'id': 123, 'head_sha': self.source},
                        name='cybex-james-published-cold-123', digest='sha256:' + action_digest)
        self.assertEqual(set(promotion.artifact_evidence(
            body, metadata, action_digest, 123, self.source)), promotion.FILES)
        for value in ('sha1:' + action_digest, 'sha256:sha256:' + action_digest,
                      action_digest[:-1], '0' * 64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                promotion.artifact_evidence(body, metadata, value, 123, self.source)

    def test_promotion_cli_accepts_action_outputs_and_preserves_asset_inventory(self):
        manifest_body = json.dumps(self.manifest).encode()
        cold = self.cold | {'qualified_manifest_sha256': hashlib.sha256(manifest_body).hexdigest()}
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as package:
            package.writestr('cybex-james-published-cold-qualification.json', json.dumps(cold))
            package.writestr('cybex-james-published-workstation-qualification.json', json.dumps(self.workstation))
        archive = output.getvalue()
        action_digest = hashlib.sha256(archive).hexdigest()
        candidate_digest = 'f' * 64
        tag = 'v' + self.manifest['version']
        base = f'https://github.com/CybexHQ/james/releases/download/{tag}/'
        identity = {'release_id': '0.2.1-dev.29'}
        bodies = {'cybex-james-release.json': manifest_body,
                  'cybex-james-release-compatibility.json': b'{}\n',
                  'cybex-james-build-predecessor.json': json.dumps(identity).encode()}
        staged = dict(id=900, immutable=True, draft=False, prerelease=True, target_commitish=self.source,
            body='\n'.join(['Cybex-Release-Workflow: https://github.com/CybexHQ/james/actions/runs/42',
                'Cybex-Candidate-Artifact-ID: 66', 'Cybex-Candidate-Artifact-SHA256: ' + candidate_digest,
                'Cybex-Cold-Qualification: required']),
            assets=[dict(id=i, name=name, browser_download_url=base + name, size=len(body),
                         digest='sha256:' + hashlib.sha256(body).hexdigest())
                    for i, (name, body) in enumerate(bodies.items(), 1)])
        promoted = {}

        def api(_repository, path):
            return {'actions/runs/42': {'head_sha': self.source, 'head_branch': tag,
                        'event': 'push', 'path': '.github/workflows/release.yml'},
                'commits/' + tag: {'sha': self.source},
                'actions/runs/42/jobs?per_page=100': {'jobs': [{'name':
                    'Verify published NixOS release in an isolated fixture', 'conclusion': 'success'}]},
                'actions/artifacts/77': dict(expired=False, size_in_bytes=len(archive),
                    workflow_run={'id': 42, 'head_sha': self.source},
                    name='cybex-james-published-cold-42', digest='sha256:' + action_digest),
                'releases/tags/' + tag: promoted or staged, 'releases/latest': promoted}[path]

        def edit(arguments, **_kwargs):
            self.assertEqual(arguments[:4], ['gh', 'release', 'edit', tag])
            self.assertIn('--prerelease=false', arguments)
            self.assertIn('--latest', arguments)
            notes = Path(arguments[arguments.index('--notes-file') + 1]).read_text()
            self.assertIn('Cybex-Cold-Artifact-SHA256: sha256:' + action_digest, notes)
            self.assertNotIn('Cybex-Cold-Qualification: required', notes)
            promoted.update(staged | {'prerelease': False, 'body': notes})

        arguments = ['promote', '--repository', 'CybexHQ/james', '--tag', tag, '--source', self.source,
            '--run', '42', '--artifact-id', '77', '--artifact-digest', action_digest,
            '--candidate-id', '66', '--candidate-digest', candidate_digest, '--trusted-public-key', 'fixture']
        # Exercise real CLI, ZIP/provenance, acceptance, notes and inventory checks.
        # Only remote transport and independently tested signature/lineage admission
        # are replaced; the immutable candidate/evidence identities remain coupled.
        with mock.patch.object(sys, 'argv', arguments), \
                mock.patch.object(promotion.predecessor, 'github', side_effect=api), \
                mock.patch.object(promotion.subprocess, 'check_output', return_value=archive), \
                mock.patch.object(promotion.subprocess, 'run', side_effect=edit) as mutation, \
                mock.patch.object(promotion.predecessor, 'fetch', side_effect=lambda url, path, *_a, **_k:
                    path.write_bytes(bodies[url.rsplit('/', 1)[-1]])), \
                mock.patch.object(promotion.predecessor, 'verify_pair', return_value=self.manifest), \
                mock.patch.object(promotion.predecessor, 'resolve', return_value=identity):
            with mock.patch.object(sys, 'argv', arguments + ['--verify-only']):
                promotion.main()
                mutation.assert_not_called()
                self.assertEqual(promoted, {})
            promotion.main()
        self.assertEqual(promoted['assets'], staged['assets'])


if __name__ == '__main__':
    unittest.main()
