"""Current Blueprint inputs must run on the candidate, never its predecessor."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
import uuid

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'
sys.path.insert(0, str(HELPERS))
SPEC = importlib.util.spec_from_file_location('blueprint_delivery', HELPERS / 'blueprint_delivery.py')
delivery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(delivery)


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.t = 0
        self.created = []
        self.old_runtime = True
        self.blocked = False
        self.policy_allowed = False
        self.cached = True
        self.manifest = {'workstation_netboot': {'runtime_version': '1.0.108', 'sha256': 'a' * 64,
                                               'manage_source_revision': 'b' * 40}}
        self.catalog = {'schema': 'tiaris.nest.qualification-blueprints.v1', 'blueprints': [
            {'id': str(uuid.uuid4()), 'current_revision_id': str(uuid.uuid4()),
             'desktop_profile': profile, 'slug': slug, 'current_revision': 1,
             'config_hash': 'c' * 64} for slug, profile in (
                ('standard_workstation', 'taskbar'), ('dock_workstation', 'dock'),
                ('qualification_dock', 'dock'))]}

    def sleep(self, seconds):
        self.t += seconds

    def api(self, path, body=None):
        if path == '/v1/nest/delivery-policy':
            return {'allow_nest_source_builds': self.policy_allowed,
                    'source_builds_allowed': self.policy_allowed, 'allow_local_builds': False,
                    'emergency_override_mode': None}
        if path.endswith('/workstation-netboot'):
            runtime = copy.deepcopy(self.manifest['workstation_netboot'])
            runtime['bundle_sha256'] = runtime.pop('sha256')
            if self.old_runtime and self.t < 5:
                runtime['bundle_sha256'] = 'd' * 64
            return {'operational': True, 'converged': True, 'active': runtime, 'desired': runtime}
        if path.endswith('/build/jobs') or '/build/jobs?' in path:
            if body:
                self.assertGreaterEqual(self.t, 5, 'current inputs were sent to the signed predecessor')
                job = {'id': str(uuid.uuid4()), 'build_spec': copy.deepcopy(body),
                       'status': 'failed' if self.blocked else 'succeeded',
                       'cache_metadata': {'error_kind': 'source_build_blocked'} if self.blocked else {}}
                self.created.append(job)
                return job
            return {'jobs': copy.deepcopy(self.created)}
        if '/nest-cache?' in path:
            return {'cached': self.cached, 'required_replicas': 1, 'ready_replicas': int(self.cached)}
        self.fail('Unexpected API path ' + path)

    def qualify(self):
        return delivery.qualify(self.api, 'dev_' + '1' * 32, self.manifest, self.catalog,
                                clock=lambda: self.t, sleep=self.sleep, timeout=12)

    def test_waits_for_exact_candidate_then_builds_all_profiles_without_sources(self):
        result = self.qualify()
        self.assertEqual(len(self.created), 3)
        self.assertEqual(result['qualified_blueprints'], self.catalog)
        self.assertTrue(result['source_free'])
        self.assertTrue(result['deliverable'])
        self.assertEqual(set(result['job_ids']), {row['id'] for row in self.created})
        delivery.validate(self.manifest, 'dev_' + '1' * 32, result)

    def test_source_build_block_and_relaxed_policy_fail_without_evidence(self):
        self.blocked = True
        with self.assertRaisesRegex(ValueError, 'source-free'):
            self.qualify()
        self.policy_allowed = True
        with self.assertRaisesRegex(ValueError, 'policy'):
            self.qualify()

    def test_missing_replica_never_passes(self):
        self.cached = False
        with self.assertRaisesRegex(ValueError, 'timed out'):
            self.qualify()

    def test_receipt_rejects_old_runtime_partial_catalog_or_substituted_device(self):
        result = self.qualify()
        for field, value in [('bundle_sha256', 'd' * 64), ('runtime_version', '1.0.1'),
                             ('nest_device_id', 'dev_' + '2' * 32), ('source_free', False),
                             ('source_builds_allowed', True), ('job_ids', result['job_ids'][:2])]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                delivery.validate(self.manifest, 'dev_' + '1' * 32, result | {field: value})
        wrong = copy.deepcopy(result)
        wrong['qualified_blueprints']['blueprints'][1] = wrong['qualified_blueprints']['blueprints'][0]
        with self.assertRaises(ValueError):
            delivery.validate(self.manifest, 'dev_' + '1' * 32, wrong)
        for profile in ('tiling', 'gnome-overview', 'minimal', 'taskbar', None):
            wrong = copy.deepcopy(result)
            wrong['qualified_blueprints']['blueprints'][2]['desktop_profile'] = profile
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                delivery.validate(self.manifest, 'dev_' + '1' * 32, wrong)


if __name__ == '__main__':
    unittest.main()
