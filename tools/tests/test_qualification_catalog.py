import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'nixos-appliance/qualification' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


catalog = load('blueprint-catalog')


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.rows = []
        self.configs = {}
        for slug, revision, profile in [('standard_workstation', 3, 'taskbar'),
                                         ('dock_workstation', 1, 'dock'),
                                         ('qualification_tiling', 2, 'tiling')]:
            row = {'id': str(uuid.uuid4()), 'slug': slug, 'current_revision': revision,
                   'current_revision_id': str(uuid.uuid4()),
                   'metadata_json': {'built_in': slug in catalog.BUILTINS,
                                     'blueprint_type': 'builtin_profile'}}
            self.rows.append(row)
            self.configs[slug] = {'blueprint_id': row['id'], 'blueprint_revision_id': row['current_revision_id'],
                'config_hash': 'a' * 64, 'expected_state_json': {
                    'checks': [{'id': 'desktop.profile', 'expected': {'desktop_profile': profile}}],
                    'applications': [{'package_ref': 'deno'}]}}

    def check(self):
        return catalog.catalog(self.rows, self.configs, 'qualification_tiling')

    def test_accepts_current_revisions_and_preserves_inputs(self):
        original = copy.deepcopy(self.rows)
        value = self.check()
        self.assertEqual(self.rows, original)
        self.assertEqual({r['current_revision'] for r in value['blueprints']}, {1, 2, 3})
        self.assertEqual({r['current_revision_id'] for r in value['blueprints']},
                         {r['current_revision_id'] for r in self.rows})

    def test_missing_duplicate_or_legacy_catalog_fails(self):
        for rows in [self.rows[:2], self.rows + self.rows[:1],
                     [{**self.rows[0], 'slug': 'standard_taskbar_workstation'}, *self.rows[1:]]]:
            with self.assertRaises(ValueError):
                catalog.catalog(rows, self.configs, 'qualification_tiling')

    def test_unreleased_revision_or_racing_config_fails(self):
        for revision in [0, -1, None, True, '3']:
            with self.subTest(revision=revision):
                self.rows[0]['current_revision'] = revision
                with self.assertRaises(ValueError):
                    self.check()
        self.rows[0]['current_revision'] = 3
        self.configs['standard_workstation']['blueprint_revision_id'] = str(uuid.uuid4())
        with self.assertRaises(ValueError):
            self.check()

    def test_desktop_and_source_free_app_coverage_cannot_be_removed(self):
        config = self.configs['qualification_tiling']
        for apps in [[], [{'package_ref': 'deno'}, {'package_ref': 'nodejs'}]]:
            config['expected_state_json']['applications'] = apps
            with self.assertRaises(ValueError):
                self.check()
        config['expected_state_json']['applications'] = [{'package_ref': 'deno'}]
        config['expected_state_json']['checks'][0]['expected']['desktop_profile'] = 'taskbar'
        with self.assertRaises(ValueError):
            self.check()

if __name__ == '__main__':
    unittest.main()
