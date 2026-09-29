"""Authenticate actual published James bytes; never accept them as Nest media."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('predecessor', ROOT / 'nixos-appliance/qualification/release_predecessor.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
FIXTURE = ROOT / 'tools/tests/fixtures/james-0.2.41'


class NamespaceTransitionTests(unittest.TestCase):
    def setUp(self):
        self.anchor = json.loads(P.TRANSITION.read_bytes())
        self.previous = {'id': self.anchor['published']['github_release_id'], **self.anchor['published']}

    def authenticate(self, directory=FIXTURE, authorization=P.TRANSITION, **overrides):
        args = dict(trusted_key=self.anchor['public_key'], repository='CybexHQ/james',
                    candidate=self.anchor['successor_version'], previous=self.previous)
        args.update(overrides)
        return P.transition.authenticate(P.release, directory, authorization, **args)

    def test_original_signed_descriptors_authenticate_without_rewriting(self):
        before = {path.name: path.read_bytes() for path in FIXTURE.iterdir()}
        anchor, manifest, compatibility = self.authenticate()
        self.assertEqual(manifest['version'], '0.2.41')
        self.assertEqual(compatibility['schema'], 'cybex.james.release-compatibility.v1')
        self.assertEqual(anchor['operation'], 'reinstall-only')
        self.assertEqual(before, {path.name: path.read_bytes() for path in FIXTURE.iterdir()})
        with self.assertRaises(P.release.ReleaseError):
            P.verify_pair(FIXTURE, self.anchor['public_key'])

    def test_exact_successor_repository_and_publication_are_required(self):
        for override in ({'candidate': '0.0.0'}, {'repository': 'CybexHQ/other'},
                         {'previous': self.previous | {'id': 42}},
                         {'previous': self.previous | {'target_commitish': '0' * 40}}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                self.authenticate(**override)

    def test_changed_authorization_signature_or_historical_bytes_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for field in ('successor_version', 'signature', 'reason'):
                anchor = copy.deepcopy(self.anchor)
                anchor[field] = 'changed'
                authorization = directory / 'authorization.json'
                authorization.write_bytes(P.canonical(anchor))
                with self.subTest(field=field), self.assertRaises((ValueError, P.release.ReleaseError)):
                    self.authenticate(authorization=authorization)
            for changed in (P.transition.MANIFEST, P.transition.COMPATIBILITY):
                for path in FIXTURE.iterdir():
                    (directory / path.name).write_bytes(path.read_bytes())
                path = directory / changed
                path.write_bytes(path.read_bytes() + b' ')
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    self.authenticate(directory=directory)

    def test_signed_current_successor_must_advance_runtime_and_preserve_origin(self):
        previous = json.loads((FIXTURE / P.transition.COMPATIBILITY).read_bytes())
        current = copy.deepcopy(previous)
        current['nest_release_version'] = self.anchor['successor_version']
        current['artifacts']['workstation_runtime']['runtime_version'] = '1.0.86'
        current['artifacts']['workstation_runtime']['sha256'] = 'a' * 64
        def verify(value):
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'current.json'
                path.write_bytes(P.canonical(value))
                with mock.patch.object(P.release, '_verified_release_compatibility_payload', return_value=value) as authenticated:
                    P.transition.verify_successor(P.release, FIXTURE, P.TRANSITION,
                        self.anchor['public_key'], 'CybexHQ/james', path)
                    authenticated.assert_called_once_with(value, P.canonical(value), self.anchor['public_key'])
        verify(current)
        for field, value in [('runtime_version', '1.0.84'), ('runtime_version', '1.0.85'),
                             ('sha256', previous['artifacts']['workstation_runtime']['sha256'])]:
            bad = copy.deepcopy(current)
            bad['artifacts']['workstation_runtime'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                verify(bad)
        bad = copy.deepcopy(current)
        bad['artifacts']['appliance_iso_template']['manage_origin'] = 'https://dev.cybex.net'
        with self.assertRaises(ValueError):
            verify(bad)

    def test_latest_legacy_publication_is_not_silently_discarded(self):
        old = {'id': 1, 'tag_name': 'v0.2.41', 'draft': False, 'published_at': '1',
               'assets': [{'name': P.transition.MANIFEST}, {'name': P.transition.COMPATIBILITY}]}
        self.assertEqual(P.latest([old], 'v0.2.42'), old)
        staged = old | {'id': 2, 'tag_name': 'v0.2.42', 'prerelease': True,
                        'body': 'Cybex-Cold-Qualification: required', 'published_at': '2'}
        self.assertEqual(P.latest([old, staged], 'v0.2.43'), old)
        ambiguous = old | {'assets': old['assets'] + [{'name': P.MANIFEST}, {'name': P.COMPATIBILITY}]}
        with self.assertRaises(ValueError):
            P.latest([ambiguous], 'v0.2.42')

    def test_resolver_preserves_legacy_names_and_reinstall_only_receipt(self):
        publication = self.previous | {'draft': False, 'published_at': '1', 'assets': [
            {'name': name, 'browser_download_url': 'https://github.com/CybexHQ/james/releases/download/v0.2.41/' + name,
             'size': (FIXTURE / name).stat().st_size} for name in (P.transition.MANIFEST, P.transition.COMPATIBILITY)]}
        def github(_repository, path):
            return [publication] if path.startswith('releases?') else {'sha': self.previous['target_commitish']}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(P, 'github', side_effect=github):
            directory = Path(temporary)
            for path in FIXTURE.iterdir():
                (directory / path.name).write_bytes(path.read_bytes())
            result = P.resolve('CybexHQ/james', self.anchor['successor_version'], self.anchor['public_key'], directory)
            self.assertEqual(result['update_contract'], 'reinstall-only')
            self.assertEqual(result['namespace_transition_sha256'], P.sha(P.TRANSITION))
            self.assertFalse((directory / P.MANIFEST).exists())
            self.assertFalse((directory / P.COMPATIBILITY).exists())


if __name__ == '__main__':
    unittest.main()
