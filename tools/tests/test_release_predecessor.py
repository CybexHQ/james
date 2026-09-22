"""Recovery admission against the exact public, signed historical descriptors."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_predecessor", ROOT / "nixos-appliance/qualification/release_predecessor.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
FIXTURES = ROOT / "tools/tests/fixtures/recovery"


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.authorization = ROOT / "release/recovery-adoption.json"
        self.anchor = json.loads(self.authorization.read_bytes())
        self.key = self.anchor["public_key"]
        self.version = self.anchor["successor_version"]

    def authority(self, path, key, version, repository):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / P.MANIFEST).write_bytes((FIXTURES / 'github-manifest.json').read_bytes())
            (directory / P.COMPATIBILITY).write_bytes((FIXTURES / 'github-compatibility.json').read_bytes())
            previous = self.anchor['published'] | {'id': self.anchor['published']['github_release_id']}
            return P.historical_authority(path, key, previous, directory, version, repository)

    def test_historical_authority_is_scoped_and_signed(self):
        self.assertEqual(self.authority(self.authorization, self.key, self.version, 'CybexHQ/james'),
                         self.anchor['published']['public_key'])
        for version, repository, key in [('99.0.0', 'CybexHQ/james', self.key),
                                         (self.version, 'other/james', self.key),
                                         (self.version, 'CybexHQ/james', self.anchor['published']['public_key'])]:
            with self.assertRaises(ValueError):
                self.authority(self.authorization, key, version, repository)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'authorization.json'
            bad = copy.deepcopy(self.anchor)
            bad['published']['manifest_sha256'] = '0' * 64
            path.write_bytes(P.canonical(bad))
            with self.assertRaises(P.release.ReleaseError):
                self.authority(path, self.key, self.version, 'CybexHQ/james')

    def test_both_original_descriptor_pairs_authenticate_under_their_own_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            for prefix, key, url in [("github", self.anchor["published"]["public_key"],
                                      "https://github.com/CybexHQ/james/releases/download/v0.2.1-dev.4/" + P.MANIFEST),
                                     ("recovery", self.key, self.anchor["recovery"]["manifest_url"])]:
                (path / P.MANIFEST).write_bytes((FIXTURES / (prefix + "-manifest.json")).read_bytes())
                (path / P.COMPATIBILITY).write_bytes((FIXTURES / (prefix + "-compatibility.json")).read_bytes())
                P.verify_pair(path, key, url)
                wrong = self.key if prefix == "github" else self.anchor["published"]["public_key"]
                with self.assertRaises(P.release.ReleaseError):
                    P.verify_pair(path, wrong, url)

    def test_missing_publication_cannot_be_treated_as_first_release(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(P, "github", return_value=[]):
            with self.assertRaisesRegex(ValueError, "first-release"):
                P.resolve("CybexHQ/james", self.version, self.key, Path(temporary), self.authorization)

    def test_latest_selection_ignores_drafts_and_rejects_ambiguous_assets(self):
        def item(i, tag, draft=False):
            return {"id": i, "tag_name": tag, "draft": draft, "published_at": str(i),
                    "assets": [{"name": P.MANIFEST}, {"name": P.COMPATIBILITY}]}
        previous = item(1, "v0.2.1-dev.4")
        self.assertEqual(P.latest([previous, item(2, "v0.2.2"), item(3, "v0.3.0", True)], "v0.2.2"), previous)
        staged = item(4, "v0.3.1") | {'prerelease': True, 'body': 'Cybex-Cold-Qualification: required'}
        self.assertEqual(P.latest([previous, staged], 'v0.3.2'), previous)
        stable = staged | {'prerelease': False, 'body': 'Cybex-Cold-Qualification: passed'}
        self.assertEqual(P.latest([previous, stable], 'v0.3.2'), stable)
        previous["assets"].append({"name": P.MANIFEST})
        with self.assertRaises(ValueError):
            P.latest([previous], "v0.2.2")

    def test_upgrade_fixture_stages_and_authenticates_workstation_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / 'source', root / 'destination'
            source.mkdir()
            destination.mkdir()
            def artifact(name, field='sha256'):
                body = ('signed ' + name).encode()
                (source / name).write_bytes(body)
                return {'url': 'https://github.com/CybexHQ/james/releases/download/v0.2.12/' + name,
                        field: hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
            manifest = {'appliance_release_v1': {'system_closure': artifact('closure.tar.zst')},
                        'installer_iso_template_v3': artifact('template.iso', 'template_sha256'),
                        'workstation_netboot': artifact('workstation.tar.zst')}
            P.stage_media(destination, manifest, source)
            self.assertEqual((destination / 'workstation.tar.zst').read_bytes(), b'signed workstation.tar.zst')
            (destination / 'workstation.tar.zst').write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'signed size or digest'):
                P.stage_media(destination, manifest, source)

    def test_cached_bytes_do_not_bypass_digest_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cached"
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "signed size or digest"):
                P.fetch("https://github.com/CybexHQ/james/releases/download/v0.2.1/retained", path, "0" * 64)


if __name__ == "__main__":
    unittest.main()
