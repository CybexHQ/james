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
FIXTURES = ROOT / "tools/tests/fixtures/tiaris-recovery"


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.authorization = ROOT / "tools/tests/fixtures/tiaris-recovery/authorization.json"
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
                                         (self.version, 'other/nest', self.key),
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
        staged = item(4, "v0.3.1") | {'prerelease': True, 'body': 'Tiaris-Cold-Qualification: required'}
        self.assertEqual(P.latest([previous, staged], 'v0.3.2'), previous)
        stable = staged | {'prerelease': False, 'body': 'Tiaris-Cold-Qualification: passed'}
        self.assertEqual(P.latest([previous, stable], 'v0.3.2'), stable)
        previous["assets"].append({"name": P.MANIFEST})
        with self.assertRaises(ValueError):
            P.latest([previous], "v0.2.2")

    def test_owner_waived_stable_release_and_pending_policy_prereleases(self):
        def item(i, tag, **fields):
            return {"id": i, "tag_name": tag, "draft": False, "published_at": f"2026-11-0{i}T00:00:00Z",
                    "assets": [{"name": P.MANIFEST}, {"name": P.COMPATIBILITY}], **fields}
        older = item(1, "v0.2.73", prerelease=False, body="Tiaris-Cold-Qualification: passed")
        # The exact shape of production's v0.2.78 on 2026-11-02: promoted to
        # stable and GitHub Latest by the owner with its cold marker still
        # `required` plus a waiver note. A stable release is ancestry.
        waived = item(2, "v0.2.78", prerelease=False, body="\n".join([
            "Tiaris-Release-Workflow: https://github.com/CybexHQ/james/actions/runs/41474948660",
            "Tiaris-Candidate-Artifact-ID: 13157802896",
            "Tiaris-Candidate-Artifact-SHA256: " + "7" * 64,
            "Tiaris-Cold-Qualification: required", "", "",
            "Cold qualification waived by owner (John) on 2026-11-02 19:27: qualification-harness deadlock "
            "(fixed in james#61), not a product defect. Warm qualification passed."]))
        self.assertEqual(P.latest([older, waived], "v0.2.79"), waived)
        # Release policy fast-v1: a staged prerelease awaiting approval is not
        # ancestry; once promoted it is, without any VM qualification marker.
        pending = item(3, "v0.2.80", prerelease=True, body="\n".join([
            "Tiaris-Release-Workflow: https://github.com/CybexHQ/james/actions/runs/1",
            "Tiaris-VM-Qualification: nightly", "Tiaris-Public-Closure: required"]))
        self.assertEqual(P.latest([older, waived, pending], "v0.2.81"), waived)
        promoted = pending | {"prerelease": False, "body": pending["body"].replace(
            "Tiaris-Public-Closure: required", "Tiaris-Public-Closure: passed")}
        self.assertEqual(P.latest([older, waived, promoted], "v0.2.81"), promoted)
        # The candidate's own staged release is never its predecessor.
        self.assertEqual(P.latest([older, waived, promoted], "v0.2.80"), waived)
        # The cancelled v0.2.79 never published a release; a draft is ignored.
        draft = item(4, "v0.2.79", draft=True, prerelease=True, body="Tiaris-Cold-Qualification: required")
        self.assertEqual(P.latest([older, waived, draft], "v0.2.80"), waived)

    def test_resolve_admits_the_waived_release_as_authenticated_predecessor(self):
        release = {"id": 7, "tag_name": "v0.2.78", "draft": False, "prerelease": False,
                   "published_at": "2026-11-02T16:54:23Z", "target_commitish": "7" * 40,
                   "body": "Tiaris-Cold-Qualification: required\n\nCold qualification waived by owner.",
                   "assets": [{"name": name, "size": 10, "digest": "sha256:" + "a" * 64,
                               "browser_download_url": "https://github.com/CybexHQ/james/releases/download/v0.2.78/" + name}
                              for name in (P.MANIFEST, P.COMPATIBILITY)]}
        manifest = {"version": "0.2.78", "appliance_release_v1": {"schema": "tiaris.nest.appliance-release.v3",
                    "source_revision": "7" * 40, "manage_source_revision": "8" * 40,
                    "system_closure": {"sha256": "9" * 64}, "system_toplevel": "/nix/store/x"}}
        def github(_repository, path):
            return [release] if path.startswith("releases") else {"sha": "7" * 40}
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(P, "github", side_effect=github), \
                mock.patch.object(P, "fetch", side_effect=lambda url, path, *_a: path.write_bytes(b"{}")), \
                mock.patch.object(P, "verify_pair", return_value=manifest):
            value = P.resolve("CybexHQ/james", "0.2.79", self.key, Path(temporary))
            self.assertEqual((value["release_id"], value["tag_name"], value["github_release_id"]),
                             ("0.2.78", "v0.2.78", 7))
            with self.assertRaisesRegex(ValueError, "strictly advance"):
                P.resolve("CybexHQ/james", "0.2.78-dev.1", self.key, Path(temporary))

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
