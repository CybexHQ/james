"""Recovery admission against the exact public, signed historical descriptors."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_predecessor", ROOT / "ubuntu-appliance/qualification/release_predecessor.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
FIXTURES = ROOT / "tools/tests/fixtures/recovery"


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.authorization = ROOT / "release/recovery-adoption.json"
        self.anchor = json.loads(self.authorization.read_bytes())
        self.key = self.anchor["public_key"]

    def test_signed_adoption_is_exactly_scoped(self):
        self.assertEqual(P.authorization(self.authorization, self.key, "0.2.2", "CybexHQ/james"), self.anchor)
        for version, repository, key in [("0.2.3", "CybexHQ/james", self.key),
                                          ("0.2.2", "other/james", self.key),
                                          ("0.2.2", "CybexHQ/james", self.anchor["published"]["public_key"])]:
            with self.assertRaises(ValueError):
                P.authorization(self.authorization, key, version, repository)

    def test_recovery_or_old_authority_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authorization.json"
            for section, field, replacement in [("recovery", "manifest_sha256", "0" * 64),
                                                 ("published", "public_key", self.key),
                                                 ("published", "github_release_id", 1)]:
                value = copy.deepcopy(self.anchor)
                value[section][field] = replacement
                path.write_bytes(P.canonical(value))
                with self.assertRaises(P.release.ReleaseError):
                    P.authorization(path, self.key, "0.2.2", "CybexHQ/james")

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
            with self.assertRaisesRegex(ValueError, "first release"):
                P.resolve("CybexHQ/james", "0.2.2", self.key, Path(temporary), self.authorization)

    def test_latest_selection_ignores_drafts_and_rejects_ambiguous_assets(self):
        def item(i, tag, draft=False):
            return {"id": i, "tag_name": tag, "draft": draft, "published_at": str(i),
                    "assets": [{"name": P.MANIFEST}, {"name": P.COMPATIBILITY}]}
        previous = item(1, "v0.2.1-dev.4")
        self.assertEqual(P.latest([previous, item(2, "v0.2.2"), item(3, "v0.3.0", True)], "v0.2.2"), previous)
        previous["assets"].append({"name": P.MANIFEST})
        with self.assertRaises(ValueError):
            P.latest([previous], "v0.2.2")

    def test_cached_bytes_do_not_bypass_digest_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cached"
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "digest changed"):
                P.fetch("https://manage.cybex.net/retained", path, "0" * 64)


if __name__ == "__main__":
    unittest.main()
