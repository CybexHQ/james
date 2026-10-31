"""The SQLite migration inventory must stay that of the releases appliances
update from (release/sqlite-migrations.sha256); see that file."""
import hashlib
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = runpy.run_path(str(ROOT / "tools/nest-release.py"))


class SqliteMigrationsPinTests(unittest.TestCase):
    def test_migrations_produce_the_pinned_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "sqlite-migrations.json"
            subprocess.run([sys.executable, "-I", str(ROOT / "nixos-appliance/metadata.py"), "migrations",
                            str(ROOT / "migrations"), str(output)], check=True)
            built = hashlib.sha256(output.read_bytes()).hexdigest()
        self.assertEqual(built, TOOL["_pinned_sqlite_migrations_sha256"](),
                         "migrations/ changed: NixOS appliances would refuse this release "
                         "(rollback_database_incompatible); see release/sqlite-migrations.sha256")

    def test_the_pin_holds_exactly_one_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            pin = Path(directory) / "pin"
            pin.write_text("# comment\n" + "a" * 64 + "\n")
            self.assertEqual(TOOL["_pinned_sqlite_migrations_sha256"](pin), "a" * 64)
            for body in ("", "a" * 64 + "\n" + "b" * 64 + "\n", "A" * 64, "not a digest"):
                pin.write_text(body)
                with self.assertRaises(TOOL["ReleaseError"]):
                    TOOL["_pinned_sqlite_migrations_sha256"](pin)

    def test_another_inventory_is_never_signed_or_accepted(self):
        pinned = TOOL["_pinned_sqlite_migrations_sha256"]()
        TOOL["_require_update_compatible_migrations"](pinned, pinned, "the pin")
        with self.assertRaisesRegex(TOOL["ReleaseError"], "rollback_database_incompatible"):
            TOOL["_require_update_compatible_migrations"]("f" * 64, pinned, "the pin")

    def test_release_manifests_must_be_the_ones_their_assets_name(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tiaris-nest-release.json"
            body = json.dumps({"appliance_release_v1": {"sqlite_migrations_sha256": "c" * 64}}).encode()
            path.write_bytes(body)
            asset = {"release_manifest": {"sha256": hashlib.sha256(body).hexdigest()}}
            self.assertEqual(TOOL["_release_sqlite_migrations"](path, asset, "manifest"), "c" * 64)
            with self.assertRaisesRegex(TOOL["ReleaseError"], "not the manifest"):
                TOOL["_release_sqlite_migrations"](path, {"release_manifest": {"sha256": "0" * 64}}, "manifest")
            ubuntu = json.dumps({"appliance_release_v1": {"tiaris_repository_snapshot": "x"}}).encode()
            path.write_bytes(ubuntu)
            asset = {"release_manifest": {"sha256": hashlib.sha256(ubuntu).hexdigest()}}
            self.assertIsNone(TOOL["_release_sqlite_migrations"](path, asset, "manifest"))


if __name__ == "__main__":
    unittest.main()
