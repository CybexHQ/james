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

    def _schema_change(self, directory, added, runs_declared=True):
        migrations = Path(directory) / "migrations"
        migrations.mkdir()
        for path in sorted((ROOT / "migrations").glob("*.sql")):
            (migrations / path.name).write_bytes(path.read_bytes())
        last = max(int(path.name.split("_", 1)[0]) for path in migrations.glob("*.sql"))
        predecessor = self._inventory(migrations)
        for name, body in added.items():
            (migrations / name).write_text(body)
        policy = Path(directory) / "policy.json"
        policy.write_text(json.dumps({
            "schema": "tiaris.nest.sqlite-schema-evolution.v1", "baseline_last_version": last,
            "predecessor_last_version": last, "predecessor_runs_declared_changes": runs_declared}))
        return predecessor, self._inventory(migrations), policy, migrations

    def _inventory(self, migrations):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "sqlite-migrations.json"
            subprocess.run([sys.executable, "-I", str(ROOT / "nixos-appliance/metadata.py"), "migrations",
                            str(migrations), str(output)], check=True)
            return hashlib.sha256(output.read_bytes()).hexdigest()

    def test_declared_schema_changes_pass_only_once_predecessors_run_them(self):
        declared = {"20991201000000_notes.sql": "-- tiaris-nest-schema: expand\nCREATE TABLE notes (id INTEGER);\n"}
        with tempfile.TemporaryDirectory() as directory:
            predecessor, candidate, policy, migrations = self._schema_change(directory, declared)
            self.assertNotEqual(predecessor, candidate)
            self.assertTrue(TOOL["_declared_schema_change"](candidate, predecessor, policy, migrations))
            # Not this checkout's inventory, or not from the pinned predecessor.
            self.assertFalse(TOOL["_declared_schema_change"]("e" * 64, predecessor, policy, migrations))
            self.assertFalse(TOOL["_declared_schema_change"](candidate, "e" * 64, policy, migrations))
        with tempfile.TemporaryDirectory() as directory:
            predecessor, candidate, policy, migrations = self._schema_change(directory, declared, False)
            self.assertFalse(TOOL["_declared_schema_change"](candidate, predecessor, policy, migrations))
        with tempfile.TemporaryDirectory() as directory:
            predecessor, candidate, policy, migrations = self._schema_change(
                directory, {"20991201000000_notes.sql": "CREATE TABLE notes (id INTEGER);\n"})
            self.assertFalse(TOOL["_declared_schema_change"](candidate, predecessor, policy, migrations))
            policy.write_text("{}")
            with self.assertRaisesRegex(TOOL["ReleaseError"], "not a SQLite schema evolution policy"):
                TOOL["_declared_schema_change"](candidate, predecessor, policy, migrations)

    def test_an_inventory_other_than_this_checkouts_is_never_a_declared_change(self):
        self.assertFalse(TOOL["_declared_schema_change"]("f" * 64, TOOL["_pinned_sqlite_migrations_sha256"]()))

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
