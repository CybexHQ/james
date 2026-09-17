import importlib.util
import contextlib
import fcntl
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("updater_repair", ROOT / "ubuntu-appliance/repair-legacy-updater.py")
repair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repair)
FROZEN = (ROOT / "tests/fixtures/appliance-updater/legacy-sourceparts.sh").read_bytes()


class LegacyUpdaterRepairTests(unittest.TestCase):
    def prepare(self, root):
        updater = root / "updater"
        updater.write_bytes(FROZEN)
        updater.chmod(0o755)
        return updater, root / "backup"

    def test_exact_repair_preserves_every_other_byte(self):
        updated = repair.repaired_bytes(FROZEN)
        self.assertEqual(repair.digest(FROZEN), repair.BEFORE)
        self.assertEqual(repair.digest(updated), repair.AFTER)
        reverted = updated.replace(
            b' "$solver_root/archives" \\\n  "$solver_root/sources.list.d"\n',
            b' "$solver_root/archives"\n',
        ).replace(b"Dir::Etc::sourceparts=/run/cybex-update-apt/sources.list.d\n",
                  b"Dir::Etc::sourceparts=-\n")
        self.assertEqual(reverted, FROZEN)
        self.assertEqual(repair.repaired_bytes(updated), updated)

    def test_unknown_or_modified_updater_is_rejected(self):
        for data in [b"", FROZEN + b"\n", FROZEN.replace(b"--no-remove", b"--allow-remove")]:
            with self.subTest(data_size=len(data)), self.assertRaises(repair.RepairError):
                repair.repaired_bytes(data)

    def test_inspection_does_not_write_and_apply_preserves_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            updater, backup = self.prepare(root)
            receipt = repair.repair(updater, backup)
            self.assertFalse(receipt["changed"])
            self.assertFalse(backup.exists())
            self.assertEqual(updater.read_bytes(), FROZEN)
            receipt = repair.repair(updater, backup, apply=True)
            self.assertTrue(receipt["changed"])
            self.assertFalse(receipt["update_started"])
            self.assertEqual((backup / "updater.before").read_bytes(), FROZEN)
            self.assertEqual(repair.digest(updater.read_bytes()), repair.AFTER)
            self.assertEqual(updater.stat().st_mode & 0o777, 0o755)
            self.assertFalse(repair.repair(updater, backup, apply=True)["changed"])

    def test_root_only_installed_updater_keeps_its_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            updater, backup = self.prepare(Path(directory))
            updater.chmod(0o700)
            self.assertTrue(repair.repair(updater, backup, apply=True)["changed"])
            self.assertEqual(updater.stat().st_mode & 0o777, 0o700)

    def test_conflicting_backup_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            updater, backup = self.prepare(Path(directory))
            backup.mkdir(mode=0o700)
            (backup / "updater.before").write_bytes(b"unrelated data")
            with self.assertRaises(repair.RepairError):
                repair.repair(updater, backup, apply=True)
            self.assertEqual(updater.read_bytes(), FROZEN)

    def test_symlink_and_writable_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            updater, backup = self.prepare(root)
            link = root / "link"
            link.symlink_to(updater)
            with self.assertRaises(OSError):
                repair.repair(link, backup, apply=True)
            updater.chmod(0o777)
            with self.assertRaises(repair.RepairError):
                repair.repair(updater, backup, apply=True)
            self.assertEqual(updater.read_bytes(), FROZEN)

    def test_backup_directory_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            updater, backup = self.prepare(root)
            target = root / "target"
            target.mkdir()
            backup.symlink_to(target)
            with self.assertRaises(repair.RepairError):
                repair.repair(updater, backup, apply=True)
            self.assertEqual(updater.read_bytes(), FROZEN)
            self.assertEqual(list(target.iterdir()), [])

    @unittest.skipUnless(os.geteuid() == 0, "root-owned appliance lock integration")
    def test_cli_initializes_missing_lock_and_preserves_existing_lock_inode(self):
        for existing_mode in [None, 0o644, 0o640]:
            with self.subTest(existing_mode=existing_mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                updater, _ = self.prepare(root)
                lock = root / "updater.lock"
                inode = None
                if existing_mode is not None:
                    lock.touch(mode=existing_mode)
                    inode = lock.stat().st_ino
                with patch.multiple(repair, UPDATER=updater, BACKUP=root / "repairs" / "v1", LOCK=lock), \
                     patch.object(repair.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=0)), \
                     patch("sys.argv", ["repair", "--apply"]), contextlib.redirect_stdout(io.StringIO()):
                    repair.main()
                self.assertEqual(repair.digest(updater.read_bytes()), repair.AFTER)
                self.assertEqual(lock.stat().st_mode & 0o777, 0o640)
                if inode is not None:
                    self.assertEqual(lock.stat().st_ino, inode)

    @unittest.skipUnless(os.geteuid() == 0, "root-owned appliance lock integration")
    def test_cli_contended_lock_leaves_updater_and_backup_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            updater, _ = self.prepare(root)
            lock = root / "updater.lock"
            with lock.open("w") as owner:
                fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.multiple(repair, UPDATER=updater, BACKUP=root / "repairs" / "v1", LOCK=lock), \
                     patch("sys.argv", ["repair", "--apply"]), self.assertRaises(BlockingIOError):
                    repair.main()
            self.assertEqual(updater.read_bytes(), FROZEN)
            self.assertFalse((root / "repairs").exists())

    @unittest.skipUnless(os.geteuid() == 0, "root-owned appliance lock integration")
    def test_cli_inspection_does_not_initialize_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            updater, backup = self.prepare(root)
            lock = root / "updater.lock"
            with patch.multiple(repair, UPDATER=updater, BACKUP=backup, LOCK=lock), \
                 patch("sys.argv", ["repair"]), contextlib.redirect_stdout(io.StringIO()):
                repair.main()
            self.assertEqual(updater.read_bytes(), FROZEN)
            self.assertFalse(lock.exists())
            self.assertFalse(backup.exists())


if __name__ == "__main__":
    unittest.main()
