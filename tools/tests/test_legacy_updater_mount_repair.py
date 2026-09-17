import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('mount_repair', ROOT / 'ubuntu-appliance/repair-legacy-updater-mounts.py')
repair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repair)
FROZEN = repair.base.repaired_bytes((ROOT / 'tests/fixtures/appliance-updater/legacy-sourceparts.sh').read_bytes())

class MountRepairTests(unittest.TestCase):
    def test_exact_repair_changes_only_mounts_and_keeps_cleanup_order(self):
        updated = repair.repaired_bytes(FROZEN)
        restored = updated
        for old, new in reversed(repair.CHANGES):
            self.assertEqual(restored.count(new), 1)
            restored = restored.replace(new, old, 1)
        self.assertEqual(restored, FROZEN)
        self.assertEqual(repair.repaired_bytes(updated), updated)
        text = updated.decode()
        cleanup = text[text.index('cleanup_mounts()'):text.index('cleanup_package_solver_state()')]
        self.assertLess(cleanup.index('"$candidate_path/dev/pts"'), cleanup.index('"$candidate_path/dev"'))
        self.assertLess(cleanup.index('"$candidate_path/dev"'), cleanup.index('"$candidate_path"\n'))
        self.assertLess(text.index('candidate_created=true'), text.index('mount -t btrfs -o "subvol='))
        self.assertLess(text.index('mount -t btrfs -o "subvol='), text.index('mount --bind /dev '))
        with tempfile.NamedTemporaryFile() as stream:
            stream.write(updated); stream.flush()
            subprocess.run(['bash', '-n', stream.name], check=True)

    def test_unreviewed_updater_bytes_are_rejected(self):
        for body in [FROZEN + b'\n', b'', FROZEN.replace(b'--no-remove', b'--allow-remove')]:
            with self.assertRaises(repair.base.RepairError): repair.repaired_bytes(body)

    def test_released_updater_has_the_same_mount_and_unmount_contract(self):
        source = (ROOT / 'ubuntu-appliance/rootfs/usr/lib/cybex-james/cybex-james-appliance-update').read_text()
        self.assertIn('mount -t btrfs -o "subvol=/.cybex-root-generations/$candidate" "UUID=$root_uuid" "$candidate_path"', source)
        self.assertIn('mount --bind /dev/pts "$candidate_path/dev/pts"', source)
        cleanup = source[source.index('cleanup_mounts()'):source.index('cleanup_package_solver_state()')]
        self.assertIn('"$candidate_path/dev/pts"', cleanup)
        self.assertIn('"$candidate_path"\n', cleanup)

if __name__ == '__main__': unittest.main()
