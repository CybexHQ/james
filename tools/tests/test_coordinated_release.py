import json
from pathlib import Path
import runpy
import tempfile
import unittest

module = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'coordinated-release.py'))


class CoordinatedReleaseTests(unittest.TestCase):
    def test_pins_development_and_requires_explicit_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'release').mkdir()
            (root / 'Cargo.toml').write_text('[package]\nname="cybex-james"\nversion = "0.2.5"\n')
            (root / 'Cargo.lock').write_text('[[package]]\nname = "cybex-james"\nversion = "0.2.5"\n')
            self.assertFalse(module['validate'](root))
            module['pin'](root, 'a' * 40, '1.0.68', '0.2.6', '20260920T120000Z')
            self.assertTrue(module['validate'](root))
            marker = json.loads((root / 'release/coordinated.json').read_text())
            self.assertEqual(marker['ubuntu_snapshot_id'], '20260920T120000Z')
            pin = root / 'release/workstation-netboot-source.json'
            self.assertEqual(json.loads(pin.read_text())['repository'], 'CybexHQ/development')
            self.assertIn('version = "0.2.6"', (root / 'Cargo.lock').read_text())
            pin.write_text(pin.read_text().replace('a' * 40, 'b' * 40))
            with self.assertRaises(ValueError):
                module['validate'](root)

    def test_rejects_invalid_snapshot_cutoffs(self):
        for snapshot in ['latest', '20260230T000000Z', '20260920T250000Z', '20260920T120000Z\nINJECT=1']:
            with self.subTest(snapshot=snapshot), self.assertRaises(ValueError):
                module['validate_snapshot'](snapshot)

    def test_workflow_uses_the_immutable_tag_snapshot(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/release.yml').read_text()
        self.assertIn(".ubuntu_snapshot_id // empty", workflow)
        self.assertIn('CYBEX_JAMES_UBUNTU_SNAPSHOT_ID="$snapshot"', workflow)
        self.assertIn('"$snapshot" >> "$GITHUB_ENV"', workflow)
