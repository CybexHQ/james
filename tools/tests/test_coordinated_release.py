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
            module['pin'](root, 'a' * 40, '1.0.68', '0.2.6')
            self.assertTrue(module['validate'](root))
            pin = root / 'release/workstation-netboot-source.json'
            self.assertEqual(json.loads(pin.read_text())['repository'], 'CybexHQ/development')
            self.assertIn('version = "0.2.6"', (root / 'Cargo.lock').read_text())
            pin.write_text(pin.read_text().replace('a' * 40, 'b' * 40))
            with self.assertRaises(ValueError):
                module['validate'](root)
