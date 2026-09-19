import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
PACKAGE = runpy.run_path(str(REPOSITORY / 'ubuntu-appliance/package-source-offer.py'))['package_source_offer']
GATE = runpy.run_path(str(REPOSITORY / 'ubuntu-appliance/qualification/legacy-bridge-gate.py'))


class SourceOfferPackageTests(unittest.TestCase):
    def fixture(self, root):
        files = {
            'CYBEX-SBOM.spdx.json': b'{"spdxVersion":"SPDX-2.3"}',
            'UDPCAST-COPYRIGHT': b'Corresponding source copyright and GPL notice',
            'udpcast_20120424-2build2.dsc': b'Authenticated source descriptor fixture',
            'udpcast_20120424.orig.tar.gz': b'Complete upstream source fixture',
            'udpcast_20120424-2build2.debian.tar.xz': b'Complete packaging source fixture',
        }
        for name, body in files.items():
            (root / name).write_bytes(body)
        return files

    def test_all_source_and_license_bytes_survive_in_a_regular_deb(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = self.fixture(root)
            package = PACKAGE(root, '0.2.1-dev.23', 1788220800)
            self.assertEqual(list(root.iterdir()), [package])
            self.assertTrue(package.name.endswith('.deb'))
            unpacked = root / 'unpacked'
            subprocess.run(['dpkg-deb', '--extract', str(package), str(unpacked)], check=True)
            documents = unpacked / 'usr/share/doc/cybex-james/source-offer'
            self.assertEqual({p.name: p.read_bytes() for p in documents.iterdir()}, files)
            for path in documents.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            fields = subprocess.check_output(['dpkg-deb', '-f', str(package), 'Package', 'Architecture'], text=True)
            self.assertIn('cybex-james-source-offer', fields)
            self.assertIn('all', fields)

    def test_output_is_reproducible(self):
        digests = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root)
                package = PACKAGE(root, '0.2.1-dev.23', 1788220800)
                digests.append(hashlib.sha256(package.read_bytes()).hexdigest())
        self.assertEqual(digests[0], digests[1])

    def test_missing_source_and_symlink_are_rejected_without_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = self.fixture(root)
            (root / 'udpcast_20120424-2build2.dsc').unlink()
            with self.assertRaises(ValueError):
                PACKAGE(root, '0.2.1-dev.23', 1788220800)
            self.assertTrue((root / 'UDPCAST-COPYRIGHT').exists())
            self.fixture(root)
            (root / 'UDPCAST-COPYRIGHT').unlink()
            (root / 'UDPCAST-COPYRIGHT').symlink_to(root / 'CYBEX-SBOM.spdx.json')
            with self.assertRaises(ValueError):
                PACKAGE(root, '0.2.1-dev.23', 1788220800)
            self.assertTrue((root / 'udpcast_20120424-2build2.dsc').exists())

    def test_existing_output_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            existing = root / 'cybex-james-source-offer_0.2.1-dev.23-1_all.deb'
            existing.write_bytes(b'protected')
            with self.assertRaises(ValueError):
                PACKAGE(root, '0.2.1-dev.23', 1788220800)
            self.assertEqual(existing.read_bytes(), b'protected')
            self.assertTrue((root / 'CYBEX-SBOM.spdx.json').exists())

    def test_release_gate_accepts_packaged_offer_and_rejects_missing_offer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            (root / 'CYBEX-SBOM.spdx.json').write_text(json.dumps({
                'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0',
                'packages': [{'name': 'udpcast', 'licenseDeclared': 'GPL-2.0-only AND BSD-2-Clause'}]}))
            package = PACKAGE(root, '0.2.1-dev.29', 1788220800)
            for name in ['udpcast_20120424-2build2_amd64.deb', 'Packages', 'Packages.gz', 'Release']:
                (root / name).write_bytes(b'authenticated fixture')
            (root / 'SHA256SUMS').write_text(''.join(
                hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
                for p in sorted(root.iterdir())))
            (root / 'UBUNTU-SNAPSHOT-ID').write_text('20260901T000000Z\n')
            GATE['validate_repository_checksums'](root)
            package.unlink()
            with self.assertRaises(GATE['GateError']):
                GATE['validate_repository_checksums'](root)


if __name__ == '__main__':
    unittest.main()
