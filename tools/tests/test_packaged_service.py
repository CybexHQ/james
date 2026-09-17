import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
LOADER = SourceFileLoader("packaged_service", str(ROOT / "ubuntu-appliance/rootfs/usr/lib/cybex-james/cybex-james-packaged-service"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
service = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(service)


class PackagedServiceTests(unittest.TestCase):
    def fixture(self, root):
        relative = "opt/cybex-james-dev/verification-fix-20260914/cybex-james"
        binary = root / relative
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"known development binary fixture")
        override = root / "etc/systemd/system/cybex-james.service.d/90-verification-fix.conf"
        override.parent.mkdir(parents=True)
        content = f"[Service]\nExecStart=\nExecStart=/{relative} --config /etc/cybex-james/config.toml serve\n".encode()
        override.write_bytes(content)
        identity = hashlib.sha256(content).hexdigest()
        self.assertIn(identity, service.KNOWN)
        return override, binary, {identity: (relative, {hashlib.sha256(binary.read_bytes()).hexdigest()})}

    def test_only_known_override_and_binary_are_retired(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            override, binary, known = self.fixture(root)
            content = override.read_bytes()
            with patch.object(service, "KNOWN", known):
                self.assertTrue(service.retire(root))
                self.assertFalse(service.retire(root))
            self.assertFalse(override.exists())
            self.assertEqual(override.with_suffix(".conf.retired").read_bytes(), content)
            self.assertTrue(binary.exists())

    def test_custom_override_or_binary_is_preserved(self):
        for modify_binary in [False, True]:
            with self.subTest(modify_binary=modify_binary), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                override, binary, known = self.fixture(root)
                target = binary if modify_binary else override
                target.write_bytes(target.read_bytes() + b"operator change\n")
                content = override.read_bytes()
                with patch.object(service, "KNOWN", known):
                    self.assertFalse(service.retire(root))
                self.assertEqual(override.read_bytes(), content)

    def test_conflicting_archive_does_not_remove_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            override, _, known = self.fixture(root)
            override.with_suffix(".conf.retired").write_bytes(b"other evidence")
            with patch.object(service, "KNOWN", known), self.assertRaises(ValueError):
                service.retire(root)
            self.assertTrue(override.exists())

    def test_override_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            override, binary, known = self.fixture(root)
            override.unlink()
            override.symlink_to(binary)
            with patch.object(service, "KNOWN", known), self.assertRaises(ValueError):
                service.retire(root)
            self.assertTrue(binary.exists())

    def test_postinst_adopts_packaged_service_before_reloading_systemd(self):
        source = (ROOT / "ubuntu-appliance/package/cybex-james-appliance.postinst").read_text()
        self.assertLess(source.index("/usr/lib/cybex-james/cybex-james-packaged-service"),
                        source.index("systemctl daemon-reload"))

    def test_older_pxe_layers_cannot_resurface_after_retiring_newer_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            verification, _, known = self.fixture(root)
            binary = root / 'opt/cybex-pxe-dev/cybex-james'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'old pxe binary fixture')
            asset = binary.with_name('autoexec.ipxe'); asset.write_bytes(b'#!ipxe\nfixture\n')
            texts = [
                '[Service]\nExecStart=\nExecStart=/opt/cybex-pxe-dev/cybex-james --config /etc/cybex-james/config.toml serve\nBindReadOnlyPaths=/opt/cybex-pxe-dev/autoexec.ipxe:/usr/share/cybex-james/autoexec.ipxe\n',
                '[Service]\nExecStartPost=/usr/bin/install -m 0644 /opt/cybex-pxe-dev/autoexec.ipxe /var/cache/cybex-james/tftp/autoexec.ipxe\n',
            ]
            rules = {}
            overrides = []
            for (relative, (identity, files)), text in zip(service.PXE.items(), texts):
                self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), identity)
                override = root / relative; override.parent.mkdir(parents=True, exist_ok=True)
                override.write_text(text); overrides.append(override)
                rules[relative] = (identity, {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in files})
            with patch.object(service, 'KNOWN', known), patch.object(service, 'PXE', rules):
                self.assertTrue(service.retire(root))
                self.assertFalse(service.retire(root))
            for override in [verification, *overrides]:
                self.assertFalse(override.exists())
                self.assertTrue(override.with_suffix('.conf.retired').is_file())

    def test_modified_pxe_asset_keeps_its_operator_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = 'etc/systemd/system/cybex-james-first-boot.service.d/90-pxe-dev.conf'
            text = '[Service]\nExecStartPost=/usr/bin/install -m 0644 /opt/cybex-pxe-dev/autoexec.ipxe /var/cache/cybex-james/tftp/autoexec.ipxe\n'
            override = root / relative; override.parent.mkdir(parents=True); override.write_text(text)
            asset = root / 'opt/cybex-pxe-dev/autoexec.ipxe'; asset.parent.mkdir(parents=True)
            asset.write_text('operator replacement')
            self.assertFalse(service.retire(root))
            self.assertTrue(override.exists())


if __name__ == "__main__":
    unittest.main()
