from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class QualificationPciTopologyTests(unittest.TestCase):
    def test_install_and_update_preserve_the_appliance_nic_slot(self):
        install = (ROOT / 'nixos-appliance/qualification/run-lifecycle.sh').read_text()
        update = (ROOT / 'nixos-appliance/qualification/isolated_fixture.py').read_text()
        for source in (install, update):
            with self.subTest(source=source[:40]):
                nic = source.index('virtio-net-pci,netdev=net0,id=nic0,mac=')
                watchdog = source.index('i6300esb,bus=pcie.0,addr=0x4')
                self.assertLess(nic, watchdog)
                self.assertIn('bus=pcie.0,addr=0x3', source[nic:watchdog])


if __name__ == '__main__':
    unittest.main()
