"""The release producer must preserve the frozen installed-client wire contract."""
import json
import unittest


class PackageAnchorContractTests(unittest.TestCase):
    def setUp(self):
        from test_james_release import JamesReleaseToolTests
        self.fixture = JamesReleaseToolTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def test_current_package_snapshot_keeps_seven_wire_anchors(self):
        fixture = self.fixture
        output = fixture.directory / 'release.json'
        extra, _ = fixture.network_package_arguments()
        result = fixture.run_tool(*fixture.manifest_arguments(output), *extra,
                                  '--appliance-source-revision', 'd' * 40)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        descriptor = json.loads(output.read_text())['appliance_release_v1']
        self.assertEqual(set(descriptor['required_package_versions']), {
            'cybex-james', 'cybex-james-appliance', 'cybex-james-bootstrap',
            'linux-firmware', 'linux-generic', 'nix-bin', 'python3',
        })
        metadata = json.loads((fixture.directory / 'package-snapshot.json').read_text())
        self.assertEqual(metadata['required_package_versions']['udpcast'], '20120424-2build2')
        self.assertEqual(descriptor['cybex_repository_snapshot']['sha256'], metadata['sha256'])
        self.assertEqual(descriptor['cybex_repository_snapshot']['size_bytes'], metadata['size_bytes'])
        self.assertEqual(descriptor['source_revision'], 'd' * 40)

    def test_signer_still_requires_udpcast_in_authenticated_build_inputs(self):
        fixture = self.fixture
        extra, _ = fixture.network_package_arguments()
        path = fixture.directory / 'package-snapshot.json'
        metadata = json.loads(path.read_text())
        del metadata['required_package_versions']['udpcast']
        path.write_text(json.dumps(metadata))
        result = fixture.run_tool(*fixture.manifest_arguments(fixture.directory / 'release.json'), *extra)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'appliance required package versions are invalid', result.stderr)


if __name__ == '__main__':
    unittest.main()
