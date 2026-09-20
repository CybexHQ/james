import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('builder', ROOT / 'tools/beast-build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BuildIsolationTests(unittest.TestCase):
    def test_only_public_inputs_and_dedicated_directories_cross_boundary(self):
        args = builder.command('sha256:image', 'owned-container', '/private/source', '/private/scratch',
                               '/private/output', Path('/dedicated'), {
                                   'GH_TOKEN': 'secret-token', 'AWS_SECRET_ACCESS_KEY': 'secret-aws',
                                   'CYBEX_JAMES_RELEASE_PRIVATE_KEY_B64': 'secret-signing-key',
                                   'CYBEX_JAMES_BUILD_MANAGE_ORIGIN': 'https://manage.cybex.net'})
        text = ' '.join(args)
        for value in ('secret-token', 'secret-aws', 'secret-signing-key', '/var/run/docker.sock',
                      '--privileged', '--network=host', 'src=/nix,'):
            self.assertNotIn(value, text)
        self.assertIn('--cap-drop=ALL', args)
        self.assertIn('--security-opt=no-new-privileges', args)
        self.assertIn('--memory-swap=48g', args)
        self.assertIn('type=bind,src=/dedicated/nix,dst=/nix', args)
        self.assertIn('CYBEX_JAMES_BUILD_MANAGE_ORIGIN=https://manage.cybex.net', args)


if __name__ == '__main__':
    unittest.main()
