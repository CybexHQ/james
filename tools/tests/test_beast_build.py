import importlib.util
from pathlib import Path
import unittest
import shutil
import subprocess
import tempfile

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
                                   'CYBEX_JAMES_UBUNTU_SNAPSHOT_ID': 'retired-snapshot',
                                   'CYBEX_JAMES_BUILD_MANAGE_ORIGIN': 'https://manage.cybex.net'})
        text = ' '.join(args)
        for value in ('secret-token', 'secret-aws', 'secret-signing-key', '/var/run/docker.sock',
                      '--privileged', '--network=host', 'src=/nix,', 'retired-snapshot'):
            self.assertNotIn(value, text)
        self.assertIn('--cap-drop=ALL', args)
        self.assertIn('--security-opt=no-new-privileges', args)
        self.assertIn('--memory-swap=48g', args)
        self.assertIn('type=bind,src=/dedicated/nix,dst=/nix', args)
        self.assertIn('CYBEX_JAMES_BUILD_MANAGE_ORIGIN=https://manage.cybex.net', args)


    def test_readonly_nix_tree_copy_is_disposable_without_changing_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / 'source', root / 'copy'
            (source / 'cache').mkdir(parents=True)
            (source / 'cache' / 'input').write_bytes(b'public cache bytes')
            (source / 'cache').chmod(0o555)
            source.chmod(0o555)
            try:
                builder.copy_disposable_tree(source, destination)
                self.assertEqual((destination / 'cache' / 'input').read_bytes(), b'public cache bytes')
                self.assertEqual((source / 'cache').stat().st_mode & 0o777, 0o555)
                self.assertEqual((destination / 'cache').stat().st_mode & 0o700, 0o700)
                shutil.rmtree(destination)
                self.assertFalse(destination.exists())
            finally:
                source.chmod(0o700)
                (source / 'cache').chmod(0o700)

    def test_origin_admission_is_exact_for_https_and_ssh(self):
        for repository in ('james', 'development'):
            for base in ('https://github.com/CybexHQ/', 'git@github.com:CybexHQ/',
                         'ssh://git@github.com/CybexHQ/'):
                for suffix in ('', '.git'):
                    with self.subTest(base=base, repository=repository, suffix=suffix):
                        self.assertEqual(builder.canonical_origin(base + repository + suffix),
                                         'https://github.com/CybexHQ/' + repository)
        for origin in ('git@github.com:CybexHQ/manage.git',
                       'https://github.com/CybexHQ/development/extra',
                       'https://github.com.evil/CybexHQ/development',
                       'ssh://git@github.com:2222/CybexHQ/development',
                       'https://token@github.com/CybexHQ/development'):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                builder.canonical_origin(origin)

    def test_isolated_checkout_retains_exact_revision_and_authorized_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / 'source', root / 'target'
            subprocess.run(['git', 'init', '-q', str(source)], check=True)
            subprocess.run(['git', '-C', str(source), 'remote', 'add', 'origin',
                            'git@github.com:CybexHQ/development.git'], check=True)
            (source / 'input').write_text('committed public input')
            subprocess.run(['git', '-C', str(source), 'add', 'input'], check=True)
            subprocess.run(['git', '-C', str(source), '-c', 'user.name=Fixture',
                            '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], check=True)
            (source / 'private-untracked').write_text('never copied')
            builder.checkout(source, target)
            self.assertEqual((target / 'input').read_text(), 'committed public input')
            self.assertFalse((target / 'private-untracked').exists())
            self.assertEqual(subprocess.check_output(['git', '-C', str(target), 'remote', 'get-url', 'origin'],
                                                    text=True).strip(), 'https://github.com/CybexHQ/development')
            self.assertEqual(subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD']),
                             subprocess.check_output(['git', '-C', str(target), 'rev-parse', 'HEAD']))
            subprocess.run(['git', '-C', str(source), 'remote', 'set-url', 'origin',
                            'https://github.com/CybexHQ/manage'], check=True)
            with self.assertRaisesRegex(ValueError, 'development source origins'):
                builder.checkout(source, root / 'forbidden')
            self.assertFalse((root / 'forbidden').exists())


if __name__ == '__main__':
    unittest.main()
