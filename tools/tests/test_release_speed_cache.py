"""Synthetic transport only: network and full archive verifier are injected fakes."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

BEAST = Path(__file__).resolve().parents[2] / 'release/beast'
sys.path.insert(0, str(BEAST))
import release_speed_cache as C
import release_speed_io as I


class Verifier:
    MANIFEST = 'cybex-james-release.json'
    COMPATIBILITY = 'cybex-james-release-compatibility.json'
    canonical = staticmethod(I.canonical)

    def __init__(self):
        self.calls = []
        self.blobs = {'closure.tar.zst': b'closure', 'installer.iso': b'iso', 'workstation.tar.zst': b'workstation'}
        self.ancestry = {'schema': 'published', 'manifest_sha256': 'a' * 64}

    def resolve(self, *args):
        self.calls.append('resolve')
        return self.ancestry

    def advance(self, candidate, previous):
        if candidate <= previous:
            raise ValueError('older candidate')

    def verify_pair_snapshot(self, directory, key):
        self.calls.append('authenticate')
        manifest = I.read(directory / self.MANIFEST)
        compatibility = I.read(directory / self.COMPATIBILITY)
        if key != 'test-public-key' or json.loads(compatibility)['manifest_sha256'] != I.digest(manifest):
            raise ValueError('unauthenticated')
        return {'manifest': json.loads(manifest), 'manifest_body': manifest,
                'compatibility': json.loads(compatibility), 'compatibility_body': compatibility}

    def fetch(self, url, path, sha, size):
        self.calls.append('fetch')
        if not path.exists():
            I.write(path, self.blobs[path.name])
        if I.digest(I.read(path)) != sha or len(I.read(path)) != size:
            raise ValueError('corrupt')

    def qualify(self, directory, version, key):
        self.calls.append('qualify')
        snap = self.verify_pair_snapshot(directory, key)
        manifest = snap['manifest']
        for field, digest in [('system_closure', 'sha256'), ('installer_iso_template_v3', 'template_sha256')]:
            value = manifest['appliance_release_v1'][field] if field == 'system_closure' else manifest[field]
            self.fetch(value['url'], directory / value['url'].rsplit('/', 1)[1], value[digest], value['size_bytes'])
        return {'schema': 'cybex.james.nixos-qualification-predecessor.v1', 'manifest_sha256': I.digest(snap['manifest_body'])}


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir(mode=0o700)
        source = self.root / 'input'
        source.mkdir(mode=0o700)
        self.p = Verifier()
        def artifact(name, field='sha256'):
            body = self.p.blobs[name]
            return {'url': 'https://releases.test/' + name, field: I.digest(body), 'size_bytes': len(body)}
        self.manifest = {'version': '1.0.0', 'appliance_release_v1': {
            'system_closure': artifact('closure.tar.zst'), 'source_revision': 'a' * 40,
            'manage_source_revision': 'b' * 40, 'nixpkgs_revision': 'c' * 40,
            'system_toplevel': '/nix/store/test', 'sqlite_migrations_sha256': 'd' * 64},
            'installer_iso_template_v3': artifact('installer.iso', 'template_sha256'),
            'workstation_netboot': artifact('workstation.tar.zst')}
        I.write(source / self.p.MANIFEST, I.canonical(self.manifest))
        I.write(source / self.p.COMPATIBILITY, I.canonical({'manifest_sha256': I.digest(I.canonical(self.manifest))}))
        I.write(self.root / 'expected.json', I.canonical(self.p.ancestry))
        I.write(self.root / 'authorization.json', b'{}')
        self.args = SimpleNamespace(mode='github-warm', cache_root=self.cache, directory=self.root / 'output',
            predecessor_dir=source, repository='example/project', candidate_version='2.0.0', trusted_public_key='test-public-key',
            authorization=self.root / 'authorization.json', expected_identity=self.root / 'expected.json',
            predecessor_manifest_sha256=I.digest(I.canonical(self.manifest)), max_bytes=16384)
        self.source = patch.object(C, 'source_digest', return_value='e' * 64)
        self.source.start()
        self.addCleanup(self.source.stop)

    def entries(self):
        return [p for p in self.cache.iterdir() if len(p.name) == 64]

    def test_hit_reauthenticates_and_requalifies_bytes_without_hardlinks(self):
        self.assertEqual(C.warm(self.args, self.p)['cache'], 'miss')
        self.args.directory = self.root / 'second'
        self.assertEqual(C.warm(self.args, self.p)['cache'], 'hit')
        self.assertEqual(self.p.calls.count('resolve'), 2)
        self.assertEqual(self.p.calls.count('qualify'), 2)
        entry = self.entries()[0]
        for name in self.p.blobs:
            self.assertNotEqual((entry / name).stat().st_ino, (self.args.directory / name).stat().st_ino)
            self.assertEqual((entry / name).stat().st_nlink, 1)
            self.assertEqual((self.args.directory / name).stat().st_mode & 0o777, 0o400)
        self.assertEqual(len(list(self.args.directory.iterdir())), 6)

    def test_corruption_cannot_fall_through_to_stale_fetch_skip(self):
        C.warm(self.args, self.p)
        blob = self.entries()[0] / 'installer.iso'
        blob.chmod(0o600)
        blob.write_bytes(b'bad')
        self.args.directory = self.root / 'second'
        before = self.p.calls.count('qualify')
        with self.assertRaises(ValueError):
            C.warm(self.args, self.p)
        self.assertFalse(self.args.directory.exists())
        self.assertEqual(self.p.calls.count('qualify'), before)

    def test_ancestry_always_fresh_and_exact(self):
        C.warm(self.args, self.p)
        self.args.directory = self.root / 'second'
        self.p.ancestry = {'changed': True}
        with self.assertRaisesRegex(ValueError, 'ancestry'):
            C.warm(self.args, self.p)
        self.assertEqual(self.p.calls.count('resolve'), 2)

    def test_trust_failure_and_offline_refusal_do_not_fetch(self):
        self.args.trusted_public_key = 'wrong'
        with self.assertRaises(ValueError):
            C.warm(self.args, self.p)
        self.assertNotIn('fetch', self.p.calls)
        self.p.calls.clear()
        self.args.mode = 'candidate-only'
        with self.assertRaisesRegex(ValueError, 'no-fetch'):
            C.warm(self.args, self.p)
        self.assertEqual(self.p.calls, [])

    def test_source_and_policy_invalidate_and_eviction_is_bounded(self):
        C.warm(self.args, self.p)
        first = self.entries()[0]
        self.args.directory = self.root / 'second'
        with patch.object(C, 'source_digest', return_value='f' * 64):
            self.assertEqual(C.warm(self.args, self.p)['cache'], 'miss')
        self.args.authorization.write_bytes(b'{"changed":true}')
        self.args.directory = self.root / 'third'
        self.assertEqual(C.warm(self.args, self.p)['cache'], 'miss')
        self.assertEqual(len(self.entries()), 2)
        self.assertFalse(first.exists())
        self.assertTrue((self.root / 'output/installer.iso').exists())

    def test_signature_or_descriptor_change_cannot_reuse_old_key(self):
        C.warm(self.args, self.p)
        self.args.directory = self.root / 'second'
        self.manifest['appliance_release_v1']['source_revision'] = 'f' * 40
        path = self.args.predecessor_dir / self.p.MANIFEST
        path.write_bytes(I.canonical(self.manifest))
        with self.assertRaises(ValueError):
            C.warm(self.args, self.p)
        self.args.predecessor_manifest_sha256 = I.digest(path.read_bytes())
        with self.assertRaises(ValueError):
            C.warm(self.args, self.p)
        (self.args.predecessor_dir / self.p.COMPATIBILITY).write_bytes(I.canonical({'manifest_sha256': I.digest(path.read_bytes())}))
        self.assertEqual(C.warm(self.args, self.p)['cache'], 'miss')

    def test_two_writers_and_reader_publish_complete_distinct_snapshots(self):
        args = [SimpleNamespace(**vars(self.args) | {'directory': self.root / ('output' + str(i))}) for i in range(3)]
        with ThreadPoolExecutor(max_workers=3) as workers:
            results = list(workers.map(lambda arg: C.warm(arg, self.p), args))
        self.assertEqual(sorted(v['cache'] for v in results), ['hit', 'hit', 'miss'])
        self.assertEqual(len(self.entries()), 1)
        for arg in args:
            self.assertEqual((arg.directory / 'installer.iso').read_bytes(), b'iso')

    def test_failed_transfer_publishes_nothing(self):
        with patch.object(self.p, 'qualify', side_effect=ValueError('invalid archive')):
            with self.assertRaises(ValueError):
                C.warm(self.args, self.p)
        self.assertEqual(self.entries(), [])
        self.assertFalse(self.args.directory.exists())
        self.assertEqual([p.name for p in self.cache.iterdir()], ['cache.lock'])

    def test_symlink_hardlink_and_incomplete_stage_refused(self):
        (self.cache / '.stage-abandoned').mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            C.warm(self.args, self.p)
        (self.cache / '.stage-abandoned').rmdir()
        metadata = self.args.predecessor_dir / self.p.MANIFEST
        original = self.root / 'original'
        metadata.rename(original)
        metadata.symlink_to(original)
        with self.assertRaises(OSError):
            C.warm(self.args, self.p)
        metadata.unlink()
        import os
        os.link(original, metadata)
        with self.assertRaises(ValueError):
            C.warm(self.args, self.p)

    def test_output_atomic_no_replace(self):
        first = self.root / 'first'
        second = self.root / 'second'
        first.mkdir(mode=0o700)
        second.mkdir(mode=0o700)
        with self.assertRaises(OSError):
            I.publish(first, second)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())


if __name__ == '__main__':
    unittest.main()
