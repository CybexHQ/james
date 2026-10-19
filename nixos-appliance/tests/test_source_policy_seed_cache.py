"""Real Nix regression for signed appliance seeds in an isolated preflight.

Only runs in the disposable CI guest: its daemon owns the temporary build and
the test key never leaves TemporaryDirectory. No source policy is relaxed.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid


@unittest.skipUnless(os.environ.get('CI') == 'true', 'requires disposable Nix CI guest')
class SignedSeedCacheTests(unittest.TestCase):
    def run_command(self, *args):
        return subprocess.run(args, check=True, text=True, capture_output=True, timeout=600).stdout

    def test_only_signed_daemon_outputs_satisfy_isolated_preflight(self):
        pin = json.loads(self.run_command(
            'nix-instantiate', '--eval', '--strict', '--json', 'release/nixpkgs.nix'))
        with tempfile.TemporaryDirectory(prefix='signed-seed-contract-') as temporary:
            root = Path(temporary)
            fixture = root / 'fixture'
            fixture.mkdir()
            nonce = uuid.uuid4().hex
            (fixture / 'flake.nix').write_text('''{
              outputs = { self }: let
                nixpkgs = builtins.fetchTarball %s;
                pkgs = import nixpkgs { system = "x86_64-linux"; };
              in { packages.x86_64-linux.seed =
                pkgs.runCommand "source-policy-seed-%s" { }
                  "printf '%%s' '%s' > $out"; };
            }''' % ('{ url = %s; sha256 = %s; }' %
                     (json.dumps(pin['url']), json.dumps(pin['sha256'])), nonce, nonce))
            installable = f'{fixture}#seed'
            built = json.loads(self.run_command('nix', '--extra-experimental-features',
                'nix-command flakes', 'build', '--no-link', '--json', installable))[0]
            seed = built['outputs']['out']
            secret = self.run_command('nix', '--extra-experimental-features', 'nix-command',
                'key', 'generate-secret', '--key-name', 'tiaris-nest-appliance-1')
            key = root / 'key'
            key.write_text(secret)
            key.chmod(0o600)
            public = subprocess.run(['nix', '--extra-experimental-features', 'nix-command',
                'key', 'convert-secret-to-public'], input=secret, text=True,
                capture_output=True, check=True, timeout=30).stdout.strip()

            def preflight():
                return subprocess.run(['cargo', 'test', '--locked',
                    'source_policy_qualifies_cache_only_installable', '--', '--ignored', '--nocapture'],
                    env={**os.environ, 'TIARIS_SOURCE_POLICY_INSTALLABLE': installable,
                         'TIARIS_SOURCE_POLICY_RELEASE_KEY': public.split(':', 1)[1]},
                    text=True, capture_output=True, timeout=600)

            # A daemon build is marked ultimate locally, but that must not
            # grant an unsigned path trust in the isolated verification store.
            unsigned = preflight()
            self.assertNotEqual(unsigned.returncode, 0, unsigned.stdout + unsigned.stderr)
            self.assertIn(f'source-policy-seed-{nonce}', unsigned.stdout + unsigned.stderr)
            self.run_command('sudo', '-n', 'nix', '--extra-experimental-features',
                'nix-command', 'store', 'sign', '--key-file', str(key), seed)
            signed = preflight()
            self.assertEqual(signed.returncode, 0, signed.stdout + signed.stderr)
