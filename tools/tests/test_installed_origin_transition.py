import base64
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
LOADER = SourceFileLoader('origin_transition', str(ROOT / 'ubuntu-appliance/rootfs/usr/lib/cybex-james/cybex-james-origin-transition'))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
transition = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(transition)
SOURCE = 'https://dev.cybex.net'
TARGET = 'https://manage.cybex.net'

class InstalledOriginTransitionTests(unittest.TestCase):
    def prepare(self, root):
        control = root / 'var/lib/cybex-james/control'
        share = root / 'usr/share/cybex-james'
        staging = control / 'origin-transitions/0.2.1-dev.26'
        receipt = control / 'appliance-updates/0.2.1-dev.26/verified-update.json'
        for path in (staging, receipt.parent, share, root / 'etc/cybex-james'):
            path.mkdir(parents=True, exist_ok=True)
        key = root / 'key.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)], check=True, capture_output=True)
        der = subprocess.check_output(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'])
        public = base64.b64encode(der[-32:]).decode()
        (share / 'release-public-key').write_text(public + '\n')
        (root / 'etc/cybex-james/config.toml').write_text('[manage]\napi_url = "' + TARGET + '"\n')
        plan = {'schema': 'fixture-plan', 'session_id': 'unchanged-session', 'signature': 'unchanged-signature'}
        state = {'manage_origin': SOURCE, 'identity_active': True, 'installation_complete': True,
                 'plan': plan, 'device_private_key_b64': 'unchanged-device-identity', 'next_event_sequence': 9}
        def save(path, value):
            path.write_bytes(transition.canonical(value))
        save(control / 'provisioning-state.json', state)
        (control / 'provisioning-state.json').chmod(0o640)
        save(control / 'install-plan.json', plan)
        save(control / 'appliance-release.json', {'appliance_release': '0.2.1-dev.21'})
        save(share / 'appliance-release.json', {'release_id': '0.2.1-dev.26'})
        manifest = {'version': '0.2.1-dev.26', 'installer_iso_template_v2': {'manage_origin': TARGET},
                    'appliance_release_v1': {'release_id': '0.2.1-dev.26', 'source_revision': 'a' * 40,
                                             'cybex_repository_snapshot': {'sha256': 'b' * 64}}}
        save(staging / 'manifest.json', manifest)
        save(receipt, {'schema': 'cybex.james.verified-appliance-update.v1', 'target_release': '0.2.1-dev.26',
                       'source_revision': 'a' * 40, 'package_snapshot_sha256': 'b' * 64})
        payload = {'schema': 'cybex.james.origin-transition.v1', 'public_key': public, 'reason': 'fixture transition',
                   'source': {'manage_origin': SOURCE, 'release_version': '0.2.1-dev.21'},
                   'target': {'manage_origin': TARGET, 'release_version': '0.2.1-dev.26',
                              'manifest': {'sha256': hashlib.sha256((staging / 'manifest.json').read_bytes()).hexdigest()}}}
        message = root / 'message'; message.write_bytes(transition.DOMAIN + transition.canonical(payload))
        sig = subprocess.check_output(['openssl', 'pkeyutl', '-sign', '-inkey', str(key), '-rawin', '-in', str(message)])
        save(staging / 'authorization.json', {**payload, 'signature': base64.b64encode(sig).decode()})
        return control, staging, receipt

    def test_signed_transition_preserves_plan_identity_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); control, _, _ = self.prepare(root)
            before = (control / 'provisioning-state.json').read_bytes()
            plan = (control / 'install-plan.json').read_bytes()
            self.assertTrue(transition.transition(root, TARGET))
            after = json.loads((control / 'provisioning-state.json').read_bytes())
            after['manage_origin'] = SOURCE
            self.assertEqual(after, json.loads(before))
            self.assertEqual((control / 'install-plan.json').read_bytes(), plan)
            self.assertEqual((control / 'provisioning-state.before-0.2.1-dev.26.json').read_bytes(), before)
            self.assertEqual((control / 'provisioning-state.json').stat().st_mode & 0o777, 0o640)
            self.assertFalse(transition.transition(root, TARGET))

    def test_changed_authority_manifest_receipt_predecessor_or_plan_is_rejected(self):
        for kind in ('signature', 'manifest', 'receipt', 'predecessor', 'plan', 'config'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); control, staging, receipt = self.prepare(root)
                before = (control / 'provisioning-state.json').read_bytes()
                path = {'signature': staging / 'authorization.json', 'manifest': staging / 'manifest.json',
                        'receipt': receipt, 'predecessor': control / 'appliance-release.json',
                        'plan': control / 'install-plan.json', 'config': root / 'etc/cybex-james/config.toml'}[kind]
                if kind == 'config':
                    path.write_text('[manage]\napi_url = "' + SOURCE + '"\n')
                else:
                    value = json.loads(path.read_bytes())
                    key, changed = {'signature': ('reason', 'tampered'), 'manifest': ('version', 'wrong'),
                                    'receipt': ('package_snapshot_sha256', 'c' * 64),
                                    'predecessor': ('appliance_release', '0.2.1-dev.17'),
                                    'plan': ('signature', 'tampered')}.get(kind, ('', ''))
                    value[key] = changed; path.write_bytes(transition.canonical(value))
                with self.assertRaises(ValueError): transition.transition(root, TARGET)
                self.assertEqual((control / 'provisioning-state.json').read_bytes(), before)

    def test_fresh_install_has_no_origin_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(transition.transition(Path(directory), TARGET))

    def test_untrusted_input_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); control, staging, _ = self.prepare(root)
            path = staging / 'authorization.json'; path.chmod(0o666)
            with self.assertRaises(ValueError): transition.transition(root, TARGET)
            self.assertEqual(json.loads((control / 'provisioning-state.json').read_bytes())['manage_origin'], SOURCE)

if __name__ == '__main__': unittest.main()
