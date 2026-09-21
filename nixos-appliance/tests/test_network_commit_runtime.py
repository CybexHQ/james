"""Execute network transaction boundaries with disposable paths and fake helpers."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NetworkCommitRuntimeTests(unittest.TestCase):
    def test_pending_generation_defers_before_lock_or_network_mutation(self):
        source = (ROOT / 'runtime/cybex-james-network-change').read_text()
        for marker in ('pending-system-generation.json', 'system-prepare-intent.json',
                       'system-commit-intent.json', 'system-rollback-intent.json'):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / marker).write_text('{}')
                script = source.replace('control_dir=/var/lib/cybex-james/control', 'control_dir=' + temporary)
                # The nonexistent lock makes any fallthrough an observable failure.
                script = script.replace('lock=/run/lock/cybex-james/maintenance.lock', 'lock=' + temporary + '/absent-lock')
                result = subprocess.run(['bash', '-c', script], text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('Network change deferred', result.stderr)
                self.assertEqual([p.name for p in root.iterdir()], [marker])

    def test_precommit_failure_restores_previous_profile(self):
        self.commit_failure('absent', False)

    def test_postreceipt_failure_retains_durable_recovery(self):
        self.commit_failure('exact', True)

    def test_unrelated_committed_receipt_does_not_authorize_candidate(self):
        self.commit_failure('wrong', False)

    def commit_failure(self, receipt, committed):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            network, control, binaries = root / 'netplan', root / 'control', root / 'bin'
            for path in (network, control, binaries): path.mkdir()
            candidate = root / 'c85b4a37-b98a-4c61-b2de-b455c383dc97.yaml'; candidate.write_text('{"candidate":"acknowledged"}')
            active = network / '90-cybex-james.yaml'; active.write_text('old approved profile')
            acknowledgement = root / 'ack'; acknowledgement.write_text('signed ack fixture')
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            def helper(name, body):
                path = binaries / name; path.write_text(body); path.chmod(0o755); return str(path)
            activation = helper('activate', '#!/bin/sh\necho activated >> "$TEST_ACTIVATIONS"\n')
            verifier = helper('verify', '#!/bin/sh\nprintf "%s\\n" "$TEST_DIGEST"\n')
            commit = helper('commit', """#!/bin/sh
case "$1" in
  commit-network-change)
    test "$TEST_RECEIPT" = absent || printf '%s' "$TEST_RECEIPT" > "$TEST_RECEIPT_FILE"
    exit 1 ;;
  verify-committed-network-change)
    test "$2" = --change-id && test "$3" = c85b4a37-b98a-4c61-b2de-b455c383dc97 && test "$4" = --no-repair || exit 2
    test -f "$TEST_RECEIPT_FILE" || exit 1
    if test "$(cat "$TEST_RECEIPT_FILE")" = exact; then printf '%s\\n' "$TEST_DIGEST"; else echo wrong-digest; fi ;;
  *) exit 2 ;;
esac
""")
            helper('stat', '#!/bin/sh\ncase "$*" in *%h*) echo root:root:600:1;; *) echo root:root:600;; esac\n')
            helper('chown', '#!/bin/sh\nexit 0\n')
            helper('install', '''#!/usr/bin/env python3
import shutil,sys
args=sys.argv[1:]; paths=[]; i=0
while i<len(args):
    if args[i] in ('-m','-o','-g'): i+=2
    else: paths.append(args[i]); i+=1
shutil.copyfile(*paths)
''')
            script = (ROOT / 'runtime/cybex-james-netplan-apply').read_text()
            replacements = {'/etc/netplan': str(network), '/var/lib/cybex-james/control': str(control),
                '/usr/lib/cybex-james/cybex-james-bootstrap': commit,
                '/usr/lib/cybex-james/cybex-james-netplan-activate': activation,
                '/usr/bin/cybex-james': verifier}
            for old, new in replacements.items(): script = script.replace(old, new)
            self.assertNotIn('/usr/lib/cybex-james/', script)
            result = subprocess.run(['bash', '-c', script, 'fixture', str(candidate), str(acknowledgement)],
                env={**os.environ, 'PATH': str(binaries) + os.pathsep + os.environ['PATH'],
                     'TEST_DIGEST': digest, 'TEST_ACTIVATIONS': str(root / 'activations'),
                     'TEST_RECEIPT': receipt, 'TEST_RECEIPT_FILE': str(control / 'network-committed.json')},
                text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 73 if committed else 72, result.stderr)
            if committed:
                self.assertIn('needs durable recovery', result.stderr)
                self.assertEqual((root / 'activations').read_text(), 'activated\n')
                self.assertEqual(active.read_bytes(), candidate.read_bytes())
                self.assertEqual((control / 'netplan-before-change.yaml').read_text(), 'old approved profile')
            else:
                self.assertEqual((root / 'activations').read_text(), 'activated\nactivated\n')
                self.assertEqual(active.read_text(), 'old approved profile')
                self.assertFalse((control / 'netplan-before-change.yaml').exists())
            self.assertEqual((control / 'netplan-pending.sha256').exists(), committed)


if __name__ == '__main__': unittest.main()
