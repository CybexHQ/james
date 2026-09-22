import importlib.util
from pathlib import Path
import subprocess
import unittest

path = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification/ssh_certificate.py'
spec = importlib.util.spec_from_file_location('ssh_certificate', path)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class CertificateTests(unittest.TestCase):
    def observe(self, accept_after, expires=300, error=b'Permission denied (publickey).', code=255):
        self.now, self.attempts = 0, []
        def run(command, **options):
            self.attempts.append((self.now, command, options['timeout']))
            return subprocess.CompletedProcess(command, 0 if self.now >= accept_after else code,
                                               b'', error)
        def sleep(seconds):
            self.now += seconds
        return helper.login(['ssh', 'owned-fixture'], expires, run=run,
                            clock=lambda: self.now, wall=lambda: self.now, sleep=sleep)

    def test_waits_for_observed_acceptance_with_same_command(self):
        self.assertEqual(self.observe(2).returncode, 0)
        self.assertEqual(self.now, 3)
        self.assertEqual(len(self.attempts), 2)
        self.assertTrue(all(command == ['ssh', 'owned-fixture'] for _, command, _ in self.attempts))

    def test_invalid_certificate_stays_rejected_at_deadline(self):
        with self.assertRaises(ValueError):
            self.observe(100)
        self.assertEqual(self.now, 3)
        self.assertEqual(len(self.attempts), 2)

    def test_expiry_bounds_attempts_and_transport_timeout(self):
        with self.assertRaises(ValueError):
            self.observe(2, expires=1)
        self.assertEqual(self.now, 1)
        self.assertTrue(all(at + timeout <= 1 for at, _, timeout in self.attempts))
        with self.assertRaises(ValueError):
            self.observe(0, expires=0)
        self.assertEqual(self.attempts, [])

    def test_transport_and_remote_command_failures_are_not_retried(self):
        for code, error in [(255, b'Connection refused'), (1, b'Permission denied (publickey).')]:
            with self.subTest(code=code), self.assertRaises(ValueError):
                self.observe(2, code=code, error=error)
            self.assertEqual(len(self.attempts), 1)


if __name__ == '__main__':
    unittest.main()
