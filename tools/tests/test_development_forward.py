"""Forwarding ownership regressions; optional real-kernel tests require a fresh netns."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
F = runpy.run_path(str(ROOT / 'nixos-appliance/qualification/development_forward.py'))
SCOPE = {'owner': '01234567-89ab-4def-8123-456789abcdef',
         'bridge': 'jnq0123456789', 'subnet': '10.254.219.1/24'}


class ForwardOwnershipTests(unittest.TestCase):
    def test_special_use_destinations_are_denied_before_public_egress(self):
        rules = F['rules'](SCOPE)
        accept = next(index for index, rule in enumerate(rules)
                      if '--dports' in rule and '80,443' in rule)
        for network in ('192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24',
                        '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24'):
            with self.subTest(network=network):
                deny = next(index for index, rule in enumerate(rules)
                            if network in rule and rule[-1] == 'DROP')
                self.assertLess(deny, accept)

    def test_forwarding_commands_use_only_the_fixed_environment(self):
        completed = Mock(returncode=0, stdout=b'')
        with patch.object(F['subprocess'], 'run', return_value=completed) as run:
            self.assertEqual(F['run'](['iptables', '-S']), b'')
        run.assert_called_once_with(['iptables', '-S'], input=None, capture_output=True,
                                    check=False, env=F['COMMAND_ENV'])
        self.assertEqual(set(F['COMMAND_ENV']), {'LC_ALL', 'PATH'})

    def test_receipt_is_complete_before_atomic_no_replace_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            real_link = os.link
            def inspect_then_link(source, target, **kwargs):
                self.assertFalse(Path(target).exists())
                self.assertEqual(json.loads(Path(source).read_bytes()), F['identity'](SCOPE))
                return real_link(source, target, **kwargs)
            with patch.object(F['os'], 'link', side_effect=inspect_then_link):
                F['create_receipt'](path, SCOPE)
            F['receipt'](path, SCOPE)
            self.assertEqual(list(path.glob('.forwarding.*.tmp')), [])

    def test_second_qualification_scope_is_explicitly_refused(self):
        existing = '-N JNQF_11111111111111111111\n'
        execute = Mock(return_value=existing.encode())
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'already active'):
                F['prepare'](Path(directory), SCOPE, execute)
            self.assertFalse((Path(directory) / 'forwarding.json').exists())
        execute.assert_called_once_with(['iptables', '--wait', '10', '-S'])

    def test_existing_chain_is_never_adopted_or_modified(self):
        execute = Mock(return_value=('-P FORWARD DROP\n-N ' + F['chain'](SCOPE) + '\n').encode())
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'adopt'):
                F['prepare'](Path(directory), SCOPE, execute)
            self.assertFalse((Path(directory) / 'forwarding.json').exists())
        execute.assert_called_once_with(['iptables', '--wait', '10', '-S'])

    def test_foreign_or_public_receipt_refuses_all_network_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            receipt = path / 'forwarding.json'
            receipt.write_text(json.dumps(F['identity'](SCOPE)))
            receipt.chmod(0o644)
            execute = Mock()
            with self.assertRaisesRegex(ValueError, 'private'):
                F['verify'](path, SCOPE, execute)
            receipt.chmod(0o600)
            value = F['identity'](SCOPE)
            value['owner'] = '11111111-1111-4111-8111-111111111111'
            receipt.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'differs'):
                F['cleanup'](path, SCOPE, execute)
            execute.assert_not_called()

    def test_unreceipted_resources_cannot_be_cleaned_by_name(self):
        execute = Mock(return_value=('-N ' + F['chain'](SCOPE) + '\n').encode())
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'without an ownership receipt'):
                F['cleanup'](Path(directory), SCOPE, execute)
        self.assertEqual(execute.call_count, 1)
        self.assertNotIn('restore', execute.call_args.args[0][0])


@unittest.skipUnless(os.environ.get('CYBEX_NIXOS_NETWORK_NAMESPACE') == '1',
                     'requires an explicitly disposable root network namespace')
class ForwardKernelTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertNotEqual(os.readlink('/proc/self/ns/net'), os.readlink('/proc/1/ns/net'),
                            'refusing to change the host network namespace')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        for binary in ('iptables', 'ip6tables'):
            self.command(binary, '-P', 'FORWARD', 'DROP')
            self.command(binary, '-N', 'KEEP_UNRELATED')
            self.command(binary, '-A', 'KEEP_UNRELATED', '-j', 'RETURN')
        self.addCleanup(self.remove_unrelated)

    @staticmethod
    def command(*arguments):
        return subprocess.check_output(arguments, stderr=subprocess.STDOUT).decode()

    def remove_unrelated(self):
        for binary in ('iptables', 'ip6tables'):
            self.command(binary, '-F', 'KEEP_UNRELATED')
            self.command(binary, '-X', 'KEEP_UNRELATED')

    def assert_unrelated_preserved(self):
        for binary in ('iptables', 'ip6tables'):
            observed = self.command(binary, '-S')
            self.assertIn('-P FORWARD DROP', observed)
            self.assertIn('-A KEEP_UNRELATED -j RETURN', observed)
            self.assertNotIn('JNQF_', observed)

    def test_real_plan_canonicalization_and_idempotent_cleanup(self):
        F['prepare'](self.path, SCOPE)
        F['verify'](self.path, SCOPE)
        F['cleanup'](self.path, SCOPE)
        F['cleanup'](self.path, SCOPE)
        self.assert_unrelated_preserved()

    def test_partial_family_failure_removes_only_receipted_first_family(self):
        def execute(arguments, **kwargs):
            if arguments[0] == 'ip6tables-restore':
                raise ValueError('induced second-family failure')
            return F['run'](arguments, **kwargs)
        with self.assertRaisesRegex(ValueError, 'induced'):
            F['prepare'](self.path, SCOPE, execute)
        F['cleanup'](self.path, SCOPE)
        self.assert_unrelated_preserved()

    def test_concurrent_chain_creation_fails_atomically_without_adoption(self):
        name = F['chain'](SCOPE)
        before = []
        def execute(arguments, **kwargs):
            if arguments[0] == 'iptables-restore':
                self.command('iptables', '-N', name)
                self.command('iptables', '-A', name, '-j', 'ACCEPT')
                before.append(self.command('iptables', '-S'))
            return F['run'](arguments, **kwargs)
        with self.assertRaisesRegex(ValueError, 'command failed'):
            F['prepare'](self.path, SCOPE, execute)
        self.assertEqual(before, [self.command('iptables', '-S')])
        with self.assertRaisesRegex(ValueError, 'ownership or contents'):
            F['cleanup'](self.path, SCOPE)
        self.assertEqual(before, [self.command('iptables', '-S')])
        self.command('iptables', '-F', name)
        self.command('iptables', '-X', name)
        self.assert_unrelated_preserved()

    def test_changed_rules_refuse_cleanup_before_any_mutation(self):
        F['prepare'](self.path, SCOPE)
        name = F['chain'](SCOPE)
        self.command('iptables', '-I', name, '1', '-j', 'ACCEPT')
        before = [self.command(binary, '-S') for binary in ('iptables', 'ip6tables')]
        with self.assertRaisesRegex(ValueError, 'ownership or contents'):
            F['cleanup'](self.path, SCOPE)
        self.assertEqual(before, [self.command(binary, '-S') for binary in ('iptables', 'ip6tables')])
        self.command('iptables', '-D', name, '-j', 'ACCEPT')
        F['cleanup'](self.path, SCOPE)
        self.assert_unrelated_preserved()

    def test_concurrent_foreign_append_aborts_cleanup_without_deleting_it(self):
        F['prepare'](self.path, SCOPE)
        name = F['chain'](SCOPE)
        before = []
        def execute(arguments, **kwargs):
            if arguments[0] == 'iptables-restore':
                self.command('iptables', '-A', name, '-s', '198.51.100.7', '-j', 'ACCEPT')
                before.append(self.command('iptables', '-S'))
            return F['run'](arguments, **kwargs)
        with self.assertRaisesRegex(ValueError, 'command failed'):
            F['cleanup'](self.path, SCOPE, execute)
        self.assertEqual(before, [self.command('iptables', '-S')])
        self.command('iptables', '-D', name, '-s', '198.51.100.7', '-j', 'ACCEPT')
        F['cleanup'](self.path, SCOPE)
        self.assert_unrelated_preserved()

    def test_changed_priority_fails_verification_but_can_clean_exact_owned_rules(self):
        F['prepare'](self.path, SCOPE)
        self.command('iptables', '-I', 'FORWARD', '1', '-j', 'DROP')
        with self.assertRaisesRegex(ValueError, 'precedes'):
            F['verify'](self.path, SCOPE)
        F['cleanup'](self.path, SCOPE)
        self.assertIn('-A FORWARD -j DROP', self.command('iptables', '-S'))
        self.command('iptables', '-D', 'FORWARD', '-j', 'DROP')
        self.assert_unrelated_preserved()


if __name__ == '__main__':
    unittest.main()
