"""Database setup must finish before an isolated fixture can serve its API."""
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'
spec = importlib.util.spec_from_file_location('fixture_database_tests',
                                            HELPERS / 'isolated_manage_database.py')
database = importlib.util.module_from_spec(spec)
spec.loader.exec_module(database)


class DatabaseSetupTests(unittest.TestCase):
    def setup_fixture(self, failure=None):
        events = []
        owner = mock.Mock(directory=Path('/owned/manage'))
        receipt = {'context': {'network_id': 'owned-network'}, 'peer_ipv4': '10.1.2.1',
                   'containers': {role: {'id': role + '-id', 'image': role + '-image',
                                        'uid': 10001, 'mounts': [], 'peer': None}
                                  for role in ('app', 'db')}}
        config = {'manage_checkout': '/reviewed/development', 'manage_revision': 'a' * 40}
        sql = {'provision.sql': b'\\set ON_ERROR_STOP on\n\\ir roles.sql\n\\ir privileges.sql\nGRANT selected_role TO :"runtime_login";\n',
               'roles.sql': b'CREATE ROLE selected_role NOLOGIN;',
               'privileges.sql': b'GRANT SELECT ON fixture_table TO selected_role;'}

        def read(args):
            self.assertEqual(args[:6], ['git', '-c', 'safe.directory=/reviewed/development',
                                       '-C', '/reviewed/development', 'show'])
            self.assertTrue(args[6].startswith('a' * 40 + ':deploy/manage/database-isolation/'))
            return sql[args[6].rsplit('/', 1)[1]]

        def call(*args, **kwargs):
            if args[:2] == ('container', 'wait'):
                events.append('migrate')
                return b'29\n' if failure == 'migrate' else b'0\n'
            if args[:3] == ('container', 'exec', '-i'):
                events.append('provision')
                self.assertEqual(args[3], 'db-id')
                self.assertIn('runtime_login=fixture', args)
                self.assertIn('ON_ERROR_STOP=1', args)
                self.assertNotIn(b'\\ir ', kwargs['data'])
                self.assertIn(sql['roles.sql'], kwargs['data'])
                self.assertIn(sql['privileges.sql'], kwargs['data'])
                if failure == 'provision':
                    raise ValueError('provision failed')
                return b''
            self.assertEqual(args, ('container', 'start', 'app-id'))
            events.append('start-api')
            return b''

        docker = owner.docker.return_value
        docker.call.side_effect = call
        owner.run.side_effect = read
        resources = mock.Mock()
        resources.write.side_effect = lambda *_args, **_kwargs: events.append('admit')
        if failure == 'ownership':
            docker.verify_container.side_effect = ValueError('ownership changed')
        return owner, receipt, config, resources, events, sql

    def test_exact_source_provisioning_follows_migrations_before_api_admission(self):
        owner, receipt, config, resources, events, _ = self.setup_fixture()
        database.initialize(owner, receipt, config, resources)
        self.assertEqual(events, ['migrate', 'provision', 'admit', 'start-api'])
        resources.write.assert_called_once_with(
            Path('/owned/manage/app-data/database-provisioned'), b'provisioned\n', uid=10001)
        self.assertEqual(owner.guard.call_count, 2)

    def test_failed_setup_cannot_admit_or_start_api(self):
        for failure, expected in (('ownership', []), ('migrate', ['migrate']),
                                  ('provision', ['migrate', 'provision'])):
            with self.subTest(failure=failure):
                owner, receipt, config, resources, events, _ = self.setup_fixture(failure)
                with self.assertRaises(ValueError):
                    database.initialize(owner, receipt, config, resources)
                self.assertEqual(events, expected)
                resources.write.assert_not_called()

    def test_missing_committed_includes_cannot_provision_or_start_api(self):
        owner, receipt, config, resources, events, sql = self.setup_fixture()
        sql['provision.sql'] = b'-- incomplete operator script\n'
        with self.assertRaises(ValueError):
            database.initialize(owner, receipt, config, resources)
        self.assertEqual(events, ['migrate'])
        resources.write.assert_not_called()

    def test_launch_script_migrates_once_and_checks_runtime_before_every_api_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'tiaris'
            binary.write_text(f'''#!{sys.executable}
import os, pathlib, sys
mode = ('migrate' if os.environ.get('TIARIS_MIGRATE_ONLY') == '1' else
        'verify' if os.environ.get('TIARIS_DATABASE_VERIFY_ONLY') == '1' else 'serve')
assert os.environ['TIARIS_DATABASE_MIGRATIONS'] == 'operator'
with pathlib.Path(os.environ['EVENTS']).open('a') as stream: stream.write(mode + '\\n')
sys.exit(29 if os.environ.get('FAIL') == mode else 0)
''')
            binary.chmod(0o755)
            marker = root / 'database-provisioned'
            script = 'set -eu\n' + database.APP_START.replace(
                '/opt/tiaris/bin/tiaris', shlex.quote(str(binary))).replace(database.READY, str(marker))
            for admitted, failure, expected, status in (
                    (False, '', ['migrate'], 0), (False, 'migrate', ['migrate'], 29),
                    (True, '', ['verify', 'serve'], 0), (True, 'verify', ['verify'], 29)):
                with self.subTest(admitted=admitted, failure=failure):
                    events = root / 'events'
                    events.unlink(missing_ok=True)
                    if admitted:
                        marker.touch()
                    else:
                        marker.unlink(missing_ok=True)
                    result = subprocess.run(['sh', '-c', script], check=False, capture_output=True,
                        env={**os.environ, 'EVENTS': str(events), 'FAIL': failure,
                             'TIARIS_DATABASE_MIGRATIONS': 'operator'}, timeout=10)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(events.read_text().splitlines(), expected)


if __name__ == '__main__':
    unittest.main()
