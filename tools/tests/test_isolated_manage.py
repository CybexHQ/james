"""No Docker/Incus commands: fixture authority tests and generated local TLS only."""
import base64
import contextlib
import copy
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import types
import unittest
from unittest import mock
import uuid

HELPERS = Path(__file__).resolve().parents[2] / 'nixos-appliance/qualification'
spec = importlib.util.spec_from_file_location('nixos_isolated_manage_owner_tests', HELPERS / 'isolated_manage.py')
owner_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner_module)
config = owner_module.inputs
resources = owner_module.resources
transport = owner_module.transport


def configuration():
    return {'schema': config.SCHEMA, 'manage_origin': 'https://dev.example.test',
            'manage_checkout': '/reviewed/development', 'manage_revision': 'a' * 40,
            'app_image': 'sha256:' + 'a' * 64, 'postgres_image': 'sha256:' + 'b' * 64,
            'tls_image': 'sha256:' + 'c' * 64, 'backend_subnet': '10.99.17.0/28',
            'tls_certificate': '/private/tls.crt', 'tls_private_key': '/private/tls.key',
            'provisioning_seed_file': '/private/seed', 'release_public_key': base64.b64encode(b'k' * 32).decode(),
            'egress_hosts': ['cache.nixos.org', 'github.com'], 'initial_release': 'predecessor'}


def receipt():
    return {'manage_origin': 'https://dev.example.test', 'peer_ipv4': '10.99.16.1',
            'certificate_sha256': 'a' * 64, 'challenge': 'b' * 64,
            'owner': '20dcb130-736e-4d79-b8d2-338781735419'}


class InputTests(unittest.TestCase):
    def test_closed_configuration_and_canonical_origin(self):
        self.assertEqual(config.validate(configuration()), configuration())
        for field, value in [('app_image', 'cybex/manage:latest'), ('manage_revision', 'main'),
                              ('backend_subnet', '8.8.8.0/28'), ('backend_subnet', '127.0.0.0/28'),
                              ('manage_origin', 'https://dev.example.test:443'),
                              ('manage_origin', 'https://dev.example.test/path'),
                              ('manage_origin', 'https://user@dev.example.test'),
                              ('egress_hosts', ['dev.example.test']), ('egress_hosts', ['127.0.0.1']),
                              ('egress_hosts', ['*.github.com']), ('egress_hosts', ['github.com', 'github.com']),
                              ('initial_release', 'latest'), ('release_public_key', 'not-base64')]:
            with self.subTest(field=field, value=value), self.assertRaises((ValueError, TypeError)):
                config.validate(configuration() | {field: value})
        with self.assertRaises(ValueError):
            config.validate(configuration() | {'env_file': '/etc/production.env'})

    def test_private_files_reject_symlinks_hardlinks_and_public_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'config.json'
            path.write_bytes(b'{}')
            path.chmod(0o600)
            self.assertEqual(config.read_file(path, uid=os.geteuid()), b'{}')
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                config.read_file(path, uid=os.geteuid())
            path.chmod(0o600)
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                config.read_file(link, uid=os.geteuid())
            link.unlink()
            os.link(path, link)
            with self.assertRaises(ValueError):
                config.read_file(path, uid=os.geteuid())

    def test_production_source_rejected_before_git_or_resolve(self):
        runner = mock.Mock()
        with mock.patch.object(Path, 'resolve', side_effect=AssertionError('must not access production')):
            with self.assertRaises(ValueError):
                config.check_source(configuration() | {'manage_checkout': str(config.PRODUCTION)}, runner)
        runner.assert_not_called()

    def test_source_requires_development_remote_exact_clean_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            settings = configuration() | {'manage_checkout': temporary}
            runner = mock.Mock(side_effect=[config.SOURCE.encode(), b'a' * 40, b''])
            config.check_source(settings, runner)
            for responses in ([b'https://github.com/CybexHQ/manage', b'a' * 40, b''],
                              [config.SOURCE.encode(), b'b' * 40],
                              [config.SOURCE.encode(), b'a' * 40, b' M modified']):
                with self.assertRaises(ValueError):
                    config.check_source(settings, mock.Mock(side_effect=responses))

    def test_images_require_development_provenance_and_no_implicit_volumes(self):
        image = {'Id': 'sha256:' + 'a' * 64, 'Config': {'Labels': {
            'org.opencontainers.image.revision': 'a' * 40,
            'org.opencontainers.image.source': config.SOURCE}}}
        docker = resources.Docker(lambda args: json.dumps([image]).encode(), receipt()['owner'], 'fixture')
        self.assertEqual(docker.image(image['Id'], 'app', 'a' * 40), image['Id'])
        for bad in [image | {'Id': 'sha256:' + 'b' * 64}, image | {'Config': {'Labels': {}}},
                    image | {'Config': image['Config'] | {'Volumes': {'/host-data': {}}}}]:
            docker.run = lambda args: json.dumps([bad]).encode()
            with self.assertRaises(ValueError):
                docker.image(image['Id'], 'app', 'a' * 40)

    def test_signer_and_origin_must_match_both_authenticated_descriptors(self):
        key = base64.b64encode(b's' * 32).decode()
        manifest = {'version': '1.2.3', 'installer_iso_template_v3': {
            'manage_origin': configuration()['manage_origin'], 'provisioning_public_keys': [key]},
            'appliance_release_v1': {'schema': 'v3', 'manage_source_revision': 'a' * 40}}
        manifests = [copy.deepcopy(manifest), copy.deepcopy(manifest) | {'version': '1.2.2'}]
        verifier = types.SimpleNamespace(
            verify_pair=mock.Mock(side_effect=manifests), checked_json=lambda path: ({
                'release_manifest': {'url': 'https://github.com/org/repo/releases/manifest.json'},
                'compatibility_sha256': 'c' * 64}, b'{}'), sha=lambda path: 'd' * 64,
            COMPATIBILITY='compat.json', MANIFEST='manifest.json',
            release=types.SimpleNamespace(appliance_v3=types.SimpleNamespace(SCHEMA='v3')), advance=mock.Mock())
        result = config.signed_releases(configuration(), {'public_key': key}, Path('/candidate'),
                                        Path('/predecessor'), verifier=verifier)
        self.assertEqual(result['candidate']['version'], '1.2.3')
        self.assertEqual(verifier.verify_pair.call_count, 2)
        for role in range(2):
            for field, value in [('manage_origin', 'https://other.example.test'), ('provisioning_public_keys', ['other'])]:
                bad = copy.deepcopy(manifests)
                bad[role]['installer_iso_template_v3'][field] = value
                verifier.verify_pair = mock.Mock(side_effect=bad)
                with self.subTest(role=role, field=field), self.assertRaises(ValueError):
                    config.signed_releases(configuration(), {'public_key': key}, Path('/candidate'),
                                            Path('/predecessor'), verifier=verifier)
        verifier.verify_pair = mock.Mock(side_effect=ValueError('invalid signature'))
        with self.assertRaisesRegex(ValueError, 'invalid signature'):
            config.signed_releases(configuration(), {'public_key': key}, Path('/candidate'),
                                    Path('/predecessor'), verifier=verifier)

    def test_environment_contains_only_fresh_explicit_values(self):
        with mock.patch.dict(os.environ, {'SMTP_PASSWORD': 'private', 'HTTPS_PROXY': 'http://production',
                                          'CYBEX_DATABASE_URL': 'postgres://production'}, clear=False):
            values = resources.environment(configuration(), {'seed': 'seed', 'public_key': 'public',
                'encryption_key': 'fresh'}, {'manifest_url': 'https://github.com/exact',
                    'manifest_sha256': 'digest', 'version': '1.2.3', 'compatibility_sha256': 'compat'},
                'newpassword', 'newsshca', 'http://10.99.17.1:3128')
        self.assertNotIn('SMTP_PASSWORD', values)
        self.assertEqual(values['CYBEX_DATABASE_URL'], 'postgres://fixture:newpassword@db:5432/fixture')
        self.assertEqual(values['CYBEX_JAMES_RELEASE_MANIFEST_URL'], 'https://github.com/exact')
        self.assertEqual(values['CYBEX_JAMES_APPLIANCE_AUTOMATIC_ROLLOUTS'], 'false')
        self.assertEqual(values['HTTPS_PROXY'], 'http://10.99.17.1:3128')


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.adapter = mock.Mock()
        self.adapter.verify.return_value = True
        self.owner = owner_module.Owner(Path('/private/run'), self.adapter)
        self.context = {'owner': receipt()['owner'], 'bridge': 'jnq0123456789', 'subnet': '10.99.16.1/24',
                        'manage_origin': receipt()['manage_origin'], 'peer_ipv4': '10.99.16.1',
                        'network_id': 'network-id', 'backend_subnet': '10.99.17.0/28',
                        'egress_hosts': ['github.com']}
        self.guard = {'schema': owner_module.GUARD_SCHEMA, **self.context,
                      'guard_id': 'verified-rules', 'proxy_url': 'http://10.99.17.1:3128'}
        self.receipt = {'context': self.context, 'guard': self.guard}

    def test_receipt_is_not_a_substitute_for_live_adapter_verification(self):
        self.assertTrue(self.owner.guard(self.receipt))
        self.adapter.verify.return_value = False
        with self.assertRaises(ValueError):
            self.owner.guard(self.receipt)
        with self.assertRaises(ValueError):
            owner_module.Owner(Path('/private/run'), None)

    def test_default_deny_rejects_missing_proxy_wrong_owner_and_public_fallback(self):
        for field, value in [('owner', str(uuid.uuid4())), ('network_id', 'different'),
                              ('proxy_url', None), ('proxy_url', 'http://public.example.org:3128'),
                              ('proxy_url', 'http://10.99.17.1:3128/path'),
                              ('egress_hosts', ['dev.example.test'])]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.owner.guard(self.receipt | {'guard': self.guard | {field: value}})
        context = self.context | {'egress_hosts': []}
        with self.assertRaises(ValueError):
            self.owner.guard({'context': context, 'guard': self.guard | context})
        self.assertTrue(self.owner.guard({'context': context, 'guard': self.guard | context | {'proxy_url': None}}))

    def test_cleanup_refuses_changed_label_or_identity_without_removing_anything(self):
        for labels, identity in [({resources.LABEL: 'other', resources.ROLE: 'app'}, 'exact'),
                                  ({resources.LABEL: receipt()['owner'], resources.ROLE: 'app'}, 'replacement')]:
            runner = mock.Mock(side_effect=[b'exact fixture-app\n', json.dumps([{'Id': identity, 'Config': {'Labels': labels}}]).encode()])
            docker = resources.Docker(runner, receipt()['owner'], 'fixture')
            with self.assertRaises(ValueError):
                docker.remove_owned('app', 'exact')
            self.assertFalse(any('rm' in call.args[0] for call in runner.call_args_list))

    def test_cleanup_removes_exact_owned_resource_by_id_only(self):
        runner = mock.Mock(side_effect=[b'exact fixture-app\n', json.dumps([{'Id': 'exact', 'Config': {'Labels': {resources.LABEL: receipt()['owner'], resources.ROLE: 'app'}}}]).encode(), b''])
        resources.Docker(runner, receipt()['owner'], 'fixture').remove_owned('app', 'exact')
        self.assertEqual(runner.call_args_list[-1].args[0][-4:], ['container', 'rm', '-f', 'exact'])


    def test_container_confinement_rejects_extra_network_mount_port_or_privilege(self):
        mounts = [('/private/run/manage/app.env', '/run/fixture/environment', True)]
        labels = {resources.LABEL: receipt()['owner'], resources.ROLE: 'app'}
        image = 'sha256:' + 'a' * 64
        value = {'Id': 'exact', 'Image': image, 'Config': {'Labels': labels, 'User': '10001:10001',
                    'Entrypoint': ['/usr/bin/env'], 'Cmd': ['-i', '/bin/sh', '/run/fixture/launch.sh']},
                 'HostConfig': {'Privileged': False, 'ReadonlyRootfs': True, 'CapAdd': None,
                    'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges:true'],
                    'PidsLimit': 256,
                    'Tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=64m'},
                    'IpcMode': 'private', 'RestartPolicy': {'Name': 'no'},
                    'NetworkMode': 'owned-network', 'PortBindings': {}, 'Dns': ['10.99.16.1'],
                    'LogConfig': {'Type': 'local', 'Config': {'max-size': '10m', 'max-file': '2'}}},
                 'NetworkSettings': {'Networks': {'owned': {'NetworkID': 'owned-network'}}},
                 'Mounts': [{'Type': 'bind', 'Source': source, 'Destination': target, 'RW': not readonly}
                            for source, target, readonly in mounts]}
        docker = resources.Docker(mock.Mock(return_value=json.dumps([value]).encode()),
                                  receipt()['owner'], 'fixture')
        docker.verify_container('app', 'exact', image, 10001, 'owned-network', mounts, dns='10.99.16.1')
        alternatives = []
        for field, invalid in [('Privileged', True), ('CapAdd', ['NET_ADMIN']), ('PidMode', 'host'),
                               ('PidsLimit', 0), ('PidsLimit', 512),
                               ('IpcMode', 'host'), ('ReadonlyRootfs', False),
                               ('Dns', []), ('Dns', ['8.8.8.8']), ('DnsSearch', ['public.test']),
                               ('LogConfig', {'Type': 'syslog', 'Config': {}}),
                               ('PortBindings', {'8080/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8080'}]}),
                               ('Devices', [{'PathOnHost': '/dev/sda'}])]:
            changed = copy.deepcopy(value)
            changed['HostConfig'][field] = invalid
            alternatives.append(changed)
        changed = copy.deepcopy(value)
        changed['NetworkSettings']['Networks']['public'] = {'NetworkID': 'public'}
        alternatives.append(changed)
        changed = copy.deepcopy(value)
        changed['Mounts'].append({'Type': 'bind', 'Source': '/etc/secrets', 'Destination': '/secrets', 'RW': False})
        alternatives.append(changed)
        for changed in alternatives:
            docker.run = mock.Mock(return_value=json.dumps([changed]).encode())
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                docker.verify_container('app', 'exact', image, 10001, 'owned-network', mounts, dns='10.99.16.1')

    def test_network_membership_is_exact_during_staged_creation_and_ready_use(self):
        value = {'Id': 'network-id', 'Name': 'fixture-backend', 'Driver': 'bridge',
                 'Internal': True, 'EnableIPv6': False,
                 'Labels': {resources.LABEL: receipt()['owner'], resources.ROLE: 'backend'},
                 'IPAM': {'Config': [{'Subnet': '10.99.17.0/28', 'Gateway': '10.99.17.1'}]},
                 'Containers': {'db-id': {'Name': 'fixture-db'}}}
        docker = resources.Docker(mock.Mock(return_value=json.dumps([value]).encode()),
                                  receipt()['owner'], 'fixture')
        docker.verify_network('network-id', '10.99.17.0/28', ['db-id'])
        for members in ([], ['db-id', 'missing-id']):
            with self.subTest(members=members), self.assertRaises(ValueError):
                docker.verify_network('network-id', '10.99.17.0/28', members)
        changed = copy.deepcopy(value)
        changed['Containers']['foreign-id'] = {'Name': 'unowned-peer'}
        docker.run = mock.Mock(return_value=json.dumps([changed]).encode())
        with self.assertRaises(ValueError):
            docker.verify_network('network-id', '10.99.17.0/28', ['db-id'])

    def test_create_pins_dns_and_local_logging_before_start(self):
        runner = mock.Mock(return_value=b'created-id')
        docker = resources.Docker(runner, receipt()['owner'], 'fixture')
        docker.verify_container = mock.Mock()
        result = docker.create('app', 'sha256:' + 'a' * 64, 10001, 'network-id',
                               Path('/private/run'), [], dns='10.99.16.1')
        self.assertEqual(result, 'created-id')
        args = runner.call_args.args[0]
        self.assertEqual(args[args.index('--dns') + 1], '10.99.16.1')
        self.assertEqual(args[args.index('--log-driver') + 1], 'local')
        self.assertIn('max-size=10m', args)
        self.assertIn('max-file=2', args)
        self.assertNotIn('start', args)
        docker.verify_container.assert_called_once_with(
            'app', 'created-id', 'sha256:' + 'a' * 64, 10001, 'network-id', [],
            dns='10.99.16.1', peer=None, created=True)
        for dns in ('127.0.0.1', '8.8.8.8', '169.254.169.254', '100.64.0.1', '::1'):
            runner.reset_mock()
            with self.assertRaises(ValueError):
                docker.create('app', 'image', 10001, 'network-id', Path('/private/run'), [], dns=dns)
            runner.assert_not_called()

    def test_partial_cleanup_passes_durable_context_and_never_deletes_unknown_files(self):
        saved = {'context': self.context, 'guard': None, 'containers': {}, 'status': 'failed'}
        self.owner.lock = contextlib.nullcontext
        self.owner.read = lambda: saved
        self.owner.save = mock.Mock()
        docker = mock.Mock()
        self.owner.docker = lambda receipt: docker
        result = self.owner.cleanup()
        self.adapter.cleanup.assert_called_once_with(self.context, None)
        self.assertEqual(docker.remove_owned.call_args_list, [mock.call('tls', None), mock.call('app', None),
                                                             mock.call('db', None), mock.call('backend', 'network-id')])
        self.assertEqual(result['status'], 'stopped')

    def test_cleanup_resumes_after_backend_removal_and_failed_terminal_save(self):
        persisted = {'context': self.context, 'guard': None, 'containers': {}, 'status': 'failed'}
        backend_removed = False
        self.owner.lock = contextlib.nullcontext
        self.owner.read = lambda: copy.deepcopy(persisted)
        docker = mock.Mock()
        self.owner.docker = lambda receipt: docker
        def remove(role, identity):
            nonlocal backend_removed
            if role == 'backend':
                backend_removed = True
        docker.remove_owned.side_effect = remove
        def guard_cleanup(context, guard):
            if backend_removed:
                raise ValueError('backend is absent')
        self.adapter.cleanup.side_effect = guard_cleanup
        def save(receipt):
            if receipt['status'] == 'stopped':
                raise OSError('interrupted terminal save')
            persisted.clear()
            persisted.update(copy.deepcopy(receipt))
        self.owner.save = save
        with self.assertRaisesRegex(OSError, 'terminal save'):
            self.owner.cleanup()
        self.assertTrue(backend_removed)
        self.owner.save = mock.Mock()
        result = self.owner.cleanup()
        self.assertEqual(result['status'], 'stopped')
        self.adapter.cleanup.assert_called_once()
        self.assertEqual(docker.remove_owned.call_args_list[-1], mock.call('backend', 'network-id'))

    def test_stopped_cleanup_is_idempotent_and_explicit_purge_uses_owned_state_cleanup(self):
        saved = {'context': self.context, 'guard': None, 'containers': {}, 'status': 'stopped'}
        self.owner.lock = contextlib.nullcontext
        self.owner.read = lambda: saved
        self.owner.save = mock.Mock()
        self.owner.purge_state = mock.Mock()
        self.owner.docker = mock.Mock(side_effect=AssertionError('stopped cleanup must not inspect Docker'))
        self.assertIs(self.owner.cleanup(), saved)
        self.owner.purge_state.assert_not_called()
        self.assertIs(self.owner.cleanup(purge=True), saved)
        self.assertEqual(saved['status'], 'purging')
        self.owner.save.assert_called_once_with(saved)
        self.owner.purge_state.assert_called_once_with(saved)
        self.adapter.cleanup.assert_not_called()

    def test_purge_rejects_nested_mounts_including_same_filesystem_binds(self):
        owner = owner_module.Owner(Path('/private/fixture'), self.adapter)
        base = '23 1 0:1 / / rw - tmpfs tmpfs rw\n'
        with mock.patch.object(Path, 'read_text', return_value=base):
            owner.refuse_mounted_state()
        for target in ('/private/fixture/manage', '/private/fixture/manage/db-data/tablespace',
                       '/private/fixture/manage/app-data/space\\040name'):
            mounts = base + f'24 23 0:1 /foreign {target} rw - tmpfs tmpfs rw\n'
            with self.subTest(target=target), mock.patch.object(Path, 'read_text', return_value=mounts):
                with self.assertRaisesRegex(ValueError, 'mounted fixture state'):
                    owner.refuse_mounted_state()
        with mock.patch.object(Path, 'read_text', return_value='incomplete'):
            with self.assertRaisesRegex(ValueError, 'mount boundaries'):
                owner.refuse_mounted_state()

    def test_purge_refuses_unknown_top_level_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = owner_module.Owner(Path(temporary), self.adapter)
            owner.directory.mkdir(mode=0o700)
            (owner.directory / 'operator-notes').write_text('do not delete')
            actual = os.lstat(owner.directory)
            directory = types.SimpleNamespace(st_mode=actual.st_mode, st_uid=0, st_dev=actual.st_dev)
            with mock.patch.object(owner_module.os, 'lstat', side_effect=lambda path: directory if Path(path) == owner.directory else os.lstat(path)):
                with self.assertRaisesRegex(ValueError, 'unexpected fixture state'):
                    owner.purge_state({'status': 'purging'})
            self.assertTrue((owner.directory / 'operator-notes').exists())

    def test_device_allowlist_environment_replacement_is_atomic_and_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = owner_module.Owner(Path(temporary), self.adapter)
            owner.directory.mkdir()
            path = owner.directory / 'app.env'
            original = b'EXISTING=retained\nCYBEX_JAMES_UPDATE_QUALIFICATION_ENABLED=false\n'
            path.write_bytes(original)
            saved = {'organization_id': str(uuid.uuid4()), 'files': {'app.env': {}}}
            device = 'dev_' + '1' * 32

            def write_plain(target, body, **_kwargs):
                Path(target).write_bytes(body)
                Path(target).chmod(0o400)

            with mock.patch.object(config, 'read_file', return_value=original), \
                    mock.patch.object(resources, 'write', side_effect=write_plain):
                owner.replace_app_environment(saved, device)
            body = path.read_text()
            self.assertIn('EXISTING=retained\n', body)
            self.assertIn('CYBEX_JAMES_UPDATE_QUALIFICATION_ENABLED=true\n', body)
            self.assertIn('CYBEX_JAMES_UPDATE_QUALIFICATION_ORGANIZATION_ID=' + saved['organization_id'] + '\n', body)
            self.assertIn('CYBEX_JAMES_UPDATE_QUALIFICATION_DEVICE_IDS=' + device + '\n', body)
            self.assertEqual(saved['files']['app.env']['sha256'], hashlib.sha256(body.encode()).hexdigest())
            self.assertEqual(list(owner.directory.glob('app.env.*')), [])

    def test_allow_device_recreates_only_app_and_persists_one_exact_target(self):
        saved = {'status': 'ready', 'organization_id': str(uuid.uuid4()), 'allowed_device_id': None,
                 'peer_ipv4': '10.99.16.1', 'context': self.context,
                 'containers': {
                     role: {'id': role + '-id', 'image': role + '-image', 'uid': 10001,
                            'mounts': [], 'peer': '10.99.16.1' if role == 'tls' else None}
                     for role in ('db', 'app', 'tls')}}
        self.owner.lock = contextlib.nullcontext
        self.owner.verify = mock.Mock(return_value=saved)
        self.owner.save = mock.Mock()
        self.owner.guard = mock.Mock(return_value=True)
        self.owner.replace_app_environment = mock.Mock()
        self.owner.wait_health = mock.Mock()
        client = mock.Mock()
        device = 'dev_' + '1' * 32
        client.request.return_value = {'node': {'device_id': device}}
        self.owner.client = mock.Mock(return_value=client)
        docker = mock.Mock()
        docker.create.return_value = 'new-app-id'
        docker.verify_container.return_value = {'State': {'Running': True}}
        self.owner.docker = mock.Mock(return_value=docker)
        with mock.patch.object(config, 'read_file', return_value=b'private-session\n'):
            result = self.owner.allow_device(device)
        self.assertIs(result, saved)
        self.assertEqual(saved['allowed_device_id'], device)
        self.assertEqual(saved['status'], 'ready')
        client.request.assert_called_once_with('/v1/james/nodes/' + device, token='private-session')
        docker.remove_owned.assert_called_once_with('app', 'app-id')
        docker.call.assert_has_calls([mock.call('container', 'start', 'new-app-id'),
                                      mock.call('container', 'restart', 'tls-id')])
        docker.verify_network.assert_called_once_with(
            'network-id', '10.99.17.0/28', ['db-id', 'new-app-id', 'tls-id'])
        self.owner.replace_app_environment.assert_called_once_with(saved, device)

    def test_allow_device_failure_keeps_durable_label_cleanup_intent(self):
        saved = {'status': 'ready', 'organization_id': str(uuid.uuid4()), 'allowed_device_id': None,
                 'peer_ipv4': '10.99.16.1', 'context': self.context,
                 'containers': {
                     role: {'id': role + '-id', 'image': role + '-image', 'uid': 10001,
                            'mounts': [], 'peer': '10.99.16.1' if role == 'tls' else None}
                     for role in ('db', 'app', 'tls')}}
        snapshots = []
        self.owner.lock = contextlib.nullcontext
        self.owner.verify = mock.Mock(return_value=saved)
        self.owner.save = mock.Mock(side_effect=lambda value: snapshots.append(copy.deepcopy(value)))
        self.owner.replace_app_environment = mock.Mock()
        client = mock.Mock()
        device = 'dev_' + '1' * 32
        client.request.return_value = {'node': {'device_id': device}}
        self.owner.client = mock.Mock(return_value=client)
        docker = mock.Mock()
        docker.create.side_effect = ValueError('create failed after name reservation')
        self.owner.docker = mock.Mock(return_value=docker)
        with mock.patch.object(config, 'read_file', return_value=b'private-session\n'):
            with self.assertRaisesRegex(ValueError, 'create failed'):
                self.owner.allow_device(device)
        docker.remove_owned.assert_called_once_with('app', 'app-id')
        self.assertIsNone(saved['containers']['app']['id'])
        self.assertEqual(saved['status'], 'failed')
        self.assertTrue(any(snapshot['containers']['app']['id'] is None for snapshot in snapshots))
        docker.call.assert_not_called()

    def test_allow_device_rejects_invalid_foreign_or_second_target_before_reconfiguration(self):
        for device in ('invalid', 'dev_' + '1' * 31):
            with self.subTest(device=device), self.assertRaises(ValueError):
                self.owner.allow_device(device)
        first = 'dev_' + '1' * 32
        second = 'dev_' + '2' * 32
        saved = {'allowed_device_id': first}
        self.owner.lock = contextlib.nullcontext
        self.owner.verify = mock.Mock(return_value=saved)
        with self.assertRaisesRegex(ValueError, 'different qualification device'):
            self.owner.allow_device(second)
        saved = {'allowed_device_id': None}
        self.owner.verify = mock.Mock(return_value=saved)
        client = mock.Mock()
        client.request.return_value = {'node': {'device_id': first}}
        self.owner.client = mock.Mock(return_value=client)
        self.owner.save = mock.Mock()
        self.owner.docker = mock.Mock(side_effect=AssertionError('foreign target must not mutate Docker'))
        with mock.patch.object(config, 'read_file', return_value=b'private-session\n'):
            with self.assertRaisesRegex(ValueError, 'not an active James node'):
                self.owner.allow_device(second)
        self.owner.save.assert_not_called()

    def test_bootstrap_uses_only_fresh_setup_api_and_keeps_session_private(self):
        saved = receipt()
        client = mock.Mock()
        organization = str(uuid.uuid4())
        client.request.return_value = {'session_token': 'fresh-private-session', 'organization': {'id': organization}}
        self.owner.client = lambda receipt: client
        self.owner.save = mock.Mock()
        with mock.patch.object(resources, 'write') as write:
            self.owner.bootstrap(saved)
        self.assertEqual(client.request.call_args.args[0], '/v1/auth/bootstrap')
        body = client.request.call_args.args[1]
        self.assertEqual(body['organization_type'], 'company')
        self.assertTrue(body['email'].endswith('@example.invalid'))
        self.assertGreaterEqual(len(body['password']), 48)
        write.assert_called_once_with(self.owner.state / 'session', b'fresh-private-session\n', mode=0o600)
        self.assertEqual(saved['organization_id'], organization)
        self.assertNotIn('session_token', saved)

    def test_adapter_failure_precedes_container_start_and_retains_owned_cleanup_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = owner_module.Owner(Path(temporary), self.adapter)
            owner.lock = contextlib.nullcontext
            owner.scope = lambda: self.context | {'schema': 'scope', 'run': 'test'}
            owner.save = mock.Mock()
            docker = mock.Mock()
            docker.image.return_value = 'sha256:' + 'a' * 64
            docker.network.return_value = 'network-id'
            owner.docker = lambda receipt: docker
            self.adapter.prepare.return_value = self.guard
            self.adapter.verify.return_value = False
            settings = configuration() | {'manage_origin': self.context['manage_origin']}
            with mock.patch.object(config, 'load', return_value=(settings, {'certificate_sha256': 'a' * 64})), \
                 mock.patch.object(config, 'signed_releases', return_value={}):
                with self.assertRaises(ValueError):
                    owner.prepare(Path('/config'), Path('/candidate'), Path('/predecessor'))
            docker.create.assert_not_called()
            saved = owner.save.call_args.args[0]
            self.assertEqual(saved['status'], 'failed')
            self.assertEqual(saved['context']['network_id'], 'network-id')


class TLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        root = Path(cls.temporary.name)
        cls.cert, cls.key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', cls.key, '-out', cls.cert, '-subj', '/CN=dev.example.test',
                        '-addext', 'subjectAltName=DNS:dev.example.test'], check=True, capture_output=True)
        cls.fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cls.cert.read_text())).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @contextlib.contextmanager
    def server(self, *, challenge_status=200, wrong_challenge=False, close_challenge=False, api_status=200):
        observed = []
        value = receipt() | {'certificate_sha256': self.fingerprint}
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_args):
                pass
            def do_GET(self):
                observed.append((self.path, dict(self.headers)))
                challenge = self.path.startswith('/.well-known/')
                status = challenge_status if challenge else api_status
                body = {key: value[key] for key in ('owner', 'manage_origin', 'challenge')} if challenge else {'ok': True}
                if wrong_challenge and challenge:
                    body['owner'] = 'other'
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header('Content-Length', str(len(data)))
                if status == 302:
                    self.send_header('Location', 'https://public.example.org/v1/health')
                if close_challenge and challenge:
                    self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(data)
        class QuietServer(http.server.ThreadingHTTPServer):
            def handle_error(self, *_args):
                # Certificate-pin failures intentionally close the TLS peer.
                pass
        server = QuietServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def connect(address, timeout):
            self.assertEqual(address, ('127.0.0.1', 443))
            return socket.create_connection(server.server_address, timeout)
        try:
            yield value, observed, connect
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def client(self, value, connector, *, trusted=True, hostname='dev.example.test'):
        context = ssl.create_default_context(cafile=self.cert if trusted else None)
        # Local test listener is loopback; production endpoint() rejects loopback.
        with mock.patch.object(transport, 'endpoint', return_value=(hostname, '127.0.0.1')):
            return transport.Transport(value, lambda: True, context=context, connector=connector)


    def test_generated_signer_and_dedicated_tls_key_are_cryptographically_bound(self):
        seed = base64.b64encode(bytes(range(32))).decode()
        material = config.key_material(seed, self.cert.read_bytes(), self.key.read_bytes())
        self.assertEqual(material['seed'], seed)
        self.assertEqual(material['certificate_sha256'], self.fingerprint)
        self.assertEqual(len(base64.b64decode(material['public_key'])), 32)
        self.assertNotEqual(material['public_key'], seed)
        wrong = subprocess.run(['openssl', 'genpkey', '-algorithm', 'ed25519'],
                               check=True, capture_output=True).stdout
        with self.assertRaisesRegex(ValueError, 'do not match'):
            config.key_material(seed, self.cert.read_bytes(), wrong)

    def test_tls_sni_peer_pin_and_challenge_precede_bearer_on_same_connection(self):
        with self.server() as (value, observed, connect), mock.patch.dict(os.environ, {'HTTPS_PROXY': 'http://wrong'}):
            client = self.client(value, connect)
            self.assertEqual(client.request('/v1/health', token='private-session'), {'ok': True})
            self.assertEqual(len(observed), 2)
            self.assertNotIn('Authorization', observed[0][1])
            self.assertEqual(observed[1][1]['Authorization'], 'Bearer private-session')
            self.assertEqual(observed[1][1]['Host'], 'dev.example.test')

    def test_wrong_challenge_redirect_or_closed_connection_never_sends_bearer(self):
        for options in ({'wrong_challenge': True}, {'challenge_status': 302}, {'close_challenge': True}):
            with self.subTest(options=options), self.server(**options) as (value, observed, connect):
                with self.assertRaises((ValueError, http.client.HTTPException)):
                    self.client(value, connect).request('/v1/health', token='private-session')
                self.assertEqual(len(observed), 1)
                self.assertNotIn('Authorization', observed[0][1])

    def test_tls_wrong_certificate_wrong_hostname_and_untrusted_chain_send_no_http(self):
        for kwargs in ({'fingerprint': '0' * 64}, {'hostname': 'other.example.test'}, {'trusted': False}):
            with self.subTest(kwargs=kwargs), self.server() as (value, observed, connect):
                if 'fingerprint' in kwargs:
                    value['certificate_sha256'] = kwargs['fingerprint']
                with self.assertRaises((ValueError, ssl.SSLCertVerificationError)):
                    self.client(value, connect, **{k: v for k, v in kwargs.items() if k != 'fingerprint'}).request('/v1/health', token='private-session')
                self.assertEqual(observed, [])

    def test_api_redirect_does_not_open_another_connection(self):
        with self.server(api_status=302) as (value, observed, connect):
            connector = mock.Mock(side_effect=connect)
            with self.assertRaises(ValueError):
                self.client(value, connector).request('/v1/health', token='private-session')
            self.assertEqual(connector.call_count, 1)
            self.assertEqual(len(observed), 2)

    def test_wrong_peer_guard_failure_and_insecure_tls_context_fail_closed(self):
        connector = mock.Mock()
        connector.return_value.getpeername.return_value = ('8.8.8.8', 443)
        client = transport.Transport(receipt(), lambda: True, connector=connector)
        with self.assertRaises(ValueError):
            client.request('/v1/health', token='private-session')
        connector.return_value.close.assert_called()
        connector.reset_mock()
        client = transport.Transport(receipt(), lambda: False, connector=connector)
        with self.assertRaises(ValueError):
            client.request('/v1/health', token='private-session')
        connector.assert_not_called()
        with self.assertRaises(ValueError):
            transport.Transport(receipt(), lambda: True, context=ssl._create_unverified_context())
        for peer in ('127.0.0.1', '8.8.8.8', '::1'):
            with self.assertRaises(ValueError):
                transport.endpoint(receipt() | {'peer_ipv4': peer})


if __name__ == '__main__':
    unittest.main()
