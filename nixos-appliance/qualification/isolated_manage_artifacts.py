#!/usr/bin/env python3
"""Stage and own the three immutable offline-qualification artifact listeners.

This module owns files and direct child processes only. Network admission belongs
to the separately reviewed adapter, and release selection belongs to the fixture
Owner. Callers must retain this Coordinator instance: receipts and PIDs alone are
deliberately insufficient to adopt or stop a listener after coordinator restart.
"""
from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid


def sibling(name):
    spec = importlib.util.spec_from_file_location('_james_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = sibling('verified_artifact_server')
release_verifier = sibling('release_predecessor')
SCHEMA = 'cybex.james.isolated-manage-artifacts.v1'
URL_SCHEMA = 'cybex.james.isolated-manage-artifact-urls.v1'
ROLES = ('predecessor', 'candidate')
LISTENERS = ('predecessor-backend', 'candidate-backend', 'guest')
PORTS = {'predecessor-backend': 18081, 'candidate-backend': 18083, 'guest': 18082}
SCOPE_FIELDS = {'owner', 'bridge', 'subnet', 'manage_origin', 'peer_ipv4',
                'network_id', 'backend_subnet', 'egress_hosts'}
SHA = re.compile(r'[0-9a-f]{64}\Z')
BRIDGE = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}\Z')
NETWORK_ID = re.compile(r'[0-9a-f]{64}\Z')
DEVICE_DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
# ArtifactServer authenticates every staged byte before it publishes a receipt.
# Preserve that full bounded hashing budget plus process/publication overhead.
START_TIMEOUT = server.REQUEST_TIMEOUT + 30
STOP_TIMEOUT = 10


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def object_identity(info):
    return {name: getattr(info, 'st_' + name) for name in
            ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink')}


def directory_identity(info):
    return {name: getattr(info, 'st_' + name) for name in
            ('dev', 'ino', 'uid', 'gid', 'mode')}


def _rfc1918(address):
    return address.version == 4 and any(address in network for network in server.RFC1918)


def normalize_scope(value):
    if not isinstance(value, dict) or set(value) != SCOPE_FIELDS:
        raise ValueError('artifact coordinator scope shape is invalid')
    try:
        owner = str(uuid.UUID(value['owner']))
        guest = ipaddress.ip_interface(value['subnet'])
        peer = ipaddress.ip_address(value['peer_ipv4'])
        backend = ipaddress.ip_network(value['backend_subnet'])
        origin = urlsplit(value['manage_origin'])
    except (ValueError, TypeError):
        raise ValueError('artifact coordinator scope is invalid') from None
    if (owner != value['owner'] or uuid.UUID(owner).int == 0
            or not isinstance(value['bridge'], str) or not BRIDGE.fullmatch(value['bridge'])
            or guest.version != 4 or guest.network.prefixlen != 24 or not _rfc1918(guest.ip)
            or peer != guest.ip or str(peer) != value['peer_ipv4']
            or backend.version != 4 or backend.prefixlen != 28 or not _rfc1918(backend.network_address)
            or backend.overlaps(guest.network)
            or not isinstance(value['network_id'], str) or not NETWORK_ID.fullmatch(value['network_id'])
            or value['egress_hosts'] != []
            or origin.scheme != 'https' or origin.netloc != origin.hostname or not origin.hostname
            or origin.path or origin.query or origin.fragment or origin.username or origin.password):
        raise ValueError('artifact coordinator scope is not an exact offline fixture')
    return dict(value)


def private_directory(path, uid):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError('artifact coordinator requires an exact absolute directory')
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != DEVICE_DIRECTORY_MODE):
        raise ValueError('artifact coordinator directory must be private and owned')
    return path


def exclusive_write(path, body, uid):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, FILE_MODE)
    try:
        os.fchmod(fd, FILE_MODE)
        os.fchown(fd, uid, uid)
        view = memoryview(body)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        return object_identity(os.fstat(fd))
    finally:
        os.close(fd)


def read_private_json(path, uid, maximum=1024 * 1024):
    pinned = server.PinnedFile(path, uid, Path(path).parent)
    try:
        if not 0 < pinned.identity['size'] <= maximum or stat.S_IMODE(pinned.identity['mode']) != FILE_MODE:
            raise ValueError('artifact coordinator document is unsafe')
        body = pinned.read(0, pinned.identity['size'])
        pinned.check()
        value = json.loads(body)
        if body != canonical(value):
            raise ValueError('artifact coordinator document is not canonical')
        return value, pinned.identity
    finally:
        pinned.close()


def _set_parent_death(parent_pid):
    """Arm Linux parent-death termination before exec, closing the fork race."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0 or os.getppid() != parent_pid:
        os._exit(127)


def spawn_direct(command):
    parent = os.getpid()
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             preexec_fn=lambda: _set_parent_death(parent))
    try:
        pidfd = os.pidfd_open(child.pid)
    except BaseException:
        child.terminate()
        child.wait(timeout=STOP_TIMEOUT)
        raise
    return child, pidfd


class Child:
    def __init__(self, process, pidfd):
        self.process, self.pidfd = process, pidfd
        self.receipt, self.receipt_identity = None, None

    def stop(self):
        # The Popen object and pidfd were captured directly at fork. Cleanup
        # never depends on untrusted or only partially validated receipt JSON.
        try:
            if self.process.poll() is None:
                try:
                    signal.pidfd_send_signal(self.pidfd, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                    self.process.wait(timeout=STOP_TIMEOUT)
        finally:
            os.close(self.pidfd)
            self.pidfd = None


class Coordinator:
    def __init__(self, state_dir, scope, releases, trusted_public_key, *, verifier=release_verifier,
                 _test_uid=None, _test_endpoints=None, _test_loopback=False, _test_anchor=None):
        self.uid = 0 if _test_uid is None else _test_uid
        self.state = private_directory(state_dir, self.uid)
        self.directory = self.state / 'artifact-transport'
        self.receipt_path = self.directory / 'coordinator.json'
        self.scope = normalize_scope(scope)
        self.verifier = verifier
        self.trusted_public_key = trusted_public_key
        self.children = {}
        self.known_files, self.known_directories = {}, {}
        self.receipt, self.receipt_identity = None, None
        self._test_loopback = _test_loopback
        self._test_anchor = Path(_test_anchor) if _test_anchor is not None else None
        self._server_anchor = (self._test_anchor or self.state) if _test_loopback else Path('/')
        if not isinstance(releases, dict) or set(releases) != set(ROLES):
            raise ValueError('artifact coordinator needs exact predecessor and candidate inputs')
        self.releases = {}
        for role in ROLES:
            entry = releases[role]
            if (not isinstance(entry, dict) or set(entry) != {'directory', 'compatibility_sha256'}
                    or not isinstance(entry['compatibility_sha256'], str)
                    or not SHA.fullmatch(entry['compatibility_sha256'])):
                raise ValueError('artifact release input is invalid')
            directory = private_directory(entry['directory'], self.uid)
            if directory == self.state or self.state in directory.parents or directory in self.state.parents:
                raise ValueError('artifact release sources must be outside coordinator state')
            self.releases[role] = {'directory': directory,
                                   'compatibility_sha256': entry['compatibility_sha256']}
        gateway = str(ipaddress.ip_network(self.scope['backend_subnet'])[1])
        expected = {'predecessor-backend': (gateway, PORTS['predecessor-backend']),
                    'candidate-backend': (gateway, PORTS['candidate-backend']),
                    'guest': (self.scope['peer_ipv4'], PORTS['guest'])}
        if _test_endpoints is not None:
            if not _test_loopback or set(_test_endpoints) != set(LISTENERS):
                raise ValueError('test endpoints require the closed listener set')
            expected = {name: tuple(_test_endpoints[name]) for name in LISTENERS}
        self.endpoints = {name: server.endpoint(*expected[name], test=_test_loopback) for name in LISTENERS}

    def _scope(self, value):
        if normalize_scope(value) != self.scope:
            raise ValueError('artifact coordinator scope changed')

    def _mkdir(self, path):
        path.mkdir(mode=DEVICE_DIRECTORY_MODE)
        path.chmod(DEVICE_DIRECTORY_MODE)
        os.chown(path, self.uid, self.uid)
        self.known_directories[path] = directory_identity(os.lstat(path))

    def _spec(self, role, kind, descriptor, digest_field='sha256'):
        try:
            filename = urlsplit(descriptor['url']).path.rsplit('/', 1)[-1]
            digest, size = descriptor[digest_field], descriptor['size_bytes']
        except (KeyError, TypeError):
            raise ValueError('verified release artifact descriptor is incomplete') from None
        if (not server.NAME.fullmatch(filename) or not isinstance(digest, str) or not SHA.fullmatch(digest)
                or type(size) is not int or not 0 < size <= server.MAX_ARTIFACT_SIZE):
            raise ValueError('verified release artifact identity is invalid')
        return {'role': role, 'kind': kind, 'filename': filename, 'sha256': digest,
                'size_bytes': size, 'source': self.releases[role]['directory'] / filename}

    def _verify_release(self, role):
        entry, directory = self.releases[role], self.releases[role]['directory']
        verified = self.verifier.verify_pair_snapshot(directory, self.trusted_public_key)
        manifest, manifest_body = verified['manifest'], verified['manifest_body']
        compatibility = verified['compatibility']
        if (compatibility.get('compatibility_sha256') != entry['compatibility_sha256']
                or compatibility.get('james_release_version') != manifest.get('version')):
            raise ValueError('verified release compatibility identity changed')
        manifest_identity = compatibility.get('release_manifest')
        if (not isinstance(manifest_identity, dict) or set(manifest_identity) != {'url', 'sha256'}
                or urlsplit(manifest_identity.get('url', '')).path.rsplit('/', 1)[-1] != self.verifier.MANIFEST
                or not SHA.fullmatch(manifest_identity.get('sha256', ''))):
            raise ValueError('verified compatibility asset lacks the exact manifest identity')
        if manifest.get('version') is None:
            raise ValueError('verified release lacks a version')
        iso = manifest.get('installer_iso_template_v3')
        if not isinstance(iso, dict) or iso.get('manage_origin') != self.scope['manage_origin']:
            raise ValueError('verified release installer origin differs from fixture scope')
        manifest_size = len(manifest_body)
        if hashlib.sha256(manifest_body).hexdigest() != manifest_identity['sha256']:
            raise ValueError('authenticated manifest bytes differ from signed identity')
        specs = {'manifest': {'role': role, 'kind': 'manifest', 'filename': self.verifier.MANIFEST,
                              'sha256': manifest_identity['sha256'], 'size_bytes': manifest_size,
                              'body': manifest_body},
                 'iso': self._spec(role, 'iso', iso, 'template_sha256'),
                 'closure': self._spec(role, 'closure', manifest['appliance_release_v1']['system_closure']),
                 'workstation': self._spec(role, 'workstation', manifest['workstation_netboot'])}
        return {'version': manifest['version'], 'manifest_sha256': manifest_identity['sha256'],
                'compatibility_sha256': entry['compatibility_sha256'], 'specs': specs}

    def _copy(self, spec, destination):
        source = None
        try:
            body = spec.get('body')
            if body is None:
                source = server.PinnedFile(spec['source'], self.uid, spec['source'].parent)
                if source.identity['size'] != spec['size_bytes']:
                    raise ValueError('artifact source size differs from signed identity')
            elif not isinstance(body, bytes) or len(body) != spec['size_bytes']:
                raise ValueError('authenticated artifact snapshot size differs from signed identity')
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, FILE_MODE)
            self.known_files[destination] = object_identity(os.fstat(fd))
            digest, offset = hashlib.sha256(), 0
            try:
                os.fchmod(fd, FILE_MODE)
                os.fchown(fd, self.uid, self.uid)
                while offset < spec['size_bytes']:
                    length = min(server.CHUNK, spec['size_bytes'] - offset)
                    data = body[offset:offset + length] if body is not None else source.read(offset, length)
                    if not data:
                        raise ValueError('artifact source truncated during staging')
                    view = memoryview(data)
                    while view:
                        view = view[os.write(fd, view):]
                    digest.update(data)
                    offset += len(data)
                os.fsync(fd)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != FILE_MODE):
                    raise ValueError('staged artifact is unsafe')
            finally:
                os.close(fd)
            if source is not None:
                source.check()
            if digest.hexdigest() != spec['sha256'] or offset != spec['size_bytes']:
                raise ValueError('artifact source bytes differ from signed identity')
        finally:
            if source is not None:
                source.close()
        staged = server.PinnedFile(destination, self.uid, self._server_anchor)
        try:
            if staged.digest() != spec['sha256'] or staged.identity['size'] != spec['size_bytes']:
                raise ValueError('staged artifact differs from signed identity')
            return {'filename': spec['filename'], 'path': str(destination), 'sha256': spec['sha256'],
                    'size_bytes': spec['size_bytes'], 'metadata': staged.identity,
                    'ancestors': staged.ancestors,
                    'roles': [spec['role']], 'kinds': [spec['kind']]}
        finally:
            staged.close()

    def _stage_listener(self, name, specs):
        directory = self.directory / name
        self._mkdir(directory)
        unique = {}
        for spec in specs:
            prior = unique.get(spec['filename'])
            if prior is not None:
                if (prior['sha256'], prior['size_bytes']) != (spec['sha256'], spec['size_bytes']):
                    raise ValueError('same listener filename has different signed identities')
                prior['roles'].append(spec['role'])
                prior['kinds'].append(spec['kind'])
                continue
            unique[spec['filename']] = self._copy(spec, directory / spec['filename'])
        return directory, [unique[key] for key in sorted(unique)]

    def _server_command(self, config, receipt):
        source = Path(server.__file__)
        if not self._test_loopback:
            return [sys.executable, '-B', str(source), '--config', str(config), '--receipt', str(receipt)]
        code = '''
import importlib.util, os, signal, sys
from pathlib import Path
spec=importlib.util.spec_from_file_location("artifact_server",sys.argv[1])
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
s=m.ArtifactServer(Path(sys.argv[2]),_test_uid=int(sys.argv[5]),_test_anchor=Path(sys.argv[4]),_test_loopback=True)
def stop(*_args): raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
try:
 m.publish_receipt(Path(sys.argv[3]),s.receipt,anchor=Path(sys.argv[4]))
 s.serve_forever(poll_interval=0.05)
finally: s.server_close()
'''
        return [sys.executable, '-B', '-c', code, str(source), str(config), str(receipt),
                str(self._test_anchor or self.state), str(self.uid)]

    def _validate_listener_receipt(self, name, receipt, config, artifacts, child):
        expected_keys = {'schema', 'scope_owner', 'server_id', 'challenge', 'config_sha256',
                         'config_path', 'config_metadata', 'config_ancestors', 'artifacts',
                         'process', 'receipt_uid', 'bind', 'port'}
        bind, port = self.endpoints[name]
        if (set(receipt) != expected_keys or receipt['scope_owner'] != self.scope['owner']
                or receipt['process']['pid'] != child.process.pid or receipt['receipt_uid'] != self.uid
                or receipt['config_path'] != str(config) or (receipt['bind'], receipt['port']) != (bind, port)):
            raise ValueError('artifact listener receipt differs from its owned configuration')
        pinned_config = server.PinnedFile(config, self.uid, self._server_anchor)
        try:
            if (receipt['config_sha256'] != pinned_config.digest()
                    or receipt['config_metadata'] != pinned_config.identity
                    or receipt['config_ancestors'] != pinned_config.ancestors):
                raise ValueError('artifact listener receipt differs from its owned configuration')
        finally:
            pinned_config.close()
        expected = [{key: artifact[key] for key in
                     ('filename', 'path', 'sha256', 'size_bytes', 'metadata', 'ancestors')}
                    for artifact in artifacts]
        if receipt['artifacts'] != expected:
            raise ValueError('artifact listener receipt differs from staged identities')
        server.verify_server(receipt, _test_loopback=self._test_loopback)

    def _start_listener(self, name, directory, artifacts):
        bind, port = self.endpoints[name]
        config = directory / 'server.json'
        receipt_path = directory / 'receipt.json'
        value = {'schema': server.SCHEMA, 'scope_owner': self.scope['owner'], 'bind': bind, 'port': port,
                 'artifacts': [{key: artifact[key] for key in ('filename', 'path', 'sha256', 'size_bytes')}
                               for artifact in artifacts]}
        self.known_files[config] = exclusive_write(config, server.canonical(value), self.uid)
        process, pidfd = spawn_direct(self._server_command(config, receipt_path))
        child = Child(process, pidfd)
        self.children[name] = child
        deadline = time.monotonic() + START_TIMEOUT
        while not receipt_path.exists():
            if process.poll() is not None:
                raise ValueError('artifact listener exited before publishing its receipt')
            if time.monotonic() >= deadline:
                raise TimeoutError('artifact listener did not publish its receipt')
            time.sleep(0.02)
        receipt, receipt_identity = read_private_json(receipt_path, self.uid)
        self.known_files[receipt_path] = {key: receipt_identity[key] for key in
                                          ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink')}
        self._validate_listener_receipt(name, receipt, config, artifacts, child)
        child.receipt, child.receipt_identity = receipt, receipt_identity
        return {'config': str(config), 'receipt': str(receipt_path), 'server': receipt,
                'artifacts': artifacts}

    def prepare(self, current_scope):
        self._scope(current_scope)
        if self.directory.exists() or self.directory.is_symlink() or self.receipt is not None:
            raise ValueError('refusing to adopt or replace artifact coordinator state')
        self._mkdir(self.directory)
        try:
            releases = {role: self._verify_release(role) for role in ROLES}
            self.verifier.advance(releases['candidate']['version'], releases['predecessor']['version'])
            layout = {
                'predecessor-backend': [releases['predecessor']['specs']['manifest'],
                                        releases['predecessor']['specs']['iso']],
                'candidate-backend': [releases['candidate']['specs']['manifest'],
                                      releases['candidate']['specs']['iso']],
                'guest': [releases[role]['specs'][kind] for role in ROLES
                          for kind in ('closure', 'workstation')],
            }
            staged, listeners = {}, {}
            for name in LISTENERS:
                directory, artifacts = self._stage_listener(name, layout[name])
                staged[name] = artifacts
                listeners[name] = self._start_listener(name, directory, artifacts)
            release_receipts = {role: {key: releases[role][key] for key in
                                       ('version', 'manifest_sha256', 'compatibility_sha256')}
                                for role in ROLES}
            plan = {'scope': self.scope, 'releases': release_receipts,
                    'endpoints': {name: {'bind': self.endpoints[name][0], 'port': self.endpoints[name][1]}
                                  for name in LISTENERS},
                    'files': staged}
            receipt = {'schema': SCHEMA, 'owner': self.scope['owner'], 'challenge': secrets.token_hex(32),
                       'configuration_sha256': hashlib.sha256(canonical(plan)).hexdigest(),
                       'coordinator_process': server.process_identity(os.getpid()), **plan,
                       'listeners': listeners}
            self.known_files[self.receipt_path] = exclusive_write(
                self.receipt_path, canonical(receipt), self.uid)
            published, identity = read_private_json(self.receipt_path, self.uid)
            if published != receipt:
                raise ValueError('artifact coordinator receipt changed while publishing')
            self.receipt, self.receipt_identity = receipt, identity
            return self.verify(current_scope)
        except BaseException:
            self._stop_children()
            self._purge_known(partial=True)
            raise

    def _urls(self, receipt):
        result = {'schema': URL_SCHEMA, 'owner': receipt['owner'], 'releases': {}}
        guest = receipt['listeners']['guest']
        for role in ROLES:
            backend = receipt['listeners'][role + '-backend']
            by_kind = {}
            for listener in (backend, guest):
                for artifact in listener['artifacts']:
                    if role in artifact['roles']:
                        for kind in artifact['kinds']:
                            by_kind[kind] = (listener['server']['bind'], listener['server']['port'],
                                             artifact['filename'])
            if set(by_kind) != {'manifest', 'iso', 'closure', 'workstation'}:
                raise ValueError('artifact listener URLs are incomplete')
            def transport(kind):
                bind, port, filename = by_kind[kind]
                return f'http://{bind}:{port}/{filename}'
            result['releases'][role] = {
                'manifest_transport_url': transport('manifest'),
                'installer_iso_transport_url': transport('iso'),
                'package_transport_url': transport('closure'),
                'bundle_transport_url': transport('workstation'),
            }
        return result

    def verify(self, current_scope):
        self._scope(current_scope)
        if self.receipt is None or set(self.children) != set(LISTENERS):
            raise ValueError('artifact coordinator cannot adopt listener receipts')
        receipt, identity = read_private_json(self.receipt_path, self.uid)
        if receipt != self.receipt or receipt.get('schema') != SCHEMA or receipt.get('owner') != self.scope['owner']:
            raise ValueError('artifact coordinator receipt changed')
        if server.process_identity(os.getpid()) != receipt['coordinator_process']:
            raise ValueError('artifact coordinator process changed')
        plan = {key: receipt[key] for key in ('scope', 'releases', 'endpoints', 'files')}
        if (receipt['scope'] != self.scope
                or receipt['configuration_sha256'] != hashlib.sha256(canonical(plan)).hexdigest()
                or identity != self.receipt_identity):
            raise ValueError('artifact coordinator configuration changed')
        for name in LISTENERS:
            listener, child = receipt['listeners'][name], self.children[name]
            if child.process.poll() is not None or child.receipt != listener['server']:
                raise ValueError('artifact listener is not the retained direct child')
            listener_receipt, listener_identity = read_private_json(Path(listener['receipt']), self.uid)
            if (listener_receipt != listener['server']
                    or listener_identity != child.receipt_identity):
                raise ValueError('artifact listener receipt changed')
            config = Path(listener['config'])
            config_file = server.PinnedFile(config, self.uid, self._server_anchor)
            try:
                if (config_file.digest() != listener['server']['config_sha256']
                        or config_file.identity != listener['server']['config_metadata']
                        or config_file.ancestors != listener['server']['config_ancestors']):
                    raise ValueError('artifact listener configuration changed')
            finally:
                config_file.close()
            for artifact in listener['artifacts']:
                staged = server.PinnedFile(artifact['path'], self.uid, self._server_anchor)
                try:
                    if (staged.identity != artifact['metadata'] or staged.identity['size'] != artifact['size_bytes']
                            or staged.ancestors != artifact['ancestors']
                            or staged.digest() != artifact['sha256']):
                        raise ValueError('staged artifact changed')
                finally:
                    staged.close()
            self._validate_listener_receipt(name, listener['server'], config,
                                            listener['artifacts'], child)
        return self._urls(receipt)

    def _stop_children(self):
        errors = []
        for name in reversed(LISTENERS):
            child = self.children.get(name)
            if child is None or child.pidfd is None:
                continue
            try:
                child.stop()
            except BaseException as error:
                errors.append(error)
        if errors:
            raise errors[0]

    def _purge_known(self, *, partial=False):
        if not self.directory.exists() and not self.directory.is_symlink():
            return
        actual_files, actual_directories = set(), {self.directory}
        for root, directories, files in os.walk(self.directory, topdown=True, followlinks=False):
            root = Path(root)
            actual_directories.update(root / name for name in directories)
            actual_files.update(root / name for name in files)
        known_files, known_directories = set(self.known_files), set(self.known_directories)
        if (actual_files - known_files or actual_directories - known_directories
                or (not partial and (actual_files != known_files
                                     or actual_directories != known_directories))):
            raise ValueError('refusing to purge unknown or missing artifact coordinator state')
        for path in actual_files:
            info = os.lstat(path)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != FILE_MODE
                    or object_identity(info) != self.known_files[path]):
                raise ValueError('refusing to purge unknown or missing artifact coordinator state')
        for path in actual_directories:
            info = os.lstat(path)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid
                    or stat.S_IMODE(info.st_mode) != DEVICE_DIRECTORY_MODE
                    or directory_identity(info) != self.known_directories[path]):
                raise ValueError('refusing to purge unknown or missing artifact coordinator state')
        for path in sorted(actual_files, key=lambda value: len(value.parts), reverse=True):
            path.unlink()
        for path in sorted(actual_directories, key=lambda value: len(value.parts), reverse=True):
            path.rmdir()

    def cleanup(self, current_scope, *, purge=False):
        self._scope(current_scope)
        self._stop_children()
        if purge:
            self._purge_known()
        return True
