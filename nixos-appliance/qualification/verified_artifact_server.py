#!/usr/bin/env python3
"""Confined HTTP transport for public artifact specs already verified by the owner.

The CLI accepts a root-owned config and root-owned, safely staged artifact files.
It checks byte identities, not release signatures: the fixture owner must derive
specs from verified signed descriptors. No credentials belong in this config.
An unprivileged container can read root-owned read-only mounts; its no-replace
0600 receipt belongs to the serving UID, in that UID's private output directory.
Internal _test_* parameters permit anchored temporary files and loopback sockets;
none are exposed by the CLI. This module does not create containers or networking.
Consumers must still verify signed hashes: a concurrently writing root process
is not cryptographically excluded from changing an inode during streaming.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import stat
import threading
import time
import uuid

SCHEMA = 'cybex.qualification.artifact-server-config.v1'
RECEIPT_SCHEMA = 'cybex.qualification.artifact-server-receipt.v1'
MAX_CONFIG = 65536
MAX_ARTIFACTS = 16
MAX_ARTIFACT_SIZE = 8 * 1024 ** 3
CHUNK = 1024 * 1024
MAX_WORKERS = 8
SOCKET_TIMEOUT = 10
REQUEST_TIMEOUT = 600
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
RFC1918 = tuple(ipaddress.ip_network(value) for value in
               ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def metadata(info):
    return {name: getattr(info, 'st_' + name) for name in
            ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


def absolute_path(value):
    if not isinstance(value, str) or not value.startswith('/') or str(Path(value)) != value:
        raise ValueError('artifact path is not canonical absolute')
    if any(part in ('.', '..') for part in value.split('/')[1:]):
        raise ValueError('artifact path contains unsafe components')
    return Path(value)


def _directory(info, uid):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid)
            or info.st_mode & 0o022):
        raise ValueError('artifact ancestor is unsafe')


def open_parent(path, uid, anchor=Path('/')):
    """Walk directories with nofollow descriptors; never resolve symlinks."""
    path, anchor = absolute_path(str(path)), absolute_path(str(anchor))
    parts = path.relative_to(anchor).parts
    if not parts:
        raise ValueError('artifact path must name a file')
    fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    ancestors = []
    try:
        for component in (None, *parts[:-1]):
            if component is not None:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            _directory(info, uid)
            ancestors.append({key: getattr(info, 'st_' + key)
                              for key in ('dev', 'ino', 'uid', 'gid', 'mode')})
        return fd, parts[-1], ancestors
    except BaseException:
        os.close(fd)
        raise


def open_source(path, uid, anchor):
    parent, name, ancestors = open_parent(path, uid, anchor)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_nlink != 1 or info.st_mode & 0o022):
            raise ValueError('artifact source is unsafe')
        return fd, metadata(info), ancestors
    except BaseException:
        os.close(fd)
        raise


class PinnedFile:
    def __init__(self, path, uid=0, anchor=Path('/')):
        self.path, self.uid, self.anchor = absolute_path(str(path)), uid, anchor
        self.fd, self.identity, self.ancestors = open_source(self.path, uid, anchor)

    def check(self):
        if metadata(os.fstat(self.fd)) != self.identity:
            raise ValueError('artifact source changed')
        fd, identity, ancestors = open_source(self.path, self.uid, self.anchor)
        os.close(fd)
        if identity != self.identity or ancestors != self.ancestors:
            raise ValueError('artifact source was replaced')

    def digest(self, deadline=None):
        digest = hashlib.sha256()
        offset = 0
        while offset < self.identity['size']:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError('artifact verification deadline exceeded')
            data = self.read(offset, min(CHUNK, self.identity['size'] - offset))
            if not data:
                raise ValueError('artifact source was truncated')
            digest.update(data)
            offset += len(data)
        self.check()
        return digest.hexdigest()

    def read(self, offset, size):
        if metadata(os.fstat(self.fd)) != self.identity:
            raise ValueError('artifact source changed')
        data = os.pread(self.fd, size, offset)
        if metadata(os.fstat(self.fd)) != self.identity:
            raise ValueError('artifact source changed during read')
        return data

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate configuration key')
        result[key] = value
    return result


def endpoint(bind, port, test=False):
    try:
        ip = ipaddress.IPv4Address(bind)
    except (ipaddress.AddressValueError, TypeError):
        raise ValueError('artifact listener address is invalid') from None
    if str(ip) != bind or not (any(ip in network for network in RFC1918)
                              or (test and ip.is_loopback)):
        raise ValueError('artifact listener must bind an RFC1918 IPv4 literal')
    if type(port) is not int or not (0 if test else 1) <= port <= 65535:
        raise ValueError('artifact listener port is invalid')
    return bind, port


def process_identity(pid):
    if type(pid) is not int or pid <= 0:
        raise ValueError('artifact process identity is invalid')
    root = Path('/proc') / str(pid)
    fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    executable = (root / 'exe').stat()
    namespace = (root / 'ns/pid').stat()
    return {'pid': pid, 'start_ticks': int(fields[19]),
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'uid': root.stat().st_uid,
            'exe_dev': executable.st_dev, 'exe_ino': executable.st_ino,
            'pid_namespace_dev': namespace.st_dev, 'pid_namespace_ino': namespace.st_ino,
            'cmdline_sha256': hashlib.sha256((root / 'cmdline').read_bytes()).hexdigest()}


def publish_receipt(path, receipt, *, anchor=Path('/')):
    uid = os.geteuid()
    parent, name, _ = open_parent(path, uid, anchor)
    temporary = '.artifact-receipt-' + secrets.token_hex(16)
    try:
        info = os.fstat(parent)
        if info.st_uid != uid or info.st_mode & 0o077:
            raise ValueError('artifact receipt directory must be private and owned')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, 'wb') as output:
                output.write(canonical(receipt))
                output.flush()
                os.fsync(output.fileno())
            # link is atomic and refuses replacement, unlike rename/replace.
            os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent,
                    follow_symlinks=False)
        finally:
            os.unlink(temporary, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


class ArtifactServer(ThreadingHTTPServer):
    daemon_threads = False
    request_queue_size = MAX_WORKERS
    # Consecutive isolated phases use the same fixed endpoint. Reclaim closed
    # connections in TIME_WAIT while retaining exclusive ownership of live ports.
    allow_reuse_address = True
    allow_reuse_port = False

    def __init__(self, config_path, *, _test_uid=None, _test_anchor=None, _test_loopback=False):
        self.sources = []
        self.artifacts = {}
        self.slots = threading.BoundedSemaphore(MAX_WORKERS)
        self.sockets = {}
        self.sockets_lock = threading.Lock()
        uid = 0 if _test_uid is None else _test_uid
        anchor = Path('/') if _test_anchor is None else Path(_test_anchor)
        try:
            self.config = PinnedFile(config_path, uid, anchor)
            self.sources.append(self.config)
            if not 0 < self.config.identity['size'] <= MAX_CONFIG:
                raise ValueError('artifact configuration exceeds bound')
            verification_deadline = time.monotonic() + REQUEST_TIMEOUT
            body = self.config.read(0, self.config.identity['size'])
            self.config.check()
            self.config.expected_digest = hashlib.sha256(body).hexdigest()
            value = json.loads(body, object_pairs_hook=_unique_object)
            if not isinstance(value, dict) or set(value) != {'schema', 'scope_owner', 'bind', 'port', 'artifacts'}:
                raise ValueError('artifact configuration shape is invalid')
            if (value['schema'] != SCHEMA or not isinstance(value['scope_owner'], str)
                    or str(uuid.UUID(value['scope_owner'])) != value['scope_owner']):
                raise ValueError('artifact configuration identity is invalid')
            if uuid.UUID(value['scope_owner']).int == 0:
                raise ValueError('artifact scope owner must be nonzero')
            address = endpoint(value['bind'], value['port'], _test_loopback)
            specs = value['artifacts']
            if not isinstance(specs, list) or not 1 <= len(specs) <= MAX_ARTIFACTS:
                raise ValueError('artifact count exceeds bound')
            evidence = []
            for spec in specs:
                if (not isinstance(spec, dict) or set(spec) != {'filename', 'path', 'sha256', 'size_bytes'}
                        or not isinstance(spec['filename'], str) or not NAME.fullmatch(spec['filename'])
                        or not isinstance(spec['sha256'], str) or not SHA.fullmatch(spec['sha256'])
                        or type(spec['size_bytes']) is not int or not 0 < spec['size_bytes'] <= MAX_ARTIFACT_SIZE
                        or spec['filename'] in self.artifacts):
                    raise ValueError('artifact spec is invalid')
                source = PinnedFile(spec['path'], uid, anchor)
                self.sources.append(source)
                if source.identity['size'] != spec['size_bytes'] or source.digest(verification_deadline) != spec['sha256']:
                    raise ValueError('artifact bytes differ from verified spec')
                source.expected_digest = spec['sha256']
                self.artifacts[spec['filename']] = source
                evidence.append({**spec, 'metadata': source.identity, 'ancestors': source.ancestors})
            for source in self.sources:
                source.check()
            self.receipt = {'schema': RECEIPT_SCHEMA, 'scope_owner': value['scope_owner'],
                            'server_id': secrets.token_hex(32), 'challenge': secrets.token_hex(32),
                            'config_sha256': hashlib.sha256(body).hexdigest(),
                            'config_path': str(self.config.path), 'config_metadata': self.config.identity,
                            'config_ancestors': self.config.ancestors, 'artifacts': evidence,
                            'process': process_identity(os.getpid()), 'receipt_uid': os.geteuid()}
            # No socket is constructed until every source has passed verification.
            super().__init__(address, Handler)
            self.receipt.update(bind=address[0], port=self.server_port)
            self.challenge_path = '/.well-known/cybex-artifact-server/' + self.receipt['server_id'] + '/' + self.receipt['challenge']
            self.ready_body = canonical({key: self.receipt[key] for key in
                                         ('scope_owner', 'server_id', 'challenge', 'config_sha256', 'process', 'bind', 'port')})
        except BaseException:
            if hasattr(self, 'socket'):
                self.socket.close()
            for source in self.sources:
                source.close()
            raise

    def process_request(self, request, client_address):
        request.settimeout(SOCKET_TIMEOUT)
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self.sockets_lock:
            self.sockets[request] = time.monotonic() + REQUEST_TIMEOUT
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.sockets_lock:
                self.sockets.pop(request, None)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        timer = threading.Timer(REQUEST_TIMEOUT, self.shutdown_request, args=(request,))
        timer.daemon = True
        timer.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            with self.sockets_lock:
                self.sockets.pop(request, None)
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # No source paths, client input or tracebacks on public logs.

    def server_close(self):
        with self.sockets_lock:
            for request in tuple(self.sockets):
                self.shutdown_request(request)
        super().server_close()
        for source in self.sources:
            source.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'CybexArtifactFixture/1'
    sys_version = ''

    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self.respond(405 if code == 501 else code, b'')

    def respond(self, status, body, *, content_range=None, length=None):
        self.close_connection = True
        self.response_started = True
        self.send_response(status)
        self.send_header('Content-Length', str(len(body) if length is None else length))
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Connection', 'close')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Accept-Ranges', 'bytes')
        if status == 405:
            self.send_header('Allow', 'GET, HEAD')
        if content_range is not None:
            self.send_header('Content-Range', content_range)
        self.end_headers()
        if getattr(self, 'command', None) != 'HEAD' and body:
            self.wfile.write(body)

    def do_GET(self):
        self.serve()

    def do_HEAD(self):
        self.serve()

    def serve(self):
        words = self.requestline.split(' ')
        if len(words) != 3 or words[1] != self.path:
            self.respond(404, b'')
            return
        try:
            challenge = self.path == self.server.challenge_path
            source = self.server.artifacts.get(self.path[1:]) if self.path.startswith('/') else None
            if not challenge and source is None:
                self.respond(404, b'')
                return
            # Metadata alone can miss a same-size write with restored mtime in
            # one ctime tick. Rehash config plus the requested artifact before
            # headers; readiness checks the full original artifact set.
            with self.server.sockets_lock:
                deadline = self.server.sockets[self.connection]
            checked = self.server.sources if challenge else [self.server.config, source]
            for pinned in checked:
                pinned.check()
                if pinned.digest(deadline) != pinned.expected_digest:
                    raise ValueError('artifact source digest changed')
            if challenge:
                if self.headers.get_all('Range'):
                    self.respond(416, b'', content_range=f'bytes */{len(self.server.ready_body)}')
                else:
                    self.respond(200, self.server.ready_body)
                return
            size, offset = source.identity['size'], 0
            ranges = self.headers.get_all('Range', [])
            if ranges:
                match = re.fullmatch(r'bytes=(0|[1-9][0-9]{0,19})-', ranges[0]) if len(ranges) == 1 else None
                if match is None or int(match[1]) >= size:
                    self.respond(416, b'', content_range=f'bytes */{size}')
                    return
                offset = int(match[1])
            self.respond(206 if ranges else 200, b'', length=size - offset,
                         content_range=f'bytes {offset}-{size - 1}/{size}' if ranges else None)
            if self.command == 'HEAD':
                return
            while offset < size:
                body = source.read(offset, min(CHUNK, size - offset))
                if not body:
                    raise ValueError('artifact truncated during response')
                self.wfile.write(body)
                offset += len(body)
        except (OSError, ValueError):
            # Once headers/body started, closing yields a visibly truncated
            # response; never append an error document to signed artifact bytes.
            self.close_connection = True
            if not getattr(self, 'response_started', False):
                self.respond(503, b'')


def verify_server(receipt, *, _test_loopback=False):
    if receipt.get('schema') != RECEIPT_SCHEMA:
        raise ValueError('artifact receipt schema is invalid')
    if process_identity(receipt['process']['pid']) != receipt['process']:
        raise ValueError('artifact server process changed')
    endpoint(receipt['bind'], receipt['port'], _test_loopback)
    for key in ('server_id', 'challenge', 'config_sha256'):
        if not isinstance(receipt.get(key), str) or not SHA.fullmatch(receipt[key]):
            raise ValueError('artifact receipt identity is invalid')
    connection = http.client.HTTPConnection(receipt['bind'], receipt['port'], timeout=REQUEST_TIMEOUT)
    try:
        connection.request('GET', '/.well-known/cybex-artifact-server/' + receipt['server_id'] + '/' + receipt['challenge'])
        response = connection.getresponse()
        body = response.read(4097)
        expected = canonical({key: receipt[key] for key in
                              ('scope_owner', 'server_id', 'challenge', 'config_sha256', 'process', 'bind', 'port')})
        if response.status != 200 or len(body) > 4096 or body != expected:
            raise ValueError('artifact server challenge did not match receipt')
    finally:
        connection.close()
    if process_identity(receipt['process']['pid']) != receipt['process']:
        raise ValueError('artifact server process changed during verification')


def stop_owned_child(child, receipt):
    """Stop only the supplied direct child, never a PID taken alone from JSON."""
    if child.pid != receipt['process']['pid'] or child.poll() is not None:
        raise ValueError('artifact server is not the running owned child')
    fd = os.pidfd_open(child.pid)
    try:
        # Readiness can legitimately fail after an artifact is corrupted.
        # Direct-child ownership plus the pinned process identity is sufficient
        # to stop that exact child; never signal a replacement PID or require a
        # still-healthy artifact listener in order to clean up a failed one.
        if process_identity(child.pid) != receipt['process']:
            raise ValueError('artifact child process identity changed')
        signal.pidfd_send_signal(fd, signal.SIGTERM)
        try:
            child.wait(timeout=SOCKET_TIMEOUT)
        except subprocess.TimeoutExpired:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            child.wait(timeout=SOCKET_TIMEOUT)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    server = ArtifactServer(args.config)
    try:
        publish_receipt(args.receipt, server.receipt)
        def stop(_signum, _frame):
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, stop)
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Verified artifact server refused unsafe input or failed') from None
