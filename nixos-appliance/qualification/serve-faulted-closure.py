#!/usr/bin/env python3
"""Private Q03 transport fault: preserve signed files and alter response bytes only."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import stat
import threading


def private_control(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 32):
            raise ValueError('Fault transport control must be a private owned ordinary file')
        mode = stream.read(33).strip()
    if mode not in {b'corrupt', b'clean'}:
        raise ValueError('Fault transport mode must be explicit')
    return mode.decode()


class VerifiedFile:
    def __init__(self, path, expected_sha256, expected_size):
        self.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.info = os.fstat(self.fd)
            if (not stat.S_ISREG(self.info.st_mode) or self.info.st_nlink != 1
                    or self.info.st_size != expected_size or expected_size < 1):
                raise ValueError('Fault transport requires the exact ordinary signed artifact')
            self.sha256 = expected_sha256
            digest = hashlib.sha256()
            for body in self.chunks('clean'):
                digest.update(body)
            if digest.hexdigest() != expected_sha256:
                raise ValueError('Original artifact differs from the signed descriptor')
            self.sha256 = expected_sha256
        except BaseException:
            os.close(self.fd)
            raise

    def unchanged(self):
        now = os.fstat(self.fd)
        if (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns, now.st_ctime_ns) != (
                self.info.st_dev, self.info.st_ino, self.info.st_size, self.info.st_mtime_ns, self.info.st_ctime_ns):
            raise ValueError('Signed source artifact changed during fault qualification')

    def chunks(self, mode):
        if mode not in {'corrupt', 'clean'}:
            raise ValueError('Unknown fault mode')
        self.unchanged()
        # A stable non-header offset isolates digest admission, while the exact
        # byte count and every signed on-disk byte remain unchanged.
        fault_offset = min(1024 * 1024 + 17, self.info.st_size - 1)
        offset = 0
        original_digest = hashlib.sha256()
        while offset < self.info.st_size:
            body = os.pread(self.fd, min(1024**2, self.info.st_size - offset), offset)
            if not body:
                raise ValueError('Original artifact ended during response')
            original_digest.update(body)
            if mode == 'corrupt' and offset <= fault_offset < offset + len(body):
                index = fault_offset - offset
                body = body[:index] + bytes([body[index] ^ 1]) + body[index + 1:]
            yield body
            offset += len(body)
        self.unchanged()
        if original_digest.hexdigest() != self.sha256:
            raise ValueError('Signed original bytes changed during fault response')

    def close(self):
        os.close(self.fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--file', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--size', type=int, required=True)
    parser.add_argument('--port-file', type=Path, required=True)
    parser.add_argument('--control', type=Path, required=True)
    parser.add_argument('--receipts', type=Path, required=True)
    args = parser.parse_args()
    address = ipaddress.ip_address(args.bind)
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_unspecified:
        raise ValueError('Fault transport must bind a private IPv4 qualification bridge')
    private_control(args.control)
    original = VerifiedFile(args.file, args.sha256, args.size)
    receipt_fd = os.open(args.receipts, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def headers(self):
            if self.path != '/' + args.file.name:
                self.send_error(404); return False
            original.unchanged()
            self.send_response(200)
            self.send_header('Content-Length', str(original.info.st_size))
            self.send_header('Content-Type', 'application/zstd')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            return True

        def do_HEAD(self):
            self.headers()

        def do_GET(self):
            mode = private_control(args.control)
            if not self.headers(): return
            digest = hashlib.sha256(); count = 0; complete = False
            try:
                for body in original.chunks(mode):
                    self.wfile.write(body)
                    digest.update(body); count += len(body)
                self.wfile.flush()
                complete = True
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                receipt = {'mode': mode, 'complete': complete, 'bytes': count,
                           'response_sha256': digest.hexdigest(), 'original_sha256': original.sha256}
                with lock:
                    os.write(receipt_fd, (json.dumps(receipt, sort_keys=True) + '\n').encode())
                    os.fsync(receipt_fd)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer((args.bind, 0), Handler)
    server.daemon_threads = True
    args.port_file.write_text(str(server.server_port) + '\n'); args.port_file.chmod(0o600)
    try:
        server.serve_forever(poll_interval=.25)
    finally:
        server.server_close(); original.close(); os.close(receipt_fd)


if __name__ == '__main__': main()
