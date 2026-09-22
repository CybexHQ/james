"""Retained TCP forwarding; TLS terminates at the owned fixture or approved upstream."""
import importlib.util
from pathlib import Path

import ipaddress
import os
import select
import socket
import socketserver
import threading


_spec = importlib.util.spec_from_file_location('fixture_tls_client_hello', Path(__file__).with_name('tls_client_hello.py'))
egress = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(egress)

class Proxy:
    def __init__(self, peer, target, *, hostname=None, upstream_hosts=(), _test_port=443):
        for address in (peer, target):
            parsed = ipaddress.ip_address(address)
            if parsed.version != 4 or not parsed.is_private or parsed.is_unspecified:
                raise ValueError('TLS forwarding requires exact private IPv4 endpoints')
        self.peer, self.target = peer, target
        self.hostname = hostname
        self.upstream_hosts = egress.hosts(list(upstream_hosts))
        if self.upstream_hosts and (not hostname or hostname in self.upstream_hosts):
            raise ValueError('fixture origin must be distinct from its upstream hosts')
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.connections = set()
        self.slots = threading.BoundedSemaphore(64)
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                if not owner.slots.acquire(blocking=False):
                    return
                upstream = None
                try:
                    with owner.lock:
                        if owner.stopped.is_set():
                            return
                        owner.connections.add(self.request)
                    destination, initial = (owner.target, 8443), b''
                    if owner.upstream_hosts:
                        hostname, initial = egress.receive(self.request)
                        if hostname != owner.hostname:
                            destination = egress.public_endpoint(hostname, owner.upstream_hosts)
                    upstream = socket.create_connection(destination, timeout=5)
                    if initial:
                        upstream.sendall(initial)
                    with owner.lock:
                        if owner.stopped.is_set():
                            return
                        owner.connections.add(upstream)
                    self.request.settimeout(5)
                    while not owner.stopped.is_set():
                        readable, _, _ = select.select([self.request, upstream], [], [], 30)
                        if not readable:
                            return
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            (upstream if source is self.request else self.request).sendall(data)
                except (OSError, ValueError, UnicodeError):
                    pass  # Broken client streams never expose plaintext or credentials.
                finally:
                    with owner.lock:
                        owner.connections.discard(self.request)
                        owner.connections.discard(upstream)
                    if upstream is not None:
                        upstream.close()
                    owner.slots.release()

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            block_on_close = False
            allow_reuse_address = True

        self.server = Server((peer, _test_port), Handler)
        self.identity = os.fstat(self.server.fileno())
        self.address = self.server.socket.getsockname()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def verify(self, peer, target, *, hostname=None, upstream_hosts=()):
        if self.stopped.is_set() or not self.thread.is_alive() or (peer, target) != (self.peer, self.target):
            raise ValueError('owned TLS forwarder is unavailable or changed')
        if (hostname, tuple(upstream_hosts)) != (self.hostname, self.upstream_hosts):
            raise ValueError('owned TLS upstream policy changed')
        current = os.fstat(self.server.fileno())
        if ((current.st_dev, current.st_ino) != (self.identity.st_dev, self.identity.st_ino)
                or self.server.socket.getsockname() != self.address):
            raise ValueError('owned TLS listener changed')
        return True

    def close(self):
        self.stopped.set()
        with self.lock:
            for connection in self.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
