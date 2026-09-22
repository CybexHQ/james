"""Bounded SNI routing for explicit upstream Nix downloads; never terminate TLS."""
import ipaddress
import socket
import time

UPSTREAM_HOSTS = ('api.github.com', 'cache.nixos.org', 'codeload.github.com', 'github.com')
MAXIMUM = 65536


def hosts(value):
    if value not in ([], list(UPSTREAM_HOSTS)):
        raise ValueError('fixture upstreams must be the exact reviewed Nix download hosts or empty')
    return tuple(value)


def server_name(body):
    """Parse one complete ClientHello body, rejecting ambiguous name extensions."""
    position = 0
    def take(length):
        nonlocal position
        if length < 0 or position + length > len(body):
            raise ValueError('truncated TLS ClientHello')
        value = body[position:position + length]
        position += length
        return value
    def number(length):
        return int.from_bytes(take(length), 'big')
    take(34)
    session_size = number(1)
    if session_size > 32:
        raise ValueError('invalid TLS session identifier')
    take(session_size)
    cipher_size = number(2)
    if cipher_size < 2 or cipher_size % 2:
        raise ValueError('invalid TLS cipher list')
    take(cipher_size)
    compression_size = number(1)
    if not compression_size:
        raise ValueError('invalid TLS compression list')
    take(compression_size)
    extension_size = number(2)
    if extension_size != len(body) - position:
        raise ValueError('invalid TLS extension bounds')
    hostname = None
    while position < len(body):
        kind, length = number(2), number(2)
        extension = take(length)
        if kind != 0:
            continue
        if hostname is not None or len(extension) < 5:
            raise ValueError('ambiguous TLS server name')
        if (int.from_bytes(extension[:2], 'big') != len(extension) - 2 or extension[2] != 0
                or int.from_bytes(extension[3:5], 'big') != len(extension) - 5):
            raise ValueError('invalid TLS server name list')
        hostname = extension[5:].decode('ascii').lower()
        if not hostname or len(hostname) > 253:
            raise ValueError('invalid TLS server name')
    if hostname is None:
        raise ValueError('TLS server name is required')
    return hostname


def receive(connection):
    deadline = time.monotonic() + 10
    wire, handshake = bytearray(), bytearray()
    def take(length):
        value = bytearray()
        while len(value) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('TLS routing deadline exceeded')
            connection.settimeout(remaining)
            chunk = connection.recv(length - len(value))
            if not chunk:
                raise ValueError('incomplete TLS routing handshake')
            value.extend(chunk)
        return bytes(value)
    while len(wire) < MAXIMUM:
        header = take(5)
        length = int.from_bytes(header[3:], 'big')
        if header[0] != 22 or header[1] != 3 or not 0 < length <= 16384 or len(wire) + 5 + length > MAXIMUM:
            raise ValueError('invalid TLS routing record')
        record = take(length)
        wire.extend(header + record)
        handshake.extend(record)
        if len(handshake) >= 4:
            total = int.from_bytes(handshake[1:4], 'big') + 4
            if handshake[0] != 1 or total > MAXIMUM:
                raise ValueError('TLS routing requires a bounded ClientHello')
            if len(handshake) >= total:
                return server_name(handshake[4:total]), bytes(wire)
    raise ValueError('TLS routing handshake exceeded bound')


def public_endpoint(hostname, allowed, resolver=socket.getaddrinfo):
    if hostname not in allowed:
        raise ValueError('TLS upstream is not approved')
    answers = resolver(hostname, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
    addresses = [answer[4][0] for answer in answers]
    parsed = [ipaddress.ip_address(address) for address in addresses]
    if not parsed or any(address.version != 4 or not address.is_global or address.is_multicast
                         or address.is_reserved for address in parsed):
        raise ValueError('TLS upstream resolution is not exclusively public')
    return addresses[0], 443
