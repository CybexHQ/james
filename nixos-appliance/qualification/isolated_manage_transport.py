"""Pinned private peer with ordinary TLS hostname validation, before any bearer data."""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import urlsplit

MAXIMUM = 16 * 1024**2


def http_error_details(error):
    """Allow only fixed diagnostics across independently loaded helper modules."""
    status = getattr(error, 'status', None)
    classification = getattr(error, 'classification', None)
    if (type(status) is not int or not 100 <= status <= 599
            or classification not in ('http_error', 'configuration_command_busy', 'response_refused')
            or (200 <= status < 300 and classification != 'response_refused')
            or (classification == 'configuration_command_busy' and status != 409)):
        return None
    return {'status': status, 'classification': classification}


class ManageHTTPError(ValueError):
    """No response body, request path, credentials or arbitrary server text."""
    def __init__(self, status, classification='http_error'):
        self.status, self.classification = status, classification
        if http_error_details(self) is None:
            raise ValueError('invalid isolated Manage HTTP error')
        super().__init__(f'isolated Manage HTTP {status} ({classification})')

    @classmethod
    def from_response(cls, status, body):
        classification = 'http_error'
        if status == 409 and len(body) <= 8192:
            try:
                value = json.loads(body)
                message = value.get('error') if isinstance(value, dict) else None
                # These are the two exact Manage configuration-slot rejections.
                # Other conflicts (capabilities, assignment, release gates) stay fatal.
                if isinstance(message, str) and (message == 'a configuration command is already active for this device'
                        or re.fullmatch(r'configuration command [0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12} is already (?:pending|dispatched) for this device', message)):
                    classification = 'configuration_command_busy'
            except (ValueError, UnicodeError):
                pass
        return cls(status, classification)


def endpoint(receipt):
    origin = urlsplit(receipt['manage_origin'])
    peer = ipaddress.ip_address(receipt['peer_ipv4'])
    if (origin.scheme != 'https' or origin.netloc != origin.hostname or origin.path
            or origin.query or origin.fragment or peer.version != 4 or not peer.is_private
            or peer.is_loopback or peer.is_link_local
            or not re.fullmatch(r'[0-9a-f]{64}', receipt['certificate_sha256'])
            or not re.fullmatch(r'[0-9a-f]{64}', receipt['challenge'])):
        raise ValueError('isolated Manage transport receipt is invalid')
    return origin.hostname, str(peer)


class Transport:
    """Never resolves the origin, follows redirects, or reads proxy environment.

    The adapter's guard verification is mandatory. Each new TLS connection reads
    the fixture challenge before sending credentials on that same connection.
    A custom trust context exists only for local generated-certificate tests; it
    must still enforce both certificate-chain and hostname verification.
    """
    def __init__(self, receipt, verify_guard, *, context=None, connector=socket.create_connection):
        self.receipt = dict(receipt)
        self.hostname, self.peer = endpoint(receipt)
        self.verify_guard = verify_guard
        self.context = context or ssl.create_default_context()
        if self.context.verify_mode != ssl.CERT_REQUIRED or not self.context.check_hostname:
            raise ValueError('TLS certificate and hostname verification cannot be disabled')
        self.connector = connector

    @staticmethod
    def read(connection, response_headers=None):
        response = connection.getresponse()
        body = response.read(MAXIMUM + 1)
        if (len(body) > MAXIMUM
                or response.getheader('Location') is not None
                or response.getheader('Content-Encoding') not in {None, 'identity'}):
            raise ManageHTTPError(response.status, 'response_refused')
        if not 200 <= response.status < 300:
            raise ManageHTTPError.from_response(response.status, body)
        if response_headers is not None:
            response_headers.update({key.lower(): value for key, value in response.getheaders()})
        return body

    def connection(self):
        if self.verify_guard() is not True:
            raise ValueError('isolated Manage network ownership is not verified')
        raw = self.connector((self.peer, 443), timeout=30)
        connection = None
        try:
            if raw.getpeername()[0] != self.peer:
                raise ValueError('isolated Manage connection reached a different peer')
            secured = self.context.wrap_socket(raw, server_hostname=self.hostname)
            if (secured.getpeername()[0] != self.peer
                    or hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest()
                    != self.receipt['certificate_sha256']):
                secured.close()
                raise ValueError('isolated Manage TLS peer differs from the owned fixture')
            connection = http.client.HTTPConnection(self.hostname, 443, timeout=30)
            connection.auto_open = 0  # HTTPConnection must never reconnect through DNS.
            connection.sock = secured
            challenge = self.receipt['challenge']
            connection.request('GET', '/.well-known/cybex-qualification/' + challenge,
                               headers={'Host': self.hostname, 'Connection': 'keep-alive'})
            expected = {'owner': self.receipt['owner'], 'challenge': challenge,
                        'manage_origin': self.receipt['manage_origin']}
            if json.loads(self.read(connection)) != expected or connection.sock is None:
                raise ValueError('isolated Manage challenge failed before credentials')
            return connection
        except BaseException:
            if connection is not None:
                connection.close()
            raw.close()
            raise

    def request_bytes(self, path, body=None, token=None, headers=None, response_headers=None):
        if (not isinstance(path, str) or not path.startswith('/v1/') or '\\' in path
                or any(ord(c) < 33 or ord(c) > 126 for c in path) or '#' in path):
            raise ValueError('isolated Manage API path is invalid')
        connection = self.connection()
        try:
            extra = headers
            headers = {'Host': self.hostname, 'Content-Type': 'application/json', 'Connection': 'close'}
            if token is not None:
                if not isinstance(token, str) or not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
                    raise ValueError('invalid isolated fixture session')
                headers['Authorization'] = 'Bearer ' + token
            if extra:
                if set(extra) != {'X-Cybex-James-Provisioning-Secret'} or any(
                        not isinstance(v, str) or not v or any(ord(c) < 33 or ord(c) > 126 for c in v)
                        for v in extra.values()):
                    raise ValueError('invalid isolated personalization header')
                headers.update(extra)
            connection.request('GET' if body is None else 'POST', path,
                               body=None if body is None else json.dumps(body).encode(), headers=headers)
            data = self.read(connection, response_headers)
            return data
        finally:
            connection.close()

    def request(self, path, body=None, token=None):
        data = self.request_bytes(path, body, token)
        return json.loads(data) if data else None
