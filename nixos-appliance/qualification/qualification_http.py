"""Bounded read-only HTTP retries for development qualification helpers."""
import errno
import http.client
import json
import socket
import ssl
import time
import urllib.error


GET_ATTEMPTS = 4
# 525 is an authenticated gateway response for an upstream handshake failure.
# Client certificate validation and gateway invalid-origin-certificate 526 stay fatal.
RETRYABLE_STATUS = frozenset({408, 429, 502, 503, 504, 525})
RETRYABLE_ERRNOS = frozenset({
    errno.ECONNABORTED,
    errno.ECONNREFUSED,
    errno.ECONNRESET,
    errno.EHOSTUNREACH,
    errno.ENETRESET,
    errno.ENETUNREACH,
    errno.EPIPE,
    errno.ETIMEDOUT,
})


def _transient(error):
    if isinstance(error, urllib.error.HTTPError):
        return error.code in RETRYABLE_STATUS
    if isinstance(error, urllib.error.URLError):
        return _transient(error.reason)
    if isinstance(error, ssl.SSLCertVerificationError):
        return False
    if isinstance(error, ssl.SSLEOFError):
        return True
    if isinstance(error, http.client.IncompleteRead):
        return True
    if isinstance(error, (TimeoutError, ConnectionError)):
        return True
    if isinstance(error, socket.gaierror):
        return error.errno == socket.EAI_AGAIN
    return isinstance(error, OSError) and error.errno in RETRYABLE_ERRNOS


def request_json(client, request, *, timeout, max_bytes, sleep=time.sleep):
    """Read one capped JSON response, retrying transient GET failures only."""
    attempts = GET_ATTEMPTS if request.get_method() == 'GET' else 1
    for attempt in range(attempts):
        try:
            with client.open(request, timeout=timeout) as response:
                data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError('Qualification API response exceeded its bound')
            return json.loads(data) if data else None
        except Exception as error:
            if attempt + 1 == attempts or not _transient(error):
                raise
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            sleep(1)
