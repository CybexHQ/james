"""Root-private, bounded child access to the retained exact-origin fixture Owner.

Children never receive an alternate production URL or resolve its public name.
Every operation uses the Owner's live confinement checks and pinned TLS transport.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import sys
import threading

LIMIT = 24 * 1024**2


def read(stream):
    data = stream.readline(LIMIT + 1)
    if len(data) > LIMIT or not data.endswith(b'\n'):
        raise ValueError('isolated fixture RPC exceeded its bound')
    return json.loads(data)


def request(state, operation, **arguments):
    state = Path(state)
    info = state.lstat()
    endpoint = state / 'manage.sock'
    socket_info = endpoint.lstat()
    if (state.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700 or socket_info.st_uid != 0
            or not stat.S_ISSOCK(socket_info.st_mode) or stat.S_IMODE(socket_info.st_mode) != 0o600):
        raise ValueError('isolated fixture RPC must be root-private')
    data = (json.dumps({'operation': operation, **arguments}) + '\n').encode()
    if len(data) > LIMIT:
        raise ValueError('isolated fixture request exceeded its bound')
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(180)
        connection.connect(str(endpoint))
        pid, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0:
            raise ValueError('isolated fixture server is not root-owned')
        connection.sendall(data)
        result = read(connection.makefile('rb'))
    if result.get('ok') is not True:
        raise ValueError('isolated fixture operation failed; inspect private runner diagnostics')
    return result['value']


class Server:
    def __init__(self, owner):
        self.owner = owner
        self.path = owner.state / 'manage.sock'
        if self.path.exists() or self.path.is_symlink():
            raise ValueError('refusing to adopt an existing fixture socket')
        parent = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                _, uid, _ = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != 0:
                    return
                try:
                    value = parent.dispatch(read(self.rfile))
                    result = {'ok': True, 'value': value}
                except Exception as error:
                    # Request contents include signed media secrets; never echo them.
                    print('Isolated fixture RPC failed: ' + type(error).__name__, file=sys.stderr)
                    result = {'ok': False, 'value': None}
                data = (json.dumps(result) + '\n').encode()
                if len(data) > LIMIT:
                    data = b'{"ok":false,"value":null}\n'
                self.wfile.write(data)

        self.server = socketserver.UnixStreamServer(str(self.path), Handler)
        self.path.chmod(0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def dispatch(self, value):
        if not isinstance(value, dict):
            raise ValueError('invalid fixture request')
        operation = value.get('operation')
        if operation == 'api' and set(value) == {'operation', 'path', 'body'}:
            return self.owner.api(value['path'], value['body'])
        if operation == 'closure_url' and set(value) == {'operation', 'manifest_sha256'}:
            receipt = self.owner.verify()
            selected = receipt['selected_release']
            if value['manifest_sha256'] != receipt['releases'][selected]['manifest_sha256']:
                raise ValueError('closure request does not match the selected authenticated release')
            return receipt['artifact_transports']['releases'][selected]['package_transport_url']
        if operation == 'personalize' and set(value) == {'operation', 'path', 'secret'}:
            import re
            if not re.fullmatch(r'/v1/james/provisioning-sessions/[0-9a-f-]{36}/personalization-envelope', value['path']):
                raise ValueError('invalid personalization endpoint')
            receipt = self.owner.verify()
            from isolated_manage_config import read_file
            token = read_file(self.owner.state / 'session').decode().strip()
            response_headers = {}
            body = self.owner.client(receipt).request_bytes(value['path'], token=token,
                headers={'X-Cybex-James-Provisioning-Secret': value['secret']}, response_headers=response_headers)
            if len(body) != 8192:
                raise ValueError('personalization envelope has an invalid length')
            digest = response_headers.get('x-cybex-james-envelope-sha256')
            if digest != hashlib.sha256(body).hexdigest():
                raise ValueError('personalization response does not bind its envelope digest')
            return {'body': base64.b64encode(body).decode(), 'envelope_sha256': digest}
        if operation == 'allow_device' and set(value) == {'operation', 'session_id'}:
            session = self.owner.api('/v1/james/provisioning-sessions/' + str(__import__('uuid').UUID(value['session_id'])))
            self.owner.allow_device(session['reserved_device_id'])
            return None
        raise ValueError('unsupported fixture operation')

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.path.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('operation', choices=('api', 'personalize', 'allow-device', 'closure-url'))
    parser.add_argument('--path')
    parser.add_argument('--body')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--headers-output', type=Path)
    parser.add_argument('--session-id')
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    if args.operation == 'api':
        print(json.dumps(request(args.state_dir, 'api', path=args.path,
                                 body=json.loads(args.body) if args.body else None)))
    elif args.operation == 'closure-url':
        print(request(args.state_dir, 'closure_url', manifest_sha256=args.manifest_sha256))
    elif args.operation == 'personalize':
        secret = sys.stdin.readline(8193).strip()
        result = request(args.state_dir, 'personalize', path=args.path, secret=secret)
        body = base64.b64decode(result['body'], validate=True)
        with args.output.open('xb') as stream:
            stream.write(body)
        with args.headers_output.open('x') as stream:
            stream.write('x-cybex-james-envelope-sha256: ' + result['envelope_sha256'] + '\n')
    else:
        request(args.state_dir, 'allow_device', session_id=args.session_id)


if __name__ == '__main__':
    main()
