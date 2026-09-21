"""Private API and owned QEMU lifecycle shared by owned development qualification."""
import datetime
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import runpy

HELPERS = Path(__file__).resolve().parent
SCOPE = runpy.run_path(str(HELPERS / 'development-scope.py'))
HTTP = runpy.run_path(str(HELPERS / 'qualification_http.py'))


def private_state(path):
    signal.signal(signal.SIGTERM, lambda _number, _frame: (_ for _ in ()).throw(KeyboardInterrupt('qualification cancelled')))
    receipt = SCOPE['read_scope'](path)
    SCOPE['verify'](path, receipt['manage_origin'], receipt['bridge'])
    return path.resolve(strict=True)


class API:
    def __init__(self, state):
        private_state(state)
        self.origin = SCOPE['read_scope'](state)['manage_origin']
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError('Private credential-bearing redirect refused')
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        token_file = state / 'session'
        info = token_file.lstat()
        if token_file.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError('Qualification session must be a private owned ordinary file')
        self.token = token_file.read_text().strip()

    def __call__(self, path, body=None):
        if not path.startswith('/v1/') or path.startswith('//'):
            raise ValueError('Qualification API path is invalid')
        request = urllib.request.Request(self.origin + path,
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json',
                     'User-Agent': 'cybex-dev-qualification/1'},
            data=None if body is None else json.dumps(body).encode())
        return HTTP['request_json'](self.client, request, timeout=30,
                                    max_bytes=16 * 1024**2)


def stop(process):
    if process and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


class QMP:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(10)
        self.socket.connect(str(path))
        self.buffer = b''
        self.pending = []
        self.sequence = 0
        self.call('qmp_capabilities')

    def read(self, timeout):
        if select.select([self.socket], [], [], timeout)[0]:
            data = self.socket.recv(65536)
            if not data:
                raise ValueError('Owned QEMU monitor disconnected')
            self.buffer += data
        values = []
        while b'\n' in self.buffer:
            line, self.buffer = self.buffer.split(b'\n', 1)
            values.append(json.loads(line))
        return values

    def call(self, command, arguments=None):
        self.sequence += 1
        identity = self.sequence
        self.socket.sendall(json.dumps({'execute': command, 'arguments': arguments or {}, 'id': identity}).encode() + b'\n')
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            reply = None
            for value in self.read(1):
                if value.get('id') == identity:
                    reply = value
                if 'event' in value:
                    self.pending.append(value)
            # RESET can arrive after the command reply in the same read.
            # Preserve the whole batch before returning to the lifecycle.
            if reply is not None:
                if 'error' in reply:
                    raise ValueError('QEMU command failed: ' + str(reply['error']))
                return reply.get('return')
        raise ValueError('QEMU monitor command timed out')

    def events(self):
        events, self.pending = self.pending, []
        events += [v for v in self.read(0) if 'event' in v]
        return events


class Fixture:
    def __init__(self, state, directory, evidence):
        self.process = None
        self.monitor = None
        self.started = datetime.datetime.now(datetime.timezone.utc)
        private_state(state)
        self.scope = SCOPE['read_scope'](state)
        self.state = state
        self.tap = None
        if directory.is_symlink():
            raise ValueError('Fixture directory cannot be a symlink')
        self.directory = directory.resolve(strict=True)
        if self.directory.parent != state or self.directory.is_symlink():
            raise ValueError('Fixture must belong to this private run')
        identity = json.loads((self.directory / 'fixture.json').read_bytes())
        self.hardware = SCOPE['hardware_identity'](self.scope, 'appliance')
        if (identity['schema'] != 'cybex.james.qualification-fixture.v1'
                or identity['bridge'] != self.scope['bridge']
                or any(identity.get(key) != value for key, value in self.hardware.items())
                or identity['device_id'] != evidence['device_id']
                or identity['manifest_sha256'] != evidence['qualified_manifest_sha256']
                or not evidence['ok'] or not str(evidence['system_generation']).isdigit()):
            raise ValueError('Fixture and clean predecessor evidence differ')
        self.device = identity['device_id']
        for name in ['appliance.raw', 'OVMF_VARS.fd']:
            p = self.directory / name
            if not p.is_file() or p.is_symlink() or p.stat().st_uid != os.geteuid():
                raise ValueError('Invalid owned fixture disk')

    def __enter__(self):
        qmp = self.directory / 'qmp.sock'
        qmp.unlink(missing_ok=True)
        d = self.directory
        try:
            self.tap = SCOPE['tap'](self.state, self.scope['manage_origin'], self.scope['bridge'], 'appliance', True)
            self.process = subprocess.Popen(['qemu-system-x86_64', '-enable-kvm', '-machine', 'q35',
                '-cpu', 'host', '-smp', '4', '-m', os.environ.get('CYBEX_JAMES_QUALIFICATION_MEMORY_MIB', '18432'),
                '-uuid', self.hardware['uuid'],
                '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                '-drive', f'if=pflash,format=raw,unit=1,file={d}/OVMF_VARS.fd',
                '-drive', f'if=none,id=system,format=raw,file={d}/appliance.raw,cache=none',
                '-device', 'virtio-scsi-pci,id=scsi0', '-device', 'scsi-hd,drive=system,serial=' + self.hardware['serial'],
                '-device', 'i6300esb', '-watchdog-action', 'reset',
                '-netdev', 'tap,id=net0,ifname=' + self.tap + ',script=no,downscript=no', '-device', 'virtio-net-pci,netdev=net0,id=nic0,mac=' + self.hardware['mac'],
                '-display', 'none', '-serial', f'file:{d}/update-serial.log', '-qmp', f'unix:{qmp},server=on,wait=off'],
                start_new_session=True)
            for _ in range(100):
                if qmp.exists():
                    self.monitor = QMP(qmp)
                    return self
                if self.process.poll() is not None:
                    raise ValueError('Fixture QEMU exited')
                time.sleep(.1)
            raise ValueError('Fixture QEMU monitor unavailable')
        except BaseException:
            self.__exit__()
            raise

    def wait_ready(self, api):
        for _ in range(240):
            if self.process.poll() is not None:
                raise ValueError('Fixture QEMU exited before readiness')
            node = api(f'/v1/james/nodes/{self.device}')['node']
            seen = datetime.datetime.fromisoformat((node.get('james_reported_at') or '1970-01-01T00:00:00Z').replace('Z', '+00:00'))
            if seen > self.started and node.get('appliance_local_health', {}).get('status') == 'healthy':
                self.monitor.events()
                return node
            time.sleep(2)
        raise ValueError('Fixture failed to report healthy after boot')

    def __exit__(self, *args):
        stop(self.process)
        if self.monitor:
            self.monitor.socket.close()
        if self.tap:
            SCOPE['tap'](self.state, self.scope['manage_origin'], self.scope['bridge'], 'appliance', False)
            self.tap = None
