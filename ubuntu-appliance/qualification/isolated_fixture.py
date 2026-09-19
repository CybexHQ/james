"""Private API and owned QEMU lifecycle shared by production qualification."""
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

STATE_ROOT = Path('/var/lib/cybex-james-qualification')
HELPERS = Path(__file__).resolve().parent


def private_state(path):
    state = path.resolve(strict=True)
    if (os.geteuid() != 0 or state.parent != STATE_ROOT or state.stat().st_uid != 0
            or state.stat().st_mode & 0o077 or path.is_symlink()):
        raise ValueError('Expected private root-owned qualification state')
    receipt = json.loads((state / 'isolation.json').read_bytes())
    if (receipt['schema'] != 'cybex.james.isolated-manage.v1'
            or receipt['origin'] != 'https://manage.cybex.net'
            or receipt['bridge'] != 'jamesqual0'
            or receipt['private_database'] != str(state / 'postgres')):
        raise ValueError('Invalid private database ownership receipt')
    return state


def enter_namespace(state, entered):
    if not entered:
        os.execvp('unshare', ['unshare', '--mount', '--propagation', 'private',
                            sys.executable, str(Path(sys.argv[0]).resolve()), *sys.argv[1:], '--namespace'])
    if os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'):
        raise ValueError('Expected private mount namespace')
    subprocess.run(['mount', '--bind', str(state / 'hosts'), '/etc/hosts'], check=True)
    subprocess.run(['mount', '-o', 'remount,bind,ro', '/etc/hosts'], check=True)
    if {v[4][0] for v in socket.getaddrinfo('manage.cybex.net', 443)} != {'10.62.57.1'}:
        raise ValueError('Private Manage DNS is not isolated')


class API:
    def __init__(self, state):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError('Private credential-bearing redirect refused')
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.token = (state / 'session').read_text().strip()

    def __call__(self, path, body=None):
        request = urllib.request.Request('https://manage.cybex.net' + path,
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'},
            data=None if body is None else json.dumps(body).encode())
        with self.client.open(request, timeout=30) as response:
            value = response.read()
        return json.loads(value) if value else None


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
            for value in self.read(1):
                if value.get('id') == identity:
                    if 'error' in value:
                        raise ValueError('QEMU command failed: ' + str(value['error']))
                    return value.get('return')
                if 'event' in value:
                    self.pending.append(value)
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
        self.directory = directory.resolve(strict=True)
        if self.directory.parent != state or self.directory.is_symlink():
            raise ValueError('Fixture must belong to this private run')
        identity = json.loads((self.directory / 'fixture.json').read_bytes())
        if (identity['schema'] != 'cybex.james.qualification-fixture.v1'
                or identity['bridge'] != 'jamesqual0' or identity['mac'] != '52:54:00:c7:be:01'
                or identity['device_id'] != evidence['device_id']
                or identity['manifest_sha256'] != evidence['qualified_manifest_sha256']
                or not evidence['ok'] or str(evidence['root_generation']) != '0'):
            raise ValueError('Fixture and clean predecessor evidence differ')
        self.device = identity['device_id']
        for name in ['appliance.raw', 'OVMF_VARS.fd']:
            p = self.directory / name
            if not p.is_file() or p.is_symlink() or p.stat().st_uid != 0:
                raise ValueError('Invalid owned fixture disk')

    def __enter__(self):
        qmp = self.directory / 'qmp.sock'
        qmp.unlink(missing_ok=True)
        d = self.directory
        self.process = subprocess.Popen(['qemu-system-x86_64', '-enable-kvm', '-machine', 'q35,smm=on',
            '-cpu', 'host', '-smp', '4', '-m', '32768', '-global', 'driver=cfi.pflash01,property=secure,value=on',
            '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd',
            '-drive', f'if=pflash,format=raw,unit=1,file={d}/OVMF_VARS.fd',
            '-drive', f'if=none,id=system,format=raw,file={d}/appliance.raw,cache=none',
            '-device', 'virtio-scsi-pci,id=scsi0', '-device', 'scsi-hd,drive=system,serial=CYBEXQUALIFICATION',
            '-netdev', 'bridge,id=net0,br=jamesqual0', '-device', 'virtio-net-pci,netdev=net0,id=nic0,mac=52:54:00:c7:be:01',
            '-display', 'none', '-serial', f'file:{d}/update-serial.log', '-qmp', f'unix:{qmp},server=on,wait=off'],
            start_new_session=True)
        try:
            for _ in range(100):
                if qmp.exists():
                    self.monitor = QMP(qmp)
                    return self
                if self.process.poll() is not None:
                    raise ValueError('Fixture QEMU exited')
                time.sleep(.1)
            raise ValueError('Fixture QEMU monitor unavailable')
        except BaseException:
            stop(self.process)
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
