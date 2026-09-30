#!/usr/bin/env python3
"""HTTP traffic generator for the separate, disposable NixOS client VM."""
import concurrent.futures
import json
from pathlib import Path
import threading
import time
import urllib.request
import uuid

CONTROL = Path('/tmp/shared/nest-memory-traffic')
URL = 'http://machine:8080'


def write(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value)+'\n')
    temporary.replace(path)


def serve_load(stop, results):
    paths = ['/files/probe.bin', '/cache/nar/'+'0'*52+'.nar.zst', '/boot/02:00:00:00:00:42']
    index = 0
    while not stop.is_set():
        path = paths[index % len(paths)]
        started = time.monotonic()
        with urllib.request.urlopen(URL+path, timeout=30) as response:
            length, prefix = 0, b''
            while chunk := response.read(1024*1024):
                if not prefix: prefix = chunk[:16]
                length += len(chunk)
        if path.startswith('/boot/'):
            if not prefix.startswith(b'#!ipxe'): raise RuntimeError('invalid iPXE response')
        elif length != 16*1024*1024 or prefix != bytes(range(16)):
            raise RuntimeError('served file content or size changed')
        results.append((path, time.monotonic()-started, length))
        index += 1
        time.sleep(.02)


def main():
    if Path('/etc/nest-memory-fixture').read_text() != 'disposable traffic fixture\n':
        raise RuntimeError('requires the disposable traffic VM')
    CONTROL.mkdir(exist_ok=True)
    previous = None
    while True:
        request = CONTROL/'request.json'
        if not request.exists():
            time.sleep(.02)
            continue
        raw = request.read_bytes()
        if len(raw) > 4096: raise RuntimeError('oversized traffic request')
        identity = str(uuid.UUID(json.loads(raw)['id']))
        if identity == previous:
            time.sleep(.02)
            continue
        previous = identity
        samples, result = [], {}
        stop = threading.Event()
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            readers = [pool.submit(serve_load, stop, samples) for _ in range(3)]
            write(CONTROL/(identity+'.ready.json'), {'ready': True})
            try:
                while not (CONTROL/(identity+'.stop')).exists():
                    if any(reader.done() for reader in readers):
                        for reader in readers:
                            if reader.done(): reader.result()
                        raise RuntimeError('traffic worker stopped unexpectedly')
                    if time.monotonic()-started > 1260: raise RuntimeError('traffic deadline exceeded')
                    time.sleep(.02)
            except Exception as error:
                result['error'] = str(error)
            finally:
                stop.set()
                for reader in readers:
                    try: reader.result()
                    except Exception as error: result['error'] = str(error)
        result.update(samples=samples, seconds=time.monotonic()-started)
        write(CONTROL/(identity+'.result.json'), result)


if __name__ == '__main__':
    main()
