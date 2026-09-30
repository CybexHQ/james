#!/usr/bin/env python3
"""Compare exact binaries inside memory-vm.nix; never target an enrolled Nest.

This is a component gate. Full signed update/rollback and workstation boot
acceptance, plus a 24–48 hour soak, remain separate release gates.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import statistics
import subprocess
import threading
import time
import urllib.request
import uuid

ROOT = Path('/var/lib/nest-memory')
DB = ROOT / 'data/nest.sqlite'
URL = 'http://127.0.0.1:8080'


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def write_evidence(path, evidence):
    body = json.dumps(evidence, indent=2)+'\n'
    temporary = path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(body)
    temporary.replace(path)
    # NixOS's test driver exposes this task-owned exchange directory to the
    # host. Preserve progress even if a long soak is interrupted before copying.
    shared = Path('/tmp/shared')
    if shared.is_dir():
        temporary = shared/(path.name+'.tmp')
        temporary.write_text(body)
        temporary.replace(shared/path.name)


def sql(statement, args=()):
    with sqlite3.connect(DB, timeout=30) as connection:
        return connection.execute(statement, args).fetchall()


def queue(nonce):
    jobs = []
    for target in ('a', 'b'):
        digest = hashlib.sha256(f'{nonce}-{target}'.encode()).hexdigest()
        spec = dict(schema_version=1, artifact_type='nixos_closure', target=target,
                    system='x86_64-linux', input_revision='a'*40,
                    input_config_hash=digest, allow_source_builds=True)
        jobs.append(sql('''INSERT INTO nest_build_jobs
            (requested_artifact_type,build_spec,target,system,input_revision,input_config_hash,status,created_at,updated_at)
            VALUES ('nixos_closure',?,?,?,?,?,'queued',datetime('now'),datetime('now')) RETURNING id''',
                        (json.dumps(spec), target, 'x86_64-linux', 'a'*40, digest))[0][0])
    return jobs


def counters():
    pid = int(run('systemctl', 'show', 'nest-memory', '--property=MainPID', '--value'))
    status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines())
    values = {name: int(status[name].split()[0])*1024 for name in ('VmRSS', 'RssAnon', 'VmSwap')}
    values.update(threads=int(status['Threads']), fds=len(list(Path(f'/proc/{pid}/fd').iterdir())), pid=pid)
    smaps = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines() if ':' in line)
    values['Pss'] = int(smaps['Pss'].split()[0])*1024
    values['guest_meminfo'] = {key: int(value.split()[0])*1024 for key, value in
                              (line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
                              if key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree')}
    values['guest_memory_pressure'] = Path('/proc/pressure/memory').read_text()
    values['restarts'] = int(run('systemctl', 'show', 'nest-memory', '--property=NRestarts', '--value'))
    for unit in ('nest-memory', 'nix-daemon'):
        group = Path('/sys/fs/cgroup/system.slice') / (unit + '.service')
        for field in ('memory.current', 'memory.peak', 'memory.swap.current'):
            if (group/field).exists():
                values[unit+'.'+field] = int((group/field).read_text())
        if (group/'memory.stat').exists():
            stat = dict((k, int(v)) for k, v in (line.split() for line in (group/'memory.stat').read_text().splitlines()))
            values[unit+'.stat'] = {key: stat.get(key) for key in ('anon', 'file', 'slab')}
        if (group/'memory.events').exists():
            values[unit+'.events'] = dict((k, int(v)) for k, v in (line.split() for line in (group/'memory.events').read_text().splitlines()))
        values[unit+'.pids'] = sorted({int(pid) for path in group.rglob('cgroup.procs') for pid in path.read_text().split()})
    return values


def cancel_probe(nonce):
    flake = Path('/etc/nest-memory-flake').read_text().replace('NONCE', nonce).replace('mkdir -p $out;', 'sleep 60; mkdir -p $out;')
    (ROOT/'flake/flake.nix').write_text(flake)
    run('chown', '-R', 'nest:nest', str(ROOT/'flake'))
    jobs = queue(nonce)
    deadline = time.monotonic()+30
    while not sql("SELECT id FROM nest_build_jobs WHERE id IN (?,?) AND status='running' AND progress_stage='building'", jobs):
        if time.monotonic()>deadline: raise RuntimeError('cancel probe never reached a running build')
        time.sleep(.2)
    time.sleep(1)
    sql("UPDATE nest_build_jobs SET cancel_requested_at=datetime('now'), status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END WHERE id IN (?,?)", jobs)
    deadline = time.monotonic()+20
    while not all(row[0] == 'cancelled' for row in sql('SELECT status FROM nest_build_jobs WHERE id IN (?,?)', jobs)):
        if time.monotonic()>deadline: raise RuntimeError('cancellation did not release its worker')
        time.sleep(.2)


def serve_load(stop, results):
    paths = ['/files/probe.bin', '/cache/nar/'+'0'*52+'.nar.zst', '/boot/02:00:00:00:00:42']
    index = 0
    while not stop.is_set():
        started = time.monotonic()
        path = paths[index % len(paths)]
        with urllib.request.urlopen(URL+path, timeout=30) as response:
            length = 0
            prefix = b''
            while chunk := response.read(1024*1024):
                if not prefix:
                    prefix = chunk[:16]
                length += len(chunk)
        if path.startswith('/boot/'):
            if not prefix.startswith(b'#!ipxe'): raise RuntimeError('invalid iPXE response')
        elif length != 16*1024*1024 or prefix != bytes(range(16)):
            raise RuntimeError('served file content or size changed')
        results.append((path, time.monotonic()-started, length))
        index += 1
        time.sleep(.02)  # Representative concurrent traffic; do not starve Nix CPU.


def wait_json(path):
    deadline = time.monotonic()+60
    while not path.exists():
        if time.monotonic() > deadline: raise RuntimeError(f'external traffic did not respond: {path.name}')
        time.sleep(.02)
    return json.loads(path.read_text())


def start_external_load():
    control = Path('/tmp/shared/nest-memory-traffic')
    control.mkdir(exist_ok=True)
    identity = str(uuid.uuid4())
    temporary = control/'request.tmp'
    temporary.write_text(json.dumps({'id': identity}))
    temporary.replace(control/'request.json')
    wait_json(control/(identity+'.ready.json'))
    return control/identity


def stop_external_load(identity):
    identity.with_suffix('.stop').touch()
    result = wait_json(identity.with_suffix('.result.json'))
    for suffix in ('.stop', '.ready.json', '.result.json'):
        identity.with_suffix(suffix).unlink()
    if 'error' in result: raise RuntimeError(result['error'])
    return result


def prepare(external_traffic=False):
    ROOT.mkdir(mode=0o700, exist_ok=True)
    for child in ('data', 'www/cache/nar', 'www/assets', 'tftp', 'flake', 'build', 'outputs'):
        (ROOT/child).mkdir(parents=True, exist_ok=True)
    payload = bytes(range(256)) * 65536
    (ROOT/'www/probe.bin').write_bytes(payload)
    (ROOT/'www/cache/nar'/('0'*52+'.nar.zst')).write_bytes(payload)
    (ROOT/'config.toml').write_text(f'''
[server]
listen_addr = "{'0.0.0.0' if external_traffic else '127.0.0.1'}:8080"
public_base_url = "http://127.0.0.1:8080"
[paths]
data_dir = "{ROOT}/data"
database_path = "{DB}"
boot_assets_dir = "{ROOT}/www"
static_dir = "{ROOT}/www/assets"
tftp_dir = "{ROOT}/tftp"
[auth]
admin_token = "disposable-local-fixture"
[build]
max_concurrent_builds = 2
max_build_cores = 4
minimum_memory_bytes = 1073741824
minimum_swap_bytes = 0
max_artifact_size_bytes = 1073741824
work_dir = "{ROOT}/build"
output_dir = "{ROOT}/outputs"
timeout_seconds = 1200
[[build.targets]]
artifact_type = "nixos_closure"
target = "a"
system = "x86_64-linux"
flake = "path:{ROOT}/flake"
attr = "packages.x86_64-linux.a"
[[build.targets]]
artifact_type = "nixos_closure"
target = "b"
system = "x86_64-linux"
flake = "path:{ROOT}/flake"
attr = "packages.x86_64-linux.b"
[cache]
root_dir = "{ROOT}/www/cache"
private_key_path = "{ROOT}/data/cache-private"
public_key_path = "{ROOT}/data/cache-public"
max_bytes = 17179869184
[manage]
enabled = false
state_path = "{ROOT}/data/manage-state.json"
''')
    run('chown', '-R', 'nest:nest', str(ROOT))


def trial(mode, cycles, soak_hours=0, checkpoint=None, external_traffic=False):
    run('systemctl', 'stop', 'nest-memory')
    active = ROOT/'active-nest'
    active.unlink(missing_ok=True)
    active.symlink_to('/etc/nest-memory-'+mode)
    run('systemctl', 'start', 'nest-memory')
    deadline = time.monotonic()+30
    while not DB.exists() or not sql("SELECT name FROM sqlite_master WHERE name='nest_build_jobs'"):
        if time.monotonic() > deadline: raise RuntimeError('Nest startup timeout')
        time.sleep(.1)
    time.sleep(2)
    sql("INSERT OR IGNORE INTO devices (mac,created_at,updated_at) VALUES ('02:00:00:00:00:42',datetime('now'),datetime('now'))")
    samples, runs = [], []
    trial_started = time.monotonic()
    deadline_soak = trial_started + soak_hours * 3600
    for cycle in range(10000 if soak_hours else cycles):
        nonce = f'{mode}-{cycle}'
        (ROOT/'flake/flake.nix').write_text(Path('/etc/nest-memory-flake').read_text().replace('NONCE', nonce))
        run('chown', '-R', 'nest:nest', str(ROOT/'flake'))
        loads = []
        transitions = []
        last_stages = None
        stop = threading.Event()
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            external = start_external_load() if external_traffic else None
            external_result = None
            readers = [] if external else [pool.submit(serve_load, stop, loads) for _ in range(3)]
            started = time.monotonic()
            jobs = queue(nonce)
            try:
                while True:
                    rows = sql('SELECT id,status,error FROM nest_build_jobs WHERE id IN (?,?)', jobs)
                    stages = sql('SELECT id,status,progress_stage FROM nest_build_jobs WHERE id IN (?,?)', jobs)
                    if stages != last_stages:
                        transitions.append(dict(seconds=time.monotonic()-started, jobs=stages))
                        last_stages = stages
                    if any(row[1] in ('failed', 'cancelled') for row in rows):
                        raise RuntimeError(f'Build failure: {rows}; logs={sql("SELECT logs FROM nest_build_jobs WHERE id IN (?,?)", jobs)}')
                    if len(rows) == 2 and all(row[1] == 'succeeded' for row in rows): break
                    if time.monotonic()-started > 1200: raise RuntimeError('build timeout')
                    time.sleep(.05)
                build_duration = time.monotonic()-started
                # A fixed traffic window avoids comparing a few startup
                # requests with many steady-state requests after a slower build.
                while time.monotonic()-started < 20:
                    time.sleep(.1)
            finally:
                stop.set()
                for reader in readers: reader.result()
                if external:
                    external_result = stop_external_load(external)
                    loads = external_result['samples']
        duration = external_result['seconds'] if external_result else time.monotonic()-started
        time.sleep(12)  # Allow Tokio blocking workers and pipe reapers to become idle.
        samples.append(counters())
        if mode == 'candidate':
            resource = json.loads((ROOT/'data/resources.json').read_text())
            if resource.get('schema') != 'tiaris.nest.resources.v1' or resource.get('process_id') != samples[-1]['pid']:
                raise RuntimeError('resource projection identity is missing or stale')
            if not resource.get('service_cgroup'):
                raise RuntimeError('actual service cgroup was not observed')
        latencies = sorted(item[1] for item in loads)
        path_p95 = {}
        for path in set(item[0] for item in loads):
            times = sorted(item[1] for item in loads if item[0] == path)
            path_p95[path] = times[int(.95*(len(times)-1))]
        runs.append(dict(seconds=build_duration, traffic_seconds=duration, requests=len(loads),
                         served_bytes=sum(item[2] for item in loads), path_p95_seconds=path_p95,
                         request_p95_seconds=latencies[int(.95*(len(latencies)-1))],
                         transitions=transitions,
                         job_evidence=[dict(id=row[0], started_at=row[1], completed_at=row[2], logs=row[3],
                                            phase_peaks=json.loads(row[4]).get('resource_phase_peaks'))
                                       for row in sql('SELECT id,started_at,completed_at,logs,cache_metadata FROM nest_build_jobs WHERE id IN (?,?)', jobs)]))
        if checkpoint:
            write_evidence(checkpoint, dict(mode=mode, cycles=cycle+1, elapsed_seconds=time.monotonic()-trial_started,
                                            runs=runs, quiescent=samples))
        # Clean only this fixture's completed build outputs. The binary cache
        # and its authenticated inventory remain for later serving/scrub cycles.
        for (output,) in sql('SELECT output_path FROM nest_build_jobs WHERE id IN (?,?)', jobs):
            if output.startswith('/nix/store/') and '-nest-memory-' in output:
                run('nix-store', '--delete', output)
        if soak_hours and cycle % 10 == 9:
            cancel_probe(f"{mode}-cancel-{cycle}")
        if soak_hours and time.monotonic() >= deadline_soak:
            break
    cancel_probe(mode+'-cancel-final')
    if len({sample['pid'] for sample in samples}) != 1:
        raise RuntimeError('unexpected Nest process restart')
    for sample in samples:
        if any(sample.get(unit+'.events', {}).get('oom_kill', 0) for unit in ('nest-memory', 'nix-daemon')):
            raise RuntimeError('OOM during qualification')
    if len(samples) >= 5:
        warm = samples[2:]
        for field, budget in (('fds', 8), ('threads', 8), ('RssAnon', 32*1024*1024), ('Pss', 32*1024*1024)):
            if warm[-1][field] - warm[0][field] > budget:
                raise RuntimeError(f'quiescent {field} growth exceeds the leak investigation budget')
    return dict(binary_sha256=hashlib.sha256(Path('/etc/nest-memory-'+mode).read_bytes()).hexdigest(),
                elapsed_seconds=time.monotonic()-trial_started, runs=runs, quiescent=samples)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cycles', type=int, default=3)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--soak-hours', type=float, default=0)
    parser.add_argument('--candidate-first', action='store_true')
    parser.add_argument('--external-traffic', action='store_true')
    args = parser.parse_args()
    if Path('/etc/nest-memory-fixture').read_text() != 'disposable component fixture\n':
        raise RuntimeError('Requires owned disposable fixture')
    if not 2 <= args.cycles <= 10000: raise ValueError('cycles outside qualification range')
    if not 0 <= args.soak_hours <= 48: raise ValueError('soak hours outside range')
    prepare(args.external_traffic)
    order = ('candidate', 'baseline') if args.candidate_first else ('baseline', 'candidate')
    evidence = dict(schema='tiaris.nest.memory-component-qualification.v1', kernel=run('uname','-r'), nix=run('nix','--version'), order=order,
                    traffic_source='separate_vm' if args.external_traffic else 'same_guest')
    write_evidence(args.output, evidence)
    write_evidence(args.output.with_suffix('.checkpoint.json'), dict(mode='starting', cycles=0))
    try:
        for mode in order:
            evidence[mode] = trial(mode, args.cycles, args.soak_hours if mode == 'candidate' else 0,
                                   args.output.with_suffix('.checkpoint.json'), args.external_traffic)
            write_evidence(args.output, evidence)
        # Exclude first-cycle cold evaluation/cache seeding from warm comparison.
        baseline = statistics.median(row['seconds'] for row in evidence['baseline']['runs'][1:])
        candidate = statistics.median(row['seconds'] for row in evidence['candidate']['runs'][1:])
        evidence['warm_build_ratio'] = candidate/baseline
        baseline_traffic = statistics.median(row['served_bytes']/row['traffic_seconds'] for row in evidence['baseline']['runs'][1:])
        candidate_traffic = statistics.median(row['served_bytes']/row['traffic_seconds'] for row in evidence['candidate']['runs'][1:])
        evidence['traffic_throughput_ratio'] = candidate_traffic/baseline_traffic
        evidence['latency_ratios'] = {path: statistics.median(row['path_p95_seconds'][path] for row in evidence['candidate']['runs'][1:]) /
                                     statistics.median(row['path_p95_seconds'][path] for row in evidence['baseline']['runs'][1:])
                                     for path in evidence['baseline']['runs'][0]['path_p95_seconds']}
        evidence['performance_pass'] = (candidate <= baseline*1.05 and candidate_traffic >= baseline_traffic/1.05
                                        and max(evidence['latency_ratios'].values()) <= 1.05)
        evidence['signed_update_and_full_pxe_qualified'] = False
        evidence['component_soak_hours'] = args.soak_hours
        evidence['soak_complete'] = evidence['candidate']['elapsed_seconds'] >= 24*3600
        write_evidence(args.output, evidence)
        if not evidence['performance_pass']: raise RuntimeError('performance regression exceeds 5%; repeat and investigate')
    finally:
        run('systemctl', 'stop', 'nest-memory')


if __name__ == '__main__':
    main()
