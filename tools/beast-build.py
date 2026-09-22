#!/usr/bin/env python3
"""Run release compilation in a disposable, resource-bounded Docker sandbox.

Only exact committed source, public build inputs, dedicated caches and output
directories cross this boundary. Signing and publication happen afterwards.
"""
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
STATE = Path.home() / '.local/state/cybex-james-build'
PUBLIC_ENV = ('CYBEX_JAMES_BUILD_MANAGE_ORIGIN', 'CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY',
              'CYBEX_JAMES_PROVISIONING_PUBLIC_KEYS',
              'GITHUB_REF_NAME', 'BUILD_VERSION', 'BUILD_BUNDLE', 'BUILD_RUNTIME',
              'BUILD_MANAGE_REVISION', 'BUILD_NIXPKGS_REVISION', 'BUILD_HAS_PREDECESSOR')


def run(*args, **kwargs):
    return subprocess.run([str(v) for v in args], check=True, **kwargs)


def canonical_origin(origin):
    # actions/checkout uses SSH for the private Manage deploy key. Copy only the
    # canonical public repository identity, never its SSH configuration or key.
    for repository in ('james', 'development'):
        canonical = 'https://github.com/CybexHQ/' + repository
        if origin.removesuffix('.git') in (canonical, 'git@github.com:CybexHQ/' + repository,
                                          'ssh://git@github.com/CybexHQ/' + repository):
            return canonical
    raise ValueError('The isolated NixOS build requires James and development source origins')


def checkout(source, destination):
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    origin = subprocess.check_output(['git', '-C', str(source), 'remote', 'get-url', 'origin'], text=True).strip()
    origin = canonical_origin(origin)
    run('git', 'init', '-q', destination)
    run('git', '-C', destination, 'remote', 'add', 'origin', origin)
    run('git', '-C', destination, 'fetch', '-q', '--depth=1', source, revision)
    run('git', '-C', destination, 'checkout', '-q', '--detach', 'FETCH_HEAD')


def command(image, name, source, scratch, output, state, environment):
    args = ['docker', 'run', '--rm', '--name', name, '--init',
            '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--cpus=12', '--memory=48g',
            '--memory-swap=48g', '--pids-limit=8192', '--network=bridge',
            '--mount', f'type=bind,src={source},dst=/work',
            '--mount', f'type=bind,src={scratch},dst=/scratch',
            '--mount', f'type=bind,src={output},dst=/work/dist',
            '--mount', f'type=bind,src={state / "cache"},dst=/cache',
            '--mount', f'type=bind,src={state / "nix"},dst=/nix',
            '--mount', f'type=bind,src={state / "target"},dst=/work/target',
            '--env', 'RUNNER_TEMP=/scratch', '--env', 'CARGO_BUILD_JOBS=8']
    for key in PUBLIC_ENV:
        if key in environment:
            args += ['--env', key + '=' + environment[key]]
    return args + [image, 'bash', '/scratch/build.sh']


def main():
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt('Release build canceled; removing its isolated container')
    signal.signal(signal.SIGTERM, interrupted)
    if subprocess.check_output(['hostname'], text=True).strip() != 'thebeast':
        raise ValueError('The local release build requires The Beast')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / '.lock').open('a') as lock:
        # Serializes cache mutation even across reruns or local smoke checks.
        fcntl.flock(lock, fcntl.LOCK_EX)
        for directory in ('cache/home', 'cache/cargo', 'nix', 'target'):
            (STATE / directory).mkdir(parents=True, exist_ok=True)
        dockerfile = ROOT / 'release/beast/Dockerfile'
        tag = 'cybex/james-release-builder:' + hashlib.sha256(dockerfile.read_bytes()).hexdigest()[:20]
        run('docker', 'build', '--tag', tag, dockerfile.parent)
        image = subprocess.check_output(['docker', 'image', 'inspect', '--format={{.Id}}', tag], text=True).strip()
        with tempfile.TemporaryDirectory(prefix='build-', dir=STATE) as temporary:
            directory = Path(temporary)
            source, scratch = directory / 'source', directory / 'scratch'
            checkout(ROOT, source)
            checkout(ROOT / 'manage-source', source / 'manage-source')
            # Known build inputs/outputs are outside tracked release source.
            with (source / '.git/info/exclude').open('a') as exclusions:
                exclusions.write('\n/manage-source/\n/dist/\n/result-workstation-netboot\n')
            scratch.mkdir()
            runner_temp = Path(os.environ['RUNNER_TEMP'])
            retained = runner_temp / 'cybex-james-retained-manage-source'
            if retained.exists():
                shutil.copytree(retained, scratch / retained.name)
            (scratch / 'build.sh').write_text(
                'set -euo pipefail\nbash release/beast/preflight.sh\n' + sys.stdin.read())
            # Only this new copy enters the container, never checkout credentials
            # or arbitrary runner scratch (which may contain signing material).
            output = ROOT / 'dist'
            output.mkdir(exist_ok=True)
            name = 'cybex-james-build-' + directory.name
            try:
                run(*command(image, name, source, scratch, output, STATE, os.environ))
                for filename in ('cybex-james-bootstrap', 'cybex-james-appliance-template-metadata.json'):
                    shutil.copyfile(scratch / filename, runner_temp / filename)
                shutil.copytree(scratch / 'cybex-workstation-netboot-tree', runner_temp / 'cybex-workstation-netboot-tree')
                # This tree contains unsigned public cache bytes only. The release
                # key is consumed by pack-system-closure.py after the sandbox exits.
                shutil.copytree(scratch / 'cybex-james-unsigned-closure', runner_temp / 'cybex-james-unsigned-closure')
                (runner_temp / 'cybex-james-bootstrap').chmod(0o700)
                (runner_temp / 'cybex-james-builder-image').write_text(image + '\n')
            finally:
                # Clean only the container we named, including cancellation.
                subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False)


if __name__ == '__main__':
    main()
