"""Retain the offline Manage owner throughout one exact-origin qualification phase."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

import isolated_manage
import isolated_manage_artifacts
import isolated_manage_config as config
import isolated_manage_network
import isolated_manage_rpc


@contextlib.contextmanager
def fixture(state, config_path, candidate, predecessor, phase):
    value, _ = config.load(config_path)
    if phase not in {'fresh', 'update', 'rollback', 'cold'}:
        raise ValueError('unsupported production qualification phase')
    if value['manage_origin'] != 'https://manage.cybex.net':
        raise ValueError('production fixture must bind the production artifact origin')
    directory = state / 'fixture-config'
    directory.mkdir(mode=0o700)
    selected = dict(value, initial_release='predecessor' if phase in {'update', 'rollback'} else 'candidate')
    for field in ('tls_certificate', 'tls_private_key', 'provisioning_seed_file'):
        source = Path(value[field])
        target = directory / field
        body = config.read_file(source, private=field != 'tls_certificate')
        with target.open('xb') as stream:
            stream.write(body)
        target.chmod(0o600)
        selected[field] = str(target)
    # Cold qualification uses only the independently downloaded candidate.
    if phase == 'cold':
        predecessor = candidate
        selected['app_images'] = {role: value['app_images']['candidate'] for role in ('candidate', 'predecessor')}
    path = directory / 'config.json'
    path.write_bytes(config.canonical(selected))
    path.chmod(0o600)
    owner = isolated_manage.Owner(state, isolated_manage_network.Adapter(),
                                  artifact_factory=isolated_manage_artifacts.Coordinator)
    try:
        owner.prepare(path, candidate, predecessor)
        import fixture_blueprints
        fixture_blueprints.prepare(owner)
        with isolated_manage_rpc.Server(owner):
            yield owner
    finally:
        if (state / 'manage.json').exists():
            owner.cleanup(purge=True)
        # These files were created here; no runtime service credential file is touched.
        for item in directory.iterdir():
            if item.is_symlink() or not item.is_file():
                raise ValueError('fixture input directory acquired an unexpected entry')
            item.unlink()
        directory.rmdir()


def stage_artifacts(source, directory):
    """Snapshot already verified producer files into private root-owned inputs."""
    if directory.exists():
        raise ValueError('refusing to adopt staged release inputs')
    directory.mkdir(mode=0o700)
    for path in source.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError('release inputs must contain only ordinary files')
        target = directory / path.name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as src, target.open('xb') as dst:
            before = os.fstat(src.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError('release input is not an ordinary file')
            shutil.copyfileobj(src, dst, 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
            after = os.fstat(src.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('release input changed while staging')
            src.seek(0)
            source_digest = hashlib.file_digest(src, 'sha256').hexdigest()
        target.chmod(0o600)
        def digest(p):
            with p.open('rb') as stream:
                return hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest(target) != source_digest:
            raise ValueError('release input changed while staging')
    return directory
