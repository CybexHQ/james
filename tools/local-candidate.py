#!/usr/bin/env python3
"""Retain build-once bytes locally; GitHub stores only their bounded receipt."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import zipfile

SCHEMA = 'cybex.james.local-candidate.v1'
RECEIPT = 'candidate.json'
ROOT = Path.home() / '.local/state/cybex-james-releases'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(run, source, tag):
    if (not re.fullmatch(r'[1-9][0-9]*', run)
            or not re.fullmatch(r'[0-9a-f]{40}', source)
            or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag)):
        raise ValueError('Invalid candidate identity')
    return dict(schema=SCHEMA, repository='CybexHQ/james', run=run, source=source, tag=tag)


def inventory(directory):
    files = {}
    for path in sorted(directory.iterdir()):
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,199}', path.name):
            raise ValueError('Candidate inventory must contain only regular release files')
        size = path.stat().st_size
        if not 0 < size < 2 * 1024**3:
            raise ValueError('Each published release file must be nonempty and under 2 GiB')
        files[path.name] = dict(size=size, sha256=digest(path))
    if not 2 <= len(files) <= 32:
        raise ValueError('Candidate inventory size is invalid')
    return files


def receipt(path, expected):
    if path.is_symlink() or path.stat().st_size > 65536:
        raise ValueError('Invalid candidate receipt file')
    value = json.loads(path.read_text())
    if set(value) != {*expected, 'files'} or any(value[k] != v for k, v in expected.items()):
        raise ValueError('Candidate receipt belongs to a different run, source or tag')
    files = value['files']
    if not isinstance(files, dict) or not 2 <= len(files) <= 32:
        raise ValueError('Invalid candidate receipt inventory')
    for name, item in files.items():
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,199}', name)
                or set(item) != {'size', 'sha256'} or type(item['size']) is not int
                or not 0 < item['size'] < 2 * 1024**3
                or not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])):
            raise ValueError('Invalid candidate file identity')
    return value


def verify(directory, value):
    if directory.is_symlink() or inventory(directory) != value['files']:
        raise ValueError('Retained candidate bytes changed; refusing rebuild or publication')


@contextmanager
def locked(root):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise ValueError('Candidate store must be private and owned by the release runner')
    with (root / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def copy_files(source, destination):
    destination.mkdir(mode=0o700)
    for path in source.iterdir():
        # Reflinks avoid duplicating multi-GB files where supported. Never use
        # hardlinks: a later consumer must never mutate retained signed inputs.
        subprocess.run(['cp', '--reflink=auto', '--', str(path), str(destination / path.name)], check=True)
        (destination / path.name).chmod(0o444)


def seal(root, expected, directory, output):
    target = root / expected['run']
    with locked(root):
        value = expected | {'files': inventory(directory)}
        if target.exists():
            if receipt(target / RECEIPT, expected) != value:
                raise ValueError('Cannot overwrite an existing signed candidate')
            verify(target / 'files', value)
        else:
            staging = Path(tempfile.mkdtemp(prefix='.seal-', dir=root))
            try:
                copy_files(directory, staging / 'files')
                verify(staging / 'files', value)
                (staging / RECEIPT).write_text(json.dumps(value, sort_keys=True) + '\n')
                (staging / RECEIPT).chmod(0o444)
                # Persist file data and metadata before the atomic rename.
                subprocess.run(['sync', '-f', str(staging)], check=True)
                staging.rename(target)
                subprocess.run(['sync', '-f', str(root)], check=True)
            finally:
                if staging.exists():
                    shutil.rmtree(staging)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(target / RECEIPT, output)


def restore(root, expected, directory, proof):
    with locked(root):
        target = root / expected['run']
        value = receipt(proof or target / RECEIPT, expected)
        if receipt(target / RECEIPT, expected) != value:
            raise ValueError('GitHub receipt differs from the sealed local candidate')
        verify(target / 'files', value)
        if directory.exists():
            raise ValueError('Candidate destination must be absent')
        copy_files(target / 'files', directory)
        verify(directory, value)


def select(root, expected, attempt):
    with locked(root):
        target = root / expected['run']
        if target.exists():
            verify(target / 'files', receipt(target / RECEIPT, expected))
            return True
        if attempt != 1:
            raise ValueError('Local candidate unavailable; retry must never rebuild or re-sign')
        return False


def prune(root):
    with locked(root):
        for path in root.iterdir():
            if not re.fullmatch(r'[1-9][0-9]*', path.name) or path.is_symlink() or not path.is_dir():
                continue
            if path.stat().st_mtime > time.time() - 30 * 86400:
                continue
            value = json.loads((path / RECEIPT).read_text())
            receipt(path / RECEIPT, identity(path.name, value['source'], value['tag']))
            shutil.rmtree(path)


def download_receipt(expected, artifact_id, artifact_digest, output):
    if (not re.fullmatch(r'[1-9][0-9]*', artifact_id or '')
            or not re.fullmatch(r'(sha256:)?[0-9a-f]{64}', artifact_digest or '')):
        raise ValueError('Invalid receipt artifact identity')
    endpoint = f'repos/{expected["repository"]}/actions/artifacts/{artifact_id}'
    metadata = json.loads(subprocess.check_output(['gh', 'api', endpoint]))
    sha = artifact_digest.removeprefix('sha256:')
    if (metadata['expired'] or metadata['size_in_bytes'] > 131072
            or metadata['name'] != 'cybex-james-release-candidate-' + expected['run']
            or metadata['workflow_run']['id'] != int(expected['run'])
            or metadata['workflow_run']['head_sha'] != expected['source']
            or metadata['digest'] != 'sha256:' + sha):
        raise ValueError('Candidate receipt artifact provenance changed')
    body = subprocess.check_output(['gh', 'api', endpoint + '/zip'])
    if len(body) > 131072 or hashlib.sha256(body).hexdigest() != sha:
        raise ValueError('Candidate receipt download digest changed')
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        if archive.namelist() != [RECEIPT] or archive.infolist()[0].file_size > 65536:
            raise ValueError('Candidate receipt archive inventory changed')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(archive.read(RECEIPT))
    receipt(output, expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['select', 'seal', 'restore', 'published', 'prune', 'download-receipt'])
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--run', default=os.environ.get('GITHUB_RUN_ID'))
    parser.add_argument('--source', default=os.environ.get('GITHUB_SHA'))
    parser.add_argument('--tag', default=os.environ.get('GITHUB_REF_NAME'))
    parser.add_argument('--attempt', type=int, default=int(os.environ.get('GITHUB_RUN_ATTEMPT', '1')))
    parser.add_argument('--directory', type=Path, default=Path('dist'))
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--artifact-id')
    parser.add_argument('--artifact-digest')
    args = parser.parse_args()
    if args.action == 'prune':
        prune(args.root)
        return
    expected = identity(args.run, args.source, args.tag)
    if args.action == 'select':
        print('reuse=' + str(select(args.root, expected, args.attempt)).lower())
    elif args.action == 'seal':
        seal(args.root, expected, args.directory, args.receipt)
    elif args.action == 'restore':
        restore(args.root, expected, args.directory, args.receipt)
    elif args.action == 'download-receipt':
        download_receipt(expected, args.artifact_id, args.artifact_digest, args.receipt)
    else:
        # This path deliberately never reads the local candidate store. It is
        # the independent customer-download proof after immutable publication.
        value = receipt(args.receipt, expected)
        args.directory.mkdir(mode=0o700)
        for name in value['files']:
            subprocess.run(['gh', 'release', 'download', args.tag, '--repo', expected['repository'],
                            '--pattern', name, '--dir', str(args.directory)], check=True)
        verify(args.directory, value)


if __name__ == '__main__':
    main()
