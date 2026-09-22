"""Warm predecessor bytes only; never lifecycle or cold-download evidence."""
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit

import release_speed_io as io

ROOT = Path(__file__).resolve().parents[2]


def verifier():
    spec = importlib.util.spec_from_file_location('neutral_nixos_predecessor',
        ROOT / 'nixos-appliance/qualification/release_predecessor.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def source_digest():
    # Conservative invalidation includes all current verifier/transitive Python
    # and policy source, not just the small resolver facade.
    paths = []
    for root in ('tools', 'nixos-appliance', 'release/beast', 'protocol'):
        paths += [p for p in (ROOT / root).rglob('*') if p.is_file() and p.suffix in {'.py', '.json'}]
    return io.digest(io.canonical({str(p.relative_to(ROOT)): io.digest(io.read(p, 16 * 1024**2))
                                   for p in sorted(paths)}))


def inventory(snapshot, p):
    manifest = snapshot['manifest']
    result = {p.MANIFEST: (io.digest(snapshot['manifest_body']), len(snapshot['manifest_body'])),
              p.COMPATIBILITY: (io.digest(snapshot['compatibility_body']), len(snapshot['compatibility_body']))}
    for artifact, field in ((manifest['appliance_release_v1']['system_closure'], 'sha256'),
                            (manifest['installer_iso_template_v3'], 'template_sha256'),
                            (manifest['workstation_netboot'], 'sha256')):
        name = urlsplit(artifact['url']).path.rsplit('/', 1)[-1]
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', name) or name in result
                or name in {'seal.json', 'identity.json'}):
            raise ValueError('Ambiguous artifact inventory')
        if (type(artifact['size_bytes']) is not int or not 0 < artifact['size_bytes'] <= 16 * 1024**3
                or not re.fullmatch('[0-9a-f]{64}', artifact[field])):
            raise ValueError('Invalid artifact identity')
        result[name] = (artifact[field], artifact['size_bytes'])
    return result


def remove_entry(path, names):
    """Delete only the exact flat owned cache entry; never recursive removal."""
    io.directory(path)
    if {p.name for p in path.iterdir()} != set(names):
        raise ValueError('Foreign cache contents require operator inspection')
    for name in names:
        with io.opened(path / name):
            pass
    for name in names:
        (path / name).unlink()
    path.rmdir()


def warm(args, p=None):
    if args.mode != 'github-warm':
        raise ValueError('No supported no-fetch verifier; candidate-only cache execution refused')
    p = p or verifier()
    root = io.directory(args.cache_root)
    if root.is_relative_to(ROOT):
        raise ValueError('Cache must be outside the source checkout')
    output_parent = io.directory(args.directory.parent)
    if args.directory.exists() or args.directory.is_symlink():
        raise ValueError('Output must be new')
    if not 0 < args.max_bytes <= 32 * 1024**3:
        raise ValueError('Cache capacity outside policy')
    # One global lease deliberately serializes reads, writers and eviction. A
    # reader owns an independent copy before releasing it, so eviction is safe.
    with io.lock(root / 'cache.lock'):
        if any(v.name != 'cache.lock' and not re.fullmatch('[0-9a-f]{64}', v.name) for v in root.iterdir()):
            raise ValueError('Incomplete cache staging requires operator inspection')
        with tempfile.TemporaryDirectory(prefix='.metadata-', dir=root) as temp:
            metadata = Path(temp)
            ancestry = metadata / 'ancestry'
            ancestry.mkdir(mode=0o700)
            authorization_body = io.read(args.authorization)
            authorization = metadata / 'authorization.json'
            io.write(authorization, authorization_body, 0o400)
            expected_body = io.read(args.expected_identity)
            expected = io.load(args.expected_identity)
            if expected_body != p.canonical(expected):
                raise ValueError('Noncanonical published ancestry')
            fresh = p.resolve(args.repository, args.candidate_version, args.trusted_public_key,
                              ancestry, authorization)
            if fresh != expected:
                raise ValueError('Published ancestry changed')
            signed = metadata / 'signed'
            signed.mkdir(mode=0o700)
            for name in (p.MANIFEST, p.COMPATIBILITY):
                io.write(signed / name, io.read(args.predecessor_dir / name), 0o400)
            if io.digest(io.read(signed / p.MANIFEST)) != args.predecessor_manifest_sha256:
                raise ValueError('Predecessor manifest changed')
            snap = p.verify_pair_snapshot(signed, args.trusted_public_key)
            p.advance(args.candidate_version, snap['manifest']['version'])
            files = inventory(snap, p)
            binding = {'schema': 'cybex.james.transport-cache.v1', 'verifier': source_digest(),
                'trust': io.digest(args.trusted_public_key.encode()), 'repository': args.repository,
                'authorization': io.digest(authorization_body),
                'manifest': io.digest(snap['manifest_body']),
                'compatibility': io.digest(snap['compatibility_body']), 'files': files}
            key = io.digest(io.canonical(binding))
            entry = root / key
            hit = entry.exists()
            total = sum(size for _, size in files.values())
            storage = total + len(io.canonical(binding))
            if storage > args.max_bytes:
                raise ValueError('Identity exceeds cache capacity')
            stage = Path(tempfile.mkdtemp(prefix='.stage-', dir=root))
            try:
                if hit:
                    io.directory(entry)
                    if io.load(entry / 'seal.json') != json.loads(io.canonical(binding)):
                        raise ValueError('Cache binding changed')
                    if {v.name for v in entry.iterdir()} != set(files) | {'seal.json'}:
                        raise ValueError('Cache inventory changed')
                    for name, (sha, size) in files.items():
                        io.copy(entry / name, stage / name, sha, size)
                else:
                    for name in (p.MANIFEST, p.COMPATIBILITY):
                        io.copy(signed / name, stage / name, *files[name])
                # Existing full signature/archive/NAR/source/ISO verification on
                # every hit and miss. Only an explicitly network-enabled warm path.
                identity = p.qualify(stage, args.candidate_version, args.trusted_public_key)
                artifact = snap['manifest']['workstation_netboot']
                name = urlsplit(artifact['url']).path.rsplit('/', 1)[-1]
                p.fetch(artifact['url'], stage / name, artifact['sha256'], artifact['size_bytes'])
                verified = p.verify_pair_snapshot(stage, args.trusted_public_key)
                if (verified['manifest_body'], verified['compatibility_body']) != (snap['manifest_body'], snap['compatibility_body']):
                    raise ValueError('Authenticated snapshot changed')
                # Materialize by verified copies even after a successful facade.
                destination = Path(tempfile.mkdtemp(prefix='.snapshot-', dir=output_parent))
                try:
                    for name, (sha, size) in files.items():
                        io.copy(stage / name, destination / name, sha, size)
                    io.write(destination / 'identity.json', p.canonical(identity), 0o400)
                    io.sync(destination)
                    if not hit:
                        io.write(stage / 'seal.json', io.canonical(binding), 0o400)
                        for file in stage.iterdir():
                            file.chmod(0o400)
                            with io.opened(file) as stream:
                                os.fsync(stream.fileno())
                        evict(root, storage, args.max_bytes)
                        io.sync(stage)
                        io.publish(stage, entry)
                        io.sync(root)
                    os.utime(entry, None, follow_symlinks=False)
                    io.publish(destination, args.directory)
                    io.sync(output_parent)
                finally:
                    if destination.exists():
                        remove_entry(destination, [v.name for v in destination.iterdir()])
            finally:
                if stage.exists():
                    remove_entry(stage, [v.name for v in stage.iterdir()])
    return {'cache': 'hit' if hit else 'miss', 'bytes': total}


def evict(root, incoming, maximum):
    entries = []
    for path in root.iterdir():
        if re.fullmatch('[0-9a-f]{64}', path.name):
            io.directory(path)
            seal = io.load(path / 'seal.json')
            if (seal.get('schema') != 'cybex.james.transport-cache.v1'
                    or io.digest(io.read(path / 'seal.json')) != path.name):
                raise ValueError('Cache seal changed')
            names = set(seal['files']) | {'seal.json'}
            if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', n) for n in names):
                raise ValueError('Unsafe cache seal')
            size = sum((path / n).lstat().st_size for n in names)
            entries.append((path.stat().st_mtime_ns, path, size, names))
    entries.sort()
    while entries and (len(entries) >= 2 or sum(v[2] for v in entries) + incoming > maximum):
        _, path, _, names = entries.pop(0)
        remove_entry(path, names)
