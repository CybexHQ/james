"""Strict inputs for a fresh Manage fixture; never consult runtime environment files."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from urllib.parse import urlsplit

SCHEMA = 'cybex.james.isolated-manage-config.v2'
SOURCE = 'https://github.com/CybexHQ/development'
PRODUCTION = Path('/home/john/Code/Cybex/manage')
FIELDS = {'schema', 'manage_origin', 'manage_checkout', 'manage_revision', 'app_images',
          'postgres_image', 'tls_image', 'backend_subnet', 'tls_certificate', 'tls_private_key',
          'provisioning_seed_file', 'release_public_key', 'egress_hosts', 'initial_release'}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def command(arguments, *, data=None):
    """No inherited Docker context, proxy, credentials, Git config or environment."""
    result = subprocess.run([str(v) for v in arguments], input=data, capture_output=True,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent',
                                 'LANG': 'C', 'GIT_CONFIG_NOSYSTEM': '1'}, check=False)
    if result.returncode:
        # A failing program may echo passwords or key material in stderr.
        raise ValueError('isolated fixture command failed: ' + str(arguments[0]))
    return result.stdout


def ordinary_path(value):
    path = Path(value)
    if path == PRODUCTION or PRODUCTION in path.parents:
        raise ValueError('production paths are not fixture inputs')
    if not path.is_absolute() or '..' in path.parts or path != path.resolve(strict=True):
        raise ValueError('fixture inputs require exact absolute paths without symlinks')
    return path


def read_file(path, *, private=True, uid=0, maximum=1024 * 1024):
    path = ordinary_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        forbidden = 0o077 if private else 0o022
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                or info.st_mode & forbidden or not 0 < info.st_size <= maximum):
            raise ValueError('fixture input must be a bounded root-owned ordinary file with safe permissions')
        body = os.read(fd, maximum + 1)
        if len(body) != info.st_size:
            raise ValueError('fixture input changed while reading')
        return body
    finally:
        os.close(fd)


def raw_key(value):
    try:
        key = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError('invalid fixture Ed25519 key encoding') from error
    if len(key) != 32 or base64.b64encode(key).decode() != value:
        raise ValueError('fixture Ed25519 keys must be canonical 32-byte Base64')
    return key


def origin(value):
    url = urlsplit(value)
    if (url.scheme != 'https' or not url.hostname or url.netloc != url.hostname
            or url.path or url.query or url.fragment
            or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', url.hostname)
            or '.' not in url.hostname or len(url.hostname) > 253
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                   for part in url.hostname.split('.'))):
        raise ValueError('fixture requires an exact canonical HTTPS hostname on port 443')
    try:
        ipaddress.ip_address(url.hostname)
    except ValueError:
        return url.hostname
    raise ValueError('fixture origin must be a DNS hostname')


def validate(value):
    if not isinstance(value, dict) or set(value) != FIELDS or value['schema'] != SCHEMA:
        raise ValueError('unexpected isolated Manage configuration fields')
    origin(value['manage_origin'])
    if not re.fullmatch(r'[0-9a-f]{40}', value['manage_revision']):
        raise ValueError('fixture needs an exact reviewed Manage source revision')
    if not isinstance(value['app_images'], dict) or set(value['app_images']) != {'predecessor', 'candidate'}:
        raise ValueError('fixture needs explicit predecessor and candidate Manage images')
    for reference in (*value['app_images'].values(), value['postgres_image'], value['tls_image']):
        if not isinstance(reference, str) or not re.fullmatch(
                r'(?:[a-z0-9][a-z0-9./:_-]*@)?sha256:[0-9a-f]{64}', reference):
            raise ValueError('fixture images must be pinned by image ID or digest')
    network = ipaddress.ip_network(value['backend_subnet'])
    if (network.version != 4 or network.prefixlen != 28
            or not any(network.subnet_of(ipaddress.ip_network(private))
                       for private in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))):
        raise ValueError('fixture backend must be an explicit private IPv4 /28')
    hosts = value['egress_hosts']
    if hosts != []:
        raise ValueError('offline fixture cannot admit external egress hosts')
    raw_key(value['release_public_key'])
    if value['initial_release'] not in {'candidate', 'predecessor'}:
        raise ValueError('initial fixture release must be explicit')
    return value


def check_source(config, run=command):
    path = Path(config['manage_checkout'])
    # Reject the production path before resolving or invoking Git on it.
    if path == PRODUCTION or PRODUCTION in path.parents:
        raise ValueError('production checkout is not an isolated fixture source')
    path = ordinary_path(path)
    if path == PRODUCTION or PRODUCTION in path.parents:
        raise ValueError('production checkout is not an isolated fixture source')
    git = ['git', '-c', 'safe.directory=' + str(path), '-C', path]
    remote = run(git + ['remote', 'get-url', 'origin']).decode().strip()
    if remote not in {SOURCE, SOURCE + '.git', 'git@github.com:CybexHQ/development.git'}:
        raise ValueError('fixture source must belong to the development repository')
    if (run(git + ['rev-parse', 'HEAD']).decode().strip() != config['manage_revision']
            or run(git + ['status', '--porcelain']).strip()):
        raise ValueError('fixture source must be clean at the exact reviewed revision')


def load(config_path, run=command):
    if os.geteuid() != 0:
        raise ValueError('isolated Manage ownership requires root')
    config_path = ordinary_path(config_path)
    directory = config_path.parent.stat()
    if directory.st_uid != 0 or stat.S_IMODE(directory.st_mode) != 0o700:
        raise ValueError('fixture configuration must live in a dedicated root-private directory')
    config = validate(json.loads(read_file(config_path, maximum=16384)))
    for name in ('tls_certificate', 'tls_private_key', 'provisioning_seed_file'):
        if ordinary_path(config[name]).parent != config_path.parent:
            raise ValueError('fixture credentials must be dedicated files alongside its private config')
    check_source(config, run)
    material = key_material(read_file(config['provisioning_seed_file'], maximum=128).decode().strip(),
                            read_file(config['tls_certificate'], private=False, maximum=65536),
                            read_file(config['tls_private_key'], maximum=65536), run)
    return config, material


def key_material(seed_b64, certificate, private_key, run=command):
    seed = raw_key(seed_b64)
    der = bytes.fromhex('302e020100300506032b657004220420') + seed
    public = run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], data=der)
    if len(public) != 44 or public[:12] != bytes.fromhex('302a300506032b6570032100'):
        raise ValueError('fixture provisioning key is not Ed25519')
    cert_public = run(['openssl', 'x509', '-pubkey', '-noout'], data=certificate)
    key_public = run(['openssl', 'pkey', '-pubout'], data=private_key)
    if cert_public != key_public:
        raise ValueError('fixture certificate and dedicated key do not match')
    cert_der = run(['openssl', 'x509', '-outform', 'DER'], data=certificate)
    return {'seed': base64.b64encode(seed).decode(), 'public_key': base64.b64encode(public[-32:]).decode(),
                    'certificate': certificate, 'tls_key': private_key,
                    'certificate_sha256': hashlib.sha256(cert_der).hexdigest()}


def signed_releases(config, secrets, candidate_dir, predecessor_dir, *, verifier=None):
    spec = importlib.util.spec_from_file_location('isolated_manage_predecessor',
                                                 Path(__file__).with_name('release_predecessor.py'))
    predecessor = verifier
    if predecessor is None:
        predecessor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(predecessor)
    result = {}
    for role, directory in (('candidate', candidate_dir), ('predecessor', predecessor_dir)):
        directory = Path(directory)
        snapshot = predecessor.verify_pair_snapshot(directory, config['release_public_key'])
        if (not isinstance(snapshot, dict)
                or set(snapshot) != {'manifest', 'manifest_body', 'compatibility', 'compatibility_body'}
                or not isinstance(snapshot['manifest_body'], bytes)
                or not isinstance(snapshot['compatibility_body'], bytes)):
            raise ValueError('release verifier returned an invalid authenticated snapshot')
        manifest = snapshot['manifest']
        asset = snapshot['compatibility']
        descriptor = manifest['installer_iso_template_v3']
        if (descriptor['manage_origin'] != config['manage_origin']
                or secrets['public_key'] not in descriptor['provisioning_public_keys']
                or manifest['appliance_release_v1']['schema'] != predecessor.release.appliance_v3.SCHEMA):
            raise ValueError('both exact signed NixOS ISOs must admit this origin and fixture signer')
        artifacts = {
            'manifest_transport_url': predecessor.MANIFEST,
            'installer_iso_transport_url': urlsplit(descriptor['url']).path.rsplit('/', 1)[-1],
            'package_transport_url': urlsplit(
                manifest['appliance_release_v1']['system_closure']['url']).path.rsplit('/', 1)[-1],
            'bundle_transport_url': urlsplit(manifest['workstation_netboot']['url']).path.rsplit('/', 1)[-1],
        }
        if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,254}', name)
               for name in artifacts.values()):
            raise ValueError('signed release artifact filename is invalid')
        result[role] = {'directory': str(directory),
                        'manifest_sha256': hashlib.sha256(snapshot['manifest_body']).hexdigest(),
                        'version': manifest['version'], 'manifest_url': asset['release_manifest']['url'],
                        'compatibility_sha256': asset['compatibility_sha256'],
                        'transport_filenames': artifacts}
        if role == 'candidate' and manifest['appliance_release_v1']['manage_source_revision'] != config['manage_revision']:
            raise ValueError('release Manage provenance differs from the reviewed fixture image')
    if result['candidate']['manifest_sha256'] == result['predecessor']['manifest_sha256']:
        if config['initial_release'] != 'candidate':
            raise ValueError('a cold-only fixture must initially select the candidate')
    else:
        predecessor.advance(result['candidate']['version'], result['predecessor']['version'])
    return result
