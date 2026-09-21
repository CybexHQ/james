#!/usr/bin/env python3
"""Build exact public inputs; release signing is always outside Nix evaluation."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

REPO = Path(__file__).resolve().parent.parent


def run(*command, **options):
    return subprocess.run([str(item) for item in command], check=True, text=True,
                          stdout=subprocess.PIPE, **options).stdout.strip()


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def clean_checkout(directory, revision, repository):
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('source revision must be exact lowercase 40-hex')
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('source checkout must be an ordinary directory')
    if run('git', '-C', directory, 'rev-parse', '--show-toplevel') != str(directory):
        raise ValueError('source path is not a checkout root')
    if run('git', '-C', directory, 'remote', 'get-url', 'origin').removesuffix('.git') != 'https://github.com/CybexHQ/' + repository:
        raise ValueError('source checkout origin differs from its environment')
    if run('git', '-C', directory, 'rev-parse', 'HEAD') != revision:
        raise ValueError('source checkout differs from requested revision')
    if run('git', '-C', directory, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('release builds require clean source checkouts')


def public_key(value):
    if len(base64.b64decode(value, validate=True)) != 32:
        raise ValueError('public key must contain 32 bytes')
    return value


def publish(source, destination):
    # Never replace an artifact another invocation has already produced.
    with Path(source).open('rb') as incoming, destination.open('xb') as output:
        shutil.copyfileobj(incoming, output, 1024 * 1024)
        output.flush()
        os.fsync(output.fileno())
    destination.chmod(0o444)


def extract(iso, path, destination):
    run('xorriso', '-osirrox', 'on', '-indev', iso, '-extract', path, destination,
        stderr=subprocess.DEVNULL)


def inspect_template(iso, package, args, work):
    expected = {
        '/cybex/release-public-key': (args.release_public_key + '\n').encode(),
        '/cybex/provisioning-public-keys': ('\n'.join(args.provisioning_public_key) + '\n').encode(),
        '/cybex/nixos-appliance': b'3\n',
        '/CYBEX_PROVISIONING.BIN': bytes(8192),
    }
    for index, (path, content) in enumerate(expected.items()):
        target = work / ('inspect-' + str(index))
        extract(iso, path, target)
        if target.read_bytes() != content:
            raise ValueError('built ISO public trust or personalization input differs')
    bootstrap = work / 'embedded-bootstrap'
    extract(iso, '/cybex/bootstrap/cybex-james-bootstrap', bootstrap)
    if sha256(bootstrap) != sha256(package / 'bin/cybex-james-bootstrap'):
        raise ValueError('ISO bootstrap differs from verified compiled package')
    if run(package / 'bin/cybex-james-bootstrap', 'required-manage-origin') != args.expected_manage_origin:
        raise ValueError('compiled bootstrap Manage origin differs')
    grub = work / 'grub.cfg'
    extract(iso, '/EFI/BOOT/grub.cfg', grub)
    content = grub.read_text()
    entries = re.findall(r'^\s*menuentry\s+[\'"]([^\'"]+)[\'"]', content, re.MULTILINE)
    if entries != ['Boot Cybex James Setup'] or re.search(r'^\s*submenu\s', content, re.MULTILINE):
        raise ValueError('ISO must expose exactly one branded installer entry')
    report = subprocess.run(['xorriso', '-indev', str(iso), '-find', '/CYBEX_PROVISIONING.BIN', '-exec', 'report_lba', '--'],
                            check=True, text=True, capture_output=True)
    rows = re.findall(r'File data lba:\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,', report.stdout + report.stderr)
    if len(rows) != 1 or int(rows[0][0]) != 0 or int(rows[0][2]) != 4 or int(rows[0][3]) != 8192:
        raise ValueError('personalization slot must have one contiguous 8192-byte ISO extent')
    offset = int(rows[0][1]) * 2048
    with iso.open('rb') as stream:
        stream.seek(offset)
        if stream.read(8192) != bytes(8192):
            raise ValueError('personalization offset does not contain the zero placeholder')
    return offset


def build(args):
    manage = Path(args.manage_source_dir).absolute()
    clean_checkout(REPO, args.source_revision, 'james')
    clean_checkout(manage, args.manage_source_revision, 'development')
    run(sys.executable, REPO / 'tools/james-release.py', 'validate-manage-origin',
        '--expected-manage-origin', args.expected_manage_origin)
    public_key(args.release_public_key)
    keys = args.provisioning_public_key
    if not 1 <= len(keys) <= 8 or sorted(set(keys)) != keys:
        raise ValueError('provisioning public keys must be sorted and unique')
    for key in keys:
        public_key(key)
    version = tomllib.loads((REPO / 'Cargo.toml').read_text())['package']['version']
    output = Path(args.unsigned_output_dir or args.output_dir).absolute()
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or any(output.iterdir()):
        raise ValueError('output directory must be an ordinary empty directory')
    with tempfile.TemporaryDirectory(prefix='.james-build-', dir=output.parent) as temporary:
        work = Path(temporary)
        archive_dir = work / 'manage-source'
        archive = Path(run(REPO / 'nixos-appliance/build-manage-source-archive.sh',
                           '--source-dir', manage, '--revision', args.manage_source_revision, '--output-dir', archive_dir))
        inputs = dict(manageRepo=str(manage), manageSourceArchive=str(archive),
                      manageSourceRevision=args.manage_source_revision, sourceRevision=args.source_revision,
                      releasePublicKey=args.release_public_key, provisioningPublicKeys=keys,
                      manageOrigin=args.expected_manage_origin, sourceDateEpoch=args.source_date_epoch)
        expression = work / 'build.nix'
        expression.write_text('let args = builtins.fromJSON ' + json.dumps(json.dumps(inputs))
                              + '; in import ' + str(REPO / 'nixos-appliance') + ' args\n')
        def nix(attribute):
            return Path(run('nix-build', expression, '-A', attribute, '--no-out-link'))
        if args.kind == 'template':
            image = nix('iso')
            candidates = list((image / 'iso').glob('*.iso'))
            if len(candidates) != 1:
                raise ValueError('Nix ISO output must contain one image')
            iso = candidates[0]
            offset = inspect_template(iso, nix('package'), args, work)
            if iso.stat().st_size >= 2 * 1024 ** 3:
                raise ValueError('installer exceeds the GitHub per-asset publication limit')
            pin_revision = run('nix-instantiate', '--eval', '--strict', '--json', '--expr',
                               '(import ' + str(REPO / 'release/nixpkgs.nix') + ').revision')
            metadata = dict(schema='cybex.james.installer-template-build.v3', version=version,
                            architecture='x86_64-linux', base_os='nixos', base_os_version='26.05',
                            manage_origin=args.expected_manage_origin, package_delivery='system-closure-v1',
                            size_bytes=iso.stat().st_size, template_sha256=sha256(iso),
                            personalization_offset=offset, personalization_size=8192,
                            placeholder_sha256=hashlib.sha256(bytes(8192)).hexdigest(),
                            nixpkgs_revision=json.loads(pin_revision), provisioning_public_keys=keys)
            name = 'cybex-james-appliance-template-' + version + '-x86_64-linux'
            metadata_file = work / 'template.json'
            metadata_file.write_text(json.dumps(metadata, sort_keys=True, separators=(',', ':')) + '\n')
            publish(iso, output / (name + '.iso'))
            publish(metadata_file, output / (name + '.json'))
        else:
            cache, metadata = nix('unsignedCache'), nix('buildMetadata')
            if args.unsigned_output_dir:
                # Ordinary files survive transfer into an isolated signing job.
                shutil.copytree(cache, output / 'cache')
                publish(metadata, output / 'build-metadata.json')
            else:
                name = 'cybex-james-appliance-closure-' + version + '-x86_64-linux'
                subprocess.run([sys.executable, str(REPO / 'tools/pack-system-closure.py'),
                                '--cache', str(cache), '--build-metadata', str(metadata),
                                '--private-key', args.private_key, '--output', str(output / (name + '.tar.zst')),
                                '--metadata-output', str(output / (name + '.json'))], check=True)
    print(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('kind', choices=['template', 'closure'])
    for option in ('manage-source-dir', 'manage-source-revision', 'source-revision', 'expected-manage-origin', 'release-public-key'):
        parser.add_argument('--' + option, required=True)
    parser.add_argument('--provisioning-public-key', action='append', required=True)
    parser.add_argument('--source-date-epoch', type=int, required=True)
    parser.add_argument('--private-key')
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument('--output-dir')
    destination.add_argument('--unsigned-output-dir')
    args = parser.parse_args()
    if args.source_date_epoch < 1:
        parser.error('source date epoch must be positive')
    if args.kind == 'template' and (args.unsigned_output_dir or args.private_key):
        parser.error('template builds require --output-dir and never take a private key')
    if args.kind == 'closure' and bool(args.private_key) == bool(args.unsigned_output_dir):
        parser.error('closure requires either --unsigned-output-dir or --output-dir with --private-key')
    build(args)


if __name__ == '__main__':
    main()
