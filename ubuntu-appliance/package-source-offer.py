#!/usr/bin/env python3
"""Keep complete source/licensing material without extending snapshot wire grammar."""
import argparse
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


def package_source_offer(snapshot, version, epoch):
    snapshot = Path(snapshot)
    if snapshot.is_symlink() or not snapshot.is_dir():
        raise ValueError('snapshot must be a regular directory')
    snapshot = snapshot.resolve()
    if not re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+(?:[-+][0-9A-Za-z.-]+)?', version):
        raise ValueError('source-offer package version is invalid')
    if not re.fullmatch(r'[0-9]{1,12}', str(epoch)):
        raise ValueError('source-offer epoch is invalid')
    files = [snapshot / 'CYBEX-SBOM.spdx.json', snapshot / 'UDPCAST-COPYRIGHT']
    sources = sorted(p for p in snapshot.glob('udpcast_*') if not p.name.endswith('.deb'))
    if len(sources) < 3 or sum(p.name.endswith('.dsc') for p in sources) != 1:
        raise ValueError('complete UDPcast corresponding source is required')
    files += sources
    identities = {}
    for path in files:
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or not re.fullmatch(r'[A-Za-z0-9+_.-]{1,255}', path.name)
                or not 0 < metadata.st_size <= 64 * 1024 * 1024):
            raise ValueError('unsafe source-offer input')
        identities[path] = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
    output = snapshot / ('cybex-james-source-offer_' + version + '-1_all.deb')
    if output.exists() or output.is_symlink():
        raise ValueError('source-offer package already exists')
    with tempfile.TemporaryDirectory(prefix='.cybex-source-offer-', dir=snapshot.parent) as temporary:
        temporary = Path(temporary)
        root = temporary / 'package'
        control = root / 'DEBIAN'
        documents = root / 'usr/share/doc/cybex-james/source-offer'
        control.mkdir(parents=True)
        documents.mkdir(parents=True)
        for path in files:
            shutil.copyfile(path, documents / path.name)
            (documents / path.name).chmod(0o644)
        (control / 'control').write_text(chr(10).join([
            'Package: cybex-james-source-offer', 'Version: ' + version + '-1',
            'Section: doc', 'Priority: optional', 'Architecture: all',
            'Maintainer: Cybex <support@cybex.net>',
            'Description: Complete corresponding source and SPDX for the James snapshot', '',
        ]))
        for directory, _, names in os.walk(root):
            Path(directory).chmod(0o755)
            for name in names:
                (Path(directory) / name).chmod(0o644)
        package = temporary / 'source-offer.deb'
        subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(root), str(package)],
                       env={**os.environ, 'SOURCE_DATE_EPOCH': str(epoch)},
                       check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['dpkg-deb', '--info', str(package)], check=True, stdout=subprocess.DEVNULL)
        package.chmod(0o644)
        # Link is atomic and refuses any existing destination. Only after the
        # source offer is safely present may the incompatible loose files go.
        os.link(package, output)
    for path, identity in identities.items():
        metadata = path.lstat()
        if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != identity:
            raise ValueError('source-offer input changed during packaging')
    for path in files:
        path.unlink()
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--epoch', required=True)
    args = parser.parse_args()
    print(package_source_offer(args.snapshot, args.version, args.epoch).name)


if __name__ == '__main__':
    main()
