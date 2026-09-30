#!/usr/bin/env python3
"""Reversible free-page reporting override for an owned, stopped test VM only.

The production change must follow qualified release/restart planning. This tool
requires a caller-held ownership nonce and never stops or starts an instance.
"""
import argparse
import configparser
import io
import json
from pathlib import Path
import subprocess
import uuid


def incus(*args):
    return subprocess.check_output(['incus', *args], text=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('enable', 'restore'))
    parser.add_argument('instance')
    parser.add_argument('--owner', required=True, type=uuid.UUID)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(incus('query', '/1.0/instances/'+args.instance))
    if data['type'] != 'virtual-machine' or data['status'] != 'Stopped':
        raise RuntimeError('Requires a stopped disposable VM')
    if data['config'].get('user.tiaris-memory-owner') != str(args.owner):
        raise RuntimeError('Instance ownership nonce does not match')
    if args.action == 'restore':
        receipt = json.loads(args.receipt.read_text())
        if receipt['instance'] != args.instance or receipt['owner'] != str(args.owner):
            raise RuntimeError('Receipt ownership mismatch')
        if data['config'].get('raw.qemu.conf', '') != receipt['applied']:
            raise RuntimeError('Override changed since enable; refusing to overwrite it')
        if receipt['previous_local'] is None:
            incus('config', 'unset', args.instance, 'raw.qemu.conf')
        else:
            incus('config', 'set', args.instance, 'raw.qemu.conf', receipt['previous_local'])
        return
    original = data['expanded_config'].get('raw.qemu.conf', '')
    config = configparser.RawConfigParser(interpolation=None, strict=True)
    config.optionxform = str
    config.read_string(original)
    section = 'device "qemu_balloon"'
    if not config.has_section(section): config.add_section(section)
    config.set(section, 'free-page-reporting', '"on"')
    output = io.StringIO()
    config.write(output)
    applied = output.getvalue()
    receipt = dict(schema='tiaris.nest.incus-memory-override.v1', instance=args.instance,
                   owner=str(args.owner), previous_local=data['config'].get('raw.qemu.conf'), applied=applied)
    # Persist rollback before mutation. Do not overwrite another qualification.
    with args.receipt.open('x') as file:
        json.dump(receipt, file, indent=2)
    incus('config', 'set', args.instance, 'raw.qemu.conf', applied)


if __name__ == '__main__':
    main()
