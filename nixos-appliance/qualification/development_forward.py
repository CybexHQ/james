"""Exact-owner forwarding for disposable development bridges on Docker hosts.

A new Incus bridge cannot override Docker's FORWARD policy through its independent
nftables table. Install one early jump matching only this bridge in each direction,
with a uniquely owned chain. Never change a global policy or an existing lab rule.
This is development transport, not the offline isolated-Manage firewall adapter.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import uuid

SCHEMA = 'cybex.james.development-forward.v1'
COMMAND_ENV = {
    'LC_ALL': 'C',
    'PATH': '/run/wrappers/bin:/run/current-system/sw/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
}


def identity(scope):
    owner = str(uuid.UUID(scope['owner']))
    bridge = scope['bridge']
    subnet = ipaddress.ip_interface(scope['subnet'])
    if (owner != scope['owner'] or not re.fullmatch(r'jnq[0-9a-f]{10}', bridge)
            or subnet.version != 4 or subnet.network.prefixlen != 24
            or not any(subnet.network.subnet_of(ipaddress.ip_network(v))
                       for v in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))):
        raise ValueError('invalid disposable forwarding owner or subnet')
    return {'schema': SCHEMA, 'owner': owner, 'bridge': bridge, 'subnet': str(subnet)}


def chain(scope):
    identity(scope)
    return 'JNQF_' + uuid.UUID(scope['owner']).hex[:20]


def rules(scope, ipv6=False):
    name, bridge = chain(scope), scope['bridge']
    mark = ['-m', 'comment', '--comment', 'cybex-qualification:' + scope['owner']]
    def rule(*args):
        return ['-A', name, *args[:-2], *mark, *args[-2:]]
    if ipv6:
        return [rule('-j', 'DROP')]
    subnet = str(ipaddress.ip_interface(scope['subnet']).network)
    result = [rule('-i', bridge, '-o', bridge, '-j', 'ACCEPT'),
              rule('-d', subnet, '-o', bridge, '-m', 'conntrack', '--ctstate',
                   'RELATED,ESTABLISHED', '-j', 'ACCEPT')]
    # Disallow every other local network, including Docker and production labs.
    # Link-local/loopback/multicast destinations must not escape this bridge.
    for network in ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
                    '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
                    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
                    '224.0.0.0/4', '240.0.0.0/4'):
        result.append(rule('-d', network, '-i', bridge, '-j', 'DROP'))
    result += [rule('-s', subnet, '-i', bridge, '-p', 'tcp', '-m', 'multiport',
                    '--dports', '80,443', '-j', 'ACCEPT'),
               rule('-s', subnet, '-i', bridge, '-p', 'udp', '-m', 'udp',
                    '--dport', '123', '-j', 'ACCEPT'), rule('-j', 'DROP')]
    return result


def anchors(scope):
    return [['-A', 'FORWARD', direction, scope['bridge'], '-m', 'comment', '--comment',
             'cybex-qualification:' + scope['owner'], '-j', chain(scope)]
            for direction in ('-o', '-i')]


def run(arguments, *, data=None):
    result = subprocess.run(arguments, input=data, capture_output=True, check=False,
                            env=COMMAND_ENV)
    if result.returncode:
        raise ValueError('owned qualification forwarding command failed')
    return result.stdout


def observed(scope, ipv6, execute):
    binary = 'ip6tables' if ipv6 else 'iptables'
    rows = [shlex.split(row) for row in execute([binary, '--wait', '10', '-S']).decode().splitlines()]
    name = chain(scope)
    exists = ['-N', name] in rows
    contents = [row for row in rows if row[:2] == ['-A', name]]
    references = [row for row in rows if row[:1] == ['-A']
                  and any(value in {'-j', '-g'} and row[index + 1] == name
                          for index, value in enumerate(row[:-1]))]
    return exists, contents, references, rows


def check(scope, ipv6, execute, *, missing=False, require_priority=True):
    exists, contents, references, rows = observed(scope, ipv6, execute)
    if missing and not exists and not contents and not references:
        return False
    if not exists or contents != rules(scope, ipv6) or references != anchors(scope):
        raise ValueError('qualification forwarding rules changed ownership or contents')
    parent = [row for row in rows if row[:2] == ['-A', 'FORWARD']]
    if require_priority and parent[:2] != anchors(scope):
        raise ValueError('qualification forwarding no longer precedes Docker forwarding')
    return True


def qualification_resources(rows):
    return [row for row in rows
            if (row[:1] == ['-N'] and len(row) == 2 and row[1].startswith('JNQF_'))
            or any(value.startswith('cybex-qualification:') for value in row)]


def transaction(ipv6, lines, execute):
    binary = 'ip6tables-restore' if ipv6 else 'iptables-restore'
    body = ('*filter\n' + '\n'.join(' '.join(row) for row in lines) + '\nCOMMIT\n').encode()
    execute([binary, '--wait', '10', '--noflush'], data=body)


def receipt(path, scope):
    file = path / 'forwarding.json'
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or info.st_mode & 0o077 or not 0 < info.st_size <= 4096):
            raise ValueError('qualification forwarding receipt is not private and owned')
        body = os.read(fd, 4097)
        if len(body) != info.st_size or json.loads(body) != identity(scope):
            raise ValueError('qualification forwarding receipt differs from the scope')
    finally:
        os.close(fd)


def create_receipt(path, scope):
    file = path / 'forwarding.json'
    temporary = path / ('.forwarding.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        body = (json.dumps(identity(scope), sort_keys=True) + '\n').encode()
        offset = 0
        while offset != len(body):
            written = os.write(fd, body[offset:])
            if written <= 0:
                raise ValueError('short forwarding ownership write')
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        # Linking a complete private temporary file gives the final receipt
        # atomic no-replace creation semantics without a partially readable
        # ownership record.
        os.link(temporary, file, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def prepare(path, scope, execute=run):
    for ipv6 in (False, True):
        own = observed(scope, ipv6, execute)
        if any(own[:3]):
            raise ValueError('refusing to adopt existing qualification forwarding')
        if qualification_resources(own[3]):
            raise ValueError('another qualification forwarding scope is already active')
    create_receipt(path, scope)
    for ipv6 in (False, True):
        inserts = [['-I', 'FORWARD', '1', *row[2:]] for row in reversed(anchors(scope))]
        transaction(ipv6, [['-N', chain(scope)], *rules(scope, ipv6), *inserts], execute)
        check(scope, ipv6, execute)


def verify(path, scope, execute=run):
    receipt(path, scope)
    for ipv6 in (False, True):
        check(scope, ipv6, execute)


def cleanup(path, scope, execute=run):
    # Old, failed pre-forwarding runs own no firewall resources. Refuse a name
    # collision even then; never infer ownership from the interface name alone.
    if not (path / 'forwarding.json').exists():
        for ipv6 in (False, True):
            if any(observed(scope, ipv6, execute)[:3]):
                raise ValueError('forwarding resources exist without an ownership receipt')
        return
    receipt(path, scope)
    present = [check(scope, family, execute, missing=True, require_priority=False)
               for family in (False, True)]
    for ipv6, exists in zip((False, True), present):
        if exists:
            deletes = [['-D', *row[1:]] for row in anchors(scope)]
            deletes += [['-D', *row[1:]] for row in rules(scope, ipv6)]
            transaction(ipv6, [*deletes, ['-X', chain(scope)]], execute)
    for ipv6 in (False, True):
        if any(observed(scope, ipv6, execute)[:3]):
            raise ValueError('owned forwarding cleanup is incomplete')
