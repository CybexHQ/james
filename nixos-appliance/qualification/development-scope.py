#!/usr/bin/env python3
"""Own one disposable development network; refuse adoption of existing lab state."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
from urllib.parse import urlsplit
import uuid

SCHEMA = "cybex.james.nixos-development-scope.v1"
FIELDS = {"schema", "run", "manage_origin", "bridge", "subnet", "owner"}


def hardware_identity(scope, role):
    if role not in {'appliance', 'workstation'}:
        raise ValueError('unknown disposable hardware role')
    owner = uuid.UUID(scope['owner'])
    digest = hashlib.sha256((str(owner) + ':' + role).encode()).digest()
    return {'mac': '02:' + ':'.join(f'{value:02x}' for value in digest[:5]),
            'serial': 'JNQ' + owner.hex[:20] + role[0],
            'uuid': str(uuid.uuid5(owner, role))}


def development_origin(value):
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.path or url.query or url.fragment
            or url.username or url.password or url.netloc != url.netloc.lower()
            or not (url.hostname.startswith("dev.") or url.hostname.endswith(".test"))):
        raise ValueError("qualification requires an explicit canonical HTTPS development origin")
    return value


def incus(*args):
    result = subprocess.run(["incus", *args], capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError("owned qualification network operation failed")
    return result.stdout


def read_scope(path):
    if path.is_symlink() or not path.is_dir():
        raise ValueError("qualification state must be an ordinary private directory")
    mode = path.stat()
    if mode.st_uid != os.geteuid() or stat.S_IMODE(mode.st_mode) != 0o700:
        raise ValueError("qualification state must be owned by its caller with mode 0700")
    fd = os.open(path / "scope.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or not 0 < info.st_size <= 4096):
            raise ValueError("qualification ownership receipt is invalid")
        body = os.read(fd, 4097)
        if len(body) != info.st_size:
            raise ValueError("qualification receipt changed during inspection")
    finally:
        os.close(fd)
    value = json.loads(body)
    if (not isinstance(value, dict) or set(value) != FIELDS or value["schema"] != SCHEMA
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", value["run"])
            or value["bridge"] != "jnq" + hashlib.sha256(value["run"].encode()).hexdigest()[:10]
            or str(uuid.UUID(value["owner"])) != value["owner"]):
        raise ValueError("qualification ownership receipt does not match the run")
    development_origin(value["manage_origin"])
    return value


def verify(path, origin, bridge):
    development_origin(origin)
    scope = read_scope(path)
    if (scope["manage_origin"], scope["bridge"]) != (origin, bridge):
        raise ValueError("qualification origin or network differs from its owned run")
    network = json.loads(incus("query", "/1.0/networks/" + bridge))
    config = network["config"]
    if (network["name"] != bridge or network["type"] != "bridge" or not network["managed"]
            or config.get("user.cybex.nixos-qualification") != scope["owner"]
            or config.get("ipv4.address") != scope["subnet"]
            or config.get("ipv4.nat") != "true" or config.get("ipv6.address") != "none"):
        raise ValueError("qualification bridge no longer matches its ownership receipt")
    return scope, network


def prepare(args):
    development_origin(args.manage_origin)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", args.run):
        raise ValueError("qualification run identity is invalid")
    subnet = ipaddress.ip_interface(args.subnet)
    if subnet.version != 4 or subnet.network.prefixlen != 24 or not subnet.ip.is_private or subnet.ip.is_loopback:
        raise ValueError("qualification requires a dedicated private IPv4 /24")
    bridge = "jnq" + hashlib.sha256(args.run.encode()).hexdigest()[:10]
    existing = json.loads(incus("network", "list", "--format=json"))
    for network in existing:
        if network["name"] == bridge:
            raise ValueError("refusing to adopt an existing qualification network")
        address = network.get("config", {}).get("ipv4.address", "")
        if "/" in address and subnet.network.overlaps(ipaddress.ip_interface(address).network):
            raise ValueError("qualification subnet overlaps an existing managed network")
    routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route", "show"], text=True))
    for route in routes:
        if route.get("dst") not in {None, "default"} and subnet.network.overlaps(ipaddress.ip_network(route["dst"], strict=False)):
            raise ValueError("qualification subnet overlaps an existing host route")
    args.state_dir.mkdir(mode=0o700)
    scope = {"schema": SCHEMA, "run": args.run, "manage_origin": args.manage_origin,
             "bridge": bridge, "subnet": str(subnet), "owner": str(uuid.uuid4())}
    fd = os.open(args.state_dir / "scope.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        body = (json.dumps(scope, sort_keys=True) + "\n").encode()
        os.write(fd, body)
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(args.state_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    try:
        incus("network", "create", bridge, "--type=bridge", "ipv4.address=" + str(subnet),
              "ipv4.nat=true", "ipv6.address=none", "user.cybex.nixos-qualification=" + scope["owner"])
        verify(args.state_dir, args.manage_origin, bridge)
    except BaseException:
        # A failed create RPC may still have created the network. Remove only
        # this durable receipt's exact owner after checking for live clients.
        observed = json.loads(incus('network', 'list', '--format=json'))
        matches = [network for network in observed if network['name'] == bridge
                   and network.get('config', {}).get('user.cybex.nixos-qualification') == scope['owner']]
        if matches:
            cleanup(args.state_dir, args.manage_origin, bridge)
        raise
    print(json.dumps(scope, sort_keys=True))


def cleanup(path, origin, bridge):
    _, network = verify(path, origin, bridge)
    if network.get('used_by'):
        raise ValueError('qualification network still has attached instances')
    # QEMU clients do not appear in Incus used_by. Never kill a client to make
    # bridge deletion succeed: its owning VM context must release it first.
    links = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'master', bridge], text=True))
    if links:
        raise ValueError('qualification network still has attached host interfaces')
    incus('network', 'delete', bridge)


def tap(path, origin, bridge, role, create):
    scope, _ = verify(path, origin, bridge)
    if role not in {'appliance', 'workstation'}:
        raise ValueError('unknown disposable network role')
    name = bridge + ('a' if role == 'appliance' else 'w')
    links = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show'], text=True))
    current = [link for link in links if link['ifname'] == name]
    if create:
        if current:
            raise ValueError('refusing to adopt an existing TAP')
        # Keep a new TAP nonpersistent while configuring it. Closing this exact
        # FD on any setup failure releases the interface without name-based
        # deletion; TUN_EXCL refuses a concurrent existing-device race.
        fd = os.open('/dev/net/tun', os.O_RDWR | os.O_CLOEXEC)
        try:
            fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', name.encode(), 0x0002 | 0x1000 | 0x8000))
            subprocess.run(['ip', 'link', 'set', 'dev', name, 'alias', scope['owner']], check=True)
            subprocess.run(['ip', 'link', 'set', 'dev', name, 'master', bridge, 'up'], check=True)
            fcntl.ioctl(fd, 0x400454cb, 1)
        finally:
            os.close(fd)
    else:
        if len(current) != 1 or current[0].get('ifalias') != scope['owner'] or current[0].get('master') != bridge:
            raise ValueError('TAP no longer matches this run owner and bridge')
        subprocess.run(['ip', 'link', 'delete', 'dev', name], check=True)
    return name


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("action", choices=("prepare", "verify", "cleanup", "tap-create", "tap-delete", "hardware"))
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--manage-origin", required=True)
    parser.add_argument("--bridge")
    parser.add_argument("--run")
    parser.add_argument("--subnet")
    parser.add_argument("--role", choices=("appliance", "workstation"))
    args = parser.parse_args()
    if args.action == "prepare":
        if not args.run or not args.subnet:
            parser.error("prepare requires --run and --subnet")
        prepare(args)
        return
    if not args.bridge:
        parser.error("verify and cleanup require --bridge")
    scope, network = verify(args.state_dir, args.manage_origin, args.bridge)
    if args.action == 'hardware':
        print(json.dumps(hardware_identity(scope, args.role), sort_keys=True))
        return
    if args.action.startswith('tap-'):
        print(tap(args.state_dir, args.manage_origin, args.bridge, args.role, args.action == 'tap-create'))
        return
    if args.action == "cleanup":
        cleanup(args.state_dir, args.manage_origin, args.bridge)
        print("Removed the exact owned qualification network; evidence retained")
    else:
        print("Verified isolated development qualification scope")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError):
        print("error: development qualification scope failed its ownership or environment checks", file=sys.stderr)
        raise SystemExit(2)
