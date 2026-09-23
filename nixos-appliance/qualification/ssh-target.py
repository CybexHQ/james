#!/usr/bin/env python3
"""Select only the owned fixture's reported SSH address."""
import ipaddress
import json
import sys
import urllib.parse
from pathlib import Path


def fixture_address(node, scope, mac):
    network = ipaddress.ip_interface(scope['subnet']).network
    if network.version != 4:
        raise ValueError('qualification subnet must be IPv4')
    interfaces = node['appliance_network']['interfaces']
    addresses = set()
    for interface in interfaces:
        if interface.get('address', '').lower() != mac.lower():
            continue
        for info in interface.get('addr_info', []):
            if info.get('family') != 'inet' or info.get('scope') != 'global':
                continue
            address = ipaddress.ip_address(info['local'])
            if address not in network or address == ipaddress.ip_interface(scope['subnet']).ip:
                raise ValueError('owned fixture address is outside its disposable bridge')
            addresses.add(address)
    if len(addresses) != 1:
        raise ValueError('expected one global IPv4 address on the owned fixture MAC')
    address = addresses.pop()
    for field in ('public_base_url', 'cache_base_url'):
        url = node.get(field)
        if url is None or url == '':
            continue
        if not isinstance(url, str):
            raise ValueError(field + ' must be a URL or absent')
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError(field + ' is not an HTTP endpoint')
        try:
            reported = ipaddress.ip_address(parsed.hostname)
        except ValueError as error:
            raise ValueError(field + ' must use the owned fixture IPv4 address') from error
        if reported != address:
            raise ValueError(field + ' differs from the owned fixture address')
    return str(address)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: ssh-target.py NODE_JSON SCOPE_JSON FIXTURE_MAC')
    print(fixture_address(json.loads(Path(sys.argv[1]).read_text()),
                          json.loads(Path(sys.argv[2]).read_text()), sys.argv[3]))
