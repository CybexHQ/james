"""Choose SSH only from the owned appliance MAC and private fixture subnet."""
import argparse
import ipaddress
import json
from pathlib import Path


def address(node, scope, mac):
    interface = ipaddress.ip_interface(scope['subnet'])
    candidates = []
    for device in node.get('appliance_network', {}).get('interfaces', []):
        if device.get('address', '').lower() != mac.lower():
            continue
        for item in device.get('addr_info', []):
            if item.get('family') != 'inet' or item.get('scope') != 'global':
                continue
            host = ipaddress.ip_address(item['local'])
            if (host.version != 4 or host not in interface.network
                    or host in {interface.ip, interface.network.network_address, interface.network.broadcast_address}):
                raise ValueError('reported appliance address escaped the owned fixture')
            candidates.append(str(host))
    if len(candidates) != 1:
        raise ValueError('owned appliance must report one unambiguous fixture address')
    return candidates[0]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--mac', required=True)
    args = parser.parse_args()
    print(address(json.loads(args.node.read_bytes()), json.loads(args.scope.read_bytes()), args.mac))
