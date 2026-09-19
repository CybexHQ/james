#!/usr/bin/env python3
"""Exercise published workstation bytes using only owned private fixtures."""
import argparse
import hashlib
import json
from pathlib import Path

from isolated_fixture import API, Fixture, enter_namespace, private_state
import workstation_lifecycle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--james-evidence', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--namespace', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    state = private_state(args.state_dir)
    enter_namespace(state, args.namespace)
    evidence = json.loads(args.james_evidence.read_bytes())
    manifest = json.loads(args.manifest.read_bytes())
    if (evidence['qualified_manifest_sha256'] != hashlib.sha256(args.manifest.read_bytes()).hexdigest()
            or not evidence['builtin_blueprints_source_free']):
        raise ValueError('Workstation must use the exact freshly qualified James')
    api = API(state)
    with Fixture(state, args.fixture, evidence) as fixture:
        fixture.wait_ready(api)
        workstation_lifecycle.run(api, state, fixture, manifest, evidence['qualified_blueprints'], args.output)


if __name__ == '__main__':
    main()
