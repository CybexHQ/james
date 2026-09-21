#!/usr/bin/env python3
"""Run the official lifecycle on an explicitly owned development network."""
import argparse
import datetime
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from isolated_fixture import API, private_state, SCOPE

ROOT = Path(__file__).resolve().parents[2]


def interrupted(_number, _frame):
    raise KeyboardInterrupt('Owned lifecycle interrupted; guest cleanup remains active')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--predecessor-identity", type=Path)
    parser.add_argument("--retain-fixture", type=Path)
    parser.add_argument("--require-candidate-runtime", action="store_true")
    parser.add_argument("--prepublication-candidate", action="store_true")
    args = parser.parse_args()
    state = private_state(args.state_dir)
    isolation = SCOPE['read_scope'](state)
    origin = isolation['manage_origin']
    api = API(state)
    catalog = json.loads(subprocess.check_output([sys.executable, "-B", str(Path(__file__).with_name("blueprint-catalog.py")),
                "--manage-origin", origin, "--token-file", str(state / "session")]))
    manifest = json.loads(args.manifest.read_bytes())
    version = manifest["version"]
    template = args.manifest.parent / f"cybex-james-appliance-template-{version}-x86_64-linux.iso"
    command = ["bash", str(Path(__file__).with_name("run-lifecycle.sh")), "--template", str(template), "--manifest", str(args.manifest),
               "--manage-origin", origin, "--token-file", str(state / "session"), "--output", str(args.output)]
    if args.predecessor_identity:
        command += ["--predecessor-identity", str(args.predecessor_identity)]
    if args.retain_fixture:
        command += ["--retain-fixture", str(args.retain_fixture)]
    if args.require_candidate_runtime:
        command += ["--require-candidate-runtime"]
    if args.prepublication_candidate:
        command += ["--prepublication-candidate"]
    environment = {**os.environ, "CYBEX_JAMES_QUALIFICATION_BRIDGE": isolation["bridge"],
                   "CYBEX_JAMES_QUALIFICATION_MANAGEMENT_CIDR": isolation["subnet"].split("/")[0] + "/32",
                   "CYBEX_JAMES_QUALIFICATION_STATE": str(state), "CYBEX_JAMES_HAS_PREDECESSOR": "true"}
    temporary = state / "temporary"
    temporary.mkdir(mode=0o700, exist_ok=True)
    environment["TMPDIR"] = str(temporary)
    environment["CYBEX_JAMES_QUALIFICATION_FAILURE_DIRECTORY"] = str(state / ("failed-fixture-" + str(int(time.time()))))
    started = datetime.datetime.now(datetime.timezone.utc)
    session_receipt = state / "lifecycle-session.json"
    environment["CYBEX_JAMES_QUALIFICATION_SESSION_RECEIPT"] = str(session_receipt)
    signal.signal(signal.SIGTERM, interrupted)
    process = subprocess.Popen(command, env=environment, start_new_session=True)
    last = None
    admitted = set()
    try:
        while process.poll() is None:
            sessions = []
            if session_receipt.is_file():
                owned = json.loads(session_receipt.read_bytes())
                session = api('/v1/james/provisioning-sessions/' + owned['session_id'])
                if session['release_version'] != version or session['id'] != owned['session_id']:
                    raise ValueError('Owned lifecycle session identity changed')
                sessions = [session]
            if sessions:
                session = sessions[0]
                device = session.get("reserved_device_id")
                observation = {"session_state": session["state"], "device_id": device}
                if device and session["state"] == "ready":
                    runtime = api(f"/v1/james/nodes/{device}/workstation-netboot")
                    jobs = api(f"/v1/james/nodes/{device}/build/jobs?limit=200&offset=0")["jobs"]
                    observation.update(runtime=runtime["state"], jobs=[v["status"] for v in jobs])
                    if runtime.get("operational") and runtime.get("converged"):
                        for blueprint in catalog["blueprints"]:
                            revision = blueprint["current_revision_id"]
                            if revision in admitted or any(j["build_spec"].get("blueprint_revision_id") == revision and j["status"] in {"queued", "running", "succeeded"} for j in jobs):
                                continue
                            api(f"/v1/james/nodes/{device}/build/jobs", {"requested_artifact_type": "nixos_closure",
                                "blueprint_id": blueprint["id"], "blueprint_revision_id": revision, "target": "blueprint", "system": "x86_64-linux"})
                            admitted.add(revision)
                if observation != last:
                    print(json.dumps(observation), flush=True)
                    last = observation
            if (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds() > 14400:
                raise ValueError("Isolated lifecycle exceeded its four-hour maintenance window")
            time.sleep(5)
        if process.returncode:
            raise ValueError(f"Official lifecycle failed (exit {process.returncode})")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


if __name__ == "__main__":
    main()
