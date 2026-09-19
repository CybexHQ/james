#!/usr/bin/env python3
"""Run the official lifecycle against the private production-image database.

The helper owns only normal cache admissions for the new fixture and a private
mount namespace. It cannot select a production device or change host-wide DNS.
"""
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

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--published-predecessor-inputs", type=Path)
    parser.add_argument("--retain-fixture", type=Path)
    parser.add_argument("--require-candidate-runtime", action="store_true")
    parser.add_argument("--namespace", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    state = args.state_dir.resolve(strict=True)
    if (os.geteuid() != 0 or state.parent != Path("/var/lib/cybex-james-qualification")
            or state.stat().st_uid != 0 or state.stat().st_mode & 0o077):
        raise ValueError("Expected private, root-owned qualification state")
    isolation = json.loads((state / "isolation.json").read_bytes())
    if isolation["schema"] != "cybex.james.isolated-manage.v1" or isolation["origin"] != "https://manage.cybex.net":
        raise ValueError("Invalid qualification isolation receipt")
    if not args.namespace:
        os.execvp("unshare", ["unshare", "--mount", "--propagation", "private", sys.executable,
                             str(Path(__file__).resolve()), *sys.argv[1:], "--namespace"])
    if os.readlink("/proc/self/ns/mnt") == os.readlink("/proc/1/ns/mnt"):
        raise ValueError("Refusing to change hosts outside a private mount namespace")
    subprocess.run(["mount", "--bind", str(state / "hosts"), "/etc/hosts"], check=True)
    subprocess.run(["mount", "-o", "remount,bind,ro", "/etc/hosts"], check=True)
    token = (state / "session").read_text().strip()
    origin = isolation["origin"]

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError("Qualification API redirected")

    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def api(path, body=None):
        request = urllib.request.Request(origin + path, headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                                         data=None if body is None else json.dumps(body).encode())
        with client.open(request, timeout=30) as response:
            return json.loads(response.read())

    catalog = json.loads(subprocess.check_output([sys.executable, "-B", str(Path(__file__).with_name("blueprint-catalog.py")),
                "--manage-origin", origin, "--token-file", str(state / "session")]))
    manifest = json.loads(args.manifest.read_bytes())
    version = manifest["version"]
    template = args.manifest.parent / f"cybex-james-appliance-template-{version}-x86_64-linux.iso"
    command = ["bash", str(Path(__file__).with_name("run-lifecycle.sh")), "--template", str(template), "--manifest", str(args.manifest),
               "--manage-origin", origin, "--token-file", str(state / "session"), "--output", str(args.output)]
    if args.published_predecessor_inputs:
        command += ["--published-predecessor-inputs", str(args.published_predecessor_inputs)]
    if args.retain_fixture:
        command += ["--retain-fixture", str(args.retain_fixture)]
    if args.require_candidate_runtime:
        command += ["--require-candidate-runtime"]
    environment = {**os.environ, "CYBEX_JAMES_QUALIFICATION_BRIDGE": isolation["bridge"],
                   "CYBEX_JAMES_QUALIFICATION_MANAGEMENT_CIDR": "10.62.57.1/32", "CYBEX_JAMES_HAS_PREDECESSOR": "true"}
    temporary = state / "temporary"
    temporary.mkdir(mode=0o700, exist_ok=True)
    environment["TMPDIR"] = str(temporary)
    environment["CYBEX_JAMES_QUALIFICATION_FAILURE_DIRECTORY"] = str(state / ("failed-fixture-" + str(int(time.time()))))
    started = datetime.datetime.now(datetime.timezone.utc)
    process = subprocess.Popen(command, env=environment, start_new_session=True)
    last = None
    admitted = set()
    try:
        while process.poll() is None:
            sessions = api("/v1/james/provisioning-sessions?limit=100&offset=0")["sessions"]
            sessions = [v for v in sessions if v["release_version"] == version and datetime.datetime.fromisoformat(v["created_at"].replace("Z", "+00:00")) >= started]
            if len(sessions) > 1:
                raise ValueError("Another lifecycle entered this isolated instance")
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
