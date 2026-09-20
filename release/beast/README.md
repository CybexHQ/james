# Local build and qualification on The Beast

Protected version-tag jobs use the existing `thebeast-james-production` runner
with the `cybex-james-lab` label. Pull requests and ordinary main checks remain
on GitHub-hosted runners. Only trusted release jobs may run on this host.

`tools/beast-build.py` creates clean, shallow checkouts of the exact James and
Manage commits in a temporary directory. It builds the pinned Dockerfile and
executes by image ID, as the unprivileged runner UID, with no capabilities,
no privilege escalation, 12 CPUs, 48 GiB RAM, no swap, and 8192 processes at most.
The container has ordinary outbound networking for authenticated package sources;
it has no host network, Docker socket, host Nix daemon, production volumes,
runner credentials, signing key or private source key. A small allowlist passes
public build inputs. Signing happens after the container exits, with the existing
protected environment key and signature/compatibility checks.

The dedicated paths below `~/.local/state/cybex-james-build` contain Cargo,
compiled target, Nix and Ubuntu ISO caches. These are deliberately separate from
the host Nix store and its build-user IDs. Docker is the isolation boundary;
Nix runs in single-user mode inside it. A host file lock serializes cache use.
Each container and source/scratch directory is removed on success or failure,
including SIGTERM. After power loss, inspect Docker containers named
`cybex-james-build-build-*` and temporary `build-*` directories under that state
path; remove only an abandoned run, never a running build. Do not clear caches
during a release. Caches can be removed while the runner is stopped if disk
reclamation is needed; the next build repopulates them.

Signed candidates live under `~/.local/state/cybex-james-releases/RUN_ID`.
An atomic seal records every filename, size and SHA-256, together with repository,
workflow run, tag and source revision. The corresponding `candidate.json` is
the only file in the GitHub Actions candidate artifact. All release files must
be smaller than GitHub's 2 GiB per-asset limit. No candidate payload travels via
Actions artifact storage. The artifact identity fields in coordinated approval
continue to identify that exact GitHub artifact, now containing the receipt.

Consumers authenticate the receipt ZIP against GitHub's digest and workflow
metadata, then verify every local file before copying it. Existing signature,
source, predecessor, installation, upgrade, rollback and immutable-publication
gates remain mandatory. Private Manage databases and VM disks remain owned by
the existing qualification orchestrator, with its host lock and cleanup.
Cold qualification never reads the candidate store: it downloads each published
payload from GitHub and verifies the complete receipt inventory before booting.

Retries reuse a sealed candidate, including recovery after sealing succeeded
but uploading its receipt failed. If a candidate is missing or corrupted, a
retry fails; it never rebuilds or signs different bytes for that run. Prepare
a new version through the normal coordinated release flow instead. Previously
tagged workflows retain their original Actions-artifact behavior.

Local candidates and their Actions receipts have a 30-day retention period.
The next release prunes expired, recognized local candidates under the store
lock. Qualified public evidence retains its existing 90-day policy. Promotion
does not depend on local retention once the immutable prerelease and cold
evidence exist. Preserve failed run receipts/logs when investigating; no failed
qualification is treated as publication approval.

Host prerequisites are Docker access, Python 3.11+, Git, `gh`, `jq`, OpenSSL,
zstd, the existing Rust audit tool, and the existing qualification prerequisites.
No new host package installation, Nix reconfiguration or production-service
restart is needed. After modifying runner configuration, restart its confirmed
user unit, `cybex-james-runner.service`, only when it is idle.
