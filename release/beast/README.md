# Local build and qualification on The Beast

Protected version-tag jobs use the existing runner with the `cybex-james-lab`
label. Pull requests and ordinary main checks remain on GitHub-hosted runners.
Only trusted release jobs may run on this host. The NixOS qualification jobs use
the separate protected `james-nixos-development-qualification` environment;
signing and publication retain `production-release`.

The NixOS production release pipeline is **blocked** pending a separately
approved contract for isolated qualification of production-bound artifacts.
The current runner accepts development origins only, and the candidate and
predecessor must already contain that exact signed origin. Setting the
qualification origin cannot retarget an immutable production candidate.
Publication and stable/latest promotion require production-bound artifacts and
reject development fixtures. Development qualification therefore cannot pass
as production release evidence. These guards deliberately leave the production
path unavailable until that missing contract is implemented and verified.

`tools/beast-build.py` creates clean, shallow checkouts of the exact James and
Manage commits in a temporary directory. It builds the pinned Dockerfile and
executes by image ID, as the unprivileged runner UID, with no capabilities,
no privilege escalation, 12 CPUs, 48 GiB RAM, no swap, and 8192 processes at most.
The container has ordinary outbound networking for authenticated package sources;
it has no host network, Docker socket, host Nix daemon, production volumes,
runner credentials, signing key or private source key. A small allowlist passes
public build inputs. Signing happens after the container exits, with the existing
protected environment key and signature/compatibility checks.

Before compilation, `preflight.sh` checks the native packaging tools and performs
a compressed cpio archive round trip inside the pinned Nix release-tools shell.
That shell explicitly supplies cpio, jq and Python instead of depending on
packages preinstalled on a GitHub runner. Nix uses the container's explicit Bash
path, so no ambient `nixpkgs` channel is needed.

The dedicated paths below `~/.local/state/cybex-james-build` contain Cargo,
compiled target and Nix caches. These are deliberately separate from
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
gates remain mandatory. Qualification uses the explicitly selected development
Manage API and newly owned Incus bridges, TAPs and disposable QEMU disks. It
never adopts an existing VM or reads a production database. An ownership receipt
binds each run to its exact development origin, bridge and subnet. Cleanup
verifies that receipt before removing owned resources.
Cold qualification never reads the candidate store: it downloads each published
payload from GitHub and verifies the complete receipt inventory before booting.

## Warm predecessor transport cache

The protected warm job can reuse authenticated predecessor transport bytes when
all of the following are configured: current published ancestry, both explicit
NixOS predecessor inputs, and
`CYBEX_JAMES_QUALIFICATION_PREDECESSOR_CACHE_ROOT`. The cache root is an existing
runner-owned mode-0700 directory outside the checkout, on storage large enough
for retained entries plus a staging copy and an output copy. The wrapper retains
at most two complete identities and 32 GiB by default.

The enabled command is:

```sh
python3 -B release/beast/release_speed.py cache \
  --mode github-warm \
  --cache-root "$CYBEX_JAMES_QUALIFICATION_PREDECESSOR_CACHE_ROOT" \
  --directory "$NEW_PREDECESSOR_DIRECTORY" \
  --predecessor-dir "$CYBEX_JAMES_NIXOS_QUALIFICATION_PREDECESSOR_DIR" \
  --predecessor-manifest-sha256 "$CYBEX_JAMES_NIXOS_QUALIFICATION_PREDECESSOR_MANIFEST_SHA256" \
  --expected-identity "$BUILD_ANCESTRY" \
  --authorization release/recovery-adoption.json \
  --repository "$GITHUB_REPOSITORY" \
  --candidate-version "$CYBEX_JAMES_RELEASE_VERSION" \
  --trusted-public-key "$CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY" \
  --timing-dir "$NEW_PRIVATE_TIMING_DIRECTORY"
```

`$NEW_PREDECESSOR_DIRECTORY` must be a new child of a caller-owned mode-0700
snapshot parent. The workflow creates that parent beneath `RUNNER_TEMP`; it does
not change the permissions of the shared runner directory. The fallback resolver
uses the same private parent and remains active whenever a cache prerequisite is
absent.

The wrapper always performs fresh ancestry resolution and exact comparison,
signed snapshot authentication, current trust/policy binding, full closure/NAR/
source/ISO verification and byte verification. A hit saves authenticated transfer
and copying only. It does not reuse lifecycle success. Missing, corrupt, foreign
or unsafe cache state fails closed; it is left for owner inspection rather than
recursively deleted. The no-explicit-pair branch continues to use the original
resolver. Final publication ancestry verification remains unconditional.

Only `timing.json` is eligible for the separate run-and-attempt-named timing
artifact. It contains bounded hashes, cache hit/miss, verified byte count and
whole-cache-command duration. `stdout.log`, `stderr.log`, private paths, command
arguments, origins and raw API data remain private. If no sidecar exists, no
measurement is claimed.

The serial `release_speed.py run` facade is not wired into Actions yet. It
requires root-owned protected input and output trees plus an explicitly reviewed
resource profile; ordinary runner-workspace paths cannot be trusted through
`sudo`. Until an owner-reviewed staging adapter exists, the workflow keeps the
original complete warm and cold runner commands. Do not enable parallel phases,
rollback-to-update fixture reuse, cold preparation overlap, or offline/zero-egress
claims from this transport cache.

Warm `run --candidate-only` is supported for prepublication execution, subject
to the same clean exact source, signed candidate/predecessor, private-path and
resource admission as an ordinary warm run. It may fetch through existing
authenticated transport. This is distinct from the cache CLI: `cache --mode
candidate-only` is unsupported. `run --offline-artifacts` remains refused, and
cold candidate-only remains refused because it cannot assert published proof.

The run child inherits the wrapper environment except for `SUDO_UID` and
`SUDO_GID`. Removing only those ownership hints keeps the evidence root-private
until the wrapper completes the full five-member warm or two-member cold
acceptance inventory. A future Actions adapter must explicitly export only those
accepted receipts and the allowlisted timing sidecar from private storage; it
must not upload raw diagnostic globs or relax ancestor ownership checks.

Disk admission measures free space at the actual `--state-root`, including the
reservation plus 100 GiB headroom. The resource profile still requires its
private `disk_root` field for schema compatibility, but that field is not the
allocation or free-space authority. Admission does not authorize allocation.

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
zstd, the existing Rust audit tool, KVM/QEMU, OVMF, Incus and the tools used by
`nixos-appliance/qualification/run-lifecycle.sh`. Qualification requires root for
owned bridge/TAP creation; it does not change the host QEMU bridge allowlist.
Provision these prerequisites independently before enabling the protected jobs.
After modifying runner configuration, restart its confirmed user unit,
`cybex-james-runner.service`, only when it is idle.

Configure the following **variables** in
`james-nixos-development-qualification`. File values are absolute host paths,
not credentials embedded in Actions variables. Both prepublication and cold
jobs pass every value as an explicit argument through `sudo -n`; they do not
depend on sudo retaining the runner environment.

| Variable suffix after `CYBEX_JAMES_QUALIFICATION_` | Required value |
| --- | --- |
| `MANAGE_ORIGIN` | Canonical HTTPS development origin, equal to the candidate and predecessor ISO descriptors; a `dev.` hostname or `.test` hostname. |
| `TOKEN_FILE` | Root-owned ordinary single-link file, no group/other permissions, containing a current session for that development API. Never a production session. |
| `SUBNET` | Unused private IPv4 bridge address with `/24` prefix, such as `192.168.246.1/24`; must not overlap Incus networks or host routes. Jobs share a concurrency group and reuse it only after verified cleanup. |
| `STATE_ROOT` | Dedicated root-owned mode-0700 directory for receipts, private sessions and disposable fixtures. Each phase creates a fresh child; failed runs require owned-resource inspection before cleanup. |
| `ALLOW_DEVICE_HELPER` | Root-owned, protected executable that admits only the session identified by `--state-dir` and `--session-id`, after verifying its development ownership receipt. It must never authorize devices against production. |
| `MANAGE_CHECKOUT` | Exact development checkout used by the admission helper to validate qualification inputs and deployed source. This is not the production checkout. |

The optional `CYBEX_JAMES_QUALIFICATION_PREDECESSOR_CACHE_ROOT` belongs to the
same protected qualification environment. It authorizes only runner-private warm
transport storage; it grants no subnet, VM, device-admission, signing, publication
or promotion authority. If it is absent, the original resolver remains active.

The current Manage checkout and deployed harness identity are separate from
the exact candidate/predecessor source ancestors encoded in each fixture's
inputs. Device admission must retain those distinct identities; substituting a
current revision for a signed predecessor invalidates the qualification.

The initial V3 qualification also requires
`CYBEX_JAMES_NIXOS_QUALIFICATION_PREDECESSOR_DIR` and
`CYBEX_JAMES_NIXOS_QUALIFICATION_PREDECESSOR_MANIFEST_SHA256` when published
ancestry is still Ubuntu. Supply a separately signed older NixOS release for
the same development origin. Ubuntu ancestry is retained as history and never
used as a NixOS upgrade fixture. Neither this documentation nor the workflow
provisions a credential, admission helper, development service, or predecessor.

Digital Brain's producer verifier and the coordinated-approval workflow now
select `nixos-appliance/qualification/promote-production-release.py`. Historical
tagged workflows and Ubuntu helpers remain available until the migration's
Phase 4 removal gate passes. Digital Brain/environment setup must provide the
new protected environment, its six explicit variables, development admission
helper and source-bound inputs before qualification can run. Its production
release lifecycle must treat the production-origin isolation gap as a blocker,
not an available release, and must not reuse development evidence for promotion.

Historical successful workflow measurements remain exactly 9,911 and 11,500
seconds. The 3,600-second target, live timing, operator/media/resource readiness,
and N1-N7 owner changes remain unverified. Unit tests and cache sidecars are not
whole-workflow timing evidence.
