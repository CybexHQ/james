# Production release continuity

Production James uses the fleet Ed25519 release authority and provisioning
authority configured in `production-release`. Repository public keys must match
the installed fleet. The protected secret storage names retain the historical
`CYBEX_FORGE_*` prefix; the workflow uses those exact names. Runtime source is
pinned to an exact commit in `CybexHQ/manage`, with a read-only deployment key.
Manage application deployment is a separate operation.

The one-time `recovery-adoption.json` authorization binds the historical GitHub
dev.4 publication and recovered production dev.29 manifests, compatibility
assets, source identity and keys to successor **0.2.3 only**. The current fleet
authority signs this admission. The resolver authenticates the old publication
under its original authority and dev.29 under the current authority, then
inspects the signed package and actual updater contract. It rechecks this exact
identity under the publication lock. Later releases follow the ordinary signed
predecessor path. Removing either artifact, moving a tag, changing a digest or
using this authorization for another successor fails closed. The failed 0.2.2
candidate and its original authorization remain unchanged at their tag; 0.2.3
supersedes that unpublished candidate with retained-source compatibility.

The release workflow builds and signs one candidate, verifies its artifact ID
and digest, then qualifies those same bytes on `thebeast-james-production`.
The disposable production-image qualification instance has its own database,
private DNS/TLS, sessions, devices and runtime watermarks. No manually retained
device ID, evidence variable or long-lived qualification token is required.
The host setup is documented in Manage's `deploy/qualification/README.md`.

The runner's user service also installs `runner-python.conf` as a drop-in.
Install `runner-python.sudoers` under `/etc/sudoers.d/` (root, mode 0440), after
checking it with `visudo -cf`. This supports already immutable workflows that
omit Python's `-B`: the exact qualification command preserves
`PYTHONDONTWRITEBYTECODE` and writes bounded public receipts with a readable
umask. Private fixture directories and credentials still have explicit 0700/0600
permissions. New workflows pass `-B` directly, and the orchestrator gives its
receipt directory to the invoking runner so checkout and scratch cleanup can
remain unprivileged.

Immutable staging requires an official Secure Boot fresh appliance installation,
an actual predecessor-to-candidate upgrade with preserved identity/runtime, and
a separate automatic rollback after the candidate loses its managed network.
Upgrade and rollback each use newly provisioned predecessor media. Every phase
disposes of its database and disks.
Legacy `legacy_all_debs` updaters cannot use the private package transport;
they still require canonical HTTPS admission and a qualified bridge.

Manage binds a workstation runtime to the exact appliance release. A fresh
unpublished candidate therefore has no runtime, even when a predecessor exists.
The prepublication receipt explicitly records absent runtime and deferred
Blueprint delivery; it cannot pass the cold-delivery gate. Upgrade qualification
still proves retention of the predecessor's real installed runtime.

Before building, the resolver authenticates the predecessor's signed manifest,
package snapshot and exact Debian package, and exports every verified Manage
source archive pair. The new package includes these archives alongside its
current source, so dpkg cannot remove the source required by a retained runtime.
Identical revisions are deduplicated; conflicting bytes, malformed pairs and
unsafe metadata fail the build. All archives remain root-owned mode 0444 inside
the signed package snapshot. The catalog is bounded to 32 revisions and 512 MiB
(256 MiB per archive). Hitting a bound requires an explicit support/retirement
decision; the builder never silently drops offline or rollback sources.

GitHub first locks the assets as a prerelease with `latest=false`. The pending
cold-qualification marker excludes this staged release from future predecessor
resolution. Cold qualification must download the public runtime and prove that
its active and desired hashes equal the signed candidate.
The same private phase then boots an empty workstation through James PXE,
installs Standard, applies Dock and Tiling, and requires a managed reboot and
fresh exact compliant evidence for each. It checks the signed runtime descriptor,
booted Nix generation and preserved workstation identity before canary selection.
The separate stable-promotion job verifies the cold artifact ZIP digest and
workflow/source provenance, rechecks every appliance and workstation receipt,
and authenticates the predecessor again under the publication lock. Only then
does it remove the prerelease flag and set GitHub's latest release. Failure
leaves the immutable prerelease unpromoted and production selection unchanged.
Keep protocol 4 and workstation compatibility epoch 1 unless a separately
reviewed compatibility change explicitly requires otherwise.

Legacy manifests are never edited or re-signed. The independent retained
artifact service serves exact historical paths and bytes, including former
`dev.cybex.net` URLs, for active and retained rollback generations. New release
artifacts use immutable GitHub URLs. Retire a legacy route only after accounting
for every supported online/offline installation and retained rollback root.

On failure, leave production selection unchanged. Fix and requalify source;
never relax signatures, substitute historical evidence or label an incomplete
test as passing. The workflow's build-once artifact must not be rebuilt or
re-signed on a retry. Publication compares the predecessor again while holding
the repository-wide lock so concurrent releases cannot reverse the lineage.
