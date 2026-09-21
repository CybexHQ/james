# Cybex James

Cybex James is a managed NixOS appliance that builds and serves Cybex
workstation netboot releases. The only supported installation route is a
personalized James appliance ISO created by Cybex Manage hands-off provisioning.

## Installation

In Cybex Manage, open James and start a new James setup. Download the
personalized ISO and boot the target appliance from it. When the appliance
appears in Manage, select its target disk and network configuration, review
the destructive installation warning, and approve the installation there.

The media contains a signed, single-use provisioning envelope. The bootstrap
verifies the envelope before installation, activates the reserved device
identity, imports the independently verified signed NixOS closure, and writes the
activated device key and ID into the installed state partition. The signed
install plan also binds the canonical organization UUID and slug; both are
validated and written to the installed managed configuration so James can
issue organization-scoped workstation boot grants immediately. There is no
install-code, pairing-code, generic ISO, or Proxmox/LXC path. Use x86-64 UEFI with
Secure Boot turned off, four cores, at least 16 GiB RAM and a 160 GiB fixed disk.

If provisioning is unavailable in Manage, installation is unavailable. No
fallback installer is supported.

## Development

```sh
cargo fmt --all --check
cargo test --locked
cargo build --release --locked
python3 -B -m unittest discover -s tools/tests -v
cargo test --locked python_packer_archive_verifies_and_extracts_in_rust -- --ignored
python3 -B -m unittest discover -s nixos-appliance/tests -p 'test_*.py'
bash -n nixos-appliance/build-closure.sh nixos-appliance/build-template.sh
```

The installed service uses `/etc/cybex-james/config.toml` and the V2-activated
identity at `/var/lib/cybex-james/state/manage-state.json`. It reports
`appliance_update_v1` for networking/recovery and additive `appliance_update_v3`
for signed system-closure updates from Manage. Workstation-netboot publication and appliance maintenance coordinate
through a shared lock so runtime promotion cannot race an appliance update.
Runtime compatibility is the explicit epoch in `protocol/compatibility.json`,
not equality between the running Manage revision and the descriptor's signed
`manage_source_revision`. That SHA remains provenance for reproduction and
audit, and selects the exact root-owned offline Manage source archive used by
installer-target builds. Compatible desired runtimes reconcile automatically in a single-flight
background task, so downloads and import failures do not delay Build, Cache,
appliance reporting, or managed heartbeats. James keeps serving its verified
active runtime while a newer candidate is retried; the candidate import state
and current service availability are intentionally separate signals in Manage.

James also advertises `workstation_netboot_transport_v1` for explicitly allowlisted
offline qualification fixtures. Its optional unsigned `bundle_transport_url` changes
only the download endpoint; the original signed descriptor and every integrity,
source and anti-rollback check remain authoritative. See the
[transport contract](protocol/workstation-transport-v1.md).

James advertises `installer_target_build_v3` when it accepts the device-agnostic
cohort identity `cybex.installer-target.build.v3` for exact installation jobs.
That identity names only closure inputs — Blueprint revision and artifact
hash, generated-Nix, expected-state, hardware-module and target-module digests,
driver policy, Manage source revision, nixpkgs pin, and source lock — and James
verifies every digest against the module text it evaluates before building, so
the echoed identity proves the exact inputs of a closure Manage may reuse for
every workstation in the same hardware cohort. James also still advertises
`installer_target_build_v2` and accepts the per-device v1/v2 identity shapes so
retained jobs from before the upgrade remain retryable; current Manage issues
only v3 and refuses to prepare installations on a James without it
(`james_installer_closure_unsupported`). Deploy James before Manage.

Source-free Blueprint preparation classifies the exact evaluated derivation
graph in an isolated store. Deterministic NixOS composition outputs and their
qualified tool providers are admitted by strict fingerprints, while an
unrecognized source-producing derivation remains blocked and is reported in
bounded `source_build_candidates` diagnostics.

Runtime integrity maintenance rechecks retained bundles every 12 hours and
renews the active runtime's reported verification time only after a successful
check. This keeps healthy nodes within Manage's 24-hour verification window.
Maintenance also repairs stale runtime evidence after an upgrade, even when
the bundle was checked recently; a corrupt or predecessor bundle cannot renew
the active runtime's evidence.

The migration history retains the multicast state migration already used by
the `.19` development appliances. Later builds must preserve that migration
and its checksum even when the multicast capability is unavailable, so those
appliances can restart or upgrade without discarding their state.

## Wake-on-LAN

James advertises `wake_on_lan_v1` and accepts bounded, signed wake requests
from Manage. Each request is tied to an existing workstation placement and a
normalized MAC address. James sends the standard magic packet three times on
UDP ports 9 and 7, stores a durable `sent` or `failed` receipt in SQLite, and
replays that receipt until Manage acknowledges it. Repeated configuration
syncs therefore never create an unbounded wake storm.

Wake-on-LAN is best effort. A failed or expired wake request does not fail or
cancel the authoritative Blueprint operation: the workstation remains safely
queued and converges when it next checks in. James reports only bounded error
codes and never treats a wake receipt as proof that a workstation actually
started.

## Classroom rootfs multicast

James can advertise `workstation_rootfs_multicast_v1` and coalesce live boot
sessions for the same immutable `nix-store.squashfs` into one rate-limited,
TTL-1 UDPcast stream. The optimization is disabled unless Manage supplies an
`automatic` policy for an explicitly qualified wired L2 multicast domain; a
missing or invalid policy, an older runtime, an unsuitable interface, or the
root-owned `workstation_netboot.multicast_emergency_disabled` override leaves
the existing HTTP path unchanged. A complete gathering window admits up to 30
compatible sessions before one sender starts. Late, single, failed, or dropped
receivers use HTTP and independently verify the signed size and SHA-256.

Only the organization-neutral rootfs bytes enter multicast. Boot contexts,
grants, nonces, device identities, enrollment, commands, secrets, closures,
and results remain per-device unicast. The sender uses one canonical
`O_NOFOLLOW`-opened artifact, a selected wired interface, fixed administrative
groups and ports, TTL 1, an absolute timeout, bounded receiver drop behavior,
and no added Linux capabilities. Nginx suppresses access logging for
bearer-like boot-session context paths. Aggregate transfer evidence is
isolated from other managed report lanes and contains no session, device, URL,
address, or interface identifiers.

The NixOS closure uses the same pinned UDPcast derivation as the workstation
runtime. Its corresponding source and license remain available through the
pinned source offer. Appliance update and rollback qualification covers the
installed dependency. The nftables boundary
remains unchanged: it restricts SSH; the unprivileged sender's own high-UDP
socket is the runtime gate.

## NixOS appliance

The implementation is under [`nixos-appliance/`](nixos-appliance/): immutable
personalized ISO templates, a writable Nix store, persistent STATE, ordinary
system generations, supervised one-shot boot and automatic rollback. Signed
two-phase systemd-networkd changes, certificate-only SSH and workstation
netboot keep their existing management contracts. Firmware Secure Boot is
informational; it is not an update or network admission rule.

Ubuntu V1/V2 appliances require a human reinstall from the current ISO. There
is no Ubuntu-to-NixOS update. The Ubuntu source remains during this branch's
qualification so behavioral parity can be checked before removal.

## Release format

`cybex.james.release.v1` retains its outer schema and `appliance_release_v1`
member. New releases contain `installer_iso_template_v3` with
`package_delivery=system-closure-v1`, and inner
`cybex.james.appliance-release.v3`. The descriptor signs the exact system
toplevel, archive digest/size, source and nixpkgs revisions, SQLite migration
inventory and system version anchors. The same closure installs and updates
James. Protocol 4 and workstation runtime epoch 1 remain unchanged.

The canonical signed `cybex-james-release-compatibility.json` retains its
historical `appliance_package_snapshot` identity slot for the closure archive.
Its signature binds every published artifact and the exact main manifest.
The closure's embedded Manage source archive must match the source hash and
size in the workstation descriptor. Historical V1/V2 signatures remain
verifiable; they do not authorize current installations or updates.

See [`RELEASES.md`](RELEASES.md), [`SECURITY.md`](SECURITY.md), and the
[appliance build and layout guide](nixos-appliance/README.md).

### Coordinated Manage releases

Release candidates build in a disposable Docker container on The Beast, using
dedicated local Cargo and Nix caches. Builders export unsigned Nix caches;
private signing keys remain outside the builder and Nix store. Signed files stay on the server
through appliance qualification; GitHub Actions retains a small hash receipt.
Publication uploads the verified files once, and cold qualification downloads
the published payload independently. See [the local release environment](release/beast/README.md)
for isolation, retention and recovery details.

Digital Brain may create a candidate tag with `release/coordinated.json` and an immutable workstation
source pin to `CybexHQ/development`. The normal release workflow still signs, builds once, publishes
an immutable prerelease and cold-qualifies James/workstations. These tags skip automatic stable
promotion. `approve-coordinated-release.yml` promotes only explicitly approved tag/source/run and
artifact identities, reusing the canonical predecessor/qualification verifier and publication lock.
`promote-production-release.py --verify-only` checks the same evidence without changing publication.

Configure `CYBEX_DEVELOPMENT_SOURCE_SSH_KEY` in the `production-release` environment with a read-only
key for the private development repository. Never copy development changes into the production Manage checkout to build a runtime.
The coordinator retains source bundles for recovery; version tags and signed assets must never be
rewritten. A failed or cancelled coordinated preparation can leave a safe, unpromoted prerelease.

The production-release environment admits version tags, so dispatch approval and
`check-development-source.yml` using the prepared `v*` tag as the workflow ref. The source-access
check reads the requested development commit without building or publishing; it is deliberately
rejected on `main` by the same environment protection. The private deploy key is available only
inside that protected environment.

### Managed appliance updates

Signed policy admits a candidate inside its maintenance window or through
**Update now**. Holds, active builds, maintenance leases and network transactions
defer activation. The service polls requests every 30 seconds. Root independently
verifies the bounded archive and the live SQLite migration inventory, imports
its closure, seals the next generation and selects it for one boot.

The known-good EFI default stays in place until repeated fresh local health
and permanent-identity Manage contact succeed. Failure returns to the known-good
generation and reports a reason. Durable receipts recover power loss without
turning an unfinished attempt into success. Retention preserves current plus
two preceding known-good generations. The old Ubuntu snapshot cutoff and
root-service immediate-update override are not NixOS policy inputs.
