# Cybex James

Cybex James is a managed Ubuntu 26.04 appliance that builds and serves Cybex
workstation netboot releases. The only supported installation route is a
personalized James appliance ISO created by Cybex Manage provisioning V2.

## Installation

In Cybex Manage, open James and start a new James setup. Download the
personalized ISO and boot the target appliance from it. When the appliance
appears in Manage, select its target disk and network configuration, review
the destructive installation warning, and approve the installation there.

The media contains a signed, single-use provisioning envelope. The bootstrap
verifies the envelope before installation, activates the reserved device
identity, installs Ubuntu 26.04 from the offline repository, and writes the
activated device key and ID into the installed state partition. The signed
install plan also binds the canonical organization UUID and slug; both are
validated and written to the installed managed configuration so James can
issue organization-scoped workstation boot grants immediately. There is no
install-code, pairing-code, generic ISO, NixOS appliance, or Proxmox/LXC path.

If provisioning V2 is unavailable in Manage, installation is unavailable. No
fallback installer is supported.

## Development

```sh
cargo fmt --all --check
cargo test --locked
cargo build --release --locked
python3 -B -m unittest discover -s tools/tests -v
bash -n ubuntu-appliance/*.sh \
  ubuntu-appliance/qualification/run-lifecycle.sh \
  ubuntu-appliance/rootfs/usr/lib/cybex-james/* \
  ubuntu-appliance/rootfs/etc/grub.d/09_cybex_generations
```

The installed service uses `/etc/cybex-james/config.toml` and the V2-activated
identity at `/var/lib/cybex-james/state/manage-state.json`. It reports
`appliance_update_v1` and accepts only signed Ubuntu appliance updates from
Manage. Workstation-netboot publication and appliance maintenance coordinate
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

The Ubuntu package snapshot binds `udpcast` `20120424-2build2` as an exact
dependency, carries an SPDX document plus its authenticated complete
corresponding source and copyright, and qualifies the dependency through
normal appliance update and rollback lifecycle gates. The nftables boundary
remains unchanged: it restricts SSH; the unprivileged sender's own high-UDP
socket is the runtime gate.

## Ubuntu appliance

The active implementation is under [`ubuntu-appliance/`](ubuntu-appliance/).
It provides:

- immutable personalized ISO templates with an 8192-byte provisioning slot;
- offline Ubuntu and Cybex package repositories;
- resumable first-boot installation and activation;
- Btrfs root generations and rollback;
- signed appliance updates and two-phase network changes;
- Secure Boot, firewall, SSH CA, and appliance qualification contracts.

See [`ubuntu-appliance/README.md`](ubuntu-appliance/README.md) for build and
qualification details.

## Release format

`tools/james-release.py manifest` emits `cybex.james.release.v1` with
`installer_iso_template_v2` as the sole James installation-media entry. The
thin USB template declares `package_delivery: network-snapshot-v1`; the
descriptor also signs its canonical `manage_origin`, and the manifest carries
the core binary, the separately delivered signed Ubuntu
appliance package snapshot, and the workstation netboot bundle. `installer_iso`
is rejected. Releases also publish the separate, canonical
`cybex-james-release-compatibility.json` asset. Its domain-separated Ed25519
signature binds the complete component compatibility contract, the exact main
manifest bytes, and every available binary, appliance, package-snapshot, and
workstation-runtime identity without adding a compatibility field to the
legacy main manifest's strict top-level schema.

See [`RELEASES.md`](RELEASES.md) for the release procedure and
[`SECURITY.md`](SECURITY.md) for trust boundaries.
