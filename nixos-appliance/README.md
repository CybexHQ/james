# NixOS James appliance

This directory is the NixOS successor to the Ubuntu James appliance. Its initial
implementation is under development; builds and qualification must not be claimed
complete until their gates pass. Existing Ubuntu appliances require a human
reinstall from the current James ISO. They do not receive a NixOS in-place update.

The product journey stays **Download James ISO → one disk safety check → Install
James once → Ready**, with no local appliance input. James requires x86-64 UEFI
with Secure Boot turned off, at least 16 GiB RAM, the existing CPU/wired-Ethernet
requirements and an eligible fixed disk of at least 160 GiB. Firmware Secure Boot
state is reported for information and is not an admission check.

## Build inputs and output contract

Use `release/nixpkgs.nix` through `builtins.fetchTarball`; no flake or separate
appliance pin. The appliance and workstation runtime move their pin together.
The initial pin is NixOS 26.05, revision
`74cc63f702f7d60a557e152a57b40fb1fd0f72ac`. Use that release's default LTS kernel,
redistributable firmware and Intel/AMD microcode. Record actual kernel, firmware,
microcode, Nix, James and systemd-boot versions in the closure manifest.
Initial evaluated versions are kernel `6.18.38`, Nix `2.34.7` and systemd-boot
`260.2`; stable OS release is `26.05` despite `lib.version=26.05pre-git`.

The planned non-flake entrypoint `default.nix` exposes the installed system
toplevel, local closure cache/manifest, installer ISO and NixOS VM tests. Build
scripts accept an exact clean James revision, exact Manage source checkout and
revision, explicit expected canonical HTTPS Manage origin, offline release public
key, appliance Nix cache public key, and sorted unique provisioning public keys.
Private signing keys must never be a Nix derivation input or enter the store.

Outputs are build-once immutable candidates:

* `cybex-james-appliance-template-<version>-x86_64-linux.iso`;
* unsigned template metadata with exact digest, length and personalization extent;
* `cybex-james-appliance-closure-<version>-x86_64-linux.tar.zst`;
* bounded closure metadata, signed descriptors and the existing release and
  compatibility assets.

The same signed closure serves fresh installation and updates. Qualification and
publication consume the same bytes; rebuilding invalidates qualification. Only
public keys and organization-neutral assets are embedded. Node identities,
customer configuration and private workstation cache keys are created at runtime.

The exact Manage source archive and digest metadata are embedded as immutable
store paths and exposed at `/usr/share/cybex-james/manage-source/<revision>.tar`
and `.json`. Activation verifies signed identity and makes atomic fsynced
root-owned 0444 single-link copies in an ordinary root-owned 0755 directory.
Store directories are 0555 and optimized files may be hardlinked, so a directory
symlink or direct bind fails existing verification. Retain bounded secure reopening;
do not weaken it to follow untrusted symlinks. The signed
workstation descriptor, embedded archive and release Manage revision must agree.
Preserve corresponding source/licence/SPDX material for the pinned udpcast
implementation and the published GPL source offer.

## Disk and state contract

All sizes use GiB (1024³ bytes), checked arithmetic and 1 MiB alignment. Read disk
bytes independently of logical sector size; `blockdev --getsz` reports 512-byte
sectors even on 4 KiB-sector hardware.

| Partition | Label | Size / filesystem | Purpose |
| --- | --- | --- | --- |
| 1 | `CYBEX_STATE` | 16 GiB ext4 | created first; identity, SQLite, config and receipts |
| 2 | `CYBEX_EFI` | 1 GiB FAT32 | `/boot`, UEFI systemd-boot |
| 3 | `CYBEX_SWAP` | 8 GiB swap | no hibernation contract |
| 4 | `CYBEX_ROOT` | remainder, ext4 | root, writable store, caches and build output |

A 160 GiB disk leaves approximately 135 GiB minus GPT/alignment slack for root;
require at least 134 GiB computed root capacity. Root ext4 reserves 1% for root.
The final admission uses actual available bytes including filesystem overhead,
not the nominal partition size. `/nix` is an executable `nodev,nosuid` bind of
`/var/cache/cybex-james/nix`; root owns the store and its parents. James is an
allowed Nix daemon user, never a trusted Nix user.

STATE mounts at `/var/lib/cybex-james/state` with `nodev,nosuid`. Its `agent/` and
`inbox/` are James-owned 0700; its `control/` and `status/` are root:James 0750,
bind-mounted at the historical control/status paths. Protected files are bounded,
single-link regular files, 0640 root:James or 0600 root for secrets. Signed plan,
identity transition, config, CA/principal, CIDRs, network decisions and update
receipts persist across every generation. Do not place secrets in store paths.

Keep at least **21 GiB** for exact workstation-install preparation, plus 2 GiB
operational headroom. Installation/update space checks also include all missing
store paths and simultaneous staging files. Current, pending and two preceding
good generations, active job roots and protected artifacts cannot be reclaimed to
make an update fit. Daily GC uses the job/update exclusion barrier.

## Closure archive and safety limits

Export the complete toplevel reference graph to a local binary cache with `nix
copy --to file://...`, sign every NARInfo with the offline appliance Nix key, and
pack canonical USTAR through zstd. The archive contains only `manifest.json`,
`nix-cache-info`, `<hash>.narinfo`, `nar/` and `nar/<safe filename>.nar.zst`.
Directory/file ownership is numeric root, stable mode and timestamp. Reject
duplicates, absolute/traversal paths, links, devices, sparse/extended headers,
unexpected files, trailing data and incomplete streams.

The public Nix key is `cybex-james-appliance-1:<canonical standard Base64 raw
release Ed25519 public key>`, reusing the offline release authority with Nix's NAR
signature format, distinct from node-generated workstation cache keys. Build the
cache unsigned; external private signing staging adds signatures before packing.
No private signing key enters a derivation, store path or log. Keep historical
`--appliance-package-snapshot` options as aliases; derive the closure filename
from its signed URL instead of constructing an Ubuntu filename.

Maximum sizes: **4 GiB compressed archive**, **8 GiB expanded tar**, **32 GiB
summed NAR payload**, **65536 archive members**, **16 MiB manifest**, **1 MiB per
NARInfo**, **128 MiB zstd window** for archive and NARs. GitHub publication also
requires **less than 2 GiB per asset**, including ISO and closure. The installer
holds at most the 4 GiB archive plus bounded decoder and runtime buffers in RAM.
It verifies the whole signature/size/hash/archive and every inner NAR's compressed
and uncompressed hashes/sizes, trusted NARInfo signature and exact reference graph before
destructive work, streams validation without unpacking a second RAM copy, and
extracts/imports onto the target only after authorized partitioning. Installation
requires sufficient measured available RAM for this budget.

`manifest.json` is canonical recursively key-sorted compact UTF-8 JSON plus LF,
schema `cybex.james.system-closure.v1`. It contains descriptor identity fields,
the pinned public Nix signing key, exact Manage source identity, Intel/AMD
microcode versions, sorted `store_paths` with NAR hashes/sizes/references and
`total_nar_bytes`. The signed archive hash authenticates it; the manifest does
not contain its own archive digest or final descriptor. The immutable system
metadata also omits its own toplevel; derive actual boot identity from
`/run/current-system` and the external signed STATE receipt. Import trusts the key
already installed in the ISO/system policy, not a key supplied only by the archive.

Manifest `nar_hash` is `sha256:<52-character canonical Nix-base32>`, references
are sorted full store paths, and NARInfo references are their sorted basenames.
NARInfo filename is the store path hash plus `.narinfo`; its URL is one exact
`nar/...` archive member, never remote/absolute. Reject duplicate fields and
require `Compression: zstd`, hashes, sizes, store path, references and trusted
signature to agree. Order manifest and NARInfos before NAR payloads, allowing
bounded pre-destructive nested verification without retaining whole NAR buffers.

Every NAR signature, compressed hash, NAR size/hash and reference graph must
validate. No public substituter or build fallback is allowed during installation
or update import. Root reopens and privately pins a daemon-downloaded archive
before verifying/importing it; an untrusted inbox path is never a trust receipt.

## V3 release and media contract

James protocol remains **4**; workstation epoch **1** and `split-squashfs-v1`
remain unchanged. The outer release manifest remains `cybex.james.release.v1`.
It contains `installer_iso_template_v3`; its historically named
`appliance_release_v1` contains the inner V3 descriptor. Compatibility keeps
`artifacts.appliance_package_snapshot` as the historical envelope name for the
closure identity. Never publish both V2 and V3 template descriptors in one current
manifest or fall back to V2 after a V3 validation failure.

The appliance descriptor has exactly:

```text
schema = cybex.james.appliance-release.v3
release_id, source_revision, base_os = nixos, base_os_version
nixpkgs_revision, manage_source_revision, system_toplevel
system_closure = {url, sha256, size_bytes}
required_system_versions = {kernel, linux-firmware, nix, cybex-james, systemd-boot}
sqlite_migrations_sha256
minimum_protocol = 4, minimum_state_schema = 3, rollback_compatible = true
release_notes, signature
```

All fields are mandatory. The five anchors are exact; `cybex-james` equals
`release_id`. No Ubuntu snapshot/package/expected-kernel fields appear in V3.
The signature is standard Base64 Ed25519 over
`CYBEX-JAMES-APPLIANCE-RELEASE-V3\n` plus recursively sorted compact JSON without
`signature`, with no final LF. Digests/revisions are lowercase hex, URLs canonical
immutable HTTPS, toplevel one validated store path. Historical V1/V2 objects retain
their original encoding and signature domain for audit but are not update targets.

The ISO descriptor has required `version`, `architecture=x86_64-linux`,
`base_os=nixos`, `base_os_version`, `url`, `size_bytes`, `template_sha256`,
`personalization_offset`, `personalization_size=8192`, `placeholder_sha256`,
sorted unique `provisioning_public_keys`, `package_delivery=system-closure-v1`,
`manage_origin`, `signature`. Sign domain
`CYBEX-JAMES-INSTALLER-ISO-TEMPLATE-V3`, then each preceding field except
signature in that exact order, one field per line, with a final LF; join key array
with commas. Origin is independently supplied and checked against compiled
bootstrap bytes. Release/ISO use standard Base64 signatures; install/network
plans retain URL-safe unpadded signatures.

The ISO uses installation-cd hardware support, UEFI USB-hybrid boot and the single
branded **Boot Cybex James Setup** entry. `/CYBEX_PROVISIONING.BIN` is an ordinary
uncompressed ISO9660 file consisting of exactly 8192 zero bytes in one extent.
Derive its offset from final xorriso LBA metadata, reopen its exact bytes, and
export slot identity. Personalization changes only those bytes; test HTTP ranges
at both edges and compare the rest of the image. Keep an arping-capable binary
in the live image for static-address safety checks.

New `cybex.james.install-plan.v3` preserves every V2 field name, including
`package_transport_url`, but binds NixOS, `system-closure-v1` and the V3
descriptor. Its signature domain is `CYBEX-JAMES-INSTALL-PLAN-V3\n`; unsigned
canonical JSON excludes `signature` and `plan_sha256`, and that JSON's SHA-256
is `plan_sha256`. Provisioning-envelope V1 and identity cross-signatures remain
unchanged. Decode historical plans for audit, but never execute an Ubuntu plan.

## Provisioning and first boot

The bootstrap service verifies media, claims a session and reports bounded
inventory while waiting for the administrator's exact-disk approval. Before
partitioning it verifies and stages the closure, recollects disk/UEFI/wired-link
identity, and repeats static ARP/gateway/DNS/TLS safety checks. Preflight failure
reports a safe code, leaves the disk untouched and supports Review and try again
with the same ISO. `plan_acknowledged` and `partitioning` events must be accepted
before the first disk write.

Create and fsync STATE first, generate the permanent key there, persist UUID and
slug, signed plan/digest and event sequence, and complete the existing cross-signed
temporary-to-permanent transition. Remaining GPT creation is idempotent. Import
the verified closure offline into the target store and use `nixos-install --system
<toplevel> --no-root-passwd` with the explicit target root. Installed systemd-boot
can touch EFI variables. Materialize STATE config/network/CA/principal/CIDRs,
record completion durably and reboot without prompting.

Recovery probes existing STATE `ro,noload,nodev,nosuid`. Same-session resume
requires exact media/session/plan/geometry and freshly verified closure. A
different session's old STATE is discovery only, never a source of identity,
tenant, keys or config: unmount it for fresh inventory and wait for a new signed
exact-disk Console approval with accepted acknowledgement/destructive events
before replacing it. Existing-device recovery retains server-side settings/history
under same-org/hardware/offline/competing-install fences and creates a new key and
incarnation. No manual disk wipe or automatic foreign-state resume is permitted.
A completed same-media boot selects the exact installed EFI
entry and reboots automatically, including when ISO remains attached.

First boot checks protected ownership, mounted store/state, actual booted closure,
identity and network, stages credential-free immutable iPXE/TFTP files and enables
managed readiness. TFTP readiness verifies exact complete transfers; HTTP boot
readiness uses the current local IPv4 origin. The tty1 console shows only safe
assigned name and Starting/Ready/Attention needed; administration stays in Manage.

## Services and network changes

The NixOS module provides unprivileged James, sandboxed Nix daemon, nginx IPv4
listener, immutable TFTP root, dnsmasq ProxyDHCP supervisor, pinned udpcast,
certificate-only OpenSSH, atomic management-CIDR SSH nftables policy, watchdog,
time synchronization, bounded journald and coordinated daily GC. James has private
HOME/XDG/TMP leaves and no Linux capabilities or Nix trusted-user status.

PXE keeps authenticated complete/fresh inventory, same-link peer MAC checks,
responder election, per-device placement and external-PXE mode. It never assigns
DHCP addresses. Workstation netboot/runtime import, signed binary cache, Blueprint
builds and multicast are the existing product paths.

Networkd renders STATE's approved deterministic network JSON before startup.
Historical `netplan-*.json` filenames and candidate hashing are preserved, while
Netplan itself is absent. Render `/run/systemd/network/10-cybex-james.network`
0640 root:systemd-network, match the approved MAC/name, reload/reconfigure, then
verify networkd selected that exact file and obtained the intended address.

A signed change writes its protected prior-plan backup and candidate digest
before activation. Commit only after the exact signed device/change/digest
acknowledgement within 120 seconds. Timeout or failure restores the previous
network; failed restoration is `network_rollback_failed`, never a successful
rollback. On reboot unacknowledged changes restore the approved plan. Power loss
after acknowledged approved-plan rename resumes receipt cleanup without replaying
an expired change. Preserve approved-static DHCP recovery tied to the exact
approved digest and runtime advertised-origin reconciliation.

CA keys, exact device principal and CIDRs live in STATE and rematerialize on every
generation. SSH permits only locked `cybex-support`, disables root/password/
keyboard-interactive login and delegates forwarding permission to the short-lived
certificate extensions. Private key material never appears in evidence or logs.

## Generation update, commit and rollback

NixOS advertises `appliance_update_v3`, retains `appliance_update_v1` for network
and recovery SSH, and keeps the qualification transport capability. A V2-only
Ubuntu node requires reinstall; do not send it a V3 update payload.

The updater/root verifier use a local build/GC/update/network lock and preserve
the server-owned nonexpiring, non-stealable maintenance lease and device→settings
admission locks. Lease and hold remain distinct. No new inbox field grants
Update now or lease authority. Admit only within the approved maintenance
window or authorized Update now, without holds/active work. Verify the descriptor,
private pinned archive, space, closure and SQLite rollback compatibility before
activating anything. Root scheduling authorization must not come from the writable
inbox.

Initial SQLite admission requires equal source/candidate migration inventory
digests and exact successful live SQLx version/checksum rows. The canonical
`sqlite-migrations.json` is recursively sorted compact JSON plus LF with schema
`cybex.james.sqlite-migrations.v1`, sorted `migrations` entries containing
`filename`, SHA-256 `sha256`, SHA-384 `sqlx_checksum`, and integer `version`.
Hash the entire file including LF. Do not ignore/rewrite SQLx history or restore
an old database on rollback. New migration inventories require a separately
qualified predecessor-compatibility bridge.

Fsync preparation intent before any profile/ESP mutation and set/verify persistent
EFI `LoaderEntryDefault` to the exact source entry **before** the boot action.
Create a normal next system profile generation and run its
`switch-to-configuration boot`; verify the source EFI override remains authoritative
despite the candidate default written to loader.conf. Preparation-only power-loss
recovery restores source profile/default and cleans only the owned candidate.
Write the pending seal durably before `bootctl set-oneshot <candidate>`, verify
both boot selections and reboot. Seal binds attempt/request/archive/source/
release/toplevel and both exact profile and loader generation identities.

Candidate commit requires `/run/current-system` equal to the sealed toplevel,
correct release/store/state, required units, three fresh successful health probes
at least five seconds apart and a fresh authenticated Manage heartbeat/report.
Use a 210-second deadline and 5-minute service cap. The supervisor starts even if
James/first-boot fails (Wants/After, not Requires on checked services); dependency
waits are included in a bounded boot deadline. A bare public health endpoint
is not identity/reachability proof. After success, fsync commit intent, set/verify
candidate default, update known-good/installed receipt, fsync succeeded/committed
status, then clear pending/inbox/archive. Resume interrupted steps idempotently
only against the exact protected transaction.

Failure restores source default/profile, records rollback intent and reboots.
Booting source with an unresolved pending seal terminalizes rolled_back, including
candidate failure before reporting. Preserve identity/database; remove only the
failed candidate generation/boot entry/owned GC root after verifying source boot.
Never report completed rollback while candidate still runs, and never reinterpret
an already committed receipt as failure after a manual retained-generation boot.
Retain current plus two preceding known-good generations; failed candidates are
not known-good retention. Garbage collection honors all active job roots.

Receipts live on shared STATE, not inside root generations:
`verified-update.json`, `known-good-system.json`, `system-prepare-intent.json`, `pending-system-generation.json`,
`system-commit-intent.json`, `system-rollback-intent.json`,
`appliance-update-status.json`, and `appliance-release.json`. Root writes them
atomically with file and parent-directory fsync and exact transaction identity.
Reports include NixOS release/pin/toplevel/closure digest/system generation,
actual kernel/firmware/microcode, boot/Secure Boot evidence and truthful update
status. Unobservable `secure_boot`, firmware or microcode are omitted in V3,
never synthesized as false or a fabricated version. The retained report object
`package_update` carries closure fields for V3.

Runtime watchdog alone does not cover failure before systemd starts. Include
`panic=30`, bounded initrd boot/failure reboot, early watchdog drivers, runtime
handoff and commit timeout reboot. QEMU i6300esb resets its timer on machine reset;
arming it in the predecessor does not prove early candidate coverage. Qualification
must prove a failing pre-switch-root
candidate resets and reaches source without host assistance. Arbitrary firmware
or very-early kernel hangs need a hardware/BMC watchdog surviving reboot and are
not universally guaranteed. Native systemd-boot counting can be considered when
the shared pin moves to 26.11; this port does not depend on it.

## Qualification and release policy

Use disposable, explicitly owned UEFI VMs with Secure Boot off, isolated networking,
an explicit development Manage origin and private untracked evidence. Reject a
production origin before any VM/API mutation. Existing lab appliances are not
qualification fixtures. Never use a host reset as evidence of automatic rollback.

Required real scenarios: personalized-media install/identity/Ready; untouched disk
on preflight failure and same-media retry; interrupted install resume; workstation
PXE/runtime/install/adoption/Blueprint/multicast; window and Update now updates,
holds/schedules and retention; failing-service, failed-health and nonbooting
candidate rollback; power-cut receipt recovery; acknowledged and timed-out network
changes; certificate-only SSH/CIDR isolation; existing-device recovery/decommission;
recorded V2 reinstall-required/cancelled-update fixture. Test archive and signature
corruption, traversal/duplicates/links/size bounds, inode replacement, migration
mismatch and Nix untrusted-user/store policy.

Run format, locked Rust tests and release build, tools unit tests, every Nix output
and NixOS service/store/firewall/SSH/watchdog/console VM test, plus branch CI. A
release candidate records exact input/output identities and bounded redacted
results. VM success does not assert physical hardware/controller qualification.
Remove temporary build output, `result*`, closure caches and owned VM disks after
successful use; keep only necessary evidence. Never commit raw evidence, secrets,
generated archives or customer configuration.

Retain the Ubuntu implementation until the complete NixOS qualification matrix
passes. Only then remove Ubuntu-only code and update the security/support policy.
Human release operators publish the qualified release and later reinstall existing
Ubuntu appliances after backups and service continuity review. A feature branch,
development deployment or local candidate is not a production release.
