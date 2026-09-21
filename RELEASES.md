# James releases

Current appliance builds use NixOS from the same non-flake nixpkgs pin as the
workstation runtime. Ubuntu appliances require human reinstall; they are never
an update predecessor for a NixOS candidate.

## Signed artifacts

The outer `cybex.james.release.v1` remains stable:

- `artifact`: the James service binary.
- `installer_iso_template_v3`: immutable x86-64 UEFI/USB ISO, exact 8192-byte
  zero personalization slot, `system-closure-v1`, public provisioning keys,
  canonical HTTPS `manage_origin` and its separate V3 signature.
- `appliance_release_v1`: inner `cybex.james.appliance-release.v3`, signing the
  closure URL/size/SHA-256, system toplevel, NixOS release, James/Manage/nixpkgs
  revisions, SQLite migration inventory and five system version anchors.
- `workstation_netboot`: the signed kernel, bootstrap initrd and store squashfs.

The closure filename is
`cybex-james-appliance-closure-VERSION-x86_64-linux.tar.zst`. Installer admission
caps it at 4 GiB compressed; publication assets must each remain below 2 GiB.
The bounded canonical USTAR contains its manifest, cache metadata, NARInfos,
`nar/` and signed NARs. Regular tar members are root-owned mode 0644; the directory
is mode 0755. NAR integrity, signatures, graph closure and actual embedded Manage
source bytes are checked independently by both release tooling and Rust.

The companion `cybex.james.release-compatibility.v1` asset keeps its historical
`appliance_package_snapshot` identity slot for the system closure. Canonical
UTF-8 sorted compact JSON plus one LF is signed with
`CYBEX-JAMES-RELEASE-COMPATIBILITY-V1\n`. It binds the exact main manifest,
component compatibility contract, and all artifact identities. Protocol 4 and
workstation runtime epoch 1 / `split-squashfs-v1` remain unchanged. The additive
`workstation_netboot_transport_v1` capability permits an unsigned fixture endpoint
only after normal signed-descriptor verification; see the
[transport contract](protocol/workstation-transport-v1.md).

See [the exact V3 protocol](protocol/appliance-v3.md) and the
[build/layout guide](nixos-appliance/README.md).

## Build, sign and verify

Build clean committed James and Manage sources. `release/workstation-netboot-source.json`
pins the development repository and exact Manage revision. Both appliance and
workstation evaluate the one `release/nixpkgs.nix` pin. The unsigned builder never
receives private signing credentials. `build-closure.sh --unsigned-output-dir`
exports cache plus `build-metadata.json`; `tools/pack-system-closure.py` verifies,
signs and packs it outside Nix. `build-template.sh` checks the embedded origin,
public keys, one branded boot entry and contiguous zero slot.

```sh
python3 -B -m unittest discover -s tools/tests -v
cargo test --locked python_packer_archive_verifies_and_extracts_in_rust -- --ignored
python3 tools/james-release.py verify \
  --manifest dist/cybex-james-release.json \
  --artifact dist/cybex-james-x86_64-linux \
  --installer-iso-template dist/cybex-james-appliance-template-VERSION-x86_64-linux.iso \
  --appliance-system-closure dist/cybex-james-appliance-closure-VERSION-x86_64-linux.tar.zst \
  --workstation-netboot-bundle "$WORKSTATION_BUNDLE" \
  --workstation-netboot-tree "$WORKSTATION_TREE" \
  --expected-manage-origin "$CYBEX_JAMES_BUILD_MANAGE_ORIGIN" \
  --trusted-public-key "$CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY"
```

Signer-side build metadata is additional local provenance, not a published
artifact. Verification remains self-contained from signed descriptors and
artifact bytes. The embedded plain-file Manage source store root must match
both the exact Git revision and workstation source digest/size. Source archives
from historical releases remain available with those releases; the new closure
contains its exact current source.

Within a runtime compatibility epoch, reusing the same runtime SemVer requires
an identical descriptor, including its immutable URL. A changed descriptor
requires greater runtime SemVer; advancing a runtime or compatibility epoch
also requires changed bundle bytes. Successor verification runs before signing
compatibility and again immediately before immutable publication.

## Qualification and publication

Published ancestry and the upgrade fixture are separate identities. Keep
`cybex-james-build-predecessor.json` as published ancestry. A historical old-key
publication requires an exact current-key signed authorization; no general trust
in that old key or historical recovery URL is introduced.

Every V3 release, including the first, requires real fresh installation, a
strictly lower-version signed NixOS predecessor, real update, and automatic
rollback. Supply both `CYBEX_JAMES_NIXOS_QUALIFICATION_PREDECESSOR_DIR` and
`CYBEX_JAMES_NIXOS_QUALIFICATION_PREDECESSOR_MANIFEST_SHA256` when the latest
publication is Ubuntu. Never relabel Ubuntu or fake a same-version update.
The qualified predecessor receipt binds the separately retained predecessor
manifest by `manifest_sha256`.

Warm predecessor transport may use `release/beast/release_speed.py cache` when
published ancestry, an explicit signed NixOS predecessor pair and a private
cache root are all configured. The wrapper re-resolves published ancestry,
compares it with `cybex-james-build-predecessor.json`, authenticates the signed
metadata, and runs the existing complete predecessor verifier on every hit and
miss. It caches immutable transport bytes only. It never caches a successful
installation, VM disk, database, personalized ISO, session, acceptance receipt
or cold-download result. Cache outputs are independent read-only copies; the
publication gate still resolves ancestry again.

When any cache prerequisite is absent, the workflow retains the existing
authenticated predecessor resolver. Cold qualification never consults this
cache: it independently downloads the published assets and checks them against
the sealed candidate receipt before booting. The cache command supports only
the network-enabled `github-warm` mode. `candidate-only` rehearsal means no
tag, publication or promotion; it does not mean zero network access. There is
no supported offline/no-fetch cache execution mode.

The `nixos-appliance/qualification/` harness requires explicit development
origin, private token file, root-owned state root and a new isolated subnet.
It creates its own bridge, TAPs and disposable QEMU disks; it refuses existing
lab adoption. Despite its retained workflow filename,
`run-production-qualification.py` does not contact production or copy a
production database. Required environment inputs are
`CYBEX_JAMES_QUALIFICATION_MANAGE_ORIGIN`, `CYBEX_JAMES_QUALIFICATION_TOKEN_FILE`,
`CYBEX_JAMES_QUALIFICATION_STATE_ROOT` and `CYBEX_JAMES_QUALIFICATION_SUBNET`.
The workflow also requires `CYBEX_JAMES_QUALIFICATION_MANAGE_CHECKOUT` and a
root-owned `CYBEX_JAMES_QUALIFICATION_ALLOW_DEVICE_HELPER`. It captures fresh
inventory before disk approval, pauses the owned guest, admits only the newly
reserved fixture ID, then resumes the guest. Cleanup removes only its recorded
allowlist addition. These six inputs belong to the protected
`james-nixos-development-qualification` environment.

Acceptance binds closure, toplevel, generation, source, permanent identity and
observed reboot. Rollback must be appliance-initiated; a host reset never counts.
UEFI uses Secure Boot off. Network acknowledgement, real recovery SSH login and
root/password rejection, source-free Standard/Dock/Tiling preparation, real PXE
installation and managed workstation reboot/compliance remain required. Private
serial logs and secrets are never publication evidence.

The release workflow keeps its build, qualify, publish, cold-qualify and promote
stages. It attests the exact bounded receipts and immutable artifacts, and cold
acceptance verifies published bytes plus workstation delivery. Coordinated tags
remain unpromoted until separate explicit approval. `promote-production-release.py
--verify-only` performs no publication change. Feature-branch engineering does not
authorize tagging, publication, production promotion or reinstalling a live appliance.
Production-origin qualification remains blocked until a separately reviewed
isolated deployment supports the exact signed production origin. The current
runner accepts development origins only, and publish/promotion reject development
artifacts. Representative physical hardware checks remain separately required;
development receipts cannot be reused as production acceptance.

The current release-speed wrapper can conservatively admit and time a complete
serial warm or cold runner invocation, but its `run` command requires separately
approved root-private candidate, predecessor, profile, lease, disk, evidence and
timing storage. The protected runner does not yet provide that staging adapter,
so the workflow intentionally continues to invoke the existing lifecycle runner
directly. It does not enable phase concurrency, predecessor-fixture reuse or
neutral cold preparation. Cache timing, when available, is uploaded separately
as the allowlisted `timing.json`, named by workflow run and attempt; private child
logs are never uploaded. The five warm and two cold acceptance members remain
separate success-gated artifacts.

Warm execution still performs two independent predecessor installations: one
for update and one for rollback, followed by a fresh candidate installation.
The 18 GiB appliance guest default preserves the 16 GiB usable-memory admission.
Acceptance requires positive Nix generation identities, a whole sparse-disk
fingerprint before approval, runtime absence for prepublication candidate and
predecessor installs, and a real short-lived recovery SSH login with root and
password rejection. The current cold runner uses the selected shared development
service; it is not evidence of a new private empty database. A future migration
owner facade must preserve these distinctions.

The release-speed target of 3,600 seconds or less remains unverified. There is no
current-NixOS live baseline, and helper unit-test duration is not release timing.
