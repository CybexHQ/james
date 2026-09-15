# James releases

James releases support one appliance platform: Ubuntu 26.04 installed from a
Manage-personalized V2 ISO.

The signed `cybex.james.release.v1` manifest contains:

- `artifact`: the James service binary;
- `installer_iso_template_v2`: the immutable Ubuntu/x86-64 ISO template,
  personalization slot, `network-snapshot-v1` delivery contract, accepted
  provisioning keys, canonical `manage_origin`, and signature;
- `appliance_release_v1`: the separately delivered APT repository snapshot, required
  package versions, kernel, rollback contract, and signature. New candidates use
  schema `cybex.james.appliance-release.v2` under this retained field name and
  sign the exact James Git commit in `source_revision`;
- `workstation_netboot`: the signed workstation kernel, bootstrap initrd, and
  Nix store squashfs bundle.

The companion `cybex-james-release-compatibility.json` asset uses the exact
`cybex.james.release-compatibility.v1` schema. It contains the complete shared
compatibility contract and its canonical SHA-256, the immutable URL and SHA-256
of `cybex-james-release.json`, and fixed identity slots for the James binary,
ISO template, appliance package snapshot, and workstation runtime. Optional
identities are explicit JSON `null`. The asset is canonical compact sorted JSON
encoded as UTF-8 with one final LF; the contract digest uses the same encoding.
It is signed with the offline release key. The signature message is the ASCII
domain line
`CYBEX-JAMES-RELEASE-COMPATIBILITY-V1`, one LF, then the canonical unsigned
asset bytes. The compatibility asset adds no top-level field to the existing
main manifest, so older Manage rollbacks retain their strict parser
compatibility.

Every newly generated `installer_iso_template_v2` carries a non-null string
`manage_origin`. It is a canonical HTTPS origin (`https://host` or
`https://host:non-default-port`, with a lowercase ASCII host and no
credentials, path, query, or fragment). The default HTTPS port is represented
without `:443`. The origin is the final line in the existing
`CYBEX-JAMES-INSTALLER-ISO-TEMPLATE-V2` signature message, after the optional
`package_delivery` line. The compatibility projection repeats it at
`artifacts.appliance_iso_template.manage_origin`. Current assets require the
field; successor verification accepts its complete absence in a signed legacy
predecessor. It is never `null` and is never inferred from artifact URLs or a
built bootstrap binary.

`installer_iso` is not a valid manifest field. The old generic NixOS appliance
ISO and executable-only updater are not release artifacts.

## Build and verify

The release workflow:

1. formats, tests, lints, and release-builds the Rust binaries;
2. validates Ubuntu appliance scripts and the pinned Ubuntu 26.04 base ISO;
3. builds the package snapshot separately from the thin immutable USB ISO
   template;
4. builds the workstation netboot bundle from pinned Manage and nixpkgs
   revisions;
5. signs the binary, template, appliance release, netboot descriptor, and
   canonical compatibility asset;
6. independently verifies the exact artifacts, main manifest, full
   compatibility contract, and cross-manifest identities;
7. boots a personalized template through the V2 lifecycle qualification;
8. attests and publishes only the qualified artifacts.

The pinned Manage and nixpkgs revisions in the workstation descriptor are
signed publication provenance. Deployment compatibility is instead the shared
workstation-runtime epoch and its signed descriptor/manifest target tuple in
`protocol/compatibility.json`. The release workflow requires James and its
pinned Manage source to agree on that contract; deployed source SHAs may differ
when both releases support the same epoch. The same exact pinned source commit
is archived into the signed appliance package snapshot for offline
installer-target builds, and release verification rejects any mismatch between
that packaged revision and the workstation descriptor.

Successor verification mirrors the runtime anti-rollback watermark. Within one
compatibility epoch, a release may reuse an exactly identical workstation
descriptor at the same runtime SemVer, but any descriptor change—including an
immutable transport URL change—requires greater runtime SemVer precedence. A
runtime version cannot decrease, advancing it requires a different bundle
SHA-256, and a published runtime cannot be removed. Compatibility epochs cannot
decrease and advancing one also requires a different bundle. This gate runs
both while the signed compatibility asset is created and immediately before
immutable publication.

Local release-tool verification:

When creating a candidate with `tools/james-release.py manifest`, pass
`--appliance-source-revision "$(git rev-parse HEAD)"` from the exact reviewed
James build checkout. Greenfield and predecessor-update lifecycle qualification
require that v2 descriptor and the same checkout revision before any network or
VM operation. Legacy v1
verification remains available for published predecessors; it is not the
new-candidate contract. This check supplements the independent signature and
artifact verification above; it does not replace them.

```sh
python3 -B -m unittest discover -s tools/tests -v
python3 tools/james-release.py verify \
  --manifest dist/cybex-james-release.json \
  --artifact dist/cybex-james-x86_64-linux \
  --installer-iso-template dist/cybex-james-appliance-template-VERSION-x86_64-linux.iso \
  --expected-manage-origin "$CYBEX_JAMES_BUILD_MANAGE_ORIGIN" \
  --appliance-package-snapshot dist/cybex-james-appliance-packages-VERSION-x86_64-linux.tar.zst \
  --appliance-package-snapshot-metadata dist/cybex-james-appliance-packages-VERSION-x86_64-linux.json \
  --trusted-public-key "$CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY"
python3 tools/james-release.py verify-compatibility \
  --asset dist/cybex-james-release-compatibility.json \
  --manifest dist/cybex-james-release.json \
  --manifest-url https://github.com/CybexHQ/james/releases/download/vVERSION/cybex-james-release.json \
  --compatibility protocol/compatibility.json \
  --trusted-public-key "$CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY"
```

The package metadata is a signer-side provenance input and is not a published
release asset. Include it in the local build verification above for the
stronger installed-bootstrap origin cross-check; post-publication verification
remains self-contained when the metadata option is omitted because the signed
package descriptor authenticates the archive bytes.

Qualification must prove Secure Boot, approval before disk mutation, identity
activation, installation resumability, an installed-media reboot, healthy
appliance reporting, signed updates, network acknowledgement, and exact SSH
certificate principals.

The first James publication in the renamed repository is an explicit brand
bootstrap. Historical releases without both signed James manifest assets do
not establish a James predecessor. That one release must still pass the full
greenfield Secure Boot lifecycle, but it omits predecessor identity and
N-to-N+1 update evidence because no installed James predecessor exists. The
publish job repeats the absence check while holding the repository-wide
release lock, so a concurrent James publication invalidates the candidate.
Every later James release requires the authenticated latest James predecessor,
real update qualification, successor verification, and the corresponding
evidence assets.

When the published predecessor still implements `legacy_all_debs`, it cannot
accept the private qualification transport field used by newer appliances.
Its successor package snapshot must already be readable at the descriptor's
signed canonical HTTPS URL while the release manifest, compatibility asset,
and selection state remain unpublished. Development deployments can expose
only that exact package through Manage's `/james-dev-artifacts` directory with
`ubuntu-appliance/qualification/stage-canonical-package.py`; the helper binds
the URL, manifest digest, snapshot digest and size, and cleanup owner in private
state and will neither overwrite nor remove unowned bytes.
This transport helper accepts exact v1 and source-bound v2 descriptors so older
staging journals remain verifiable and cleanable. New-candidate admission still
requires v2; staging never substitutes for independent signature verification.

Historical development predecessors with mutable build layouts use the private
`prepare-local-predecessor` snapshot workflow in
`ubuntu-appliance/README.md`. It preserves signed descriptors and reused runtime
URLs, authenticates the complete artifact closure, and binds immutable copies
to the original served index for identification and post-qualification recheck.
It does not republish or normalize the historical served directories in place.

Production manifests currently bind package assets to GitHub immutable-release
download URLs. GitHub draft assets do not provide anonymous canonical transport
to the frozen predecessor, and early publication would make the package-only
release immutable before the remaining qualified assets exist. Accordingly,
the release workflow fails closed at its canonical-package download check until
an authorized publication backend can serve an unpublished package at its
final signed URL and later atomically publish the complete release. Changing
the signed package origin alone is not a valid workaround because Manage's
production release importer requires one immutable GitHub release identity for
all assets.

Local qualification captures the supported Standard and Dock built-ins at their
current released revision IDs and an explicitly prepared Tiling/Deno rehearsal
fixture. See `ubuntu-appliance/README.md` for read-only catalog admission and
for reconstructing missing historical predecessor lifecycle evidence. Neither
mode resets Blueprint settings, permits source builds, or replaces node-scoped
preparation and required-replica checks. A historical run records its original
manifest identity separately from the current harness revision and cannot be
used as candidate qualification.
