# Production release continuity

Production James uses the fleet Ed25519 release authority and provisioning
authority configured in `production-release`. Repository public keys must match
the installed fleet. The protected secret storage names retain the historical
`CYBEX_FORGE_*` prefix; the workflow uses those exact names. Runtime source is
pinned to an exact commit in `CybexHQ/manage`, with a read-only deployment key.
Manage application deployment is a separate operation.

The one-time `recovery-adoption.json` authorization binds the historical GitHub
dev.4 publication and recovered production dev.29 manifests, compatibility
assets, source identity and keys to successor **0.2.2 only**. The current fleet
authority signs this admission. The resolver authenticates the old publication
under its original authority and dev.29 under the current authority, then
inspects the signed package and actual updater contract. It rechecks this exact
identity under the publication lock. Later releases follow the ordinary signed
predecessor path. Removing either artifact, moving a tag, changing a digest or
using this authorization for another successor fails closed.

The release workflow builds and signs one candidate, verifies its artifact ID
and digest, then qualifies those same bytes on `thebeast-james-production`.
The disposable production-image qualification instance has its own database,
private DNS/TLS, sessions, devices and runtime watermarks. No manually retained
device ID, evidence variable or long-lived qualification token is required.
The host setup is documented in Manage's `deploy/qualification/README.md`.

Publication requires an official Secure Boot fresh installation, an actual
predecessor-to-candidate upgrade with preserved identity/runtime, and a separate
automatic rollback after the candidate loses its managed network. Each test
uses newly provisioned predecessor media and disposes of its database and disks.
Legacy `legacy_all_debs` updaters cannot use the private package transport;
they still require canonical HTTPS admission and a qualified bridge.

After GitHub locks the release, cold qualification must download the published
runtime and prove that its active and desired hashes equal the signed candidate.
Then qualify PXE and source-free Blueprint apply/reboot before canary selection.
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
