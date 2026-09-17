# September 2026 installed updater repair

The frozen updater with SHA-256
`efe7a184a4295d8988b152afab010f6a1012d68ad4e3279725db1c84142bcdd1`
uses `Dir::Etc::sourceparts=-`. APT can still read host repositories with this
setting, admitting packages outside the signed snapshot into its solver.

Run `python3 repair-legacy-updater.py` as root on an appliance to inspect it.
With `--apply`, the helper locks the installed updater and atomically changes
only the creation and selection of an explicit empty source-parts directory.
It accepts only the exact known original or already-repaired bytes. The repaired
SHA-256 is
`413681546e086b1cf51d17d3497f9af6bad5884d118d5a4c2fec7333ff76f059`.
Unknown predecessors require separate review; do not add their hashes blindly.

The original and a repair receipt are preserved in
`/var/lib/cybex-james/control/maintenance-repairs/apt-sourceparts-v1/`.
The helper retains the original owner and executable permissions and does not
restart James, initiate an update, or change its configuration, identity,
database, signed package verification, maintenance window or rollback logic.
An active updater lock blocks the repair. For rollback, restore `updater.before`
atomically under that same updater lock, preserving the installed permissions;
do not restore an entire appliance snapshot over newer state.

This repair is a prerequisite for the first transition through the frozen
updater. It is not proof of an installed upgrade or permission to enable fleet
rollouts. A signed production-origin candidate still needs actual predecessor
upgrade, rollback, reboot identity and fresh-install qualification.

The candidate's package configuration also retires only the exact known
September development daemon overrides, retaining a `.conf.retired` copy in
the candidate root. Unknown/custom overrides remain authoritative. This avoids
claiming an upgraded package while systemd still runs the old development
binary. The prior root remains available for rollback.

The Blueprint classifier adds three reviewed deterministic service-link and
`/etc` assembly recipes. Their normalized and executable-pinned fingerprints
are both required; hooks, injected compilation and changed tool hashes remain
rejected. Fixtures retain the exact reviewed production tiling recipes.

The immediate-migration rehearsal also found an older PXE override underneath
the September verifier override on Bench and GreenField. Package activation
retires both exact known service layers and their matching first-boot asset
override, checking the referenced binaries/assets before changing any file.

An origin change requires staging `authorization.json` and `manifest.json` in
the root-owned `control/origin-transitions/<candidate-release>/` directory.
`cybex-james-origin-transition` runs during candidate package configuration. It
verifies the retained authority's Ed25519 origin authorization and binds it to
the original release/origin, exact candidate manifest, compiled target origin
and root updater's protected package-verification receipt. The Management
configuration must already name that target. Only the candidate root's
`provisioning-state.json` origin is changed; a private backup is kept there.
The signed plan, device keys, shared state partitions and old root are unchanged.
Missing, altered or mismatched authorization fails candidate configuration.

This is necessary because the first-boot network guard compares the durable
origin to the package's compiled origin. Changing the daemon API endpoint alone
does not make a future production-origin package bootable.

The installed upgrade rehearsal also found that kernel post-install hooks fail
inside a candidate subvolume that has no explicit root mount (`grub-probe` cannot
resolve `/`). `repair-legacy-updater-mounts.py` repairs only the exact APT-repaired
predecessor: it mounts the candidate root and `/dev/pts`, then unmounts children
before the candidate root during cleanup. It imports the adjacent original repair
helper for locking, atomic replacement and permission checks, and retains a
separate backup under `maintenance-repairs/candidate-mount-v1/`.
The resulting frozen updater SHA-256 is
`98b3c6a5ebb85b91f289276b441a6472743edc4b4dd0c3ccecd79529fcfc688f`.
This repair also leaves signatures, maintenance policy and rollback intact.


## September installed-database rollback repair

An isolated dev.17-to-dev.26 update successfully booted the candidate but its
automatic rollback exposed SQLx's rejection of the new Wake-on-LAN migration.
The shared SQLite database must never be restored over newer writes or have its
migration ledger rewritten. Two predecessor source branches retain their exact
old application code and add only the candidate's unchanged additive migration:

- dev.19 base `8bd6a04cef8624de2e354d2140e5e875293d1866`, repair
  `0762443360e56e25cc1bcf1476081d81bb0a5397`.
- dev.21 base `b1d6a5542b766f45bb9200a0f0b25905d25a5d94`, repair
  `02084d383a5eedf0cd12384a2cb3a44dca221d12`.

Both branches include database restart/data-preservation and checksum-rejection
regressions. `repair-predecessor-database.py` installs only their exact tested
binary digests over the known development repair binaries. It takes the updater
lock, stops the daemon, retains the binary and database/sidecar recovery copies,
and restarts the repaired predecessor. It neither changes nor restores database
contents itself; the ordinary SQLx migrator applies the additive schema.
This is an operator repair of the predecessor, not a signed appliance release.

The dev.28 package retires the repaired overrides only in its candidate root.
It rejects the two known incompatible predecessor binaries before retiring any
overrides. Fresh installs have no predecessor override. Installed qualification
must exercise the real candidate boot and rollback with the repaired predecessor;
unit tests alone are not evidence that a fleet upgrade is qualified.
