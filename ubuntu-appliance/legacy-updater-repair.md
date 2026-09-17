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
