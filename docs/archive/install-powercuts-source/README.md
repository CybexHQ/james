# Inactive installation power-cut experiment

These files preserve the exact unique source from the historical
`install-powercuts-source` experiment. They are text archives, not executable
qualification helpers or discoverable tests. Nothing in the release workflow or
runtime imports them.

The experiment was based on James commit
`fe61c08eaee83db4a07f963cfdab0ac90ebec57c`. Both files were untracked when reviewed
for source consolidation on 2026-09-30 against current main
`5643a38f315e46106a6884574b2fa55a26897e22`. The source bytes are preserved verbatim.
The obsolete worktree can be retired after this archive is verified on main.

| Original source path | Archived exact bytes | SHA-256 |
| --- | --- | --- |
| `nixos-appliance/qualification/install_powercuts.py` | [install_powercuts.py.txt](install_powercuts.py.txt) | `31db605195b4db6200f82a51f860952ef81c0970e9184b413de52a9c2d9725e1` |
| `tools/tests/test_install_powercuts.py` | [test_install_powercuts.py.txt](test_install_powercuts.py.txt) | `5ab8f245c751a398e6e3d13fec061518e906c46d21ff6efe58a593a3dfbf42a5` |

The controller attempts three exact interrupted-install boundaries while binding
the same disk, media, firmware and permanent identity. It inspects a private copy
of STATE and models event replay and guest-initiated restart. This behavior is
unique historical work, but its integration was unfinished:

- It uses retired `/v1/james` routes, `cybex.james` schemas, `CYBEX_STATE`, and
  James event-identity and report fields. Current Nest contracts differ.
- No lifecycle runner calls the controller or owns the required cut/resume flow.
- Its QEMU 10.0.13 pin and stop/drain assertion require a current runtime review
  before they can support real power-cut evidence.
- Its tests model the controller; they do not establish VM or hardware
  qualification, installation recovery, or release acceptance.

These sources were reviewed for embedded credentials. Their identity-key fixture
is a public RFC 8032 test vector, and their management-key fixture is the
explicit deterministic byte sequence 00 through 1f. No private configuration,
credentials, disks, or qualification receipts are archived here.

Any future implementation must adapt and review the contracts, provide owned
runner integration, and obtain separate real qualification evidence. This archive
does not change production or claim that the power-cut experiment passed.
