# Regional workstation recipes (time zone and keyboard)

`regional-taskbar-new-york-de-generators.json` and `regional-xkb-validated.json`
are the unmodified output of `nix derivation show` (Nix 2.26.3, unversioned
derivation JSON) for derivations evaluated locally on 2026-10-30. Nothing was
built: the systems were only instantiated, with
`--option allow-import-from-derivation false`.

Source pins:

- nixpkgs: `74cc63f702f7d60a557e152a57b40fb1fd0f72ac` (`release/nixpkgs.nix`).
- Nest prebuild templates: `nest_nixos_configuration` and
  `blueprint_compat_module` from `src/build.rs` at `a1bd988` (byte-identical at
  `bc92bb4` and `6960aebb`), extracted as
  `deploy/nixos/check-workstation-cache-contract.py` does.
- Manage compiler exports: `desktop.nix` and `taskbar.nix` from development's
  `var/workstation-cache-contract`, written on 2026-10-28 by its
  `export_workstation_cache_contract_fixtures` test (development `main` was
  `cc2e1c6d` at evaluation time). SHA-256: `desktop.nix`
  `d3eeceddde4e3da98ed23a6c1e4e6905b977dcdfd5e5532855544a4ee04cb5cf`,
  `taskbar.nix` `a33724f666d5bba54c7c179bc42d6c144876b551eb6a3cf101b92e685a82dcae`.

Each system is `nixos/lib/eval-config.nix` over `[ nest-configuration.nix,
<profile>.nix ]`, as in development's `deploy/nixos/workstation-cache-contract.nix`.
The unmodified Taskbar export (and the Dock export) yields the reviewed GNOME
`/etc` recipe exactly: its raw pair is `3d6c68e6…`/`f919faf2…`, the UTC recipe
`ghzyzs3k…-etc.drv` in `tiaris-production-generators.json`.

Regional variants change only the lines the compiler emits for the setting
(`crates/tiaris-configuration/src/blueprint_nix.rs`), plus the matching
`tiaris/policy.json` record (`configured: true`, new value). The edit was made
by hand because running the compiler writes into the development checkout:

- New York and DE: `time.timeZone = "America/New_York";`,
  `console.keyMap = "de";`, `services.xserver.xkb.layout = "de";`.
- US (International): `console.keyMap = "us-acentos";`,
  `services.xserver.xkb.layout = "us";`, `services.xserver.xkb.variant = "intl";`.
- DE alone: as above without the time zone.

`regional-taskbar-new-york-de-generators.json` holds the ten derivations in the
New York + DE system's derivation closure that are absent from the unmodified
Taskbar closure (`comm -13` of `nix-store -qR` on both `.drv` files): the work a
strict Nest must do locally beyond the cached default profile.
`regional-xkb-validated.json` holds the `xkb-validated` derivations for
US (International) (`14kjnpgk…`) and DE (`5hfkza0y…`).

With the previous policy the same local classification (real pinned-source
verifier, `would_build` = the closure difference) rejected `etc`, `activate`
and the system for New York (and for Dock with New York), and `xkb-validated`
and the system for DE and US (International). Europe/Amsterdam and the
vconsole, X11 keyboard, unit and policy materializations were already admitted.
With this change every derivation in all those sets is admitted.

After the localtime zone is replaced by `<time-zone>`, the New York `/etc`
recipe has the reviewed GNOME pair
`f494402d7245d07ef464c8e16d97a8573f746be8ccd7bafd8183f549a5525efb` /
`6fd3a636583672a1f4cbdcc6f0d1b1b5543963baefa10fb8c303751f05fbb356`, the same as
the UTC and Amsterdam recipes. The `xkb-validated` command does not depend on
the layout; both halves of its pair are
`cd2952b1dd7e7671a65d7fbcc4b1852c22b845652bed7f6c26932bc4b6b0417e`. The default
`us` output (`xmqsskw2…-xkb-validated`), `xkbvalidate` (`na9axm2h…`) and
`xkeyboard-config-2.47` (`czwchfqv…`) were present on `cache.nixos.org`
(`nix path-info --store https://cache.nixos.org`) on 2026-10-30.

The regressions accept these recipes and reject an appended command, injected
phase hooks, altered executable providers, mixed fingerprint halves, unsafe or
duplicated zones, renamed or extra inputs, untrusted local dependencies, a
non-reviewed `xkeyboard-config` directory and keyboard attributes containing
shell metacharacters. Source-file verification is synthetic only in unit
tests.
