# Generic desktop prebuild assembly recipes

`generic-desktop-prebuild-generators.json` is the unmodified Nix JSON v4 output
for the three rejected derivations from Development integration run
[`40903134220`](https://github.com/CybexHQ/development/actions/runs/40903134220).
The derivations were read from that run's retained Dragon Nix store with
`nix derivation show`; they were not reconstructed from renamed fixtures.

Source pins:

- Development/compiler: `36437452bd0a8d3dc86f3ea200e8304e4f09a3af`.
- Nest policy used by the failed run: `6960aebbb59bc400692f17ca8b9c2755215d20bc`.
- nixpkgs: `74cc63f702f7d60a557e152a57b40fb1fd0f72ac`.

The Dock `/etc` recipe is
`/nix/store/1j03pchcpghdkchjrdhz54487hnyx77m-etc.drv`. Compared with the reviewed
Dock `/etc` recipe in `tiaris-production-generators.json`, its only difference
after store-path normalization is removal of this line:

```text
makeEtcEntry /nix/store/<hash>-etc-xdg-autostart-tiaris-wallpaper.desktop xdg/autostart/tiaris-wallpaper.desktop symlink +0 +0
```

The generic prebuild has no pinned workstation runtime, so it omits session
activation. Installed workstation configurations continue to include their
runtime's wallpaper helper. Builder, arguments, stdenv and executable providers
are unchanged; no build command was added. The exact new fingerprint pair is:

- Store-normalized: `88d5a9f22b7d13f683d2f5db87a75c933fe639c518a0eb69c5748cd022dc6e16`.
- Executable-pinned: `234f84b30c84077c13c9040245f338e203fbf18566d1b6328bba5ffbd48eabbb`.

That raw UTC pair is no longer pinned. Nest now pins this recipe with its
localtime zone replaced by a placeholder (see
`regional-workstation-generators.md`):

- Store-normalized: `9cdb204a2eae6ce407308df14327fad4eefa0e17fe953983fe58296df530c8ad`.
- Executable-pinned: `5830004382ba9f7078c561efd881680f671d750960dc03289487d1971eeada42`.

The retained `activate` derivation depends on `/etc`; the final NixOS system
depends on both. Their assembly recipes were already reviewed. The unit
regression uses this actual three-node graph in reverse dependency order and
rejects the entire chain when `/etc` gains a compiler command or phase hook,
changes its executable provider, or depends on unreviewed local work. It also
rejects mixing the old and new recipe fingerprint halves. Source-file verification
is synthetic only in unit tests; all production provider, source and dependency
checks remain unchanged.

This Dock fixture does not establish Taskbar compatibility by itself. Development's
unchanged workstation cache contract must qualify both actual compiler exports
against the updated Nest revision with signed seeds and isolated Nix stores.
Updating that qualification pin does not publish an appliance or workstation
runtime; component release qualification and promotion remain separate.
