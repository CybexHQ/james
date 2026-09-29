# Tiaris production assembly recipes

`tiaris-production-generators.json` records seven real derivations evaluated
from the failed production-origin qualification run `36551755060`, using its
persisted Standard, Dock and Tiling build inputs. The source pins are:

- Nest: `e382a553356047878175886f2fbee856bb8d2c1f` (`0.2.42` candidate).
- Manage/desktop module: `92999fa2a43880c4db027072fd5c85aabdab7d1c`.
- nixpkgs: `74cc63f702f7d60a557e152a57b40fb1fd0f72ac`.

The Standard `g1rcw7rqd9wsvl1x35fz0jqhni94ikqq-system-units.drv` matches the
failed VM's evaluated derivation exactly. All six system-unit and `/etc`
recipes have the same commands and inputs as their reviewed production
fixtures after store-hash normalization and the explicit Amsterdam-to-UTC
symlink change. Their order differs: Nix sorts `tiaris-*` entries after the
system entries, whereas text replacement in the old fixtures left them at
the former `cybex-*` positions.

The Tiling `desktops` recipe only checks the two selected session packages
and links their desktop files with the exact pinned `lndir` executable. It
contains no compiler, source fetch, or package build.

Keep executable-provider fingerprints paired with the normalized recipes.
The regression covers the exact UTC recipes and explicit Amsterdam variants,
and rejects appended compilation, injected phase hooks and altered executable
providers. Existing independent input/dependency checks remain mandatory.
