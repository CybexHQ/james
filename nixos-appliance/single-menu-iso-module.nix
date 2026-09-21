{ nixpkgs }:
let
  lib = import (nixpkgs + "/lib");
  # The pinned ISO module has no option to hide its optional submenus/firmware
  # actions. Keep its hardware/EFI image machinery and replace only that menu
  # tail, with exact anchor assertions so a pin update cannot silently drift.
  source = builtins.readFile (nixpkgs + "/nixos/modules/installer/cd-dvd/iso-image.nix");
  start = "        submenu \"Options\" --class submenu --class hidpi {";
  end = "        EOF\n\n        grub-script-check";
  first = lib.splitString start source;
  remainder = builtins.elemAt first 1;
  last = lib.splitString end remainder;
  result = builtins.head first + end + builtins.elemAt last 1;
  absolute = builtins.replaceStrings
    [ "../../image/file-options.nix" "../../../lib/make-iso9660-image.nix" ]
    [ (toString nixpkgs + "/nixos/modules/image/file-options.nix") (toString nixpkgs + "/nixos/lib/make-iso9660-image.nix") ] result;
in
assert builtins.length first == 2;
assert builtins.length last == 2;
builtins.toFile "cybex-single-menu-iso-image.nix" absolute
