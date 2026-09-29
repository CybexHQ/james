# Evaluate the real appliance modules without compiling Nest or an ISO.
# `installerKiosk` defaults to a placeholder; the tty1 VM passes the real
# kiosk so its units run the packaged binary.
{ nixpkgs, installerKiosk ? null }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  placeholder = pkgs.runCommand "nest-console-evaluation-placeholder" { version = "0.0.0"; } "mkdir -p $out";
  appliance = {
    package = placeholder;
    udpcast = placeholder;
    sourceArchive = placeholder;
    sourceArchiveFile = placeholder;
    migrations = placeholder;
    grubTheme = placeholder;
    installerKiosk = if installerKiosk == null then placeholder else installerKiosk;
    releasePublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    provisioningPublicKeys = [ "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ];
    sourceRevision = builtins.concatStringsSep "" (builtins.genList (_: "a") 40);
    manageSourceRevision = builtins.concatStringsSep "" (builtins.genList (_: "b") 40);
    nixpkgsRevision = (import ../../release/nixpkgs.nix).revision;
    nixpkgsPath = nixpkgs;
    manageOrigin = "https://dev.example.test";
  };
  evaluate = modules: (import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    specialArgs = { inherit appliance; };
    inherit modules;
  }).config;
in {
  inherit appliance;
  setup = evaluate [ ../iso.nix ];
  installed = evaluate [ ../module.nix {
    services.tiaris-nest = { enable = true; inherit appliance; };
    system.stateVersion = "26.05";
  } ];
}
