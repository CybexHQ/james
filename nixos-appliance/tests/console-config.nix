# Evaluate the real appliance modules without compiling Nest or an ISO.
{ nixpkgs }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  placeholder = pkgs.runCommand "nest-console-evaluation-placeholder" { version = "0.0.0"; } "mkdir -p $out";
  appliance = {
    package = placeholder;
    udpcast = placeholder;
    sourceArchive = placeholder;
    sourceArchiveFile = placeholder;
    migrations = placeholder;
    themeSource = placeholder;
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
  setup = evaluate [ ../iso.nix ];
  installed = evaluate [ ../module.nix {
    services.tiaris-nest = { enable = true; inherit appliance; };
    system.stateVersion = "26.05";
  } ];
}
