# Custom workstation outputs are absent from cache.nixos.org. Carry the exact
# outputs selected by the current Blueprint modules in the signed Nest closure,
# without enabling a workstation desktop or agent service on the appliance.
{ nixpkgs, pkgs, manageRepo, workstationAgent, system ? "x86_64-linux" }:
let
  lib = pkgs.lib;
  repo = builtins.toPath manageRepo;
  evaluate = profile: (import (nixpkgs + "/nixos/lib/eval-config.nix") {
    inherit system;
    modules = [
      (repo + "/deploy/nixos/tiaris-blueprints.nix")
      (repo + "/deploy/nixos/tiaris-agent-module.nix")
      {
        nixpkgs.pkgs = pkgs;
        system.stateVersion = "26.05";
        tiaris.desktop.profile = profile;
        services.tiaris-agent = {
          enable = true;
          package = workstationAgent;
          apiUrl = "https://invalid.invalid";
          organizationSlug = "cache-seed";
        };
      }
    ];
  }).config;
  profiles = lib.genAttrs [ "taskbar" "dock" "tiling" ] evaluate;
  observers = config: lib.filter (package:
    builtins.elem (lib.getName package) [ "tiaris-gsettings" "tiaris-session-gsettings" ]
  ) config.environment.systemPackages;
  perProfile = lib.mapAttrs (_: config: observers config ++ [ config.services.avahi.package ]) profiles;
in
assert lib.all (config: builtins.length (observers config) == 2) (builtins.attrValues profiles);
{
  inherit perProfile;
  packages = lib.unique (lib.concatLists (builtins.attrValues perProfile));
}
