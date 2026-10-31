# Evaluate both real modules: Blueprint dependencies may use the signed public
# cache and the Tiaris software cache, while recovery media and appliance
# imports retain release-only trust.
{ nixpkgs, pkgs }:
let
  configurations = import ./console-config.nix { inherit nixpkgs; };
  installed = configurations.installed.nix.settings;
  setup = configurations.setup.nix.settings;
  cacheKey = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";
  softwareCacheKey = "cache.tiaris.com-1:xIrpkpeFBAzhhUQojSWqkpAWTwGoW4HtUEtHAcd4taY=";
  releaseKey = "tiaris-nest-appliance-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
in
assert installed.substituters == [ "https://cache.nixos.org" "https://cache.tiaris.com" ];
assert builtins.elem cacheKey installed.trusted-public-keys;
assert builtins.elem softwareCacheKey installed.trusted-public-keys;
assert installed.netrc-file == "/var/lib/tiaris-nest/state/agent/software-cache.netrc";
assert builtins.elem releaseKey installed.trusted-public-keys;
assert installed.require-sigs;
assert installed.trusted-users != [] && builtins.all (user: user == "root") installed.trusted-users;
assert installed.sandbox;
assert setup.substituters == [];
assert setup.trusted-public-keys == [ releaseKey ];
assert !(setup ? netrc-file);
pkgs.runCommand "nest-blueprint-cache-policy" {} "touch $out"
