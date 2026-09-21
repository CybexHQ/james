# Evaluate both real modules: Blueprint dependencies may use the signed public
# cache, while recovery media and appliance imports retain release-only trust.
{ nixpkgs, pkgs }:
let
  configurations = import ./console-config.nix { inherit nixpkgs; };
  installed = configurations.installed.nix.settings;
  setup = configurations.setup.nix.settings;
  cacheKey = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";
  releaseKey = "cybex-james-appliance-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
in
assert installed.substituters == [ "https://cache.nixos.org" ];
assert builtins.elem cacheKey installed.trusted-public-keys;
assert builtins.elem releaseKey installed.trusted-public-keys;
assert installed.require-sigs;
assert installed.trusted-users != [] && builtins.all (user: user == "root") installed.trusted-users;
assert installed.sandbox;
assert setup.substituters == [];
assert setup.trusted-public-keys == [ releaseKey ];
pkgs.runCommand "james-blueprint-cache-policy" {} "touch $out"
