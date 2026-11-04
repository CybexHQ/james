# Evaluate the real appliance modules: the installed Nest substitutes from its
# own signed export first and trusts its own cache key only through the
# root-written include; recovery media keeps release-only trust.
{ nixpkgs ? builtins.fetchTarball (let pin = import ../../release/nixpkgs.nix; in { inherit (pin) url sha256; }) }:
let
  configurations = import ./console-config.nix { inherit nixpkgs; };
  installed = configurations.installed;
  setup = configurations.setup;
  include = "/etc/tiaris-nest/nix-self-cache.conf";
  # nix.conf itself is built from these; extraOptions is appended verbatim.
  extraLines = builtins.filter builtins.isString (builtins.split "\n" installed.nix.extraOptions);
  trust = installed.systemd.services.tiaris-nest-self-cache-trust;
  watch = installed.systemd.paths.tiaris-nest-self-cache-trust;
  rules = installed.systemd.tmpfiles.rules;
in {
  selfCacheFirst = installed.nix.settings.substituters == [
    "file:///var/cache/tiaris-nest/www/cache?priority=10"
    "https://cache.nixos.org"
    "https://cache.tiaris.com"
  ];
  includeIsOptional = builtins.elem "!include ${include}" extraLines;
  ownKeyNotInStaticTrust = builtins.all (key: builtins.substring 0 18 key != "tiaris-nest-cache:")
    installed.nix.settings.trusted-public-keys;
  trustRunsAsRoot = !(trust.serviceConfig ? User) && trust.serviceConfig.Type == "oneshot"
    && builtins.elem "multi-user.target" trust.wantedBy;
  trustFollowsKeyChanges = watch.pathConfig.PathChanged == [
    "/var/lib/tiaris-nest/state/agent/cache-public.pem"
    "/var/lib/tiaris-nest/state/cache-public.pem"
  ];
  exportLayoutOwnedByNest = builtins.all (dir: builtins.elem "d ${dir} 0755 tiaris-nest tiaris-nest -" rules) [
    "/var/cache/tiaris-nest/www/cache"
    "/var/cache/tiaris-nest/www/cache/nar"
    "/var/cache/tiaris-nest/www/cache/realisations"
  ];
  recoveryMediaUnchanged = setup.nix.settings.substituters == []
    && builtins.match ".*nix-self-cache.*" setup.nix.extraOptions == null;
}
