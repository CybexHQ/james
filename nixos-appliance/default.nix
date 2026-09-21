{ manageRepo, manageSourceArchive, manageSourceRevision, sourceRevision
, releasePublicKey, provisioningPublicKeys, manageOrigin, sourceDateEpoch
, system ? "x86_64-linux"
}:
let
  pin = import ../release/nixpkgs.nix;
  nixpkgs = builtins.fetchTarball { inherit (pin) url sha256; };
  pkgs = import nixpkgs { inherit system; };
  lib = pkgs.lib;
  publicKeys = if builtins.isString provisioningPublicKeys then builtins.fromJSON provisioningPublicKeys else provisioningPublicKeys;
  archiveInput = builtins.path { path = manageSourceArchive; name = "cybex-manage-${manageSourceRevision}.tar"; };
  package = import ./package.nix { inherit pkgs manageOrigin; };
  migrations = pkgs.runCommand "cybex-james-sqlite-migrations" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    mkdir -p $out
    python3 ${./metadata.py} migrations ${../migrations} $out/sqlite-migrations.json
  '';
  sourceArchive = pkgs.runCommand "cybex-james-manage-source-${manageSourceRevision}" {
    nativeBuildInputs = [ pkgs.python3 ];
  } ''
    mkdir -p $out
    cp ${archiveInput} $out/${manageSourceRevision}.tar
    python3 ${./metadata.py} source $out/${manageSourceRevision}.tar ${manageSourceRevision} $out/${manageSourceRevision}.json
    chmod 0444 $out/*
  '';
  common = {
    inherit package sourceArchive migrations sourceRevision manageSourceRevision manageOrigin sourceDateEpoch releasePublicKey;
    sourceArchiveFile = archiveInput;
    provisioningPublicKeys = publicKeys;
    nixpkgsRevision = pin.revision;
    nixpkgsPath = nixpkgs;
    udpcast = import (builtins.toPath manageRepo + "/deploy/nixos/udpcast-pinned.nix") { inherit pkgs; };
    themeSource = builtins.path { path = builtins.toPath manageRepo + "/deploy/nixos/cybex-grub-theme"; name = "cybex-grub-theme"; };
  };
  installed = import (nixpkgs + "/nixos/lib/eval-config.nix") {
    inherit system;
    specialArgs.appliance = common;
    modules = [ ./system.nix ];
  };
  live = import (nixpkgs + "/nixos/lib/eval-config.nix") {
    inherit system;
    specialArgs.appliance = common;
    modules = [ ./iso.nix ];
  };
  metadataBase = {
    schema = "cybex.james.appliance-closure-build.v1";
    release_id = package.version;
    base_os = "nixos";
    base_os_version = "26.05";
    source_revision = sourceRevision;
    manage_source_revision = manageSourceRevision;
    nixpkgs_revision = pin.revision;
    system_toplevel = toString installed.config.system.build.toplevel;
    required_system_versions = {
      kernel = installed.config.boot.kernelPackages.kernel.version;
      linux-firmware = pkgs.linux-firmware.version;
      nix = installed.config.nix.package.version;
      cybex-james = package.version;
      systemd-boot = pkgs.systemd.version;
    };
    nix_signing_public_key = "cybex-james-appliance-1:${releasePublicKey}";
    manage_origin = manageOrigin;
    manage_source = {
      revision = manageSourceRevision;
      sha256 = builtins.hashFile "sha256" (builtins.toPath manageSourceArchive);
      store_path = toString archiveInput;
    };
    microcode_versions = { intel = pkgs.microcode-intel.version; amd = pkgs.microcode-amd.version; };
  };
  buildMetadata = pkgs.runCommand "cybex-james-system-build.json" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    python3 ${./metadata.py} build ${pkgs.writeText "metadata.json" (builtins.toJSON metadataBase)} ${migrations}/sqlite-migrations.json ${sourceArchive}/${manageSourceRevision}.tar $out
  '';
  unsignedCache = import ./closure.nix { inherit pkgs buildMetadata sourceDateEpoch; toplevel = installed.config.system.build.toplevel; };
in
assert system == "x86_64-linux";
assert builtins.match "[0-9a-f]{40}" sourceRevision != null;
assert builtins.match "[0-9a-f]{40}" manageSourceRevision != null;
assert builtins.length publicKeys >= 1 && builtins.length publicKeys <= 8;
assert publicKeys == lib.sort builtins.lessThan (lib.unique publicKeys);
{
  inherit package unsignedCache buildMetadata;
  system = installed.config.system.build.toplevel;
  iso = live.config.system.build.isoImage;
  inherit (installed) config;
  tests = import ./tests { inherit nixpkgs pkgs common; };
}
