# Evaluate the real ISO and bootstrap PATH without compiling appliance artifacts.
{ nixpkgs ? builtins.fetchTarball (let pin = import ../../release/nixpkgs.nix; in { inherit (pin) url sha256; }) }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  configurations = import ./console-config.nix { inherit nixpkgs; };
  setup = configurations.setup;
  dnsProbe = pkgs.bind.dnsutils;
in {
  isoHasDnsProbe = builtins.elem dnsProbe setup.environment.systemPackages;
  bootstrapHasDnsProbe = builtins.elem dnsProbe setup.systemd.services.tiaris-nest-bootstrap.path;
}
