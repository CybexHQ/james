# Exercise network reporting with the daemon's actual evaluated service PATH.
{ nixpkgs }:
let
  configurations = import ./console-config.nix { inherit nixpkgs; };
  daemon = configurations.installed.systemd.services.cybex-james;
in import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, ... }: {
  name = "cybex-james-daemon-network-report";
  nodes.machine = { ... }: {
    system.stateVersion = "26.05";
    users.groups.cybex-james = {};
    users.users.cybex-james = { isSystemUser = true; group = "cybex-james"; };
    systemd.services.network-report = {
      inherit (daemon) path;
      serviceConfig = {
        Type = "oneshot";
        User = "cybex-james";
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        RestrictAddressFamilies = daemon.serviceConfig.RestrictAddressFamilies;
        ExecStart = pkgs.writeShellScript "network-report-probe" ''
          set -euo pipefail
          ip -j address show | ${pkgs.python3}/bin/python3 -c 'import json,sys; assert any(a.get("family") == "inet" for n in json.load(sys.stdin) for a in n.get("addr_info", []))'
        '';
      };
    };
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl start network-report.service")
  '';
}) { system = "x86_64-linux"; }
