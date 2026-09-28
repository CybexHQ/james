# Exercise network reporting with the daemon's actual evaluated service PATH.
{ nixpkgs }:
let
  configurations = import ./console-config.nix { inherit nixpkgs; };
  daemon = configurations.installed.systemd.services.tiaris-nest;
in import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, ... }: {
  name = "tiaris-nest-daemon-network-report";
  nodes.machine = { ... }: {
    system.stateVersion = "26.05";
    users.groups.tiaris-nest = {};
    users.users.tiaris-nest = { isSystemUser = true; group = "tiaris-nest"; };
    systemd.services.network-report = {
      inherit (daemon) path;
      serviceConfig = {
        Type = "oneshot";
        User = "tiaris-nest";
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
