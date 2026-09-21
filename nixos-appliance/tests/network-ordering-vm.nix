{ nixpkgs, common }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  networkPlan = pkgs.writeText "network-ordering.json" (builtins.toJSON {
    network = {
      version = 2;
      renderer = "networkd";
      ethernets.cybex-james = {
        match.macaddress = "52:54:00:12:01:01";
        set-name = "eth1";
        dhcp4 = true;
        dhcp6 = false;
      };
    };
  });
in import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ ... }: {
  name = "cybex-james-network-render-ordering";
  nodes = {
    machine = { lib, ... }: {
      imports = [ ../module.nix ];
      services.cybex-james = { enable = true; appliance = common; };
      system.stateVersion = "26.05";
      virtualisation.vlans = [ 1 ];
      services.timesyncd.enable = lib.mkForce false;
      system.activationScripts.network-ordering-fixture.text = ''
        install -d -m0750 -o root -g cybex-james /var/lib/cybex-james/control
        install -m0600 -o root -g root ${networkPlan} /var/lib/cybex-james/control/netplan-approved.json
      '';
    };
    router = { ... }: {
      system.stateVersion = "26.05";
      virtualisation.vlans = [ 1 ];
      networking = { useNetworkd = true; useDHCP = false; firewall.enable = false; };
      systemd.network.enable = true;
      systemd.network.networks."10-router" = {
        name = "eth1";
        networkConfig = { Address = "10.0.0.1/24"; DHCPServer = true; };
        dhcpServerConfig = { PoolOffset = 60; PoolSize = 10; };
      };
    };
  };
  testScript = ''
    start_all()
    router.wait_for_unit("systemd-networkd.service")
    machine.wait_for_unit("systemd-networkd.service")

    machine.succeed("test $(cat /sys/class/net/eth1/address) = 52:54:00:12:01:01")
    machine.succeed("test -f /run/systemd/network/10-cybex-james.network")
    machine.succeed("grep -Fx 'DHCP=ipv4' /run/systemd/network/10-cybex-james.network")
    machine.succeed("systemctl show systemd-networkd.service -P Requires | tr ' ' '\\n' | grep -Fx cybex-james-network-render.service")
    machine.succeed("test $(systemctl show cybex-james-network-render.service -P Result) = success")
    machine.succeed("rendered=$(systemctl show cybex-james-network-render.service -P ExecMainExitTimestampMonotonic); networkd=$(systemctl show systemd-networkd.service -P ExecMainStartTimestampMonotonic); test $rendered -gt 0; test $rendered -le $networkd")
    machine.wait_for_unit("systemd-networkd-wait-online.service")
    machine.wait_until_succeeds("ip -4 address show dev eth1 | grep -E '10\\.0\\.0\\.(6[0-9])/24'")
    machine.succeed("networkctl --no-pager status eth1 | grep -F 'Network File: /run/systemd/network/10-cybex-james.network'")
    machine.succeed("ping -c 1 10.0.0.1")
  '';
}) { system = "x86_64-linux"; }
