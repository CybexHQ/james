{ nixpkgs, common }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  runtime = import ../runtime.nix { inherit pkgs; inherit (common) package udpcast; };
  firstBootProbe = pkgs.writeText "cybex-first-boot-permission-probe.py" ''
    from importlib.machinery import SourceFileLoader
    helper = SourceFileLoader('cybex_first_boot', '${../runtime/cybex-james-first-boot}').load_module()
    helper.prepare_cache_directories()
  '';
in import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, ... }: {
  name = "cybex-james-install-permissions";
  nodes.machine = { ... }: {
    system.stateVersion = "26.05";
    networking.useDHCP = false;
    networking.useNetworkd = true;
    systemd.network.enable = true;
    users.groups.cybex-james.gid = 985;
    users.users.cybex-james = {
      uid = 985;
      group = "cybex-james";
      isSystemUser = true;
    };
    environment.systemPackages = [ runtime pkgs.coreutils pkgs.iproute2 pkgs.python3 ];
    environment.etc."qualification/network.json".text = builtins.toJSON {
      network = {
        version = 2;
        renderer = "networkd";
        ethernets.cybex-james = {
          match.macaddress = "02:00:00:00:00:42";
          set-name = "enp-permission";
          dhcp4 = false;
          dhcp6 = false;
          addresses = [ "192.0.2.42/24" ];
          routes = [ { to = "default"; via = "192.0.2.1"; } ];
          nameservers.addresses = [ "192.0.2.53" ];
        };
      };
    };
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    machine.succeed("ip link add enp-permission type dummy")
    machine.succeed("ip link set enp-permission address 02:00:00:00:00:42 up")
    machine.succeed("install -d -m0700 /etc/netplan")
    machine.succeed("install -m0600 /etc/qualification/network.json /etc/netplan/90-cybex-james.yaml")
    machine.succeed("rm -rf /run/systemd/network; test ! -e /run/systemd/network")
    machine.succeed("umask 077; ${runtime}/bin/cybex-james-netplan-activate")
    machine.wait_until_succeeds("ip -4 address show dev enp-permission | grep -F 192.0.2.42/24")
    machine.succeed("test $(stat -c %a /run) = 755")
    machine.succeed("test $(stat -c %a /run/systemd) = 755")
    machine.succeed("test $(stat -c %a /run/systemd/network) = 755")
    machine.succeed("test $(stat -c %a /run/systemd/network/10-cybex-james.network) = 640")
    machine.succeed("test $(stat -c %U:%G /run/systemd/network/10-cybex-james.network) = root:systemd-network")
    machine.succeed("runuser -u systemd-network -- cat /run/systemd/network/10-cybex-james.network >/dev/null")

    machine.succeed("umask 077; PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 ${firstBootProbe}")
    machine.succeed("test $(stat -c %U:%G:%a /var/cache/cybex-james) = root:root:755")
    machine.succeed("test $(stat -c %U:%G:%a /var/cache/cybex-james/agent) = cybex-james:cybex-james:700")
    for directory in ("home", "cache", "config", "state", "tmp"):
        machine.succeed(f"test $(stat -c %U:%G:%a /var/cache/cybex-james/agent/{directory}) = cybex-james:cybex-james:700")
        machine.succeed(f"runuser -u cybex-james -- touch /var/cache/cybex-james/agent/{directory}/write-probe")
    machine.fail("runuser -u cybex-james -- touch /var/cache/cybex-james/root-write-probe")

    machine.succeed("install -d -m0755 /usr/share/cybex-james")
    machine.succeed("umask 077; ${pkgs.python3}/bin/python3 ${../runtime/source-copy.py} ${common.sourceArchive} /usr/share/cybex-james/manage-source")
    machine.succeed("test $(stat -c %U:%G:%a /usr/share/cybex-james/manage-source) = root:root:755")
    machine.succeed("test $(stat -c %a /usr/share/cybex-james/manage-source/*.tar) = 444")
    machine.succeed("runuser -u systemd-network -- cat /usr/share/cybex-james/manage-source/*.json >/dev/null")
  '';
}) { system = "x86_64-linux"; }
