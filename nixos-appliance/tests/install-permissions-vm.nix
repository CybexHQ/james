{ nixpkgs, common }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  runtime = import ../runtime.nix { inherit pkgs; inherit (common) package udpcast; };
  firstBootProbe = pkgs.writeText "tiaris-first-boot-permission-probe.py" ''
    from importlib.machinery import SourceFileLoader
    helper = SourceFileLoader('tiaris_first_boot', '${../runtime/tiaris-nest-first-boot}').load_module()
    helper.prepare_cache_directories()
  '';
in import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, ... }: {
  name = "tiaris-nest-install-permissions";
  nodes.machine = { ... }: {
    system.stateVersion = "26.05";
    networking.useDHCP = false;
    networking.useNetworkd = true;
    systemd.network.enable = true;
    users.groups.tiaris-nest.gid = 985;
    users.users.tiaris-nest = {
      uid = 985;
      group = "tiaris-nest";
      isSystemUser = true;
    };
    environment.systemPackages = [ runtime pkgs.coreutils pkgs.iproute2 pkgs.python3 ];
    environment.etc."qualification/network.json".text = builtins.toJSON {
      network = {
        version = 2;
        renderer = "networkd";
        ethernets.tiaris-nest = {
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
    machine.succeed("install -m0600 /etc/qualification/network.json /etc/netplan/90-tiaris-nest.yaml")
    machine.succeed("rm -rf /run/systemd/network; test ! -e /run/systemd/network")
    machine.succeed("umask 077; ${runtime}/bin/tiaris-nest-netplan-activate")
    machine.wait_until_succeeds("ip -4 address show dev enp-permission | grep -F 192.0.2.42/24")
    machine.succeed("test $(stat -c %a /run) = 755")
    machine.succeed("test $(stat -c %a /run/systemd) = 755")
    machine.succeed("test $(stat -c %a /run/systemd/network) = 755")
    machine.succeed("test $(stat -c %a /run/systemd/network/10-tiaris-nest.network) = 640")
    machine.succeed("test $(stat -c %U:%G /run/systemd/network/10-tiaris-nest.network) = root:systemd-network")
    machine.succeed("runuser -u systemd-network -- cat /run/systemd/network/10-tiaris-nest.network >/dev/null")

    machine.succeed("umask 077; PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 ${firstBootProbe}")
    machine.succeed("test $(stat -c %U:%G:%a /var/cache/tiaris-nest) = root:root:755")
    machine.succeed("test $(stat -c %U:%G:%a /var/cache/tiaris-nest/agent) = tiaris-nest:tiaris-nest:700")
    for directory in ("home", "cache", "config", "state", "tmp"):
        machine.succeed(f"test $(stat -c %U:%G:%a /var/cache/tiaris-nest/agent/{directory}) = tiaris-nest:tiaris-nest:700")
        machine.succeed(f"runuser -u tiaris-nest -- touch /var/cache/tiaris-nest/agent/{directory}/write-probe")
    machine.fail("runuser -u tiaris-nest -- touch /var/cache/tiaris-nest/root-write-probe")

    machine.succeed("install -d -m0755 /usr/share/tiaris-nest")
    machine.succeed("umask 077; ${pkgs.python3}/bin/python3 ${../runtime/source-copy.py} ${common.sourceArchive} /usr/share/tiaris-nest/manage-source")
    machine.succeed("test $(stat -c %U:%G:%a /usr/share/tiaris-nest/manage-source) = root:root:755")
    machine.succeed("test $(stat -c %a /usr/share/tiaris-nest/manage-source/*.tar) = 444")
    machine.succeed("runuser -u systemd-network -- cat /usr/share/tiaris-nest/manage-source/*.json >/dev/null")
  '';
}) { system = "x86_64-linux"; }
