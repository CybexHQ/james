{ nixpkgs, pkgs, common }:
{
  console = import ./console-vm.nix { inherit nixpkgs; };
  daemonPath = import ./daemon-path-vm.nix { inherit nixpkgs; };
  sshPolicy = import ./ssh-policy-vm.nix { inherit nixpkgs common; };
  firstBoot = import ./first-boot-vm.nix { inherit nixpkgs common; };
  installPermissions = import ./install-permissions-vm.nix { inherit nixpkgs common; };
  networkOrdering = import ./network-ordering-vm.nix { inherit nixpkgs common; };
  runtime = import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, ... }: {
    name = "cybex-james-nixos-runtime-policy";
    nodes.machine = { config, lib, ... }: {
      imports = [ ../module.nix ];
      services.cybex-james = { enable = true; appliance = common; };
      # Deliberately no installed STATE: this VM proves fail-closed service and
      # trust policy without manufacturing enrollment or candidate success.
      system.stateVersion = "26.05";
      services.timesyncd.enable = lib.mkForce false;
      environment.etc."qualification/nginx-command".text = config.systemd.services.nginx.serviceConfig.ExecStart;
      environment.etc."qualification/build.nix".text = ''
        builtins.derivation {
          name = "cybex-untrusted-daemon-build";
          system = "x86_64-linux";
          builder = (builtins.storePath "${pkgs.bash}") + "/bin/bash";
          args = [ "-c" "echo cybex-daemon-build > $out" ];
        }
      '';
      environment.etc."qualification/network.json".text = builtins.toJSON {
        network = { version = 2; renderer = "networkd"; ethernets.cybex-james = {
          match.macaddress = "02:00:00:00:00:42"; set-name = "enp-test"; dhcp4 = false; dhcp6 = false;
          addresses = [ "192.0.2.42/24" ]; routes = [ { to = "default"; via = "192.0.2.1"; } ];
          nameservers.addresses = [ "192.0.2.53" ];
        }; };
      };
      environment.etc."qualification/config.toml".text = ''
        [server]
        listen_addr = "127.0.0.1:8080"
        public_base_url = "http://192.0.2.42"
        [paths]
        data_dir = "/var/lib/cybex-james/state/agent"
        database_path = "/var/lib/cybex-james/state/agent/cybex-james.sqlite"
        boot_assets_dir = "/var/cache/cybex-james/www"
        static_dir = "/var/cache/cybex-james/www/assets"
        tftp_dir = "/var/cache/cybex-james/tftp"
        [auth]
        admin_token = "public-qualification-fixture-only"
        [build]
        work_dir = "/var/cache/cybex-james/build"
        output_dir = "/var/cache/cybex-james/build-outputs"
        nix_binary = "/usr/bin/nix"
        manage_source_url_template = "tarball+file:///usr/share/cybex-james/manage-source/{revision}.tar"
        [cache]
        root_dir = "/var/cache/cybex-james/www/cache"
        private_key_path = "/var/lib/cybex-james/state/agent/cache-private.pem"
        public_key_path = "/var/lib/cybex-james/state/agent/cache-public.pem"
        [update]
        trusted_public_key = "${common.releasePublicKey}"
        [manage]
        enabled = true
        api_url = "https://192.0.2.1"
        organization_id = "00000000-0000-4000-8000-000000000001"
        organization_slug = "qualification"
        state_path = "/var/lib/cybex-james/state/agent/manage-state.json"
      '';
    };
    testScript = ''
      def permit_component(unit):
          # Dependency lists cannot be subtracted using a systemd drop-in.
          # Preserve the real packaged service command and credentials, while
          # replacing this unit only inside the isolated component-test VM.
          machine.succeed(f"sed '/^Requires=/d' /etc/systemd/system/{unit}.service > /tmp/{unit}.service")
          machine.succeed(f"cp /tmp/{unit}.service /run/systemd/system/qualification-{unit}.service")

      machine.start()
      machine.wait_for_unit("multi-user.target")
      machine.succeed("test $(id -u cybex-james) = 985")
      machine.succeed("test $(stat -c %U /nix/store) = root")
      machine.succeed("grep -q 'trusted-users = root' /etc/nix/nix.conf")
      machine.fail("systemctl is-active cybex-james.service")
      machine.fail("systemctl is-active sshd.service")
      machine.succeed("test -f /usr/share/cybex-james/system-identity.json")
      machine.succeed("test ! -L /etc/cybex-james/pxe-discovery.json && test $(stat -c %h /etc/cybex-james/pxe-discovery.json) = 1")
      machine.succeed("test $(stat -c %a /usr/share/cybex-james/manage-source) = 755")
      machine.succeed("test $(stat -c %h /usr/share/cybex-james/manage-source/*.tar) = 1")
      machine.succeed("mkdir -p /run/nginx /var/log/nginx")
      machine.succeed(machine.succeed("cat /etc/qualification/nginx-command").strip() + " -t")
      machine.succeed("runuser -u cybex-james -- sh -c 'printf public-asset > /var/cache/cybex-james/www/assets/qualification.txt; chmod 0644 /var/cache/cybex-james/www/assets/qualification.txt'")
      # The installed-state test above proved startup is blocked. Permit only
      # nginx in this disposable fixture to exercise its real worker identity.
      permit_component("nginx")
      machine.succeed("systemctl daemon-reload && systemctl start qualification-nginx")
      machine.wait_for_open_port(80)
      machine.succeed("curl --noproxy '*' --fail --silent --show-error http://127.0.0.1/assets/qualification.txt | grep -Fx public-asset")
      machine.fail("runuser -u nginx -- test -r /var/lib/cybex-james/state/agent/manage-state.json")
      machine.fail("runuser -u cybex-james -- touch /nix/store/cybex-unauthorized-write")
      machine.succeed("runuser -u cybex-james -- touch /var/cache/cybex-james/appliance-updates/inbox/allowed")
      machine.fail("runuser -u cybex-james -- touch /var/cache/cybex-james/appliance-updates/private/forbidden")
      machine.wait_for_unit("nix-daemon.socket")
      machine.succeed("runuser -u cybex-james -- nix store ping --store daemon")
      machine.succeed("runuser -u cybex-james -- nix-build /etc/qualification/build.nix --no-out-link | xargs cat | grep -Fx cybex-daemon-build")
      machine.succeed("ip link add enp-test type dummy")
      machine.succeed("ip link set enp-test address 02:00:00:00:00:42 up")
      machine.succeed("install -m0600 /etc/qualification/network.json /etc/netplan/90-cybex-james.yaml")
      machine.succeed("/usr/lib/cybex-james/cybex-james-netplan-activate")
      machine.wait_until_succeeds("ip -4 address show dev enp-test | grep -F 192.0.2.42/24")
      machine.succeed("install -d -m0750 -o root -g cybex-james /var/lib/cybex-james/control")
      machine.succeed("install -m0600 /etc/qualification/network.json /var/lib/cybex-james/control/netplan-approved.json")
      machine.succeed("printf '192.0.2.0/24\\n2001:db8::/32\\n' > /var/lib/cybex-james/control/management-cidrs.txt")
      machine.succeed("chmod 0640 /var/lib/cybex-james/control/management-cidrs.txt")
      machine.succeed("/usr/lib/cybex-james/cybex-james-firewall")
      machine.succeed("/usr/lib/cybex-james/cybex-james-firewall")
      machine.succeed("nft list table inet cybex_james | grep -F 'tcp dport 22 drop'")
      machine.succeed("ln -s /usr/share/cybex-james/manage-source /tmp/unsafe-source-directory")
      machine.fail("${pkgs.python3}/bin/python3 ${../runtime/source-copy.py} ${common.sourceArchive} /tmp/unsafe-source-directory")
      # This is a local service-component fixture, not an enrolled-install test:
      # retain the earlier fail-closed proof, then bypass only that dependency
      # so real packaged binaries can probe their actual HTTP and TFTP assets.
      machine.succeed("install -d -m0750 -o root -g cybex-james /var/lib/cybex-james/state")
      machine.succeed("install -d -m0700 -o cybex-james -g cybex-james /var/lib/cybex-james/state/agent /var/lib/cybex-james/state/inbox /var/cache/cybex-james/agent/{home,cache,config,state,tmp} /var/cache/cybex-james/{build,build-outputs,www/cache}")
      machine.succeed("install -d -m0755 -o root -g root /var/cache/cybex-james/tftp")
      machine.succeed("install -m0644 /usr/lib/ipxe/snponly.efi /var/cache/cybex-james/tftp/snponly.efi")
      machine.succeed("install -m0644 /usr/lib/ipxe/ipxe-amd64.efi /var/cache/cybex-james/tftp/ipxe.efi")
      machine.succeed("install -m0644 /usr/share/cybex-james/autoexec.ipxe /var/cache/cybex-james/tftp/autoexec.ipxe")
      machine.succeed("install -m0640 -o root -g cybex-james /etc/qualification/config.toml /etc/cybex-james/config.toml")
      machine.succeed("/usr/bin/cybex-james validate-appliance-config")
      permit_component("tftpd-hpa")
      permit_component("cybex-james")
      machine.succeed("systemctl daemon-reload && systemctl start qualification-tftpd-hpa qualification-cybex-james")
      machine.wait_for_open_port(8080)
      # NixOS readiness must include fresh, real PXE supervisor evidence. With
      # no authenticated inventory it cannot report ready just because HTTP
      # and TFTP are serving; the local component fixture then supplies one
      # complete own-peer inventory and runs the actual hardened supervisor.
      machine.fail("curl --fail --silent 'http://127.0.0.1:8080/healthz?cybex_fresh=1'")
      machine.succeed("python3 -c 'import json,time; print(json.dumps({\"received_at\":int(time.time()),\"desired\":{\"schema\":\"cybex.james.pxe-discovery.v1\",\"server_device_id\":\"qualification\",\"complete\":True,\"peers\":[{\"server_device_id\":\"qualification\",\"address\":\"192.0.2.42\",\"mac\":\"02:00:00:00:00:42\",\"bootloader_filename\":\"snponly.efi\",\"proxy_capable\":True}],\"clients\":[]}}))' > /var/lib/cybex-james/state/agent/pxe-discovery.json")
      machine.succeed("chown cybex-james:cybex-james /var/lib/cybex-james/state/agent/pxe-discovery.json && chmod 0600 /var/lib/cybex-james/state/agent/pxe-discovery.json")
      machine.succeed("systemctl restart cybex-james-pxe")
      machine.wait_until_succeeds("jq -e '.status == \"active\" and .reason == \"proxy_ready\"' /run/cybex-james-pxe/status.json", timeout=90)
      machine.succeed("ss -lunp | grep -F ':67 '")
      machine.wait_until_succeeds("curl --fail --silent 'http://127.0.0.1:8080/healthz?cybex_fresh=1'")
      machine.succeed("chmod 0600 /var/cache/cybex-james/tftp/autoexec.ipxe")
      machine.fail("curl --fail --silent 'http://127.0.0.1:8080/healthz?cybex_fresh=1'")
      machine.succeed("chmod 0644 /var/cache/cybex-james/tftp/autoexec.ipxe")
      machine.succeed("curl --fail --silent 'http://127.0.0.1:8080/healthz?cybex_fresh=1'")
      machine.succeed("systemctl stop cybex-james-pxe")
      machine.fail("curl --fail --silent 'http://127.0.0.1:8080/healthz?cybex_fresh=1'")
    '';
  }) { inherit (pkgs.stdenv.hostPlatform) system; };
}
