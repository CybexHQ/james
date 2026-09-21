{ config, lib, pkgs, ... }:
let
  cfg = config.services.cybex-james;
  a = cfg.appliance;
  runtime = import ./runtime.nix { inherit pkgs; inherit (a) package udpcast; };
  ipxe = pkgs.ipxe.override { additionalTargets."bin-x86_64-efi/snponly.efi" = null; };
  command = name: "${runtime}/bin/cybex-james-${name}";
  publicKey = pkgs.writeText "james-release-public-key" (a.releasePublicKey + "\n");
  provisioningKeys = pkgs.writeText "james-provisioning-public-keys" (lib.concatStringsSep "\n" a.provisioningPublicKeys + "\n");
  immutableMetadata = pkgs.writeText "james-system-inputs.json" (builtins.toJSON {
    schema = "cybex.james.system-inputs.v3";
    release_id = a.package.version; base_os = "nixos"; base_os_version = "26.05";
    source_revision = a.sourceRevision; manage_source_revision = a.manageSourceRevision;
    nixpkgs_revision = a.nixpkgsRevision; manage_origin = a.manageOrigin;
    required_system_versions = { kernel = config.boot.kernelPackages.kernel.version; linux-firmware = pkgs.linux-firmware.version; nix = config.nix.package.version; cybex-james = a.package.version; systemd-boot = config.systemd.package.version; };
  });
  baseUnit = { path = [ pkgs.coreutils pkgs.curl pkgs.jq pkgs.util-linux pkgs.systemd pkgs.nix pkgs.python3 a.package runtime ]; };
  rootService = name: {
    description = "Cybex James ${name}";
    serviceConfig = { Type = "oneshot"; ExecStart = command name; UMask = "0077"; };
  } // baseUnit;
in {
  options.services.cybex-james = {
    enable = lib.mkEnableOption "managed NixOS James appliance";
    appliance = lib.mkOption { type = lib.types.attrs; description = "Organization-neutral package, source identity and public trust inputs"; };
  };
  config = lib.mkIf cfg.enable {
    system.extraDependencies = [ a.sourceArchiveFile ];
    users.groups.cybex-james.gid = 985;
    users.groups.nix-users = {};
    users.groups.tftp = {};
    users.users.cybex-james = { uid = 985; group = "cybex-james"; extraGroups = [ "nix-users" ]; isSystemUser = true; home = "/var/cache/cybex-james/agent/home"; createHome = false; };
    users.users.cybex-support = { isNormalUser = true; hashedPassword = "!"; home = "/var/lib/cybex-support"; };
    users.users.tftp = { isSystemUser = true; group = "tftp"; };
    users.users.dnsmasq = { isSystemUser = true; group = "nogroup"; };
    users.groups.nogroup = {};
    networking.useDHCP = false;
    networking.useNetworkd = true;
    networking.networkmanager.enable = lib.mkForce false;
    networking.firewall.enable = false; # owned atomic nftables SSH policy, PXE/multicast stay reachable
    systemd.network.enable = true;
    services.resolved.enable = true;
    services.timesyncd.enable = true;
    services.journald.extraConfig = "SystemMaxUse=256M\nRuntimeMaxUse=64M\nMaxRetentionSec=14day";
    systemd.settings.Manager = { RuntimeWatchdogSec = "120s"; RebootWatchdogSec = "10min"; };
    nix.settings = {
      sandbox = true;
      allowed-users = [ "root" "@nix-users" ];
      trusted-users = [ "root" ];
      substituters = lib.mkForce [];
      trusted-public-keys = lib.mkForce [ "cybex-james-appliance-1:${a.releasePublicKey}" ];
      experimental-features = [ "nix-command" "flakes" ]; # existing Blueprint jobs use governed flakes
      auto-optimise-store = false; # source exposure explicitly preserves nlink=1
    };
    nix.gc.automatic = false;
    environment.systemPackages = [ a.package runtime a.udpcast pkgs.iproute2 pkgs.iputils pkgs.curl pkgs.jq pkgs.nftables pkgs.dnsmasq pkgs.openssh pkgs.python3 pkgs.tftp-hpa ];
    # The privileged supervisor intentionally refuses symlink configuration.
    environment.etc."cybex-james/pxe-discovery.json" = { text = ''{"mode":"automatic"}''; mode = "0644"; };
    services.openssh = {
      enable = true;
      settings = { PasswordAuthentication = false; KbdInteractiveAuthentication = false; PermitRootLogin = "no"; PubkeyAuthentication = true; AllowUsers = [ "cybex-support" ]; TrustedUserCAKeys = "/etc/ssh/cybex-james-ca.pub"; AuthorizedPrincipalsFile = "/etc/ssh/cybex-james-principals"; AllowAgentForwarding = true; AllowTcpForwarding = "yes"; GatewayPorts = "no"; PermitTunnel = "no"; X11Forwarding = false; };
    };
    systemd.services.sshd = { aliases = [ "ssh.service" ]; requires = [ "cybex-james-first-boot.service" "cybex-james-firewall.service" ]; after = [ "cybex-james-first-boot.service" "cybex-james-firewall.service" ]; };
    services.nginx = {
      enable = true;
      defaultListenAddresses = [ "0.0.0.0" ];
      virtualHosts."_" = {
        default = true;
        locations."/".proxyPass = "http://127.0.0.1:8080";
        locations."~ \"^/boot-session/[A-Za-z0-9_-]{22}/context\\.cpio$\"" = { proxyPass = "http://127.0.0.1:8080"; extraConfig = "access_log off;"; };
        locations."= /files/assets/pxe-menu.png".alias = "${a.package}/share/cybex-james/assets/pxe-menu.png";
        locations."~ \"^/manage-source/(?<source_file>[0-9a-f]{40}\\.(?:tar|json))$\"" = { alias = "/usr/share/cybex-james/manage-source/$source_file"; extraConfig = ''
          autoindex off;
          disable_symlinks on;
          limit_except GET { deny all; }
          add_header Cache-Control "public, max-age=31536000, immutable";
          add_header X-Content-Type-Options "nosniff";
        ''; };
        locations."/assets/" = { alias = "/var/cache/cybex-james/www/assets/"; extraConfig = "autoindex off;"; };
      };
    };
    systemd.services.nginx = { after = [ "cybex-james-first-boot.service" ]; requires = [ "cybex-james-first-boot.service" ]; };
    systemd.tmpfiles.rules = [
      "d /var/lib/cybex-james 0750 root cybex-james -"
      "d /var/cache/cybex-james 0755 root root -"
      "d /var/cache/cybex-james/appliance-updates 0755 root root -"
      "d /var/cache/cybex-james/appliance-updates/inbox 0700 cybex-james cybex-james -"
      "d /var/cache/cybex-james/appliance-updates/private 0700 root root -"
      "d /var/cache/cybex-james/www 0755 cybex-james cybex-james -"
      "d /var/cache/cybex-james/www/assets 0755 cybex-james cybex-james -"
      "d /run/lock/cybex-james 0750 root cybex-james -"
      "f /run/lock/cybex-james/maintenance.lock 0660 root cybex-james -"
      "d /etc/cybex-james 0755 root root -"
      "d /etc/netplan 0700 root root -"
    ];
    system.activationScripts.cybex-james-public-assets = {
      deps = [ "users" ];
      text = ''
        install -d -m0755 /usr/bin /usr/sbin /usr/lib/cybex-james /usr/share/cybex-james /usr/lib/ipxe
        install -m0644 -o root -g root ${ipxe}/snponly.efi /usr/lib/ipxe/snponly.efi
        install -m0644 -o root -g root ${ipxe}/ipxe.efi /usr/lib/ipxe/ipxe-amd64.efi
        install -m0644 -o root -g root ${./autoexec.ipxe} /usr/share/cybex-james/autoexec.ipxe
        ln -sfn ${pkgs.tzdata}/share/zoneinfo /usr/share/zoneinfo
        ln -sfn ${a.package}/bin/cybex-james /usr/bin/cybex-james
        ln -sfn ${a.package}/bin/cybex-james-bootstrap /usr/lib/cybex-james/cybex-james-bootstrap
        ln -sfn ${pkgs.nix}/bin/nix /usr/bin/nix
        ln -sfn ${a.udpcast}/bin/udp-sender /usr/bin/udp-sender
        ln -sfn ${pkgs.iproute2}/bin/ip /usr/sbin/ip
        ln -sfn ${pkgs.dnsmasq}/bin/dnsmasq /usr/sbin/dnsmasq
        for program in ${runtime}/bin/*; do ln -sfn "$program" "/usr/lib/cybex-james/$(basename "$program")"; done
        install -m0444 ${publicKey} /usr/share/cybex-james/release-public-key
        install -m0444 ${provisioningKeys} /usr/share/cybex-james/provisioning-public-keys
        install -m0444 ${immutableMetadata} /usr/share/cybex-james/appliance-release.json
        install -m0444 ${immutableMetadata} /usr/share/cybex-james/system-identity.json
        install -m0444 ${a.migrations}/sqlite-migrations.json /usr/share/cybex-james/sqlite-migrations.json
        ${pkgs.python3}/bin/python3 ${./runtime/source-copy.py} ${a.sourceArchive} /usr/share/cybex-james/manage-source
      '';
    };
    systemd.services.cybex-james-network-render = (rootService "network-render") // {
      wantedBy = [ "network-pre.target" ]; requiredBy = [ "systemd-networkd.service" ];
      before = [ "systemd-networkd.service" "network-pre.target" ];
      after = [ "local-fs.target" "systemd-tmpfiles-setup.service" ]; unitConfig.DefaultDependencies = false;
      unitConfig.RequiresMountsFor = [ "/var/lib/cybex-james/control" ];
    };
    systemd.services.cybex-james-first-boot = (rootService "first-boot") // {
      wantedBy = [ "multi-user.target" ]; after = [ "network-online.target" "sshd-keygen.service" "systemd-tmpfiles-setup.service" ]; wants = [ "network-online.target" ];
      requires = [ "sshd-keygen.service" ];
      before = [ "cybex-james.service" "nginx.service" "tftpd-hpa.service" ];
      unitConfig.RequiresMountsFor = [ "/var/lib/cybex-james/state" "/var/lib/cybex-james/control" "/var/lib/cybex-james/status" "/nix" ];
      environment.CYBEX_IPXE_SOURCE = toString ipxe;
      environment.CYBEX_HANDOFF_SOURCE = "${./autoexec.ipxe}";
      serviceConfig = { Type = "oneshot"; ExecStart = command "first-boot"; RemainAfterExit = true; TimeoutStartSec = "180s"; };
    };
    systemd.services.cybex-james-firewall = (rootService "firewall") // {
      wantedBy = [ "multi-user.target" ]; after = [ "cybex-james-first-boot.service" ]; before = [ "sshd.service" ];
      serviceConfig = { Type = "oneshot"; ExecStart = command "firewall"; RemainAfterExit = true; };
    };
    systemd.services.tftpd-hpa = {
      wantedBy = [ "multi-user.target" ]; after = [ "cybex-james-first-boot.service" ]; requires = [ "cybex-james-first-boot.service" ];
      serviceConfig = { ExecStart = "${pkgs.tftp-hpa}/bin/in.tftpd --foreground --listen --address 0.0.0.0:69 --user tftp --secure /var/cache/cybex-james/tftp"; Restart = "on-failure"; };
    };
    systemd.services.cybex-james = {
      wantedBy = [ "multi-user.target" ]; after = [ "network-online.target" "cybex-james-first-boot.service" "cybex-james-network-runtime.service" "nginx.service" "tftpd-hpa.service" "nix-daemon.service" ];
      requires = [ "cybex-james-first-boot.service" "cybex-james-network-runtime.service" ]; wants = [ "network-online.target" "nginx.service" "tftpd-hpa.service" "nix-daemon.service" ];
      environment = { HOME = "/var/cache/cybex-james/agent/home"; XDG_CACHE_HOME = "/var/cache/cybex-james/agent/cache"; XDG_CONFIG_HOME = "/var/cache/cybex-james/agent/config"; XDG_STATE_HOME = "/var/cache/cybex-james/agent/state"; TMPDIR = "/var/cache/cybex-james/agent/tmp"; NIX_USER_CONF_FILES = "/dev/null"; };
      path = [ pkgs.nix pkgs.git pkgs.openssh pkgs.coreutils pkgs.iproute2 a.udpcast ];
      serviceConfig = { Type = "notify"; NotifyAccess = "all"; WatchdogSec = "30s"; User = "cybex-james"; Group = "cybex-james"; ExecStart = "${a.package}/bin/cybex-james --config /etc/cybex-james/config.toml serve"; Restart = "always"; RestartSec = "3s"; UMask = "0077"; NoNewPrivileges = true; PrivateTmp = true; PrivateDevices = true; ProtectSystem = "strict"; ProtectHome = true; ProtectKernelTunables = true; ProtectKernelModules = true; ProtectControlGroups = true; CapabilityBoundingSet = ""; AmbientCapabilities = ""; RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ]; ReadWritePaths = [ "/var/lib/cybex-james/state/agent" "/var/lib/cybex-james/state/inbox" "/var/cache/cybex-james" "/run/lock/cybex-james/maintenance.lock" ]; };
    };
    systemd.services.cybex-james-pxe = {
      wantedBy = [ "multi-user.target" ]; after = [ "cybex-james.service" ]; wants = [ "cybex-james.service" ];
      serviceConfig = { ExecStart = command "pxe"; Restart = "always"; RestartSec = "5s"; RuntimeDirectory = "cybex-james-pxe"; RuntimeDirectoryMode = "0755"; User = "root"; UMask = "0022"; NoNewPrivileges = true; ProtectSystem = "strict"; ProtectHome = true; PrivateTmp = true; ReadWritePaths = [ "/run/cybex-james-pxe" ]; CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" "CAP_NET_RAW" "CAP_NET_ADMIN" "CAP_SETUID" "CAP_SETGID" "CAP_DAC_READ_SEARCH" "CAP_KILL" ]; AmbientCapabilities = [ "CAP_SETUID" ]; };
    };
    systemd.services.cybex-james-network-runtime = (rootService "network-runtime") // { after = [ "cybex-james-first-boot.service" "network-online.target" ]; wants = [ "network-online.target" ]; before = [ "cybex-james.service" ]; serviceConfig = { Type = "oneshot"; ExecStart = command "network-runtime"; TimeoutStartSec = "30s"; }; };
    systemd.timers.cybex-james-network-runtime = { wantedBy = [ "timers.target" ]; timerConfig = { OnBootSec = "1min"; OnUnitActiveSec = "1min"; }; };
    systemd.services.cybex-james-network-change = (rootService "network-change") // { after = [ "cybex-james.service" ]; serviceConfig = { Type = "oneshot"; ExecStart = command "network-change"; TimeoutStartSec = "5min"; }; };
    systemd.paths.cybex-james-network-change = { wantedBy = [ "multi-user.target" ]; pathConfig.PathExists = "/var/lib/cybex-james/state/inbox/appliance-network-change-request.json"; };
    systemd.services.cybex-james-appliance-update = (rootService "appliance-update") // { after = [ "cybex-james.service" ]; serviceConfig = { Type = "oneshot"; ExecStart = command "appliance-update"; TimeoutStartSec = "4h"; }; };
    systemd.timers.cybex-james-appliance-update = { wantedBy = [ "timers.target" ]; timerConfig = { OnBootSec = "1min"; OnUnitInactiveSec = "30s"; RandomizedDelaySec = "5s"; }; };
    systemd.services.cybex-james-generation-commit = (rootService "generation-commit") // {
      wantedBy = [ "multi-user.target" ]; after = [ "cybex-james.service" "nginx.service" "tftpd-hpa.service" ]; wants = [ "cybex-james.service" ];
      unitConfig = { ConditionPathExists = "/var/lib/cybex-james/control/pending-system-generation.json"; FailureAction = "reboot"; JobTimeoutSec = "5min"; JobTimeoutAction = "reboot"; };
      serviceConfig = { Type = "oneshot"; ExecStart = command "generation-commit"; TimeoutStartSec = "5min"; };
    };
    systemd.services.cybex-james-gc = (rootService "gc");
    systemd.timers.cybex-james-gc = { wantedBy = [ "timers.target" ]; timerConfig = { OnCalendar = "daily"; Persistent = true; }; };
    # Mask both login paths. A dedicated unit avoids getty@.service.d's
    # template ExecStart override replacing our console command with agetty.
    systemd.services."autovt@tty1".enable = false;
    systemd.services."getty@tty1".enable = false;
    systemd.services.cybex-james-console = { wantedBy = [ "getty.target" ]; conflicts = [ "rescue.service" ]; before = [ "getty.target" "rescue.service" ]; serviceConfig = { Type = "idle"; ExecStart = command "console"; Restart = "always"; RestartSec = "2s"; StandardInput = "tty"; StandardOutput = "tty"; StandardError = "journal"; TTYPath = "/dev/tty1"; TTYReset = true; TTYVHangup = true; TTYVTDisallocate = true; }; };
  };
}
