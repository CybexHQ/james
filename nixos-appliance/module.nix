{ config, lib, pkgs, ... }:
let
  cfg = config.services.tiaris-nest;
  a = cfg.appliance;
  runtime = import ./runtime.nix { inherit pkgs; inherit (a) package udpcast; };
  ipxe = pkgs.ipxe.override { additionalTargets."bin-x86_64-efi/snponly.efi" = null; };
  command = name: "${runtime}/bin/tiaris-nest-${name}";
  publicKey = pkgs.writeText "nest-release-public-key" (a.releasePublicKey + "\n");
  provisioningKeys = pkgs.writeText "nest-provisioning-public-keys" (lib.concatStringsSep "\n" a.provisioningPublicKeys + "\n");
  immutableMetadata = pkgs.writeText "nest-system-inputs.json" (builtins.toJSON {
    schema = "tiaris.nest.system-inputs.v3";
    release_id = a.package.version; base_os = "nixos"; base_os_version = "26.05";
    source_revision = a.sourceRevision; manage_source_revision = a.manageSourceRevision;
    nixpkgs_revision = a.nixpkgsRevision; manage_origin = a.manageOrigin;
    required_system_versions = { kernel = config.boot.kernelPackages.kernel.version; linux-firmware = pkgs.linux-firmware.version; nix = config.nix.package.version; tiaris-nest = a.package.version; systemd-boot = config.systemd.package.version; };
  });
  baseUnit = { path = [ pkgs.coreutils pkgs.curl pkgs.jq pkgs.util-linux pkgs.systemd pkgs.nix pkgs.python3 a.package runtime ]; };
  rootService = name: {
    description = "Tiaris Nest ${name}";
    serviceConfig = { Type = "oneshot"; ExecStart = command name; UMask = "0077"; };
  } // baseUnit;
in {
  options.services.tiaris-nest = {
    enable = lib.mkEnableOption "managed NixOS Nest appliance";
    appliance = lib.mkOption { type = lib.types.attrs; description = "Organization-neutral package, source identity and public trust inputs"; };
  };
  config = lib.mkIf cfg.enable {
    system.extraDependencies = [ a.sourceArchiveFile ];
    users.groups.tiaris-nest.gid = 985;
    users.groups.nix-users = {};
    users.groups.tftp = {};
    users.users.tiaris-nest = { uid = 985; group = "tiaris-nest"; extraGroups = [ "nix-users" ]; isSystemUser = true; home = "/var/cache/tiaris-nest/agent/home"; createHome = false; };
    users.users.tiaris-support = { isNormalUser = true; hashedPassword = "!"; home = "/var/lib/tiaris-support"; };
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
      # Blueprint builds need upstream binary dependencies. Appliance imports
      # separately verify every NAR against the release key and disable remote
      # substitution explicitly; recovery media retains release-only trust.
      substituters = lib.mkForce [ "https://cache.nixos.org" ];
      trusted-public-keys = lib.mkForce [
        "tiaris-nest-appliance-1:${a.releasePublicKey}"
        "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      ];
      require-sigs = true;
      experimental-features = [ "nix-command" "flakes" ]; # existing Blueprint jobs use governed flakes
      auto-optimise-store = false; # source exposure explicitly preserves nlink=1
    };
    nix.gc.automatic = false;
    # Include daemon-side builders in diagnostics. No throttling/OOM limits:
    # smaller budgets require the performance qualification gate first.
    systemd.services.nix-daemon.serviceConfig.MemoryAccounting = true;
    environment.systemPackages = [ a.package runtime a.udpcast pkgs.iproute2 pkgs.iputils pkgs.curl pkgs.jq pkgs.nftables pkgs.dnsmasq pkgs.openssh pkgs.python3 pkgs.tftp-hpa ];
    # The privileged supervisor intentionally refuses symlink configuration.
    environment.etc."tiaris-nest/pxe-discovery.json" = { text = ''{"mode":"automatic"}''; mode = "0644"; };
    services.openssh = {
      enable = true;
      settings = { PasswordAuthentication = false; KbdInteractiveAuthentication = false; PermitRootLogin = "no"; PubkeyAuthentication = true; AllowUsers = [ "tiaris-support" ]; TrustedUserCAKeys = "/etc/ssh/tiaris-nest-ca.pub"; AuthorizedPrincipalsFile = "/etc/ssh/tiaris-nest-principals"; AllowAgentForwarding = true; AllowTcpForwarding = "yes"; GatewayPorts = "no"; PermitTunnel = "no"; X11Forwarding = false; };
    };
    systemd.services.sshd = { aliases = [ "ssh.service" ]; requires = [ "tiaris-nest-first-boot.service" "tiaris-nest-firewall.service" ]; after = [ "tiaris-nest-first-boot.service" "tiaris-nest-firewall.service" ]; };
    services.nginx = {
      enable = true;
      defaultListenAddresses = [ "0.0.0.0" ];
      virtualHosts."_" = {
        default = true;
        locations."/".proxyPass = "http://127.0.0.1:8080";
        locations."~ \"^/boot-session/[A-Za-z0-9_-]{22}/context\\.cpio$\"" = { proxyPass = "http://127.0.0.1:8080"; extraConfig = "access_log off;"; };
        locations."= /files/assets/pxe-menu.png".alias = "${a.package}/share/tiaris-nest/assets/pxe-menu.png";
        locations."~ \"^/manage-source/(?<source_file>[0-9a-f]{40}\\.(?:tar|json))$\"" = { alias = "/usr/share/tiaris-nest/manage-source/$source_file"; extraConfig = ''
          autoindex off;
          disable_symlinks on;
          limit_except GET { deny all; }
          add_header Cache-Control "public, max-age=31536000, immutable";
          add_header X-Content-Type-Options "nosniff";
        ''; };
        locations."/assets/" = { alias = "/var/cache/tiaris-nest/www/assets/"; extraConfig = "autoindex off;"; };
      };
    };
    systemd.services.nginx = { after = [ "tiaris-nest-first-boot.service" ]; requires = [ "tiaris-nest-first-boot.service" ]; };
    systemd.tmpfiles.rules = [
      "d /var/lib/tiaris-nest 0750 root tiaris-nest -"
      "d /var/cache/tiaris-nest 0755 root root -"
      "d /var/cache/tiaris-nest/appliance-updates 0755 root root -"
      "d /var/cache/tiaris-nest/appliance-updates/inbox 0700 tiaris-nest tiaris-nest -"
      "d /var/cache/tiaris-nest/appliance-updates/private 0700 root root -"
      "d /var/cache/tiaris-nest/www 0755 tiaris-nest tiaris-nest -"
      "d /var/cache/tiaris-nest/www/assets 0755 tiaris-nest tiaris-nest -"
      "d /run/lock/tiaris-nest 0750 root tiaris-nest -"
      "f /run/lock/tiaris-nest/maintenance.lock 0660 root tiaris-nest -"
      "d /etc/tiaris-nest 0755 root root -"
      "d /etc/netplan 0700 root root -"
    ];
    system.activationScripts.tiaris-nest-public-assets = {
      deps = [ "users" ];
      text = ''
        install -d -m0755 /usr/bin /usr/sbin /usr/lib/tiaris-nest /usr/share/tiaris-nest /usr/lib/ipxe
        install -m0644 -o root -g root ${ipxe}/snponly.efi /usr/lib/ipxe/snponly.efi
        install -m0644 -o root -g root ${ipxe}/ipxe.efi /usr/lib/ipxe/ipxe-amd64.efi
        install -m0644 -o root -g root ${./autoexec.ipxe} /usr/share/tiaris-nest/autoexec.ipxe
        ln -sfn ${pkgs.tzdata}/share/zoneinfo /usr/share/zoneinfo
        ln -sfn ${a.package}/bin/tiaris-nest /usr/bin/tiaris-nest
        ln -sfn ${a.package}/bin/tiaris-nest-bootstrap /usr/lib/tiaris-nest/tiaris-nest-bootstrap
        ln -sfn ${pkgs.nix}/bin/nix /usr/bin/nix
        ln -sfn ${a.udpcast}/bin/udp-sender /usr/bin/udp-sender
        ln -sfn ${pkgs.iproute2}/bin/ip /usr/sbin/ip
        ln -sfn ${pkgs.dnsmasq}/bin/dnsmasq /usr/sbin/dnsmasq
        for program in ${runtime}/bin/*; do ln -sfn "$program" "/usr/lib/tiaris-nest/$(basename "$program")"; done
        install -m0444 ${publicKey} /usr/share/tiaris-nest/release-public-key
        install -m0444 ${provisioningKeys} /usr/share/tiaris-nest/provisioning-public-keys
        install -m0444 ${immutableMetadata} /usr/share/tiaris-nest/appliance-release.json
        install -m0444 ${immutableMetadata} /usr/share/tiaris-nest/system-identity.json
        install -m0444 ${a.migrations}/sqlite-migrations.json /usr/share/tiaris-nest/sqlite-migrations.json
        ${pkgs.python3}/bin/python3 ${./runtime/source-copy.py} ${a.sourceArchive} /usr/share/tiaris-nest/manage-source
      '';
    };
    systemd.services.tiaris-nest-network-render = (rootService "network-render") // {
      wantedBy = [ "network-pre.target" ]; requiredBy = [ "systemd-networkd.service" ];
      before = [ "systemd-networkd.service" "network-pre.target" ];
      after = [ "local-fs.target" "systemd-tmpfiles-setup.service" ]; unitConfig.DefaultDependencies = false;
      unitConfig.RequiresMountsFor = [ "/var/lib/tiaris-nest/control" ];
    };
    systemd.services.tiaris-nest-first-boot = (rootService "first-boot") // {
      wantedBy = [ "multi-user.target" ]; after = [ "network-online.target" "sshd-keygen.service" "systemd-tmpfiles-setup.service" ]; wants = [ "network-online.target" ];
      requires = [ "sshd-keygen.service" ];
      before = [ "tiaris-nest.service" "nginx.service" "tftpd-hpa.service" ];
      unitConfig.RequiresMountsFor = [ "/var/lib/tiaris-nest/state" "/var/lib/tiaris-nest/control" "/var/lib/tiaris-nest/status" "/nix" ];
      environment.TIARIS_IPXE_SOURCE = toString ipxe;
      environment.TIARIS_HANDOFF_SOURCE = "${./autoexec.ipxe}";
      serviceConfig = { Type = "oneshot"; ExecStart = command "first-boot"; RemainAfterExit = true; TimeoutStartSec = "180s"; };
    };
    systemd.services.tiaris-nest-firewall = (rootService "firewall") // {
      wantedBy = [ "multi-user.target" ]; after = [ "tiaris-nest-first-boot.service" ]; before = [ "sshd.service" ];
      serviceConfig = { Type = "oneshot"; ExecStart = command "firewall"; RemainAfterExit = true; };
    };
    systemd.services.tftpd-hpa = {
      wantedBy = [ "multi-user.target" ]; after = [ "tiaris-nest-first-boot.service" ]; requires = [ "tiaris-nest-first-boot.service" ];
      serviceConfig = { ExecStart = "${pkgs.tftp-hpa}/bin/in.tftpd --foreground --listen --address 0.0.0.0:69 --user tftp --secure /var/cache/tiaris-nest/tftp"; Restart = "on-failure"; };
    };
    systemd.services.tiaris-nest = {
      wantedBy = [ "multi-user.target" ]; after = [ "network-online.target" "tiaris-nest-first-boot.service" "tiaris-nest-network-runtime.service" "nginx.service" "tftpd-hpa.service" "nix-daemon.service" ];
      requires = [ "tiaris-nest-first-boot.service" "tiaris-nest-network-runtime.service" ]; wants = [ "network-online.target" "nginx.service" "tftpd-hpa.service" "nix-daemon.service" ];
      environment = { HOME = "/var/cache/tiaris-nest/agent/home"; XDG_CACHE_HOME = "/var/cache/tiaris-nest/agent/cache"; XDG_CONFIG_HOME = "/var/cache/tiaris-nest/agent/config"; XDG_STATE_HOME = "/var/cache/tiaris-nest/agent/state"; TMPDIR = "/var/cache/tiaris-nest/agent/tmp"; NIX_USER_CONF_FILES = "/dev/null"; };
      path = [ pkgs.nix pkgs.git pkgs.openssh pkgs.coreutils pkgs.iproute2 pkgs.systemd a.udpcast ];
      serviceConfig = { MemoryAccounting = true; Type = "notify"; NotifyAccess = "all"; WatchdogSec = "30s"; User = "tiaris-nest"; Group = "tiaris-nest"; ExecStart = "${a.package}/bin/tiaris-nest --config /etc/tiaris-nest/config.toml serve"; Restart = "always"; RestartSec = "3s"; UMask = "0077"; NoNewPrivileges = true; PrivateTmp = true; PrivateDevices = true; ProtectSystem = "strict"; ProtectHome = true; ProtectKernelTunables = true; ProtectKernelModules = true; ProtectControlGroups = true; CapabilityBoundingSet = ""; AmbientCapabilities = ""; RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ]; ReadWritePaths = [ "/var/lib/tiaris-nest/state/agent" "/var/lib/tiaris-nest/state/inbox" "/var/cache/tiaris-nest" "/run/lock/tiaris-nest/maintenance.lock" "/run/tiaris-nest" ];
        # Public console projection (console-status.json, 0644) for the root
        # tty1 kiosk. Preserved across restarts so a stopped daemon leaves a
        # visibly stale status instead of an apparent first boot.
        RuntimeDirectory = "tiaris-nest"; RuntimeDirectoryMode = "0755"; RuntimeDirectoryPreserve = "yes"; };
    };
    systemd.services.tiaris-nest-pxe = {
      wantedBy = [ "multi-user.target" ]; after = [ "tiaris-nest.service" ]; wants = [ "tiaris-nest.service" ];
      serviceConfig = { ExecStart = command "pxe"; Restart = "always"; RestartSec = "5s"; RuntimeDirectory = "tiaris-nest-pxe"; RuntimeDirectoryMode = "0755"; User = "root"; UMask = "0022"; NoNewPrivileges = true; ProtectSystem = "strict"; ProtectHome = true; PrivateTmp = true; ReadWritePaths = [ "/run/tiaris-nest-pxe" ]; CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" "CAP_NET_RAW" "CAP_NET_ADMIN" "CAP_SETUID" "CAP_SETGID" "CAP_DAC_READ_SEARCH" "CAP_KILL" ]; AmbientCapabilities = [ "CAP_SETUID" ]; };
    };
    systemd.services.tiaris-nest-network-runtime = (rootService "network-runtime") // { after = [ "tiaris-nest-first-boot.service" "network-online.target" ]; wants = [ "network-online.target" ]; before = [ "tiaris-nest.service" ]; serviceConfig = { Type = "oneshot"; ExecStart = command "network-runtime"; TimeoutStartSec = "30s"; }; };
    systemd.timers.tiaris-nest-network-runtime = { wantedBy = [ "timers.target" ]; timerConfig = { OnBootSec = "1min"; OnUnitActiveSec = "1min"; }; };
    systemd.services.tiaris-nest-network-change = (rootService "network-change") // { after = [ "tiaris-nest.service" ]; serviceConfig = { Type = "oneshot"; ExecStart = command "network-change"; TimeoutStartSec = "5min"; }; };
    systemd.paths.tiaris-nest-network-change = { wantedBy = [ "multi-user.target" ]; pathConfig.PathExists = "/var/lib/tiaris-nest/state/inbox/appliance-network-change-request.json"; };
    systemd.services.tiaris-nest-appliance-update = (rootService "appliance-update") // { after = [ "tiaris-nest.service" ]; serviceConfig = { Type = "oneshot"; ExecStart = command "appliance-update"; TimeoutStartSec = "4h"; }; };
    systemd.timers.tiaris-nest-appliance-update = { wantedBy = [ "timers.target" ]; timerConfig = { OnBootSec = "1min"; OnUnitInactiveSec = "30s"; RandomizedDelaySec = "5s"; }; };
    systemd.services.tiaris-nest-generation-commit = (rootService "generation-commit") // {
      wantedBy = [ "multi-user.target" ]; after = [ "tiaris-nest.service" "nginx.service" "tftpd-hpa.service" ]; wants = [ "tiaris-nest.service" ];
      unitConfig = { ConditionPathExists = "/var/lib/tiaris-nest/control/pending-system-generation.json"; FailureAction = "reboot"; JobTimeoutSec = "5min"; JobTimeoutAction = "reboot"; };
      serviceConfig = { Type = "oneshot"; ExecStart = command "generation-commit"; TimeoutStartSec = "5min"; };
    };
    systemd.services.tiaris-nest-gc = (rootService "gc");
    systemd.timers.tiaris-nest-gc = { wantedBy = [ "timers.target" ]; timerConfig = { OnCalendar = "daily"; Persistent = true; }; };
    # Mask both login paths. A dedicated unit avoids getty@.service.d's
    # template ExecStart override replacing our console command with agetty.
    systemd.services."autovt@tty1".enable = false;
    systemd.services."getty@tty1".enable = false;
    # Native Canopy appliance screen; it falls back to its own text feed on
    # tty1 when no DRM output is usable. Status comes from the daemon.
    systemd.services.tiaris-nest-console = {
      description = "Tiaris Nest console";
      wantedBy = [ "getty.target" ]; conflicts = [ "rescue.service" ]; before = [ "getty.target" "rescue.service" ];
      after = [ "systemd-logind.service" "systemd-user-sessions.service" ];
      environment = {
        TIARIS_NEST_CONSOLE_STATUS = "/run/tiaris-nest/console-status.json";
        FONTCONFIG_FILE = "${pkgs.fontconfig.out}/etc/fonts/fonts.conf";
        XDG_RUNTIME_DIR = "/run/tiaris-nest-console";
        HOME = "/root";
      };
      serviceConfig = { Type = "idle"; ExecStart = "${a.installerKiosk}/bin/tiaris-installer-kiosk --appliance"; Restart = "always"; RestartSec = "2s"; StandardInput = "tty"; StandardOutput = "tty"; StandardError = "journal"; TTYPath = "/dev/tty1"; TTYReset = true; TTYVHangup = true; TTYVTDisallocate = true; UtmpIdentifier = "tty1"; UtmpMode = "user"; PAMName = "login"; RuntimeDirectory = "tiaris-nest-console"; RuntimeDirectoryMode = "0700"; };
    };
  };
}
