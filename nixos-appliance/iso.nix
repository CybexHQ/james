{ config, lib, pkgs, modulesPath, appliance, ... }:
let
  a = appliance;
  slot = pkgs.runCommand "tiaris-provisioning-slot" {} ''
    dd if=/dev/zero of=$out bs=8192 count=1 status=none
  '';
  key = pkgs.writeText "release-public-key" (a.releasePublicKey + "\n");
  keys = pkgs.writeText "provisioning-public-keys" (lib.concatStringsSep "\n" a.provisioningPublicKeys + "\n");
  setupStatus = "/run/tiaris-nest-setup/status.json";
in {
  disabledModules = [ "installer/cd-dvd/iso-image.nix" ];
  imports = [
    (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix")
    (import ./single-menu-iso-module.nix { nixpkgs = appliance.nixpkgsPath; })
  ];
  networking.hostName = "tiaris-nest-setup";
  system.stateVersion = "26.05";
  system.installer.channel.enable = false;
  system.tools.nixos-rebuild.enable = false;
  hardware.enableRedistributableFirmware = true;
  hardware.cpu.intel.updateMicrocode = true;
  hardware.cpu.amd.updateMicrocode = true;
  boot.initrd.systemd.enable = true;
  boot.zfs.forceImportRoot = false;
  boot.kernelParams = [ "console=ttyS0,115200n8" "console=tty0" "panic=30" ];
  boot.loader.timeout = lib.mkForce 3;
  isoImage = {
    makeEfiBootable = true;
    makeUsbBootable = true;
    makeBiosBootable = false;
    volumeID = "TIARIS_NEST_SETUP";
    grubTheme = a.grubTheme;
    # The pinned module labels its entry prepend + distroName + " " + label.
    # single-menu-iso-module.nix removes every other entry, so the menu is
    # exactly "Install Tiaris Nest".
    prependToMenuLabel = "Install ";
    appendToMenuLabel = "";
    squashfsCompression = "zstd -Xcompression-level 10";
    contents = [
      { source = slot; target = "/TIARIS_PROVISIONING.BIN"; }
      { source = key; target = "/tiaris/release-public-key"; }
      { source = keys; target = "/tiaris/provisioning-public-keys"; }
      { source = pkgs.writeText "nixos-appliance" "3\n"; target = "/tiaris/nixos-appliance"; }
      { source = "${a.package}/bin/tiaris-nest-bootstrap"; target = "/tiaris/bootstrap/tiaris-nest-bootstrap"; }
    ];
  };
  image.baseName = lib.mkForce "tiaris-nest-appliance-template-${a.package.version}-x86_64-linux";
  system.nixos.distroName = lib.mkForce "Tiaris";
  system.nixos.label = lib.mkForce "Nest";
  networking.networkmanager.enable = lib.mkForce false;
  networking.useDHCP = lib.mkForce false;
  networking.useNetworkd = true;
  systemd.network.enable = true;
  systemd.network.networks."20-tiaris-installer" = { matchConfig.Name = "en* eth*"; networkConfig = { DHCP = "ipv4"; IPv6AcceptRA = false; }; };
  services.resolved.enable = true;
  services.timesyncd.enable = true;
  # timesyncd does not include its optional wait unit in this nixpkgs pin.
  # Give NTP a bounded opportunity before HTTPS; an offline clock must not
  # prevent the setup screen or bootstrap retry loop from starting forever.
  systemd.additionalUpstreamSystemUnits = [ "systemd-time-wait-sync.service" ];
  systemd.services.systemd-time-wait-sync.serviceConfig.TimeoutStartSec = "60s";
  services.openssh.enable = lib.mkForce false;
  services.getty.autologinUser = lib.mkForce null;
  environment.systemPackages = [ a.package pkgs.nix pkgs.nixos-install-tools pkgs.iputils pkgs.iproute2 pkgs.gptfdisk pkgs.e2fsprogs pkgs.dosfstools pkgs.util-linux pkgs.curl pkgs.jq pkgs.zstd pkgs.python3 ];
  nix.settings = { experimental-features = [ "nix-command" ]; substituters = lib.mkForce []; trusted-public-keys = lib.mkForce [ "tiaris-nest-appliance-1:${a.releasePublicKey}" ]; };
  systemd.services.tiaris-nest-bootstrap = {
    wantedBy = [ "multi-user.target" ]; after = [ "network-online.target" "systemd-time-wait-sync.service" ]; wants = [ "network-online.target" "systemd-time-wait-sync.service" ];
    path = config.environment.systemPackages;
    preStart = ''
      mkdir -p /cdrom
      mountpoint -q /cdrom || mount --bind /iso /cdrom
    '';
    # The public setup projection for the tty1 kiosk. Preserve it across
    # restarts so a stopped or failed screen stays readable meanwhile.
    serviceConfig = { Type = "simple"; ExecStart = "${a.package}/bin/tiaris-nest-bootstrap prepare --setup-status ${setupStatus}"; Restart = "on-failure"; RestartSec = "15s"; StandardOutput = "journal"; StandardError = "journal"; UMask = "0077"; TimeoutStartSec = "infinity"; RuntimeDirectory = "tiaris-nest-setup"; RuntimeDirectoryMode = "0755"; RuntimeDirectoryPreserve = "yes"; };
  };
  systemd.services."getty@tty1".enable = false;
  # getty.target and logind use this alias, not getty@tty1. Mask the exact
  # instance as well so neither boot nor a VT switch starts a login prompt.
  systemd.services."autovt@tty1".enable = false;
  # Native Canopy setup screen (Slint software renderer straight to KMS).
  # Without a usable DRM output it prints its own line-oriented text feed,
  # so tty1 stays readable on nomodeset and serial-only machines.
  systemd.services.tiaris-nest-setup-console = {
    description = "Tiaris Nest setup screen";
    wantedBy = [ "multi-user.target" ];
    after = [ "systemd-logind.service" "systemd-user-sessions.service" ];
    environment = {
      TIARIS_NEST_SETUP_STATUS = setupStatus;
      # Slint embeds the Canopy faces but builds its fallback map through
      # Fontconfig; the ISO has no global Fontconfig profile.
      FONTCONFIG_FILE = "${pkgs.fontconfig.out}/etc/fonts/fonts.conf";
      XDG_RUNTIME_DIR = "/run/tiaris-nest-setup-console";
      HOME = "/root";
    };
    serviceConfig = { Type = "simple"; ExecStart = "${a.installerKiosk}/bin/tiaris-installer-kiosk --nest-setup"; Restart = "always"; RestartSec = "2s"; StandardInput = "tty"; StandardOutput = "tty"; StandardError = "journal"; TTYPath = "/dev/tty1"; TTYReset = true; TTYVHangup = true; TTYVTDisallocate = true; UtmpIdentifier = "tty1"; UtmpMode = "user"; PAMName = "login"; RuntimeDirectory = "tiaris-nest-setup-console"; RuntimeDirectoryMode = "0700"; };
  };
}
