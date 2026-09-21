{ config, lib, pkgs, modulesPath, appliance, ... }:
let
  a = appliance;
  slot = pkgs.runCommand "cybex-provisioning-slot" {} ''
    dd if=/dev/zero of=$out bs=8192 count=1 status=none
  '';
  key = pkgs.writeText "release-public-key" (a.releasePublicKey + "\n");
  keys = pkgs.writeText "provisioning-public-keys" (lib.concatStringsSep "\n" a.provisioningPublicKeys + "\n");
  theme = pkgs.runCommand "cybex-james-setup-theme" {} ''
    mkdir -p $out
    cp ${a.themeSource}/theme.txt $out/theme.txt
    cp ${../assets/pxe-menu.png} $out/background.png
    substituteInPlace $out/theme.txt --replace 'background.svg' 'background.png'
    cp ${pkgs.grub2_efi}/share/grub/unicode.pf2 $out/unicode.pf2
  '';
in {
  disabledModules = [ "installer/cd-dvd/iso-image.nix" ];
  imports = [
    (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix")
    (import ./single-menu-iso-module.nix { nixpkgs = appliance.nixpkgsPath; })
  ];
  networking.hostName = "cybex-james-setup";
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
    volumeID = "CYBEX_JAMES_SETUP";
    grubTheme = theme;
    prependToMenuLabel = "Boot Cybex ";
    appendToMenuLabel = "";
    squashfsCompression = "zstd -Xcompression-level 10";
    contents = [
      { source = slot; target = "/CYBEX_PROVISIONING.BIN"; }
      { source = key; target = "/cybex/release-public-key"; }
      { source = keys; target = "/cybex/provisioning-public-keys"; }
      { source = pkgs.writeText "nixos-appliance" "3\n"; target = "/cybex/nixos-appliance"; }
      { source = "${a.package}/bin/cybex-james-bootstrap"; target = "/cybex/bootstrap/cybex-james-bootstrap"; }
    ];
  };
  image.baseName = lib.mkForce "cybex-james-appliance-template-${a.package.version}-x86_64-linux";
  system.nixos.distroName = lib.mkForce "James";
  system.nixos.label = lib.mkForce "Setup";
  networking.networkmanager.enable = lib.mkForce false;
  networking.useDHCP = lib.mkForce false;
  networking.useNetworkd = true;
  systemd.network.enable = true;
  systemd.network.networks."20-cybex-installer" = { matchConfig.Name = "en* eth*"; networkConfig = { DHCP = "ipv4"; IPv6AcceptRA = false; }; };
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
  nix.settings = { experimental-features = [ "nix-command" ]; substituters = lib.mkForce []; trusted-public-keys = lib.mkForce [ "cybex-james-appliance-1:${a.releasePublicKey}" ]; };
  systemd.services.cybex-james-bootstrap = {
    wantedBy = [ "multi-user.target" ]; after = [ "network-online.target" "systemd-time-wait-sync.service" ]; wants = [ "network-online.target" "systemd-time-wait-sync.service" ];
    path = config.environment.systemPackages;
    preStart = ''
      mkdir -p /cdrom
      mountpoint -q /cdrom || mount --bind /iso /cdrom
    '';
    serviceConfig = { Type = "simple"; ExecStart = "${a.package}/bin/cybex-james-bootstrap prepare"; Restart = "on-failure"; RestartSec = "15s"; StandardOutput = "journal"; StandardError = "journal"; UMask = "0077"; TimeoutStartSec = "infinity"; };
  };
  systemd.services."getty@tty1".enable = false;
  # getty.target and logind use this alias, not getty@tty1. Mask the exact
  # instance as well so neither boot nor a VT switch starts a login prompt.
  systemd.services."autovt@tty1".enable = false;
  systemd.services.cybex-james-setup-console = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = { ExecStart = pkgs.writeShellScript "cybex-james-setup-console" ''
      while true; do
        # Graphics initialization or a VT reset can erase an unchanged screen.
        printf '\033[2J\033[HCybex James Setup\nContinue in Cybex Manage.\n'
        ${pkgs.coreutils}/bin/sleep 10
      done
    ''; Restart = "always"; RestartSec = "2s"; StandardInput = "null"; StandardOutput = "tty"; StandardError = "journal"; TTYPath = "/dev/tty1"; TTYReset = true; TTYVHangup = true; TTYVTDisallocate = true; };
  };
}
