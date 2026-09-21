{ config, lib, pkgs, appliance, ... }:
{
  imports = [ ./module.nix ];
  services.cybex-james = { enable = true; inherit appliance; };
  networking.hostName = "cybex-james";
  system.stateVersion = "26.05";
  boot.loader.systemd-boot.enable = true;
  boot.loader.systemd-boot.configurationLimit = 4; # current + 2 known good + pending
  boot.loader.efi.canTouchEfiVariables = true;
  boot.loader.timeout = 3;
  boot.initrd.availableKernelModules = [ "xhci_pci" "ahci" "nvme" "virtio_pci" "virtio_blk" "virtio_scsi" "sd_mod" "sr_mod" "usbhid" "usb_storage" "vmd" ];
  boot.initrd.kernelModules = [ "i6300esb" ];
  boot.initrd.systemd.enable = true;
  boot.initrd.systemd.emergencyAccess = false;
  boot.initrd.systemd.settings.Manager = { RuntimeWatchdogSec = "120s"; RebootWatchdogSec = "10min"; };
  boot.initrd.systemd.targets.initrd.unitConfig = { JobTimeoutSec = "180s"; JobTimeoutAction = "reboot-force"; };
  boot.initrd.systemd.services.emergency.serviceConfig.ExecStart = lib.mkForce "${pkgs.systemd}/bin/systemctl --no-block reboot";
  boot.kernelParams = [ "panic=30" "console=ttyS0,115200n8" "console=tty0" ];
  hardware.enableRedistributableFirmware = true;
  hardware.cpu.intel.updateMicrocode = true;
  hardware.cpu.amd.updateMicrocode = true;
  fileSystems."/" = { device = "/dev/disk/by-label/CYBEX_ROOT"; fsType = "ext4"; };
  fileSystems."/boot" = { device = "/dev/disk/by-label/CYBEX_EFI"; fsType = "vfat"; options = [ "umask=0077" ]; };
  fileSystems."/var/lib/cybex-james/state" = { device = "/dev/disk/by-label/CYBEX_STATE"; fsType = "ext4"; options = [ "nodev" "nosuid" ]; neededForBoot = true; };
  fileSystems."/nix" = { device = "/var/cache/cybex-james/nix"; fsType = "none"; options = [ "bind" "nodev" "nosuid" ]; neededForBoot = true; depends = [ "/" ]; };
  fileSystems."/var/lib/cybex-james/control" = { device = "/var/lib/cybex-james/state/control"; fsType = "none"; options = [ "bind" "nodev" "nosuid" ]; depends = [ "/var/lib/cybex-james/state" ]; };
  fileSystems."/var/lib/cybex-james/status" = { device = "/var/lib/cybex-james/state/status"; fsType = "none"; options = [ "bind" "nodev" "nosuid" ]; depends = [ "/var/lib/cybex-james/state" ]; };
  swapDevices = [ { device = "/dev/disk/by-label/CYBEX_SWAP"; } ];
}
