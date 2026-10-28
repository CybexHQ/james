# Evaluate the installed production module, not the installer or a local profile.
# Reuse the console seam's test-only package/trust placeholders; build nothing.
{ nixpkgs ? builtins.fetchTarball (let pin = import ../../release/nixpkgs.nix; in { inherit (pin) url sha256; }) }:
let
  fixtures = import ./console-config.nix { inherit nixpkgs; };
  appliance = fixtures.appliance // { workstationAgent = fixtures.appliance.package; };
  installed = (import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    specialArgs = { inherit appliance; };
    modules = [ ../system.nix ];
  }).config;
  agent = installed.systemd.services.qemu-guest-agent;
  incus = installed.systemd.services.incus-agent;
  incusLoader = installed.virtualisation.incus.package.agent_loader;
  checks = {
    installedGuestAgentEnabled = installed.services.qemuGuest.enable;
    guestAgentRunsPackagedBinary = agent.serviceConfig.ExecStart
      == "${installed.services.qemuGuest.package}/bin/qemu-ga --statedir /run/qemu-ga";
    guestAgentActivatedOnlyByVirtioChannel = agent.wantedBy == []
      && (import nixpkgs { system = "x86_64-linux"; }).lib.hasInfix
        ''SUBSYSTEM=="virtio-ports", ATTR{name}=="org.qemu.guest_agent.0", TAG+="systemd", ENV{SYSTEMD_WANTS}="qemu-guest-agent.service"''
        installed.services.udev.extraRules;
    guestAgentStateIsEphemeral = agent.serviceConfig.RuntimeDirectory == "qemu-ga";
    installedIncusAgentEnabled = installed.virtualisation.incus.agent.enable && incus.enable;
    incusUsesPackagedLoaderAndUdev = builtins.elem incusLoader installed.systemd.packages
      && builtins.elem incusLoader installed.services.udev.packages;
    incusAgentStartsAtBoot = builtins.elem "multi-user.target" incus.wantedBy;
    incusAgentRequiresItsHypervisorChannel = incus.unitConfig.ConditionPathExists
      == "/dev/virtio-ports/org.linuxcontainers.incus";
    incusExecFindsSystemBinaries = builtins.elem "/run/current-system/sw" incus.path;
    incusExecSurvivesGenerationSwitch = !incus.restartIfChanged && !incus.stopIfChanged;
    incusHostDaemonRemainsDisabled = !installed.virtualisation.incus.enable;
    statePartitionPreserved = installed.fileSystems."/var/lib/tiaris-nest/state".device == "/dev/disk/by-label/TIARIS_STATE"
      && installed.fileSystems."/var/lib/tiaris-nest/state".fsType == "ext4"
      && installed.fileSystems."/var/lib/tiaris-nest/state".neededForBoot
      && builtins.elem "nodev" installed.fileSystems."/var/lib/tiaris-nest/state".options
      && builtins.elem "nosuid" installed.fileSystems."/var/lib/tiaris-nest/state".options;
    controlAndStatusRemainOnState = installed.fileSystems."/var/lib/tiaris-nest/control".device == "/var/lib/tiaris-nest/state/control"
      && installed.fileSystems."/var/lib/tiaris-nest/status".device == "/var/lib/tiaris-nest/state/status";
    bootSelectionPreserved = installed.boot.loader.systemd-boot.enable
      && installed.boot.loader.systemd-boot.configurationLimit == 4
      && installed.boot.loader.efi.canTouchEfiVariables
      && installed.fileSystems."/boot".device == "/dev/disk/by-label/TIARIS_EFI";
    releaseSignaturePolicyPreserved = installed.nix.settings.require-sigs
      && installed.nix.settings.trusted-users != []
      && builtins.all (user: user == "root") installed.nix.settings.trusted-users
      && builtins.elem "tiaris-nest-appliance-1:${appliance.releasePublicKey}" installed.nix.settings.trusted-public-keys;
    stateVersionPreserved = installed.system.stateVersion == "26.05";
    workstationAgentRemainsCacheSeed = builtins.elem appliance.workstationAgent installed.system.extraDependencies;
    workstationCustomOutputsRemainCacheSeeds = builtins.all
      (package: builtins.elem package installed.system.extraDependencies)
      appliance.workstationCacheSeeds.packages;
  };
in
assert installed.services.qemuGuest.enable;
assert builtins.all (value: value) (builtins.attrValues checks);
checks
