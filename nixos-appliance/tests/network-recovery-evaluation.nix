# Evaluate the real first-boot/SSH dependency graph without booting a VM.
{ nixpkgs ? builtins.fetchTarball (let pin = import ../../release/nixpkgs.nix; in { inherit (pin) url sha256; }) }:
let
  installed = (import ./console-config.nix { inherit nixpkgs; }).installed;
  firstBoot = installed.systemd.services.tiaris-nest-first-boot;
  ssh = installed.systemd.services.sshd;
  firewall = installed.systemd.services.tiaris-nest-firewall;
  nest = installed.systemd.services.tiaris-nest;
  networkRuntime = installed.systemd.services.tiaris-nest-network-runtime;
  checks = {
    retryStartsRecoverySsh = builtins.elem "sshd.service" firstBoot.wants;
    sshFailureDoesNotFailFirstBoot = !(builtins.elem "sshd.service" firstBoot.requires);
    firstBootDoesNotWaitForSsh = !(builtins.elem "sshd.service" firstBoot.after);
    sshRequiresMaterializedTrust = builtins.elem "tiaris-nest-first-boot.service" ssh.requires
      && builtins.elem "tiaris-nest-first-boot.service" ssh.after;
    sshRequiresFirewall = builtins.elem "tiaris-nest-firewall.service" ssh.requires
      && builtins.elem "tiaris-nest-firewall.service" ssh.after;
    firewallFollowsFirstBoot = builtins.elem "tiaris-nest-first-boot.service" firewall.after;
    nestRetriesFirstBoot = builtins.elem "tiaris-nest-first-boot.service" nest.requires;
    networkRuntimeCanRetryWithoutNest = !(builtins.elem "tiaris-nest.service" networkRuntime.requires);
    networkRetryTimerRemainsEnabled = builtins.elem "timers.target"
      installed.systemd.timers.tiaris-nest-network-runtime.wantedBy;
  };
in assert builtins.all (value: value) (builtins.attrValues checks); checks
