{ nixpkgs ? builtins.fetchTarball (let pin = import ../../release/nixpkgs.nix; in { inherit (pin) url sha256; }) }:
let
  configurations = import ./console-config.nix { inherit nixpkgs; };
  setup = configurations.setup;
  installed = configurations.installed;
  noAutomaticLogin = config: !(config.systemd.services."autovt@tty1".enable or true);
  checks = {
    setupMasksAutomaticTty1 = noAutomaticLogin setup;
    installedMasksAutomaticTty1 = noAutomaticLogin installed;
    installedMasksDirectTty1 = !installed.systemd.services."getty@tty1".enable;
    setupMasksDirectTty1 = !setup.systemd.services."getty@tty1".enable;
    setupHasVisibleConsole = setup.systemd.services.cybex-james-setup-console.serviceConfig.TTYPath == "/dev/tty1";
    installedHasVisibleConsole = installed.systemd.services.cybex-james-console.serviceConfig.TTYPath == "/dev/tty1";
    setupKeepsBootstrapLogsOffConsole = setup.systemd.services.cybex-james-bootstrap.serviceConfig.StandardOutput == "journal"
      && setup.systemd.services.cybex-james-bootstrap.serviceConfig.StandardError == "journal";
    setupBoundsTimeWait = setup.systemd.services.systemd-time-wait-sync.serviceConfig.TimeoutStartSec == "60s";
    setupHasTimeWaitUnit = builtins.elem "systemd-time-wait-sync.service" setup.systemd.additionalUpstreamSystemUnits;
  };
in assert builtins.all (value: value) (builtins.attrValues checks); checks
