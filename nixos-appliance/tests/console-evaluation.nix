{ nixpkgs ? builtins.fetchTarball (let pin = import ../../release/nixpkgs.nix; in { inherit (pin) url sha256; }) }:
let
  configurations = import ./console-config.nix { inherit nixpkgs; };
  inherit (configurations) appliance;
  setup = configurations.setup;
  installed = configurations.installed;
  setupConsole = setup.systemd.services.tiaris-nest-setup-console;
  installedConsole = installed.systemd.services.tiaris-nest-console;
  bootstrap = setup.systemd.services.tiaris-nest-bootstrap.serviceConfig;
  daemon = installed.systemd.services.tiaris-nest.serviceConfig;
  kiosk = "${appliance.installerKiosk}/bin/tiaris-installer-kiosk";
  noAutomaticLogin = config: !(config.systemd.services."autovt@tty1".enable or true);
  ownsTty1 = unit: unit.serviceConfig.TTYPath == "/dev/tty1"
    && unit.serviceConfig.TTYReset && unit.serviceConfig.TTYVHangup && unit.serviceConfig.TTYVTDisallocate
    # The kiosk's no-DRM text feed is stdout; it must reach tty1.
    && unit.serviceConfig.StandardOutput == "tty" && unit.serviceConfig.StandardInput == "tty"
    && unit.serviceConfig.Restart == "always" && unit.serviceConfig.PAMName == "login"
    && unit.environment.FONTCONFIG_FILE != "";
  menuLabel = setup.isoImage.prependToMenuLabel + setup.system.nixos.distroName + " "
    + setup.system.nixos.label + setup.isoImage.appendToMenuLabel;
  checks = {
    setupMasksAutomaticTty1 = noAutomaticLogin setup;
    installedMasksAutomaticTty1 = noAutomaticLogin installed;
    installedMasksDirectTty1 = !installed.systemd.services."getty@tty1".enable;
    setupMasksDirectTty1 = !setup.systemd.services."getty@tty1".enable;
    setupHasVisibleConsole = ownsTty1 setupConsole;
    installedHasVisibleConsole = ownsTty1 installedConsole;
    setupRunsSetupKiosk = setupConsole.serviceConfig.ExecStart == "${kiosk} --nest-setup"
      && setupConsole.environment.TIARIS_NEST_SETUP_STATUS == "/run/tiaris-nest-setup/status.json";
    installedRunsApplianceKiosk = installedConsole.serviceConfig.ExecStart == "${kiosk} --appliance"
      && installedConsole.environment.TIARIS_NEST_CONSOLE_STATUS == "/run/tiaris-nest/console-status.json";
    installedConsoleKeepsGettyOrdering = builtins.elem "getty.target" installedConsole.wantedBy
      && builtins.elem "rescue.service" installedConsole.conflicts
      && installedConsole.serviceConfig.Type == "idle";
    bootstrapPublishesSetupStatus = bootstrap.RuntimeDirectory == "tiaris-nest-setup"
      && bootstrap.RuntimeDirectoryMode == "0755" && bootstrap.RuntimeDirectoryPreserve == "yes"
      && bootstrap.ExecStart == "${appliance.package}/bin/tiaris-nest-bootstrap prepare --setup-status /run/tiaris-nest-setup/status.json";
    daemonPublishesConsoleStatus = daemon.RuntimeDirectory == "tiaris-nest"
      && daemon.RuntimeDirectoryMode == "0755" && daemon.RuntimeDirectoryPreserve == "yes"
      && builtins.elem "/run/tiaris-nest" daemon.ReadWritePaths;
    daemonStaysHardened = daemon.User == "tiaris-nest" && daemon.NoNewPrivileges
      && daemon.ProtectSystem == "strict" && daemon.CapabilityBoundingSet == "";
    setupKeepsBootstrapLogsOffConsole = bootstrap.StandardOutput == "journal"
      && bootstrap.StandardError == "journal";
    setupBoundsTimeWait = setup.systemd.services.systemd-time-wait-sync.serviceConfig.TimeoutStartSec == "60s";
    setupHasTimeWaitUnit = builtins.elem "systemd-time-wait-sync.service" setup.systemd.additionalUpstreamSystemUnits;
    setupMenuInstallsTiarisNest = menuLabel == "Install Tiaris Nest";
    setupUsesManageGrubTheme = setup.isoImage.grubTheme == appliance.grubTheme;
  };
in assert builtins.all (value: value) (builtins.attrValues checks); checks
