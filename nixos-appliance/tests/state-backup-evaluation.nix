# Evaluate the automatic state backup units without booting a VM.
{ nixpkgs ? builtins.fetchTarball (let pin = import ../../release/nixpkgs.nix; in { inherit (pin) url sha256; }) }:
let
  installed = (import ./console-config.nix { inherit nixpkgs; }).installed;
  service = installed.systemd.services.tiaris-nest-state-backup;
  timer = installed.systemd.timers.tiaris-nest-state-backup;
  backups = "/var/cache/tiaris-nest/state-backups";
  checks = {
    timerIsEnabled = builtins.elem "timers.target" timer.wantedBy;
    timerRunsDaily = timer.timerConfig.OnCalendar == "daily";
    timerCatchesUpAfterDowntime = timer.timerConfig.Persistent;
    timerSpreadsNestsOut = timer.timerConfig.RandomizedDelaySec == "4h";
    serviceRunsOnlyWithABackupKey = service.unitConfig.ConditionPathExists
      == "/var/lib/tiaris-nest/state/backup/recipient.pub";
    serviceIsAOneshot = service.serviceConfig.Type == "oneshot";
    serviceRunsTheScheduledBackup = builtins.match ".*/bin/tiaris-nest scheduled-state-backup"
      service.serviceConfig.ExecStart != null;
    serviceRunsAsRoot = !(service.serviceConfig ? User);
    serviceWritesOnlyItsPaths = service.serviceConfig.ProtectSystem == "strict"
      && builtins.sort builtins.lessThan service.serviceConfig.ReadWritePaths == [
        "/var/cache/tiaris-nest/state-backups"
        "/var/lib/tiaris-nest/state/agent"
        "/var/lib/tiaris-nest/state/status"
      ];
    serviceIsNotStartedAtBoot = !(service ? wantedBy) || service.wantedBy == [ ];
    backupFolderIsReadableByTheNest = builtins.elem "d ${backups} 0750 root tiaris-nest -"
      installed.systemd.tmpfiles.rules;
  };
in assert builtins.all (value: value) (builtins.attrValues checks); checks
