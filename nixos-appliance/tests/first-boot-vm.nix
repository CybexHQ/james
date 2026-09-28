{ nixpkgs, common }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  lib = pkgs.lib;
  installed = import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    specialArgs.appliance = common;
    modules = [ ../system.nix ];
  };
  handoff = installed.config.systemd.services.tiaris-nest-first-boot.environment.TIARIS_HANDOFF_SOURCE;
  firstBootAfter = installed.config.systemd.services.tiaris-nest-first-boot.after;
  firstBootRequires = installed.config.systemd.services.tiaris-nest-first-boot.requires;
  firstBootUnit = installed.config.systemd.units."tiaris-nest-first-boot.service".text;
  emergency = installed.config.boot.initrd.systemd.services.emergency.serviceConfig.ExecStart;
  emergencyUnit = installed.config.boot.initrd.systemd.units."emergency.service".text;
  emergencyCommands = builtins.filter (lib.hasPrefix "ExecStart=") (lib.splitString "\n" emergencyUnit);
in
assert lib.hasPrefix "/nix/store/" handoff;
assert builtins.pathExists handoff;
assert lib.hasInfix
  (builtins.unsafeDiscardStringContext "Environment=\"TIARIS_HANDOFF_SOURCE=${handoff}\"")
  (builtins.unsafeDiscardStringContext firstBootUnit);
assert builtins.elem "sshd-keygen.service" firstBootAfter;
assert builtins.elem "sshd-keygen.service" firstBootRequires;
assert emergency == [ "" "${pkgs.systemd}/bin/systemctl --no-block reboot" ];
assert emergencyCommands == [ "ExecStart=" "ExecStart=${pkgs.systemd}/bin/systemctl --no-block reboot" ];
import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, ... }: {
  name = "tiaris-nest-first-boot-mount-policy";
  nodes.machine = { ... }: {
    system.stateVersion = "26.05";
    users.groups.probe = {};
    users.users.probe = { isSystemUser = true; group = "probe"; };
    environment.systemPackages = [ pkgs.coreutils pkgs.python3 pkgs.util-linux ];
    services.openssh = {
      enable = true;
      hostKeys = [ { path = "/etc/ssh/ssh_host_ed25519_key"; type = "ed25519"; } ];
    };
    systemd.services.sshd-keygen.preStart = ''
      touch /run/tiaris-keygen-started
      sleep 2
    '';
    systemd.services.tiaris-nest-first-boot = {
      wantedBy = [ "multi-user.target" ];
      after = firstBootAfter;
      requires = firstBootRequires;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "tiaris-first-boot-keygen-probe" ''
          test -e /run/tiaris-keygen-started
          test -s /etc/ssh/ssh_host_ed25519_key
          ${pkgs.openssh}/bin/sshd -t
          touch /run/tiaris-first-boot-probed
        '';
      };
    };
    systemd.services.tiaris-store-probe = {
      serviceConfig = {
        Type = "oneshot";
        User = "probe";
        ExecStart = "/srv/tiaris-nix/store/probe";
      };
    };
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("tiaris-nest-first-boot.service")
    machine.succeed("test -e /run/tiaris-first-boot-probed")
    machine.succeed("install -d -m0755 /var/cache/tiaris-qualification /srv/tiaris-nix; umask 077; mkdir -p /var/cache/tiaris-qualification/nix/store /var/cache/tiaris-qualification/wrong; chmod 1775 /var/cache/tiaris-qualification/nix/store")
    machine.succeed("printf '#!${pkgs.runtimeShell}\\nexit 0\\n' > /var/cache/tiaris-qualification/nix/store/probe; chmod 0555 /var/cache/tiaris-qualification/nix/store/probe")
    machine.succeed("chmod 0755 /var/cache/tiaris-qualification/nix")
    machine.fail("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/tiaris-nix', '/var/cache/tiaris-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("mount --bind /var/cache/tiaris-qualification/nix /srv/tiaris-nix")
    machine.fail("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/tiaris-nix', '/var/cache/tiaris-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("mount -o remount,bind,rw,nodev,nosuid,noexec /srv/tiaris-nix")
    machine.fail("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/tiaris-nix', '/var/cache/tiaris-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("mount -o remount,bind,rw,nodev,nosuid,exec /srv/tiaris-nix")
    machine.succeed("${pkgs.python3}/bin/python3 -c \"import os; assert not os.path.ismount('/srv/tiaris-nix')\"")
    machine.succeed("chmod 0700 /var/cache/tiaris-qualification/nix")
    machine.fail("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/tiaris-nix', '/var/cache/tiaris-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("chmod 0755 /var/cache/tiaris-qualification/nix")
    machine.succeed("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/tiaris-nix', '/var/cache/tiaris-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("umount /srv/tiaris-nix; mount --bind /var/cache/tiaris-qualification/wrong /srv/tiaris-nix; mount -o remount,bind,rw,nodev,nosuid,exec /srv/tiaris-nix")
    machine.fail("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/tiaris-nix', '/var/cache/tiaris-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("umount /srv/tiaris-nix; mount --bind /var/cache/tiaris-qualification/nix /srv/tiaris-nix; mount -o remount,bind,rw,nodev,nosuid,exec /srv/tiaris-nix")
    machine.succeed("runuser -u probe -- /srv/tiaris-nix/store/probe")
    machine.succeed("systemctl start tiaris-store-probe.service")
  '';
}) { system = "x86_64-linux"; }
