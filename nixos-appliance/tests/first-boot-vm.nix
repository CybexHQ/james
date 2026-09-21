{ nixpkgs, common }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  lib = pkgs.lib;
  installed = import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    specialArgs.appliance = common;
    modules = [ ../system.nix ];
  };
  handoff = installed.config.systemd.services.cybex-james-first-boot.environment.CYBEX_HANDOFF_SOURCE;
  firstBootAfter = installed.config.systemd.services.cybex-james-first-boot.after;
  firstBootRequires = installed.config.systemd.services.cybex-james-first-boot.requires;
  firstBootUnit = installed.config.systemd.units."cybex-james-first-boot.service".text;
  emergency = installed.config.boot.initrd.systemd.services.emergency.serviceConfig.ExecStart;
  emergencyUnit = installed.config.boot.initrd.systemd.units."emergency.service".text;
  emergencyCommands = builtins.filter (lib.hasPrefix "ExecStart=") (lib.splitString "\n" emergencyUnit);
in
assert lib.hasPrefix "/nix/store/" handoff;
assert builtins.pathExists handoff;
assert lib.hasInfix
  (builtins.unsafeDiscardStringContext "Environment=\"CYBEX_HANDOFF_SOURCE=${handoff}\"")
  (builtins.unsafeDiscardStringContext firstBootUnit);
assert builtins.elem "sshd-keygen.service" firstBootAfter;
assert builtins.elem "sshd-keygen.service" firstBootRequires;
assert emergency == [ "" "${pkgs.systemd}/bin/systemctl --no-block reboot" ];
assert emergencyCommands == [ "ExecStart=" "ExecStart=${pkgs.systemd}/bin/systemctl --no-block reboot" ];
import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, ... }: {
  name = "cybex-james-first-boot-mount-policy";
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
      touch /run/cybex-keygen-started
      sleep 2
    '';
    systemd.services.cybex-james-first-boot = {
      wantedBy = [ "multi-user.target" ];
      after = firstBootAfter;
      requires = firstBootRequires;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "cybex-first-boot-keygen-probe" ''
          test -e /run/cybex-keygen-started
          test -s /etc/ssh/ssh_host_ed25519_key
          ${pkgs.openssh}/bin/sshd -t
          touch /run/cybex-first-boot-probed
        '';
      };
    };
    systemd.services.cybex-store-probe = {
      serviceConfig = {
        Type = "oneshot";
        User = "probe";
        ExecStart = "/srv/cybex-nix/store/probe";
      };
    };
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("cybex-james-first-boot.service")
    machine.succeed("test -e /run/cybex-first-boot-probed")
    machine.succeed("install -d -m0755 /var/cache/cybex-qualification /srv/cybex-nix; umask 077; mkdir -p /var/cache/cybex-qualification/nix/store /var/cache/cybex-qualification/wrong; chmod 1775 /var/cache/cybex-qualification/nix/store")
    machine.succeed("printf '#!${pkgs.runtimeShell}\\nexit 0\\n' > /var/cache/cybex-qualification/nix/store/probe; chmod 0555 /var/cache/cybex-qualification/nix/store/probe")
    machine.succeed("chmod 0755 /var/cache/cybex-qualification/nix")
    machine.fail("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/cybex-nix', '/var/cache/cybex-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("mount --bind /var/cache/cybex-qualification/nix /srv/cybex-nix")
    machine.fail("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/cybex-nix', '/var/cache/cybex-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("mount -o remount,bind,rw,nodev,nosuid,noexec /srv/cybex-nix")
    machine.fail("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/cybex-nix', '/var/cache/cybex-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("mount -o remount,bind,rw,nodev,nosuid,exec /srv/cybex-nix")
    machine.succeed("${pkgs.python3}/bin/python3 -c \"import os; assert not os.path.ismount('/srv/cybex-nix')\"")
    machine.succeed("chmod 0700 /var/cache/cybex-qualification/nix")
    machine.fail("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/cybex-nix', '/var/cache/cybex-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("chmod 0755 /var/cache/cybex-qualification/nix")
    machine.succeed("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/cybex-nix', '/var/cache/cybex-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("umount /srv/cybex-nix; mount --bind /var/cache/cybex-qualification/wrong /srv/cybex-nix; mount -o remount,bind,rw,nodev,nosuid,exec /srv/cybex-nix")
    machine.fail("PYTHONPATH=${../runtime} ${pkgs.python3}/bin/python3 -c \"from mount_policy import require_bind_mount; require_bind_mount('/srv/cybex-nix', '/var/cache/cybex-qualification/nix', required=('rw','nodev','nosuid'), forbidden=('noexec',), root_searchable=True)\"")
    machine.succeed("umount /srv/cybex-nix; mount --bind /var/cache/cybex-qualification/nix /srv/cybex-nix; mount -o remount,bind,rw,nodev,nosuid,exec /srv/cybex-nix")
    machine.succeed("runuser -u probe -- /srv/cybex-nix/store/probe")
    machine.succeed("systemctl start cybex-store-probe.service")
  '';
}) { system = "x86_64-linux"; }
