# Small component VM: run the real evaluated tty1 kiosk units without
# building an appliance ISO, enrolling a node, or starting the Nest daemon.
# Both nodes boot without a usable DRM output (no VGA, nomodeset), so the
# kiosk must fall back to its text feed on tty1 instead of a blank screen.
# The readiness rules behind the appliance status are unit-tested in Rust
# (src/console_status); here fixtures stand in for the status projections.
{ nixpkgs ? builtins.fetchTarball (let pin = import ../../release/nixpkgs.nix; in { inherit (pin) url sha256; })
, installerKiosk
}:
let
  configurations = import ./console-config.nix { inherit nixpkgs installerKiosk; };
  checks = import ./console-evaluation.nix { inherit nixpkgs; };
  unit = config: name: { inherit (config.systemd.services.${name}) description wantedBy after environment serviceConfig; };
  headless = {
    virtualisation.qemu.options = [ "-vga" "none" ];
    boot.kernelParams = [ "nomodeset" ];
  };
in assert builtins.all (value: value) (builtins.attrValues checks);
import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, ... }: {
  name = "tiaris-nest-tty1-consoles";
  nodes = {
    setup = { ... }: headless // {
      system.stateVersion = "26.05";
      systemd.services = {
        "getty@tty1".enable = configurations.setup.systemd.services."getty@tty1".enable;
        "autovt@tty1".enable = configurations.setup.systemd.services."autovt@tty1".enable;
        tiaris-nest-setup-console = unit configurations.setup "tiaris-nest-setup-console";
      };
      environment.systemPackages = [ pkgs.kbd ];
    };
    installed = { ... }: headless // {
      system.stateVersion = "26.05";
      systemd.services = {
        "autovt@tty1".enable = configurations.installed.systemd.services."autovt@tty1".enable;
        "getty@tty1".enable = configurations.installed.systemd.services."getty@tty1".enable;
        tiaris-nest-console = (unit configurations.installed "tiaris-nest-console") // {
          inherit (configurations.installed.systemd.services.tiaris-nest-console) conflicts before;
        };
      };
      environment.systemPackages = [ pkgs.kbd ];
    };
  };
  testScript = ''
    import json

    start_all()
    setup.wait_for_unit("tiaris-nest-setup-console.service")
    installed.wait_for_unit("tiaris-nest-console.service")
    for node in (setup, installed):
        node.succeed("test $(systemctl show -p LoadState --value autovt@tty1.service) = masked")
        node.fail("systemctl start autovt@tty1.service")
        node.fail("systemctl start getty@tty1.service")
        node.succeed("systemctl restart getty.target")
        node.succeed("chvt 2; chvt 1")
        node.fail("pgrep -af 'agetty.*tty1([[:space:]]|$)'")
        node.fail("grep -aF 'login:' /dev/vcs1")

    setup_status = {
        "schema": "tiaris.nest-setup-status.v1",
        "state": "stopped",
        "updated_at": "2026-09-29T10:00:00Z",
        "boot_mode": "uefi",
        "tiaris_host": "manage.example.test",
        "stop": {
            "reason": "The wired network link went down during the hardware check. Nothing was written to the disk.",
            "disk_untouched": True,
            "steps": ["Connect a network cable to eno1."],
            "check": {"label": "Wired Ethernet", "value": "No link on eno1"},
        },
    }
    setup.succeed("install -d -m0755 /run/tiaris-nest-setup")
    setup.succeed(f"printf '%s' '{json.dumps(setup_status)}' > /run/tiaris-nest-setup/status.json")
    setup.wait_until_succeeds("grep -aF 'tiaris-nest-setup ' /dev/vcs1", timeout=60)

    console_status = {
        "schema": "tiaris.nest-console-status.v1",
        "state": "starting",
        "updated_at": "2026-09-29T10:00:00Z",
        "stage": "services",
        "name": "Console VM Nest",
    }
    installed.succeed("install -d -m0755 /run/tiaris-nest")
    installed.succeed(f"printf '%s' '{json.dumps(console_status)}' > /run/tiaris-nest/console-status.json")
    installed.wait_until_succeeds("grep -aF 'tiaris-nest ' /dev/vcs1", timeout=60)

    # A crashed kiosk is restarted on tty1 and never yields a login prompt.
    for node, name in ((setup, "tiaris-nest-setup-console"), (installed, "tiaris-nest-console")):
        node.succeed(f"systemctl kill --signal=KILL {name}.service")
        node.wait_until_succeeds(f"systemctl is-active {name}.service", timeout=30)
        node.fail("pgrep -af 'agetty.*tty1([[:space:]]|$)'")
  '';
}) { system = "x86_64-linux"; }
