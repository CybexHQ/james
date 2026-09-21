# Small component VM: use the real evaluated console units without building
# an appliance ISO, enrolling a node, or starting any appliance integration.
{ nixpkgs ? builtins.fetchTarball (let pin = import ../../release/nixpkgs.nix; in { inherit (pin) url sha256; }) }:
let
  configurations = import ./console-config.nix { inherit nixpkgs; };
  checks = import ./console-evaluation.nix { inherit nixpkgs; };
in assert builtins.all (value: value) (builtins.attrValues checks);
import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, ... }: {
  name = "cybex-james-tty1-consoles";
  nodes = {
    setup = { ... }: {
      system.stateVersion = "26.05";
      systemd.services = {
        "getty@tty1".enable = configurations.setup.systemd.services."getty@tty1".enable;
        "autovt@tty1".enable = configurations.setup.systemd.services."autovt@tty1".enable;
        cybex-james-setup-console = { inherit (configurations.setup.systemd.services.cybex-james-setup-console) wantedBy serviceConfig; };
      };
      environment.systemPackages = [ pkgs.kbd ];
    };
    installed = { ... }: {
      system.stateVersion = "26.05";
      systemd.services."autovt@tty1".enable = configurations.installed.systemd.services."autovt@tty1".enable;
      systemd.services."getty@tty1".enable = configurations.installed.systemd.services."getty@tty1".enable;
      systemd.services.cybex-james-console = { inherit (configurations.installed.systemd.services.cybex-james-console) wantedBy conflicts before serviceConfig; };
      # No enrollment: exercise the real safe Starting -> Attention screen.
      systemd.services.cybex-james-first-boot.serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.coreutils}/bin/false";
      };
      environment.systemPackages = [ pkgs.kbd ];
    };
  };
  testScript = ''
    start_all()
    setup.wait_for_unit("cybex-james-setup-console.service")
    installed.wait_for_unit("cybex-james-console.service")
    setup.wait_until_succeeds("grep -aF 'Cybex James Setup' /dev/vcs1")
    installed.wait_until_succeeds("grep -aF 'Starting' /dev/vcs1", timeout=30)
    for node in (setup, installed):
        node.succeed("test $(systemctl show -p LoadState --value autovt@tty1.service) = masked")
        node.fail("systemctl start autovt@tty1.service")
        node.fail("systemctl start getty@tty1.service")
        node.succeed("systemctl restart getty.target")
        node.succeed("chvt 2; chvt 1")
        node.fail("pgrep -af 'agetty.*tty1([[:space:]]|$)'")
        node.fail("grep -aF 'login:' /dev/vcs1")
    # Model a late framebuffer reset after both screens have already rendered.
    for node in (setup, installed):
        node.succeed("printf '\\033c' > /dev/tty1")
    setup.wait_until_succeeds("grep -aF 'Continue in Cybex Manage.' /dev/vcs1", timeout=30)
    installed.wait_until_succeeds("grep -aF 'Starting' /dev/vcs1", timeout=30)
    installed.fail("systemctl start cybex-james-first-boot.service")
    installed.wait_until_succeeds("grep -aF 'Attention needed' /dev/vcs1")
    installed.succeed("grep -aF 'Managed by Cybex Manage' /dev/vcs1")
  '';
}) { system = "x86_64-linux"; }
