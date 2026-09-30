# Component performance/leak fixture. Does not enroll or contact Manage.
# Arguments are exact locally built baseline/candidate ELF files, never live VMs.
{ baselineBinary, candidateBinary, memoryMiB ? 18432, freePageReporting ? false, cycles ? 5, soakHours ? 0, candidateFirst ? false }:
let
  pin = import ../../release/nixpkgs.nix;
  nixpkgs = builtins.fetchTarball { inherit (pin) url sha256; };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  wrap = name: binary: pkgs.runCommand name { nativeBuildInputs = [ pkgs.patchelf ]; } ''
    mkdir -p $out/bin
    cp ${builtins.path { path = builtins.toPath binary; name = name + "-input"; }} $out/bin/tiaris-nest
    chmod 0755 $out/bin/tiaris-nest
    patchelf --set-interpreter ${pkgs.stdenv.cc.bintools.dynamicLinker} \
      --set-rpath ${pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib pkgs.glibc ]} $out/bin/tiaris-nest
  '';
  baseline = wrap "nest-memory-baseline" baselineBinary;
  candidate = wrap "nest-memory-candidate" candidateBinary;
  flake = pkgs.writeText "memory-flake.nix" ''
    {
      inputs.nixpkgs = { url = "path:${nixpkgs}"; flake = false; };
      outputs = { self, nixpkgs }: let
        pkgs = import nixpkgs { system = "x86_64-linux"; };
        # Real Nix evaluation, daemon builders, closure hashing, signing and
        # zstd export. A repeated nonce prevents a build-result cache hit.
        make = name: pkgs.runCommand ("nest-memory-" + name + "-NONCE") {} "mkdir -p $out; head -c 33554432 /dev/zero > $out/payload; ln -s ${pkgs.bash}/bin/bash $out/bash";
      in { packages.x86_64-linux = pkgs.lib.genAttrs
        (builtins.genList (index: "target-" + toString index) 32) make; };
    }
  '';
in import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ ... }: {
  name = "nest-memory-${toString memoryMiB}-${if freePageReporting then "reporting" else "baseline"}";
  nodes.machine = { lib, ... }: {
    system.stateVersion = "26.05";
    networking.firewall.allowedTCPPorts = [ 8080 ];
    virtualisation = {
      memorySize = memoryMiB; cores = 4; diskSize = 65536;
      qemu.options = [ "-no-user-config" ] ++ pkgs.lib.optional freePageReporting "-global virtio-balloon-pci.free-page-reporting=on";
    };
    swapDevices = [ { device = "/var/swapfile"; size = 8192; } ];
    users.groups.nest = {};
    users.users.nest = { isSystemUser = true; group = "nest"; home = "/var/lib/nest-memory"; createHome = true; };
    nix.settings = {
      experimental-features = [ "nix-command" "flakes" ];
      allowed-users = [ "root" "nest" ]; trusted-users = [ "root" ];
      sandbox = true; max-jobs = "auto";
      # All fixture dependencies are supplied by its closure. An unreachable
      # public substituter measures DNS/retry backoff, not build performance.
      # Production substitution settings are deliberately unchanged.
      substituters = lib.mkForce [];
    };
    systemd.services.nix-daemon.serviceConfig.MemoryAccounting = true;
    systemd.services.nest-memory = {
      path = [ pkgs.nix pkgs.coreutils pkgs.systemd ];
      environment = { NIX_REMOTE = "daemon"; };
      serviceConfig = { User = "nest"; Group = "nest"; MemoryAccounting = true; ExecStart = "/var/lib/nest-memory/active-nest --config /var/lib/nest-memory/config.toml serve"; Restart = "no"; KillMode = "control-group"; TimeoutStopSec = 20; };
    };
    environment.systemPackages = [ pkgs.python3 pkgs.curl pkgs.sqlite pkgs.nix pkgs.coreutils ];
    environment.etc."nest-memory-fixture".text = "disposable component fixture\n";
    environment.etc."nest-memory-baseline".source = baseline + "/bin/tiaris-nest";
    environment.etc."nest-memory-candidate".source = candidate + "/bin/tiaris-nest";
    environment.etc."nest-memory-flake".source = flake;
    environment.etc."nest-memory-qualification.py".source = ../../tools/qualify-memory.py;
  };
  nodes.traffic = { ... }: {
    system.stateVersion = "26.05";
    virtualisation = { memorySize = 2048; cores = 2; qemu.options = [ "-no-user-config" ]; };
    environment.etc."nest-memory-fixture".text = "disposable traffic fixture\n";
    environment.etc."nest-memory-traffic.py".source = ../../tools/memory-traffic.py;
    systemd.services.nest-memory-traffic = {
      wantedBy = [ "multi-user.target" ]; after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = { ExecStart = "${pkgs.python3}/bin/python3 /etc/nest-memory-traffic.py"; Restart = "no"; };
    };
  };
  globalTimeout = 3600 + soakHours * 3600;
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    traffic.wait_for_unit("nest-memory-traffic.service")
    machine.succeed("test $(systemd-detect-virt) = kvm")
    traffic.succeed("test $(systemd-detect-virt) = kvm")
    status, output = machine.execute("python3 /etc/nest-memory-qualification.py --external-traffic --cycles ${toString cycles} --soak-hours ${toString soakHours} ${pkgs.lib.optionalString candidateFirst "--candidate-first"} --output /var/lib/nest-memory-results.json", timeout=${toString (3600 + soakHours * 3600)})
    print(output)
    machine.copy_from_machine("/var/lib/nest-memory-results.json", ".")
    machine.copy_from_machine("/var/lib/nest-memory-results.checkpoint.json", ".")
    assert status == 0, "memory component qualification failed; inspect the retained evidence"
  '';
}) { system = "x86_64-linux"; }
