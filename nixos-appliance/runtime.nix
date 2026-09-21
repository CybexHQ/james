{ pkgs, package, udpcast }:
let
  source = pkgs.lib.cleanSourceWith {
    src = ./runtime;
    filter = path: type: builtins.baseNameOf path != "__pycache__" && !(pkgs.lib.hasSuffix ".pyc" path);
  };
  commands = [ "coreutils" "curl" "jq" "sqlite" "util-linux" "iproute2" "nftables" "systemd" "findutils" "gawk" "gnugrep" "gnused" "procps" "openssh" "nix" "dnsmasq" ];
  path = pkgs.lib.makeBinPath ((map (name: pkgs.${name}) commands) ++ [ pkgs.python3 package udpcast ]);
in pkgs.runCommand "cybex-james-runtime" { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
  mkdir -p $out/lib/cybex-james $out/bin
  find ${source} -maxdepth 1 -type f -exec cp {} $out/lib/cybex-james/ \;
  chmod 0755 $out/lib/cybex-james/cybex-james-*
  for file in $out/lib/cybex-james/cybex-james-*; do
    substituteInPlace "$file" --replace '#!/usr/bin/env python3' '#!${pkgs.python3}/bin/python3' --replace '#!/usr/bin/python3' '#!${pkgs.python3}/bin/python3' --replace '#!/usr/bin/env bash' '#!${pkgs.bash}/bin/bash'
    wrapProgram "$file" --prefix PATH : ${path}
    ln -s "$file" "$out/bin/$(basename "$file")"
  done
''
