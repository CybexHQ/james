{ pkgs, toplevel, buildMetadata, sourceDateEpoch }:
pkgs.stdenvNoCC.mkDerivation {
  name = "cybex-james-unsigned-system-cache";
  __structuredAttrs = true;
  exportReferencesGraph.closure = [ toplevel ];
  nativeBuildInputs = [ pkgs.python3 pkgs.nix pkgs.zstd ];
  preferLocalBuild = true;
  buildCommand = ''
    python3 ${./export-cache.py} "$NIX_ATTRS_JSON_FILE" ${buildMetadata} "''${outputs[out]}"
  '';
}
