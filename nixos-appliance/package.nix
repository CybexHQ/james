{ pkgs, repoRoot ? ../., manageOrigin }:
let
  repo = builtins.toPath repoRoot;
  source = pkgs.lib.cleanSourceWith {
    src = repo;
    filter = path: type:
      let relative = pkgs.lib.removePrefix (toString repo + "/") (toString path);
          top = builtins.head (pkgs.lib.splitString "/" relative);
          handoff = "assets/autoexec.ipxe";
      in builtins.elem top [ "Cargo.toml" "Cargo.lock" "build.rs" "src" "migrations" "protocol" "release" "assets" ]
        || relative == handoff || (type == "directory" && pkgs.lib.hasPrefix (relative + "/") handoff);
  };
in pkgs.rustPlatform.buildRustPackage {
  pname = "cybex-james";
  version = (builtins.fromTOML (builtins.readFile (repo + "/Cargo.toml"))).package.version;
  src = source;
  cargoLock.lockFile = source + "/Cargo.lock";
  CYBEX_JAMES_BUILD_MANAGE_ORIGIN = manageOrigin;
  doCheck = false; # Locked Rust tests are a separate release gate.
  postInstall = ''
    install -Dm0444 ${source}/assets/pxe-menu.png $out/share/cybex-james/assets/pxe-menu.png
  '';
  meta = { license = pkgs.lib.licenses.gpl3Only; platforms = [ "x86_64-linux" ]; };
}
