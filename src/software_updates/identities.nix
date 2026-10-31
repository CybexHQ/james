# Commit identities of the Nest source-build preflight, evaluated at one
# nixpkgs commit. Every attribute is the one whose 74cc63f value is compiled
# into Nest (`COMMIT_IDENTITIES` in src/build/profile.rs); evaluated at 74cc63f
# this expression reproduces those paths exactly. Evaluation only: nothing is
# built and import-from-derivation is disabled by the caller.
{ nixpkgs, system ? "x86_64-linux" }:
let
  pkgs = import nixpkgs { inherit system; config = { }; overlays = [ ]; };
  lib = pkgs.lib;
  plain = value: builtins.unsafeDiscardStringContext value;
  out = drv: output: {
    path = plain (lib.getOutput output drv).outPath;
    drv = plain drv.drvPath;
  };
  sub = drv: output: suffix: let o = out drv output; in o // { path = o.path + suffix; };
  # buildEnv's command is `<perl>/bin/perl -w <builder.pl>`; both inputs come
  # from its string context.
  linkFarmCommand = (pkgs.buildEnv { name = "tiaris-identity"; paths = [ ]; }).drvAttrs.buildCommand;
  linkFarmWords = lib.splitString " " (plain (lib.head (lib.splitString "\n" linkFarmCommand)));
  linkFarmInput = suffix: lib.head (lib.filter (path: lib.hasSuffix suffix path)
    (builtins.attrNames (builtins.getContext linkFarmCommand)));
  systemd = pkgs.systemd;
  hash = path: builtins.hashFile "sha256" (nixpkgs + path);
in
{
  release = lib.trivial.release;
  kernel_version = pkgs.linuxPackages.kernel.version;
  files = {
    "source-stdenv.sh" = hash "/pkgs/stdenv/generic/source-stdenv.sh";
    "default-builder.sh" = hash "/pkgs/stdenv/generic/default-builder.sh";
    "substitute.sh" = hash "/pkgs/build-support/substitute/substitute.sh";
    "wrapper.c" = hash "/nixos/modules/security/wrappers/wrapper.c";
    # replaceVars substitutes only @storeDir@ in the reviewed builder.
    "builder.pl" = builtins.hashString "sha256" (builtins.replaceStrings [ "@storeDir@" ]
      [ builtins.storeDir ] (builtins.readFile (nixpkgs + "/pkgs/build-support/buildenv/builder.pl")));
  };
  identities = {
    "stdenv.shell" = sub pkgs.bashNonInteractive "out" "/bin/bash";
    stdenvNoCC = out pkgs.stdenvNoCC "out";
    stdenv = out pkgs.stdenv "out";
    "pkgsStatic.stdenv" = out pkgs.pkgsStatic.stdenv "out";
    "substitute.sh" = { path = "${nixpkgs + "/pkgs/build-support/substitute/substitute.sh"}"; };
    "buildEnv builder.pl" = { path = lib.elemAt linkFarmWords 2; drv = linkFarmInput "-builder.pl.drv"; };
    "buildEnv perl" = { path = lib.elemAt linkFarmWords 0; drv = linkFarmInput "-perl-${pkgs.buildPackages.perl.version}.drv"; };
    dbus = out pkgs.dbus "out";
    "libxslt.bin" = out pkgs.libxslt "bin";
    findXMLCatalogs = out pkgs.findXMLCatalogs "out";
    systemdMinimal = out pkgs.systemdMinimal "out";
    remarshal = out pkgs.remarshal "out";
    makeInitrdNG = out pkgs.makeInitrdNGTool "out";
    cpio = out pkgs.cpio "out";
    installShellFiles = out pkgs.installShellFiles "out";
    makeBinaryWrapper = out pkgs.makeBinaryWrapper "out";
    "stdenv.cc" = out pkgs.stdenv.cc "out";
    "ibus.dev" = out pkgs.ibus "dev";
    makeShellWrapper = out pkgs.makeShellWrapper "out";
    # NixOS' i18n.inputMethod.ibus with no engines configured.
    "ibus-with-plugins" = out (pkgs.ibus-with-plugins.override { plugins = [ ]; }) "out";
    "gtk3.dev" = out pkgs.gtk3 "dev";
    "xorg.lndir" = out pkgs.lndir "out";
    "jq.dev" = out pkgs.jq "dev";
    dconf = out pkgs.dconf "out";
    "makeShellWrapper setup hook" = sub pkgs.makeShellWrapper "out" "/nix-support/setup-hook";
    "texinfo install-info" = sub pkgs.texinfo "out" "/bin/install-info";
    "shared-mime-info update-mime-database" = sub pkgs.shared-mime-info "out" "/bin/update-mime-database";
    "desktop-file-utils update-desktop-database" = sub pkgs.desktop-file-utils "out" "/bin/update-desktop-database";
    "gtk3 gtk-update-icon-cache" = sub pkgs.gtk3 "out" "/bin/gtk-update-icon-cache";
    "desktop-file-utils desktop-file-validate" = sub pkgs.desktop-file-utils "out" "/bin/desktop-file-validate";
    coreutils = out pkgs.coreutils "out";
    logrotate = sub pkgs.logrotate "out" "/sbin/logrotate";
    nix = sub pkgs.nix "out" "/bin/nix";
    # nixos/modules/system/boot/systemd/coredump.nix
    "systemd coredump sysctl" = sub systemd "out" "/example/sysctl.d/50-coredump.conf";
    "systemd coredump substitution target" =
      out (pkgs.symlinkJoin { name = "systemd"; paths = [ systemd ]; }) "out";
    "pkgsStatic.linuxHeaders" = out pkgs.pkgsStatic.linuxHeaders "out";
    # nixos/modules/security/wrappers/default.nix
    "security wrapper unsecvars" = out (lib.overrideDerivation (pkgs.srcOnly pkgs.glibc) (
        { name, ... }:
        {
          name = "${name}-unsecvars";
          installPhase = ''
            mkdir $out
            cp sysdeps/generic/unsecvars.h $out
          '';
        }
      )) "out";
    xkbvalidate = out pkgs.xkbvalidate "out";
    xkeyboard-config = sub pkgs.xkeyboard_config "out" "/etc/X11/xkb";
    nixos-init = out pkgs.nixos-init "out";
  };
}
