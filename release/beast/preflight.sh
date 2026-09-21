#!/usr/bin/env bash
set -Eeuo pipefail

# Fail before expensive compilation when the minimal image lacks a native
# packaging dependency. This runs in the same unprivileged build container.
for tool in awk cargo cmp cpio curl git gzip jq nix nix-build nix-instantiate nix-store \
  nix-shell openssl python3 rsync sha256sum stat tar \
  unsquashfs xorriso zstd; do
  command -v "$tool" >/dev/null || { echo "Missing release build tool: $tool" >&2; exit 127; }
done

# Exercise the archive operations used by netboot verification through the
# pinned Nix tool environment, without relying on GitHub runner packages.
# shellcheck disable=SC2016 # Expand these variables inside the Nix shell.
nix-shell release/release-tools.nix --pure --run '
  set -euo pipefail
  scratch=$(mktemp -d)
  trap '\''rm -rf -- "$scratch"'\'' EXIT
  cd "$scratch"
  printf "Cybex release archive preflight\n" > expected
  printf "expected\n" | cpio --quiet -o -H newc | zstd --quiet > archive.zst
  zstd --quiet -dc archive.zst | cpio --quiet -i --to-stdout expected > actual
  cmp expected actual
  for tool in jq python3 unsquashfs tar; do command -v "$tool" >/dev/null; done
'
echo 'Isolated release packaging preflight passed'
