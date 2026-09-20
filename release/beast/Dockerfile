# The build never mounts the host Docker socket, Nix store or production data.
FROM rust:1.85.0-bookworm@sha256:16a7f242108de02f10fe4a392991679bafa7694e59f5b40a54d5af1be9b40d03 AS rust
FROM ubuntu:24.04@sha256:496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    apt-utils build-essential ca-certificates curl dpkg-dev git gpgv jq libssl-dev \
    nix-bin openssl pkg-config python3 rsync squashfs-tools ubuntu-keyring xorriso xz-utils zstd \
    && rm -rf /var/lib/apt/lists/*
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=rust /usr/local/cargo /usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/cache/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/cache/home NIX_REMOTE=local
# The unprivileged container is the outer sandbox. Nix uses its own dedicated
# store, never the host daemon/build users or production PostgreSQL UID range.
RUN mkdir -p /etc/nix && printf 'sandbox = false\nbuild-users-group =\nmax-jobs = 4\ncores = 4\nfilter-syscalls = false\n' > /etc/nix/nix.conf
WORKDIR /work
