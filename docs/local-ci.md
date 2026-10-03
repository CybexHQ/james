# Local Nest CI

Buildbot on The Beast runs ordinary main and PR checks in disposable Incus VMs.
GitHub remains the source/PR host and displays the real `CI` commit status.

Use `ci-platform run tiaris-james --job fast --revision FULL_SHA` to retry main,
or add `--ref refs/pull/NUMBER/head` for a PR head. The dashboard is
<http://100.80.13.18:18091/> on Tailscale. Shared CI source lives in
`/home/john/Code/ci-platform`; the installed controller lives in `/opt/ci-platform`.
See the shared platform's `README.md` and `docs/acceptance.md` for its runbook.

The suite retains Rust formatting/tests/clippy, the ignored Python-packer/Rust
integration, the native provisioning TLS regression, shell/Python/Nix contracts,
and the networked dependency audit. The existing MySQL advisory exception is
accepted only while `sqlx-mysql` is inactive.
Compiler and package caches persist separately for main and reviews; repository
code receives no host secrets and cannot reach private host or lab networks.

Linux Rust tests require Python 3.11+ and the OpenSSL command-line tools (1.1.1 or
newer), supplied by the CI template. Standard `cargo test --locked` runs the native
TLS parent in both `fast` and `nest-release`. Only its private subprocess test stays
ignored; the parent invokes it with isolated trust settings and fresh loopback
fixtures.

Version-tag release orchestration remains in GitHub because signed proofs bind
run/attempt/artifact identities, protected environment approval, immutable Releases
and attestations. All jobs execute on the existing local `cybex-james-lab` runner;
no hosted compute remains. Ordinary PR/main code never reaches that signing runner.
Warm and cold release qualification, signing, publication and explicit promotion
remain required. This migration does not publish a new appliance or runtime.

Digital Brain no longer drives coordinated releases. The local `tiaris-release`
command in development prepares, reviews and explicitly approves immutable
Manage/Nest/workstation candidates. Production is never deployed by ordinary CI.

The former Digital Brain source-access dispatch is retired. Its use of `main`
was rejected by the tag-only production environment. Local preparation checks
source availability; the tagged producer still checks out the exact development
commit with its protected read-only key before any build/signing step. Environment
restrictions and signing secrets remain unchanged.
