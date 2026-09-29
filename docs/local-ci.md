# Local Nest CI

Buildbot on The Beast runs ordinary main and PR checks in disposable Incus VMs.
GitHub remains the source/PR host and displays the real `CI` commit status.

Use `tiaris-ci run james --revision FULL_SHA` to retry main, or add
`--ref refs/pull/NUMBER/head` for a PR head. The dashboard is
<http://100.80.13.18:18090/> on Tailscale. The controller and runbook live in
`CybexHQ/development` under `deploy/ci/` and `docs/local-ci.md`.

The suite retains Rust formatting/tests/clippy, the ignored Python-packer/Rust
integration, shell/Python/Nix contracts, and the networked dependency audit. The
existing MySQL advisory exception is accepted only while `sqlx-mysql` is inactive.
Compiler and package caches persist separately for main and reviews; repository
code receives no host secrets and cannot reach private host or lab networks.

Version-tag release orchestration remains in GitHub because signed proofs bind
run/attempt/artifact identities, protected environment approval, immutable Releases
and attestations. All jobs execute on the existing local `cybex-james-lab` runner;
no hosted compute remains. Ordinary PR/main code never reaches that signing runner.
Warm and cold release qualification, signing, publication and explicit promotion
remain required. This migration does not publish a new appliance or runtime.

Digital Brain no longer drives coordinated releases. The local `tiaris-release`
command in development prepares, reviews and explicitly approves immutable
Manage/Nest/workstation candidates. Production is never deployed by ordinary CI.
