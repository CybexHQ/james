# Nest memory implementation and qualification

The host RSS of an Incus QEMU process includes resident guest pages and is not
Nest's heap. The 2026-09-30 investigation found unbounded log framing and NARInfo
response collection, not a demonstrated persistent idle heap leak.

The implementation keeps the two build workers and four cores per build. New
admission uses available RAM, parent cgroup limits, outstanding reservations and
memory PSI. A waiting worker leaves its job queued. Default reservations are
4 GiB per build plus 2 GiB for serving; they are admission estimates, not kernel
limits. `max_nix_jobs = 0` explicitly selects NixOS's `auto` concurrency. Positive
values cap Nix jobs independently of cores. Existing installer RAM and signed
closure validation requirements are unchanged. Smaller runtime memory settings
require baseline/candidate qualification first.

Status counts use SQL COUNT without manifests. Eviction uses lightweight roots;
integrity checks process one manifest at a time. Cache disk walks coalesce and
reuse estimates for up to 60 seconds, with invalidation after local writes,
failed exports, sweeps and quarantine. The next measurement refreshes expired
estimates, including changes from other processes. Explicit deletions and
integrity checks retain their cross-process lease.

Build log frames are limited to 64 KiB before decoding. Oversized frames are
redacted completely and drained to the next newline. Retained log history is a
separate limit. NARInfo responses stop at 1 MiB while receiving, including
chunked responses. Nix progress state has bounded activity IDs and display names.

Each Nix client uses its own process group. Cancellation, deadlines, output
limits, dropped supervisors and inherited pipes release its resources. Queries
fail closed on excess output; successful verbose cache exports retain diagnostic
tails while draining output. Export retries share one configured build timeout.
No cleanup signals unrelated nix-daemon jobs. Closing a cancelled client's
connection lets the daemon manage its own work and shared dependencies.

Verification hints sequential access and NOREUSE on its own descriptor. Linux
6.3+ avoids promoting cold scan pages; older kernels may ignore the hint. No
DONTNEED or global cache flushing is used. Hash and signature verification still
read and validate all bytes.

Resource evidence uses `tiaris.nest.resources.v1` in
`appliance.local_health.resources` and the local `paths.data_dir/resources.json`
projection. Manage already preserves and exposes this bounded JSON lane in
`appliance_local_health`, so no database migration or protocol negotiation is
needed. It includes guest available/swap/PSI, process RSS/PSS/anonymous/swap,
threads/FDs/start identity, service restarts, and separate Nest and nix-daemon
cgroup current/peak/anon/file/slab/swap/limits/OOM/PSI. Missing measurements are
null, not zero. Detailed process observations refresh every 30 seconds; shared
build phase totals sample every second. Phase peaks are sampled shared totals,
not exclusive per-job allocations or proof of a subsecond maximum. At most 128
phase records are retained in memory and completed job metadata retains its
available phase observations. Kernel cgroup peaks are lifetime values.

## Performance gate

Run the ordinary Rust/security checks first, then compare an unchanged baseline
and candidate on the same disposable NixOS fixture. Record exact binaries,
kernel/Nix versions, RAM/vCPU, build settings, cold/warm build/export duration,
concurrent cache and boot-file throughput and latency, PSI, swap, OOM, service
restarts and post-cycle quiescent process/cgroup counters. Reject reduced RAM or
job limits if any correctness check fails or repeatable throughput/latency
regression exceeds 5%. Do not use production-attached appliances as fixtures.

The 8 GiB runtime and virtio balloon free-page reporting are qualification
variants, not new production defaults. Free-page reporting requires a restart
and returns free pages only. It does not promise to reclaim guest file cache.
The Incus override belongs to the actual balloon device section from the owned
VM's generated QEMU configuration; retain any existing override and restore it
on failed qualification. Never edit the generated QEMU configuration itself.

A 24–48 hour soak must repeat build/export/cancel/update cycles and simultaneous
PXE/cache traffic. Compare quiescent anonymous/PSS, descriptors and descendants
after equivalent cycles, with warm-up separated from trend fitting. Signed
appliance install/update/rollback and full workstation boot acceptance remain
release gates; component benchmarks do not replace them. Production activation
requires the normal qualified, signed release.

## Reproducing component qualification

Build baseline and candidate with the same Rust toolchain and profile in isolated
worktrees. Pass the resulting exact ELF paths to the fixture:

```sh
nix-build nixos-appliance/tests/memory-vm.nix -A driver \
  --argstr baselineBinary /absolute/path/to/baseline \
  --argstr candidateBinary /absolute/path/to/candidate \
  --out-link /absolute/path/to/memory-driver
mkdir -p /absolute/path/to/evidence
/absolute/path/to/memory-driver/bin/nixos-test-driver \
  -o /absolute/path/to/evidence
```

Run the driver as an account with KVM access; it explicitly rejects software
CPU emulation. Its temporary runtime path must fit Unix socket length limits.
Use `--arg memoryMiB 8192` for the smaller-runtime experiment,
`--arg freePageReporting true` for a guest-reporting variant, and
`--arg soakHours 24` for the long component soak. Keep production settings until
the appropriate comparison passes. The component fixture uses genuine Nix
evaluation/build/closure export, cache and iPXE HTTP traffic, running-build
cancellation, descriptor/anonymous-memory checks and restarts between binary
versions. It is deliberately not presented as a signed appliance upgrade or a
full workstation installation.

All build dependencies are already in the fixture's closure; remote substituters
are disabled there to avoid measuring unreachable-network retry delays. Normal
production substitution remains enabled. Results retain per-job phase transitions
and logs, guest pressure/swap, process PSS, cgroup descendants and serving response
checks. During a soak, atomic checkpoints also appear in the driver's shared
exchange directory as `nest-memory-results.checkpoint.json`; preserve them from
the host before cleaning the disposable VM state.

For Incus's own balloon device, `tools/incus-memory-reporting.py` enables/restores
an override only on a stopped disposable VM carrying the supplied
`user.tiaris-memory-owner` UUID. It preserves inherited/local overrides in a
rollback receipt, refuses unowned/running instances and rejects restoration
if somebody has since edited the setting. Restart the owned fixture to exercise
it; the helper never restarts a production VM.

The summary microbenchmark is `cargo run --example cache-summary-benchmark --
seed|legacy|count DATABASE [rows] [manifest_MiB]`. Use separate processes for
`legacy` and `count` to compare process high-water marks. Generated SQLite
fixtures and VM disks are disposable; retain the small JSON receipts, then
remove only the resources created for that run.
