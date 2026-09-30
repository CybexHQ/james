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

Run at least five build/export cycles per binary with simultaneous PXE/cache
traffic and cancellation checks. Compare quiescent anonymous/PSS, descriptors
and descendants after equivalent cycles, with warm-up separated from trend
fitting. A longer soak is optional for investigating a specific growth pattern;
there is no fixed-duration soak requirement for deployment. Signed
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
Use `--arg memoryMiB 8192` for the smaller-runtime experiment and
`--arg freePageReporting true` for a guest-reporting variant. The default fixture
runs five cycles per binary without a timed soak. Keep production settings until
the appropriate comparison passes. The component fixture uses genuine Nix
evaluation/build/closure export, cache and iPXE HTTP traffic, running-build
cancellation, descriptor/anonymous-memory checks and restarts between binary
versions. It is deliberately not presented as a signed appliance upgrade or a
full workstation installation.

The fixture places its HTTP traffic generator in a second, disposable VM with
two vCPUs and 2 GiB RAM. Client-side request/response processing therefore does
not consume the Nest's four vCPUs. The isolated test network exposes only the
fixture's public serving endpoint to that client; it never enrolls in Manage.
Use `--arg candidateFirst true` to reverse binary order when checking variation.
Each cycle queues 32 distinct builds so both workers have a sustained backlog.
Two-job bursts disproportionately measure the phase of the existing two-second
idle queue poll; retain individual execution times and stage transitions as well
as complete batch time when interpreting a result. Earlier two-job fixture runs
must not be combined numerically with this sustained-throughput workload.

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

## Production rollout on 30 September 2026

Signed release [v0.2.45](https://github.com/CybexHQ/james/releases/tag/v0.2.45),
source `fa173c3f830df6d5c40fe6b9f9129fe081a4f4c2`, was installed on
`demo-arnold-james-01` and `james-greenfield-install`. Both committed generation 2
and reported healthy local services and working PXE/cache endpoints. The offline
physical Arnold Nest was excluded. Both VMs retain 18 GiB RAM and four CPUs;
the earlier reduction from 20 GiB saves 4 GiB of combined allocation.

Before deployment, the exact signed 0.2.43 and 0.2.45 appliance binaries each
completed five 32-build cycles. Candidate build duration was +0.2%, serving
throughput -1.0%, and file/cache/iPXE p95 latency +2.8%/+3.2%/+4.3%, within the
existing 5% gate. There were no OOM kills, unexpected service restarts or FD
growth in that comparison. These bounded measurements do not establish
long-term leak freedom or guarantee every workload's performance.

The administrator explicitly instructed: "Stop validation and deploy
immediately." Remaining qualification was cancelled, not recorded as passed.
Native upgrade and automatic rollback qualification had completed; final
fresh-install acceptance and published cold/workstation qualification had not.
The original signed artifacts were published unchanged as a prerelease and
installed directly on the two authorized Nests without an extended stability
wait. This records that specific exception to the normal release gates above.

Automatic appliance updates were temporarily disabled to enforce the two-Nest
scope, then immediately restored after Greenfield completed. Both organizations
reported automation running, with no update or maintenance holds. Manage's
original image and global release selection were restored; the two updated
Nests remain on 0.2.45. No workstation deployment was performed.

The release uses workstation runtime 1.0.87 from development source
`4735edd1e945b4b450283acc8bf829718612cf88`. Bringing these release commits back
to main preserves the published tag and artifact identities; main also retains
its newer console implementation and optional-soak tooling.
