//! Read-only Linux resource accounting. Guest memory, process allocations and
//! daemon-side Nix builders are separate observations, never added together.
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

#[cfg(test)]
const GIB: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Pressure {
    pub some_avg10: Option<f64>,
    pub full_avg10: Option<f64>,
    pub some_total_us: Option<u64>,
    pub full_total_us: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Cgroup {
    pub path: String,
    pub current_bytes: Option<u64>,
    pub peak_bytes: Option<u64>,
    pub anonymous_bytes: Option<u64>,
    pub file_bytes: Option<u64>,
    pub slab_bytes: Option<u64>,
    pub swap_current_bytes: Option<u64>,
    pub effective_max_bytes: Option<u64>,
    pub effective_high_bytes: Option<u64>,
    pub effective_swap_max_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub oom_kills: Option<u64>,
    pub pressure: Pressure,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    pub schema: &'static str,
    pub sampled_at: String,
    pub process_id: u32,
    pub process_start_ticks: Option<u64>,
    pub process_rss_bytes: Option<u64>,
    pub process_pss_bytes: Option<u64>,
    pub process_anonymous_bytes: Option<u64>,
    pub process_swap_bytes: Option<u64>,
    pub process_threads: Option<u64>,
    pub process_fds: Option<u64>,
    pub service_restarts: Option<u64>,
    pub guest_total_bytes: Option<u64>,
    pub guest_available_bytes: Option<u64>,
    pub guest_swap_total_bytes: Option<u64>,
    pub guest_swap_used_bytes: Option<u64>,
    pub guest_pressure: Pressure,
    pub service_cgroup: Option<Cgroup>,
    pub nix_daemon_cgroup: Option<Cgroup>,
    /// Sampled shared totals during this job/phase, not exclusive job usage.
    pub build_phase_peaks: Vec<PhasePeak>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PhasePeak {
    pub job_id: i64,
    pub phase: String,
    pub samples: u64,
    pub process_rss_bytes: Option<u64>,
    pub service_current_bytes: Option<u64>,
    pub nix_daemon_current_bytes: Option<u64>,
    pub guest_used_bytes: Option<u64>,
}

#[derive(Clone, Debug)]
struct CgroupLocation {
    directory: PathBuf,
    mount: PathBuf,
}

fn unescape_mount(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn locate(cgroup: &str, mounts: &str) -> Option<CgroupLocation> {
    let relative = cgroup.lines().find_map(|line| line.strip_prefix("0::"))?;
    let group = Path::new(relative);
    if !group.is_absolute()
        || group
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return None;
    }
    mounts
        .lines()
        .filter_map(|line| {
            let (prefix, filesystem) = line.split_once(" - ")?;
            if filesystem.split_whitespace().next()? != "cgroup2" {
                return None;
            }
            let fields = prefix.split_whitespace().collect::<Vec<_>>();
            let root = PathBuf::from(unescape_mount(fields.get(3)?));
            let mount = PathBuf::from(unescape_mount(fields.get(4)?));
            let suffix = group.strip_prefix(&root).ok()?;
            Some((
                root.components().count(),
                CgroupLocation {
                    directory: mount.join(suffix),
                    mount,
                },
            ))
        })
        .max_by_key(|(depth, _)| *depth)
        .map(|(_, location)| location)
}

fn self_cgroup() -> Option<CgroupLocation> {
    locate(
        &fs::read_to_string("/proc/self/cgroup").ok()?,
        &fs::read_to_string("/proc/self/mountinfo").ok()?,
    )
}

fn number(path: impl AsRef<Path>) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}
fn field(raw: &str, name: &str) -> Option<u64> {
    raw.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next()?.trim_end_matches(':') == name)
            .then(|| words.next()?.parse().ok())
            .flatten()
    })
}
fn bytes(raw: &str, name: &str) -> Option<u64> {
    field(raw, name)?.checked_mul(1024)
}
fn minimum(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
fn pressure(raw: &str) -> Pressure {
    let metric = |class: &str, key: &str| -> Option<&str> {
        raw.lines()
            .find(|line| line.starts_with(&format!("{class} ")))?
            .split_whitespace()
            .find_map(|word| word.strip_prefix(key))
    };
    let avg = |class| {
        metric(class, "avg10=")?
            .parse::<f64>()
            .ok()
            .filter(|n| n.is_finite() && (0.0..=100.0).contains(n))
    };
    Pressure {
        some_avg10: avg("some"),
        full_avg10: avg("full"),
        some_total_us: metric("some", "total=").and_then(|v| v.parse().ok()),
        full_total_us: metric("full", "total=").and_then(|v| v.parse().ok()),
    }
}

fn cgroup_stats(location: &CgroupLocation) -> Cgroup {
    let dir = &location.directory;
    let stat = fs::read_to_string(dir.join("memory.stat")).unwrap_or_default();
    let mut out = Cgroup {
        path: dir.display().to_string(),
        current_bytes: number(dir.join("memory.current")),
        peak_bytes: number(dir.join("memory.peak")),
        anonymous_bytes: field(&stat, "anon"),
        file_bytes: field(&stat, "file"),
        slab_bytes: field(&stat, "slab"),
        swap_current_bytes: number(dir.join("memory.swap.current")),
        oom_kills: fs::read_to_string(dir.join("memory.events"))
            .ok()
            .and_then(|s| field(&s, "oom_kill")),
        pressure: pressure(&fs::read_to_string(dir.join("memory.pressure")).unwrap_or_default()),
        ..Default::default()
    };
    // A service's own limit may say 'max' while a parent slice/container is bounded.
    for parent in dir
        .ancestors()
        .take_while(|parent| parent.starts_with(&location.mount))
    {
        let max = number(parent.join("memory.max"));
        let high = number(parent.join("memory.high"));
        out.effective_max_bytes = minimum(out.effective_max_bytes, max);
        out.effective_high_bytes = minimum(out.effective_high_bytes, high);
        out.effective_swap_max_bytes = minimum(
            out.effective_swap_max_bytes,
            number(parent.join("memory.swap.max")),
        );
        if let (Some(limit), Some(current)) =
            (minimum(max, high), number(parent.join("memory.current")))
        {
            let stat = fs::read_to_string(parent.join("memory.stat")).unwrap_or_default();
            // Inactive clean file pages are reclaimable; do not charge hot serving cache twice.
            let reclaimable = field(&stat, "inactive_file")
                .unwrap_or(0)
                .saturating_sub(field(&stat, "file_dirty").unwrap_or(0))
                .saturating_sub(field(&stat, "file_writeback").unwrap_or(0));
            out.available_bytes = minimum(
                out.available_bytes,
                Some(limit.saturating_sub(current.saturating_sub(reclaimable))),
            );
        }
    }
    out
}

fn kernel_memory() -> Option<(u64, u64, u64, u64)> {
    let mut info = std::mem::MaybeUninit::<libc::sysinfo>::zeroed();
    // sysinfo remains available when a hardened service hides /proc/meminfo.
    if unsafe { libc::sysinfo(info.as_mut_ptr()) } != 0 {
        return None;
    }
    let info = unsafe { info.assume_init() };
    let unit = u64::from(info.mem_unit);
    Some((
        info.totalram.saturating_mul(unit),
        info.freeram
            .saturating_add(info.bufferram)
            .saturating_mul(unit),
        info.totalswap.saturating_mul(unit),
        info.freeswap.saturating_mul(unit),
    ))
}

pub(crate) fn oom_kills() -> u64 {
    let snapshot = memory_snapshot();
    snapshot
        .service_cgroup
        .and_then(|s| s.oom_kills)
        .unwrap_or(0)
        .saturating_add(
            snapshot
                .nix_daemon_cgroup
                .and_then(|s| s.oom_kills)
                .unwrap_or(0),
        )
}

fn memory_snapshot() -> Snapshot {
    let mem = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let fallback = kernel_memory();
    let service = self_cgroup();
    // The NixOS appliance declares this unit explicitly. It is a sibling, not
    // a child of Nest: a Nest-only memory limit cannot contain its builders.
    let daemon = service
        .as_ref()
        .map(|s| CgroupLocation {
            directory: s.mount.join("system.slice/nix-daemon.service"),
            mount: s.mount.clone(),
        })
        .filter(|s| s.directory.join("memory.current").exists());
    let swap_total = bytes(&mem, "SwapTotal").or_else(|| fallback.map(|v| v.2));
    Snapshot {
        schema: "tiaris.nest.resources.v1",
        sampled_at: chrono::Utc::now().to_rfc3339(),
        process_id: std::process::id(),
        guest_total_bytes: bytes(&mem, "MemTotal").or_else(|| fallback.map(|v| v.0)),
        guest_available_bytes: bytes(&mem, "MemAvailable").or_else(|| fallback.map(|v| v.1)),
        guest_swap_total_bytes: swap_total,
        guest_swap_used_bytes: swap_total
            .zip(bytes(&mem, "SwapFree").or_else(|| fallback.map(|v| v.3)))
            .map(|(t, f)| t.saturating_sub(f)),
        guest_pressure: pressure(&fs::read_to_string("/proc/pressure/memory").unwrap_or_default()),
        service_cgroup: service.as_ref().map(cgroup_stats),
        nix_daemon_cgroup: daemon.as_ref().map(cgroup_stats),
        ..Default::default()
    }
}

pub fn sample() -> Snapshot {
    let mut sample = memory_snapshot();
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    sample.process_rss_bytes = bytes(&status, "VmRSS");
    sample.process_anonymous_bytes = bytes(&status, "RssAnon");
    sample.process_swap_bytes = bytes(&status, "VmSwap");
    sample.process_threads = field(&status, "Threads");
    sample.process_fds = fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count().saturating_sub(1) as u64);
    sample.process_pss_bytes = fs::read_to_string("/proc/self/smaps_rollup")
        .ok()
        .and_then(|s| bytes(&s, "Pss"));
    sample.process_start_ticks = fs::read_to_string("/proc/self/stat").ok().and_then(|s| {
        s.rsplit_once(") ")
            .and_then(|(_, fields)| fields.split_whitespace().nth(19))
            .and_then(|v| v.parse().ok())
    });
    sample
}

static LATEST: OnceLock<Mutex<Snapshot>> = OnceLock::new();
static PHASES: OnceLock<Mutex<BTreeMap<(i64, String), PhasePeak>>> = OnceLock::new();
pub fn latest() -> Snapshot {
    LATEST
        .get_or_init(|| Mutex::new(sample()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}
pub(crate) fn job_peaks(id: i64) -> Vec<PhasePeak> {
    PHASES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .filter(|p| p.job_id == id)
        .cloned()
        .collect()
}

pub fn spawn(pool: sqlx::SqlitePool, evidence_path: PathBuf) {
    tokio::spawn(async move {
        let mut last_full = Instant::now() - Duration::from_secs(30);
        let mut restarts = None;
        loop {
            let full_sample = last_full.elapsed() >= Duration::from_secs(30);
            let mut snapshot = if last_full.elapsed() >= Duration::from_secs(30) {
                last_full = Instant::now();
                let mut cmd = tokio::process::Command::new("systemctl");
                cmd.args([
                    "show",
                    "tiaris-nest.service",
                    "--property=NRestarts",
                    "--value",
                ]);
                restarts = crate::subprocess::run_bounded_command(
                    cmd,
                    Duration::from_secs(2),
                    64,
                    1024,
                    "service restart count",
                )
                .await
                .ok()
                .filter(|out| out.status.success())
                .and_then(|out| String::from_utf8(out.stdout).ok())
                .and_then(|s| s.trim().parse().ok());
                tokio::task::spawn_blocking(sample)
                    .await
                    .unwrap_or_default()
            } else {
                // smaps_rollup is sampled only once per reporting interval.
                let mut next = memory_snapshot();
                let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
                let previous = latest();
                next.process_rss_bytes = bytes(&status, "VmRSS");
                next.process_anonymous_bytes = bytes(&status, "RssAnon");
                next.process_swap_bytes = bytes(&status, "VmSwap");
                next.process_threads = field(&status, "Threads");
                next.process_fds = previous.process_fds;
                next.process_pss_bytes = previous.process_pss_bytes;
                next.process_start_ticks = previous.process_start_ticks;
                next
            };
            snapshot.service_restarts = restarts;
            if let Ok(active) = sqlx::query_as::<_, (i64, Option<String>)>(
                "SELECT id, progress_stage FROM nest_build_jobs WHERE status = 'running' ORDER BY id DESC LIMIT 16")
                .fetch_all(&pool).await {
                let mut phases = PHASES.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
                for (job_id, stage) in active {
                    let phase = stage.unwrap_or_else(|| "preparing".into());
                    let peak = phases.entry((job_id, phase.clone())).or_insert_with(|| PhasePeak {job_id, phase, ..Default::default()});
                    peak.samples += 1;
                    peak.process_rss_bytes = peak.process_rss_bytes.max(snapshot.process_rss_bytes);
                    peak.service_current_bytes = peak.service_current_bytes.max(snapshot.service_cgroup.as_ref().and_then(|c| c.current_bytes));
                    peak.nix_daemon_current_bytes = peak.nix_daemon_current_bytes.max(snapshot.nix_daemon_cgroup.as_ref().and_then(|c| c.current_bytes));
                    peak.guest_used_bytes = peak.guest_used_bytes.max(snapshot.guest_total_bytes.zip(snapshot.guest_available_bytes).map(|(total, available)| total.saturating_sub(available)));
                }
                while phases.len() > 128 { phases.pop_first(); }
                snapshot.build_phase_peaks = phases.values().cloned().collect();
            }
            if full_sample {
                if let Ok(bytes) = serde_json::to_vec(&snapshot) {
                    let path = evidence_path.clone();
                    if !matches!(
                        tokio::task::spawn_blocking(move || {
                            crate::public_status::write_public_json(&path, &bytes, 65536)
                        })
                        .await,
                        Ok(Ok(()))
                    ) {
                        tracing::warn!("could not write Nest resource diagnostics");
                    }
                }
            }
            *LATEST
                .get_or_init(|| Mutex::new(Snapshot::default()))
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = snapshot;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

pub(crate) fn capacity() -> Option<(u64, u64)> {
    let snapshot = memory_snapshot();
    let mut ram = snapshot.guest_total_bytes;
    let mut swap = snapshot.guest_swap_total_bytes;
    for cgroup in [snapshot.service_cgroup, snapshot.nix_daemon_cgroup]
        .into_iter()
        .flatten()
    {
        ram = minimum(ram, cgroup.effective_max_bytes);
        swap = minimum(swap, cgroup.effective_swap_max_bytes);
    }
    Some((ram?, swap.unwrap_or(0)))
}

#[derive(Default)]
pub(crate) struct Admission {
    state: Mutex<Reservations>,
}
#[derive(Default)]
struct Reservations {
    count: usize,
    bytes: u64,
    baseline_used: u64,
}
pub(crate) struct Lease<'a> {
    admission: &'a Admission,
    bytes: u64,
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state.count = state.count.saturating_sub(1);
        state.bytes = state.bytes.saturating_sub(self.bytes);
    }
}
impl Admission {
    pub(crate) fn try_acquire(&self, config: &crate::config::BuildConfig) -> Option<Lease<'_>> {
        self.try_sample(config, &memory_snapshot())
    }
    fn try_sample(
        &self,
        config: &crate::config::BuildConfig,
        snapshot: &Snapshot,
    ) -> Option<Lease<'_>> {
        let host_available = snapshot.guest_available_bytes?;
        let used = snapshot.guest_total_bytes?.saturating_sub(host_available);
        let mut available = host_available;
        let mut full_pressure = snapshot.guest_pressure.full_avg10.unwrap_or(0.0);
        for cgroup in [&snapshot.service_cgroup, &snapshot.nix_daemon_cgroup]
            .into_iter()
            .flatten()
        {
            available = available.min(cgroup.available_bytes.unwrap_or(u64::MAX));
            full_pressure = full_pressure.max(cgroup.pressure.full_avg10.unwrap_or(0.0));
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.count >= config.max_concurrent_builds {
            return None;
        }
        let mut capacity = snapshot.guest_total_bytes;
        let mut swap = snapshot.guest_swap_total_bytes;
        for cgroup in [&snapshot.service_cgroup, &snapshot.nix_daemon_cgroup]
            .into_iter()
            .flatten()
        {
            capacity = minimum(capacity, cgroup.effective_max_bytes);
            swap = minimum(swap, cgroup.effective_swap_max_bytes);
        }
        // Claim intrinsically unsupported jobs so the existing capacity check
        // reports its explicit failure. Do not leave them queued forever behind
        // a budget they can never satisfy. They execute no Nix command.
        if capacity
            .is_some_and(|bytes| bytes.saturating_add(1024 * 1024) < config.minimum_memory_bytes)
            || swap
                .is_some_and(|bytes| bytes.saturating_add(1024 * 1024) < config.minimum_swap_bytes)
        {
            state.count += 1;
            return Some(Lease {
                admission: self,
                bytes: 0,
            });
        }
        if state.count == 0 {
            state.baseline_used = used;
        }
        // Only charge the unconsumed portion of existing reservations. Already
        // resident builders are reflected in MemAvailable/cgroup.current.
        let unconsumed = state
            .bytes
            .saturating_sub(used.saturating_sub(state.baseline_used));
        let required = config
            .memory_per_build_bytes
            .saturating_add(config.serving_memory_reserve_bytes);
        if state.count >= config.max_concurrent_builds
            || full_pressure >= config.memory_pressure_full_percent as f64
            || available.saturating_sub(unconsumed) < required
        {
            return None;
        }
        state.count += 1;
        state.bytes = state.bytes.saturating_add(config.memory_per_build_bytes);
        Some(Lease {
            admission: self,
            bytes: config.memory_per_build_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolves_nested_cgroup_mount_and_rejects_escape() {
        let mount = "33 24 0:29 /tenant /sys/fs/cgroup rw - cgroup2 cgroup2 rw";
        let loc = locate("0::/tenant/system.slice/nest.service\n", mount).unwrap();
        assert_eq!(
            loc.directory,
            Path::new("/sys/fs/cgroup/system.slice/nest.service")
        );
        assert!(locate("0::/../../escape", mount).is_none());
    }
    #[test]
    fn preserves_concurrency_and_does_not_double_charge_resident_builds() {
        let config = crate::config::BuildConfig::default();
        let admission = Admission::default();
        let mut sample = Snapshot {
            guest_total_bytes: Some(18 * GIB),
            guest_available_bytes: Some(16 * GIB),
            ..Default::default()
        };
        let first = admission.try_sample(&config, &sample).unwrap();
        sample.guest_available_bytes = Some(12 * GIB);
        let second = admission.try_sample(&config, &sample).unwrap();
        assert!(admission.try_sample(&config, &sample).is_none());
        drop(second);
        drop(first);
        sample.guest_pressure.full_avg10 = Some(10.0);
        assert!(admission.try_sample(&config, &sample).is_none());
        sample.guest_pressure.full_avg10 = Some(0.0);
        sample.guest_available_bytes = Some(2 * GIB);
        assert!(admission.try_sample(&config, &sample).is_none());
        sample.guest_available_bytes = Some(16 * GIB);
        assert!(admission.try_sample(&config, &sample).is_some());
    }
    #[test]
    fn impossible_static_capacity_reaches_existing_failure_path() {
        let config = crate::config::BuildConfig::default();
        let admission = Admission::default();
        let sample = Snapshot {
            guest_total_bytes: Some(4 * GIB),
            guest_available_bytes: Some(3 * GIB),
            ..Default::default()
        };
        let lease = admission.try_sample(&config, &sample).unwrap();
        assert_eq!(lease.bytes, 0);
    }

    #[test]
    fn parent_limits_and_reclaimable_pages_are_accounted() {
        let root = std::env::temp_dir().join(format!("nest-cgroup-{}", uuid::Uuid::new_v4()));
        let child = root.join("child");
        fs::create_dir_all(&child).unwrap();
        fs::write(root.join("memory.max"), "1000").unwrap();
        fs::write(root.join("memory.current"), "900").unwrap();
        fs::write(
            root.join("memory.stat"),
            "inactive_file 300\nfile_dirty 100\n",
        )
        .unwrap();
        fs::write(child.join("memory.max"), "max").unwrap();
        let stats = cgroup_stats(&CgroupLocation {
            directory: child,
            mount: root.clone(),
        });
        assert_eq!(stats.effective_max_bytes, Some(1000));
        assert_eq!(stats.available_bytes, Some(300));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn missing_evidence_is_null_and_live_sample_is_plausible() {
        assert_eq!(bytes("", "VmRSS"), None);
        assert_eq!(pressure("full avg10=NaN total=7").full_avg10, None);
        let sample = sample();
        assert!(sample.process_rss_bytes.unwrap() > 0);
        assert!(sample.process_threads.unwrap() > 0);
    }
}
