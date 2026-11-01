//! Vulnerability scans and package status of update candidates (Manage
//! `docs/design/nest-driven-software-updates.md`, section 4).
//!
//! Manage prepares an update-only candidate of each released Blueprint as
//! soon as Nest reports a ready detected commit, and Nest builds it through
//! the ordinary build-job path, as a generic Blueprint closure or, as Manage
//! prepares Blueprints for computers, one per hardware cohort. Once the
//! candidate's closure is built, Nest:
//!
//! 1. finds the closure of the release the candidate was prepared from,
//!    named by `software_update.release_blueprint_revision_id` on the build
//!    job, of the same kind and, when it has one, hardware cohort; a
//!    candidate without it is skipped (`missing_release_hint`) until Manage
//!    names it, so a finding never compares against a guessed release. Nest
//!    serves finished closures from its cache, so garbage collection empties
//!    the store of them: a closure or derivations no longer there are built
//!    again from the job (`crate::build::rebuild_for_scan`) and kept only for
//!    the scan;
//! 2. scans the runtime closures of both in one vulnix run (`--closure`), so
//!    both are judged by the same NVD data, at low CPU and I/O priority under
//!    a memory and time limit, with its NVD database cached in the Nest state
//!    directory; each finding belongs to the closure whose derivations
//!    include the one it names;
//! 3. keeps the advisories of the release the candidate no longer has, with
//!    severity from the CVSS v3 base score;
//! 4. looks up each App List package ref of the job at the commit:
//!    `public_cache` when cache.nixos.org has its output, `software_cache`
//!    when the Tiaris software cache serves it, otherwise
//!    `preparation_required`. A ref Nest cannot answer for is left out, so
//!    Manage keeps its compiled catalog for it.
//!
//! Each candidate (commit and Blueprint revision) is scanned once. A failed
//! scan records its reason, produces no finding and never blocks a build; it
//! is retried at most daily, three attempts in all. A lookup that decides no
//! package at all is such a failure. Scans wait while a build runs and stop,
//! recording nothing, when one starts before a vulnix run. Findings reach Manage only in protocol-5 reports
//! (`software_update_findings`).
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, SqlitePool};

use crate::state_files;
use tokio::{sync::Notify, time::sleep};
use tracing::{info, warn};

use crate::{AppState, config::AppConfig, subprocess::run_bounded_command};

/// Report limits of Manage (`docs/api.md`): a lane or finding beyond them is
/// dropped whole, so Nest never sends more.
const MAX_REPORTED_FINDINGS: i64 = 256;
pub(crate) const MAX_ADVISORIES: usize = 500;
const MAX_PACKAGE_REFS: usize = 128;
/// All findings of one report together; the newest scans are kept.
const MAX_REPORTED_FINDINGS_BYTES: usize = 4 * 1024 * 1024;
const MAX_SUMMARY_CHARS: usize = 280;
const MAX_DETAIL_CHARS: usize = 500;

const SCAN_INTERVAL: Duration = Duration::from_secs(15 * 60);
const STARTUP_DELAY: Duration = Duration::from_secs(120);
const RETRY_INTERVAL: chrono::Duration = chrono::Duration::hours(24);
const MAX_ATTEMPTS: i64 = 3;
/// One vulnix run, including the first download of its NVD database (about
/// 50 seconds and 2.5 GiB resident on The Beast for the full feed).
const VULNIX_TIMEOUT: Duration = Duration::from_secs(40 * 60);
const VULNIX_MEMORY_LIMIT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const VULNIX_STDOUT_MAX_BYTES: usize = 64 * 1024 * 1024;
const VULNIX_STDERR_MAX_BYTES: usize = 64 * 1024;
const VULNIX_CACHE_DIR: &str = "vulnix";
const PATH_INFO_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PATH_INFO_STDOUT_MAX_BYTES: usize = 64 * 1024 * 1024;
/// vulnix skips closure paths whose derivation is not in the store. A scan
/// that would miss more than this share of either closure says nothing
/// about what the candidate fixes, so it fails instead.
const MIN_DERIVER_COVERAGE_PERCENT: usize = 90;
const PACKAGE_EVAL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PACKAGE_EVAL_STDOUT_MAX_BYTES: usize = 1024 * 1024;
const NARINFO_TIMEOUT: Duration = Duration::from_secs(15);
const PACKAGE_LOOKUP_DEADLINE: Duration = Duration::from_secs(5 * 60);
const PUBLIC_CACHE: &str = "https://cache.nixos.org";

pub(crate) const REASON_RELEASE_CLOSURE_UNAVAILABLE: &str = "release_closure_unavailable";
pub(crate) const REASON_CLOSURE_UNAVAILABLE: &str = "closure_unavailable";
pub(crate) const REASON_DERIVATIONS_UNAVAILABLE: &str = "derivations_unavailable";
pub(crate) const REASON_SCAN_FAILED: &str = "scan_failed";
pub(crate) const REASON_MISSING_RELEASE_HINT: &str = "missing_release_hint";
pub(crate) const REASON_PACKAGE_STATUS_UNAVAILABLE: &str = "package_status_unavailable";
/// One ref's evaluation when the batch evaluation of all refs fails.
const PACKAGE_REF_EVAL_TIMEOUT: Duration = Duration::from_secs(120);
const HINTS_FILE: &str = "candidate-hints.json";
const HINTS_SCHEMA: &str = "tiaris.nest.software-update-hints.v1";
const MAX_HINTS: usize = 4096;
const MAX_HINTS_BYTES: u64 = 1024 * 1024;
const SCAN_SCHEMA: &str = "tiaris.nest.software-update-scan.v1";
/// One scan: at most `MAX_ADVISORIES` advisories and `MAX_PACKAGE_REFS`
/// package statuses.
const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;
/// Scans kept at most, the newest, after those of jobs Nest no longer holds
/// are gone.
const MAX_SCAN_RECORDS: usize = 1024;

fn scans_dir(data_dir: &Path) -> PathBuf {
    super::state_dir(data_dir).join("scans")
}

/// A Manage job or Blueprint revision id, safe as part of a file name.
fn valid_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// One scan record (`scans/<commit>.<revision>.json`).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScanFile {
    commit_rev: String,
    blueprint_revision_id: String,
    candidate_job_id: i64,
    release_job_id: Option<i64>,
    /// `succeeded`, `failed` or `skipped` (`missing_release_hint`).
    state: String,
    reason: Option<String>,
    detail: String,
    attempts: i64,
    advisories: Vec<Advisory>,
    package_delivery: Vec<PackageDelivery>,
    scanned_at: String,
}

impl ScanFile {
    fn name(commit: &str, revision: &str) -> String {
        format!("{commit}.{revision}.json")
    }

    fn is_valid(&self, name: &str) -> bool {
        matches!(self.state.as_str(), "succeeded" | "failed" | "skipped")
            && (self.state == "succeeded") == self.reason.is_none()
            && super::valid_commit(&self.commit_rev)
            && valid_id(&self.blueprint_revision_id)
            && Self::name(&self.commit_rev, &self.blueprint_revision_id) == name
            && (0..=MAX_ATTEMPTS).contains(&self.attempts)
            && self.advisories.len() <= MAX_ADVISORIES
            && self.package_delivery.len() <= MAX_PACKAGE_REFS
            && self
                .advisories
                .iter()
                .all(|advisory| valid_advisory_id(&advisory.id))
            && self.package_delivery.iter().all(|item| {
                valid_package_ref(&item.package_ref)
                    && matches!(
                        item.status.as_str(),
                        "public_cache" | "software_cache" | "preparation_required"
                    )
            })
            && chrono::DateTime::parse_from_rfc3339(&self.scanned_at).is_ok()
    }
}

fn read_scan(data_dir: &Path, name: &str) -> Option<ScanFile> {
    state_files::read::<ScanFile>(&scans_dir(data_dir), name, SCAN_SCHEMA, MAX_SCAN_BYTES).filter(
        |scan| {
            let valid = scan.is_valid(name);
            if !valid {
                warn!(
                    record = name,
                    "ignoring a scan record that breaks its rules"
                );
            }
            valid
        },
    )
}

fn scan_of(data_dir: &Path, commit: &str, revision: &str) -> Option<ScanFile> {
    if !super::valid_commit(commit) || !valid_id(revision) {
        return None;
    }
    read_scan(data_dir, &ScanFile::name(commit, revision))
}

fn all_scans(data_dir: &Path) -> Vec<(String, ScanFile)> {
    state_files::list(&scans_dir(data_dir), ".json", 4 * MAX_SCAN_RECORDS)
        .into_iter()
        .filter_map(|name| read_scan(data_dir, &name).map(|scan| (name, scan)))
        .collect()
}

/// Managed job id → the release Manage named for it.
fn read_hints(data_dir: &Path) -> BTreeMap<String, String> {
    state_files::read::<BTreeMap<String, String>>(
        &super::state_dir(data_dir),
        HINTS_FILE,
        HINTS_SCHEMA,
        MAX_HINTS_BYTES,
    )
    .filter(|hints| {
        hints.len() <= MAX_HINTS
            && hints
                .iter()
                .all(|(job, release)| valid_id(job) && uuid::Uuid::parse_str(release).is_ok())
    })
    .unwrap_or_default()
}

async fn update_hints(
    data_dir: &Path,
    change: impl FnOnce(&mut BTreeMap<String, String>),
) -> Result<()> {
    let dir = super::state_dir(data_dir);
    let _guard = state_files::lock(&dir).await;
    let mut hints = read_hints(data_dir);
    let before = hints.clone();
    change(&mut hints);
    if hints == before {
        return Ok(());
    }
    if hints.len() > MAX_HINTS {
        bail!("more than {MAX_HINTS} software update release hints");
    }
    state_files::write(&dir, HINTS_FILE, HINTS_SCHEMA, MAX_HINTS_BYTES, &hints)
}

fn candidate_built_signal() -> &'static Notify {
    static SIGNAL: OnceLock<Notify> = OnceLock::new();
    SIGNAL.get_or_init(Notify::new)
}

/// A Blueprint closure was built; scan it soon if it is an update candidate.
pub(crate) fn candidate_built() {
    candidate_built_signal().notify_one();
}

/// One advisory a candidate fixes (protocol 5).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Advisory {
    pub(crate) id: String,
    pub(crate) package: String,
    pub(crate) severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) score: Option<f64>,
    pub(crate) summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PackageDelivery {
    #[serde(rename = "ref")]
    pub(crate) package_ref: String,
    pub(crate) status: String,
}

/// One finding in the Nest report (protocol 5).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct FindingReport {
    pub(crate) commit: String,
    pub(crate) blueprint_revision_id: String,
    pub(crate) scanned_at: String,
    pub(crate) advisories: Vec<Advisory>,
    pub(crate) package_delivery: Vec<PackageDelivery>,
}

/// CVSS v3: critical ≥ 9.0, important ≥ 7.0, moderate ≥ 4.0, otherwise low.
/// An advisory without a score counts as moderate, as in
/// `tools/software-base.py`.
pub(crate) fn severity(score: Option<f64>) -> &'static str {
    match score {
        None => "moderate",
        Some(score) if score >= 9.0 => "critical",
        Some(score) if score >= 7.0 => "important",
        Some(score) if score >= 4.0 => "moderate",
        Some(_) => "low",
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 3,
        "important" => 2,
        "moderate" => 1,
        _ => 0,
    }
}

/// Manage's advisory id rule.
fn valid_advisory_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn clean_text(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(max_chars)
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Debug, Deserialize)]
struct VulnixEntry {
    #[serde(default)]
    derivation: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    pname: Option<String>,
    #[serde(default)]
    affected_by: Vec<String>,
    #[serde(default)]
    cvssv3_basescore: BTreeMap<String, Value>,
    #[serde(default)]
    description: BTreeMap<String, String>,
}

fn parse_vulnix(stdout: &[u8]) -> Result<Vec<VulnixEntry>> {
    serde_json::from_slice(stdout).context("parse vulnix JSON")
}

/// The advisories of the release's and of the candidate's closure, from one
/// vulnix run over both, by the derivation each finding names. A finding of
/// a derivation in neither counts as the candidate's, so it never shows as
/// fixed.
fn attribute(
    entries: Vec<VulnixEntry>,
    release: &BTreeSet<String>,
    candidate: &BTreeSet<String>,
) -> (BTreeMap<String, Advisory>, BTreeMap<String, Advisory>) {
    let (mut of_release, mut of_candidate) = (Vec::new(), Vec::new());
    for entry in entries {
        let derivation = entry.derivation.as_deref().map(absolute_store_path);
        let in_release = derivation
            .as_ref()
            .is_some_and(|path| release.contains(path));
        let in_candidate = derivation
            .as_ref()
            .is_some_and(|path| candidate.contains(path));
        if in_release {
            of_release.push(entry.clone());
        }
        if in_candidate || !in_release {
            of_candidate.push(entry);
        }
    }
    (advisories(of_release), advisories(of_candidate))
}

/// Advisory id → advisory of vulnix findings. An advisory reported for
/// several packages keeps the first package by name.
fn advisories(mut entries: Vec<VulnixEntry>) -> BTreeMap<String, Advisory> {
    entries.sort_by(|left, right| {
        left.pname
            .as_deref()
            .or(left.name.as_deref())
            .cmp(&right.pname.as_deref().or(right.name.as_deref()))
    });
    let mut found = BTreeMap::new();
    for entry in entries {
        let package = clean_text(
            entry
                .pname
                .as_deref()
                .filter(|name| !name.trim().is_empty())
                .or(entry.name.as_deref())
                .unwrap_or_default(),
            128,
        );
        if package.is_empty() {
            continue;
        }
        for id in entry.affected_by {
            let id = id.trim().to_string();
            if !valid_advisory_id(&id) || found.contains_key(&id) {
                continue;
            }
            let score = entry
                .cvssv3_basescore
                .get(&id)
                .and_then(Value::as_f64)
                .filter(|score| score.is_finite() && (0.0..=10.0).contains(score));
            let summary = entry
                .description
                .get(&id)
                .map(|text| clean_text(text, MAX_SUMMARY_CHARS))
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| format!("Fixed in {package}."));
            let url = id
                .starts_with("CVE-")
                .then(|| format!("https://nvd.nist.gov/vuln/detail/{id}"));
            found.insert(
                id.clone(),
                Advisory {
                    id,
                    package: package.clone(),
                    severity: severity(score).to_string(),
                    score,
                    summary,
                    url,
                },
            );
        }
    }
    found
}

/// The release's advisories the candidate no longer has, most severe first,
/// at most `MAX_ADVISORIES`.
pub(crate) fn fixed_advisories(
    release: &BTreeMap<String, Advisory>,
    candidate: &BTreeMap<String, Advisory>,
) -> Vec<Advisory> {
    let mut fixed = release
        .iter()
        .filter(|(id, _)| !candidate.contains_key(*id))
        .map(|(_, advisory)| advisory.clone())
        .collect::<Vec<_>>();
    fixed.sort_by(|left, right| {
        severity_rank(&right.severity)
            .cmp(&severity_rank(&left.severity))
            .then_with(|| {
                right
                    .score
                    .unwrap_or(0.0)
                    .total_cmp(&left.score.unwrap_or(0.0))
            })
            .then_with(|| left.id.cmp(&right.id))
    });
    fixed.truncate(MAX_ADVISORIES);
    fixed
}

/// Where the scanner finds its tools and caches.
#[derive(Clone)]
pub(crate) struct Scanner {
    nix: String,
    vulnix: String,
    vulnix_cache: PathBuf,
    public_cache: String,
    /// Origin and read token of the Tiaris software cache, from the netrc
    /// file Manage's access keeps current.
    software_cache: Option<(String, String)>,
    memory_limit_bytes: u64,
    /// The Nest, to build a job again whose closure left the store; `None`
    /// fails such a scan instead.
    rebuild: Option<AppState>,
}

impl Scanner {
    /// `program` at nice 19, idle I/O and the scanner's memory limit, like
    /// every process the scanner starts.
    fn command(&self, program: &str) -> tokio::process::Command {
        let mut command = crate::nix_command::tokio_command(program);
        command.stdin(std::process::Stdio::null());
        let memory = self.memory_limit_bytes;
        // SAFETY: only async-signal-safe libc calls between fork and exec.
        unsafe {
            command.pre_exec(move || {
                lower_priority(memory);
                Ok(())
            });
        }
        command
    }

    fn from_config(config: &AppConfig) -> Self {
        Self {
            nix: config.build.nix_binary.clone(),
            vulnix: "vulnix".to_string(),
            vulnix_cache: config.paths.data_dir.join(VULNIX_CACHE_DIR),
            public_cache: PUBLIC_CACHE.to_string(),
            software_cache: crate::software_cache::current_access(&config.paths.data_dir),
            memory_limit_bytes: VULNIX_MEMORY_LIMIT_BYTES,
            rebuild: None,
        }
    }
}

#[derive(Clone, Debug, FromRow)]
struct JobRow {
    id: i64,
    managed_job_id: Option<String>,
    requested_artifact_type: String,
    system: String,
    target: String,
    build_spec: String,
    output_path: String,
}

#[derive(Debug, Deserialize)]
struct SpecFields {
    #[serde(default)]
    blueprint_id: Option<String>,
    #[serde(default)]
    blueprint_revision_id: Option<String>,
    #[serde(default)]
    nixpkgs_commit: Option<String>,
    #[serde(default)]
    software_package_refs: Vec<String>,
    #[serde(default)]
    build_input: Option<BuildInputFields>,
}

#[derive(Debug, Deserialize)]
struct BuildInputFields {
    #[serde(default)]
    installer_target: Option<InstallerTargetFields>,
}

/// The hardware cohort of an installer-target job.
#[derive(Debug, Deserialize)]
struct InstallerTargetFields {
    #[serde(default)]
    hardware_module_sha256: Option<String>,
    #[serde(default)]
    hardware_driver_policy: Option<String>,
}

#[derive(Clone, Debug)]
struct Job {
    id: i64,
    managed_job_id: Option<String>,
    blueprint_id: String,
    blueprint_revision_id: String,
    commit: String,
    package_refs: Vec<String>,
    output_path: String,
    /// Hardware module and driver policy of an installer-target job.
    cohort: Option<(Option<String>, Option<String>)>,
}

impl Job {
    fn from_row(row: &JobRow) -> Option<Self> {
        let spec: SpecFields = serde_json::from_str(&row.build_spec).ok()?;
        Some(Self {
            id: row.id,
            managed_job_id: row.managed_job_id.clone(),
            blueprint_id: spec.blueprint_id?,
            blueprint_revision_id: spec.blueprint_revision_id?,
            commit: spec.nixpkgs_commit?,
            package_refs: spec.software_package_refs,
            output_path: row.output_path.clone(),
            cohort: spec
                .build_input
                .and_then(|input| input.installer_target)
                .map(|target| (target.hardware_module_sha256, target.hardware_driver_policy)),
        })
    }
}

/// Blueprint closures, generic or of one hardware cohort: Manage prepares
/// Blueprints for computers per cohort, and a release and its update are
/// compared within one kind (`target`).
const BLUEPRINT_JOB_FILTER: &str = "status = 'succeeded' AND output_path != ''
     AND json_valid(build_spec)
     AND json_extract(build_spec, '$.build_input.kind')
         IN ('blueprint_nixos_module', 'installer_target_nixos_module')
     AND json_type(build_spec, '$.blueprint_id') = 'text'
     AND json_type(build_spec, '$.blueprint_revision_id') = 'text'
     AND json_type(build_spec, '$.nixpkgs_commit') = 'text'";

const JOB_COLUMNS: &str =
    "id, managed_job_id, requested_artifact_type, system, target, build_spec, output_path";

fn timestamp(value: chrono::DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Record the release Manage named for a candidate job, or forget it.
pub(crate) async fn record_hint(
    data_dir: &Path,
    managed_job_id: &str,
    software_update: Option<&Value>,
) -> Result<()> {
    let release = software_update
        .and_then(|value| value.get("release_blueprint_revision_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .map(|value| value.hyphenated().to_string());
    if !valid_id(managed_job_id) {
        return Ok(());
    }
    update_hints(data_dir, |hints| match release {
        Some(release) => {
            hints.insert(managed_job_id.to_string(), release);
        }
        None => {
            hints.remove(managed_job_id);
        }
    })
    .await
}

/// Start the scanner (only on Nests that check for updates).
pub(crate) fn spawn(state: AppState) {
    tokio::spawn(async move {
        sleep(STARTUP_DELAY).await;
        loop {
            match scan_pending(&state).await {
                Ok(scanned) if scanned > 0 => info!(scanned, "scanned software update candidates"),
                Ok(_) => {}
                Err(error) => warn!(error = %error, "software update scan pass failed"),
            }
            tokio::select! {
                _ = sleep(SCAN_INTERVAL) => {}
                _ = candidate_built_signal().notified() => {}
            }
        }
    });
}

/// Scan every pending candidate, one at a time, while no build runs.
async fn scan_pending(state: &AppState) -> Result<usize> {
    let data_dir = &state.config.paths.data_dir;
    prune(&state.db, data_dir).await?;
    let mut scanned = 0;
    loop {
        if build_running(&state.db).await? {
            return Ok(scanned);
        }
        let release_pins = crate::config::workstation_nixpkgs_commits(&state.config);
        let Some(candidate) =
            next_candidate(&state.db, data_dir, &release_pins, Utc::now()).await?
        else {
            return Ok(scanned);
        };
        let scanner = Scanner {
            rebuild: Some(state.clone()),
            ..Scanner::from_config(&state.config)
        };
        if !scan_and_record(&state.db, data_dir, &scanner, &candidate).await? {
            // A build started: scan again once it is done.
            return Ok(scanned);
        }
        scanned += 1;
    }
}

async fn build_running(db: &SqlitePool) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM nest_build_jobs WHERE status = 'running')",
    )
    .fetch_one(db)
    .await?)
}

/// Scans and hints of jobs Nest no longer holds go with them; beyond those,
/// at most `MAX_SCAN_RECORDS` scans are kept, the newest.
async fn prune(db: &SqlitePool, data_dir: &Path) -> Result<()> {
    let jobs = sqlx::query_as::<_, (i64, Option<String>)>(
        "SELECT id, managed_job_id FROM nest_build_jobs",
    )
    .fetch_all(db)
    .await?;
    let ids = jobs.iter().map(|(id, _)| *id).collect::<BTreeSet<_>>();
    let managed = jobs
        .into_iter()
        .filter_map(|(_, managed)| managed)
        .collect::<BTreeSet<_>>();
    let dir = scans_dir(data_dir);
    let _guard = state_files::lock(&dir).await;
    let mut kept = Vec::new();
    for (name, scan) in all_scans(data_dir) {
        if ids.contains(&scan.candidate_job_id) {
            kept.push((name, scan));
        } else {
            state_files::remove(&dir, &name)?;
        }
    }
    kept.sort_by(|left, right| right.1.scanned_at.cmp(&left.1.scanned_at));
    for (name, _) in kept.iter().skip(MAX_SCAN_RECORDS) {
        state_files::remove(&dir, name)?;
    }
    drop(_guard);
    update_hints(data_dir, |hints| {
        hints.retain(|job, _| managed.contains(job))
    })
    .await
}

/// A built candidate: a Blueprint job at a ready detected commit whose commit
/// and revision have no scan yet, only a failed one due for a retry, or a
/// skipped one whose job now names its release. A job at a workstation pin is
/// one only once Manage names its release: Manage pins a detected commit too,
/// so the Nest can build its candidates.
#[derive(Clone, Debug)]
struct Candidate {
    job: Job,
    artifact_type: String,
    system: String,
    target: String,
    nar_hash: String,
}

async fn next_candidate(
    db: &SqlitePool,
    data_dir: &Path,
    release_pins: &[String],
    now: chrono::DateTime<Utc>,
) -> Result<Option<Candidate>> {
    let rows = sqlx::query_as::<_, JobRow>(&format!(
        "SELECT {JOB_COLUMNS} FROM nest_build_jobs AS jobs
         WHERE {BLUEPRINT_JOB_FILTER}
         ORDER BY completed_at, id"
    ))
    .fetch_all(db)
    .await?;
    let retry_before = timestamp(now - RETRY_INTERVAL);
    let hints = read_hints(data_dir);
    for row in rows {
        let Some(job) = Job::from_row(&row) else {
            continue;
        };
        let named = job
            .managed_job_id
            .as_ref()
            .is_some_and(|managed| hints.contains_key(managed));
        if release_pins.contains(&job.commit) && !named {
            continue;
        }
        // A scan of these could never be stored; skip it instead of scanning
        // it again on every pass ahead of every later candidate.
        if !valid_id(&job.blueprint_revision_id)
            || job
                .managed_job_id
                .as_deref()
                .is_some_and(|id| !valid_id(id))
        {
            if named {
                warn!(
                    job_id = job.id,
                    "software update candidate has ids a scan cannot be stored under; not scanned"
                );
            }
            continue;
        }
        let done = scan_of(data_dir, &job.commit, &job.blueprint_revision_id).is_some_and(|scan| {
            match scan.state.as_str() {
                "succeeded" => true,
                "failed" => scan.attempts >= MAX_ATTEMPTS || scan.scanned_at > retry_before,
                // Skipped until the job names its release.
                _ => !job
                    .managed_job_id
                    .as_ref()
                    .is_some_and(|managed| hints.contains_key(managed)),
            }
        });
        if done {
            continue;
        }
        let Some(nar_hash) = super::current_ready_nar_hash(data_dir, &job.commit).await? else {
            if named {
                info!(
                    job_id = job.id,
                    commit = %job.commit,
                    "software update candidate waits for its commit to be ready on this Nest"
                );
            }
            continue;
        };
        return Ok(Some(Candidate {
            job,
            artifact_type: row.requested_artifact_type,
            system: row.system,
            target: row.target,
            nar_hash,
        }));
    }
    Ok(None)
}

/// The release Manage named for the candidate, if it did.
fn release_hint(data_dir: &Path, candidate: &Candidate) -> Option<String> {
    let managed = candidate.job.managed_job_id.as_deref()?;
    read_hints(data_dir).remove(managed)
}

/// The built closure of `release`, the revision the candidate was prepared
/// from, at another commit, of the candidate's hardware cohort when there is
/// one; otherwise of any cohort, as the software is the same.
async fn release_job(db: &SqlitePool, candidate: &Candidate, release: &str) -> Result<Option<Job>> {
    let rows = sqlx::query_as::<_, JobRow>(&format!(
        "SELECT {JOB_COLUMNS} FROM nest_build_jobs
         WHERE {BLUEPRINT_JOB_FILTER}
           AND requested_artifact_type = ? AND system = ? AND target = ?
           AND json_extract(build_spec, '$.blueprint_id') = ?
           AND json_extract(build_spec, '$.blueprint_revision_id') = ?
           AND json_extract(build_spec, '$.nixpkgs_commit') != ?
         ORDER BY completed_at DESC, id DESC"
    ))
    .bind(&candidate.artifact_type)
    .bind(&candidate.system)
    .bind(&candidate.target)
    .bind(&candidate.job.blueprint_id)
    .bind(release)
    .bind(&candidate.job.commit)
    .fetch_all(db)
    .await?;
    let jobs = rows.iter().filter_map(Job::from_row).collect::<Vec<_>>();
    Ok(jobs
        .iter()
        .find(|job| job.cohort == candidate.job.cohort)
        .or(jobs.first())
        .cloned())
}

#[derive(Debug)]
struct ScanFailure {
    reason: &'static str,
    detail: String,
}

impl ScanFailure {
    fn new(reason: &'static str, error: impl std::fmt::Display) -> Self {
        Self {
            reason,
            detail: clean_text(&error.to_string(), MAX_DETAIL_CHARS),
        }
    }
}

enum ScanResult {
    Succeeded(Vec<Advisory>, Vec<PackageDelivery>),
    /// Retried at most daily, `MAX_ATTEMPTS` in all.
    Failed(ScanFailure),
    /// Nothing to compare with until Manage names the release.
    Skipped(ScanFailure),
    /// A build started; nothing is recorded and the scan runs again later.
    Deferred,
}

struct ScanOutcome {
    release_job_id: Option<i64>,
    result: ScanResult,
}

impl ScanOutcome {
    fn failed(release_job_id: Option<i64>, failure: ScanFailure) -> Self {
        Self {
            release_job_id,
            result: ScanResult::Failed(failure),
        }
    }
}

/// Scan one candidate and record the outcome; `false` when a build started
/// and nothing was recorded.
async fn scan_and_record(
    db: &SqlitePool,
    data_dir: &Path,
    scanner: &Scanner,
    candidate: &Candidate,
) -> Result<bool> {
    let outcome = scan(db, data_dir, scanner, candidate).await?;
    let now = timestamp(Utc::now());
    let (state, reason, detail, advisories, delivery) = match outcome.result {
        ScanResult::Deferred => return Ok(false),
        ScanResult::Succeeded(advisories, delivery) => {
            info!(
                commit = %candidate.job.commit,
                blueprint_revision_id = %candidate.job.blueprint_revision_id,
                fixed = advisories.len(),
                packages = delivery.len(),
                "scanned software update candidate"
            );
            ("succeeded", None, String::new(), advisories, delivery)
        }
        ScanResult::Failed(failure) => not_scanned(candidate, "failed", failure),
        ScanResult::Skipped(failure) => not_scanned(candidate, "skipped", failure),
    };
    let dir = scans_dir(data_dir);
    let _guard = state_files::lock(&dir).await;
    let previous = scan_of(
        data_dir,
        &candidate.job.commit,
        &candidate.job.blueprint_revision_id,
    )
    .map_or(0, |scan| scan.attempts);
    let record = ScanFile {
        commit_rev: candidate.job.commit.clone(),
        blueprint_revision_id: candidate.job.blueprint_revision_id.clone(),
        candidate_job_id: candidate.job.id,
        release_job_id: outcome.release_job_id,
        state: state.to_string(),
        reason: reason.map(str::to_string),
        detail,
        attempts: (previous + i64::from(state == "failed")).min(MAX_ATTEMPTS),
        advisories,
        package_delivery: delivery,
        scanned_at: now,
    };
    let name = ScanFile::name(&record.commit_rev, &record.blueprint_revision_id);
    if !record.is_valid(&name) {
        bail!("a scan of {name} would break its record's rules");
    }
    state_files::write(&dir, &name, SCAN_SCHEMA, MAX_SCAN_BYTES, &record)?;
    Ok(true)
}

type ScanRecord = (
    &'static str,
    Option<&'static str>,
    String,
    Vec<Advisory>,
    Vec<PackageDelivery>,
);

fn not_scanned(candidate: &Candidate, state: &'static str, failure: ScanFailure) -> ScanRecord {
    warn!(
        commit = %candidate.job.commit,
        blueprint_revision_id = %candidate.job.blueprint_revision_id,
        state,
        reason = failure.reason,
        detail = %failure.detail,
        "software update candidate not scanned; no finding is reported"
    );
    (
        state,
        Some(failure.reason),
        failure.detail,
        Vec::new(),
        Vec::new(),
    )
}

/// Scan one candidate. Database errors are returned; everything about the
/// closures, vulnix or the network is a recorded failure.
async fn scan(
    db: &SqlitePool,
    data_dir: &Path,
    scanner: &Scanner,
    candidate: &Candidate,
) -> Result<ScanOutcome> {
    let Some(release) = release_hint(data_dir, candidate) else {
        return Ok(ScanOutcome {
            release_job_id: None,
            result: ScanResult::Skipped(ScanFailure::new(
                REASON_MISSING_RELEASE_HINT,
                "the build job does not name the release this update was prepared from",
            )),
        });
    };
    let Some(release) = release_job(db, candidate, &release).await? else {
        return Ok(ScanOutcome::failed(
            None,
            ScanFailure::new(
                REASON_RELEASE_CLOSURE_UNAVAILABLE,
                "no built closure of the named release at another commit",
            ),
        ));
    };
    let release_job_id = Some(release.id);
    // Closures built again stay in the store until the scan is done.
    let mut rebuilt = Vec::new();
    let mut closures = Vec::with_capacity(2);
    for job in [&release, &candidate.job] {
        match closure_for_scan(scanner, job, &mut rebuilt).await {
            Ok(Some(path)) => closures.push(path),
            Ok(None) => {
                return Ok(ScanOutcome {
                    release_job_id,
                    result: ScanResult::Deferred,
                });
            }
            Err(failure) => return Ok(ScanOutcome::failed(release_job_id, failure)),
        }
    }
    let [
        (release_path, release_derivations),
        (candidate_path, candidate_derivations),
    ] = <[_; 2]>::try_from(closures).expect("two closures");
    if build_running(db).await? {
        return Ok(ScanOutcome {
            release_job_id,
            result: ScanResult::Deferred,
        });
    }
    let entries = match run_vulnix(scanner, &[&release_path, &candidate_path]).await {
        Ok(entries) => entries,
        Err(error) => {
            return Ok(ScanOutcome::failed(
                release_job_id,
                ScanFailure::new(REASON_SCAN_FAILED, format!("{error:#}")),
            ));
        }
    };
    let (release_advisories, candidate_advisories) =
        attribute(entries, &release_derivations, &candidate_derivations);
    let fixed = fixed_advisories(&release_advisories, &candidate_advisories);
    let delivery = match package_delivery(scanner, candidate).await {
        Ok(delivery) => delivery,
        Err(failure) => return Ok(ScanOutcome::failed(release_job_id, failure)),
    };
    Ok(ScanOutcome {
        release_job_id,
        result: ScanResult::Succeeded(fixed, delivery),
    })
}

/// The job's closure and its derivations, nearly all of them in the store,
/// built again when garbage collection took them; `None` while the Nest has
/// no memory for that build.
async fn closure_for_scan(
    scanner: &Scanner,
    job: &Job,
    rebuilt: &mut Vec<crate::build::RebuiltClosure>,
) -> std::result::Result<Option<(String, BTreeSet<String>)>, ScanFailure> {
    let failure = match check_derivers(scanner, &job.output_path).await {
        Ok(derivations) => return Ok(Some((job.output_path.clone(), derivations))),
        Err(failure) => failure,
    };
    let Some(state) = scanner.rebuild.as_ref() else {
        return Err(failure);
    };
    info!(
        job_id = job.id,
        reason = failure.reason,
        detail = %failure.detail,
        "building a software update closure again to scan it"
    );
    let closure = match crate::build::rebuild_for_scan(state, job.id).await {
        Ok(Some(closure)) => closure,
        Ok(None) => return Ok(None),
        Err(error) => {
            return Err(ScanFailure::new(
                failure.reason,
                format!("{}; building it again failed: {error:#}", failure.detail),
            ));
        }
    };
    if closure.output_path != job.output_path {
        warn!(
            job_id = job.id,
            built = %job.output_path,
            rebuilt = %closure.output_path,
            "a software update closure built again differs from the original; scanning the new one"
        );
    }
    let derivations = check_derivers(scanner, &closure.output_path).await?;
    let path = closure.output_path.clone();
    rebuilt.push(closure);
    Ok(Some((path, derivations)))
}

fn valid_store_path(path: &str) -> bool {
    path.strip_prefix("/nix/store/").is_some_and(|name| {
        name.len() > 33
            && name.as_bytes()[32] == b'-'
            && name[..32]
                .bytes()
                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
            && name[33..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(&byte))
    })
}

/// The derivations vulnix finds for the closure's paths, which must be in the
/// store with nearly every path's derivation. Like vulnix, a path whose
/// recorded deriver is gone counts when a valid derivation in the store
/// declares it as output.
async fn check_derivers(
    scanner: &Scanner,
    path: &str,
) -> std::result::Result<BTreeSet<String>, ScanFailure> {
    if !valid_store_path(path) {
        return Err(ScanFailure::new(
            REASON_CLOSURE_UNAVAILABLE,
            "the job's output is not a store path",
        ));
    }
    let closure = nix_json(scanner, &["path-info", "--recursive", "--json", path])
        .await
        .and_then(|value| closure_derivers(&value))
        .map_err(|error| ScanFailure::new(REASON_CLOSURE_UNAVAILABLE, format!("{error:#}")))?;
    let total = closure.len();
    let missing = closure
        .iter()
        .filter(|(_, deriver)| {
            !deriver
                .as_deref()
                .is_some_and(|path| Path::new(path).exists())
        })
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let mut derivations = closure
        .iter()
        .filter_map(|(_, deriver)| deriver.clone())
        .filter(|deriver| Path::new(deriver).exists())
        .collect::<BTreeSet<_>>();
    let missing_paths = missing.iter().collect::<BTreeSet<_>>();
    let mut recovered = BTreeSet::new();
    for (derivation, outputs) in valid_derivations(scanner, &missing)
        .await
        .map_err(|error| ScanFailure::new(REASON_DERIVATIONS_UNAVAILABLE, format!("{error:#}")))?
    {
        let declared = outputs
            .into_iter()
            .filter(|output| missing_paths.contains(output))
            .collect::<Vec<_>>();
        if !declared.is_empty() {
            derivations.insert(derivation);
            recovered.extend(declared);
        }
    }
    let present = total - missing.len() + recovered.len();
    if total == 0 || present * 100 < total * MIN_DERIVER_COVERAGE_PERCENT {
        return Err(ScanFailure::new(
            REASON_DERIVATIONS_UNAVAILABLE,
            format!("{present} of {total} closure paths have their derivation in the store"),
        ));
    }
    Ok(derivations)
}

/// Bounded `nix … --json`.
async fn nix_json(scanner: &Scanner, args: &[&str]) -> Result<Value> {
    let mut command = scanner.command(&scanner.nix);
    command.args(args);
    let output = run_bounded_command(
        command,
        PATH_INFO_TIMEOUT,
        PATH_INFO_STDOUT_MAX_BYTES,
        VULNIX_STDERR_MAX_BYTES,
        "nix query of a scanned closure",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "nix {} failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse nix JSON")
}

fn absolute_store_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/nix/store/{path}")
    }
}

/// Each closure path with its recorded deriver, from either JSON shape of
/// `nix path-info --json`.
fn closure_derivers(value: &Value) -> Result<Vec<(String, Option<String>)>> {
    let deriver = |info: &Value| {
        info.get("deriver")
            .and_then(Value::as_str)
            .filter(|deriver| deriver.ends_with(".drv"))
            .map(absolute_store_path)
    };
    Ok(match value {
        Value::Object(paths) => paths
            .iter()
            .map(|(path, info)| (absolute_store_path(path), deriver(info)))
            .collect(),
        Value::Array(paths) => paths
            .iter()
            .filter_map(|info| {
                let path = info.get("path").and_then(Value::as_str)?;
                Some((absolute_store_path(path), deriver(info)))
            })
            .collect(),
        _ => bail!("nix path-info returned neither an object nor a list"),
    })
}

/// The valid derivations of `paths` with the outputs each declares
/// (`nix-store --query --valid-derivers`, then `nix derivation show`).
async fn valid_derivations(
    scanner: &Scanner,
    paths: &[String],
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    const CHUNK: usize = 1000;
    let nix_store = Path::new(&scanner.nix).with_file_name("nix-store");
    let nix_store = if scanner.nix.contains('/') {
        nix_store.display().to_string()
    } else {
        "nix-store".to_string()
    };
    let mut derivers = BTreeSet::new();
    for chunk in paths.chunks(CHUNK) {
        let mut command = scanner.command(&nix_store);
        command.args(["--query", "--valid-derivers"]).args(chunk);
        let output = run_bounded_command(
            command,
            PATH_INFO_TIMEOUT,
            PATH_INFO_STDOUT_MAX_BYTES,
            VULNIX_STDERR_MAX_BYTES,
            "nix-store --valid-derivers of a scanned closure",
        )
        .await?;
        if !output.status.success() {
            bail!(
                "nix-store --valid-derivers failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        derivers.extend(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::trim)
                .filter(|line| line.ends_with(".drv") && Path::new(line).exists())
                .map(str::to_string),
        );
    }
    let derivers = derivers.into_iter().collect::<Vec<_>>();
    let mut declared = BTreeMap::new();
    for chunk in derivers.chunks(CHUNK) {
        let mut args = vec!["derivation", "show"];
        args.extend(chunk.iter().map(String::as_str));
        let shown = nix_json(scanner, &args).await?;
        let shown = shown.get("derivations").unwrap_or(&shown);
        for (path, derivation) in shown.as_object().into_iter().flatten() {
            let outputs: &mut BTreeSet<String> =
                declared.entry(absolute_store_path(path)).or_default();
            outputs.extend(
                derivation
                    .get("outputs")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|map| map.values())
                    .filter_map(|output| output.get("path").and_then(Value::as_str))
                    .map(absolute_store_path),
            );
        }
    }
    Ok(declared)
}

/// `vulnix --json --closure` of the closures at idle priority, in one run:
/// vulnix refreshes its NVD data before it scans, so separate runs could
/// judge them by different data.
async fn run_vulnix(scanner: &Scanner, paths: &[&str]) -> Result<Vec<VulnixEntry>> {
    create_private_dir(&scanner.vulnix_cache)?;
    let mut command = scanner.command(&scanner.vulnix);
    command.args(["--json", "--closure", "--cache-dir"]);
    command.arg(&scanner.vulnix_cache);
    command.args(paths);
    let output = run_bounded_command(
        command,
        VULNIX_TIMEOUT,
        VULNIX_STDOUT_MAX_BYTES,
        VULNIX_STDERR_MAX_BYTES,
        "vulnix scan",
    )
    .await?;
    // vulnix exits 0 without findings, 2 with findings and also 2 on its own
    // errors; only a JSON list on stdout is a result.
    let code = output.status.code();
    if !matches!(code, Some(0..=2)) || output.stdout.iter().all(u8::is_ascii_whitespace) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "vulnix exited with {} and no result: {}",
            code.map_or_else(|| "a signal".to_string(), |code| code.to_string()),
            stderr.lines().last().unwrap_or_default()
        );
    }
    parse_vulnix(&output.stdout)
}

/// Lowest CPU and idle I/O priority, and a bound on address space. Runs in
/// the child before exec.
fn lower_priority(memory_limit_bytes: u64) {
    const IOPRIO_WHO_PROCESS: libc::c_long = 1;
    const IOPRIO_CLASS_IDLE: libc::c_long = 3;
    const IOPRIO_CLASS_SHIFT: libc::c_long = 13;
    // SAFETY: plain syscalls on the calling process; failures leave the
    // default priority, which is still bounded by time and memory.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
        libc::syscall(
            libc::SYS_ioprio_set,
            IOPRIO_WHO_PROCESS,
            0 as libc::c_long,
            IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT,
        );
        let limit = libc::rlimit {
            rlim_cur: memory_limit_bytes as libc::rlim_t,
            rlim_max: memory_limit_bytes as libc::rlim_t,
        };
        libc::setrlimit(libc::RLIMIT_AS, &limit);
    }
}

fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.is_dir() {
                bail!("{} is not a directory", path.display());
            }
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("create {}", path.display())),
    }
}

/// A package ref as Manage writes it: an attribute path, safe to embed in a
/// Nix string.
fn valid_package_ref(value: &str) -> bool {
    (1..=200).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
        && !value.contains("..")
}

/// Status of each package ref of the job at the candidate's commit. Refs
/// whose output Nest cannot evaluate, or whose caches do not answer, are left
/// out, so Manage keeps its compiled catalog for them. A lookup that decides
/// none of the refs failed as a whole (network, time limit) and is retried.
async fn package_delivery(
    scanner: &Scanner,
    candidate: &Candidate,
) -> std::result::Result<Vec<PackageDelivery>, ScanFailure> {
    let refs = candidate
        .job
        .package_refs
        .iter()
        .filter(|value| valid_package_ref(value))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_PACKAGE_REFS)
        .collect::<Vec<_>>();
    if refs.is_empty() {
        return Ok(Vec::new());
    }
    let unavailable = |detail: String| ScanFailure::new(REASON_PACKAGE_STATUS_UNAVAILABLE, detail);
    let outputs = package_outputs(scanner, candidate, &refs)
        .await
        .map_err(|error| unavailable(format!("{error:#}")))?;
    let client = reqwest::Client::builder()
        .timeout(NARINFO_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| unavailable(error.to_string()))?;
    let deadline = tokio::time::Instant::now() + PACKAGE_LOOKUP_DEADLINE;
    let mut delivery = Vec::new();
    for (package_ref, output) in outputs {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        if let Some(status) = output_status(&client, scanner, &output).await {
            delivery.push(PackageDelivery {
                package_ref,
                status: status.to_string(),
            });
        }
    }
    if delivery.is_empty() {
        return Err(unavailable(format!(
            "no status decided for any of {} App List packages",
            refs.len()
        )));
    }
    Ok(delivery)
}

/// ref → output path at the commit, for the refs that evaluate. All refs are
/// evaluated at once; when that fails (a ref Nix cannot recover from), each
/// ref is evaluated on its own so one ref cannot hide the others.
async fn package_outputs(
    scanner: &Scanner,
    candidate: &Candidate,
    refs: &[String],
) -> Result<BTreeMap<String, String>> {
    let flake = crate::build::nixpkgs_flake_ref(&candidate.job.commit, Some(&candidate.nar_hash))?;
    if !candidate
        .system
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("job system is not a Nix system name");
    }
    let batch = eval_package_outputs(
        scanner,
        &flake,
        &candidate.system,
        refs,
        PACKAGE_EVAL_TIMEOUT,
    )
    .await;
    let error = match batch {
        Ok(outputs) => return Ok(outputs),
        Err(error) => error,
    };
    warn!(error = %error, commit = %candidate.job.commit,
        "App List packages did not evaluate together; evaluating them one by one");
    let deadline = tokio::time::Instant::now() + PACKAGE_EVAL_TIMEOUT;
    let mut outputs = BTreeMap::new();
    for package_ref in refs {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let single = std::slice::from_ref(package_ref);
        let limit = remaining.min(PACKAGE_REF_EVAL_TIMEOUT);
        match eval_package_outputs(scanner, &flake, &candidate.system, single, limit).await {
            Ok(found) => outputs.extend(found),
            Err(error) => warn!(error = %error, %package_ref, "App List package did not evaluate"),
        }
    }
    Ok(outputs)
}

async fn eval_package_outputs(
    scanner: &Scanner,
    flake: &str,
    system: &str,
    refs: &[String],
    time_limit: Duration,
) -> Result<BTreeMap<String, String>> {
    let expression = package_outputs_expression(flake, system, refs)?;
    let mut command = scanner.command(&scanner.nix);
    command.args([
        "--option",
        "accept-flake-config",
        "false",
        "--option",
        "allow-import-from-derivation",
        "false",
        "eval",
        "--json",
        "--expr",
        &expression,
    ]);
    let output = run_bounded_command(
        command,
        time_limit,
        PACKAGE_EVAL_STDOUT_MAX_BYTES,
        VULNIX_STDERR_MAX_BYTES,
        "nix eval of App List package outputs",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "nix eval failed: {}",
            clean_text(&String::from_utf8_lossy(&output.stderr), MAX_DETAIL_CHARS)
        );
    }
    let values: BTreeMap<String, Option<String>> =
        serde_json::from_slice(&output.stdout).context("parse App List package outputs")?;
    Ok(values
        .into_iter()
        .filter(|(package_ref, _)| refs.contains(package_ref))
        .filter_map(|(package_ref, output)| {
            output
                .filter(|path| valid_store_path(path))
                .map(|path| (package_ref, path))
        })
        .collect())
}

/// Each ref's `(package.out or package).outPath` at the narHash-pinned
/// commit, as Manage's cache catalog takes it; `null` when it does not
/// evaluate. Unfree packages are allowed: the output path does not depend on
/// the licence decision, which the Blueprint makes.
fn package_outputs_expression(flake: &str, system: &str, refs: &[String]) -> Result<String> {
    if refs.iter().any(|value| !valid_package_ref(value)) || flake.contains('"') {
        bail!("package refs must be attribute paths");
    }
    let refs = refs
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(format!(
        r#"let
  pkgs = import (builtins.getFlake "{flake}") {{
    system = "{system}";
    config = {{ allowUnfree = true; }};
  }};
  output = ref:
    let
      found = builtins.tryEval (
        let
          package = pkgs.lib.attrByPath (pkgs.lib.splitString "." ref) null pkgs;
          out = if builtins.isAttrs package then package.out or package else null;
        in if builtins.isAttrs out && out ? outPath
           then builtins.toString out.outPath else null
      );
    in if found.success then found.value else null;
in builtins.listToAttrs (map (ref: {{ name = ref; value = output ref; }}) [ {refs} ])"#
    ))
}

/// `public_cache`, `software_cache`, `preparation_required`, or `None` when a
/// cache did not answer.
async fn output_status(
    client: &reqwest::Client,
    scanner: &Scanner,
    output: &str,
) -> Option<&'static str> {
    let hash = output.strip_prefix("/nix/store/")?.get(..32)?;
    let public = client
        .get(format!("{}/{hash}.narinfo", scanner.public_cache))
        .send()
        .await
        .ok()?
        .status();
    match public.as_u16() {
        200 => return Some("public_cache"),
        // cache.nixos.org answers 404 for an absent path, its bucket 403.
        403 | 404 => {}
        _ => return None,
    }
    let Some((origin, token)) = scanner.software_cache.as_ref() else {
        // This Nest has no access, so it prepares the package itself.
        return Some("preparation_required");
    };
    let software = client
        .get(format!("{origin}/{hash}.narinfo"))
        .basic_auth("nest", Some(token))
        .send()
        .await
        .ok()?
        .status();
    match software.as_u16() {
        200 => Some("software_cache"),
        404 => Some("preparation_required"),
        _ => None,
    }
}

/// Findings for the report: the newest successful scans of candidates Nest
/// still holds at commits it reports ready, within Manage's limits.
///
/// Manage replaces a Nest's package status for a commit with the list of
/// whichever finding it stores last, so every finding of a commit carries
/// the status of all scanned package refs at that commit.
pub(crate) async fn report(db: &SqlitePool, data_dir: &Path) -> Result<Vec<FindingReport>> {
    let jobs = sqlx::query_scalar::<_, i64>("SELECT id FROM nest_build_jobs")
        .fetch_all(db)
        .await?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut ready = BTreeMap::new();
    let mut rows = Vec::new();
    for (_, scan) in all_scans(data_dir) {
        if scan.state != "succeeded" || !jobs.contains(&scan.candidate_job_id) {
            continue;
        }
        let commit_ready = match ready.get(&scan.commit_rev) {
            Some(ready) => *ready,
            None => {
                let is_ready = super::detected_row(data_dir, &scan.commit_rev)
                    .await?
                    .is_some_and(|row| row.state == "ready");
                ready.insert(scan.commit_rev.clone(), is_ready);
                is_ready
            }
        };
        if commit_ready {
            rows.push(scan);
        }
    }
    rows.sort_by(|left, right| {
        right
            .scanned_at
            .cmp(&left.scanned_at)
            .then_with(|| left.commit_rev.cmp(&right.commit_rev))
            .then_with(|| left.blueprint_revision_id.cmp(&right.blueprint_revision_id))
    });
    rows.truncate(MAX_REPORTED_FINDINGS as usize);
    let mut delivery_by_commit: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut parsed = Vec::with_capacity(rows.len());
    for mut row in rows {
        let advisories = std::mem::take(&mut row.advisories);
        let delivery = std::mem::take(&mut row.package_delivery);
        // Rows are newest first: a newer scan's status of a ref wins.
        let merged = delivery_by_commit
            .entry(row.commit_rev.clone())
            .or_default();
        for item in delivery {
            merged.entry(item.package_ref).or_insert(item.status);
        }
        parsed.push((row, advisories));
    }
    let mut findings = Vec::with_capacity(parsed.len());
    let mut used = 0;
    for (row, mut advisories) in parsed {
        advisories.truncate(MAX_ADVISORIES);
        let package_delivery = delivery_by_commit
            .get(&row.commit_rev)
            .into_iter()
            .flatten()
            .take(MAX_PACKAGE_REFS)
            .map(|(package_ref, status)| PackageDelivery {
                package_ref: package_ref.clone(),
                status: status.clone(),
            })
            .collect();
        let finding = FindingReport {
            commit: row.commit_rev,
            blueprint_revision_id: row.blueprint_revision_id,
            scanned_at: row.scanned_at,
            advisories,
            package_delivery,
        };
        used += serde_json::to_vec(&finding)?.len();
        if used > MAX_REPORTED_FINDINGS_BYTES {
            break;
        }
        findings.push(finding);
    }
    Ok(findings)
}

#[cfg(test)]
#[path = "findings_tests.rs"]
mod tests;
