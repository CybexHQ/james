//! Vulnerability scans and package status of update candidates (Manage
//! `docs/design/nest-driven-software-updates.md`, section 4).
//!
//! Manage prepares an update-only candidate of each released Blueprint as
//! soon as Nest reports a ready detected commit, and Nest builds it through
//! the ordinary build-job path. Once the candidate's closure is built, Nest:
//!
//! 1. finds the closure of the release the candidate was prepared from,
//!    named by `software_update.release_blueprint_revision_id` on the build
//!    job; a candidate without it is skipped (`missing_release_hint`) until
//!    Manage names it, so a finding never compares against a guessed release;
//! 2. scans the runtime closure of both with vulnix (`--closure`), at low CPU
//!    and I/O priority under a memory and time limit, with its NVD database
//!    cached in the Nest state directory; both scans must see the same
//!    database;
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

use anyhow::{Context, Result, anyhow, bail};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, SqlitePool};
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
const NVD_DATABASE_FILE: &str = "Data.fs";

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

#[derive(Debug, Deserialize)]
struct VulnixEntry {
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

/// Advisory id → advisory, from `vulnix --json`. An advisory reported for
/// several packages keeps the first package by name.
pub(crate) fn vulnix_advisories(stdout: &[u8]) -> Result<BTreeMap<String, Advisory>> {
    let mut entries: Vec<VulnixEntry> =
        serde_json::from_slice(stdout).context("parse vulnix JSON")?;
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
    Ok(found)
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
#[derive(Clone, Debug)]
pub(crate) struct Scanner {
    nix: String,
    vulnix: String,
    vulnix_cache: PathBuf,
    public_cache: String,
    /// Origin and read token of the Tiaris software cache, from the netrc
    /// file Manage's access keeps current.
    software_cache: Option<(String, String)>,
    memory_limit_bytes: u64,
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
        })
    }
}

/// Generic Blueprint closures: installer-target jobs carry a workstation's
/// hardware and are not what the release or the update installs as such.
const BLUEPRINT_JOB_FILTER: &str = "status = 'succeeded' AND output_path != ''
     AND json_valid(build_spec)
     AND json_extract(build_spec, '$.build_input.kind') = 'blueprint_nixos_module'
     AND COALESCE(json_type(build_spec, '$.build_input.installer_target'), 'null') = 'null'
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
    db: &SqlitePool,
    managed_job_id: &str,
    software_update: Option<&Value>,
) -> Result<()> {
    let release = software_update
        .and_then(|value| value.get("release_blueprint_revision_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .map(|value| value.hyphenated().to_string());
    match release {
        Some(release) => {
            sqlx::query(
                "INSERT INTO software_update_candidate_hints
                     (managed_job_id, release_blueprint_revision_id) VALUES (?, ?)
                 ON CONFLICT(managed_job_id) DO UPDATE SET
                     release_blueprint_revision_id = excluded.release_blueprint_revision_id",
            )
            .bind(managed_job_id)
            .bind(release)
            .execute(db)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM software_update_candidate_hints WHERE managed_job_id = ?")
                .bind(managed_job_id)
                .execute(db)
                .await?;
        }
    }
    Ok(())
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
    prune(&state.db).await?;
    let mut scanned = 0;
    loop {
        if build_running(&state.db).await? {
            return Ok(scanned);
        }
        let release_pins = crate::config::workstation_nixpkgs_commits(&state.config);
        let Some(candidate) = next_candidate(&state.db, &release_pins, Utc::now()).await? else {
            return Ok(scanned);
        };
        let scanner = Scanner::from_config(&state.config);
        if !scan_and_record(&state.db, &scanner, &candidate).await? {
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

/// Scans and hints of jobs Nest no longer holds go with them.
async fn prune(db: &SqlitePool) -> Result<()> {
    sqlx::query(
        "DELETE FROM software_update_scans
         WHERE candidate_job_id NOT IN (SELECT id FROM nest_build_jobs)",
    )
    .execute(db)
    .await?;
    sqlx::query(
        "DELETE FROM software_update_candidate_hints WHERE managed_job_id NOT IN
             (SELECT managed_job_id FROM nest_build_jobs WHERE managed_job_id IS NOT NULL)",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// A built candidate: a Blueprint job at a ready detected commit (not a
/// release pin) whose commit and revision have no scan yet, only a failed
/// one due for a retry, or a skipped one whose job now names its release.
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
    release_pins: &[String],
    now: chrono::DateTime<Utc>,
) -> Result<Option<Candidate>> {
    let rows = sqlx::query_as::<_, JobRow>(&format!(
        "SELECT {JOB_COLUMNS} FROM nest_build_jobs AS jobs
         WHERE {BLUEPRINT_JOB_FILTER}
           AND EXISTS (SELECT 1 FROM detected_nixpkgs_commits AS detected
                       WHERE detected.commit_rev = json_extract(jobs.build_spec, '$.nixpkgs_commit')
                         AND detected.state = 'ready')
           AND NOT EXISTS (SELECT 1 FROM software_update_scans AS scans
                           WHERE scans.commit_rev = json_extract(jobs.build_spec, '$.nixpkgs_commit')
                             AND scans.blueprint_revision_id
                                 = json_extract(jobs.build_spec, '$.blueprint_revision_id')
                             AND (scans.state = 'succeeded'
                                  OR (scans.state = 'failed'
                                      AND (scans.attempts >= ? OR scans.scanned_at > ?))
                                  OR (scans.state = 'skipped' AND NOT EXISTS (
                                      SELECT 1 FROM software_update_candidate_hints AS hints
                                      WHERE hints.managed_job_id = jobs.managed_job_id))))
         ORDER BY completed_at, id"
    ))
    .bind(MAX_ATTEMPTS)
    .bind(timestamp(now - RETRY_INTERVAL))
    .fetch_all(db)
    .await?;
    for row in rows {
        let Some(job) = Job::from_row(&row) else {
            continue;
        };
        if release_pins.contains(&job.commit) {
            continue;
        }
        let Some(nar_hash) = super::current_ready_nar_hash(db, &job.commit).await? else {
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
async fn release_hint(db: &SqlitePool, candidate: &Candidate) -> Result<Option<String>> {
    let Some(managed) = candidate.job.managed_job_id.as_deref() else {
        return Ok(None);
    };
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT release_blueprint_revision_id FROM software_update_candidate_hints
         WHERE managed_job_id = ?",
    )
    .bind(managed)
    .fetch_optional(db)
    .await?)
}

/// The built closure of `release`, the revision the candidate was prepared
/// from, at another commit.
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
    Ok(rows.iter().find_map(Job::from_row))
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
    scanner: &Scanner,
    candidate: &Candidate,
) -> Result<bool> {
    let outcome = scan(db, scanner, candidate).await?;
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
    let attempt = i64::from(state == "failed");
    sqlx::query(
        "INSERT INTO software_update_scans (
             commit_rev, blueprint_revision_id, candidate_job_id, release_job_id, state,
             reason, detail, attempts, advisories, package_delivery, scanned_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(commit_rev, blueprint_revision_id) DO UPDATE SET
             candidate_job_id = excluded.candidate_job_id,
             release_job_id = excluded.release_job_id,
             state = excluded.state,
             reason = excluded.reason,
             detail = excluded.detail,
             attempts = attempts + excluded.attempts,
             advisories = excluded.advisories,
             package_delivery = excluded.package_delivery,
             scanned_at = excluded.scanned_at",
    )
    .bind(&candidate.job.commit)
    .bind(&candidate.job.blueprint_revision_id)
    .bind(candidate.job.id)
    .bind(outcome.release_job_id)
    .bind(state)
    .bind(reason)
    .bind(detail)
    .bind(attempt)
    .bind(serde_json::to_string(&advisories)?)
    .bind(serde_json::to_string(&delivery)?)
    .bind(now)
    .execute(db)
    .await?;
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
async fn scan(db: &SqlitePool, scanner: &Scanner, candidate: &Candidate) -> Result<ScanOutcome> {
    let Some(release) = release_hint(db, candidate).await? else {
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
    for path in [&release.output_path, &candidate.job.output_path] {
        if let Err(failure) = check_derivers(scanner, path).await {
            return Ok(ScanOutcome::failed(release_job_id, failure));
        }
    }
    // Both closures must be judged by the same NVD data. vulnix refreshes its
    // database at most every two hours, before it scans; if the candidate's
    // run changed it, the release is scanned again with what the candidate
    // saw.
    let mut scanned = Vec::with_capacity(3);
    let mut paths = vec![&release.output_path, &candidate.job.output_path];
    let mut stamp = nvd_stamp(scanner);
    while let Some(path) = paths.first().copied() {
        if build_running(db).await? {
            return Ok(ScanOutcome {
                release_job_id,
                result: ScanResult::Deferred,
            });
        }
        match run_vulnix(scanner, path).await {
            Ok(advisories) => scanned.push(advisories),
            Err(error) => {
                return Ok(ScanOutcome::failed(
                    release_job_id,
                    ScanFailure::new(REASON_SCAN_FAILED, format!("{error:#}")),
                ));
            }
        }
        paths.remove(0);
        let current = nvd_stamp(scanner);
        if scanned.len() >= 2 && current != stamp {
            if scanned.len() == 3 {
                return Ok(ScanOutcome::failed(
                    release_job_id,
                    ScanFailure::new(
                        REASON_SCAN_FAILED,
                        "the NVD database changed between the two scans twice",
                    ),
                ));
            }
            paths.push(&release.output_path);
        }
        stamp = current;
    }
    let release_scan = scanned
        .last()
        .filter(|_| scanned.len() == 3)
        .unwrap_or(&scanned[0]);
    let fixed = fixed_advisories(release_scan, &scanned[1]);
    let delivery = match package_delivery(scanner, candidate).await {
        Ok(delivery) => delivery,
        Err(failure) => return Ok(ScanOutcome::failed(release_job_id, failure)),
    };
    Ok(ScanOutcome {
        release_job_id,
        result: ScanResult::Succeeded(fixed, delivery),
    })
}

/// Size and modification time of vulnix's database; vulnix rewrites it only
/// when the NVD data changes (or it packs it).
fn nvd_stamp(scanner: &Scanner) -> Option<(u64, std::time::SystemTime)> {
    let metadata = std::fs::metadata(scanner.vulnix_cache.join(NVD_DATABASE_FILE)).ok()?;
    Some((metadata.len(), metadata.modified().ok()?))
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

/// The closure must be in the store, and vulnix must find the derivation of
/// nearly every path in it. Like vulnix, a path whose recorded deriver is
/// gone counts when a valid derivation in the store declares it as output.
async fn check_derivers(scanner: &Scanner, path: &str) -> std::result::Result<(), ScanFailure> {
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
    let recovered = valid_deriver_outputs(scanner, &missing)
        .await
        .map_err(|error| ScanFailure::new(REASON_DERIVATIONS_UNAVAILABLE, format!("{error:#}")))?;
    let present = total - missing.len()
        + missing
            .iter()
            .filter(|path| recovered.contains(*path))
            .count();
    if total == 0 || present * 100 < total * MIN_DERIVER_COVERAGE_PERCENT {
        return Err(ScanFailure::new(
            REASON_DERIVATIONS_UNAVAILABLE,
            format!("{present} of {total} closure paths have their derivation in the store"),
        ));
    }
    Ok(())
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

/// Outputs declared by the valid derivations of `paths`
/// (`nix-store --query --valid-derivers`, then `nix derivation show`).
async fn valid_deriver_outputs(scanner: &Scanner, paths: &[String]) -> Result<BTreeSet<String>> {
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
    let mut outputs = BTreeSet::new();
    for chunk in derivers.chunks(CHUNK) {
        let mut args = vec!["derivation", "show"];
        args.extend(chunk.iter().map(String::as_str));
        let shown = nix_json(scanner, &args).await?;
        let shown = shown.get("derivations").unwrap_or(&shown);
        for derivation in shown.as_object().into_iter().flat_map(|map| map.values()) {
            for output in derivation
                .get("outputs")
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|map| map.values())
            {
                if let Some(path) = output.get("path").and_then(Value::as_str) {
                    outputs.insert(absolute_store_path(path));
                }
            }
        }
    }
    Ok(outputs)
}

/// `vulnix --json --closure` of one closure at idle priority.
async fn run_vulnix(scanner: &Scanner, path: &str) -> Result<BTreeMap<String, Advisory>> {
    create_private_dir(&scanner.vulnix_cache)?;
    let mut command = scanner.command(&scanner.vulnix);
    command.args(["--json", "--closure", "--cache-dir"]);
    command.arg(&scanner.vulnix_cache);
    command.arg(path);
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
    vulnix_advisories(&output.stdout)
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

#[derive(Debug, FromRow)]
struct ScanRow {
    commit_rev: String,
    blueprint_revision_id: String,
    advisories: String,
    package_delivery: String,
    scanned_at: String,
}

/// Findings for the report: the newest successful scans of candidates Nest
/// still holds at commits it reports ready, within Manage's limits.
///
/// Manage replaces a Nest's package status for a commit with the list of
/// whichever finding it stores last, so every finding of a commit carries
/// the status of all scanned package refs at that commit.
pub(crate) async fn report(db: &SqlitePool) -> Result<Vec<FindingReport>> {
    let rows = sqlx::query_as::<_, ScanRow>(
        "SELECT scans.commit_rev, scans.blueprint_revision_id, scans.advisories,
                scans.package_delivery, scans.scanned_at
         FROM software_update_scans AS scans
         JOIN detected_nixpkgs_commits AS detected
           ON detected.commit_rev = scans.commit_rev AND detected.state = 'ready'
         WHERE scans.state = 'succeeded'
           AND EXISTS (SELECT 1 FROM nest_build_jobs AS jobs
                       WHERE jobs.id = scans.candidate_job_id)
         ORDER BY scans.scanned_at DESC, scans.commit_rev, scans.blueprint_revision_id
         LIMIT ?",
    )
    .bind(MAX_REPORTED_FINDINGS)
    .fetch_all(db)
    .await?;
    let mut delivery_by_commit: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let advisories: Vec<Advisory> = serde_json::from_str(&row.advisories)
            .with_context(|| anyhow!("parse stored advisories of {}", row.commit_rev))?;
        let delivery: Vec<PackageDelivery> = serde_json::from_str(&row.package_delivery)
            .with_context(|| anyhow!("parse stored package status of {}", row.commit_rev))?;
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
