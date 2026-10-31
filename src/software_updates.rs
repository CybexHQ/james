//! Nest-driven software updates: the daily NixOS channel check.
//!
//! Once a day, at a random minute between 01:00 and 05:00 in the Nest's
//! update-schedule time zone, and when Manage asks
//! (`software_update_check_requested_at`), Nest reads the newest commit of its
//! NixOS channel. A commit it has not handled is evaluated, never built:
//!
//! 1. `nix flake metadata` records the commit's `lastModified` and `narHash`;
//!    every later fetch of the commit is pinned to that `narHash`.
//! 2. The commit identities of the source-build preflight are evaluated from
//!    the same nixpkgs attributes as the built-in profile
//!    (`software_updates/identities.nix`), together with the hashes of the
//!    reviewed builder files.
//! 3. The Tiaris packages (Manage's `tiaris-workstation-cache-seeds.nix`,
//!    evaluated with this commit's nixpkgs and the Tiaris source shipped with
//!    the Nest) are dry-run; only their top-level derivations may compile.
//! 4. The Blueprints this Nest built at its pin are dry-run at the pin and,
//!    with only nixpkgs replaced, at this commit. Each derivation admitted at
//!    the pin gives its counterpart's content to the commit's profile
//!    (`build/counterpart.rs`); then every one of those jobs must leave no
//!    unadmitted derivation at this commit.
//!
//! The result is a detected commit, `ready` or `blocked` with a reason.
//! Ready commits are admitted by `build_target`, selected by
//! `spec.nixpkgs_commit` in the preflight and reported to Manage.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Days, NaiveTime, TimeZone, Utc};
use rand::{Rng, RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, SqlitePool};
use tokio::{sync::Notify, time::sleep};
use tracing::{info, warn};

use crate::{
    AppState,
    build::{
        self, BUILTIN_LAST_MODIFIED, BUILTIN_NIXOS_RELEASE, DerivedIdentity,
        MAX_TIARIS_PACKAGE_DERIVATIONS, NixBuildCommand, ReviewedContent, WorkstationBuildProfile,
    },
    config::AppConfig,
    manage_source,
    nix_log::derivation_display_name,
    subprocess::run_bounded_command,
};

pub const DEFAULT_CHANNEL: &str = "nixos-26.05";
/// Report limit (Manage design §5).
pub(crate) const MAX_REPORTED_DETECTED_COMMITS: i64 = 32;
const MAX_REASON_DETAILS: usize = 50;
const CHANNEL_ORIGIN: &str = "https://channels.nixos.org";
const MAX_CHANNEL_RESPONSE_BYTES: usize = 128;
const BUILTIN_BLUEPRINT_PROFILES: [&str; 2] = ["taskbar", "dock"];
/// Blueprints of this Nest re-checked at a detected commit.
const MAX_RETAINED_BLUEPRINTS: usize = 8;
const SYSTEM_IDENTITY_PATH: &str = "/usr/share/tiaris-nest/system-identity.json";
const MAX_SYSTEM_IDENTITY_BYTES: u64 = 64 * 1024;
/// 01:00 local time, and the length of the daily window in minutes.
const DAILY_WINDOW_START_MINUTE: u32 = 60;
const DAILY_WINDOW_MINUTES: u32 = 240;
const ON_DEMAND_MIN_INTERVAL: chrono::Duration = chrono::Duration::minutes(10);
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);
const EVALUATION_TIMEOUT: Duration = Duration::from_secs(900);
const EVALUATION_STDOUT_MAX_BYTES: usize = 1024 * 1024;
const EVALUATION_STDERR_MAX_BYTES: usize = 1024 * 1024;
const IDENTITIES_NIX: &str = include_str!("software_updates/identities.nix");

pub(crate) const REASON_BUILD_SCRIPT_CHANGED: &str = "build_script_changed";
pub(crate) const REASON_SOURCE_BUILD_REQUIRED: &str = "source_build_required";
pub(crate) const REASON_EVALUATION_FAILED: &str = "evaluation_failed";

fn check_now() -> &'static Notify {
    static CHECK_NOW: OnceLock<Notify> = OnceLock::new();
    CHECK_NOW.get_or_init(Notify::new)
}

/// Nest follows only the channel of its own NixOS release; moving to the
/// next release is a Tiaris release.
fn supported_channel(channel: &str) -> bool {
    channel == format!("nixos-{BUILTIN_NIXOS_RELEASE}")
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Clone, Debug, Default, FromRow)]
struct CheckState {
    channel: Option<String>,
    check_requested_at: Option<String>,
    check_handled_at: Option<String>,
    last_checked_at: Option<String>,
}

async fn check_state(db: &SqlitePool) -> Result<CheckState> {
    Ok(sqlx::query_as::<_, CheckState>(
        "SELECT channel, check_requested_at, check_handled_at, last_checked_at
         FROM software_update_check_state WHERE id = 1",
    )
    .fetch_optional(db)
    .await?
    .unwrap_or_default())
}

fn parse_timestamp(value: Option<&str>) -> Option<DateTime<Utc>> {
    value
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

/// The software-update lane of the Nest configuration Manage sends. Both
/// fields are optional; an older Manage sends neither and Nest follows the
/// default channel on its daily schedule.
pub(crate) async fn apply_managed(
    db: &SqlitePool,
    channel: Option<&Value>,
    check_requested_at: Option<&Value>,
) -> Result<()> {
    let channel = match channel {
        None | Some(Value::Null) => None,
        Some(Value::String(channel)) if supported_channel(channel) => Some(channel.clone()),
        Some(_) => bail!(
            "software_update_channel must be nixos-{BUILTIN_NIXOS_RELEASE}; this Nest does not cross NixOS releases"
        ),
    };
    let requested = match check_requested_at {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(
            parse_timestamp(Some(value))
                .ok_or_else(|| anyhow!("software_update_check_requested_at is not RFC 3339"))?,
        ),
        Some(_) => bail!("software_update_check_requested_at must be a timestamp"),
    };
    let current = check_state(db).await?;
    let newer_request = requested.filter(|requested| {
        parse_timestamp(current.check_requested_at.as_deref())
            .is_none_or(|previous| *requested > previous)
    });
    sqlx::query(
        "INSERT INTO software_update_check_state (id, channel, check_requested_at)
         VALUES (1, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
             channel = excluded.channel,
             check_requested_at = COALESCE(excluded.check_requested_at, check_requested_at)",
    )
    .bind(&channel)
    .bind(newer_request.map(|value| value.to_rfc3339()))
    .execute(db)
    .await?;
    if newer_request.is_some() {
        check_now().notify_one();
    }
    Ok(())
}

#[derive(Clone, Debug, FromRow)]
struct DetectedRow {
    commit_rev: String,
    channel: String,
    last_modified: String,
    nar_hash: String,
    kernel_version: String,
    state: String,
    reason: Option<String>,
    profile: Option<String>,
    tiaris_derivations: String,
    detected_at: String,
}

/// One detected commit in the Nest report (protocol 5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct DetectedCommitReport {
    pub(crate) commit: String,
    pub(crate) channel: String,
    pub(crate) last_modified: String,
    pub(crate) nar_hash: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) kernel_version: String,
    pub(crate) state: String,
    /// Why a commit is blocked. The names behind it stay in the Nest's
    /// record (`reason_details`); Manage's wire carries the reason only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    pub(crate) detected_at: String,
}

impl From<DetectedRow> for DetectedCommitReport {
    fn from(row: DetectedRow) -> Self {
        Self {
            commit: row.commit_rev,
            channel: row.channel,
            last_modified: row.last_modified,
            nar_hash: row.nar_hash,
            kernel_version: row.kernel_version,
            state: row.state,
            reason: row.reason,
            detected_at: row.detected_at,
        }
    }
}

const DETECTED_COLUMNS: &str = "commit_rev, channel, last_modified, nar_hash, kernel_version, \
     state, reason, profile, tiaris_derivations, detected_at";

async fn detected_row(db: &SqlitePool, commit: &str) -> Result<Option<DetectedRow>> {
    Ok(sqlx::query_as::<_, DetectedRow>(&format!(
        "SELECT {DETECTED_COLUMNS} FROM detected_nixpkgs_commits WHERE commit_rev = ?"
    ))
    .bind(commit)
    .fetch_optional(db)
    .await?)
}

/// The Nest's full current list for the report; each report replaces the
/// previous one in Manage. Ready commits a Blueprint job still uses come
/// first, so the 32-entry limit never drops a commit this Nest builds; then
/// the newest.
pub(crate) async fn report(db: &SqlitePool) -> Result<Vec<DetectedCommitReport>> {
    Ok(sqlx::query_as::<_, DetectedRow>(&format!(
        "SELECT {DETECTED_COLUMNS} FROM detected_nixpkgs_commits AS detected
         ORDER BY (detected.state = 'ready' AND EXISTS (
                 SELECT 1 FROM nest_build_jobs AS jobs
                 WHERE json_valid(jobs.build_spec)
                   AND json_extract(jobs.build_spec, '$.nixpkgs_commit') = detected.commit_rev
             )) DESC,
             last_modified DESC, commit_rev
         LIMIT ?"
    ))
    .bind(MAX_REPORTED_DETECTED_COMMITS)
    .fetch_all(db)
    .await?
    .into_iter()
    .map(DetectedCommitReport::from)
    .collect())
}

/// A ready detected commit: the jobs it admits build with its derived
/// profile and with nixpkgs pinned to its recorded `narHash`.
pub(crate) struct ReadyCommit {
    pub(crate) commit: String,
    pub(crate) nar_hash: String,
    pub(crate) profile: WorkstationBuildProfile,
}

pub(crate) async fn ready_commit(db: &SqlitePool, commit: &str) -> Result<Option<ReadyCommit>> {
    let Some(row) = detected_row(db, commit).await? else {
        return Ok(None);
    };
    if row.state != "ready" {
        return Ok(None);
    }
    ready_commit_from_row(row).map(Some)
}

/// The derived profile of a ready commit as stored with its record.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredProfile {
    identities: BTreeMap<String, DerivedIdentity>,
    reviewed: ReviewedContent,
}

fn ready_commit_from_row(row: DetectedRow) -> Result<ReadyCommit> {
    let stored: StoredProfile = serde_json::from_str(
        row.profile
            .as_deref()
            .ok_or_else(|| anyhow!("ready detected commit has no build profile"))?,
    )
    .context("parse detected commit build profile")?;
    let tiaris: BTreeSet<String> = serde_json::from_str(&row.tiaris_derivations)
        .context("parse detected commit Tiaris packages")?;
    if !build::valid_nar_hash(&row.nar_hash) {
        bail!("detected commit narHash is invalid");
    }
    let last_modified = parse_timestamp(Some(&row.last_modified))
        .ok_or_else(|| anyhow!("detected commit lastModified is invalid"))?
        .timestamp();
    let profile = WorkstationBuildProfile::derived(
        &row.commit_rev,
        last_modified,
        &stored.identities,
        tiaris,
    )?
    .with_reviewed_content(&stored.reviewed)?;
    Ok(ReadyCommit {
        commit: row.commit_rev,
        nar_hash: row.nar_hash,
        profile,
    })
}

/// The commits this Nest can build: its release pins, the newest ready
/// detected commit, and every ready detected commit a Blueprint job it still
/// holds uses (the jobs of released Blueprints and open updates).
pub(crate) async fn workstation_nixpkgs_commits(state: &AppState) -> Vec<String> {
    let mut commits = crate::config::workstation_nixpkgs_commits(&state.config);
    if commits.is_empty() {
        return commits;
    }
    match ready_commits_in_use(&state.db).await {
        Ok(ready) => commits.extend(ready),
        Err(error) => warn!(error = %error, "could not read ready detected nixpkgs commits"),
    }
    commits.sort();
    commits.dedup();
    commits
}

async fn ready_commits_in_use(db: &SqlitePool) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT commit_rev FROM (
             SELECT commit_rev FROM detected_nixpkgs_commits WHERE state = 'ready'
             ORDER BY last_modified DESC, commit_rev LIMIT 1
         )
         UNION
         SELECT detected.commit_rev FROM detected_nixpkgs_commits AS detected
         WHERE detected.state = 'ready' AND EXISTS (
             SELECT 1 FROM nest_build_jobs AS jobs
             WHERE json_valid(jobs.build_spec)
               AND json_extract(jobs.build_spec, '$.nixpkgs_commit') = detected.commit_rev
         )",
    )
    .fetch_all(db)
    .await?)
}

/// Start the daily check. Only Nests that build Blueprints and report to
/// Manage check for updates.
pub fn spawn(state: AppState) {
    if !state.config.manage.enabled
        || crate::config::workstation_nixpkgs_commits(&state.config).is_empty()
    {
        return;
    }
    tokio::spawn(run(state));
}

async fn run(state: AppState) {
    let offset = rand::thread_rng().gen_range(0..DAILY_WINDOW_MINUTES);
    match check_state(&state.db).await {
        Ok(current) if pending_request(&current).is_some() => check_now().notify_one(),
        Ok(_) => {}
        Err(error) => warn!(error = %error, "could not read software update check state"),
    }
    loop {
        let timezone = crate::appliance::nixos::is_nixos()
            .then(crate::appliance::update_schedule::timezone)
            .flatten()
            .unwrap_or(chrono_tz::UTC);
        let now = Utc::now();
        let wait = (next_daily_check(now, timezone, offset) - now)
            .to_std()
            .unwrap_or_default();
        let on_demand = tokio::select! {
            _ = sleep(wait) => false,
            _ = check_now().notified() => true,
        };
        let current = check_state(&state.db).await.unwrap_or_default();
        let request = pending_request(&current);
        if on_demand
            && (request.is_none()
                || parse_timestamp(current.last_checked_at.as_deref())
                    .is_some_and(|last| Utc::now() - last < ON_DEMAND_MIN_INTERVAL))
        {
            // Duplicate wake-ups and requests within minutes of a check are
            // answered by the check that just ran.
            if let Some(request) = request {
                let _ = mark_checked(&state.db, Some(&request), None).await;
            }
            continue;
        }
        let outcome = match check(&state, on_demand).await {
            Ok(()) => Ok(()),
            Err(error) => {
                warn!(error = %error, "software update check failed");
                Err(format!("{error:#}").chars().take(500).collect::<String>())
            }
        };
        if let Err(error) = mark_checked(&state.db, request.as_deref(), Some(outcome)).await {
            warn!(error = %error, "could not record software update check");
        }
    }
}

fn pending_request(state: &CheckState) -> Option<String> {
    let requested = parse_timestamp(state.check_requested_at.as_deref())?;
    parse_timestamp(state.check_handled_at.as_deref())
        .is_none_or(|handled| requested > handled)
        .then(|| state.check_requested_at.clone())
        .flatten()
}

/// Record a handled request and, when a check ran (`outcome`), its result.
/// Only a check that completed moves `last_completed_at`.
async fn mark_checked(
    db: &SqlitePool,
    handled_request: Option<&str>,
    outcome: Option<std::result::Result<(), String>>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let ran = outcome.is_some();
    let completed = matches!(outcome, Some(Ok(())));
    let error = match outcome {
        Some(Err(error)) => error,
        _ => String::new(),
    };
    sqlx::query(
        "INSERT INTO software_update_check_state
             (id, check_handled_at, last_checked_at, last_completed_at, last_error)
         VALUES (1, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
             check_handled_at = COALESCE(excluded.check_handled_at, check_handled_at),
             last_checked_at = COALESCE(excluded.last_checked_at, last_checked_at),
             last_completed_at = COALESCE(excluded.last_completed_at, last_completed_at),
             last_error = CASE WHEN excluded.last_checked_at IS NULL
                 THEN last_error ELSE excluded.last_error END",
    )
    .bind(handled_request)
    .bind(ran.then_some(&now))
    .bind(completed.then_some(&now))
    .bind(error)
    .execute(db)
    .await?;
    Ok(())
}

/// When a channel check last completed, whether or not it found a new
/// commit (`software_update_checked_at`).
pub(crate) async fn checked_at(db: &SqlitePool) -> Result<Option<String>> {
    let value: Option<Option<String>> = sqlx::query_scalar(
        "SELECT last_completed_at FROM software_update_check_state WHERE id = 1",
    )
    .fetch_optional(db)
    .await?;
    Ok(parse_timestamp(value.flatten().as_deref())
        .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)))
}

/// The next daily check after `now`: 01:00 plus `offset_minutes` (below 240)
/// in `timezone`, today or tomorrow. A time skipped by a DST change runs an
/// hour later.
fn next_daily_check<Tz: TimeZone>(
    now: DateTime<Utc>,
    timezone: Tz,
    offset_minutes: u32,
) -> DateTime<Utc> {
    let minute = DAILY_WINDOW_START_MINUTE + offset_minutes % DAILY_WINDOW_MINUTES;
    let time = NaiveTime::from_hms_opt(minute / 60, minute % 60, 0).expect("minute within a day");
    let today = now.with_timezone(&timezone).date_naive();
    for date in [today, today + Days::new(1), today + Days::new(2)] {
        let local = date.and_time(time);
        let candidate = timezone
            .from_local_datetime(&local)
            .earliest()
            .or_else(|| {
                timezone
                    .from_local_datetime(&(local + chrono::Duration::hours(1)))
                    .earliest()
            })
            .map(|value| value.with_timezone(&Utc));
        if let Some(candidate) = candidate.filter(|candidate| *candidate > now) {
            return candidate;
        }
    }
    now + chrono::Duration::days(1)
}

/// Read the channel and handle its newest commit once. Network failures
/// record nothing, so the next check retries; an on-demand check also retries
/// a commit whose evaluation failed.
async fn check(state: &AppState, on_demand: bool) -> Result<()> {
    let channel = check_state(&state.db)
        .await?
        .channel
        .unwrap_or_else(|| DEFAULT_CHANNEL.to_string());
    if !supported_channel(&channel) {
        bail!("channel {channel} is not this Nest's NixOS release");
    }
    let commit = channel_revision(&channel).await?;
    if crate::config::workstation_nixpkgs_commits(&state.config).contains(&commit) {
        return Ok(());
    }
    let existing = detected_row(&state.db, &commit).await?;
    if existing
        .as_ref()
        .is_some_and(|row| !(on_demand && row.reason.as_deref() == Some(REASON_EVALUATION_FAILED)))
    {
        return Ok(());
    }
    let metadata = flake_metadata(
        &state.config,
        &commit,
        existing.as_ref().map(|row| row.nar_hash.as_str()),
    )
    .await?;
    if metadata.last_modified <= BUILTIN_LAST_MODIFIED {
        bail!("channel commit {commit} is not newer than the release pin");
    }
    let newest: Option<i64> = sqlx::query_scalar(
        "SELECT CAST(strftime('%s', MAX(last_modified)) AS INTEGER) FROM detected_nixpkgs_commits
         WHERE commit_rev != ?",
    )
    .bind(&commit)
    .fetch_one(&state.db)
    .await?;
    if newest.is_some_and(|newest| metadata.last_modified < newest) {
        bail!("channel commit {commit} is older than a commit this Nest already detected");
    }
    info!(%commit, %channel, "evaluating new NixOS channel commit");
    let outcome = evaluate_commit(&state.config, &state.db, &commit, &metadata).await?;
    store_detected(&state.db, &commit, &channel, &metadata, &outcome).await?;
    info!(%commit, state = outcome.state(), reason = outcome.reason, "recorded detected nixpkgs commit");
    Ok(())
}

async fn channel_revision(channel: &str) -> Result<String> {
    let url = format!("{CHANNEL_ORIGIN}/{channel}/git-revision");
    let response = crate::release_transport::get(&url, false, true, CHANNEL_TIMEOUT, None)
        .await
        .context("read NixOS channel revision")?;
    if !response.status().is_success() {
        bail!("NixOS channel revision returned {}", response.status());
    }
    let body = crate::bounded_io::response_bytes(response, MAX_CHANNEL_RESPONSE_BYTES)
        .await
        .context("read NixOS channel revision body")?;
    let commit = std::str::from_utf8(&body)
        .context("NixOS channel revision is not UTF-8")?
        .trim()
        .to_string();
    if !valid_commit(&commit) {
        bail!("NixOS channel revision is not a 40-character commit");
    }
    Ok(commit)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FlakeMetadata {
    path: String,
    last_modified: i64,
    nar_hash: String,
}

/// `nix flake metadata` of the commit, pinned to `known_nar_hash` when Nest
/// has fetched it before.
async fn flake_metadata(
    config: &AppConfig,
    commit: &str,
    known_nar_hash: Option<&str>,
) -> Result<FlakeMetadata> {
    let reference = build::nixpkgs_flake_ref(commit, known_nar_hash)?;
    let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
    command
        .args(["flake", "metadata", "--json", "--no-write-lock-file"])
        .args(["--option", "accept-flake-config", "false"])
        .arg(&reference)
        .env("LC_ALL", "C")
        .env("LANG", "C");
    let output = run_bounded_command(
        command,
        EVALUATION_TIMEOUT,
        EVALUATION_STDOUT_MAX_BYTES,
        EVALUATION_STDERR_MAX_BYTES,
        "nix flake metadata",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "nix flake metadata failed: {}",
            tail(&String::from_utf8_lossy(&output.stderr), 300)
        );
    }
    parse_flake_metadata(&output.stdout, commit, known_nar_hash)
}

fn parse_flake_metadata(
    stdout: &[u8],
    commit: &str,
    known_nar_hash: Option<&str>,
) -> Result<FlakeMetadata> {
    let value: Value = serde_json::from_slice(stdout).context("parse nix flake metadata")?;
    let locked = &value["locked"];
    let path = value["path"].as_str().unwrap_or_default();
    let nar_hash = locked["narHash"].as_str().unwrap_or_default();
    let last_modified = locked["lastModified"]
        .as_i64()
        .ok_or_else(|| anyhow!("nix flake metadata has no lastModified"))?;
    if locked["rev"].as_str() != Some(commit)
        || !build::valid_nar_hash(nar_hash)
        || known_nar_hash.is_some_and(|known| known != nar_hash)
        || build::store_path_item(path).is_none()
        || last_modified <= 0
    {
        bail!("nix flake metadata does not describe commit {commit} with its recorded narHash");
    }
    Ok(FlakeMetadata {
        path: path.to_string(),
        last_modified,
        nar_hash: nar_hash.to_string(),
    })
}

/// Outcome of evaluating one commit.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DetectedOutcome {
    kernel_version: String,
    reason: Option<&'static str>,
    details: Vec<String>,
    identities: Option<BTreeMap<String, DerivedIdentity>>,
    tiaris_derivations: BTreeSet<String>,
    /// Content derived from counterparts; stored only for ready commits.
    reviewed: ReviewedContent,
    counterparts: Option<build::Counterparts>,
    /// Local work of the Tiaris packages besides their own derivations.
    tiaris_dependencies: Vec<String>,
}

impl DetectedOutcome {
    fn state(&self) -> &'static str {
        if self.reason.is_none() {
            "ready"
        } else {
            "blocked"
        }
    }

    fn blocked(kernel_version: String, reason: &'static str, details: Vec<String>) -> Self {
        let mut details = details;
        details.truncate(MAX_REASON_DETAILS);
        Self {
            kernel_version,
            reason: Some(reason),
            details,
            identities: None,
            tiaris_derivations: BTreeSet::new(),
            reviewed: ReviewedContent::default(),
            counterparts: None,
            tiaris_dependencies: Vec::new(),
        }
    }
}

async fn store_detected(
    db: &SqlitePool,
    commit: &str,
    channel: &str,
    metadata: &FlakeMetadata,
    outcome: &DetectedOutcome,
) -> Result<()> {
    let last_modified = DateTime::<Utc>::from_timestamp(metadata.last_modified, 0)
        .ok_or_else(|| anyhow!("lastModified is out of range"))?
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let profile = outcome
        .identities
        .as_ref()
        .filter(|_| outcome.reason.is_none())
        .map(|identities| {
            serde_json::to_string(&StoredProfile {
                identities: identities.clone(),
                reviewed: outcome.reviewed.clone(),
            })
        })
        .transpose()?;
    sqlx::query(
        "INSERT INTO detected_nixpkgs_commits (
             commit_rev, channel, last_modified, nar_hash, kernel_version, state, reason,
             reason_details, profile, tiaris_derivations, detected_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(commit_rev) DO UPDATE SET
             kernel_version = excluded.kernel_version,
             state = excluded.state,
             reason = excluded.reason,
             reason_details = excluded.reason_details,
             profile = excluded.profile,
             tiaris_derivations = excluded.tiaris_derivations,
             detected_at = excluded.detected_at",
    )
    .bind(commit)
    .bind(channel)
    .bind(last_modified)
    .bind(&metadata.nar_hash)
    .bind(&outcome.kernel_version)
    .bind(outcome.state())
    .bind(outcome.reason)
    .bind(serde_json::to_string(&outcome.details)?)
    .bind(profile)
    .bind(serde_json::to_string(&outcome.tiaris_derivations)?)
    .bind(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    .execute(db)
    .await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluatedIdentities {
    release: String,
    kernel_version: String,
    files: BTreeMap<String, String>,
    identities: BTreeMap<String, DerivedIdentity>,
}

/// Evaluate the commit in a private work directory that is always removed.
/// Errors that are not about the commit itself (the work directory, the
/// shipped Tiaris source) are returned and record nothing.
async fn evaluate_commit(
    config: &AppConfig,
    db: &SqlitePool,
    commit: &str,
    metadata: &FlakeMetadata,
) -> Result<DetectedOutcome> {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let work = config
        .build
        .work_dir
        .join(format!("software-update-{}", hex::encode(nonce)));
    let manage_source_url = shipped_manage_source_url(config)?;
    create_private_dir(&work)?;
    let result = evaluate_commit_in(config, db, commit, metadata, &manage_source_url, &work).await;
    let _ = tokio::fs::remove_dir_all(&work).await;
    result
}

fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::create_dir_all(path.parent().unwrap_or(Path::new("/")))?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("create {}", path.display()))
}

fn write_private_file(path: PathBuf, contents: &str) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("write {}", path.display()))
}

async fn evaluate_commit_in(
    config: &AppConfig,
    db: &SqlitePool,
    commit: &str,
    metadata: &FlakeMetadata,
    manage_source_url: &str,
    work: &Path,
) -> Result<DetectedOutcome> {
    let evaluated = match evaluate_identities(config, &metadata.path, work).await {
        Ok(evaluated) => evaluated,
        Err(error) => {
            warn!(%commit, error = %error, "could not evaluate the commit's build identities");
            return Ok(DetectedOutcome::blocked(
                String::new(),
                REASON_EVALUATION_FAILED,
                vec!["build identities".to_string()],
            ));
        }
    };
    if evaluated.release != BUILTIN_NIXOS_RELEASE {
        bail!(
            "commit {commit} is NixOS {}, not {BUILTIN_NIXOS_RELEASE}; Nest does not cross releases",
            evaluated.release
        );
    }
    let kernel = evaluated
        .kernel_version
        .chars()
        .take(64)
        .collect::<String>();
    let identities_only = match WorkstationBuildProfile::derived(
        commit,
        metadata.last_modified,
        &evaluated.identities,
        BTreeSet::new(),
    ) {
        Ok(profile) => profile,
        Err(error) => {
            warn!(%commit, error = %error, "derived build identities are unusable");
            return Ok(DetectedOutcome::blocked(
                kernel,
                REASON_EVALUATION_FAILED,
                vec!["build identities".to_string()],
            ));
        }
    };

    let commit_flake = work.join("flake");
    let pin_flake = work.join("pin-flake");
    create_private_dir(&commit_flake)?;
    create_private_dir(&pin_flake)?;
    write_builtin_blueprint_flake(
        &commit_flake,
        &build::nixpkgs_flake_ref(commit, Some(&metadata.nar_hash))?,
        manage_source_url,
    )?;
    write_builtin_blueprint_flake(
        &pin_flake,
        &build::nixpkgs_flake_ref(build::BUILTIN_NIXPKGS_COMMIT, None)?,
        manage_source_url,
    )?;
    let installable = |flake: &Path, name: &str| {
        NixBuildCommand::for_dry_run(
            &config.build.nix_binary,
            format!("{}#packages.x86_64-linux.{name}", flake.display()),
        )
    };

    // Tiaris packages: only the top-level derivations themselves may compile.
    let tiaris = match build::unadmitted_local_derivations(
        config,
        &installable(&commit_flake, "tiaris-packages"),
        &identities_only,
    )
    .await
    {
        Ok(unadmitted) => unadmitted,
        Err(error) => {
            warn!(%commit, error = %error, "could not evaluate the Tiaris packages");
            return Ok(DetectedOutcome::blocked(
                kernel,
                REASON_EVALUATION_FAILED,
                vec!["tiaris-packages".to_string()],
            ));
        }
    };
    let (tiaris_derivations, tiaris_dependencies) =
        top_level_tiaris_packages(&tiaris, &evaluated.identities);
    if !tiaris_dependencies.is_empty() {
        info!(
            %commit,
            dependencies = ?tiaris_dependencies,
            "Tiaris package inputs that are neither cached nor top-level must be admitted by the ordinary rules"
        );
    }
    if tiaris_derivations.len() > MAX_TIARIS_PACKAGE_DERIVATIONS {
        return Ok(DetectedOutcome::blocked(
            kernel,
            REASON_SOURCE_BUILD_REQUIRED,
            tiaris_derivations
                .iter()
                .map(|path| derivation_display_name(path))
                .collect(),
        ));
    }
    let base = WorkstationBuildProfile::derived(
        commit,
        metadata.last_modified,
        &evaluated.identities,
        tiaris_derivations.clone(),
    )?;

    // The reference set: the Blueprints this Nest built at the pin, or the
    // built-in profiles when it has built none.
    let jobs = match build::retained_blueprint_commands(
        config,
        db,
        work,
        commit,
        &metadata.nar_hash,
        MAX_RETAINED_BLUEPRINTS,
    )
    .await
    {
        Ok(jobs) if !jobs.is_empty() => jobs,
        Ok(_) => BUILTIN_BLUEPRINT_PROFILES
            .iter()
            .map(|profile| build::ReferenceJob {
                label: profile.to_string(),
                pin: installable(&pin_flake, profile),
                detected: installable(&commit_flake, profile),
            })
            .collect(),
        Err(error) => {
            warn!(%commit, error = %format!("{error:#}"), "could not prepare this Nest's Blueprints");
            return Ok(DetectedOutcome::blocked(
                kernel,
                REASON_EVALUATION_FAILED,
                vec!["blueprints".to_string()],
            ));
        }
    };

    // Counterparts of everything admitted at the pin.
    let builtin = WorkstationBuildProfile::builtin();
    let mut counterparts = build::Counterparts::default();
    for job in &jobs {
        let pair = async {
            let pin = build::unadmitted_local_derivations(config, &job.pin, builtin).await?;
            let detected =
                build::unadmitted_local_derivations(config, &job.detected, &base).await?;
            anyhow::Ok((pin, detected))
        };
        match pair.await {
            Ok((pin, detected)) => {
                build::add_counterparts(&base, &evaluated.files, &pin, &detected, &mut counterparts)
            }
            Err(error) => {
                warn!(%commit, job = job.label, error = %format!("{error:#}"), "could not evaluate a reference job");
                return Ok(DetectedOutcome::blocked(
                    kernel,
                    REASON_EVALUATION_FAILED,
                    vec![job.label.clone()],
                ));
            }
        }
    }
    let content = counterparts.content();
    let profile = match base.clone().with_reviewed_content(&content) {
        Ok(profile) => profile,
        Err(error) => {
            warn!(%commit, error = %error, "counterpart content is unusable");
            return Ok(DetectedOutcome::blocked(
                kernel,
                REASON_EVALUATION_FAILED,
                vec!["counterparts".to_string()],
            ));
        }
    };
    info!(
        %commit,
        paired = counterparts.paired,
        changed = ?counterparts.changed,
        unpaired = ?counterparts.unpaired,
        builder_files = ?counterparts.builder_files,
        "derived reviewed content from counterparts"
    );

    // Readiness: every reference job at the commit under the full profile.
    let mut changed = BTreeSet::new();
    let mut compiles = Vec::new();
    for job in &jobs {
        let unadmitted = match build::unadmitted_local_derivations(config, &job.detected, &profile)
            .await
        {
            Ok(unadmitted) => unadmitted,
            Err(error) => {
                warn!(%commit, job = job.label, error = %format!("{error:#}"), "could not dry-run a Blueprint");
                return Ok(DetectedOutcome::blocked(
                    kernel,
                    REASON_EVALUATION_FAILED,
                    vec![job.label.clone()],
                ));
            }
        };
        let (scripts, others) = classify_unadmitted(&profile, &unadmitted);
        changed.extend(scripts);
        changed.extend(
            unadmitted
                .changed_builder_files
                .iter()
                .map(|name| name.to_string()),
        );
        for name in others {
            if !compiles.contains(&name) {
                compiles.push(name);
            }
        }
    }
    let mut outcome = decide(
        kernel,
        changed,
        compiles,
        evaluated.identities,
        tiaris_derivations,
    );
    if outcome.reason.is_none() {
        outcome.reviewed = content;
    }
    outcome.counterparts = Some(counterparts);
    outcome.tiaris_dependencies = tiaris_dependencies;
    Ok(outcome)
}

/// The Tiaris packages' own derivations (the inputs of the `tiaris-packages`
/// list that are not commit identities) among the local work, and the names
/// of the other local work their dry run lists: inputs that must be cached
/// or admitted by the ordinary rules.
fn top_level_tiaris_packages(
    dry_run: &build::UnadmittedDerivations,
    identities: &BTreeMap<String, DerivedIdentity>,
) -> (BTreeSet<String>, Vec<String>) {
    let identity_drvs = identities
        .values()
        .filter_map(|identity| identity.drv.as_deref())
        .collect::<BTreeSet<_>>();
    let local = dry_run.would_build.iter().collect::<BTreeSet<_>>();
    let list = dry_run
        .would_build
        .iter()
        .find(|path| path.ends_with("-tiaris-packages.drv"));
    let top_level = list
        .and_then(|path| dry_run.derivations.get(path))
        .and_then(build::derivation_input_drvs)
        .unwrap_or_default()
        .into_iter()
        .map(|(path, _)| path)
        .filter(|path| local.contains(path) && !identity_drvs.contains(path.as_str()))
        .collect::<BTreeSet<_>>();
    let dependencies = dry_run
        .would_build
        .iter()
        .filter(|path| Some(*path) != list && !top_level.contains(*path))
        .map(|path| derivation_display_name(path))
        .collect();
    (top_level, dependencies)
}

fn decide(
    kernel_version: String,
    changed: BTreeSet<String>,
    compiles: Vec<String>,
    identities: BTreeMap<String, DerivedIdentity>,
    tiaris_derivations: BTreeSet<String>,
) -> DetectedOutcome {
    if !changed.is_empty() {
        return DetectedOutcome::blocked(
            kernel_version,
            REASON_BUILD_SCRIPT_CHANGED,
            changed.into_iter().collect(),
        );
    }
    if !compiles.is_empty() {
        return DetectedOutcome::blocked(kernel_version, REASON_SOURCE_BUILD_REQUIRED, compiles);
    }
    DetectedOutcome {
        kernel_version,
        reason: None,
        details: Vec::new(),
        identities: Some(identities),
        tiaris_derivations,
        reviewed: ReviewedContent::default(),
        counterparts: None,
        tiaris_dependencies: Vec::new(),
    }
}

/// Split the derivations rejected on their own into changed reviewed scripts
/// (local materializers run by the commit's stdenv shell: their reviewed
/// content changed beyond store paths) and everything else, which would
/// compile. A derivation rejected only because a local input was rejected
/// (a stock `writeText` of a changed `system-path`) is not named.
fn classify_unadmitted(
    profile: &WorkstationBuildProfile,
    unadmitted: &build::UnadmittedDerivations,
) -> (BTreeSet<String>, Vec<String>) {
    let mut scripts = BTreeSet::new();
    let mut others = Vec::new();
    for path in &unadmitted.rejected_on_their_own {
        let name = derivation_display_name(path);
        if unadmitted
            .derivations
            .get(path)
            .is_some_and(|drv| build::derivation_is_local_script(profile, drv))
        {
            scripts.insert(name);
        } else if !others.contains(&name) {
            others.push(name);
        }
    }
    (scripts, others)
}

async fn evaluate_identities(
    config: &AppConfig,
    nixpkgs_path: &str,
    work: &Path,
) -> Result<EvaluatedIdentities> {
    let expression = work.join("identities.nix");
    write_private_file(expression.clone(), IDENTITIES_NIX)?;
    let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
    command
        .args(["eval", "--json", "--impure"])
        .args(["--option", "allow-import-from-derivation", "false"])
        .args(["--option", "accept-flake-config", "false"])
        .arg("--expr")
        .arg(format!(
            "import {} {{ nixpkgs = {nixpkgs_path}; }}",
            expression.display()
        ))
        .current_dir(work)
        .env("LC_ALL", "C")
        .env("LANG", "C");
    let output = run_bounded_command(
        command,
        EVALUATION_TIMEOUT,
        EVALUATION_STDOUT_MAX_BYTES,
        EVALUATION_STDERR_MAX_BYTES,
        "evaluate build identities",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "nix eval failed: {}",
            tail(&String::from_utf8_lossy(&output.stderr), 300)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse evaluated build identities")
}

#[derive(Deserialize)]
struct SystemIdentity {
    manage_source_revision: String,
}

/// The Tiaris source shipped with this Nest: the revision named by the
/// installed system identity, verified like installer-target builds.
fn shipped_manage_source_url(config: &AppConfig) -> Result<String> {
    use std::io::Read;
    let mut body = Vec::new();
    std::fs::File::open(SYSTEM_IDENTITY_PATH)
        .context("open installed system identity")?
        .take(MAX_SYSTEM_IDENTITY_BYTES)
        .read_to_end(&mut body)?;
    let identity: SystemIdentity =
        serde_json::from_slice(&body).context("parse installed system identity")?;
    if !valid_commit(&identity.manage_source_revision) {
        bail!("installed system identity has no Tiaris source revision");
    }
    Ok(manage_source::verify_revision(
        &config.build.manage_source_url_template,
        &identity.manage_source_revision,
        config.workstation_netboot.allow_private_release_urls,
    )
    .context("verify shipped Tiaris source")?
    .url)
}

/// The flake the check dry-runs: the Tiaris packages and each built-in
/// Blueprint, configured by the same Nest templates as Blueprint jobs.
fn write_builtin_blueprint_flake(work: &Path, nixpkgs_ref: &str, manage_url: &str) -> Result<()> {
    for (name, contents) in build::blueprint_job_template_files() {
        write_private_file(work.join(name), &contents)?;
    }
    write_private_file(work.join("blueprint.nix"), "{ ... }:\n\n{ }\n")?;
    write_private_file(
        work.join("tiaris-blueprints.nix"),
        "{ manageSource, ... }:\n\n{\n  imports = [ (manageSource + \"/deploy/nixos/tiaris-blueprints.nix\") ];\n}\n",
    )?;
    write_private_file(
        work.join("flake.nix"),
        &builtin_blueprint_flake(nixpkgs_ref, manage_url),
    )
}

fn builtin_blueprint_flake(nixpkgs_ref: &str, manage_url: &str) -> String {
    let nixpkgs = serde_json::to_string(nixpkgs_ref).expect("string serializes");
    let manage = serde_json::to_string(manage_url).expect("string serializes");
    let blueprints = BUILTIN_BLUEPRINT_PROFILES
        .iter()
        .fold(String::new(), |mut lines, profile| {
            use std::fmt::Write;
            let _ = writeln!(lines, "        {profile} = blueprint \"{profile}\";");
            lines
        });
    format!(
        r#"{{
  description = "Tiaris Nest software update check";

  inputs.nixpkgs.url = {nixpkgs};
  inputs.manage = {{
    url = {manage};
    flake = false;
  }};

  outputs = {{ self, nixpkgs, manage }}:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {{ inherit system; }};
      workstationAgent = import (manage + "/deploy/nixos/tiaris-agent-package.nix") {{
        inherit pkgs;
        repoRoot = manage;
      }};
      seeds = import (manage + "/deploy/nixos/tiaris-workstation-cache-seeds.nix") {{
        inherit pkgs system workstationAgent;
        nixpkgs = nixpkgs.outPath;
        manageRepo = manage;
      }};
      blueprint = profile:
        (nixpkgs.lib.nixosSystem {{
          inherit system;
          specialArgs.manageSource = manage;
          modules = [
            ./configuration.nix
            {{ tiaris.desktop.profile = profile; }}
          ];
        }}).config.system.build.toplevel;
    in {{
      packages.${{system}} = {{
        tiaris-packages = pkgs.writeText "tiaris-packages"
          (builtins.concatStringsSep "\n" (map (package: package.outPath) ([ workstationAgent ] ++ seeds.packages)));
{blueprints}      }};
    }};
}}
"#
    )
}

fn tail(text: &str, max_chars: usize) -> String {
    let skip = text.chars().count().saturating_sub(max_chars);
    text.chars().skip(skip).collect()
}

#[cfg(test)]
mod tests;
