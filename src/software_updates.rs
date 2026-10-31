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
/// Desktop profiles of the shipped `tiaris-blueprints.nix`, used as plain
/// references next to the shipped reference Blueprints.
const BUILTIN_BLUEPRINT_PROFILES: [&str; 2] = ["taskbar", "dock"];
/// Directory of the shipped Tiaris source holding the built-in Blueprints'
/// compiler exports, one `<name>/{blueprint.nix,desktop.nix}` each.
const REFERENCE_BLUEPRINTS_DIR: &str = "deploy/nixos/reference-blueprints";
const MAX_REFERENCE_BLUEPRINTS: usize = 16;
/// Wall-clock bound on evaluating one commit.
const CHECK_TIME_LIMIT: Duration = Duration::from_secs(60 * 60);
/// A commit whose evaluation or provenance failed is retried at most daily,
/// whoever asks; a request only repeats the channel lookup.
const RETRY_INTERVAL: chrono::Duration = chrono::Duration::hours(24);
/// Ready commits derived by another Nest build are derived again, a few per
/// check.
const MAX_REDERIVED_PER_CHECK: usize = 2;
/// Version of the stored profile format and derivation rules.
const PROFILE_SCHEMA: u32 = 2;
const GITHUB_COMPARE: &str = "https://api.github.com/repos/NixOS/nixpkgs/compare";
const MAX_GITHUB_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
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
/// The commit could not be shown to be on the channel's branch of
/// NixOS/nixpkgs after the release pin.
pub(crate) const REASON_PROVENANCE_UNVERIFIED: &str = "provenance_unverified";
/// The shipped Tiaris source has no reference Blueprints to derive reviewed
/// content from.
pub(crate) const REASON_REFERENCE_BLUEPRINTS_MISSING: &str = "reference_blueprints_missing";

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

/// The derived profile of a ready commit as stored with its record, with the
/// rules and the Nest build that derived it. A profile from another schema
/// or build is derived again, never re-mapped.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredProfile {
    schema: u32,
    nest_build: String,
    identities: BTreeMap<String, DerivedIdentity>,
    reviewed: ReviewedContent,
}

impl StoredProfile {
    fn is_current(&self) -> bool {
        self.schema == PROFILE_SCHEMA && self.nest_build == nest_build_identity()
    }
}

/// This Nest build: its version and the release, source and Tiaris source
/// revisions of the installed system.
fn nest_build_identity() -> String {
    #[derive(Deserialize)]
    struct Installed {
        #[serde(default)]
        release_id: String,
        #[serde(default)]
        source_revision: String,
        #[serde(default)]
        manage_source_revision: String,
    }
    let installed = std::fs::read(SYSTEM_IDENTITY_PATH)
        .ok()
        .filter(|body| body.len() as u64 <= MAX_SYSTEM_IDENTITY_BYTES)
        .and_then(|body| serde_json::from_slice::<Installed>(&body).ok());
    match installed {
        Some(installed) => format!(
            "{} release={} source={} tiaris={}",
            env!("CARGO_PKG_VERSION"),
            installed.release_id,
            installed.source_revision,
            installed.manage_source_revision
        ),
        None => format!("{} release=unknown", env!("CARGO_PKG_VERSION")),
    }
}

fn ready_commit_from_row(row: DetectedRow) -> Result<ReadyCommit> {
    let stored: StoredProfile = serde_json::from_str(
        row.profile
            .as_deref()
            .ok_or_else(|| anyhow!("ready detected commit has no build profile"))?,
    )
    .context("parse detected commit build profile")?;
    if !stored.is_current() {
        bail!("detected commit profile was derived by another Nest build; it is derived again");
    }
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
    // After an update of this Nest, ready commits are derived again soon
    // rather than waiting for the daily check; until then they admit nothing.
    if stale_ready_rows(&state.db)
        .await
        .is_ok_and(|rows| !rows.is_empty())
    {
        if let Err(error) = check(&state).await {
            warn!(error = %error, "software update check after an update of this Nest failed");
        }
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
        let outcome = match check(&state).await {
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

/// Read the channel and handle its newest commit, then derive again a few
/// ready commits whose profile another Nest build derived. A commit already
/// recorded is evaluated again only when its evaluation or provenance failed
/// at least a day ago; a request from Manage repeats only the channel lookup.
/// Network failures before evaluation record nothing.
async fn check(state: &AppState) -> Result<()> {
    let channel = check_state(&state.db)
        .await?
        .channel
        .unwrap_or_else(|| DEFAULT_CHANNEL.to_string());
    if !supported_channel(&channel) {
        bail!("channel {channel} is not this Nest's NixOS release");
    }
    let commit = channel_revision(&channel).await?;
    if !crate::config::workstation_nixpkgs_commits(&state.config).contains(&commit) {
        let existing = detected_row(&state.db, &commit).await?;
        if needs_evaluation(existing.as_ref(), Utc::now()) {
            evaluate_and_record(state, &channel, &commit, existing.as_ref(), true).await?;
        }
    }
    for row in stale_ready_rows(&state.db)
        .await?
        .into_iter()
        .take(MAX_REDERIVED_PER_CHECK)
    {
        info!(commit = %row.commit_rev, "deriving a ready commit's profile again for this Nest build");
        evaluate_and_record(
            state,
            &row.channel.clone(),
            &row.commit_rev.clone(),
            Some(&row),
            false,
        )
        .await?;
    }
    Ok(())
}

fn needs_evaluation(existing: Option<&DetectedRow>, now: DateTime<Utc>) -> bool {
    existing.is_none_or(|row| {
        matches!(
            row.reason.as_deref(),
            Some(REASON_EVALUATION_FAILED | REASON_PROVENANCE_UNVERIFIED)
        ) && parse_timestamp(Some(&row.detected_at))
            .is_none_or(|detected| now - detected >= RETRY_INTERVAL)
    })
}

/// Ready commits whose stored profile is from another schema or Nest build.
async fn stale_ready_rows(db: &SqlitePool) -> Result<Vec<DetectedRow>> {
    Ok(sqlx::query_as::<_, DetectedRow>(&format!(
        "SELECT {DETECTED_COLUMNS} FROM detected_nixpkgs_commits WHERE state = 'ready'
         ORDER BY last_modified DESC, commit_rev"
    ))
    .fetch_all(db)
    .await?
    .into_iter()
    .filter(|row| {
        !row.profile
            .as_deref()
            .and_then(|profile| serde_json::from_str::<StoredProfile>(profile).ok())
            .is_some_and(|stored| stored.is_current())
    })
    .collect())
}

async fn evaluate_and_record(
    state: &AppState,
    channel: &str,
    commit: &str,
    existing: Option<&DetectedRow>,
    channel_head: bool,
) -> Result<()> {
    let metadata = flake_metadata(
        &state.config,
        commit,
        existing.map(|row| row.nar_hash.as_str()),
    )
    .await?;
    if metadata.last_modified <= BUILTIN_LAST_MODIFIED {
        bail!("channel commit {commit} is not newer than the release pin");
    }
    if channel_head {
        let newest: Option<i64> = sqlx::query_scalar(
            "SELECT CAST(strftime('%s', MAX(last_modified)) AS INTEGER) FROM detected_nixpkgs_commits
             WHERE commit_rev != ?",
        )
        .bind(commit)
        .fetch_one(&state.db)
        .await?;
        if newest.is_some_and(|newest| metadata.last_modified < newest) {
            bail!("channel commit {commit} is older than a commit this Nest already detected");
        }
    }
    let outcome = match verify_provenance(channel, commit).await {
        Err(error) => {
            warn!(%commit, error = %format!("{error:#}"), "could not verify the commit's provenance");
            DetectedOutcome::blocked(
                String::new(),
                REASON_PROVENANCE_UNVERIFIED,
                vec![format!("{error:#}").chars().take(200).collect()],
            )
        }
        Ok(()) => {
            info!(%commit, %channel, "evaluating NixOS channel commit");
            match tokio::time::timeout(
                CHECK_TIME_LIMIT,
                evaluate_commit(&state.config, commit, &metadata),
            )
            .await
            {
                Ok(outcome) => outcome?,
                Err(_) => {
                    warn!(%commit, "evaluating the commit exceeded its time limit");
                    DetectedOutcome::blocked(
                        String::new(),
                        REASON_EVALUATION_FAILED,
                        vec!["time limit".to_string()],
                    )
                }
            }
        }
    };
    store_detected(&state.db, commit, channel, &metadata, &outcome).await?;
    info!(%commit, state = outcome.state(), reason = outcome.reason, "recorded detected nixpkgs commit");
    Ok(())
}

/// The commit is on the channel's branch of NixOS/nixpkgs (an ancestor of,
/// or the same as, its tip) and descends from the release pin. A fork-only
/// commit diverges from the branch. Any failure leaves the commit unverified.
async fn verify_provenance(channel: &str, commit: &str) -> Result<()> {
    let on_branch = github_compare(commit, channel).await?;
    if !matches!(on_branch.as_str(), "ahead" | "identical") {
        bail!("{commit} is not on NixOS/nixpkgs {channel} (compare status {on_branch})");
    }
    let after_pin = github_compare(build::BUILTIN_NIXPKGS_COMMIT, commit).await?;
    if after_pin != "ahead" {
        bail!("{commit} does not descend from the release pin (compare status {after_pin})");
    }
    Ok(())
}

/// GitHub's comparison of `base...head` on NixOS/nixpkgs: `ahead` when head
/// descends from base, `identical`, `behind` or `diverged`.
async fn github_compare(base: &str, head: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(CHANNEL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("tiaris-nest/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build GitHub client")?;
    let response = client
        .get(format!("{GITHUB_COMPARE}/{base}...{head}?per_page=1"))
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .context("compare commits on GitHub")?;
    if !response.status().is_success() {
        bail!("GitHub compare returned {}", response.status());
    }
    let body = crate::bounded_io::response_bytes(response, MAX_GITHUB_RESPONSE_BYTES).await?;
    compare_status(&body)
}

fn compare_status(body: &[u8]) -> Result<String> {
    let value: Value = serde_json::from_slice(body).context("parse GitHub compare")?;
    match value.get("status").and_then(Value::as_str) {
        Some(status @ ("ahead" | "behind" | "identical" | "diverged")) => Ok(status.to_string()),
        _ => bail!("GitHub compare has no status"),
    }
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
    /// Local derivations of the Tiaris packages' build closure.
    tiaris_closure_size: usize,
    /// Per reference: local work at the commit and roles the pin did not
    /// cover.
    coverage: Vec<String>,
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
            tiaris_closure_size: 0,
            coverage: Vec::new(),
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
                schema: PROFILE_SCHEMA,
                nest_build: nest_build_identity(),
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
    let result = evaluate_commit_in(config, commit, metadata, &manage_source_url, &work).await;
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
    let blocked = |reason: &'static str, details: Vec<String>| {
        DetectedOutcome::blocked(kernel.clone(), reason, details)
    };
    let identities_only = match WorkstationBuildProfile::derived(
        commit,
        metadata.last_modified,
        &evaluated.identities,
        BTreeSet::new(),
    ) {
        Ok(profile) => profile,
        Err(error) => {
            warn!(%commit, error = %error, "derived build identities are unusable");
            return Ok(blocked(
                REASON_EVALUATION_FAILED,
                vec!["build identities".to_string()],
            ));
        }
    };

    // Everything below is evaluated from the shipped Tiaris source and
    // nixpkgs (the commit, narHash-pinned, or the pin): never from an
    // organization's Blueprint.
    let commit_flake = work.join("flake");
    let pin_flake = work.join("pin-flake");
    create_private_dir(&commit_flake)?;
    create_private_dir(&pin_flake)?;
    write_reference_flake(
        &commit_flake,
        &build::nixpkgs_flake_ref(commit, Some(&metadata.nar_hash))?,
        manage_source_url,
    )?;
    write_reference_flake(
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

    // Tiaris packages: the local build closure of the top-level packages.
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
            return Ok(blocked(
                REASON_EVALUATION_FAILED,
                vec!["tiaris-packages".to_string()],
            ));
        }
    };
    let closure = tiaris_package_closure(&tiaris, &evaluated.identities);
    info!(
        %commit,
        admitted = closure.admitted.len(),
        fixed_output = ?closure.fixed_output,
        "evaluated the Tiaris packages' local build closure"
    );
    if closure.admitted.len() > MAX_TIARIS_PACKAGE_DERIVATIONS {
        let mut outcome = blocked(
            REASON_SOURCE_BUILD_REQUIRED,
            closure
                .admitted
                .iter()
                .map(|path| derivation_display_name(path))
                .collect(),
        );
        outcome.tiaris_closure_size = closure.admitted.len();
        return Ok(outcome);
    }
    let tiaris_derivations = closure.admitted;
    let tiaris_closure_size = tiaris_derivations.len();
    let base = WorkstationBuildProfile::derived(
        commit,
        metadata.last_modified,
        &evaluated.identities,
        tiaris_derivations.clone(),
    )?;

    // The references: the shipped reference Blueprints, plus the plain
    // desktop profiles of the shipped module.
    let names = match reference_blueprint_names(config, &commit_flake).await {
        Ok(names) => names,
        Err(error) => {
            warn!(%commit, error = %format!("{error:#}"), "could not list the reference Blueprints");
            return Ok(blocked(
                REASON_EVALUATION_FAILED,
                vec!["reference blueprints".to_string()],
            ));
        }
    };
    if names.is_empty() {
        return Ok(blocked(
            REASON_REFERENCE_BLUEPRINTS_MISSING,
            vec![REFERENCE_BLUEPRINTS_DIR.to_string()],
        ));
    }
    let references = names
        .iter()
        .map(|name| format!("reference-{name}"))
        .chain(
            BUILTIN_BLUEPRINT_PROFILES
                .iter()
                .map(|profile| profile.to_string()),
        )
        .collect::<Vec<_>>();

    // Each reference at the pin (built-in profile) and at the commit. The
    // commit's dry run is kept for the readiness pass.
    let builtin = WorkstationBuildProfile::builtin();
    let mut counterparts = build::Counterparts::default();
    let mut sessions = Vec::new();
    for reference in &references {
        let pin = match build::unadmitted_local_derivations(
            config,
            &installable(&pin_flake, reference),
            builtin,
        )
        .await
        {
            Ok(pin) => pin,
            Err(error) => {
                warn!(%commit, reference, error = %format!("{error:#}"), "could not evaluate a reference at the pin");
                return Ok(blocked(REASON_EVALUATION_FAILED, vec![reference.clone()]));
            }
        };
        let session = match build::DryRunSession::start(
            config,
            &installable(&commit_flake, reference),
        )
        .await
        {
            Ok(session) => session,
            Err(error) => {
                warn!(%commit, reference, error = %format!("{error:#}"), "could not evaluate a reference");
                return Ok(blocked(REASON_EVALUATION_FAILED, vec![reference.clone()]));
            }
        };
        let detected = match session.classify(&base).await {
            Ok(detected) => detected,
            Err(error) => {
                warn!(%commit, reference, error = %format!("{error:#}"), "could not classify a reference");
                return Ok(blocked(REASON_EVALUATION_FAILED, vec![reference.clone()]));
            }
        };
        build::add_counterparts(&base, &evaluated.files, &pin, &detected, &mut counterparts);
        let uncovered_at_pin = pin
            .rejected_on_their_own
            .iter()
            .map(|path| builtin.derivation_role(path))
            .collect::<BTreeSet<_>>();
        sessions.push((reference.clone(), session, uncovered_at_pin));
    }
    let content = counterparts.content();
    let profile = match base.clone().with_reviewed_content(&content) {
        Ok(profile) => profile,
        Err(error) => {
            warn!(%commit, error = %error, "counterpart content is unusable");
            return Ok(blocked(
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

    // Readiness: at the commit, every reference must leave nothing
    // unadmitted that the pin admitted. Roles the pin did not cover in that
    // reference are not the commit's regressions; they stay uncovered.
    let mut changed = BTreeSet::new();
    let mut compiles = Vec::new();
    let mut coverage = Vec::new();
    for (reference, session, uncovered_at_pin) in sessions {
        let classified = session.classify(&profile).await;
        let _ = session.finish().await;
        let unadmitted = match classified {
            Ok(unadmitted) => unadmitted,
            Err(error) => {
                warn!(%commit, reference, error = %format!("{error:#}"), "could not classify a reference");
                return Ok(blocked(REASON_EVALUATION_FAILED, vec![reference]));
            }
        };
        coverage.push(format!(
            "{reference}: {} local, not covered at the pin: {:?}",
            unadmitted.would_build.len(),
            uncovered_at_pin.iter().take(10).collect::<Vec<_>>()
        ));
        let regressions = build::UnadmittedDerivations {
            rejected_on_their_own: unadmitted
                .rejected_on_their_own
                .iter()
                .filter(|path| !uncovered_at_pin.contains(&profile.derivation_role(path)))
                .cloned()
                .collect(),
            ..unadmitted
        };
        let (scripts, others) = classify_unadmitted(&profile, &regressions);
        changed.extend(scripts);
        changed.extend(
            regressions
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
    info!(%commit, coverage = ?coverage, "checked the references at the commit");
    let mut outcome = decide(
        kernel.clone(),
        changed,
        compiles,
        evaluated.identities,
        tiaris_derivations,
    );
    if outcome.reason.is_none() {
        outcome.reviewed = content;
    }
    outcome.counterparts = Some(counterparts);
    outcome.tiaris_closure_size = tiaris_closure_size;
    outcome.coverage = coverage;
    Ok(outcome)
}

/// The shipped reference Blueprints (`deploy/nixos/reference-blueprints/<name>`).
async fn reference_blueprint_names(config: &AppConfig, flake: &Path) -> Result<Vec<String>> {
    let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
    command
        .args(["eval", "--json", "--no-write-lock-file"])
        .args(["--option", "allow-import-from-derivation", "false"])
        .args(["--option", "accept-flake-config", "false"])
        .arg(format!("{}#referenceBlueprints", flake.display()))
        .env("LC_ALL", "C")
        .env("LANG", "C");
    let output = run_bounded_command(
        command,
        EVALUATION_TIMEOUT,
        EVALUATION_STDOUT_MAX_BYTES,
        EVALUATION_STDERR_MAX_BYTES,
        "list reference Blueprints",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "nix eval failed: {}",
            tail(&String::from_utf8_lossy(&output.stderr), 300)
        );
    }
    let names: Vec<String> =
        serde_json::from_slice(&output.stdout).context("parse reference Blueprint names")?;
    if names.len() > MAX_REFERENCE_BLUEPRINTS
        || !names.iter().all(|name| valid_reference_name(name))
    {
        bail!("the shipped reference Blueprints are not a bounded list of safe names");
    }
    Ok(names)
}

fn valid_reference_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// The Tiaris packages' local build closure in the dry run of the
/// `tiaris-packages` list.
#[derive(Debug, Default, PartialEq, Eq)]
struct TiarisClosure {
    /// The top-level packages (the list's inputs that are not commit
    /// identities) and every local, non-fixed-output derivation they reach.
    admitted: BTreeSet<String>,
    /// Fixed-output derivations of the closure: left to the fetch rules.
    fixed_output: Vec<String>,
}

fn tiaris_package_closure(
    dry_run: &build::UnadmittedDerivations,
    identities: &BTreeMap<String, DerivedIdentity>,
) -> TiarisClosure {
    let identity_drvs = identities
        .values()
        .filter_map(|identity| identity.drv.as_deref())
        .collect::<BTreeSet<_>>();
    let local = dry_run.would_build.iter().collect::<BTreeSet<_>>();
    let inputs = |path: &str| {
        dry_run
            .derivations
            .get(path)
            .and_then(build::derivation_input_drvs)
            .unwrap_or_default()
            .into_iter()
            .map(|(input, _)| input)
            .filter(|input| local.contains(input) && !identity_drvs.contains(input.as_str()))
            .collect::<Vec<_>>()
    };
    let Some(list) = dry_run
        .would_build
        .iter()
        .find(|path| path.ends_with("-tiaris-packages.drv"))
    else {
        return TiarisClosure::default();
    };
    let mut closure = TiarisClosure::default();
    let mut seen = BTreeSet::new();
    let mut pending = inputs(list);
    while let Some(path) = pending.pop() {
        if !seen.insert(path.clone()) {
            continue;
        }
        if dry_run
            .derivations
            .get(&path)
            .is_some_and(build::derivation_is_fixed_output)
        {
            closure.fixed_output.push(derivation_display_name(&path));
            continue;
        }
        pending.extend(inputs(&path));
        closure.admitted.insert(path);
    }
    closure.fixed_output.sort();
    closure
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
        tiaris_closure_size: 0,
        coverage: Vec::new(),
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

/// The flake the check dry-runs: the Tiaris packages, each shipped
/// reference Blueprint and the plain desktop profiles, configured by the same
/// Nest templates as Blueprint jobs. Every input is the shipped Tiaris source
/// or nixpkgs.
fn write_reference_flake(work: &Path, nixpkgs_ref: &str, manage_url: &str) -> Result<()> {
    for (name, contents) in build::blueprint_job_template_files()? {
        write_private_file(work.join(name), &contents)?;
    }
    write_private_file(work.join("blueprint.nix"), "{ ... }:\n\n{ }\n")?;
    write_private_file(
        work.join("tiaris-blueprints.nix"),
        "{ manageSource, ... }:\n\n{\n  imports = [ (manageSource + \"/deploy/nixos/tiaris-blueprints.nix\") ];\n}\n",
    )?;
    write_private_file(
        work.join("flake.nix"),
        &reference_flake(nixpkgs_ref, manage_url),
    )
}

fn reference_flake(nixpkgs_ref: &str, manage_url: &str) -> String {
    let nixpkgs = serde_json::to_string(nixpkgs_ref).expect("string serializes");
    let manage = serde_json::to_string(manage_url).expect("string serializes");
    let profiles = BUILTIN_BLUEPRINT_PROFILES
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
      lib = nixpkgs.lib;
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
        (lib.nixosSystem {{
          inherit system;
          specialArgs.manageSource = manage;
          modules = [
            ./configuration.nix
            {{ tiaris.desktop.profile = profile; }}
          ];
        }}).config.system.build.toplevel;
      references = manage + "/{REFERENCE_BLUEPRINTS_DIR}";
      referenceNames =
        if builtins.pathExists references
        then builtins.attrNames (lib.filterAttrs (_: type: type == "directory") (builtins.readDir references))
        else [ ];
      # The job configuration with the reference's compiler exports in the
      # places of a job's desktop module and generated Blueprint.
      reference = name:
        (lib.nixosSystem {{
          inherit system;
          modules = [
            (import ./reference-configuration.nix {{
              desktop = references + "/${{name}}/desktop.nix";
              blueprint = references + "/${{name}}/blueprint.nix";
            }})
          ];
        }}).config.system.build.toplevel;
    in {{
      referenceBlueprints = referenceNames;
      packages.${{system}} = {{
        tiaris-packages = pkgs.writeText "tiaris-packages"
          (builtins.concatStringsSep "\n" (map (package: package.outPath) ([ workstationAgent ] ++ seeds.packages)));
{profiles}      }} // lib.listToAttrs (map (name: {{
        name = "reference-${{name}}";
        value = reference name;
      }}) referenceNames);
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
