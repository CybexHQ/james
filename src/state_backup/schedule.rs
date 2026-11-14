//! Automatic state backups: the root side.
//!
//! `tiaris-nest-state-backup.timer` runs `scheduled-state-backup` once a day
//! (randomized, catching up after downtime) when an operator has set a
//! backup public key with `set-state-backup-key`. The key lives in STATE at
//! `backup/recipient.pub`; its private half never touches the Nest. Each run
//! writes one encrypted backup to `BACKUP_DIR` (outside STATE, so a backup
//! can never fill it), next to a secret-free description, and keeps the
//! newest `KEEP` within `BUDGET_BYTES`. The daemon uploads them to Manage
//! (`super::upload`). The folder and its files are root:tiaris-nest
//! 0750/0640: the daemon reads them, only root writes or removes them.
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{PRIVATE_LABEL, PUBLIC_LABEL, create_private, fingerprint, read_key, sync_parent};

/// The backup public key, relative to STATE.
pub const KEY_FILE: &str = "backup/recipient.pub";
/// Where automatic backups are kept (root filesystem, not STATE).
pub const BACKUP_DIR: &str = "/var/cache/tiaris-nest/state-backups";
/// The newest backups kept on the Nest.
pub const KEEP: usize = 3;
/// At most this much in kept backups; the newest is always kept.
pub const BUDGET_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// A backup starts only if this much stays free on its filesystem after it
/// (or a tenth of the filesystem when that is more): the Nix store and the
/// workstation cache live there too.
pub const RESERVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const FILE_SCHEMA: &str = "tiaris.nest.state-backup-file.v1";
/// What the last scheduled run did, relative to STATE (`local_health`).
pub const RUN_STATUS: &str = "status/state-backup-schedule.json";
pub const RUN_STATUS_SCHEMA: &str = "tiaris.nest.state-backup-schedule.v1";
const LOCK: &str = ".lock";

/// The description next to `<backup_id>.backup`: no secret material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupFile {
    pub schema: String,
    pub backup_id: String,
    pub created_at: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub recipient_fingerprint: String,
}

impl BackupFile {
    pub fn created(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.created_at)
            .ok()
            .map(|time| time.with_timezone(&Utc))
    }

    pub fn path(&self, dir: &Path) -> PathBuf {
        dir.join(format!("{}.backup", self.backup_id))
    }
}

/// What a scheduled run did; printed and kept in `RUN_STATUS`.
#[derive(Clone, Debug, Serialize)]
pub struct RunOutcome {
    pub schema: &'static str,
    pub at: String,
    /// `backed_up`, `key_missing`, `low_disk` or `failed`.
    pub outcome: &'static str,
    pub backup_id: Option<String>,
    pub size_bytes: Option<u64>,
    pub kept: usize,
    pub removed: usize,
}

pub fn key_path(state: &Path) -> PathBuf {
    state.join(KEY_FILE)
}

/// Whether an operator set a backup key (a regular file, not a link).
pub fn key_configured(state: &Path) -> bool {
    fs::symlink_metadata(key_path(state)).is_ok_and(|metadata| metadata.is_file())
}

fn first_line(path: &Path) -> Result<String> {
    let file = super::open_nofollow(path)?;
    let mut text = String::new();
    file.take(256).read_to_string(&mut text).ok();
    Ok(text.lines().next().unwrap_or_default().to_owned())
}

/// Installs `public_key` as this Nest's backup key; returns its fingerprint.
/// Refuses a private key: it must stay off the Nest.
pub fn set_key(state: &Path, public_key: &Path) -> Result<String> {
    if first_line(public_key)? == PRIVATE_LABEL {
        bail!(
            "{} is the backup private key: keep it off the Nest and give the public key (.pub)",
            public_key.display()
        );
    }
    let key = read_key(public_key, PUBLIC_LABEL, false)?;
    let target = key_path(state);
    let directory = target.parent().expect("key has a directory");
    match fs::symlink_metadata(directory) {
        Ok(metadata) => ensure!(
            metadata.is_dir(),
            "{} is not a directory",
            directory.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
            sync_parent(directory)?;
        }
        Err(error) => return Err(error.into()),
    }
    let temporary = directory.join(format!(
        ".recipient.pub.tmp-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let mut file = create_private(&temporary, 0o644)?;
    let body = format!(
        "{PUBLIC_LABEL}\n{}\n",
        base64::Engine::encode(&super::b64(), key)
    );
    let written = file
        .write_all(body.as_bytes())
        .and_then(|()| file.set_permissions(fs::Permissions::from_mode(0o644)))
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, &target));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written?;
    sync_parent(&target)?;
    Ok(fingerprint(&key))
}

fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.hyphenated().to_string() == id)
}

/// The kept backups that are complete (description written last), newest first.
pub fn list(dir: &Path) -> Vec<BackupFile> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<BackupFile> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let id = name.strip_suffix(".json")?;
            if !valid_id(id) {
                return None;
            }
            let file = super::open_nofollow(&entry.path()).ok()?;
            let mut body = Vec::new();
            file.take(4096).read_to_end(&mut body).ok()?;
            let record: BackupFile = serde_json::from_slice(&body).ok()?;
            let backup = fs::symlink_metadata(record.path(dir)).ok()?;
            (record.schema == FILE_SCHEMA
                && record.backup_id == id
                && record.created().is_some()
                && backup.is_file()
                && backup.len() == record.size_bytes)
                .then_some(record)
        })
        .collect();
    files.sort_by(|a, b| {
        b.created()
            .cmp(&a.created())
            .then(b.backup_id.cmp(&a.backup_id))
    });
    files
}

/// Which of `files` (newest first) retention removes: everything after the
/// newest `keep`, and older ones once the kept total passes `budget`.
pub fn expired(files: &[BackupFile], keep: usize, budget: u64) -> Vec<BackupFile> {
    let mut total = 0u64;
    files
        .iter()
        .enumerate()
        .filter(|(index, file)| {
            total = total.saturating_add(file.size_bytes);
            *index > 0 && (*index >= keep || total > budget)
        })
        .map(|(_, file)| file.clone())
        .collect()
}

fn remove_backup(dir: &Path, file: &BackupFile) -> Result<()> {
    // The description first: a backup without one is never uploaded.
    for path in [dir.join(format!("{}.json", file.backup_id)), file.path(dir)] {
        match fs::remove_file(&path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    Ok(())
}

/// Removes what an interrupted run left: database snapshots, temporary
/// descriptions and backups without a description. Runs under the lock.
fn remove_leftovers(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)?.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let orphan = name
            .strip_suffix(".backup")
            .is_some_and(|id| !dir.join(format!("{id}.json")).exists());
        let partial = name.starts_with('.') && name != LOCK;
        if (orphan || partial) && entry.file_type().is_ok_and(|kind| kind.is_file()) {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

struct DirLock(fs::File);

impl Drop for DirLock {
    fn drop(&mut self) {
        unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN) };
    }
}

fn lock(dir: &Path) -> Result<DirLock> {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(LOCK))?;
    let locked = unsafe {
        libc::flock(
            std::os::fd::AsRawFd::as_raw_fd(&file),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    ensure!(locked == 0, "another state backup is running");
    Ok(DirLock(file))
}

/// The backup folder, root:<Nest group> 0750 (the daemon reads it).
fn prepare_dir(dir: &Path, group: u32, root: bool) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) => ensure!(metadata.is_dir(), "{} is not a directory", dir.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(dir)?,
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o750))?;
    if root {
        std::os::unix::fs::chown(dir, Some(0), Some(group))?;
    }
    Ok(())
}

/// Readable by the Nest group, so the daemon can upload it.
fn share(path: &Path, group: u32, root: bool) -> Result<()> {
    let file = super::open_nofollow(path)?;
    if root {
        std::os::unix::fs::fchown(&file, Some(0), Some(group))?;
    }
    file.set_permissions(fs::Permissions::from_mode(0o640))?;
    Ok(())
}

fn write_description(dir: &Path, record: &BackupFile, group: u32, root: bool) -> Result<()> {
    let target = dir.join(format!("{}.json", record.backup_id));
    let temporary = dir.join(format!(".{}.json.tmp", record.backup_id));
    let mut file = create_private(&temporary, 0o600)?;
    file.write_all(&serde_json::to_vec(record)?)?;
    file.sync_all()?;
    drop(file);
    share(&temporary, group, root)?;
    fs::rename(&temporary, &target)?;
    sync_parent(&target)
}

/// What a backup of `state` needs on disk while it runs: the files it
/// holds plus the database snapshot taken next to the output.
fn estimate(state: &Path) -> Result<u64> {
    let mut files = Vec::new();
    super::walk(state, Path::new(""), &mut files)?;
    let database = fs::symlink_metadata(state.join(super::DATABASE))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    Ok(files
        .iter()
        .map(|(_, metadata)| metadata.len())
        .sum::<u64>()
        .saturating_add(database.saturating_mul(2)))
}

/// Retention and the free space a backup must leave.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub keep: usize,
    pub budget_bytes: u64,
    pub reserve_bytes: u64,
    /// Also keep `1 / reserve_divisor` of the filesystem free.
    pub reserve_divisor: u64,
}

impl Limits {
    pub const DEFAULT: Self = Self {
        keep: KEEP,
        budget_bytes: BUDGET_BYTES,
        reserve_bytes: RESERVE_BYTES,
        reserve_divisor: 10,
    };

    /// The space a backup must leave free on a filesystem of `total_bytes`.
    pub fn reserve(&self, total_bytes: u64) -> u64 {
        self.reserve_bytes
            .max(total_bytes / self.reserve_divisor.max(1))
    }
}

fn write_status(state: &Path, outcome: &RunOutcome) {
    let target = state.join(RUN_STATUS);
    let Some(directory) = target.parent() else {
        return;
    };
    let Ok(metadata) = fs::symlink_metadata(directory) else {
        return;
    };
    if !metadata.is_dir() {
        return;
    }
    let written = (|| -> Result<()> {
        let temporary = directory.join(format!(
            ".state-backup-schedule.json.tmp-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let mut file = create_private(&temporary, 0o640)?;
        file.write_all(&serde_json::to_vec(outcome)?)?;
        if unsafe { libc::geteuid() } == 0 {
            std::os::unix::fs::fchown(&file, Some(0), Some(metadata.gid()))?;
        }
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &target)?;
        sync_parent(&target)
    })();
    if let Err(error) = written {
        tracing::warn!(error = %error, "state backup schedule status was not written");
    }
}

/// The scheduled run: back up `state` into `dir` if a key is set and the
/// disk has room, then apply retention.
pub async fn run(state: &Path, dir: &Path) -> Result<RunOutcome> {
    run_with(state, dir, Limits::DEFAULT).await
}

pub async fn run_with(state: &Path, dir: &Path, limits: Limits) -> Result<RunOutcome> {
    let state = fs::canonicalize(state).with_context(|| format!("open {}", state.display()))?;
    let mut outcome = RunOutcome {
        schema: RUN_STATUS_SCHEMA,
        at: crate::db::now_rfc3339(),
        outcome: "key_missing",
        backup_id: None,
        size_bytes: None,
        kept: 0,
        removed: 0,
    };
    if !key_configured(&state) {
        write_status(&state, &outcome);
        return Ok(outcome);
    }
    outcome.outcome = "failed";
    let result = run_with_key(&state, dir, limits, &mut outcome).await;
    write_status(&state, &outcome);
    result.map(|()| outcome)
}

async fn run_with_key(
    state: &Path,
    dir: &Path,
    limits: Limits,
    outcome: &mut RunOutcome,
) -> Result<()> {
    let root = unsafe { libc::geteuid() } == 0;
    let group = fs::metadata(state)?.gid();
    prepare_dir(dir, group, root)?;
    let _lock = lock(dir)?;
    remove_leftovers(dir)?;
    let needed = estimate(state)?;
    let disk = crate::disk::stats(dir)?;
    if disk.available_bytes < needed.saturating_add(limits.reserve(disk.total_bytes)) {
        outcome.outcome = "low_disk";
        bail!(
            "not enough free space for a state backup in {} ({} bytes free, {} needed and {} kept free)",
            dir.display(),
            disk.available_bytes,
            needed,
            limits.reserve(disk.total_bytes)
        );
    }
    let backup_id = uuid::Uuid::new_v4().hyphenated().to_string();
    let output = dir.join(format!("{backup_id}.backup"));
    let summary = super::backup(state, &key_path(state), &output).await?;
    let record = BackupFile {
        schema: FILE_SCHEMA.into(),
        backup_id: backup_id.clone(),
        created_at: summary.created_at,
        sha256: summary.sha256,
        size_bytes: summary.size_bytes,
        recipient_fingerprint: summary.recipient_fingerprint,
    };
    let published =
        share(&output, group, root).and_then(|()| write_description(dir, &record, group, root));
    if published.is_err() {
        let _ = fs::remove_file(&output);
    }
    published?;
    outcome.outcome = "backed_up";
    outcome.backup_id = Some(backup_id);
    outcome.size_bytes = Some(record.size_bytes);
    let files = list(dir);
    let expired = expired(&files, limits.keep, limits.budget_bytes);
    for file in &expired {
        remove_backup(dir, file)?;
    }
    outcome.kept = files.len() - expired.len();
    outcome.removed = expired.len();
    Ok(())
}

/// The last scheduled run, for `local_health`.
pub fn last_run(state: &Path) -> Option<serde_json::Value> {
    let file = super::open_nofollow(&state.join(RUN_STATUS)).ok()?;
    let mut body = Vec::new();
    file.take(16 * 1024).read_to_end(&mut body).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&body).ok()?;
    (value["schema"] == RUN_STATUS_SCHEMA).then(|| {
        serde_json::json!({
            "at": value["at"],
            "outcome": value["outcome"],
        })
    })
}

#[cfg(test)]
#[path = "schedule_tests.rs"]
mod tests;
