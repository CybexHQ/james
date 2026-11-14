//! Automatic state backups: the daemon uploads them to Manage.
//!
//! Every kept backup (`super::schedule`, newest first) is sent once as
//!
//! ```text
//! PUT /v1/agent/nest/state-backups/{backup_id}   (signed Nest agent request)
//! Content-Type: application/octet-stream          (the encrypted file, ≤ 256 MiB)
//! X-Tiaris-Backup-Sha256: <hex>
//! X-Tiaris-Backup-Created-At: <RFC 3339>
//! X-Tiaris-Backup-Format: tiaris.nest-state-backup.v1
//! ```
//!
//! Manage answers `{backup_id, sha256, size_bytes, stored_at}`, the same for
//! a repeated upload, and 409 when it holds other bytes under that id. A
//! failure is retried with back-off; a Manage without the route (404/405) is
//! asked again once a day and the backups stay on the Nest. The record of
//! what was sent is `UPLOADS` in the daemon's data directory; `health` turns
//! it into `local_health` facts.
//!
//! Cloudflare caps one request body at 100 MB on its Free and Pro plans. A
//! backup larger than [`SINGLE_REQUEST_MAX_BYTES`] therefore goes in chunks
//! when Manage advertises it (`state_backup_chunked_upload_supported`):
//!
//! ```text
//! POST .../state-backups/{backup_id}/upload          {sha256, size_bytes, created_at, format}
//!   -> {state: open|stored, chunk_bytes, chunk_count, received_chunks, next_chunk, receipt}
//! PUT  .../state-backups/{backup_id}/chunks/{index}  (X-Tiaris-Chunk-Sha256; one chunk)
//! POST .../state-backups/{backup_id}/complete        -> the receipt
//! ```
//!
//! Each is a signed request of at most one chunk. The Nest keeps no upload
//! state: a failed chunk fails the attempt, and the next one opens the upload
//! again and sends only the chunks Manage is missing. A Manage that answers
//! the open with 404/405 gets the single `PUT`.
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use chrono::{DateTime, Utc};
use reqwest::{Method, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use super::schedule::{self, BackupFile};
use crate::{config::AppConfig, state_files};

pub const FORMAT: &str = "tiaris.nest-state-backup.v1";
pub const MAX_UPLOAD_BYTES: u64 = 256 * 1024 * 1024;
/// Backups up to this size go in one request (well below the edge's cap).
pub const SINGLE_REQUEST_MAX_BYTES: u64 = 32 * 1024 * 1024;
/// The largest chunk Manage may ask for: one chunk is held in memory.
const MAX_CHUNK_BYTES: u64 = 64 * 1024 * 1024;
/// The upload record, in the daemon's data directory (STATE `agent/`).
pub const UPLOADS: &str = "state-backup-uploads.json";
const UPLOADS_SCHEMA: &str = "tiaris.nest.state-backup-uploads";
const MAX_UPLOADS_BYTES: u64 = 64 * 1024;
const START_DELAY: Duration = Duration::from_secs(120);
const PASS_INTERVAL: Duration = Duration::from_secs(15 * 60);
const BACKOFF_BASE_SECONDS: i64 = 60;
const BACKOFF_MAX_SECONDS: i64 = 6 * 3600;
/// How often a Manage without the route is asked again.
const UNSUPPORTED_RECHECK_SECONDS: i64 = 24 * 3600;
/// Failed attempts on the newest backup before it is attention.
pub const FAILING_AFTER_ATTEMPTS: u32 = 3;
/// A request may take as long as the upload at this rate, plus slack.
const MIN_ASSUMED_BYTES_PER_SECOND: u64 = 128 * 1024;
const REQUEST_SLACK: Duration = Duration::from_secs(120);
const MAX_RECEIPT_BYTES: usize = 16 * 1024;
const MAX_UPLOAD_STATUS_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    Pending,
    /// Failed; retried at `next_attempt_at`.
    Failing,
    Uploaded,
    /// Manage holds other bytes under this id: never retried.
    Conflict,
    /// Larger than Manage accepts: kept on the Nest only.
    TooLarge,
    /// The local file no longer matches its description: never sent.
    Damaged,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Attempt {
    pub status: Status,
    pub attempts: u32,
    pub next_attempt_at: Option<DateTime<Utc>>,
    /// A fixed code (`network`, `http_503`, …), never response text.
    pub last_error: Option<String>,
}

/// Manage's receipt for a stored backup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub backup_id: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub stored_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uploaded {
    pub backup_id: String,
    pub created_at: String,
    pub size_bytes: u64,
    pub stored_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Uploads {
    /// The newest backup Manage confirmed.
    pub last_uploaded: Option<Uploaded>,
    /// Set while Manage answers 404/405 (`backup_upload_unsupported`).
    pub unsupported_since: Option<DateTime<Utc>>,
    pub unsupported_checked_at: Option<DateTime<Utc>>,
    /// Per kept backup.
    pub backups: BTreeMap<String, Attempt>,
}

/// Where backups come from and where they go.
#[derive(Clone, Debug)]
pub struct Uploader {
    pub config: AppConfig,
    pub backup_dir: PathBuf,
    pub data_dir: PathBuf,
    /// Larger backups go in chunks to a Manage that accepts them
    /// ([`SINGLE_REQUEST_MAX_BYTES`]).
    pub single_request_max_bytes: u64,
}

pub fn spawn(state: crate::AppState) {
    let uploader = Uploader {
        config: (*state.config).clone(),
        backup_dir: PathBuf::from(schedule::BACKUP_DIR),
        data_dir: state.config.paths.data_dir.clone(),
        single_request_max_bytes: SINGLE_REQUEST_MAX_BYTES,
    };
    tokio::spawn(async move {
        tokio::time::sleep(START_DELAY).await;
        loop {
            if let Err(error) = pass(&uploader, Utc::now()).await {
                warn!(error = %format!("{error:#}"), "state backup upload pass failed");
            }
            tokio::time::sleep(PASS_INTERVAL).await;
        }
    });
}

fn backoff(attempts: u32) -> chrono::Duration {
    let exponent = attempts.saturating_sub(1).min(16);
    chrono::Duration::seconds(
        BACKOFF_BASE_SECONDS
            .saturating_mul(1i64 << exponent)
            .min(BACKOFF_MAX_SECONDS),
    )
}

pub fn load(data_dir: &Path) -> Uploads {
    state_files::read(data_dir, UPLOADS, UPLOADS_SCHEMA, MAX_UPLOADS_BYTES).unwrap_or_default()
}

/// Why one upload did not succeed.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Unsupported,
    Conflict,
    TooLarge,
    Damaged,
    Retry(String),
}

/// One pass: sends every kept backup that is due, newest first.
pub async fn pass(uploader: &Uploader, now: DateTime<Utc>) -> Result<Uploads> {
    let _guard = state_files::lock(&uploader.data_dir).await;
    let mut uploads = load(&uploader.data_dir);
    let files = schedule::list(&uploader.backup_dir);
    let before = uploads.clone();
    uploads
        .backups
        .retain(|id, _| files.iter().any(|file| &file.backup_id == id));
    let recheck = uploads.unsupported_checked_at.is_none_or(|checked| {
        now - checked >= chrono::Duration::seconds(UNSUPPORTED_RECHECK_SECONDS)
    });
    if recheck {
        for file in &files {
            let attempt = uploads.backups.entry(file.backup_id.clone()).or_default();
            let due = attempt.next_attempt_at.is_none_or(|at| at <= now);
            if !matches!(attempt.status, Status::Pending | Status::Failing) || !due {
                continue;
            }
            match upload(uploader, file).await {
                Ok(receipt) => {
                    attempt.status = Status::Uploaded;
                    attempt.next_attempt_at = None;
                    attempt.last_error = None;
                    uploads.unsupported_since = None;
                    uploads.unsupported_checked_at = None;
                    let newer = uploads.last_uploaded.as_ref().is_none_or(|last| {
                        file.created()
                            > DateTime::parse_from_rfc3339(&last.created_at)
                                .ok()
                                .map(|time| time.with_timezone(&Utc))
                    });
                    if newer {
                        uploads.last_uploaded = Some(Uploaded {
                            backup_id: receipt.backup_id,
                            created_at: file.created_at.clone(),
                            size_bytes: receipt.size_bytes,
                            stored_at: receipt.stored_at,
                        });
                    }
                    info!(backup_id = %file.backup_id, size_bytes = file.size_bytes,
                        "state backup uploaded to Manage");
                }
                Err(Failure::Unsupported) => {
                    // An older Manage: keep the backups here, ask again tomorrow.
                    uploads.unsupported_since.get_or_insert(now);
                    uploads.unsupported_checked_at = Some(now);
                    info!("Manage does not accept state backups yet (backup_upload_unsupported)");
                    break;
                }
                Err(failure) => {
                    attempt.attempts = attempt.attempts.saturating_add(1);
                    attempt.status = match failure {
                        Failure::Conflict => Status::Conflict,
                        Failure::TooLarge => Status::TooLarge,
                        Failure::Damaged => Status::Damaged,
                        _ => Status::Failing,
                    };
                    let code = match failure {
                        Failure::Retry(code) => code,
                        Failure::Conflict => "conflict".into(),
                        Failure::TooLarge => "too_large".into(),
                        Failure::Damaged => "damaged".into(),
                        Failure::Unsupported => unreachable!("handled above"),
                    };
                    attempt.next_attempt_at = (attempt.status == Status::Failing)
                        .then(|| now + backoff(attempt.attempts));
                    warn!(backup_id = %file.backup_id, error = %code, attempts = attempt.attempts,
                        "state backup upload failed");
                    attempt.last_error = Some(code);
                }
            }
        }
    }
    if uploads != before {
        state_files::write(
            &uploader.data_dir,
            UPLOADS,
            UPLOADS_SCHEMA,
            MAX_UPLOADS_BYTES,
            &uploads,
        )?;
    }
    Ok(uploads)
}

fn digest(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = super::open_nofollow(path).map_err(std::io::Error::other)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut size = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        size += count as u64;
    }
    Ok((hex::encode(digest.finalize()), size))
}

async fn upload(uploader: &Uploader, file: &BackupFile) -> Result<Receipt, Failure> {
    if file.size_bytes > MAX_UPLOAD_BYTES {
        return Err(Failure::TooLarge);
    }
    let path = file.path(&uploader.backup_dir);
    let hashed = path.clone();
    let (sha256, size) = tokio::task::spawn_blocking(move || digest(&hashed))
        .await
        .map_err(|_| Failure::Retry("local_read".into()))?
        .map_err(|_| Failure::Retry("local_read".into()))?;
    if sha256 != file.sha256 || size != file.size_bytes {
        return Err(Failure::Damaged);
    }
    if size > uploader.single_request_max_bytes
        && crate::manage::state_backup_chunks_supported(&uploader.config)
    {
        match upload_chunked(uploader, file, &path, &sha256, size).await {
            // Manage rolled back to a release without chunks: one request.
            Err(Failure::Unsupported) => {}
            outcome => return outcome,
        }
    }
    upload_single(uploader, file, &path, &sha256, size).await
}

async fn upload_single(
    uploader: &Uploader,
    file: &BackupFile,
    path: &Path,
    sha256: &str,
    size: u64,
) -> Result<Receipt, Failure> {
    let body = tokio::fs::File::open(path)
        .await
        .map_err(|_| Failure::Retry("local_read".into()))?;
    let request = crate::manage::signed_streaming_request(
        &uploader.config,
        Method::PUT,
        &format!("/v1/agent/nest/state-backups/{}", file.backup_id),
        sha256,
    )
    .map_err(|_| Failure::Retry("not_enrolled".into()))?;
    let response = request
        .timeout(request_timeout(size))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, size)
        .header("X-Tiaris-Backup-Sha256", sha256)
        .header("X-Tiaris-Backup-Created-At", &file.created_at)
        .header("X-Tiaris-Backup-Format", FORMAT)
        .body(reqwest::Body::wrap_stream(
            tokio_util::io::ReaderStream::new(body),
        ))
        .send()
        .await
        .map_err(|_| Failure::Retry("network".into()))?;
    let status = response.status();
    match status {
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => {
            return Err(Failure::Unsupported);
        }
        StatusCode::CONFLICT => return Err(Failure::Conflict),
        StatusCode::PAYLOAD_TOO_LARGE => return Err(Failure::TooLarge),
        status if !status.is_success() => {
            return Err(Failure::Retry(format!("http_{}", status.as_u16())));
        }
        _ => {}
    }
    checked_receipt(read_receipt(response).await, file, sha256, size)
}

fn request_timeout(bytes: u64) -> Duration {
    REQUEST_SLACK + Duration::from_secs(bytes / MIN_ASSUMED_BYTES_PER_SECOND)
}

fn checked_receipt(
    receipt: Option<Receipt>,
    file: &BackupFile,
    sha256: &str,
    size: u64,
) -> Result<Receipt, Failure> {
    let receipt = receipt.ok_or_else(|| Failure::Retry("receipt_invalid".into()))?;
    if receipt.backup_id != file.backup_id
        || !receipt.sha256.eq_ignore_ascii_case(sha256)
        || receipt.size_bytes != size
    {
        return Err(Failure::Retry("receipt_mismatch".into()));
    }
    Ok(receipt)
}

/// Manage's answer to opening a chunked upload and to each chunk.
#[derive(Debug, Deserialize)]
struct UploadStatus {
    state: String,
    #[serde(default)]
    chunk_bytes: u64,
    #[serde(default)]
    chunk_count: u64,
    #[serde(default)]
    received_chunks: Vec<u64>,
    #[serde(default)]
    receipt: Option<Receipt>,
}

/// A signed request of `body` (at most one chunk), sent once.
async fn send(
    uploader: &Uploader,
    method: Method,
    path: &str,
    content_type: &'static str,
    body: Vec<u8>,
    extra: Option<(&'static str, &str)>,
) -> Result<reqwest::Response, Failure> {
    let digest = hex::encode(Sha256::digest(&body));
    let mut request =
        crate::manage::signed_streaming_request(&uploader.config, method, path, &digest)
            .map_err(|_| Failure::Retry("not_enrolled".into()))?
            .timeout(request_timeout(body.len() as u64))
            .header(header::CONTENT_TYPE, content_type);
    if let Some((name, value)) = extra {
        request = request.header(name, value);
    }
    request
        .body(body)
        .send()
        .await
        .map_err(|_| Failure::Retry("network".into()))
}

async fn read_bounded(mut response: reqwest::Response, limit: usize) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len() + chunk.len() > limit {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(body)
}

/// The `diagnostic_code` of a Manage error answer.
async fn diagnostic_code(response: reqwest::Response) -> Option<String> {
    let body = read_bounded(response, MAX_RECEIPT_BYTES).await?;
    let value: Value = serde_json::from_slice(&body).ok()?;
    value
        .get("diagnostic_code")
        .and_then(Value::as_str)
        .filter(|code| code.len() <= 64)
        .map(str::to_owned)
}

async fn upload_status(response: reqwest::Response) -> Result<UploadStatus, Failure> {
    read_bounded(response, MAX_UPLOAD_STATUS_BYTES)
        .await
        .and_then(|body| serde_json::from_slice(&body).ok())
        .ok_or_else(|| Failure::Retry("upload_status_invalid".into()))
}

/// Bytes `offset..offset + len` of the backup; one chunk in memory.
fn read_chunk(path: &Path, offset: u64, len: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    let mut file = super::open_nofollow(path).map_err(std::io::Error::other)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; usize::try_from(len).map_err(std::io::Error::other)?];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Sends the backup in chunks, from the first one Manage is missing.
async fn upload_chunked(
    uploader: &Uploader,
    file: &BackupFile,
    path: &Path,
    sha256: &str,
    size: u64,
) -> Result<Receipt, Failure> {
    let base = format!("/v1/agent/nest/state-backups/{}", file.backup_id);
    let declaration = serde_json::to_vec(&json!({
        "sha256": sha256, "size_bytes": size, "created_at": file.created_at, "format": FORMAT,
    }))
    .map_err(|_| Failure::Retry("local_read".into()))?;
    let response = send(
        uploader,
        Method::POST,
        &format!("{base}/upload"),
        "application/json",
        declaration,
        None,
    )
    .await?;
    match response.status() {
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => return Err(Failure::Unsupported),
        StatusCode::CONFLICT => return Err(Failure::Conflict),
        StatusCode::PAYLOAD_TOO_LARGE => return Err(Failure::TooLarge),
        status if !status.is_success() => {
            return Err(Failure::Retry(format!("http_{}", status.as_u16())));
        }
        _ => {}
    }
    let opened = upload_status(response).await?;
    if opened.state == "stored" {
        return checked_receipt(opened.receipt, file, sha256, size);
    }
    let chunk_bytes = opened.chunk_bytes;
    if opened.state != "open"
        || chunk_bytes == 0
        || chunk_bytes > MAX_CHUNK_BYTES
        || opened.chunk_count != size.div_ceil(chunk_bytes)
    {
        return Err(Failure::Retry("upload_status_invalid".into()));
    }
    for index in (0..opened.chunk_count).filter(|index| !opened.received_chunks.contains(index)) {
        let offset = index * chunk_bytes;
        let len = chunk_bytes.min(size - offset);
        let source = path.to_path_buf();
        let content = tokio::task::spawn_blocking(move || read_chunk(&source, offset, len))
            .await
            .map_err(|_| Failure::Retry("local_read".into()))?
            .map_err(|_| Failure::Retry("local_read".into()))?;
        let digest = hex::encode(Sha256::digest(&content));
        let response = send(
            uploader,
            Method::PUT,
            &format!("{base}/chunks/{index}"),
            "application/octet-stream",
            content,
            Some(("X-Tiaris-Chunk-Sha256", &digest)),
        )
        .await?;
        match response.status() {
            status if status.is_success() => {}
            // The upload expired or was finalized meanwhile: open it again.
            StatusCode::NOT_FOUND => return Err(Failure::Retry("upload_expired".into())),
            StatusCode::CONFLICT => return Err(Failure::Retry("chunk_conflict".into())),
            status => return Err(Failure::Retry(format!("http_{}", status.as_u16()))),
        }
    }
    let response = send(
        uploader,
        Method::POST,
        &format!("{base}/complete"),
        "application/octet-stream",
        Vec::new(),
        None,
    )
    .await?;
    match response.status() {
        status if status.is_success() => {}
        StatusCode::NOT_FOUND => return Err(Failure::Retry("upload_expired".into())),
        StatusCode::CONFLICT => {
            return Err(match diagnostic_code(response).await.as_deref() {
                Some("backup_upload_incomplete") => Failure::Retry("upload_incomplete".into()),
                _ => Failure::Conflict,
            });
        }
        // The chunks did not add up (the file changed underway): start over.
        StatusCode::BAD_REQUEST => return Err(Failure::Retry("upload_digest_mismatch".into())),
        status => return Err(Failure::Retry(format!("http_{}", status.as_u16()))),
    }
    checked_receipt(read_receipt(response).await, file, sha256, size)
}

async fn read_receipt(response: reqwest::Response) -> Option<Receipt> {
    let body = read_bounded(response, MAX_RECEIPT_BYTES).await?;
    let receipt: Receipt = serde_json::from_slice(&body).ok()?;
    (receipt.stored_at.len() <= 64 && DateTime::parse_from_rfc3339(&receipt.stored_at).is_ok())
        .then_some(receipt)
}

/// `local_health.state_backup_upload` and its attention codes.
pub struct Health {
    pub fact: Value,
    pub attention: Vec<&'static str>,
}

/// Reads the key, the kept backups and the upload record of an installed Nest.
pub fn health(state: &Path) -> Health {
    facts(
        schedule::key_configured(state),
        &schedule::list(Path::new(schedule::BACKUP_DIR)),
        &load(&state.join("agent")),
        schedule::last_run(state),
    )
}

/// `files` newest first. `status`: `none` (nothing kept yet), `pending`,
/// `uploaded` (the newest is in Manage), `failing` or `unsupported`.
pub fn facts(
    key_configured: bool,
    files: &[BackupFile],
    uploads: &Uploads,
    last_run: Option<Value>,
) -> Health {
    let mut attention = Vec::new();
    if !key_configured {
        attention.push("backup_key_missing");
    }
    let newest = files.first();
    let newest_attempt = newest.and_then(|file| uploads.backups.get(&file.backup_id));
    let status = if uploads.unsupported_since.is_some() {
        "unsupported"
    } else if let Some(newest) = newest {
        let uploaded = uploads
            .last_uploaded
            .as_ref()
            .is_some_and(|last| last.backup_id == newest.backup_id)
            || newest_attempt.is_some_and(|attempt| attempt.status == Status::Uploaded);
        match newest_attempt {
            _ if uploaded => "uploaded",
            Some(attempt)
                if matches!(
                    attempt.status,
                    Status::Conflict | Status::TooLarge | Status::Damaged
                ) || attempt.attempts >= FAILING_AFTER_ATTEMPTS =>
            {
                "failing"
            }
            _ => "pending",
        }
    } else {
        "none"
    };
    if status == "failing" {
        attention.push("backup_upload_failing");
    }
    Health {
        fact: json!({
            "key_configured": key_configured,
            "status": status,
            "last_local": newest.map(|file| json!({
                "backup_id": file.backup_id,
                "created_at": file.created_at,
                "size_bytes": file.size_bytes,
            })),
            "kept": files.len(),
            "last_uploaded": uploads.last_uploaded,
            "last_error": newest_attempt.and_then(|attempt| attempt.last_error.clone()),
            "unsupported_since": uploads.unsupported_since,
            "last_run": last_run,
        }),
        attention,
    }
}

#[cfg(test)]
#[path = "upload_tests.rs"]
mod tests;
