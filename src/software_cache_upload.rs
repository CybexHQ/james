//! Off-site downloads: uploads to the organization's tree of the Tiaris
//! software cache (Manage `docs/design/nest-driven-software-updates.md`,
//! section 7, and `docs/software-cache.md`).
//!
//! A computer away from school cannot reach its Nest. For an update that may
//! be downloaded off-site, Manage signs an upload grant naming what this Nest
//! may upload: the closure paths it built itself, with the hashes and sizes of
//! its verified closure manifest, and files such as the workstation runtime's
//! Manage source archive. Nest advertises `software_cache_upload_v1` only to a
//! Manage that says it accepts it (`software_cache_upload_supported`), and
//! receives
//!
//! ```json
//! "software_cache": {"url": "…", "token": "tsc1…", "expires_at": "…",
//!   "upload": {"url": "https://cache.tiaris.com/o/<issuer>/o-<organization hex>",
//!              "token": "tsc2.….w.…", "expires_at": "…",
//!              "grants": [{"grant": "tug1.<payload>.<mac>", "grant_id": "…"}]}}
//! ```
//!
//! For each grant Nest registers it (`POST <url>/upload-grants`), then uploads
//! every granted store path from its own cache, NAR before narinfo, the
//! narinfo exactly as Nix wrote it (with the Nest signature), and each granted
//! file, all as Nix HTTP binary cache PUTs with the write token as the Basic
//! password and `X-Tiaris-Upload-Grant: <grant id>`. Nothing that is not in a
//! grant is ever sent, and a local narinfo or file that does not match its
//! grant is refused locally. One grant and one upload at a time, at most
//! `BYTES_PER_SECOND`; failures are retried with backoff until the grant
//! expires. The write token is kept in a 0600 file and never logged. Each
//! report carries the state of every grant (`software_cache_uploads`).
use std::{
    collections::BTreeSet,
    fmt, fs,
    future::Future,
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    pin::Pin,
    sync::OnceLock,
    task::{Context as TaskContext, Poll, ready},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::{StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, SqlitePool};
use tokio::{
    io::{AsyncRead, AsyncReadExt, ReadBuf},
    sync::Notify,
    time::{Instant, Sleep, sleep},
};
use tracing::{info, warn};

use crate::AppState;

pub const CAPABILITY: &str = "software_cache_upload_v1";
pub const CREDENTIALS_FILE_NAME: &str = "software-cache-upload.json";
/// Root-owned offline Manage source archives (`<revision>.tar`).
const SOURCE_ARCHIVE_DIR: &str = "/usr/share/tiaris-nest/manage-source";
const GRANT_SCHEMA: &str = "tiaris.software-cache.upload-grant.v1";
const GRANT_HEADER: &str = "X-Tiaris-Upload-Grant";
const MAX_GRANTS: usize = 32;
/// The cache server's limits.
const MAX_GRANT_BYTES: usize = 4 * 1024 * 1024;
const MAX_UPLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_CREDENTIALS_BYTES: u64 = 4096;
/// Upload bandwidth: one upload at a time at most this fast (64 Mbit/s).
const BYTES_PER_SECOND: u64 = 8 * 1024 * 1024;
/// A request may take as long as the upload at this rate, plus slack.
const MIN_ASSUMED_BYTES_PER_SECOND: u64 = 256 * 1024;
const REQUEST_SLACK: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const PASS_INTERVAL: Duration = Duration::from_secs(60);
const BACKOFF_BASE_SECONDS: i64 = 60;
const BACKOFF_MAX_SECONDS: i64 = 3600;
const NIX32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

fn grants_changed() -> &'static Notify {
    static SIGNAL: OnceLock<Notify> = OnceLock::new();
    SIGNAL.get_or_init(Notify::new)
}

/// `software_cache.upload` of the Nest configuration.
#[derive(Clone, Deserialize)]
pub struct ManagedUpload {
    pub url: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub grants: Vec<ManagedGrant>,
}

impl fmt::Debug for ManagedUpload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedUpload")
            .field("url", &self.url)
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("grants", &self.grants.len())
            .finish()
    }
}

/// One upload grant Manage hands this Nest. Only `grant` is needed; Manage's
/// other fields (`grant_id`, `expires_at`, counts) are checked or ignored.
#[derive(Clone, Debug, Deserialize)]
pub struct ManagedGrant {
    pub grant: String,
    #[serde(default)]
    pub grant_id: Option<String>,
}

/// The upload destination and write token, kept in `CREDENTIALS_FILE_NAME`.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
struct Credentials {
    url: String,
    token: String,
    expires_at: DateTime<Utc>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("url", &self.url)
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// An organization tree: `<origin>/o/<issuer>/<scope>`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Destination {
    base: String,
    issuer: String,
    scope: String,
}

/// `https://<host>/o/<issuer>/o-<32 hex>`; plain HTTP to a loopback address
/// only in tests.
fn destination(url: &str, allow_loopback_http: bool) -> Result<Destination> {
    let parsed = reqwest::Url::parse(url).context("software cache upload URL is invalid")?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("software cache upload URL has no host"))?;
    let scheme_ok = parsed.scheme() == "https"
        || (allow_loopback_http && parsed.scheme() == "http" && host == "127.0.0.1");
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-');
    let tree = parsed
        .path()
        .trim_end_matches('/')
        .strip_prefix("/o/")
        .and_then(|tree| tree.split_once('/'))
        .filter(|(issuer, scope)| valid_issuer(issuer) && valid_scope(scope))
        .map(|(issuer, scope)| (issuer.to_string(), scope.to_string()));
    let (true, true, Some((issuer, scope))) = (scheme_ok, host_ok, tree) else {
        bail!("software cache upload URL must be https://<host>/o/<issuer>/o-<organization hex>");
    };
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (parsed.port().is_some() && !allow_loopback_http)
    {
        bail!("software cache upload URL must be a plain origin and tree path");
    }
    let origin = match parsed.port() {
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    };
    Ok(Destination {
        base: format!("{origin}/o/{issuer}/{scope}"),
        issuer,
        scope,
    })
}

impl Destination {
    /// `<issuer>/<scope>`, as grants are stored.
    fn tree(&self) -> String {
        format!("{}/{}", self.issuer, self.scope)
    }

    fn from_tree(tree: &str) -> Option<Self> {
        let (issuer, scope) = tree.split_once('/')?;
        (valid_issuer(issuer) && valid_scope(scope)).then(|| Self {
            base: String::new(),
            issuer: issuer.to_string(),
            scope: scope.to_string(),
        })
    }
}

fn valid_issuer(issuer: &str) -> bool {
    (1..=16).contains(&issuer.len())
        && issuer
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_scope(scope: &str) -> bool {
    scope.len() == 34
        && scope.starts_with("o-")
        && scope[2..]
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub fn credentials_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CREDENTIALS_FILE_NAME)
}

/// Writes the credentials (0600, never through a link), or removes them.
/// Unchanged credentials leave the file untouched.
fn write_credentials(data_dir: &Path, credentials: Option<&Credentials>) -> Result<()> {
    let path = credentials_path(data_dir);
    let Some(credentials) = credentials else {
        return match fs::remove_file(&path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                Err(error).with_context(|| format!("remove {}", path.display()))
            }
            _ => Ok(()),
        };
    };
    if read_credentials(data_dir).as_ref() == Some(credentials) {
        return Ok(());
    }
    let body = serde_json::to_vec(credentials)?;
    let temporary = path.with_extension("json.tmp");
    let _ = fs::remove_file(&temporary);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    file.write_all(&body)?;
    file.sync_all()?;
    fs::rename(&temporary, &path).with_context(|| format!("replace {}", path.display()))
}

fn read_credentials(data_dir: &Path) -> Option<Credentials> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(credentials_path(data_dir))
        .ok()?;
    let mut body = Vec::new();
    file.take(MAX_CREDENTIALS_BYTES)
        .read_to_end(&mut body)
        .ok()?;
    serde_json::from_slice(&body).ok()
}

#[derive(Clone, Debug, Deserialize)]
struct GrantPayload {
    schema: String,
    issuer: String,
    scope: String,
    expires: i64,
    #[serde(default)]
    manifest_id: Option<String>,
    paths: Vec<GrantPath>,
    files: Vec<GrantFile>,
}

#[derive(Clone, Debug, Deserialize)]
struct GrantPath {
    store_path: String,
    nar_url: String,
    compression: String,
    file_hash: String,
    file_size: u64,
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct GrantFile {
    path: String,
    sha256: String,
    size: u64,
}

fn store_hash(store_path: &str) -> Option<&str> {
    let name = store_path.strip_prefix("/nix/store/")?;
    let (hash, rest) = name.split_at_checked(32)?;
    (hash.bytes().all(|byte| NIX32.contains(&byte))
        && rest.starts_with('-')
        && rest.len() > 1
        && rest[1..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(&byte)))
    .then_some(hash)
}

fn compression_suffix(compression: &str) -> Option<&'static str> {
    match compression {
        "none" => Some(""),
        "xz" => Some(".xz"),
        "zstd" => Some(".zst"),
        "bzip2" => Some(".bz2"),
        _ => None,
    }
}

fn valid_nar_url(nar_url: &str, compression: &str) -> bool {
    compression_suffix(compression)
        .and_then(|suffix| {
            nar_url
                .strip_prefix("nar/")?
                .strip_suffix(&format!(".nar{suffix}"))
        })
        .is_some_and(|name| name.len() == 52 && name.bytes().all(|byte| NIX32.contains(&byte)))
}

/// The Manage source revision of `manage-source/<40 hex>.tar`.
fn source_revision(path: &str) -> Option<&str> {
    path.strip_prefix("manage-source/")?
        .strip_suffix(".tar")
        .filter(|revision| {
            revision.len() == 40
                && revision
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// The id and payload of a `tug1.<payload>.<mac>` grant for `scope`. Nest
/// cannot check the MAC (the cache server does); it checks that the grant
/// names only well-formed items, so a malformed grant is never acted on.
fn decode_grant(text: &str, tree: &Destination) -> Result<(String, GrantPayload)> {
    let parts = text.trim().split('.').collect::<Vec<_>>();
    let ["tug1", payload, mac] = parts[..] else {
        bail!("upload grant is not a tug1 document");
    };
    if text.len() > MAX_GRANT_BYTES || payload.is_empty() || mac.is_empty() {
        bail!("upload grant is empty or too large");
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .context("upload grant payload is not base64url")?;
    let grant: GrantPayload =
        serde_json::from_slice(&decoded).context("upload grant payload is invalid")?;
    if grant.schema != GRANT_SCHEMA {
        bail!("upload grant has an unsupported schema");
    }
    if grant.scope != tree.scope || grant.issuer != tree.issuer {
        bail!("upload grant is for another organization tree");
    }
    if grant.paths.is_empty() && grant.files.is_empty() {
        bail!("upload grant names nothing");
    }
    for path in &grant.paths {
        let sizes_ok = (1..=MAX_UPLOAD_BYTES).contains(&path.file_size)
            && (1..=MAX_UPLOAD_BYTES).contains(&path.nar_size);
        if store_hash(&path.store_path).is_none()
            || !valid_nar_url(&path.nar_url, &path.compression)
            || crate::cache::sha256_digest(&path.file_hash).is_err()
            || crate::cache::sha256_digest(&path.nar_hash).is_err()
            || !sizes_ok
            || path
                .references
                .iter()
                .any(|reference| store_hash(reference).is_none())
        {
            bail!("upload grant names a malformed store path");
        }
    }
    for file in &grant.files {
        if source_revision(&file.path).is_none()
            || file.sha256.len() != 64
            || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !(1..=MAX_UPLOAD_BYTES).contains(&file.size)
        {
            bail!("upload grant names a malformed file");
        }
    }
    let id = hex::encode(&Sha256::digest(payload.as_bytes())[..16]);
    Ok((id, grant))
}

fn now_text() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Applies `software_cache.upload` of the Nest configuration: keeps the write
/// token, records new grants and forgets the grants Manage no longer sends.
pub async fn apply(state: &AppState, upload: Option<&Value>) -> Result<()> {
    apply_with(&state.db, &state.config.paths.data_dir, upload, false).await
}

async fn apply_with(
    db: &SqlitePool,
    data_dir: &Path,
    upload: Option<&Value>,
    allow_loopback_http: bool,
) -> Result<()> {
    let upload = match upload {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            serde_json::from_value::<ManagedUpload>(value.clone())
                .map_err(|_| anyhow!("software_cache.upload is not {{url, token, expires_at}}"))?,
        ),
    };
    let Some(upload) = upload else {
        write_credentials(data_dir, None)?;
        sqlx::query("DELETE FROM software_cache_upload_grants")
            .execute(db)
            .await?;
        return Ok(());
    };
    let destination = destination(&upload.url, allow_loopback_http)?;
    if !valid_token(&upload.token) {
        bail!("software cache upload token contains unsupported characters");
    }
    write_credentials(
        data_dir,
        Some(&Credentials {
            url: upload.url.clone(),
            token: upload.token.clone(),
            expires_at: upload.expires_at,
        }),
    )?;
    let mut kept = BTreeSet::new();
    for managed in upload.grants.iter().take(MAX_GRANTS) {
        let (id, grant) = match decode_grant(&managed.grant, &destination) {
            Ok(decoded) => decoded,
            Err(error) => {
                warn!(error = %error, "ignoring an unusable software cache upload grant");
                continue;
            }
        };
        if managed.grant_id.as_deref().is_some_and(|given| given != id) {
            warn!(grant_id = %id, "ignoring an upload grant whose id does not match it");
            continue;
        }
        let now = now_text();
        sqlx::query(
            "INSERT INTO software_cache_upload_grants
                 (grant_id, grant_text, manifest_id, tree, expires_at, state, received_at,
                  updated_at)
             VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
             ON CONFLICT(grant_id) DO NOTHING",
        )
        .bind(&id)
        .bind(managed.grant.trim())
        .bind(grant.manifest_id.as_deref())
        .bind(destination.tree())
        .bind(grant.expires)
        .bind(&now)
        .bind(&now)
        .execute(db)
        .await?;
        kept.insert(id);
    }
    let held = sqlx::query_scalar::<_, String>("SELECT grant_id FROM software_cache_upload_grants")
        .fetch_all(db)
        .await?;
    for id in held.into_iter().filter(|id| !kept.contains(id)) {
        sqlx::query("DELETE FROM software_cache_upload_grants WHERE grant_id = ?")
            .bind(id)
            .execute(db)
            .await?;
    }
    grants_changed().notify_one();
    Ok(())
}

/// Start the uploader.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let uploader = Uploader::from_config(&state.config);
        loop {
            if let Err(error) = upload_pass(
                &state.db,
                &state.config.paths.data_dir,
                &uploader,
                Utc::now(),
            )
            .await
            {
                warn!(error = %error, "software cache upload pass failed");
            }
            tokio::select! {
                _ = sleep(PASS_INTERVAL) => {}
                _ = grants_changed().notified() => {}
            }
        }
    });
}

/// Where uploads come from and how fast they go.
#[derive(Clone, Debug)]
struct Uploader {
    cache_root: PathBuf,
    source_dir: PathBuf,
    bytes_per_second: u64,
    allow_loopback_http: bool,
}

impl Uploader {
    fn from_config(config: &crate::config::AppConfig) -> Self {
        Self {
            cache_root: config.cache.root_dir.clone(),
            source_dir: PathBuf::from(SOURCE_ARCHIVE_DIR),
            bytes_per_second: BYTES_PER_SECOND,
            allow_loopback_http: false,
        }
    }
}

#[derive(Clone, Debug, FromRow)]
struct GrantRow {
    grant_id: String,
    grant_text: String,
    registered: bool,
    attempts: i64,
}

/// One pass over the grants that are due, oldest first.
async fn upload_pass(
    db: &SqlitePool,
    data_dir: &Path,
    uploader: &Uploader,
    now: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        "UPDATE software_cache_upload_grants SET state = 'expired', updated_at = ?
         WHERE expires_at <= ? AND state IN ('pending', 'uploading')",
    )
    .bind(now_text())
    .bind(now.timestamp())
    .execute(db)
    .await?;
    // Without a current write token nothing is sent; Manage rotates it.
    let Some(credentials) = read_credentials(data_dir).filter(|item| item.expires_at > now) else {
        return Ok(());
    };
    let destination = destination(&credentials.url, uploader.allow_loopback_http)?;
    let due = sqlx::query_as::<_, GrantRow>(
        "SELECT grant_id, grant_text, registered, attempts FROM software_cache_upload_grants
         WHERE state IN ('pending', 'uploading') AND next_attempt_at <= ? AND tree = ?
         ORDER BY received_at, grant_id",
    )
    .bind(now.timestamp())
    .bind(destination.tree())
    .fetch_all(db)
    .await?;
    if due.is_empty() {
        return Ok(());
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .https_only(!uploader.allow_loopback_http)
        .build()
        .context("create the software cache upload client")?;
    let session = Session {
        db,
        client: &client,
        credentials: &credentials,
        destination: &destination,
        uploader,
    };
    for row in due {
        let outcome = session.upload_grant(&row).await?;
        let retry = matches!(outcome, GrantOutcome::Retry(_));
        session.finish_grant(&row, outcome, now).await?;
        if retry {
            // The service or the network is unavailable: try every grant
            // again on the next pass rather than failing each in turn.
            break;
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum GrantOutcome {
    Uploaded,
    /// Refused for good, with the first reason.
    Failed(String),
    /// Try again later (network, server or token trouble).
    Retry(String),
    /// Manage withdrew the grant meanwhile, or it expired.
    Gone,
}

#[derive(Debug, PartialEq, Eq)]
enum ItemOutcome {
    Uploaded(u64),
    Refused(String),
    Retry(String),
    Quota,
}

struct Session<'a> {
    db: &'a SqlitePool,
    client: &'a reqwest::Client,
    credentials: &'a Credentials,
    destination: &'a Destination,
    uploader: &'a Uploader,
}

/// What a status means for one upload.
fn classify(status: StatusCode, uploaded: u64) -> ItemOutcome {
    match status.as_u16() {
        200..=299 => ItemOutcome::Uploaded(uploaded),
        507 => ItemOutcome::Quota,
        // The token rotated or expired: try again with the next one.
        401 => ItemOutcome::Retry("unauthorized".to_string()),
        400 | 403 | 404 | 409 | 411 | 413 => {
            ItemOutcome::Refused(format!("refused_{}", status.as_u16()))
        }
        _ => ItemOutcome::Retry(format!("http_{}", status.as_u16())),
    }
}

impl Session<'_> {
    async fn upload_grant(&self, row: &GrantRow) -> Result<GrantOutcome> {
        let (id, grant) = decode_grant(&row.grant_text, self.destination)?;
        if id != row.grant_id {
            return Ok(GrantOutcome::Failed("grant_mismatch".to_string()));
        }
        sqlx::query(
            "UPDATE software_cache_upload_grants SET state = 'uploading', updated_at = ?
             WHERE grant_id = ?",
        )
        .bind(now_text())
        .bind(&id)
        .execute(self.db)
        .await?;
        if !row.registered {
            let response = self
                .client
                .post(format!("{}/upload-grants", self.destination.base))
                .basic_auth("nest", Some(&self.credentials.token))
                .header(header::CONTENT_TYPE, "text/plain")
                .timeout(REQUEST_SLACK)
                .body(row.grant_text.clone())
                .send()
                .await;
            let status = match response {
                Ok(response) => response.status(),
                Err(error) => return Ok(GrantOutcome::Retry(transport_error(&error))),
            };
            match classify(status, 0) {
                ItemOutcome::Uploaded(_) => {
                    sqlx::query(
                        "UPDATE software_cache_upload_grants SET registered = 1
                         WHERE grant_id = ?",
                    )
                    .bind(&id)
                    .execute(self.db)
                    .await?;
                }
                ItemOutcome::Refused(reason) => {
                    return Ok(GrantOutcome::Failed(format!("grant_{reason}")));
                }
                ItemOutcome::Quota => return Ok(GrantOutcome::Failed("quota_exceeded".into())),
                ItemOutcome::Retry(reason) => return Ok(GrantOutcome::Retry(reason)),
            }
        }
        let done = sqlx::query_scalar::<_, String>(
            "SELECT item FROM software_cache_upload_items WHERE grant_id = ?",
        )
        .bind(&id)
        .fetch_all(self.db)
        .await?
        .into_iter()
        .collect::<BTreeSet<_>>();
        let items = grant
            .paths
            .iter()
            .map(|path| {
                (
                    format!("{}.narinfo", store_hash(&path.store_path).unwrap_or("")),
                    Some(path),
                    None,
                )
            })
            .chain(
                grant
                    .files
                    .iter()
                    .map(|file| (file.path.clone(), None, Some(file))),
            );
        for (item, path, file) in items {
            if done.contains(&item) {
                continue;
            }
            if !self.still_granted(&id, grant.expires).await? {
                return Ok(GrantOutcome::Gone);
            }
            let outcome = match (path, file) {
                (Some(path), _) => self.upload_path(&id, path).await,
                (_, Some(file)) => self.upload_file(&id, file).await,
                _ => unreachable!("every item is a path or a file"),
            };
            match outcome {
                ItemOutcome::Uploaded(bytes) => {
                    self.record_item(&id, &item, "uploaded", "", bytes).await?;
                }
                ItemOutcome::Refused(reason) => {
                    warn!(grant_id = %id, %item, %reason, "software cache upload refused");
                    self.record_item(&id, &item, "failed", &reason, 0).await?;
                }
                ItemOutcome::Quota => return Ok(GrantOutcome::Failed("quota_exceeded".into())),
                ItemOutcome::Retry(reason) => return Ok(GrantOutcome::Retry(reason)),
            }
        }
        let failure = sqlx::query_scalar::<_, String>(
            "SELECT error FROM software_cache_upload_items
             WHERE grant_id = ? AND state = 'failed' ORDER BY item LIMIT 1",
        )
        .bind(&id)
        .fetch_optional(self.db)
        .await?;
        Ok(match failure {
            Some(reason) => GrantOutcome::Failed(reason),
            None => GrantOutcome::Uploaded,
        })
    }

    async fn still_granted(&self, id: &str, expires: i64) -> Result<bool> {
        if expires <= Utc::now().timestamp() {
            return Ok(false);
        }
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM software_cache_upload_grants WHERE grant_id = ?)",
        )
        .bind(id)
        .fetch_one(self.db)
        .await?)
    }

    async fn record_item(
        &self,
        id: &str,
        item: &str,
        state: &str,
        error: &str,
        bytes: u64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO software_cache_upload_items (grant_id, item, state, error)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(grant_id, item) DO UPDATE SET state = excluded.state,
                 error = excluded.error",
        )
        .bind(id)
        .bind(item)
        .bind(state)
        .bind(error)
        .execute(self.db)
        .await?;
        sqlx::query(
            "UPDATE software_cache_upload_grants
             SET bytes_uploaded = bytes_uploaded + ?, updated_at = ? WHERE grant_id = ?",
        )
        .bind(i64::try_from(bytes).unwrap_or(i64::MAX))
        .bind(now_text())
        .bind(id)
        .execute(self.db)
        .await?;
        Ok(())
    }

    async fn finish_grant(
        &self,
        row: &GrantRow,
        outcome: GrantOutcome,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let (state, error, next) = match &outcome {
            GrantOutcome::Uploaded => ("uploaded", String::new(), 0),
            GrantOutcome::Failed(reason) => ("failed", reason.clone(), 0),
            GrantOutcome::Retry(reason) => {
                let delay = BACKOFF_BASE_SECONDS
                    .saturating_mul(1 << row.attempts.clamp(0, 6))
                    .min(BACKOFF_MAX_SECONDS);
                ("uploading", reason.clone(), now.timestamp() + delay)
            }
            GrantOutcome::Gone => return Ok(()),
        };
        match &outcome {
            GrantOutcome::Uploaded => {
                info!(grant_id = %row.grant_id, "uploaded a software cache grant");
            }
            _ => warn!(grant_id = %row.grant_id, state, reason = %error,
                "software cache upload did not complete"),
        }
        sqlx::query(
            "UPDATE software_cache_upload_grants
             SET state = ?, error = ?, next_attempt_at = ?,
                 attempts = attempts + ?, updated_at = ?
             WHERE grant_id = ?",
        )
        .bind(state)
        .bind(error)
        .bind(next)
        .bind(i64::from(matches!(outcome, GrantOutcome::Retry(_))))
        .bind(now_text())
        .bind(&row.grant_id)
        .execute(self.db)
        .await?;
        Ok(())
    }

    /// NAR, then narinfo, of one granted store path from the Nest cache.
    async fn upload_path(&self, id: &str, path: &GrantPath) -> ItemOutcome {
        let Some(hash) = store_hash(&path.store_path) else {
            return ItemOutcome::Refused("invalid_store_path".into());
        };
        let narinfo =
            match crate::cache::read_cached_narinfo(&self.uploader.cache_root, &path.store_path) {
                Ok(narinfo) => narinfo,
                Err(_) => return ItemOutcome::Refused("not_in_cache".into()),
            };
        if !narinfo_matches(&narinfo, path) {
            return ItemOutcome::Refused("narinfo_mismatch".into());
        }
        let narinfo_url = format!("{}/{hash}.narinfo", self.destination.base);
        // Already in the tree (an earlier grant, or a retry after the narinfo
        // was stored): nothing to send.
        if self
            .client
            .get(&narinfo_url)
            .basic_auth("nest", Some(&self.credentials.token))
            .timeout(REQUEST_SLACK)
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::OK)
        {
            return ItemOutcome::Uploaded(0);
        }
        let nar = match crate::cache::open_cached_nar(&self.uploader.cache_root, &path.nar_url) {
            Ok(nar) => nar,
            Err(_) => return ItemOutcome::Refused("not_in_cache".into()),
        };
        if nar.metadata().map(|metadata| metadata.len()).ok() != Some(path.file_size) {
            return ItemOutcome::Refused("nar_mismatch".into());
        }
        let nar_url = format!("{}/{}", self.destination.base, path.nar_url);
        match self.put_file(id, &nar_url, nar, path.file_size).await {
            ItemOutcome::Uploaded(_) => {}
            other => return other,
        }
        let response = self
            .client
            .put(&narinfo_url)
            .basic_auth("nest", Some(&self.credentials.token))
            .header(GRANT_HEADER, id)
            .header(header::CONTENT_TYPE, "text/x-nix-narinfo")
            .timeout(REQUEST_SLACK)
            .body(narinfo.text.clone())
            .send()
            .await;
        match response {
            Ok(response) => classify(
                response.status(),
                path.file_size + narinfo.text.len() as u64,
            ),
            Err(error) => ItemOutcome::Retry(transport_error(&error)),
        }
    }

    /// A granted file, after checking its size and SHA-256 locally.
    async fn upload_file(&self, id: &str, file: &GrantFile) -> ItemOutcome {
        let Some(revision) = source_revision(&file.path) else {
            return ItemOutcome::Refused("invalid_file".into());
        };
        let local = self.uploader.source_dir.join(format!("{revision}.tar"));
        let expected = file.sha256.to_ascii_lowercase();
        let size = file.size;
        let checked = tokio::task::spawn_blocking(move || -> Result<Option<fs::File>> {
            let mut handle = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&local)?;
            if !handle.metadata()?.is_file() || handle.metadata()?.len() != size {
                return Ok(None);
            }
            let mut hasher = Sha256::new();
            io::copy(&mut handle, &mut hasher)?;
            if hex::encode(hasher.finalize()) != expected {
                return Ok(None);
            }
            Ok(Some(
                fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&local)?,
            ))
        })
        .await;
        let handle = match checked {
            Ok(Ok(Some(handle))) => handle,
            Ok(Ok(None)) => return ItemOutcome::Refused("file_mismatch".into()),
            _ => return ItemOutcome::Refused("file_unavailable".into()),
        };
        let url = format!("{}/{}", self.destination.base, file.path);
        self.put_file(id, &url, handle, size).await
    }

    /// PUT exactly `size` bytes of `file` at the upload rate.
    async fn put_file(&self, id: &str, url: &str, file: fs::File, size: u64) -> ItemOutcome {
        let reader = Throttled::new(
            tokio::fs::File::from_std(file).take(size),
            self.uploader.bytes_per_second,
        );
        let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(reader));
        let response = self
            .client
            .put(url)
            .basic_auth("nest", Some(&self.credentials.token))
            .header(GRANT_HEADER, id)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, size)
            .timeout(REQUEST_SLACK + Duration::from_secs(size / MIN_ASSUMED_BYTES_PER_SECOND))
            .body(body)
            .send()
            .await;
        match response {
            Ok(response) => classify(response.status(), size),
            Err(error) => ItemOutcome::Retry(transport_error(&error)),
        }
    }
}

/// A reason code for a transport error. reqwest errors carry the URL but
/// never the Basic credentials; only the kind is kept.
fn transport_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "timeout".into()
    } else if error.is_connect() {
        "connect_failed".into()
    } else {
        "transport_failed".into()
    }
}

/// The local narinfo describes exactly the granted path.
fn narinfo_matches(narinfo: &crate::cache::CachedNarInfo, path: &GrantPath) -> bool {
    let digest = |value: &str| crate::cache::sha256_digest(value).ok();
    let references = path
        .references
        .iter()
        .map(|reference| reference.trim_start_matches("/nix/store/").to_string())
        .collect::<BTreeSet<_>>();
    narinfo.store_path == path.store_path
        && narinfo.url == path.nar_url
        && narinfo.compression == path.compression
        && Some(narinfo.file_hash) == digest(&path.file_hash)
        && narinfo.file_size == path.file_size
        && Some(narinfo.nar_hash) == digest(&path.nar_hash)
        && narinfo.nar_size == path.nar_size
        && narinfo.references == references
}

/// An `AsyncRead` that yields at most `rate` bytes per second (with one
/// second of burst).
struct Throttled<R> {
    inner: R,
    rate: u64,
    started: Instant,
    sent: u64,
    wait: Option<Pin<Box<Sleep>>>,
}

impl<R> Throttled<R> {
    fn new(inner: R, rate: u64) -> Self {
        Self {
            inner,
            rate: rate.max(1),
            started: Instant::now(),
            sent: 0,
            wait: None,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Throttled<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if let Some(wait) = this.wait.as_mut() {
                ready!(wait.as_mut().poll(cx));
                this.wait = None;
            }
            let allowed =
                (this.rate as f64 * this.started.elapsed().as_secs_f64()) as u64 + this.rate;
            if this.sent < allowed {
                let budget = usize::try_from(allowed - this.sent)
                    .unwrap_or(usize::MAX)
                    .min(buf.remaining());
                let read = {
                    let mut limited = buf.take(budget);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut limited))?;
                    limited.filled().len()
                };
                // SAFETY: `limited` filled these bytes of `buf`'s unfilled part.
                unsafe { buf.assume_init(read) };
                buf.advance(read);
                this.sent += read as u64;
                return Poll::Ready(Ok(()));
            }
            let behind = (this.sent - allowed + 1) as f64 / this.rate as f64;
            this.wait = Some(Box::pin(sleep(Duration::from_secs_f64(behind))));
        }
    }
}

/// One grant in the Nest report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct UploadReport {
    pub(crate) grant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) manifest_id: Option<String>,
    pub(crate) state: String,
    pub(crate) paths_total: usize,
    pub(crate) paths_uploaded: usize,
    pub(crate) files_total: usize,
    pub(crate) files_uploaded: usize,
    pub(crate) items_failed: usize,
    pub(crate) bytes_uploaded: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) error: String,
    pub(crate) updated_at: String,
}

#[derive(Debug, FromRow)]
struct ReportRow {
    grant_id: String,
    grant_text: String,
    manifest_id: Option<String>,
    tree: String,
    state: String,
    error: String,
    bytes_uploaded: i64,
    updated_at: String,
}

/// The state of every grant this Nest holds (`software_cache_uploads`).
pub(crate) async fn report(db: &SqlitePool) -> Result<Vec<UploadReport>> {
    let rows = sqlx::query_as::<_, ReportRow>(
        "SELECT grant_id, grant_text, manifest_id, tree, state, error, bytes_uploaded,
                updated_at
         FROM software_cache_upload_grants ORDER BY received_at, grant_id",
    )
    .fetch_all(db)
    .await?;
    let mut reports = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(Ok((_, grant))) =
            Destination::from_tree(&row.tree).map(|tree| decode_grant(&row.grant_text, &tree))
        else {
            continue;
        };
        let items = sqlx::query_as::<_, (String, String)>(
            "SELECT item, state FROM software_cache_upload_items WHERE grant_id = ?",
        )
        .bind(&row.grant_id)
        .fetch_all(db)
        .await?;
        let uploaded = |paths: bool| {
            items
                .iter()
                .filter(|(item, state)| state == "uploaded" && item.ends_with(".narinfo") == paths)
                .count()
        };
        reports.push(UploadReport {
            grant_id: row.grant_id,
            manifest_id: row.manifest_id,
            state: row.state,
            paths_total: grant.paths.len(),
            paths_uploaded: uploaded(true),
            files_total: grant.files.len(),
            files_uploaded: uploaded(false),
            items_failed: items.iter().filter(|(_, state)| state == "failed").count(),
            bytes_uploaded: row.bytes_uploaded,
            error: row.error,
            updated_at: row.updated_at,
        });
    }
    Ok(reports)
}

#[cfg(test)]
#[path = "software_cache_upload_tests.rs"]
mod tests;
