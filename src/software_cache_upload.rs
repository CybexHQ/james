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
    collections::{BTreeMap, BTreeSet},
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

use crate::state_files;
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::{StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
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

/// Directory of the grants this Nest holds (`<data_dir>/software-cache-uploads`):
/// per grant the document exactly as Manage sent it (`<id>.grant`, written
/// once) and its upload state (`<id>.state.json`).
fn uploads_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("software-cache-uploads")
}

const STATE_SCHEMA: &str = "tiaris.nest.software-cache-upload.v1";
const MAX_STATE_BYTES: u64 = 1024 * 1024;
const GRANT_STATES: [&str; 5] = ["pending", "uploading", "uploaded", "failed", "expired"];

fn grant_file(id: &str) -> String {
    format!("{id}.grant")
}

fn state_file(id: &str) -> String {
    format!("{id}.state.json")
}

fn valid_grant_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Upload state of one grant. Items are the grant's paths, then its files,
/// named by their index in the grant, so the state can never name anything
/// the grant does not.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantState {
    /// `<issuer>/<scope>` of the organization tree the grant is for.
    tree: String,
    manifest_id: Option<String>,
    expires_at: i64,
    state: String,
    registered: bool,
    error: String,
    attempts: i64,
    next_attempt_at: i64,
    bytes_uploaded: i64,
    received_at: String,
    updated_at: String,
    uploaded: BTreeSet<u32>,
    failed: BTreeMap<u32, String>,
}

impl GrantState {
    fn is_valid(&self, items: usize) -> bool {
        GRANT_STATES.contains(&self.state.as_str())
            && Destination::from_tree(&self.tree).is_some()
            && (0..=64).contains(&self.attempts)
            && self.bytes_uploaded >= 0
            && self
                .uploaded
                .iter()
                .chain(self.failed.keys())
                .all(|index| (*index as usize) < items)
            && self
                .uploaded
                .iter()
                .all(|index| !self.failed.contains_key(index))
            && self.failed.values().all(|reason| valid_reason(reason))
            && valid_reason(&self.error)
    }
}

/// Reasons are this module's own codes.
fn valid_reason(reason: &str) -> bool {
    reason.len() <= 64
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// A grant this Nest holds: its decoded document (`None` when the stored
/// document no longer decodes) and its state.
struct HeldGrant {
    id: String,
    text: Option<String>,
    grant: Option<GrantPayload>,
    state: GrantState,
}

fn read_grant_text(dir: &Path, id: &str) -> Option<String> {
    match state_files::read_bytes(dir, &grant_file(id), MAX_GRANT_BYTES as u64) {
        Ok(Some(bytes)) => String::from_utf8(bytes).ok(),
        Ok(None) => None,
        Err(error) => {
            warn!(grant_id = id, error = %format!("{error:#}"), "ignoring an unreadable upload grant");
            None
        }
    }
}

/// The grant `id` as stored. A grant whose document does not decode (for its
/// tree, to its id) is held without it and fails; a missing or invalid state
/// starts again from `pending`, which can only re-send what the grant names.
fn held_grant(dir: &Path, id: &str) -> Option<HeldGrant> {
    if !valid_grant_id(id) {
        return None;
    }
    let state =
        state_files::read::<GrantState>(dir, &state_file(id), STATE_SCHEMA, MAX_STATE_BYTES);
    let text = read_grant_text(dir, id);
    let tree = state
        .as_ref()
        .and_then(|state| Destination::from_tree(&state.tree));
    let decoded = match (&text, &tree) {
        (Some(text), Some(tree)) => decode_grant(text, tree)
            .ok()
            .filter(|(decoded, _)| decoded == id)
            .map(|(_, grant)| grant),
        _ => None,
    };
    let items = decoded
        .as_ref()
        .map_or(0, |grant| grant.paths.len() + grant.files.len());
    let state = match state {
        Some(state) if state.is_valid(items) => state,
        Some(state) if decoded.is_some() => {
            warn!(
                grant_id = id,
                "upload state breaks its rules; starting the grant again"
            );
            GrantState {
                state: "pending".into(),
                registered: false,
                error: String::new(),
                attempts: 0,
                next_attempt_at: 0,
                bytes_uploaded: 0,
                uploaded: BTreeSet::new(),
                failed: BTreeMap::new(),
                ..state
            }
        }
        // Without a usable state the grant's tree is unknown: it is not
        // uploaded, and Manage's next configuration records it again.
        _ => return None,
    };
    Some(HeldGrant {
        id: id.to_string(),
        text,
        grant: decoded,
        state,
    })
}

fn held_grants(dir: &Path) -> Vec<HeldGrant> {
    let mut grants = state_files::list(dir, ".state.json", 4 * MAX_GRANTS)
        .into_iter()
        .filter_map(|name| held_grant(dir, name.trim_end_matches(".state.json")))
        .collect::<Vec<_>>();
    grants.sort_by(|left, right| {
        left.state
            .received_at
            .cmp(&right.state.received_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    grants
}

fn remove_grant(dir: &Path, id: &str) -> Result<()> {
    state_files::remove(dir, &state_file(id))?;
    state_files::remove(dir, &grant_file(id))
}

/// Changes the state of a grant still held; a withdrawn grant stays gone.
async fn update_state(
    data_dir: &Path,
    id: &str,
    change: impl FnOnce(&mut GrantState),
) -> Result<bool> {
    let dir = uploads_dir(data_dir);
    let _guard = state_files::lock(&dir).await;
    let Some(mut held) = held_grant(&dir, id) else {
        return Ok(false);
    };
    change(&mut held.state);
    held.state.updated_at = now_text();
    state_files::write(
        &dir,
        &state_file(id),
        STATE_SCHEMA,
        MAX_STATE_BYTES,
        &held.state,
    )?;
    Ok(true)
}

/// Applies `software_cache.upload` of the Nest configuration: keeps the write
/// token, records new grants and forgets the grants Manage no longer sends.
pub async fn apply(state: &AppState, upload: Option<&Value>) -> Result<()> {
    apply_with(&state.config.paths.data_dir, upload, false).await
}

async fn apply_with(
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
    let dir = uploads_dir(data_dir);
    let Some(upload) = upload else {
        write_credentials(data_dir, None)?;
        let _guard = state_files::lock(&dir).await;
        for held in held_grants(&dir) {
            remove_grant(&dir, &held.id)?;
        }
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
    let _guard = state_files::lock(&dir).await;
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
        if held_grant(&dir, &id).is_none() {
            let now = now_text();
            state_files::write_bytes(
                &dir,
                &grant_file(&id),
                managed.grant.trim().as_bytes(),
                MAX_GRANT_BYTES as u64,
            )?;
            let state = GrantState {
                tree: destination.tree(),
                manifest_id: grant.manifest_id.clone(),
                expires_at: grant.expires,
                state: "pending".into(),
                received_at: now.clone(),
                updated_at: now,
                ..GrantState::default()
            };
            state_files::write(
                &dir,
                &state_file(&id),
                STATE_SCHEMA,
                MAX_STATE_BYTES,
                &state,
            )?;
        }
        kept.insert(id);
    }
    for held in held_grants(&dir) {
        if !kept.contains(&held.id) {
            remove_grant(&dir, &held.id)?;
        }
    }
    // Grant documents without a state (an interrupted first write).
    for name in state_files::list(&dir, ".grant", 4 * MAX_GRANTS) {
        if !kept.contains(name.trim_end_matches(".grant")) {
            state_files::remove(&dir, &name)?;
        }
    }
    grants_changed().notify_one();
    Ok(())
}

/// Start the uploader.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let uploader = Uploader::from_config(&state.config);
        loop {
            if let Err(error) =
                upload_pass(&state.config.paths.data_dir, &uploader, Utc::now()).await
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

/// One pass over the grants that are due, oldest first.
async fn upload_pass(data_dir: &Path, uploader: &Uploader, now: DateTime<Utc>) -> Result<()> {
    let dir = uploads_dir(data_dir);
    for held in held_grants(&dir) {
        if held.state.expires_at <= now.timestamp()
            && matches!(held.state.state.as_str(), "pending" | "uploading")
        {
            update_state(data_dir, &held.id, |state| state.state = "expired".into()).await?;
        }
    }
    // Without a current write token nothing is sent; Manage rotates it.
    let Some(credentials) = read_credentials(data_dir).filter(|item| item.expires_at > now) else {
        return Ok(());
    };
    let destination = destination(&credentials.url, uploader.allow_loopback_http)?;
    let due = held_grants(&dir)
        .into_iter()
        .filter(|held| {
            matches!(held.state.state.as_str(), "pending" | "uploading")
                && held.state.next_attempt_at <= now.timestamp()
                && held.state.tree == destination.tree()
        })
        .collect::<Vec<_>>();
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
        data_dir,
        client: &client,
        credentials: &credentials,
        destination: &destination,
        uploader,
    };
    for held in due {
        let outcome = session.upload_grant(&held).await?;
        let retry = matches!(outcome, GrantOutcome::Retry(_));
        session.finish_grant(&held, outcome, now).await?;
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
    data_dir: &'a Path,
    client: &'a reqwest::Client,
    credentials: &'a Credentials,
    destination: &'a Destination,
    uploader: &'a Uploader,
}

/// 1, 2, 4 … minutes after the `attempts`-th retry, at most an hour.
fn backoff_seconds(attempts: i64) -> i64 {
    BACKOFF_BASE_SECONDS
        .saturating_mul(1 << attempts.clamp(0, 6))
        .min(BACKOFF_MAX_SECONDS)
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
    async fn upload_grant(&self, held: &HeldGrant) -> Result<GrantOutcome> {
        // A stored grant that no longer decodes fails on its own; the other
        // grants still upload.
        let (Some(grant), Some(text)) = (&held.grant, &held.text) else {
            return Ok(GrantOutcome::Failed("grant_invalid".to_string()));
        };
        let id = held.id.as_str();
        if !self
            .update(id, |state| state.state = "uploading".into())
            .await?
        {
            return Ok(GrantOutcome::Gone);
        }
        if !held.state.registered {
            let response = self
                .client
                .post(format!("{}/upload-grants", self.destination.base))
                .basic_auth("nest", Some(&self.credentials.token))
                .header(header::CONTENT_TYPE, "text/plain")
                .timeout(REQUEST_SLACK)
                .body(text.clone())
                .send()
                .await;
            let status = match response {
                Ok(response) => response.status(),
                Err(error) => return Ok(GrantOutcome::Retry(transport_error(&error))),
            };
            match classify(status, 0) {
                ItemOutcome::Uploaded(_) => {
                    if !self.update(id, |state| state.registered = true).await? {
                        return Ok(GrantOutcome::Gone);
                    }
                }
                ItemOutcome::Refused(reason) => {
                    return Ok(GrantOutcome::Failed(format!("grant_{reason}")));
                }
                ItemOutcome::Quota => return Ok(GrantOutcome::Failed("quota_exceeded".into())),
                ItemOutcome::Retry(reason) => return Ok(GrantOutcome::Retry(reason)),
            }
        }
        let paths = grant.paths.iter().map(|path| (Some(path), None));
        let files = grant.files.iter().map(|file| (None, Some(file)));
        for (index, (path, file)) in paths.chain(files).enumerate() {
            let index = u32::try_from(index)?;
            if held.state.uploaded.contains(&index) || held.state.failed.contains_key(&index) {
                continue;
            }
            if !self.still_granted(id, grant.expires) {
                return Ok(GrantOutcome::Gone);
            }
            let outcome = match (path, file) {
                (Some(path), _) => self.upload_path(id, path).await,
                (_, Some(file)) => self.upload_file(id, file).await,
                _ => unreachable!("every item is a path or a file"),
            };
            let recorded = match outcome {
                ItemOutcome::Uploaded(bytes) => {
                    self.update(id, |state| {
                        state.uploaded.insert(index);
                        state.bytes_uploaded = state
                            .bytes_uploaded
                            .saturating_add(i64::try_from(bytes).unwrap_or(i64::MAX));
                    })
                    .await?
                }
                ItemOutcome::Refused(reason) => {
                    warn!(grant_id = %id, item = index, %reason, "software cache upload refused");
                    self.update(id, |state| {
                        state.failed.insert(index, reason);
                    })
                    .await?
                }
                ItemOutcome::Quota => return Ok(GrantOutcome::Failed("quota_exceeded".into())),
                ItemOutcome::Retry(reason) => return Ok(GrantOutcome::Retry(reason)),
            };
            if !recorded {
                return Ok(GrantOutcome::Gone);
            }
        }
        let failure = held_grant(&uploads_dir(self.data_dir), id)
            .and_then(|held| held.state.failed.values().next().cloned());
        Ok(match failure {
            Some(reason) => GrantOutcome::Failed(reason),
            None => GrantOutcome::Uploaded,
        })
    }

    async fn update(&self, id: &str, change: impl FnOnce(&mut GrantState)) -> Result<bool> {
        update_state(self.data_dir, id, change).await
    }

    fn still_granted(&self, id: &str, expires: i64) -> bool {
        expires > Utc::now().timestamp() && held_grant(&uploads_dir(self.data_dir), id).is_some()
    }

    /// Records a grant's outcome. A retry waits from the moment it failed,
    /// not from the start of the pass, so a long failing upload is not
    /// repeated on the next pass; success resets the backoff.
    async fn finish_grant(
        &self,
        held: &HeldGrant,
        outcome: GrantOutcome,
        pass_started: DateTime<Utc>,
    ) -> Result<()> {
        let failed_at = Utc::now().max(pass_started).timestamp();
        let attempts = held.state.attempts;
        let (state, error, next, attempts) = match &outcome {
            GrantOutcome::Uploaded => ("uploaded", String::new(), 0, 0),
            GrantOutcome::Failed(reason) => ("failed", reason.clone(), 0, attempts),
            GrantOutcome::Retry(reason) => (
                "uploading",
                reason.clone(),
                failed_at + backoff_seconds(attempts),
                (attempts + 1).min(64),
            ),
            GrantOutcome::Gone => return Ok(()),
        };
        match &outcome {
            GrantOutcome::Uploaded => {
                info!(grant_id = %held.id, "uploaded a software cache grant");
            }
            _ => warn!(grant_id = %held.id, state, reason = %error,
                "software cache upload did not complete"),
        }
        self.update(&held.id, |grant| {
            grant.state = state.into();
            grant.error = error;
            grant.next_attempt_at = next;
            grant.attempts = attempts;
        })
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
        // A corrupted NAR is never sent: its size and FileHash are checked
        // first, and the same handle is uploaded.
        let nar = match checked_file(nar, path.file_size, narinfo.file_hash).await {
            Ok(Some(nar)) => nar,
            Ok(None) => return ItemOutcome::Refused("nar_mismatch".into()),
            Err(_) => return ItemOutcome::Refused("not_in_cache".into()),
        };
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
        let Ok(Ok(expected)) = hex::decode(&file.sha256).map(<[u8; 32]>::try_from) else {
            return ItemOutcome::Refused("invalid_file".into());
        };
        let opened = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&local);
        let handle = match opened {
            Ok(handle) => checked_file(handle, file.size, expected).await,
            Err(error) => Err(error.into()),
        };
        let handle = match handle {
            Ok(Some(handle)) => handle,
            Ok(None) => return ItemOutcome::Refused("file_mismatch".into()),
            Err(_) => return ItemOutcome::Refused("file_unavailable".into()),
        };
        let size = file.size;
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

/// `file`, rewound, when it is a regular file of `size` bytes whose SHA-256
/// is `expected`; `None` when it is not. The caller uploads this very handle.
async fn checked_file(file: fs::File, size: u64, expected: [u8; 32]) -> Result<Option<fs::File>> {
    tokio::task::spawn_blocking(move || -> Result<Option<fs::File>> {
        use std::io::{Seek, SeekFrom};
        let mut file = file;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != size {
            return Ok(None);
        }
        let mut hasher = Sha256::new();
        let copied = io::copy(&mut (&mut file).take(size), &mut hasher)?;
        if copied != size || <[u8; 32]>::from(hasher.finalize()) != expected {
            return Ok(None);
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(Some(file))
    })
    .await
    .context("join file check")?
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

/// The state of every grant this Nest holds (`software_cache_uploads`). A
/// grant whose document no longer decodes is reported failed with no totals,
/// so Manage sees it.
pub(crate) fn report(data_dir: &Path) -> Result<Vec<UploadReport>> {
    Ok(held_grants(&uploads_dir(data_dir))
        .into_iter()
        .map(|held| {
            let (paths_total, files_total) = held
                .grant
                .as_ref()
                .map_or((0, 0), |grant| (grant.paths.len(), grant.files.len()));
            let state = held.state;
            let paths_uploaded = state
                .uploaded
                .iter()
                .filter(|index| (**index as usize) < paths_total)
                .count();
            UploadReport {
                grant_id: held.id,
                manifest_id: state.manifest_id,
                state: state.state,
                paths_total,
                paths_uploaded,
                files_total,
                files_uploaded: state.uploaded.len() - paths_uploaded,
                items_failed: state.failed.len(),
                bytes_uploaded: state.bytes_uploaded,
                error: state.error,
                updated_at: state.updated_at,
            }
        })
        .collect())
}

#[cfg(test)]
#[path = "software_cache_upload_tests.rs"]
mod tests;
