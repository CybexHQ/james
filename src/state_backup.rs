//! Encrypted backup of a Nest's state and its restore onto a replacement.
//!
//! A backup holds every regular file of the STATE partition
//! (`/var/lib/tiaris-nest/state`: identity, keys, signed plan, network and
//! update receipts, state records) and a consistent snapshot of the SQLite
//! database, without what the Nest downloads or rebuilds again (the vulnix
//! database, netboot staging and sessions, cache quarantine, the inbox). It
//! is encrypted to an operator's backup key (X25519, HKDF-SHA256 and
//! ChaCha20-Poly1305 in authenticated 1 MiB chunks), so it can be stored off
//! the Nest; the Nest never holds the key that opens it. Nothing secret is
//! printed: summaries name files, sizes and digests only.
//!
//! A restore decrypts and checks everything into a private staging folder
//! before it changes anything. `data` (the default, for a replacement Nest
//! that was installed and enrolled again) restores the database, the
//! workstation cache signing key and the state records, and keeps the
//! replacement's own Manage identity, credentials, signed plan, network and
//! update receipts: Manage gives a replacement a new key and incarnation.
//! `full` restores everything into an empty STATE (the same Nest on a new
//! disk). See `docs/nest-state-backup.md`.
use std::{
    collections::BTreeMap,
    fs,
    io::{self, BufReader, BufWriter, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use curve25519_dalek::montgomery::MontgomeryPoint;
use ring::{
    aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey},
    hkdf,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The STATE partition of an installed Nest.
pub const STATE_DIR: &str = "/var/lib/tiaris-nest/state";
const MAGIC: &[u8; 28] = b"TIARIS-NEST-STATE-BACKUP-V1\n";
const HEADER_BYTES: usize = 28 + 32 + 32;
const PRIVATE_LABEL: &str = "TIARIS-NEST-BACKUP-KEY-V1";
const PUBLIC_LABEL: &str = "TIARIS-NEST-BACKUP-RECIPIENT-V1";
const INFO: &[u8] = b"tiaris-nest-state-backup-v1 chacha20-poly1305";
const CHUNK: usize = 1024 * 1024;
const TAG: usize = 16;
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 3 * 1024 * 1024 * 1024;
const MAX_FILES: usize = 100_000;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MANIFEST_SCHEMA: &str = "tiaris.nest.state-backup.v1";
/// The live database, replaced in the backup by a consistent snapshot.
pub const DATABASE: &str = "agent/tiaris-nest.sqlite";
const DATABASE_ENTRY: &str = "database/tiaris-nest.sqlite";
/// Downloaded again or transient: never in a backup.
pub const EXCLUDED: &[&str] = &[
    "inbox",
    "lost+found",
    "agent/vulnix",
    "agent/netboot",
    "agent/cache-quarantine",
    "agent/public-cache",
];
/// Bound to the installed machine and its Manage enrolment: a `data` restore
/// keeps the replacement's own.
pub const IDENTITY_BOUND: &[&str] = &[
    "agent/manage-state.json",
    "agent/manage-contact.json",
    "agent/software-cache.netrc",
    "agent/software-cache-upload.json",
    "agent/software-cache-uploads",
    "agent/state-backup-uploads.json",
];
/// Where a backup leaves its secret-free receipt (`local_health`).
pub const RECEIPT: &str = "status/state-backup.json";
pub const RECEIPT_SCHEMA: &str = "tiaris.nest.state-backup-receipt.v1";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("no system randomness"))?;
    Ok(bytes)
}

fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

fn fingerprint(public: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public))
}

fn create_private(path: &Path, mode: u32) -> Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("create {}", path.display()))
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Creates a backup key pair; returns the recipient fingerprint. The private
/// key belongs off the Nest (it opens every backup made to it).
pub fn generate_key(private_out: &Path, public_out: &Path) -> Result<String> {
    let mut secret = random::<32>()?;
    let public = public_of(&secret);
    let mut file = create_private(private_out, 0o600)?;
    file.write_all(format!("{PRIVATE_LABEL}\n{}\n", b64().encode(secret)).as_bytes())?;
    file.sync_all()?;
    secret.fill(0);
    let mut file = create_private(public_out, 0o644)?;
    file.write_all(format!("{PUBLIC_LABEL}\n{}\n", b64().encode(public)).as_bytes())?;
    file.sync_all()?;
    Ok(fingerprint(&public))
}

fn read_key(path: &Path, label: &str, private: bool) -> Result<[u8; 32]> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= 4096,
        "{} is not a backup key file",
        path.display()
    );
    ensure!(
        !private || metadata.mode() & 0o077 == 0,
        "the backup private key {} must be readable by its owner only (chmod 600)",
        path.display()
    );
    let mut text = String::new();
    file.take(4096).read_to_string(&mut text)?;
    let mut lines = text.lines();
    ensure!(
        lines.next() == Some(label),
        "{} is not a {label} file",
        path.display()
    );
    let mut decoded = b64()
        .decode(lines.next().unwrap_or_default().trim())
        .map_err(|_| anyhow!("{} holds no valid key", path.display()))?;
    ensure!(
        decoded.len() == 32 && lines.next().is_none(),
        "{} holds no valid key",
        path.display()
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    decoded.fill(0);
    Ok(key)
}

fn derive(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32]) -> Result<LessSafeKey> {
    ensure!(
        shared.iter().any(|byte| *byte != 0),
        "invalid backup recipient key"
    );
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral);
    salt.extend_from_slice(recipient);
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(shared);
    let okm = prk
        .expand(&[INFO], &CHACHA20_POLY1305)
        .map_err(|_| anyhow!("backup key derivation failed"))?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

fn nonce(counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::assume_unique_for_key(bytes)
}

fn aad(header: &[u8], last: bool) -> Vec<u8> {
    let mut value = header.to_vec();
    value.push(u8::from(last));
    value
}

/// Encrypts a byte stream in authenticated chunks: `[last][length][ciphertext]`
/// after the header, the flag and position bound by the nonce and AAD, so a
/// reordered, truncated or extended backup fails to open.
struct Sealer<W: Write> {
    out: W,
    key: LessSafeKey,
    header: Vec<u8>,
    buffer: Vec<u8>,
    counter: u64,
}

impl<W: Write> Sealer<W> {
    fn new(mut out: W, recipient: &[u8; 32]) -> Result<Self> {
        let mut ephemeral_secret = random::<32>()?;
        let ephemeral = public_of(&ephemeral_secret);
        let shared = MontgomeryPoint(*recipient)
            .mul_clamped(ephemeral_secret)
            .to_bytes();
        ephemeral_secret.fill(0);
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&Sha256::digest(recipient));
        header.extend_from_slice(&ephemeral);
        out.write_all(&header)?;
        Ok(Self {
            out,
            key: derive(&shared, &ephemeral, recipient)?,
            header,
            buffer: Vec::with_capacity(CHUNK + TAG),
            counter: 0,
        })
    }

    fn seal(&mut self, length: usize, last: bool) -> io::Result<()> {
        let mut data: Vec<u8> = self.buffer.drain(..length).collect();
        self.key
            .seal_in_place_append_tag(
                nonce(self.counter),
                Aad::from(aad(&self.header, last)),
                &mut data,
            )
            .map_err(|_| io::Error::other("backup encryption failed"))?;
        self.counter += 1;
        self.out.write_all(&[u8::from(last)])?;
        self.out.write_all(&(data.len() as u32).to_be_bytes())?;
        self.out.write_all(&data)
    }

    fn finish(mut self) -> io::Result<W> {
        let length = self.buffer.len();
        self.seal(length, true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for Sealer<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(bytes);
        while self.buffer.len() > CHUNK {
            self.seal(CHUNK, false)?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Opener<R: Read> {
    input: R,
    key: LessSafeKey,
    header: Vec<u8>,
    plain: Vec<u8>,
    position: usize,
    counter: u64,
    done: bool,
}

impl<R: Read> Opener<R> {
    fn new(mut input: R, secret: &[u8; 32]) -> Result<Self> {
        let mut header = vec![0u8; HEADER_BYTES];
        input
            .read_exact(&mut header)
            .map_err(|_| anyhow!("not a Nest state backup"))?;
        ensure!(&header[..28] == MAGIC, "not a Nest state backup");
        let own = public_of(secret);
        ensure!(
            header[28..60] == Sha256::digest(own)[..],
            "this backup was made for another backup key"
        );
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&header[60..92]);
        let shared = MontgomeryPoint(ephemeral).mul_clamped(*secret).to_bytes();
        Ok(Self {
            input,
            key: derive(&shared, &ephemeral, &own)?,
            header,
            plain: Vec::new(),
            position: 0,
            counter: 0,
            done: false,
        })
    }

    fn next_chunk(&mut self) -> io::Result<()> {
        let truncated = || io::Error::new(io::ErrorKind::InvalidData, "backup is truncated");
        let mut frame = [0u8; 5];
        self.input.read_exact(&mut frame).map_err(|_| truncated())?;
        ensure_io(frame[0] <= 1, "backup chunk is malformed")?;
        let length = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        ensure_io(
            (TAG..=CHUNK + TAG).contains(&length),
            "backup chunk is malformed",
        )?;
        let mut data = vec![0u8; length];
        self.input.read_exact(&mut data).map_err(|_| truncated())?;
        let last = frame[0] == 1;
        let plain = self
            .key
            .open_in_place(
                nonce(self.counter),
                Aad::from(aad(&self.header, last)),
                &mut data,
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "backup failed authentication (damaged or altered)",
                )
            })?
            .len();
        data.truncate(plain);
        self.counter += 1;
        self.plain = data;
        self.position = 0;
        if last {
            let mut extra = [0u8; 1];
            ensure_io(
                self.input.read(&mut extra)? == 0,
                "backup has data after its end",
            )?;
            self.done = true;
        }
        Ok(())
    }
}

fn ensure_io(condition: bool, message: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, message))
    }
}

impl<R: Read> Read for Opener<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.position == self.plain.len() {
            if self.done {
                return Ok(0);
            }
            self.next_chunk()?;
        }
        let count = out.len().min(self.plain.len() - self.position);
        out[..count].copy_from_slice(&self.plain[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

/// One file of the backup, as the manifest records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    created_at: String,
    nest_release: String,
    device_id: Option<String>,
    database: Option<FileRecord>,
    files: Vec<FileRecord>,
    excluded: Vec<String>,
}

/// What `backup` printed and recorded: no secret material.
#[derive(Clone, Debug, Serialize)]
pub struct BackupSummary {
    pub schema: &'static str,
    pub output: String,
    pub created_at: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub files: usize,
    pub database_bytes: Option<u64>,
    pub recipient_fingerprint: String,
}

/// Whether a STATE-relative path belongs in a backup.
pub fn included(relative: &str) -> bool {
    !relative.split('/').any(|part| part.starts_with('.'))
        && !EXCLUDED
            .iter()
            .any(|prefix| relative == *prefix || relative.starts_with(&format!("{prefix}/")))
        && !matches!(
            relative.strip_prefix(DATABASE),
            Some("" | "-wal" | "-shm" | "-journal")
        )
}

fn identity_bound(relative: &str) -> bool {
    IDENTITY_BOUND
        .iter()
        .any(|prefix| relative == *prefix || relative.starts_with(&format!("{prefix}/")))
}

fn walk(root: &Path, relative: &Path, out: &mut Vec<(String, fs::Metadata)>) -> Result<()> {
    let directory = root.join(relative);
    let mut entries = fs::read_dir(&directory)
        .with_context(|| format!("read {}", directory.display()))?
        .collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let path = relative.join(&name);
        let text = path
            .to_str()
            .ok_or_else(|| anyhow!("state path is not UTF-8"))?
            .to_owned();
        if !included(&text) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            walk(root, &path, out)?;
        } else if metadata.is_file() {
            ensure!(out.len() < MAX_FILES, "state holds too many files");
            ensure!(
                metadata.len() <= MAX_FILE_BYTES,
                "state file {text} exceeds the backup bound"
            );
            out.push((text, metadata));
        }
        // Links, sockets and devices are not Nest state.
    }
    Ok(())
}

struct Hashing<R> {
    inner: R,
    digest: Sha256,
    bytes: u64,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(out)?;
        self.digest.update(&out[..count]);
        self.bytes += count as u64;
        Ok(count)
    }
}

fn append<W: Write>(
    builder: &mut tar::Builder<W>,
    name: &str,
    file: fs::File,
    size: u64,
) -> Result<(String, u64)> {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o600);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    let mut reader = Hashing {
        inner: file.take(size),
        digest: Sha256::new(),
        bytes: 0,
    };
    builder.append_data(&mut header, name, &mut reader)?;
    ensure!(
        reader.bytes == size,
        "{name} changed while it was backed up"
    );
    Ok((hex::encode(reader.digest.finalize()), reader.bytes))
}

fn record(path: &str, metadata: &fs::Metadata, sha256: String, size: u64) -> FileRecord {
    FileRecord {
        path: path.into(),
        sha256,
        size_bytes: size,
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
    }
}

fn open_nofollow(path: &Path) -> Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

fn device_id(state: &Path) -> Option<String> {
    let body = fs::read(state.join("agent/manage-state.json")).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&body).ok()?;
    value["device_id"]
        .as_str()
        .filter(|id| id.len() <= 128)
        .map(str::to_owned)
}

/// Backs up `state` to a new file `output`, encrypted to `recipient`.
pub async fn backup(state: &Path, recipient: &Path, output: &Path) -> Result<BackupSummary> {
    let recipient = read_key(recipient, PUBLIC_LABEL, false)?;
    let state = fs::canonicalize(state)?;
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure!(
        !fs::canonicalize(parent)?.starts_with(&state),
        "write the backup outside the state it backs up"
    );
    let snapshot = output.with_file_name(format!(
        ".{}.database-{}",
        output
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("backup"),
        uuid::Uuid::new_v4().simple()
    ));
    // Only a file this run created may be removed on failure: `output` may
    // name an earlier backup (a second date-named backup on the same day).
    let mut created = false;
    let result = async {
        let database = state.join(DATABASE);
        let database_metadata = match fs::symlink_metadata(&database) {
            Ok(metadata) if metadata.is_file() => {
                crate::schema_evolution::private_copy(&database, &snapshot).await?;
                Some(metadata)
            }
            Ok(_) => bail!("the Nest database is not a regular file"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let mut files = Vec::new();
        walk(&state, Path::new(""), &mut files)?;
        let total: u64 = files.iter().map(|(_, metadata)| metadata.len()).sum();
        ensure!(total <= MAX_TOTAL_BYTES, "state exceeds the backup bound");
        let created_at = crate::db::now_rfc3339();
        let file = create_private(output, 0o600)?;
        created = true;
        let sealer = Sealer::new(BufWriter::new(file), &recipient)?;
        let mut builder = tar::Builder::new(zstd::Encoder::new(sealer, 3)?);
        let mut records = Vec::new();
        for (path, metadata) in &files {
            let file = open_nofollow(&state.join(path))?;
            let opened = file.metadata()?;
            ensure!(
                opened.is_file() && opened.ino() == metadata.ino(),
                "{path} changed while it was backed up"
            );
            let (sha256, size) =
                append(&mut builder, &format!("state/{path}"), file, opened.len())?;
            records.push(record(path, &opened, sha256, size));
        }
        let database = match &database_metadata {
            Some(metadata) => {
                let file = open_nofollow(&snapshot)?;
                let size = file.metadata()?.len();
                let (sha256, size) = append(&mut builder, DATABASE_ENTRY, file, size)?;
                Some(record(DATABASE, metadata, sha256, size))
            }
            None => None,
        };
        let manifest = Manifest {
            schema: MANIFEST_SCHEMA.into(),
            created_at: created_at.clone(),
            nest_release: env!("CARGO_PKG_VERSION").into(),
            device_id: device_id(&state),
            database,
            files: records,
            excluded: EXCLUDED.iter().map(|path| (*path).into()).collect(),
        };
        let body = serde_json::to_vec(&manifest)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o600);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        builder.append_data(&mut header, "manifest.json", body.as_slice())?;
        let writer = builder.into_inner()?.finish()?.finish()?;
        let file = writer.into_inner().map_err(|error| error.into_error())?;
        file.sync_all()?;
        drop(file);
        sync_parent(output)?;
        let mut digest = Sha256::new();
        let size = io::copy(&mut open_nofollow(output)?, &mut digest)?;
        anyhow::Ok(BackupSummary {
            schema: "tiaris.nest.state-backup-summary.v1",
            output: output.display().to_string(),
            created_at,
            size_bytes: size,
            sha256: hex::encode(digest.finalize()),
            files: manifest.files.len(),
            database_bytes: manifest.database.as_ref().map(|record| record.size_bytes),
            recipient_fingerprint: fingerprint(&recipient),
        })
    }
    .await;
    let _ = fs::remove_file(&snapshot);
    if result.is_err() && created {
        let _ = fs::remove_file(output);
    }
    let summary = result?;
    if let Err(error) = write_receipt(&state, &summary) {
        tracing::warn!(error = %error, "state backup receipt was not written");
    }
    Ok(summary)
}

/// Writes the secret-free receipt the daemon reports (`status/` is
/// root:tiaris-nest 0750; the receipt is 0640 in that group).
fn write_receipt(state: &Path, summary: &BackupSummary) -> Result<()> {
    let target = state.join(RECEIPT);
    let directory = target.parent().expect("receipt has a directory");
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() => metadata,
        _ => return Ok(()),
    };
    let body = serde_json::to_vec(&serde_json::json!({
        "schema": RECEIPT_SCHEMA,
        "created_at": summary.created_at,
        "size_bytes": summary.size_bytes,
        "sha256": summary.sha256,
        "files": summary.files,
        "recipient_fingerprint": summary.recipient_fingerprint,
    }))?;
    let temporary = directory.join(format!(
        ".state-backup.json.tmp-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let mut file = create_private(&temporary, 0o640)?;
    file.write_all(&body)?;
    if unsafe { libc::geteuid() } == 0 {
        std::os::unix::fs::fchown(&file, Some(0), Some(metadata.gid()))?;
    }
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &target)?;
    sync_parent(&target)
}

/// The last backup's receipt, for `local_health`.
pub fn last_receipt(state: &Path) -> Option<serde_json::Value> {
    let path = state.join(RECEIPT);
    let file = open_nofollow(&path).ok()?;
    let mut body = Vec::new();
    file.take(16 * 1024).read_to_end(&mut body).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&body).ok()?;
    (value["schema"] == RECEIPT_SCHEMA).then(|| {
        serde_json::json!({
            "created_at": value["created_at"],
            "size_bytes": value["size_bytes"],
            "files": value["files"],
        })
    })
}

/// Which files a restore writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// A replacement Nest: database, cache signing key and state records;
    /// keeps its own identity, credentials, plan, network and receipts.
    Data,
    /// Everything, into an empty STATE (the same Nest on a new disk).
    Full,
}

/// What `restore` did: no secret material.
#[derive(Clone, Debug, Serialize)]
pub struct RestoreSummary {
    pub schema: &'static str,
    pub scope: Scope,
    pub dry_run: bool,
    pub backup_created_at: String,
    pub backup_nest_release: String,
    pub backup_device_id: Option<String>,
    pub files_restored: usize,
    pub files_kept: Vec<String>,
    pub database_restored: bool,
}

fn safe_relative(path: &str) -> Result<PathBuf> {
    let relative = Path::new(path);
    ensure!(
        !path.is_empty()
            && path.len() <= 512
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
            && included(path),
        "backup holds an unsafe path"
    );
    Ok(relative.to_path_buf())
}

/// Entry name to its SHA-256 (hex) and size.
type Digests = BTreeMap<String, (String, u64)>;

/// Decrypts, bounds and digests every entry into `staging`.
fn extract(backup: &Path, secret: &[u8; 32], staging: &Path) -> Result<(Manifest, Digests)> {
    let opener = Opener::new(BufReader::new(open_nofollow(backup)?), secret)?;
    let mut archive = tar::Archive::new(zstd::Decoder::new(opener)?);
    let mut seen = BTreeMap::new();
    let mut total = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        ensure!(
            entry.header().entry_type() == tar::EntryType::Regular,
            "backup holds a non-file entry"
        );
        let name = entry
            .path()?
            .to_str()
            .ok_or_else(|| anyhow!("backup path is not UTF-8"))?
            .to_owned();
        let size = entry.size();
        let bound = if name == "manifest.json" {
            MAX_MANIFEST_BYTES
        } else {
            MAX_FILE_BYTES
        };
        ensure!(size <= bound, "backup entry {name} exceeds its bound");
        total = total.saturating_add(size);
        ensure!(
            total <= MAX_TOTAL_BYTES && seen.len() <= MAX_FILES,
            "backup exceeds its bound"
        );
        let target = match name.as_str() {
            "manifest.json" | DATABASE_ENTRY => staging.join(&name),
            other => {
                let relative = other
                    .strip_prefix("state/")
                    .ok_or_else(|| anyhow!("backup holds an unexpected entry"))?;
                staging.join("state").join(safe_relative(relative)?)
            }
        };
        ensure!(!seen.contains_key(&name), "backup repeats {name}");
        fs::create_dir_all(target.parent().expect("entry has a directory"))?;
        let mut file = create_private(&target, 0o600)?;
        let mut reader = Hashing {
            inner: (&mut entry).take(size),
            digest: Sha256::new(),
            bytes: 0,
        };
        io::copy(&mut reader, &mut file)?;
        ensure!(reader.bytes == size, "backup entry {name} is short");
        file.sync_all()?;
        seen.insert(name, (hex::encode(reader.digest.finalize()), size));
    }
    // Authenticate to the very end: the tar end marker can come before the
    // final chunk, and only that chunk proves the backup is complete.
    let mut decoder = archive.into_inner();
    io::copy(&mut decoder, &mut io::sink())?;
    let manifest_path = staging.join("manifest.json");
    ensure!(manifest_path.is_file(), "backup has no manifest");
    let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    ensure!(
        manifest.schema == MANIFEST_SCHEMA,
        "unknown backup manifest schema"
    );
    let mut expected: Digests = manifest
        .files
        .iter()
        .map(|file| {
            safe_relative(&file.path)?;
            Ok((
                format!("state/{}", file.path),
                (file.sha256.clone(), file.size_bytes),
            ))
        })
        .collect::<Result<_>>()?;
    ensure!(
        expected.len() == manifest.files.len(),
        "backup manifest repeats a file"
    );
    if let Some(database) = &manifest.database {
        ensure!(database.path == DATABASE, "backup database path");
        expected.insert(
            DATABASE_ENTRY.into(),
            (database.sha256.clone(), database.size_bytes),
        );
    }
    seen.remove("manifest.json");
    ensure!(seen == expected, "backup contents differ from its manifest");
    Ok((manifest, seen))
}

fn remove_tree(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn ensure_parent(state: &Path, relative: &Path, owner: (u32, u32), root: bool) -> Result<()> {
    let mut current = state.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) => ensure!(
                    metadata.is_dir(),
                    "{} is not a directory",
                    current.display()
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    fs::create_dir(&current)?;
                    fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?;
                    if root {
                        std::os::unix::fs::chown(&current, Some(owner.0), Some(owner.1))?;
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn place(source: &Path, target: &Path, record: &FileRecord, root: bool) -> Result<()> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    file.set_permissions(fs::Permissions::from_mode(record.mode & 0o777))?;
    if root {
        std::os::unix::fs::fchown(&file, Some(record.uid), Some(record.gid))?;
    }
    file.sync_all()?;
    drop(file);
    fs::rename(source, target)?;
    sync_parent(target)
}

/// Restores `backup` (opened with the private key at `identity`) into
/// `state`. Nothing is changed unless the whole backup authenticates, matches
/// its manifest and holds a database this release can run on.
pub async fn restore(
    backup: &Path,
    identity: &Path,
    state: &Path,
    scope: Scope,
    dry_run: bool,
) -> Result<RestoreSummary> {
    let mut secret = read_key(identity, PRIVATE_LABEL, true)?;
    let state = fs::canonicalize(state)?;
    let staging = state.join(format!(".restore-{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
    let result = async {
        let (manifest, _) = extract(backup, &secret, &staging)?;
        secret.fill(0);
        let staged_database = staging.join(DATABASE_ENTRY);
        if manifest.database.is_some() {
            crate::schema_evolution::verify_openable(&staged_database)
                .await
                .context("the backed-up database cannot be opened by this Nest release")?;
        }
        if scope == Scope::Full {
            for entry in fs::read_dir(&state)? {
                let name = entry?.file_name();
                ensure!(
                    name == "lost+found" || name == staging.file_name().expect("staging name"),
                    "a full restore needs an empty state directory"
                );
            }
        }
        let root = unsafe { libc::geteuid() } == 0;
        let mut restored = 0usize;
        let mut kept = Vec::new();
        for record in &manifest.files {
            if scope == Scope::Data
                && (!record.path.starts_with("agent/") || identity_bound(&record.path))
            {
                kept.push(record.path.clone());
                continue;
            }
            restored += 1;
            if dry_run {
                continue;
            }
            let relative = safe_relative(&record.path)?;
            ensure_parent(&state, &relative, (record.uid, record.gid), root)?;
            place(
                &staging.join("state").join(&relative),
                &state.join(&relative),
                record,
                root,
            )?;
        }
        let database_restored = manifest.database.is_some();
        if let (Some(record), false) = (&manifest.database, dry_run) {
            let relative = Path::new(DATABASE);
            ensure_parent(&state, relative, (record.uid, record.gid), root)?;
            // A leftover journal of the database being replaced must never be
            // applied to the restored one.
            for suffix in ["-wal", "-shm", "-journal"] {
                match fs::remove_file(state.join(format!("{DATABASE}{suffix}"))) {
                    Err(error) if error.kind() != io::ErrorKind::NotFound => {
                        return Err(error.into());
                    }
                    _ => {}
                }
            }
            place(&staged_database, &state.join(relative), record, root)?;
        }
        anyhow::Ok(RestoreSummary {
            schema: "tiaris.nest.state-restore-summary.v1",
            scope,
            dry_run,
            backup_created_at: manifest.created_at,
            backup_nest_release: manifest.nest_release,
            backup_device_id: manifest.device_id,
            files_restored: restored,
            files_kept: kept,
            database_restored,
        })
    }
    .await;
    secret.fill(0);
    remove_tree(&staging);
    result
}

pub mod schedule;
pub mod upload;

#[cfg(test)]
mod tests;
