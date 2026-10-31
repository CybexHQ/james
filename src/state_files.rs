//! Small state records kept as files under the Nest state directory.
//!
//! The NixOS appliance updater requires every release to carry the SQLite
//! migration inventory of the release it replaces (`release/sqlite-migrations.sha256`),
//! so state added without an update-contract design lives here instead of in
//! new tables. Every record is one JSON document `{schema, version, data}`:
//!
//! - written atomically: a private temporary file (`O_CREAT|O_EXCL`, 0600,
//!   `O_NOFOLLOW`) is written, fsynced and renamed over the record, then the
//!   directory is fsynced;
//! - read without following links, only when it is a regular file of at most
//!   the record's size bound, and only with the expected schema and version;
//! - tolerant of absence and corruption: an unreadable record is logged and
//!   treated as absent, never a crash. Callers validate the content as
//!   strictly as they would anything else they did not write themselves.
//!
//! Directories are created 0700 and must not be links. Read-modify-write
//! sequences hold `lock(dir)`, one async lock per directory in this process.
use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use rand::RngCore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tracing::warn;

/// Version of the envelope every record carries.
pub(crate) const VERSION: u32 = 1;

#[derive(Serialize)]
struct EnvelopeOut<'a, T> {
    schema: &'a str,
    version: u32,
    data: &'a T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeIn {
    schema: String,
    version: u32,
    data: Value,
}

/// Serialises read-modify-write sequences on the records of `dir`.
pub(crate) async fn lock(dir: &Path) -> OwnedMutexGuard<()> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<AsyncMutex<()>>>>> = OnceLock::new();
    let lock = LOCKS
        .get_or_init(Default::default)
        .lock()
        .expect("state file lock map")
        .entry(dir.to_path_buf())
        .or_default()
        .clone();
    lock.lock_owned().await
}

/// Creates `dir` (0700) and its parents; refuses a link or non-directory.
pub(crate) fn ensure_dir(dir: &Path) -> Result<()> {
    match fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
    {
        Ok(()) => {}
        Err(error) => {
            return Err(error).with_context(|| format!("create {}", dir.display()));
        }
    }
    let metadata =
        fs::symlink_metadata(dir).with_context(|| format!("inspect {}", dir.display()))?;
    if !metadata.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    Ok(())
}

/// A record file name: letters, digits, `.`, `-` and `_`, not starting with
/// a dot (temporary files do).
pub(crate) fn valid_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn record_path(dir: &Path, name: &str) -> Result<PathBuf> {
    if !valid_name(name) {
        bail!("state record name {name:?} is not a plain file name");
    }
    Ok(dir.join(name))
}

/// Writes `bytes` as `dir/name` atomically.
pub(crate) fn write_bytes(dir: &Path, name: &str, bytes: &[u8], max_bytes: u64) -> Result<()> {
    if bytes.len() as u64 > max_bytes {
        bail!("state record {name} exceeds {max_bytes} bytes");
    }
    ensure_dir(dir)?;
    let path = record_path(dir, name)?;
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let temporary = dir.join(format!(".{name}.tmp-{}", hex::encode(suffix)));
    let written = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &path).with_context(|| format!("replace {}", path.display()))?;
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

/// The bytes of `dir/name`; `Ok(None)` when absent. A link, a non-regular
/// file or one larger than `max_bytes` is an error.
pub(crate) fn read_bytes(dir: &Path, name: &str, max_bytes: u64) -> Result<Option<Vec<u8>>> {
    let path = record_path(dir, name)?;
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if metadata.len() > max_bytes {
        bail!("{} exceeds {max_bytes} bytes", path.display());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        bail!("{} exceeds {max_bytes} bytes", path.display());
    }
    Ok(Some(bytes))
}

/// Writes `data` as the record `dir/name` with `schema`.
pub(crate) fn write<T: Serialize>(
    dir: &Path,
    name: &str,
    schema: &str,
    max_bytes: u64,
    data: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec(&EnvelopeOut {
        schema,
        version: VERSION,
        data,
    })?;
    write_bytes(dir, name, &bytes, max_bytes)
}

/// Parses a record's bytes: the envelope must name `schema` and `VERSION`.
pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8], schema: &str) -> Result<T> {
    let envelope: EnvelopeIn =
        serde_json::from_slice(bytes).context("state record is not a JSON envelope")?;
    if envelope.schema != schema || envelope.version != VERSION {
        bail!(
            "state record is {} version {}, not {schema} version {VERSION}",
            envelope.schema,
            envelope.version
        );
    }
    serde_json::from_value(envelope.data).map_err(|error| anyhow!("state record data: {error}"))
}

/// The record `dir/name`, or `None` when it is absent or unusable. An
/// unusable record is logged; the caller treats it as absent.
pub(crate) fn read<T: DeserializeOwned>(
    dir: &Path,
    name: &str,
    schema: &str,
    max_bytes: u64,
) -> Option<T> {
    let bytes = match read_bytes(dir, name, max_bytes) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return None,
        Err(error) => {
            warn!(record = %dir.join(name).display(), error = %format!("{error:#}"),
                "ignoring an unreadable state record");
            return None;
        }
    };
    match decode(&bytes, schema) {
        Ok(data) => Some(data),
        Err(error) => {
            warn!(record = %dir.join(name).display(), error = %format!("{error:#}"),
                "ignoring a corrupt state record");
            None
        }
    }
}

/// Removes `dir/name`; absence is fine.
pub(crate) fn remove(dir: &Path, name: &str) -> Result<()> {
    let path = record_path(dir, name)?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

/// A temporary file this old belongs to an interrupted write, not a live one.
const STALE_TEMPORARY_AGE: Duration = Duration::from_secs(10 * 60);

/// Record names in `dir` ending in `suffix`, sorted, at most `limit`; leftover
/// temporary files of interrupted writes are removed. A missing directory has
/// none.
pub(crate) fn list(dir: &Path, suffix: &str, limit: usize) -> Vec<String> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            if error.kind() != io::ErrorKind::NotFound {
                warn!(dir = %dir.display(), error = %error, "could not list state records");
            }
            return Vec::new();
        }
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.starts_with('.') && name.contains(".tmp-") {
            // Another task may be between creating and renaming this file;
            // only an interrupted write is old.
            let stale = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age >= STALE_TEMPORARY_AGE);
            if stale {
                let _ = fs::remove_file(entry.path());
            }
            continue;
        }
        if valid_name(&name) && name.ends_with(suffix) {
            names.push(name);
        }
    }
    names.sort();
    names.truncate(limit);
    names
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use serde_json::json;

    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tiaris-nest-state-files-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn records_are_written_privately_and_read_back_strictly() {
        let dir = dir("roundtrip");
        write(&dir, "a.json", "test.v1", 1024, &json!({"x": 1})).unwrap();
        let path = dir.join("a.json");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            read::<Value>(&dir, "a.json", "test.v1", 1024),
            Some(json!({"x": 1}))
        );
        // Another schema or version is not this record.
        assert_eq!(read::<Value>(&dir, "a.json", "test.v2", 1024), None);
        fs::write(&path, r#"{"schema":"test.v1","version":2,"data":{}}"#).unwrap();
        assert_eq!(read::<Value>(&dir, "a.json", "test.v1", 1024), None);
        fs::write(
            &path,
            r#"{"schema":"test.v1","version":1,"data":{},"extra":1}"#,
        )
        .unwrap();
        assert_eq!(read::<Value>(&dir, "a.json", "test.v1", 1024), None);
        // Corrupt, truncated or oversized records are absent, not a crash.
        fs::write(&path, b"{\"schema\":\"test.v1\",\"vers").unwrap();
        assert_eq!(read::<Value>(&dir, "a.json", "test.v1", 1024), None);
        fs::write(&path, vec![b' '; 2048]).unwrap();
        assert_eq!(read::<Value>(&dir, "a.json", "test.v1", 1024), None);
        assert!(write(&dir, "a.json", "test.v1", 8, &json!({"x": 1})).is_err());
        assert_eq!(read::<Value>(&dir, "missing.json", "test.v1", 1024), None);
        remove(&dir, "a.json").unwrap();
        remove(&dir, "a.json").unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn links_and_unsafe_names_are_refused() {
        let dir = dir("links");
        ensure_dir(&dir).unwrap();
        let target = dir.join("target");
        fs::write(&target, r#"{"schema":"test.v1","version":1,"data":1}"#).unwrap();
        std::os::unix::fs::symlink(&target, dir.join("link.json")).unwrap();
        assert!(read_bytes(&dir, "link.json", 1024).is_err());
        assert_eq!(read::<Value>(&dir, "link.json", "test.v1", 1024), None);
        // Writing replaces the link itself, never its target.
        write(&dir, "link.json", "test.v1", 1024, &2).unwrap();
        assert_eq!(
            read::<Value>(&dir, "link.json", "test.v1", 1024),
            Some(json!(2))
        );
        assert_eq!(
            read::<Value>(&dir, "target", "test.v1", 1024),
            Some(json!(1))
        );
        for name in ["../x", "a/b", ".hidden", "", "a b"] {
            assert!(write(&dir, name, "test.v1", 1024, &1).is_err(), "{name}");
        }
        let linked = dir.join("linked-dir");
        std::os::unix::fs::symlink(&dir, &linked).unwrap();
        assert!(ensure_dir(&linked).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn listing_skips_and_cleans_interrupted_writes() {
        let dir = dir("list");
        write(&dir, "b.json", "test.v1", 1024, &1).unwrap();
        write(&dir, "a.json", "test.v1", 1024, &1).unwrap();
        fs::write(dir.join(".a.json.tmp-0011"), b"partial").unwrap();
        fs::File::options()
            .write(true)
            .open(dir.join(".a.json.tmp-0011"))
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        fs::write(dir.join(".b.json.tmp-0022"), b"in flight").unwrap();
        fs::write(dir.join("other.txt"), b"x").unwrap();
        assert_eq!(list(&dir, ".json", 10), ["a.json", "b.json"]);
        assert_eq!(list(&dir, ".json", 1), ["a.json"]);
        assert!(!dir.join(".a.json.tmp-0011").exists());
        // A write still in progress keeps its temporary file.
        assert!(dir.join(".b.json.tmp-0022").exists());
        assert!(list(&dir.join("missing"), ".json", 10).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
