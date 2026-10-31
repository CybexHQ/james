//! Access to the Tiaris software cache (`https://cache.tiaris.com`).
//!
//! The NixOS appliance lists the cache as a substituter after cache.nixos.org,
//! trusts its signing key and points Nix's `netrc-file` at
//! `<data_dir>/software-cache.netrc`. Manage sends each Nest a short-lived
//! token in its configuration; this module keeps the netrc file in step. Without
//! a token Nix gets 401 from the cache, treats every path as absent there and
//! the Nest prepares the software itself, as before.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Deserialize;

pub const NETRC_FILE_NAME: &str = "software-cache.netrc";
const MAX_TOKEN_BYTES: usize = 512;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ManagedSoftwareCacheAccess {
    pub url: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

pub fn netrc_path(data_dir: &Path) -> PathBuf {
    data_dir.join(NETRC_FILE_NAME)
}

/// Writes the netrc entry for `access`, or removes the file when Manage sends
/// none. Unchanged access leaves the file untouched.
pub fn apply(data_dir: &Path, access: Option<&ManagedSoftwareCacheAccess>) -> Result<()> {
    let path = netrc_path(data_dir);
    let Some(access) = access else {
        return match fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(error).with_context(|| format!("remove {}", path.display()))
            }
            _ => Ok(()),
        };
    };
    let body = netrc_entry(access)?;
    if fs::read(&path).is_ok_and(|current| current == body.as_bytes()) {
        return Ok(());
    }
    let temporary = path.with_extension("netrc.tmp");
    let _ = fs::remove_file(&temporary);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temporary, &path).with_context(|| format!("replace {}", path.display()))
}

/// One netrc line. Host and token are validated strictly: a space or newline
/// in either would let Manage's value add entries for other machines.
fn netrc_entry(access: &ManagedSoftwareCacheAccess) -> Result<String> {
    let url = reqwest::Url::parse(&access.url).context("software cache URL is invalid")?;
    let host = match (url.scheme(), url.host_str(), url.port(), url.path()) {
        ("https", Some(host), None, "/") if url.username().is_empty() => host,
        _ => bail!("software cache URL must be an HTTPS origin"),
    };
    let host_valid = !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-');
    let token_valid = !access.token.is_empty()
        && access.token.len() <= MAX_TOKEN_BYTES
        && access
            .token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    if !host_valid || !token_valid {
        bail!("software cache access contains unsupported characters");
    }
    Ok(format!(
        "machine {host} login nest password {}\n",
        access.token
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(url: &str, token: &str) -> ManagedSoftwareCacheAccess {
        ManagedSoftwareCacheAccess {
            url: url.into(),
            token: token.into(),
            expires_at: "2026-11-01T12:00:00Z".parse().unwrap(),
        }
    }

    #[test]
    fn writes_replaces_and_removes_the_netrc_file() {
        let directory = std::env::temp_dir().join(format!(
            "tiaris-nest-software-cache-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&directory).unwrap();
        let first = access("https://cache.tiaris.com", "tsc1.dev.1.nest.AAA");
        apply(&directory, Some(&first)).unwrap();
        let path = netrc_path(&directory);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "machine cache.tiaris.com login nest password tsc1.dev.1.nest.AAA\n"
        );
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions())
                & 0o777,
            0o600
        );
        let second = access("https://cache.tiaris.com", "tsc1.dev.2.nest.BBB");
        apply(&directory, Some(&second)).unwrap();
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .ends_with("tsc1.dev.2.nest.BBB\n")
        );
        apply(&directory, None).unwrap();
        assert!(!path.exists());
        apply(&directory, None).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn rejects_values_that_could_change_the_netrc_meaning() {
        for (url, token) in [
            ("https://cache.tiaris.com", "tok en"),
            ("https://cache.tiaris.com", "token\nmachine evil.example"),
            ("https://cache.tiaris.com", ""),
            ("http://cache.tiaris.com", "token"),
            ("https://cache.tiaris.com:8443", "token"),
            ("https://cache.tiaris.com/path", "token"),
            ("https://user@cache.tiaris.com", "token"),
        ] {
            assert!(netrc_entry(&access(url, token)).is_err(), "{url} {token:?}");
        }
        assert!(netrc_entry(&access("https://cache.tiaris.com", &"a".repeat(513))).is_err());
    }
}
