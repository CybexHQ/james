//! Atomic writer for small, world-readable status documents under `/run`.
//!
//! The tty1 kiosk reads these projections as a different unit. They are
//! presentation only, so every caller treats a failed write as best-effort.
use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// Replace `path` with `body` (mode 0644) using a same-directory temporary
/// file, fsync and rename. A missing parent is created with mode 0755; an
/// existing parent must be a real directory and is left unchanged.
pub(crate) fn write_public_json(path: &Path, body: &[u8], maximum: usize) -> Result<()> {
    if body.len() > maximum {
        bail!("{} exceeds its {maximum}-byte bound", path.display())
    }
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent", path.display()))?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => bail!("{} is not a directory", parent.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", parent.display()));
        }
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("status");
    let temporary = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        // Writers run with UMask=0077; the kiosk reads as another unit.
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
