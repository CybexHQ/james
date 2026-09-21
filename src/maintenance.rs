#[cfg(unix)]
use std::os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt},
};
use std::{fs, io, path::Path};

use anyhow::{Context, Result, bail};

const APPLIANCE_UPDATE_LOCK: &str = "/run/lock/cybex-james/appliance-update.lock";
const CONTROL: &str = "/var/lib/cybex-james/control";

fn generation_recovery_pending(control: &Path) -> bool {
    [
        "system-prepare-intent.json",
        "pending-system-generation.json",
        "system-commit-intent.json",
        "system-rollback-intent.json",
    ]
    .iter()
    .any(|name| match fs::symlink_metadata(control.join(name)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        // Existence, including malformed or inaccessible evidence, fences work.
        // Only the root supervisor can authenticate and clear these receipts.
        _ => true,
    })
}

/// Return whether appliance maintenance currently holds the shared mutation
/// lease. Netboot publication uses this as a promotion barrier while an
/// appliance update is changing the installed runtime.
pub fn lease_active() -> Result<bool> {
    if crate::appliance::nixos::is_nixos() && generation_recovery_pending(Path::new(CONTROL)) {
        return Ok(true);
    }
    let path = Path::new(if crate::appliance::nixos::is_nixos() {
        "/run/lock/cybex-james/maintenance.lock"
    } else {
        APPLIANCE_UPDATE_LOCK
    });
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(true),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };

    #[cfg(unix)]
    {
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect {}", path.display()))?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || (metadata.uid() != unsafe { libc::geteuid() } && metadata.uid() != 0)
        {
            bail!("appliance maintenance lock must be a singly-linked trusted file");
        }
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(true);
            }
            return Err(error).with_context(|| format!("lock {}", path.display()));
        }
        let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }

    Ok(false)
}

/// Hold the shared fixed-inode maintenance barrier for an entire build, including
/// source preparation and output promotion. A root exclusive transaction cannot
/// race past a point-in-time `lease_active` check.
pub struct BuildLease(Option<fs::File>);
impl Drop for BuildLease {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(file) = &self.0 {
            unsafe {
                libc::flock(file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}
pub async fn acquire_build_lease() -> Result<BuildLease> {
    if !crate::appliance::nixos::is_nixos() {
        return Ok(BuildLease(None));
    }
    loop {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/run/lock/cybex-james/maintenance.lock")?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != 0
            || metadata.gid() != 985
            || metadata.mode() & 0o007 != 0
        {
            bail!("unsafe maintenance barrier")
        }
        let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        if status == 0 {
            if !generation_recovery_pending(Path::new(CONTROL)) {
                return Ok(BuildLease(Some(file)));
            }
            // Check inside the lease: an updater cannot publish its seal between
            // this test and claiming work. After reboot its durable receipts
            // give recovery priority over every queued build.
            drop(BuildLease(Some(file)));
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock {
            return Err(error.into());
        }
        drop(file);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_generation_recovery_fences_builds_until_cleanup() {
        let root = std::env::temp_dir().join(format!("james-maintenance-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        assert!(!generation_recovery_pending(&root));
        for receipt in [
            "system-prepare-intent.json",
            "pending-system-generation.json",
            "system-commit-intent.json",
            "system-rollback-intent.json",
        ] {
            fs::write(root.join(receipt), b"untrusted or incomplete receipt").unwrap();
            assert!(generation_recovery_pending(&root));
            fs::remove_file(root.join(receipt)).unwrap();
            assert!(!generation_recovery_pending(&root));
        }
        std::os::unix::fs::symlink(
            root.join("absent"),
            root.join("pending-system-generation.json"),
        )
        .unwrap();
        assert!(generation_recovery_pending(&root));
        fs::remove_dir_all(root).unwrap();
    }
}
