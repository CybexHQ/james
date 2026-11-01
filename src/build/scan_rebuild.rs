//! A finished Blueprint job built again for a software update scan
//! (`crate::software_updates::findings`).
//!
//! The Nest serves finished closures from its cache and removes a job's
//! out-link once the job ends, so garbage collection takes the closure and its
//! derivations from the store, which vulnix needs. The scanner builds such a
//! job again from its own build spec, through the same validation, admission
//! and source policy as its worker, into the job's out-link, and drops that
//! root once the scan is done.
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use tracing::warn;

use super::{
    WorkstationBuildProfile, admit_build_target, ensure_nix_daemon_available,
    nix_build_command_with_nixpkgs_nar_hash, preflight_source_build_check_for_profile,
    source_build_blocked_message, validate_build_spec,
};
use crate::{AppState, db, subprocess::run_cancellable_command};

const REBUILD_STDOUT_MAX_BYTES: usize = 64 * 1024;
const REBUILD_STDERR_TAIL_BYTES: usize = 64 * 1024;

/// A rebuilt closure, kept from garbage collection by the job's out-link
/// until dropped.
pub(crate) struct RebuiltClosure {
    pub(crate) output_path: String,
    dirs: [PathBuf; 2],
}

impl Drop for RebuiltClosure {
    fn drop(&mut self) {
        remove_dirs(&self.dirs);
    }
}

fn remove_dirs(dirs: &[PathBuf]) {
    for dir in dirs {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                warn!(error = %error, path = %dir.display(), "failed to remove a rebuilt scan closure's directory");
            }
        }
    }
}

/// The build's arguments with plain logs: only the error tail is kept.
fn plain_log_args(args: &[String]) -> Vec<&String> {
    let mut kept = Vec::with_capacity(args.len());
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--print-build-logs" => {}
            "--log-format" => {
                args.next();
            }
            _ => kept.push(arg),
        }
    }
    kept
}

/// Build succeeded Blueprint job `job_id` again; `None` while the Nest has no
/// memory for a build, so the scan waits.
pub(crate) async fn rebuild_for_scan(
    state: &AppState,
    job_id: i64,
) -> Result<Option<RebuiltClosure>> {
    let config = &state.config;
    let _maintenance_lease = crate::maintenance::acquire_build_lease().await?;
    let Some(_memory_lease) = state.build_admission.try_acquire(&config.build) else {
        return Ok(None);
    };
    let job = db::get_build_job(&state.db, job_id)
        .await
        .map_err(|error| anyhow::anyhow!("read build job {job_id}: {error}"))?;
    if job.status != "succeeded" {
        bail!("build job {job_id} is {}, not succeeded", job.status);
    }
    let spec = validate_build_spec(config, &job)?;
    if spec.build_input.is_none() || spec.closure_source.is_some() {
        bail!("build job {job_id} is not a Blueprint build");
    }
    let detected = match spec.nixpkgs_commit.as_deref() {
        Some(commit) => {
            crate::software_updates::ready_commit(&config.paths.data_dir, commit).await?
        }
        None => None,
    };
    let admitted = admit_build_target(
        config,
        &spec,
        detected.as_ref().map(|ready| ready.commit.as_str()),
    )?;
    let nar_hash = detected.as_ref().map(|ready| ready.nar_hash.as_str());
    crate::disk::ensure_headroom(
        std::path::Path::new("/nix/store"),
        config.build.max_artifact_size_bytes,
        "Nest rebuild for a software update scan",
    )?;
    ensure_nix_daemon_available(config).await?;

    // The job is finished, so its worker no longer uses these directories.
    let mut rebuilt = RebuiltClosure {
        output_path: String::new(),
        dirs: [
            config.build.output_dir.join(format!("job-{job_id}")),
            config.build.work_dir.join(format!("job-{job_id}-input")),
        ],
    };
    remove_dirs(&rebuilt.dirs);
    let command =
        nix_build_command_with_nixpkgs_nar_hash(config, admitted.target, &spec, job_id, nar_hash)?;
    if !spec.allow_source_builds {
        let profile = WorkstationBuildProfile::for_build(
            admitted.nixpkgs_commit.as_deref(),
            detected.as_ref().map(|ready| &ready.profile),
        )
        .context("no reviewed build profile for the job's nixpkgs commit")?;
        let offenders = preflight_source_build_check_for_profile(config, &command, profile).await?;
        if !offenders.is_empty() {
            bail!("{}", source_build_blocked_message(&offenders));
        }
    }
    if let Some(parent) = command.out_link.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut process = crate::nix_command::tokio_command(&command.program);
    process
        .args(plain_log_args(&command.args))
        .envs(command.env.iter().map(|(key, value)| (key, value)))
        .current_dir(&config.build.work_dir)
        .stdin(std::process::Stdio::null());
    let output = run_cancellable_command(
        process,
        std::time::Duration::from_secs(config.build.timeout_seconds),
        REBUILD_STDOUT_MAX_BYTES,
        REBUILD_STDERR_TAIL_BYTES,
        "Nest rebuild for a software update scan",
        &tokio_util::sync::CancellationToken::new(),
        true,
    )
    .await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lines = stderr.lines().collect::<Vec<_>>();
        let tail = lines[lines.len().saturating_sub(5)..].join(" / ");
        bail!(
            "nix build failed: {}",
            super::safe_error(&anyhow::anyhow!("{tail}"))
        );
    }
    rebuilt.output_path = std::fs::read_link(&command.out_link)
        .with_context(|| format!("read rebuild out-link {}", command.out_link.display()))?
        .to_str()
        .filter(|path| path.starts_with("/nix/store/"))
        .context("rebuilt output is not a store path")?
        .to_string();
    Ok(Some(rebuilt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rebuild_logs_plainly() {
        let args = [
            "build",
            "/input#toplevel",
            "--print-build-logs",
            "--log-format",
            "internal-json",
            "--no-write-lock-file",
        ]
        .map(String::from);
        assert_eq!(
            plain_log_args(&args),
            ["build", "/input#toplevel", "--no-write-lock-file"]
        );
    }

    #[test]
    fn a_rebuilt_closure_drops_its_root() {
        let root = std::env::temp_dir().join(format!("scan-rebuild-{}", std::process::id()));
        let dirs = [root.join("job-7"), root.join("job-7-input")];
        for dir in &dirs {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::os::unix::fs::symlink("/nix/store/missing", dirs[0].join("result")).unwrap();
        drop(RebuiltClosure {
            output_path: String::new(),
            dirs: dirs.clone(),
        });
        assert!(dirs.iter().all(|dir| !dir.exists()));
        std::fs::remove_dir_all(root).unwrap();
    }
}
