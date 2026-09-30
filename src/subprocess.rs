//! Supervise only the process group we create, never unrelated nix-daemon jobs.
use anyhow::{Context, Result, anyhow, bail};
use std::{
    io,
    process::{ExitStatus, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::{sleep, timeout},
};

pub(crate) const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct ProcessGroup(Option<i32>);
impl ProcessGroup {
    pub(crate) fn new(pid: Option<u32>) -> Self {
        Self(pid.and_then(|id| i32::try_from(id).ok()))
    }
    pub(crate) fn signal(&self, signal: i32) {
        if let Some(pid) = self.0 {
            // SAFETY: this is the group created exclusively for this command.
            unsafe {
                libc::kill(-pid, signal);
            }
        }
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.signal(libc::SIGKILL);
    }
}

type BoundedCommandOutput = std::process::Output;

async fn read_bounded_command_stream<R>(
    mut stream: R,
    limit: usize,
    label: &'static str,
    tail: bool,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::with_capacity(limit.min(16 * 1024));
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .with_context(|| format!("read {label}"))?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > limit {
            if !tail {
                bail!("{label} exceeded the {limit} byte source-policy limit");
            }
            let discard = output
                .len()
                .saturating_add(read)
                .saturating_sub(limit)
                .min(output.len());
            output.drain(..discard);
        }
        output.extend_from_slice(&buffer[read.saturating_sub(limit)..read]);
    }
}

/// Capture both pipes concurrently and enforce bounds while bytes arrive. A
/// completed `Command::output` can already have allocated attacker-controlled
/// output, so source-policy subprocesses use this streaming primitive instead.
#[cfg(unix)]
fn command_spawn_is_transient(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ETXTBSY)
}

#[cfg(not(unix))]
fn command_spawn_is_transient(_error: &io::Error) -> bool {
    false
}

async fn spawn_bounded_command(
    command: &mut Command,
    label: &'static str,
) -> Result<tokio::process::Child> {
    const MAX_ATTEMPTS: usize = 8;

    for attempt in 0..MAX_ATTEMPTS {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) if command_spawn_is_transient(&error) && attempt + 1 < MAX_ATTEMPTS => {
                // CLOEXEC takes effect at exec, so a concurrently forked
                // process can briefly retain a writer for an executable that
                // was just prepared. Retry only Linux/Unix ETXTBSY, with a
                // short bound; all other spawn failures remain fail-closed.
                sleep(Duration::from_millis(1_u64 << attempt.min(6))).await;
            }
            Err(error) => return Err(error).with_context(|| format!("run {label}")),
        }
    }
    unreachable!("bounded command spawn loop returns on its final attempt")
}

pub(crate) async fn run_bounded_command(
    command: Command,
    time_limit: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    label: &'static str,
) -> Result<BoundedCommandOutput> {
    run_cancellable_command(
        command,
        time_limit,
        stdout_limit,
        stderr_limit,
        label,
        &current_cancellation(),
        false,
    )
    .await
}

pub(crate) async fn run_cancellable_command(
    mut command: Command,
    time_limit: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    label: &'static str,
    cancellation: &tokio_util::sync::CancellationToken,
    tail: bool,
) -> Result<BoundedCommandOutput> {
    if cancellation.is_cancelled() {
        bail!("{label} cancelled");
    }
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = spawn_bounded_command(&mut command, label).await?;
    let process_group = child.id();
    let _group = ProcessGroup::new(process_group);
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("capture {label} stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("capture {label} stderr"))?;
    let mut stdout_capture = Box::pin(read_bounded_command_stream(
        stdout,
        stdout_limit,
        "command stdout",
        tail,
    ));
    let mut stderr_capture = Box::pin(read_bounded_command_stream(
        stderr,
        stderr_limit,
        "command stderr",
        tail,
    ));
    let deadline = sleep(time_limit);
    tokio::pin!(deadline);
    let pipe_deadline = sleep(time_limit);
    tokio::pin!(pipe_deadline);
    let mut status = None;
    let mut captured_stdout = None;
    let mut captured_stderr = None;

    enum CaptureEvent {
        Stdout(Result<Vec<u8>>),
        Stderr(Result<Vec<u8>>),
        Exit(std::io::Result<ExitStatus>),
        Timeout,
        Cancelled,
        PipeTimeout,
    }

    loop {
        let event = tokio::select! {
            result = &mut stdout_capture, if captured_stdout.is_none() => {
                CaptureEvent::Stdout(result)
            }
            result = &mut stderr_capture, if captured_stderr.is_none() => {
                CaptureEvent::Stderr(result)
            }
            result = child.wait(), if status.is_none() => CaptureEvent::Exit(result),
            _ = &mut deadline => CaptureEvent::Timeout,
            _ = cancellation.cancelled() => CaptureEvent::Cancelled,
            _ = &mut pipe_deadline, if status.is_some() => CaptureEvent::PipeTimeout,
        };
        match event {
            CaptureEvent::Stdout(Ok(output)) => captured_stdout = Some(output),
            CaptureEvent::Stderr(Ok(output)) => captured_stderr = Some(output),
            CaptureEvent::Exit(Ok(exit_status)) => {
                status = Some(exit_status);
                pipe_deadline
                    .as_mut()
                    .reset(tokio::time::Instant::now() + PIPE_DRAIN_TIMEOUT);
            }
            CaptureEvent::Exit(Err(error)) => {
                terminate_bounded_command(&mut child, process_group).await;
                return Err(error).with_context(|| format!("wait for {label}"));
            }
            CaptureEvent::Stdout(Err(error)) | CaptureEvent::Stderr(Err(error)) => {
                terminate_bounded_command(&mut child, process_group).await;
                return Err(error).with_context(|| format!("capture {label}"));
            }
            CaptureEvent::Cancelled => {
                terminate_bounded_command(&mut child, process_group).await;
                bail!("{label} cancelled");
            }
            CaptureEvent::PipeTimeout => {
                terminate_bounded_command(&mut child, process_group).await;
                bail!("{label} output pipes remained open after child exit");
            }
            CaptureEvent::Timeout => {
                terminate_bounded_command(&mut child, process_group).await;
                bail!("{label} timed out");
            }
        }
        if status.is_some() && captured_stdout.is_some() && captured_stderr.is_some() {
            let (Some(status), Some(stdout), Some(stderr)) = (
                status.take(),
                captured_stdout.take(),
                captured_stderr.take(),
            ) else {
                unreachable!("bounded command completion state was checked")
            };
            return Ok(BoundedCommandOutput {
                status,
                stdout,
                stderr,
            });
        }
    }
}

async fn terminate_bounded_command(child: &mut tokio::process::Child, process_group: Option<u32>) {
    #[cfg(unix)]
    if let Some(process_group) = process_group.and_then(|pid| i32::try_from(pid).ok()) {
        // The child is placed in a fresh process group before exec. Kill the
        // whole group so a helper that inherited stdout/stderr cannot outlive
        // a timed-out or overflowing source-policy command.
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    let _ = child.start_kill();
    let _ = timeout(PIPE_DRAIN_TIMEOUT, child.wait()).await;
}

tokio::task_local! {
    pub(crate) static BUILD_CANCELLATION: tokio_util::sync::CancellationToken;
}

pub(crate) fn current_cancellation() -> tokio_util::sync::CancellationToken {
    BUILD_CANCELLATION
        .try_with(Clone::clone)
        .unwrap_or_default()
}

/// Used only inside spawn_blocking (and synchronous tests). Retain bounded
/// diagnostic tails for chatty exports without limiting successful throughput.
pub(crate) fn blocking_output(
    command: &mut std::process::Command,
    time_limit: Duration,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<std::process::Output> {
    let command = std::mem::replace(command, std::process::Command::new("true"));
    let future = run_cancellable_command(
        Command::from(command),
        time_limit,
        65536,
        1024 * 1024,
        "Nix cache command",
        cancellation,
        true,
    );
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.block_on(future)
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(future)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shell(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    #[tokio::test]
    async fn inherited_pipe_does_not_hold_worker_and_timeout_kills_group() {
        let started = std::time::Instant::now();
        let error = run_bounded_command(
            shell("sleep 60 & exit 0"),
            Duration::from_secs(20),
            1024,
            1024,
            "pipe test",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("pipes remained open"));
        assert!(started.elapsed() < Duration::from_secs(8));
        let error = run_bounded_command(
            shell("sleep 60"),
            Duration::from_millis(30),
            1024,
            1024,
            "deadline test",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn cancellation_and_output_limits_release_resources_on_retries() {
        let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
        for _ in 0..20 {
            let token = tokio_util::sync::CancellationToken::new();
            token.cancel();
            assert!(
                run_cancellable_command(
                    Command::new("/nonexistent-nest-cancelled-command"),
                    Duration::from_secs(10),
                    1024,
                    1024,
                    "cancel test",
                    &token,
                    false
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("cancelled")
            );
            assert!(
                run_bounded_command(
                    shell("head -c 65536 /dev/zero"),
                    Duration::from_secs(2),
                    1024,
                    1024,
                    "overflow test"
                )
                .await
                .is_err()
            );
        }
        // Other tests may have sockets open; exact FD equality is tested by the
        // isolated qualification process instead of relying on global counters.
        assert!(std::fs::read_dir("/proc/self/fd").unwrap().count() < before + 128);
    }

    #[tokio::test]
    async fn chatty_successful_export_keeps_tail_without_failing() {
        let output = run_cancellable_command(
            shell("head -c 1048576 /dev/zero; printf finished"),
            Duration::from_secs(5),
            1024,
            1024,
            "export test",
            &Default::default(),
            true,
        )
        .await
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 1024);
        assert!(output.stdout.ends_with(b"finished"));
    }

    #[tokio::test]
    async fn cancellation_or_dropping_supervisor_kills_descendants() {
        for cancel in [false, true] {
            let path = std::env::temp_dir().join(format!("nest-process-{}", uuid::Uuid::new_v4()));
            let mut command = Command::new("sh");
            command
                .arg("-c")
                .arg("sleep 60 & echo $! > \"$1\"; wait")
                .arg("test")
                .arg(&path);
            let token = tokio_util::sync::CancellationToken::new();
            let run_token = token.clone();
            let task = tokio::spawn(async move {
                run_cancellable_command(
                    command,
                    Duration::from_secs(60),
                    1024,
                    1024,
                    "drop test",
                    &run_token,
                    false,
                )
                .await
            });
            let child = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let Ok(pid) = std::fs::read_to_string(&path) {
                        if let Ok(pid) = pid.trim().parse::<u32>() {
                            break pid;
                        }
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            if cancel {
                token.cancel();
                assert!(
                    task.await
                        .unwrap()
                        .unwrap_err()
                        .to_string()
                        .contains("cancelled")
                );
            } else {
                task.abort();
                let _ = task.await;
            }
            sleep(Duration::from_millis(50)).await;
            let stat = std::fs::read_to_string(format!("/proc/{child}/stat"));
            assert!(stat.is_err() || stat.unwrap().split_whitespace().nth(2) == Some("Z"));
            std::fs::remove_file(path).unwrap();
        }
    }
}
