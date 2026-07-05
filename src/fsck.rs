use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempfile;

const DEFAULT_FSCK_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Limits applied to a single fsck.erofs execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecLimits {
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

impl Default for ExecLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_FSCK_TIMEOUT_SECS),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

/// Result of invoking fsck.erofs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsckResult {
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub classification: String,
    pub reason: String,
}

/// Run fsck.erofs against an image.
pub fn run_fsck<A: AsRef<Path>, B: AsRef<Path>>(
    fsck_path: A,
    image_path: B,
    extra_args: &[String],
) -> Result<FsckResult> {
    run_fsck_with_limits(fsck_path, image_path, extra_args, ExecLimits::default())
}

/// Run fsck.erofs against an image with an explicit timeout.
pub fn run_fsck_with_timeout<A: AsRef<Path>, B: AsRef<Path>>(
    fsck_path: A,
    image_path: B,
    extra_args: &[String],
    timeout: Duration,
) -> Result<FsckResult> {
    run_fsck_with_limits(
        fsck_path,
        image_path,
        extra_args,
        ExecLimits {
            timeout,
            ..ExecLimits::default()
        },
    )
}

/// Run fsck.erofs against an image with explicit execution limits.
pub fn run_fsck_with_limits<A: AsRef<Path>, B: AsRef<Path>>(
    fsck_path: A,
    image_path: B,
    extra_args: &[String],
    limits: ExecLimits,
) -> Result<FsckResult> {
    let mut stdout_file = tempfile().context("failed to create fsck stdout tempfile")?;
    let mut stderr_file = tempfile().context("failed to create fsck stderr tempfile")?;
    let child_stdout = stdout_file
        .try_clone()
        .context("failed to clone fsck stdout tempfile")?;
    let child_stderr = stderr_file
        .try_clone()
        .context("failed to clone fsck stderr tempfile")?;

    let mut cmd = Command::new(fsck_path.as_ref());
    cmd.args(extra_args)
        .arg(image_path.as_ref())
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::from(child_stderr));

    let mut child = cmd.spawn().with_context(|| {
        format!(
            "failed to execute fsck.erofs ({})",
            fsck_path.as_ref().display()
        )
    })?;

    let start = Instant::now();
    let mut timed_out = false;
    loop {
        if child
            .try_wait()
            .with_context(|| {
                format!(
                    "failed to wait for fsck.erofs ({})",
                    fsck_path.as_ref().display()
                )
            })?
            .is_some()
        {
            break;
        }
        if start.elapsed() >= limits.timeout {
            timed_out = true;
            let _ = child.kill();
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    let status = child.wait().with_context(|| {
        format!(
            "failed to collect fsck.erofs status for {}",
            image_path.as_ref().display()
        )
    })?;

    let (stdout, stdout_truncated) = read_limited_output(
        &mut stdout_file,
        limits.max_output_bytes,
        "stdout",
        image_path.as_ref(),
    )?;
    let (stderr, stderr_truncated) = read_limited_output(
        &mut stderr_file,
        limits.max_output_bytes,
        "stderr",
        image_path.as_ref(),
    )?;
    let signal = if timed_out {
        None
    } else {
        exit_signal(&status)
    };
    let exit_code = if timed_out {
        124
    } else {
        status
            .code()
            .or_else(|| signal.map(|signal| 128 + signal))
            .unwrap_or(-1)
    };

    let (classification, reason) = classify_fsck_result(exit_code, &stderr, &stdout);

    Ok(FsckResult {
        exit_code,
        signal,
        timed_out,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        classification: classification.to_string(),
        reason: reason.to_string(),
    })
}

fn read_limited_output(
    file: &mut File,
    max_output_bytes: usize,
    stream: &str,
    image_path: &Path,
) -> Result<(String, bool)> {
    file.seek(SeekFrom::Start(0)).with_context(|| {
        format!(
            "failed to seek fsck {stream} tempfile for {}",
            image_path.display()
        )
    })?;
    let read_limit = u64::try_from(max_output_bytes)
        .unwrap_or(u64::MAX - 1)
        .saturating_add(1);
    let mut data = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut data)
        .with_context(|| {
            format!(
                "failed to read fsck {stream} tempfile for {}",
                image_path.display()
            )
        })?;

    let truncated = data.len() > max_output_bytes;
    if truncated {
        data.truncate(max_output_bytes);
    }
    let mut text = String::from_utf8_lossy(&data).to_string();
    if truncated {
        text.push_str(&format!(
            "\n[erofs-rs: fsck {stream} truncated to {max_output_bytes} bytes]\n"
        ));
    }
    Ok((text, truncated))
}

#[cfg(unix)]
fn exit_signal(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &ExitStatus) -> Option<i32> {
    None
}

/// Classify fsck.erofs output into consistent categories.
///
/// fsck.erofs often exits 0 even when errors were printed, so stderr is
/// inspected first.
pub fn classify_fsck_result(
    exit_code: i32,
    stderr: &str,
    stdout: &str,
) -> (&'static str, &'static str) {
    let err = stderr.to_lowercase();
    let out = stdout.to_lowercase();
    let combined = format!("{err}\n{out}");

    if exit_code == 124 || err.contains("timed out") {
        return ("rejected_timeout", "fsck timed out");
    }

    if matches!(exit_code, 134 | 135 | 136 | 139) {
        return ("rejected_crash", "fsck exited on a fatal signal");
    }

    let has_error_keyword = [
        "error",
        "failed",
        "invalid",
        "corruption",
        "bogus",
        "not supported",
    ]
    .iter()
    .any(|k| combined.contains(k));

    if exit_code == 0 && !has_error_keyword {
        return ("accepted", "fsck accepted the image");
    }

    if err.contains("failed to verify superblock checksum") || err.contains("invalid checksum") {
        return (
            "rejected_checksum",
            "superblock checksum verification failed",
        );
    }

    if err.contains("i/o error") || err.contains("failed to read") {
        return ("rejected_io_error", "I/O error during read");
    }

    if err.contains("found some filesystem corruption")
        || err.contains("bogus")
        || err.contains("corruption")
    {
        return ("rejected_corruption", "fsck detected corruption");
    }

    if err.contains("not supported") || err.contains("invalid") {
        return ("rejected_invalid", "fsck rejected as invalid");
    }

    if exit_code != 0 {
        return ("rejected_other", "fsck rejected");
    }

    ("accepted_with_errors", "fsck exited 0 but printed errors")
}
