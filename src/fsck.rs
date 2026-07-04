use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_FSCK_TIMEOUT_SECS: u64 = 30;

/// Result of invoking fsck.erofs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsckResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub classification: String,
    pub reason: String,
}

/// Run fsck.erofs against an image.
pub fn run_fsck<A: AsRef<Path>, B: AsRef<Path>>(
    fsck_path: A,
    image_path: B,
    extra_args: &[String],
) -> Result<FsckResult> {
    run_fsck_with_timeout(
        fsck_path,
        image_path,
        extra_args,
        Duration::from_secs(DEFAULT_FSCK_TIMEOUT_SECS),
    )
}

/// Run fsck.erofs against an image with an explicit timeout.
pub fn run_fsck_with_timeout<A: AsRef<Path>, B: AsRef<Path>>(
    fsck_path: A,
    image_path: B,
    extra_args: &[String],
    timeout: Duration,
) -> Result<FsckResult> {
    let mut cmd = Command::new(fsck_path.as_ref());
    cmd.args(extra_args)
        .arg(image_path.as_ref())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

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
        if start.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    let output = child.wait_with_output().with_context(|| {
        format!(
            "failed to collect fsck.erofs output for {}",
            image_path.as_ref().display()
        )
    })?;

    let exit_code = if timed_out {
        124
    } else {
        output.status.code().unwrap_or(-1)
    };
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let (classification, reason) = classify_fsck_result(exit_code, &stderr, &stdout);

    Ok(FsckResult {
        exit_code,
        stdout,
        stderr,
        classification: classification.to_string(),
        reason: reason.to_string(),
    })
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
