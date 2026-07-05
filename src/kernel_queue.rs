use crate::cli::{KernelQueueImportArgs, KernelReplayQueue};
use crate::kernel_replay::parse_kernel_replay_report;
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

const GENERAL_QUEUE: &str = "corpus/crashes/kernel-candidates";
const KASAN_QUEUE: &str = "corpus/crashes/kernel-kasan-candidates";
const KCOV_QUEUE: &str = "corpus/crashes/kernel-kcov-candidates";
const REGRESSION_QUEUE: &str = "corpus/regressions/kernel";

fn queue_dir(queue: KernelReplayQueue) -> &'static str {
    match queue {
        KernelReplayQueue::General => GENERAL_QUEUE,
        KernelReplayQueue::Kasan => KASAN_QUEUE,
        KernelReplayQueue::Kcov => KCOV_QUEUE,
        KernelReplayQueue::Regression => REGRESSION_QUEUE,
    }
}

fn queue_label(queue: KernelReplayQueue) -> &'static str {
    match queue {
        KernelReplayQueue::General => "general",
        KernelReplayQueue::Kasan => "kasan",
        KernelReplayQueue::Kcov => "kcov",
        KernelReplayQueue::Regression => "regression",
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn require_expected_digest(expected: Option<&str>, actual: &str) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if !is_sha256_digest(expected) {
        bail!("expected artifact SHA-256 is malformed: {expected}");
    }
    if expected != actual {
        bail!("artifact digest mismatch: expected {expected}, actual {actual}");
    }
    Ok(())
}

fn validate_kernel_report_digest(report_path: &Path, artifact_sha256: &str) -> Result<()> {
    let content = fs::read_to_string(report_path)
        .with_context(|| format!("failed to read kernel report {}", report_path.display()))?;
    let report = parse_kernel_replay_report(&content)
        .with_context(|| format!("failed to parse kernel report {}", report_path.display()))?;
    let Some(report_sha256) = report.artifact_sha256.as_deref() else {
        bail!(
            "kernel report {} does not record artifact_sha256",
            report_path.display()
        );
    };
    if report_sha256 != artifact_sha256 {
        bail!(
            "kernel report {} digest mismatch: expected {}, actual {}",
            report_path.display(),
            artifact_sha256,
            report_sha256
        );
    }
    Ok(())
}

fn input_stem(path: &Path, name: Option<&str>) -> Result<String> {
    let raw = if let Some(name) = name {
        name
    } else {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| anyhow::anyhow!("input artifact has no usable file stem"))?
    };
    let raw = raw.strip_suffix(".erofs").unwrap_or(raw);
    let sanitized: String = raw
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
                char::from(byte)
            } else {
                '_'
            }
        })
        .collect();
    let sanitized = sanitized
        .trim_matches(|ch| matches!(ch, '.' | '_' | '-'))
        .to_string();
    if sanitized.is_empty() {
        bail!("queued artifact name has no portable characters");
    }
    Ok(sanitized)
}

fn destination_path(args: &KernelQueueImportArgs, digest: &str) -> Result<PathBuf> {
    let input = Path::new(&args.input);
    let stem = input_stem(input, args.name.as_deref())?;
    let short_digest = digest
        .get(..12)
        .ok_or_else(|| anyhow::anyhow!("artifact digest is too short"))?;
    Ok(Path::new(&args.queue_root)
        .join(queue_dir(args.queue))
        .join(format!("{stem}-{short_digest}.erofs")))
}

pub fn run_import(args: &KernelQueueImportArgs) -> Result<()> {
    let input = Path::new(&args.input);
    if !input.is_file() {
        bail!("kernel queue input is not a file: {}", input.display());
    }

    let artifact_sha256 = sha256_file(input)?;
    require_expected_digest(args.artifact_sha256.as_deref(), &artifact_sha256)?;
    if let Some(report) = &args.kernel_report {
        validate_kernel_report_digest(Path::new(report), &artifact_sha256)?;
    }

    let dest_path = destination_path(args, &artifact_sha256)?;
    let dest_dir = dest_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("destination has no parent directory"))?;
    fs::create_dir_all(dest_dir)
        .with_context(|| format!("failed to create kernel queue {}", dest_dir.display()))?;

    let mut already_present = false;
    if dest_path.exists() {
        let existing_sha256 = sha256_file(&dest_path)?;
        if existing_sha256 != artifact_sha256 {
            bail!(
                "refusing to overwrite existing kernel queue artifact {}: expected {}, actual {}",
                dest_path.display(),
                artifact_sha256,
                existing_sha256
            );
        }
        already_present = true;
    } else {
        fs::copy(input, &dest_path).with_context(|| {
            format!(
                "failed to import kernel queue artifact {} to {}",
                input.display(),
                dest_path.display()
            )
        })?;
        let copied_sha256 = sha256_file(&dest_path)?;
        if copied_sha256 != artifact_sha256 {
            bail!(
                "copied kernel queue artifact {} digest mismatch: expected {}, actual {}",
                dest_path.display(),
                artifact_sha256,
                copied_sha256
            );
        }
    }

    if already_present {
        println!("Kernel queue artifact already present:");
    } else {
        println!("Imported kernel queue artifact:");
    }
    println!("  Queue: {}", queue_label(args.queue));
    println!("  Path: {}", dest_path.display());
    println!("  SHA-256: {artifact_sha256}");
    println!(
        "  Add intentionally with: git add -f {}",
        dest_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{run_import, sha256_file};
    use crate::cli::{KernelQueueImportArgs, KernelReplayQueue};
    use serde_json::json;
    use std::fs;

    fn write_kernel_report(path: &std::path::Path, sha256: &str) {
        fs::write(
            path,
            json!({
                "schema": "erofs-rs.kernel-replay.v1",
                "artifact_sha256": sha256,
                "kernel_git": "linux-test-rev",
                "qemu_exit_code": 0,
                "outcome": "unsafe",
                "message": "dangerous kernel output matched BUG",
                "signature": "kernel_unsafe: BUG: test",
                "dangerous_pattern": "BUG:"
            })
            .to_string(),
        )
        .unwrap();
    }

    #[test]
    fn kernel_queue_import_copies_reviewed_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let artifact = tmp.path().join("crash image.erofs");
        fs::write(&artifact, b"artifact bytes").unwrap();
        let sha256 = sha256_file(&artifact).unwrap();
        let report = tmp.path().join("kernel-report.json");
        write_kernel_report(&report, &sha256);
        let args = KernelQueueImportArgs {
            input: artifact.to_string_lossy().into_owned(),
            queue: KernelReplayQueue::Regression,
            queue_root: tmp.path().to_string_lossy().into_owned(),
            name: Some("fixed-crash".to_string()),
            artifact_sha256: Some(sha256.clone()),
            kernel_report: Some(report.to_string_lossy().into_owned()),
        };

        run_import(&args).unwrap();

        let queued = tmp
            .path()
            .join("corpus/regressions/kernel")
            .join(format!("fixed-crash-{}.erofs", &sha256[..12]));
        assert_eq!(fs::read(queued).unwrap(), b"artifact bytes");
    }

    #[test]
    fn kernel_queue_import_rejects_report_digest_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let artifact = tmp.path().join("crash.erofs");
        fs::write(&artifact, b"artifact bytes").unwrap();
        let report = tmp.path().join("kernel-report.json");
        write_kernel_report(&report, &"0".repeat(64));
        let args = KernelQueueImportArgs {
            input: artifact.to_string_lossy().into_owned(),
            queue: KernelReplayQueue::Kasan,
            queue_root: tmp.path().to_string_lossy().into_owned(),
            name: None,
            artifact_sha256: None,
            kernel_report: Some(report.to_string_lossy().into_owned()),
        };

        let error = run_import(&args).unwrap_err();

        assert!(error.to_string().contains("digest mismatch"));
    }
}
