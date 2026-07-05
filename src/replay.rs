use crate::cli::ReplayArgs;
use crate::fsck::{ExecLimits, FsckResult, run_fsck_with_limits};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

const FUZZ_ARTIFACT_SCHEMA: &str = "erofs-rs.fuzz-artifact.v1";
const DEFAULT_FSCK_PATH: &str = "./build/erofs-utils/fsck/fsck.erofs";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ReplayCommands {
    fsck: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ReplaySidecar {
    schema: String,
    rng_seed: u64,
    iteration: u64,
    strategy: String,
    seed_name: String,
    artifact_sha256: String,
    artifact_path: String,
    commands: ReplayCommands,
    fsck_exit_code: i32,
    fsck_timed_out: bool,
    fsck_kill_process_group: bool,
    fsck_rss_limit_mb: Option<u64>,
    classification: String,
    reason: String,
    signature: String,
}

fn limits_from_args(args: &ReplayArgs, sidecar: &ReplaySidecar) -> ExecLimits {
    ExecLimits {
        timeout: Duration::from_secs(args.exec_timeout),
        max_output_bytes: args.max_output_bytes,
        kill_process_group: !args.no_kill_process_group && sidecar.fsck_kill_process_group,
        rss_limit_mb: args.rss_limit_mb.or(sidecar.fsck_rss_limit_mb),
    }
}

fn read_sidecar(path: &Path) -> Result<ReplaySidecar> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read replay sidecar {}", path.display()))?;
    let sidecar: ReplaySidecar = serde_json::from_str(&content)
        .with_context(|| format!("failed to decode replay sidecar {}", path.display()))?;
    if sidecar.schema != FUZZ_ARTIFACT_SCHEMA {
        bail!(
            "unsupported fuzz sidecar schema {} in {}",
            sidecar.schema,
            path.display()
        );
    }
    Ok(sidecar)
}

fn resolve_artifact(
    sidecar_path: &Path,
    sidecar: &ReplaySidecar,
    override_path: Option<&str>,
) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return require_existing_artifact(PathBuf::from(path));
    }

    let recorded = PathBuf::from(&sidecar.artifact_path);
    if recorded.exists() {
        return Ok(recorded);
    }

    if let Some(file_name) = recorded.file_name() {
        let sibling = sidecar_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(file_name);
        if sibling.exists() {
            return Ok(sibling);
        }
    }

    require_existing_artifact(recorded)
}

fn require_existing_artifact(path: PathBuf) -> Result<PathBuf> {
    if !path.exists() {
        bail!("artifact image not found: {}", path.display());
    }
    Ok(path)
}

fn fsck_path(args: &ReplayArgs, sidecar: &ReplaySidecar) -> String {
    args.fsck
        .clone()
        .or_else(|| sidecar.commands.fsck.first().cloned())
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| DEFAULT_FSCK_PATH.to_string())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open artifact {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to hash artifact {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn replay_matches(sidecar: &ReplaySidecar, result: &FsckResult) -> bool {
    sidecar.classification == result.classification
        && sidecar.fsck_exit_code == result.exit_code
        && sidecar.fsck_timed_out == result.timed_out
}

fn render_report(
    sidecar_path: &Path,
    artifact_path: &Path,
    fsck_path: &str,
    sidecar: &ReplaySidecar,
    result: &FsckResult,
    artifact_sha256: &str,
) -> String {
    let matched = replay_matches(sidecar, result);
    let mut lines = vec![
        "# EROFS Fuzz Artifact Replay Report".to_string(),
        String::new(),
        format!("sidecar: {}", sidecar_path.display()),
        format!("artifact: {}", artifact_path.display()),
        format!("artifact_sha256: {artifact_sha256}"),
        format!("fsck: {fsck_path}"),
        format!("rng_seed: {}", sidecar.rng_seed),
        format!("iteration: {}", sidecar.iteration),
        format!("strategy: {}", sidecar.strategy),
        format!("seed_name: {}", sidecar.seed_name),
        String::new(),
        "## Original".to_string(),
        String::new(),
        format!("classification: {}", sidecar.classification),
        format!("reason: {}", sidecar.reason),
        format!("exit_code: {}", sidecar.fsck_exit_code),
        format!("timed_out: {}", sidecar.fsck_timed_out),
        format!("signature: {}", sidecar.signature),
        String::new(),
        "## Replay".to_string(),
        String::new(),
        format!("classification: {}", result.classification),
        format!("reason: {}", result.reason),
        format!("exit_code: {}", result.exit_code),
        format!("signal: {}", optional_i32(result.signal)),
        format!("timed_out: {}", result.timed_out),
        format!("killed_process_group: {}", result.killed_process_group),
        format!("rss_limit_mb: {}", optional_u64(result.rss_limit_mb)),
        format!("stdout_truncated: {}", result.stdout_truncated),
        format!("stderr_truncated: {}", result.stderr_truncated),
        String::new(),
        "## Comparison".to_string(),
        String::new(),
        format!(
            "classification_match: {}",
            sidecar.classification == result.classification
        ),
        format!(
            "exit_code_match: {}",
            sidecar.fsck_exit_code == result.exit_code
        ),
        format!(
            "timeout_match: {}",
            sidecar.fsck_timed_out == result.timed_out
        ),
        format!("replay_match: {matched}"),
    ];

    lines.push(String::new());
    lines.join("\n")
}

fn optional_i32(value: Option<i32>) -> String {
    value.map_or_else(|| "none".to_string(), |value| value.to_string())
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_string(), |value| value.to_string())
}

pub fn run(args: &ReplayArgs) -> Result<()> {
    let sidecar_path = Path::new(&args.sidecar);
    let sidecar = read_sidecar(sidecar_path)?;
    let artifact_path = resolve_artifact(sidecar_path, &sidecar, args.artifact.as_deref())?;
    let artifact_sha256 = sha256_file(&artifact_path)?;
    if artifact_sha256 != sidecar.artifact_sha256 {
        bail!(
            "artifact SHA-256 mismatch for {}: sidecar={}, actual={}",
            artifact_path.display(),
            sidecar.artifact_sha256,
            artifact_sha256
        );
    }

    let fsck = fsck_path(args, &sidecar);
    let result = run_fsck_with_limits(&fsck, &artifact_path, &[], limits_from_args(args, &sidecar))
        .with_context(|| format!("failed to replay fsck for {}", artifact_path.display()))?;
    let report = render_report(
        sidecar_path,
        &artifact_path,
        &fsck,
        &sidecar,
        &result,
        &artifact_sha256,
    );

    if let Some(report_path) = &args.report {
        fs::write(report_path, &report)
            .map_err(|e| anyhow::anyhow!("failed to write replay report {report_path}: {e}"))?;
    }

    print!("{report}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ReplayCommands, ReplaySidecar, replay_matches, resolve_artifact};
    use crate::fsck::FsckResult;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn sidecar(artifact_path: &str, classification: &str) -> ReplaySidecar {
        ReplaySidecar {
            schema: "erofs-rs.fuzz-artifact.v1".to_string(),
            rng_seed: 7,
            iteration: 9,
            strategy: "mutation".to_string(),
            seed_name: "seed.erofs".to_string(),
            artifact_sha256: "hash".to_string(),
            artifact_path: artifact_path.to_string(),
            commands: ReplayCommands {
                fsck: vec!["fsck.erofs".to_string(), artifact_path.to_string()],
            },
            fsck_exit_code: 0,
            fsck_timed_out: false,
            fsck_kill_process_group: true,
            fsck_rss_limit_mb: None,
            classification: classification.to_string(),
            reason: "reason".to_string(),
            signature: format!("{classification}: reason"),
        }
    }

    #[test]
    fn replay_resolves_artifact_next_to_sidecar() {
        let tmp = TempDir::new().unwrap();
        let sidecar_path = tmp.path().join("fuzz_seed_iter1.json");
        let artifact_path = tmp.path().join("fuzz_seed_iter1.erofs");
        fs::write(&artifact_path, b"image").unwrap();
        let sidecar = sidecar("/stale/path/fuzz_seed_iter1.erofs", "accepted");

        assert_eq!(
            resolve_artifact(&sidecar_path, &sidecar, None).unwrap(),
            artifact_path
        );
    }

    #[test]
    fn replay_prefers_artifact_override() {
        let tmp = TempDir::new().unwrap();
        let override_path = tmp.path().join("override.erofs");
        fs::write(&override_path, b"image").unwrap();
        let sidecar = sidecar("/stale/path/fuzz_seed_iter1.erofs", "accepted");

        assert_eq!(
            resolve_artifact(
                Path::new("fuzz_seed_iter1.json"),
                &sidecar,
                Some(override_path.to_str().unwrap())
            )
            .unwrap(),
            override_path
        );
    }

    #[test]
    fn replay_match_requires_classification_exit_and_timeout() {
        let sidecar = sidecar("artifact.erofs", "accepted");
        let result = FsckResult {
            exit_code: 0,
            classification: "accepted".to_string(),
            timed_out: false,
            ..FsckResult::default()
        };
        assert!(replay_matches(&sidecar, &result));

        let result = FsckResult {
            classification: "rejected_invalid".to_string(),
            ..result
        };
        assert!(!replay_matches(&sidecar, &result));
    }
}
