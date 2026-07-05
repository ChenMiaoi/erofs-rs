use crate::cli::ReplayArgs;
use crate::fsck::{ExecLimits, FsckResult, run_fsck_with_limits};
use crate::fuzz::{FuzzArtifactSidecar, parse_fuzz_artifact_sidecar};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

pub const REPLAY_REPORT_SCHEMA: &str = "erofs-rs.replay-report.v1";
const DEFAULT_FSCK_PATH: &str = "./build/erofs-utils/fsck/fsck.erofs";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayReport {
    pub schema: String,
    pub sidecar_path: String,
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub fsck_path: String,
    pub rng_seed: u64,
    pub iteration: u64,
    pub strategy: String,
    pub seed_name: String,
    pub original: ReplayOriginalOutcome,
    pub replay: ReplayFsckOutcome,
    pub comparison: ReplayComparison,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayOriginalOutcome {
    pub classification: String,
    pub reason: String,
    pub exit_code: i32,
    pub timed_out: bool,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayFsckOutcome {
    pub classification: String,
    pub reason: String,
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub killed_process_group: bool,
    pub rss_limit_mb: Option<u64>,
    #[serde(default)]
    pub peak_rss_kb: Option<u64>,
    #[serde(default)]
    pub cgroup_v2: bool,
    #[serde(default)]
    pub cgroup_oom_delta: Option<u64>,
    #[serde(default)]
    pub cgroup_oom_kill_delta: Option<u64>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayComparison {
    pub classification_match: bool,
    pub exit_code_match: bool,
    pub timeout_match: bool,
    pub replay_match: bool,
}

#[derive(Debug, Error)]
pub enum ReplayReportError {
    #[error("failed to decode replay report: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unsupported replay report schema: {0}")]
    UnsupportedSchema(String),
    #[error("replay report field {0} is empty")]
    EmptyField(&'static str),
    #[error("replay report field {field} has invalid SHA-256 digest: {sha256}")]
    InvalidSha256 { field: &'static str, sha256: String },
    #[error(
        "replay report original signature {signature} does not match classification {classification}"
    )]
    SignatureClassificationMismatch {
        classification: String,
        signature: String,
    },
    #[error("replay report comparison field {0} does not match outcomes")]
    InconsistentComparison(&'static str),
}

pub fn parse_replay_report(content: &str) -> std::result::Result<ReplayReport, ReplayReportError> {
    let report: ReplayReport = serde_json::from_str(content)?;
    validate_replay_report(&report)?;
    Ok(report)
}

pub fn validate_replay_report(report: &ReplayReport) -> std::result::Result<(), ReplayReportError> {
    if report.schema != REPLAY_REPORT_SCHEMA {
        return Err(ReplayReportError::UnsupportedSchema(report.schema.clone()));
    }
    require_replay_nonempty("sidecar_path", &report.sidecar_path)?;
    require_replay_nonempty("artifact_path", &report.artifact_path)?;
    require_replay_nonempty("fsck_path", &report.fsck_path)?;
    require_replay_nonempty("strategy", &report.strategy)?;
    require_replay_nonempty("seed_name", &report.seed_name)?;
    if !is_sha256_digest(&report.artifact_sha256) {
        return Err(ReplayReportError::InvalidSha256 {
            field: "artifact_sha256",
            sha256: report.artifact_sha256.clone(),
        });
    }

    validate_original_outcome(&report.original)?;
    validate_replay_outcome(&report.replay)?;
    validate_replay_comparison(report)?;
    Ok(())
}

fn validate_original_outcome(
    outcome: &ReplayOriginalOutcome,
) -> std::result::Result<(), ReplayReportError> {
    require_replay_nonempty("original.classification", &outcome.classification)?;
    require_replay_nonempty("original.reason", &outcome.reason)?;
    require_replay_nonempty("original.signature", &outcome.signature)?;
    let signature_prefix = format!("{}: ", outcome.classification);
    if outcome.signature != outcome.classification
        && !outcome.signature.starts_with(&signature_prefix)
    {
        return Err(ReplayReportError::SignatureClassificationMismatch {
            classification: outcome.classification.clone(),
            signature: outcome.signature.clone(),
        });
    }
    Ok(())
}

fn validate_replay_outcome(
    outcome: &ReplayFsckOutcome,
) -> std::result::Result<(), ReplayReportError> {
    require_replay_nonempty("replay.classification", &outcome.classification)?;
    require_replay_nonempty("replay.reason", &outcome.reason)?;
    Ok(())
}

fn validate_replay_comparison(report: &ReplayReport) -> std::result::Result<(), ReplayReportError> {
    let classification_match = report.original.classification == report.replay.classification;
    if report.comparison.classification_match != classification_match {
        return Err(ReplayReportError::InconsistentComparison(
            "classification_match",
        ));
    }

    let exit_code_match = report.original.exit_code == report.replay.exit_code;
    if report.comparison.exit_code_match != exit_code_match {
        return Err(ReplayReportError::InconsistentComparison("exit_code_match"));
    }

    let timeout_match = report.original.timed_out == report.replay.timed_out;
    if report.comparison.timeout_match != timeout_match {
        return Err(ReplayReportError::InconsistentComparison("timeout_match"));
    }

    let replay_match = classification_match && exit_code_match && timeout_match;
    if report.comparison.replay_match != replay_match {
        return Err(ReplayReportError::InconsistentComparison("replay_match"));
    }

    Ok(())
}

fn require_replay_nonempty(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), ReplayReportError> {
    if value.is_empty() {
        return Err(ReplayReportError::EmptyField(field));
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn limits_from_args(args: &ReplayArgs, sidecar: &FuzzArtifactSidecar) -> ExecLimits {
    ExecLimits {
        timeout: Duration::from_secs(args.exec_timeout),
        max_output_bytes: args.max_output_bytes,
        kill_process_group: !args.no_kill_process_group && sidecar.fsck_kill_process_group,
        rss_limit_mb: args.rss_limit_mb.or(sidecar.fsck_rss_limit_mb),
    }
}

fn read_sidecar(path: &Path) -> Result<FuzzArtifactSidecar> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read replay sidecar {}", path.display()))?;
    parse_fuzz_artifact_sidecar(&content)
        .with_context(|| format!("failed to parse replay sidecar {}", path.display()))
}

fn resolve_artifact(
    sidecar_path: &Path,
    sidecar: &FuzzArtifactSidecar,
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

fn fsck_path(args: &ReplayArgs, sidecar: &FuzzArtifactSidecar) -> String {
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

fn replay_matches(sidecar: &FuzzArtifactSidecar, result: &FsckResult) -> bool {
    sidecar.classification == result.classification
        && sidecar.fsck_exit_code == result.exit_code
        && sidecar.fsck_timed_out == result.timed_out
}

fn render_report(
    sidecar_path: &Path,
    artifact_path: &Path,
    fsck_path: &str,
    sidecar: &FuzzArtifactSidecar,
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
        format!("peak_rss_kb: {}", optional_u64(result.peak_rss_kb)),
        format!("cgroup_v2: {}", result.cgroup_v2),
        format!(
            "cgroup_oom_delta: {}",
            optional_u64(result.cgroup_oom_delta)
        ),
        format!(
            "cgroup_oom_kill_delta: {}",
            optional_u64(result.cgroup_oom_kill_delta)
        ),
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

fn build_replay_report(
    sidecar_path: &Path,
    artifact_path: &Path,
    fsck_path: &str,
    sidecar: &FuzzArtifactSidecar,
    result: &FsckResult,
    artifact_sha256: &str,
) -> ReplayReport {
    let classification_match = sidecar.classification == result.classification;
    let exit_code_match = sidecar.fsck_exit_code == result.exit_code;
    let timeout_match = sidecar.fsck_timed_out == result.timed_out;
    ReplayReport {
        schema: REPLAY_REPORT_SCHEMA.to_string(),
        sidecar_path: sidecar_path.display().to_string(),
        artifact_path: artifact_path.display().to_string(),
        artifact_sha256: artifact_sha256.to_string(),
        fsck_path: fsck_path.to_string(),
        rng_seed: sidecar.rng_seed,
        iteration: sidecar.iteration,
        strategy: sidecar.strategy.clone(),
        seed_name: sidecar.seed_name.clone(),
        original: ReplayOriginalOutcome {
            classification: sidecar.classification.clone(),
            reason: sidecar.reason.clone(),
            exit_code: sidecar.fsck_exit_code,
            timed_out: sidecar.fsck_timed_out,
            signature: sidecar.signature.clone(),
        },
        replay: ReplayFsckOutcome {
            classification: result.classification.clone(),
            reason: result.reason.clone(),
            exit_code: result.exit_code,
            signal: result.signal,
            timed_out: result.timed_out,
            killed_process_group: result.killed_process_group,
            rss_limit_mb: result.rss_limit_mb,
            peak_rss_kb: result.peak_rss_kb,
            cgroup_v2: result.cgroup_v2,
            cgroup_oom_delta: result.cgroup_oom_delta,
            cgroup_oom_kill_delta: result.cgroup_oom_kill_delta,
            stdout_truncated: result.stdout_truncated,
            stderr_truncated: result.stderr_truncated,
        },
        comparison: ReplayComparison {
            classification_match,
            exit_code_match,
            timeout_match,
            replay_match: classification_match && exit_code_match && timeout_match,
        },
    }
}

fn write_json_report(path: &str, report: &ReplayReport) -> Result<()> {
    validate_replay_report(report)
        .map_err(|error| anyhow::anyhow!("generated replay report is invalid: {error}"))?;
    let json =
        serde_json::to_string_pretty(report).context("failed to serialize replay JSON report")?;
    fs::write(path, json + "\n")
        .map_err(|e| anyhow::anyhow!("failed to write replay JSON report {path}: {e}"))
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
    let json_report = build_replay_report(
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
    if let Some(report_path) = &args.json_report {
        write_json_report(report_path, &json_report)?;
    }

    print!("{report}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        REPLAY_REPORT_SCHEMA, ReplayReportError, build_replay_report, parse_replay_report,
        replay_matches, resolve_artifact, validate_replay_report,
    };
    use crate::fsck::FsckResult;
    use crate::fuzz::{
        FuzzArtifactCommands, FuzzArtifactSidecar, FuzzArtifactVersions, MutationRecord,
    };
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn sidecar(artifact_path: &str, classification: &str) -> FuzzArtifactSidecar {
        FuzzArtifactSidecar {
            schema: "erofs-rs.fuzz-artifact.v1".to_string(),
            tool: "erofs-rs".to_string(),
            tool_version: "0.1.0".to_string(),
            rng_seed: 7,
            iteration: 9,
            strategy: "mutation".to_string(),
            seed_name: "seed.erofs".to_string(),
            seed_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            artifact_sha256: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            artifact_path: artifact_path.to_string(),
            mutations: vec![MutationRecord {
                kind: "byte".to_string(),
                field: None,
                offset: Some(7),
                width: Some("u8".to_string()),
                bit: None,
                old: Some("0x00".to_string()),
                new: Some("0xff".to_string()),
            }],
            commands: FuzzArtifactCommands {
                fsck: vec!["fsck.erofs".to_string(), artifact_path.to_string()],
                dump: vec![
                    "dump.erofs".to_string(),
                    "-s".to_string(),
                    artifact_path.to_string(),
                ],
                kernel_replay: vec![
                    "make".to_string(),
                    "smoke-malformed".to_string(),
                    format!("MALFORMED_IMG={artifact_path}"),
                ],
            },
            versions: FuzzArtifactVersions {
                tool_git: None,
                erofs_utils_git: None,
                linux_git: None,
            },
            fsck_exit_code: 0,
            fsck_timed_out: false,
            fsck_kill_process_group: true,
            fsck_killed_process_group: false,
            fsck_rss_limit_mb: None,
            fsck_peak_rss_kb: None,
            fsck_cgroup_v2: false,
            fsck_cgroup_oom_delta: None,
            fsck_cgroup_oom_kill_delta: None,
            stdout_truncated: false,
            stderr_truncated: false,
            classification: classification.to_string(),
            reason: "reason".to_string(),
            signature: format!("{classification}: reason"),
            stdout_path: "artifact.stdout.txt".to_string(),
            stderr_path: "artifact.stderr.txt".to_string(),
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

    #[test]
    fn replay_report_parser_accepts_generated_report() {
        let sidecar = sidecar("artifact.erofs", "accepted");
        let result = FsckResult {
            exit_code: 0,
            classification: "accepted".to_string(),
            reason: "fsck accepted the image".to_string(),
            ..FsckResult::default()
        };
        let report = build_replay_report(
            Path::new("fuzz_seed_iter1.json"),
            Path::new("artifact.erofs"),
            "fsck.erofs",
            &sidecar,
            &result,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let content = serde_json::to_string(&report).unwrap();

        let parsed = parse_replay_report(&content).unwrap();

        assert_eq!(parsed.schema, REPLAY_REPORT_SCHEMA);
        assert!(parsed.comparison.replay_match);
    }

    #[test]
    fn replay_report_parser_rejects_invalid_artifact_hash() {
        let sidecar = sidecar("artifact.erofs", "accepted");
        let result = FsckResult {
            exit_code: 0,
            classification: "accepted".to_string(),
            reason: "fsck accepted the image".to_string(),
            ..FsckResult::default()
        };
        let mut report = build_replay_report(
            Path::new("fuzz_seed_iter1.json"),
            Path::new("artifact.erofs"),
            "fsck.erofs",
            &sidecar,
            &result,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        report.artifact_sha256 = "not-sha".to_string();

        let error = validate_replay_report(&report).unwrap_err();

        assert!(matches!(
            error,
            ReplayReportError::InvalidSha256 {
                field: "artifact_sha256",
                ..
            }
        ));
    }

    #[test]
    fn replay_report_parser_rejects_signature_mismatch() {
        let sidecar = sidecar("artifact.erofs", "accepted");
        let result = FsckResult {
            exit_code: 0,
            classification: "accepted".to_string(),
            reason: "fsck accepted the image".to_string(),
            ..FsckResult::default()
        };
        let mut report = build_replay_report(
            Path::new("fuzz_seed_iter1.json"),
            Path::new("artifact.erofs"),
            "fsck.erofs",
            &sidecar,
            &result,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        report.original.signature = "rejected_invalid: bad inode".to_string();

        let error = validate_replay_report(&report).unwrap_err();

        assert!(matches!(
            error,
            ReplayReportError::SignatureClassificationMismatch {
                classification,
                signature,
            } if classification == "accepted"
                && signature == "rejected_invalid: bad inode"
        ));
    }

    #[test]
    fn replay_report_parser_rejects_unknown_schema() {
        let sidecar = sidecar("artifact.erofs", "accepted");
        let result = FsckResult {
            exit_code: 0,
            classification: "accepted".to_string(),
            reason: "fsck accepted the image".to_string(),
            ..FsckResult::default()
        };
        let mut report = build_replay_report(
            Path::new("fuzz_seed_iter1.json"),
            Path::new("artifact.erofs"),
            "fsck.erofs",
            &sidecar,
            &result,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        report.schema = "erofs-rs.replay-report.v0".to_string();

        let error = validate_replay_report(&report).unwrap_err();

        assert!(matches!(error, ReplayReportError::UnsupportedSchema(_)));
    }

    #[test]
    fn replay_report_parser_rejects_inconsistent_comparison() {
        let sidecar = sidecar("artifact.erofs", "accepted");
        let result = FsckResult {
            exit_code: 0,
            classification: "accepted".to_string(),
            reason: "fsck accepted the image".to_string(),
            ..FsckResult::default()
        };
        let mut report = build_replay_report(
            Path::new("fuzz_seed_iter1.json"),
            Path::new("artifact.erofs"),
            "fsck.erofs",
            &sidecar,
            &result,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        report.comparison.replay_match = false;

        let error = validate_replay_report(&report).unwrap_err();

        assert!(matches!(
            error,
            ReplayReportError::InconsistentComparison("replay_match")
        ));
    }
}
