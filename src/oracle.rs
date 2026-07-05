use crate::checksum::fix_checksum;
use crate::cli::OracleArgs;
use crate::dirent::locate_dirents_in_image;
use crate::fsck::{ExecLimits, FsckResult, run_fsck_with_limits};
use crate::image::{Image, read_image, write_image};
use crate::inode::locate_inodes;
use crate::kernel_replay::{KernelReplayOutcome, parse_kernel_replay_report};
use crate::parse::{ParseMode, parse_image};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::Duration;
use tempfile::NamedTempFile;
use thiserror::Error;

pub const ORACLE_REPORT_SCHEMA: &str = "erofs-rs.oracle-report.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
enum OracleStatus {
    Accepted,
    Rejected,
    Skipped,
}

impl OracleStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Skipped => "skipped",
        }
    }

    fn is_decision(&self) -> bool {
        matches!(self, Self::Accepted | Self::Rejected)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OracleCheck {
    name: &'static str,
    status: OracleStatus,
    classification: String,
    reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleJsonReport {
    pub schema: String,
    pub input: String,
    pub input_sha256: Option<String>,
    pub checks: Vec<OracleJsonCheck>,
    pub matrix: Vec<OracleMatrixEntry>,
    pub interesting_findings: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleJsonCheck {
    pub name: String,
    pub status: String,
    pub classification: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleMatrixEntry {
    pub name: String,
    pub left: String,
    pub right: String,
    pub left_status: String,
    pub right_status: String,
    pub left_classification: String,
    pub right_classification: String,
    pub verdict: String,
    pub disagrees: bool,
}

#[derive(Debug, Error)]
pub enum OracleJsonReportError {
    #[error("failed to decode oracle JSON report: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unsupported oracle JSON report schema: {0}")]
    UnsupportedSchema(String),
    #[error("oracle JSON report field {0} is empty")]
    EmptyField(&'static str),
    #[error("oracle JSON report list {0} is empty")]
    EmptyList(&'static str),
    #[error("oracle JSON report field {field} has invalid SHA-256 digest: {sha256}")]
    InvalidSha256 { field: &'static str, sha256: String },
    #[error("oracle JSON report field {field} has invalid status: {status}")]
    InvalidStatus { field: &'static str, status: String },
    #[error("oracle JSON report field {field} has invalid verdict: {verdict}")]
    InvalidVerdict {
        field: &'static str,
        verdict: String,
    },
    #[error("oracle JSON report matrix entry {0} has inconsistent verdict")]
    InconsistentVerdict(String),
    #[error("oracle JSON report contains duplicate check: {0}")]
    DuplicateCheck(String),
    #[error("oracle JSON report contains duplicate matrix entry: {0}")]
    DuplicateMatrixEntry(String),
    #[error("oracle JSON report matrix is missing entry: {0}")]
    MissingMatrixEntry(String),
    #[error("oracle JSON report matrix entry {entry} has invalid pair, expected {expected}")]
    InvalidMatrixPair { entry: String, expected: String },
    #[error("oracle JSON report matrix entry {entry} references unknown check: {check}")]
    UnknownMatrixCheck { entry: String, check: String },
    #[error(
        "oracle JSON report matrix entry {entry} field {field} for check {check} is {actual}, expected {expected}"
    )]
    MatrixCheckMismatch {
        entry: String,
        check: String,
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error(
        "oracle JSON report check {check} has status {status} with classification {classification}"
    )]
    CheckStatusClassificationMismatch {
        check: String,
        status: String,
        classification: String,
    },
    #[error("oracle JSON report interesting_findings is {actual}, expected {expected}")]
    InterestingFindingsMismatch { expected: usize, actual: usize },
}

pub fn parse_oracle_json_report(
    content: &str,
) -> std::result::Result<OracleJsonReport, OracleJsonReportError> {
    let report: OracleJsonReport = serde_json::from_str(content)?;
    validate_oracle_json_report(&report)?;
    Ok(report)
}

pub fn validate_oracle_json_report(
    report: &OracleJsonReport,
) -> std::result::Result<(), OracleJsonReportError> {
    if report.schema != ORACLE_REPORT_SCHEMA {
        return Err(OracleJsonReportError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    require_nonempty("input", &report.input)?;
    if let Some(input_sha256) = &report.input_sha256 {
        require_sha256("input_sha256", input_sha256)?;
    }
    if report.checks.is_empty() {
        return Err(OracleJsonReportError::EmptyList("checks"));
    }
    let mut check_names = HashSet::new();
    let mut check_order = HashMap::new();
    let mut checks_by_name = HashMap::new();
    for (index, check) in report.checks.iter().enumerate() {
        validate_json_check(check)?;
        if !check_names.insert(check.name.as_str()) {
            return Err(OracleJsonReportError::DuplicateCheck(check.name.clone()));
        }
        check_order.insert(check.name.as_str(), index);
        checks_by_name.insert(check.name.as_str(), check);
    }
    let mut missing_entries = expected_matrix_entries(&report.checks);
    let mut matrix_names = HashSet::new();
    for entry in &report.matrix {
        validate_matrix_entry(entry)?;
        if !matrix_names.insert(entry.name.as_str()) {
            return Err(OracleJsonReportError::DuplicateMatrixEntry(
                entry.name.clone(),
            ));
        }
        require_matrix_check(entry, &entry.left, &check_names)?;
        require_matrix_check(entry, &entry.right, &check_names)?;
        validate_matrix_check_values(entry, &checks_by_name)?;
        validate_matrix_verdict(entry)?;
        let expected_name = expected_matrix_entry_name(entry, &check_order)?;
        if entry.name != expected_name {
            return Err(OracleJsonReportError::InvalidMatrixPair {
                entry: entry.name.clone(),
                expected: expected_name,
            });
        }
        missing_entries.remove(entry.name.as_str());
    }
    if let Some(entry) = missing_entries.into_iter().next() {
        return Err(OracleJsonReportError::MissingMatrixEntry(entry));
    }
    let expected = interesting_findings(&report.matrix);
    if report.interesting_findings != expected {
        return Err(OracleJsonReportError::InterestingFindingsMismatch {
            expected,
            actual: report.interesting_findings,
        });
    }
    Ok(())
}

fn expected_matrix_entries(checks: &[OracleJsonCheck]) -> BTreeSet<String> {
    let mut entries = BTreeSet::new();
    for left_idx in 0..checks.len() {
        for right_idx in (left_idx + 1)..checks.len() {
            entries.insert(format!(
                "{}_vs_{}",
                checks[left_idx].name, checks[right_idx].name
            ));
        }
    }
    entries
}

fn expected_matrix_entry_name(
    entry: &OracleMatrixEntry,
    check_order: &HashMap<&str, usize>,
) -> std::result::Result<String, OracleJsonReportError> {
    let left_index = check_order[entry.left.as_str()];
    let right_index = check_order[entry.right.as_str()];
    if left_index == right_index {
        return Err(OracleJsonReportError::InvalidMatrixPair {
            entry: entry.name.clone(),
            expected: "distinct checks".to_string(),
        });
    }

    let (left, right) = if left_index < right_index {
        (&entry.left, &entry.right)
    } else {
        (&entry.right, &entry.left)
    };
    Ok(format!("{left}_vs_{right}"))
}

fn require_matrix_check(
    entry: &OracleMatrixEntry,
    check: &str,
    check_names: &HashSet<&str>,
) -> std::result::Result<(), OracleJsonReportError> {
    if !check_names.contains(check) {
        return Err(OracleJsonReportError::UnknownMatrixCheck {
            entry: entry.name.clone(),
            check: check.to_string(),
        });
    }
    Ok(())
}

fn validate_matrix_check_values(
    entry: &OracleMatrixEntry,
    checks_by_name: &HashMap<&str, &OracleJsonCheck>,
) -> std::result::Result<(), OracleJsonReportError> {
    let left = checks_by_name[entry.left.as_str()];
    require_matrix_check_value(
        entry,
        &entry.left,
        "matrix.left_status",
        &entry.left_status,
        &left.status,
    )?;
    require_matrix_check_value(
        entry,
        &entry.left,
        "matrix.left_classification",
        &entry.left_classification,
        &left.classification,
    )?;

    let right = checks_by_name[entry.right.as_str()];
    require_matrix_check_value(
        entry,
        &entry.right,
        "matrix.right_status",
        &entry.right_status,
        &right.status,
    )?;
    require_matrix_check_value(
        entry,
        &entry.right,
        "matrix.right_classification",
        &entry.right_classification,
        &right.classification,
    )
}

fn require_matrix_check_value(
    entry: &OracleMatrixEntry,
    check: &str,
    field: &'static str,
    actual: &str,
    expected: &str,
) -> std::result::Result<(), OracleJsonReportError> {
    if actual != expected {
        return Err(OracleJsonReportError::MatrixCheckMismatch {
            entry: entry.name.clone(),
            check: check.to_string(),
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn validate_matrix_verdict(
    entry: &OracleMatrixEntry,
) -> std::result::Result<(), OracleJsonReportError> {
    let skipped =
        !is_decision_status(&entry.left_status) || !is_decision_status(&entry.right_status);
    let disagrees = !skipped
        && (entry.left_status != entry.right_status
            || entry.left_classification != entry.right_classification);
    let expected_verdict = if skipped {
        "skipped"
    } else if disagrees {
        "disagree"
    } else {
        "agree"
    };
    if entry.verdict != expected_verdict || entry.disagrees != disagrees {
        return Err(OracleJsonReportError::InconsistentVerdict(
            entry.name.clone(),
        ));
    }
    Ok(())
}

fn is_decision_status(status: &str) -> bool {
    matches!(status, "accepted" | "rejected")
}

fn validate_json_check(check: &OracleJsonCheck) -> std::result::Result<(), OracleJsonReportError> {
    require_nonempty("checks.name", &check.name)?;
    require_status("checks.status", &check.status)?;
    require_nonempty("checks.classification", &check.classification)?;
    require_nonempty("checks.reason", &check.reason)?;
    let classification_is_skipped = check.classification == "skipped";
    let status_is_skipped = check.status == "skipped";
    if classification_is_skipped != status_is_skipped {
        return Err(OracleJsonReportError::CheckStatusClassificationMismatch {
            check: check.name.clone(),
            status: check.status.clone(),
            classification: check.classification.clone(),
        });
    }
    Ok(())
}

fn validate_matrix_entry(
    entry: &OracleMatrixEntry,
) -> std::result::Result<(), OracleJsonReportError> {
    require_nonempty("matrix.name", &entry.name)?;
    require_nonempty("matrix.left", &entry.left)?;
    require_nonempty("matrix.right", &entry.right)?;
    require_status("matrix.left_status", &entry.left_status)?;
    require_status("matrix.right_status", &entry.right_status)?;
    require_nonempty("matrix.left_classification", &entry.left_classification)?;
    require_nonempty("matrix.right_classification", &entry.right_classification)?;
    require_verdict("matrix.verdict", &entry.verdict)?;
    if (entry.verdict == "disagree") != entry.disagrees {
        return Err(OracleJsonReportError::InconsistentVerdict(
            entry.name.clone(),
        ));
    }
    Ok(())
}

fn require_nonempty(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), OracleJsonReportError> {
    if value.is_empty() {
        return Err(OracleJsonReportError::EmptyField(field));
    }
    Ok(())
}

fn require_sha256(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), OracleJsonReportError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(OracleJsonReportError::InvalidSha256 {
            field,
            sha256: value.to_string(),
        });
    }
    Ok(())
}

fn require_status(
    field: &'static str,
    status: &str,
) -> std::result::Result<(), OracleJsonReportError> {
    if matches!(status, "accepted" | "rejected" | "skipped") {
        return Ok(());
    }
    Err(OracleJsonReportError::InvalidStatus {
        field,
        status: status.to_string(),
    })
}

fn require_verdict(
    field: &'static str,
    verdict: &str,
) -> std::result::Result<(), OracleJsonReportError> {
    if matches!(verdict, "agree" | "disagree" | "skipped") {
        return Ok(());
    }
    Err(OracleJsonReportError::InvalidVerdict {
        field,
        verdict: verdict.to_string(),
    })
}

impl OracleCheck {
    fn accepted(
        name: &'static str,
        classification: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            name,
            status: OracleStatus::Accepted,
            classification: classification.into(),
            reason: reason.into(),
        }
    }

    fn rejected(
        name: &'static str,
        classification: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            name,
            status: OracleStatus::Rejected,
            classification: classification.into(),
            reason: reason.into(),
        }
    }

    fn skipped(name: &'static str, reason: impl Into<String>) -> Self {
        Self {
            name,
            status: OracleStatus::Skipped,
            classification: "skipped".to_string(),
            reason: reason.into(),
        }
    }
}

fn limits_from_args(args: &OracleArgs) -> ExecLimits {
    ExecLimits {
        timeout: Duration::from_secs(args.exec_timeout),
        max_output_bytes: args.max_output_bytes,
        kill_process_group: !args.no_kill_process_group,
        rss_limit_mb: args.rss_limit_mb,
    }
}

fn run_rust_parser(image: &Image) -> OracleCheck {
    let superblock = match image.superblock() {
        Ok(superblock) => superblock,
        Err(error) => {
            return OracleCheck::rejected(
                "rust_parser",
                "rejected_parse",
                format!("superblock parse failed: {error}"),
            );
        }
    };

    let inodes = match locate_inodes(image, &superblock) {
        Ok(inodes) => inodes,
        Err(error) => {
            return OracleCheck::rejected(
                "rust_parser",
                "rejected_parse",
                format!("inode location failed: {error}"),
            );
        }
    };

    match locate_dirents_in_image(image, &superblock, &inodes) {
        Ok(dirents) => OracleCheck::accepted(
            "rust_parser",
            "accepted",
            format!(
                "parsed superblock, {} inode(s), {} dirent(s)",
                inodes.len(),
                dirents.len()
            ),
        ),
        Err(error) => OracleCheck::rejected(
            "rust_parser",
            "rejected_parse",
            format!("dirent location failed: {error}"),
        ),
    }
}

fn run_rust_strict_parser(image: &Image) -> OracleCheck {
    match parse_image(image, ParseMode::Strict) {
        Ok(report) => OracleCheck::accepted(
            "rust_strict_parser",
            "accepted",
            format!(
                "strict parser decoded {} inode(s) and {} dirent(s)",
                report.inodes.iter().filter(|entry| entry.is_ok()).count(),
                report.dirents.iter().filter(|entry| entry.is_ok()).count()
            ),
        ),
        Err(error) => OracleCheck::rejected(
            "rust_strict_parser",
            "rejected_parse",
            format!("strict parser failed: {error}"),
        ),
    }
}

fn run_rust_tolerant_parser(image: &Image) -> OracleCheck {
    let report = match parse_image(image, ParseMode::FuzzTolerant) {
        Ok(report) => report,
        Err(error) => {
            return OracleCheck::rejected(
                "rust_tolerant_parser",
                "rejected_parse",
                format!("tolerant parser failed: {error}"),
            );
        }
    };

    if report.superblock.is_none() {
        return OracleCheck::rejected(
            "rust_tolerant_parser",
            "rejected_parse",
            "tolerant parser could not decode the superblock",
        );
    }

    let parsed_inodes = report.inodes.iter().filter(|entry| entry.is_ok()).count();
    let parsed_dirents = report.dirents.iter().filter(|entry| entry.is_ok()).count();
    let reason = format!(
        "tolerant parser recorded {} recoverable error(s), {} inode(s), {} dirent(s)",
        report.errors.len(),
        parsed_inodes,
        parsed_dirents
    );

    if report.errors.is_empty() {
        OracleCheck::accepted("rust_tolerant_parser", "accepted", reason)
    } else {
        OracleCheck::accepted("rust_tolerant_parser", "accepted_with_errors", reason)
    }
}

fn fsck_check(args: &OracleArgs, input: &Path, limits: ExecLimits) -> Result<OracleCheck> {
    let result = run_fsck_with_limits(&args.fsck, input, &[], limits)?;
    Ok(tool_result_check("fsck", &result))
}

fn sanitized_fsck_check(
    args: &OracleArgs,
    input: &Path,
    limits: ExecLimits,
) -> Result<OracleCheck> {
    let Some(fsck) = &args.sanitized_fsck else {
        return Ok(OracleCheck::skipped(
            "sanitized_fsck",
            "no sanitized fsck.erofs path supplied",
        ));
    };
    let result = run_fsck_with_limits(fsck, input, &[], limits)?;
    Ok(tool_result_check("sanitized_fsck", &result))
}

fn dump_check(args: &OracleArgs, input: &Path, limits: ExecLimits) -> Result<OracleCheck> {
    let Some(dump) = &args.dump else {
        return Ok(OracleCheck::skipped("dump", "no dump.erofs path supplied"));
    };
    let extra_args = vec!["-s".to_string()];
    let result = run_fsck_with_limits(dump, input, &extra_args, limits)?;
    Ok(tool_result_check("dump", &result))
}

fn kernel_replay_check(args: &OracleArgs) -> Result<OracleCheck> {
    let Some(report_path) = &args.kernel_report else {
        return Ok(OracleCheck::skipped(
            "kernel_replay",
            "no kernel replay report supplied",
        ));
    };

    let content = fs::read_to_string(report_path)
        .with_context(|| format!("failed to read kernel replay report {report_path}"))?;
    let report = parse_kernel_replay_report(&content)
        .with_context(|| format!("failed to parse kernel replay report {report_path}"))?;
    let reason = format!("{} ({})", report.message, report.signature);

    match report.outcome {
        KernelReplayOutcome::Accepted => {
            Ok(OracleCheck::accepted("kernel_replay", "accepted", reason))
        }
        KernelReplayOutcome::Rejected => Ok(OracleCheck::rejected(
            "kernel_replay",
            "rejected_kernel",
            reason,
        )),
        KernelReplayOutcome::Unsafe => {
            let pattern = report
                .dangerous_pattern
                .as_deref()
                .unwrap_or("unknown dangerous pattern");
            Ok(OracleCheck::rejected(
                "kernel_replay",
                "kernel_unsafe",
                format!("{reason}; dangerous_pattern={pattern}"),
            ))
        }
        KernelReplayOutcome::Timeout => {
            Ok(OracleCheck::rejected("kernel_replay", "timeout", reason))
        }
        KernelReplayOutcome::Unknown => Ok(OracleCheck::rejected(
            "kernel_replay",
            "kernel_unknown",
            reason,
        )),
    }
}

fn checksum_repair_check(
    args: &OracleArgs,
    image: &Image,
    limits: ExecLimits,
) -> Result<OracleCheck> {
    let mut repaired = image.clone();
    if let Err(error) = fix_checksum(&mut repaired) {
        return Ok(OracleCheck::rejected(
            "checksum_repair_fsck",
            "rejected_checksum_repair",
            format!("checksum repair failed: {error}"),
        ));
    }

    let temp = NamedTempFile::new().context("failed to create checksum repair temp image")?;
    write_image(temp.path(), &repaired).with_context(|| {
        format!(
            "failed to write checksum repair temp image {}",
            temp.path().display()
        )
    })?;
    let result = run_fsck_with_limits(&args.fsck, temp.path(), &[], limits)?;
    Ok(tool_result_check("checksum_repair_fsck", &result))
}

fn tool_result_check(name: &'static str, result: &FsckResult) -> OracleCheck {
    if result.timed_out {
        return OracleCheck::rejected(name, "timeout", "tool timed out");
    }
    if result.classification == "accepted" {
        return OracleCheck::accepted(name, &result.classification, &result.reason);
    }
    OracleCheck::rejected(name, &result.classification, &result.reason)
}

fn compare_checks(left: &OracleCheck, right: &OracleCheck) -> OracleMatrixEntry {
    let name = format!("{}_vs_{}", left.name, right.name);
    let skipped = !left.status.is_decision() || !right.status.is_decision();
    let disagrees =
        !skipped && (left.status != right.status || left.classification != right.classification);
    let verdict = if skipped {
        "skipped"
    } else if disagrees {
        "disagree"
    } else {
        "agree"
    };

    OracleMatrixEntry {
        name,
        left: left.name.to_string(),
        right: right.name.to_string(),
        left_status: left.status.as_str().to_string(),
        right_status: right.status.as_str().to_string(),
        left_classification: left.classification.clone(),
        right_classification: right.classification.clone(),
        verdict: verdict.to_string(),
        disagrees,
    }
}

fn oracle_matrix(checks: &[OracleCheck]) -> Vec<OracleMatrixEntry> {
    let mut matrix = Vec::new();
    for left_idx in 0..checks.len() {
        for right_idx in (left_idx + 1)..checks.len() {
            matrix.push(compare_checks(&checks[left_idx], &checks[right_idx]));
        }
    }
    matrix
}

fn interesting_findings(matrix: &[OracleMatrixEntry]) -> usize {
    matrix.iter().filter(|entry| entry.disagrees).count()
}

fn matrix_line(entry: &OracleMatrixEntry) -> String {
    if entry.verdict == "skipped" {
        return format!("- {}: skipped", entry.name);
    }

    format!(
        "- {}: {} ({}={}/{}, {}={}/{})",
        entry.name,
        entry.verdict,
        entry.left,
        entry.left_status,
        entry.left_classification,
        entry.right,
        entry.right_status,
        entry.right_classification
    )
}

fn render_report(input: &Path, checks: &[OracleCheck], matrix: &[OracleMatrixEntry]) -> String {
    let mut lines = vec![
        "# EROFS Userspace Oracle Report".to_string(),
        String::new(),
        format!("input: {}", input.display()),
        String::new(),
        "## Checks".to_string(),
        String::new(),
    ];

    for check in checks {
        lines.push(format!(
            "- {}: {} ({}) - {}",
            check.name,
            check.status.as_str(),
            check.classification,
            check.reason
        ));
    }

    lines.extend([String::new(), "## Oracle Matrix".to_string(), String::new()]);

    for entry in matrix {
        lines.push(matrix_line(entry));
    }

    lines.extend([
        String::new(),
        format!("interesting_findings: {}", interesting_findings(matrix)),
    ]);

    lines.join("\n") + "\n"
}

fn json_report(
    input: &Path,
    input_sha256: &str,
    checks: &[OracleCheck],
    matrix: &[OracleMatrixEntry],
) -> OracleJsonReport {
    OracleJsonReport {
        schema: ORACLE_REPORT_SCHEMA.to_string(),
        input: input.to_string_lossy().to_string(),
        input_sha256: Some(input_sha256.to_string()),
        checks: checks
            .iter()
            .map(|check| OracleJsonCheck {
                name: check.name.to_string(),
                status: check.status.as_str().to_string(),
                classification: check.classification.clone(),
                reason: check.reason.clone(),
            })
            .collect(),
        matrix: matrix.to_vec(),
        interesting_findings: interesting_findings(matrix),
    }
}

fn write_json_report(path: &str, report: &OracleJsonReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)
        .map_err(|e| anyhow::anyhow!("failed to encode oracle JSON report: {e}"))?;
    fs::write(path, json + "\n")
        .map_err(|e| anyhow::anyhow!("failed to write oracle JSON report {path}: {e}"))?;
    Ok(())
}

fn image_sha256(image: &Image) -> String {
    let mut hasher = Sha256::new();
    hasher.update(image.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn run(args: &OracleArgs) -> Result<()> {
    let input = Path::new(&args.input);
    if !input.exists() {
        bail!("Input file not found: {}", args.input);
    }

    let image = read_image(input).with_context(|| format!("failed to read {}", input.display()))?;
    let input_sha256 = image_sha256(&image);
    let limits = limits_from_args(args);
    let checks = vec![
        run_rust_parser(&image),
        run_rust_strict_parser(&image),
        run_rust_tolerant_parser(&image),
        fsck_check(args, input, limits).context("failed to run fsck oracle")?,
        sanitized_fsck_check(args, input, limits).context("failed to run sanitized fsck oracle")?,
        dump_check(args, input, limits).context("failed to run dump oracle")?,
        kernel_replay_check(args).context("failed to read kernel replay oracle")?,
        checksum_repair_check(args, &image, limits)
            .context("failed to run checksum repair oracle")?,
    ];
    let matrix = oracle_matrix(&checks);
    let report = render_report(input, &checks, &matrix);

    if let Some(report_path) = &args.report {
        fs::write(report_path, &report)
            .map_err(|e| anyhow::anyhow!("failed to write oracle report {report_path}: {e}"))?;
    }
    if let Some(report_path) = &args.json_report {
        let json = json_report(input, &input_sha256, &checks, &matrix);
        write_json_report(report_path, &json)?;
    }

    print!("{report}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ORACLE_REPORT_SCHEMA, OracleCheck, OracleJsonReportError, OracleStatus, compare_checks,
        parse_oracle_json_report, run_rust_strict_parser, run_rust_tolerant_parser,
    };
    use crate::image::{FieldWidth, read_image};
    use crate::parse::{ParseMode, parse_image};
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    const VALID_JSON_REPORT: &str = r#"{
  "schema": "erofs-rs.oracle-report.v1",
  "input": "sample.erofs",
  "input_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "checks": [
    {
      "name": "rust_parser",
      "status": "accepted",
      "classification": "accepted",
      "reason": "ok"
    },
    {
      "name": "fsck",
      "status": "rejected",
      "classification": "rejected_invalid",
      "reason": "invalid image"
    }
  ],
  "matrix": [
    {
      "name": "rust_parser_vs_fsck",
      "left": "rust_parser",
      "right": "fsck",
      "left_status": "accepted",
      "right_status": "rejected",
      "left_classification": "accepted",
      "right_classification": "rejected_invalid",
      "verdict": "disagree",
      "disagrees": true
    }
  ],
  "interesting_findings": 1
}"#;

    #[test]
    fn oracle_json_report_parser_accepts_valid_report() {
        let report = parse_oracle_json_report(VALID_JSON_REPORT).unwrap();

        assert_eq!(report.schema, ORACLE_REPORT_SCHEMA);
        assert_eq!(report.input, "sample.erofs");
        assert_eq!(
            report.input_sha256.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(report.checks.len(), 2);
        assert_eq!(report.interesting_findings, 1);
    }

    #[test]
    fn oracle_json_report_parser_accepts_legacy_report_without_input_hash() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_JSON_REPORT).unwrap();
        report.as_object_mut().unwrap().remove("input_sha256");
        let report = serde_json::to_string(&report).unwrap();

        let report = parse_oracle_json_report(&report).unwrap();

        assert_eq!(report.input_sha256, None);
    }

    #[test]
    fn oracle_json_report_parser_rejects_unknown_schema() {
        let report =
            VALID_JSON_REPORT.replace("erofs-rs.oracle-report.v1", "erofs-rs.oracle-report.v0");

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(error, OracleJsonReportError::UnsupportedSchema(_)));
    }

    #[test]
    fn oracle_json_report_parser_rejects_invalid_input_hash() {
        let report = VALID_JSON_REPORT.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "short",
        );

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::InvalidSha256 {
                field: "input_sha256",
                ..
            }
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_invalid_status() {
        let report =
            VALID_JSON_REPORT.replace(r#""status": "accepted""#, r#""status": "maybe_accepted""#);

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::InvalidStatus {
                field: "checks.status",
                ..
            }
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_skipped_status_classification_mismatch() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_JSON_REPORT).unwrap();
        report["checks"][0]["status"] = serde_json::json!("skipped");
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::CheckStatusClassificationMismatch {
                check,
                status,
                classification,
            } if check == "rust_parser"
                && status == "skipped"
                && classification == "accepted"
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_skipped_classification_status_mismatch() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_JSON_REPORT).unwrap();
        report["checks"][0]["classification"] = serde_json::json!("skipped");
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::CheckStatusClassificationMismatch {
                check,
                status,
                classification,
            } if check == "rust_parser"
                && status == "accepted"
                && classification == "skipped"
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_inconsistent_verdict() {
        let report = VALID_JSON_REPORT.replace(r#""verdict": "disagree""#, r#""verdict": "agree""#);

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::InconsistentVerdict(_)
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_skipped_verdict_mismatch() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_JSON_REPORT).unwrap();
        report["checks"][0]["status"] = serde_json::json!("skipped");
        report["checks"][0]["classification"] = serde_json::json!("skipped");
        report["matrix"][0]["left_status"] = serde_json::json!("skipped");
        report["matrix"][0]["left_classification"] = serde_json::json!("skipped");
        report["matrix"][0]["verdict"] = serde_json::json!("agree");
        report["matrix"][0]["disagrees"] = serde_json::json!(false);
        report["interesting_findings"] = serde_json::json!(0);
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::InconsistentVerdict(entry)
                if entry == "rust_parser_vs_fsck"
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_interesting_count_mismatch() {
        let report = VALID_JSON_REPORT.replace(
            r#""interesting_findings": 1"#,
            r#""interesting_findings": 0"#,
        );

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::InterestingFindingsMismatch {
                expected: 1,
                actual: 0
            }
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_unknown_fields() {
        let report = VALID_JSON_REPORT.replace(
            r#""interesting_findings": 1"#,
            r#""interesting_findings": 1,
  "unexpected": true"#,
        );

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(error, OracleJsonReportError::Decode(_)));
    }

    #[test]
    fn oracle_json_report_parser_rejects_duplicate_check() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_JSON_REPORT).unwrap();
        let check = report["checks"][0].clone();
        report["checks"].as_array_mut().unwrap().push(check);
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::DuplicateCheck(check) if check == "rust_parser"
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_duplicate_matrix_entry() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_JSON_REPORT).unwrap();
        let entry = report["matrix"][0].clone();
        report["matrix"].as_array_mut().unwrap().push(entry);
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::DuplicateMatrixEntry(entry)
                if entry == "rust_parser_vs_fsck"
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_missing_matrix_entry() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_JSON_REPORT).unwrap();
        report["matrix"].as_array_mut().unwrap().clear();
        report["interesting_findings"] = serde_json::json!(0);
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::MissingMatrixEntry(entry)
                if entry == "rust_parser_vs_fsck"
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_mismatched_matrix_pair() {
        let report = VALID_JSON_REPORT.replace(
            r#""name": "rust_parser_vs_fsck""#,
            r#""name": "fsck_vs_rust_parser""#,
        );

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::InvalidMatrixPair { entry, expected }
                if entry == "fsck_vs_rust_parser"
                    && expected == "rust_parser_vs_fsck"
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_unknown_matrix_check() {
        let report = VALID_JSON_REPORT.replace(r#""right": "fsck""#, r#""right": "missing""#);

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::UnknownMatrixCheck { entry, check }
                if entry == "rust_parser_vs_fsck" && check == "missing"
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_matrix_status_mismatch() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_JSON_REPORT).unwrap();
        report["matrix"][0]["left_status"] = serde_json::json!("rejected");
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::MatrixCheckMismatch {
                entry,
                check,
                field: "matrix.left_status",
                expected,
                actual,
            } if entry == "rust_parser_vs_fsck"
                && check == "rust_parser"
                && expected == "accepted"
                && actual == "rejected"
        ));
    }

    #[test]
    fn oracle_json_report_parser_rejects_matrix_classification_mismatch() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_JSON_REPORT).unwrap();
        report["matrix"][0]["right_classification"] = serde_json::json!("rejected_checksum");
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::MatrixCheckMismatch {
                entry,
                check,
                field: "matrix.right_classification",
                expected,
                actual,
            } if entry == "rust_parser_vs_fsck"
                && check == "fsck"
                && expected == "rejected_invalid"
                && actual == "rejected_checksum"
        ));
    }

    #[test]
    fn agreement_detects_decision_disagreements() {
        let rust = OracleCheck {
            name: "rust_parser",
            status: OracleStatus::Accepted,
            classification: "accepted".to_string(),
            reason: "ok".to_string(),
        };
        let fsck = OracleCheck {
            name: "fsck",
            status: OracleStatus::Rejected,
            classification: "rejected_invalid".to_string(),
            reason: "bad".to_string(),
        };

        let entry = compare_checks(&rust, &fsck);

        assert!(entry.disagrees);
        assert_eq!(entry.verdict, "disagree");
        assert_eq!(entry.left_status, "accepted");
        assert_eq!(entry.right_status, "rejected");
    }

    #[test]
    fn sanitized_fsck_crash_counts_as_interesting_disagreement() {
        let normal = OracleCheck {
            name: "fsck",
            status: OracleStatus::Accepted,
            classification: "accepted".to_string(),
            reason: "ok".to_string(),
        };
        let sanitized = OracleCheck {
            name: "sanitized_fsck",
            status: OracleStatus::Rejected,
            classification: "sanitizer_crash".to_string(),
            reason: "AddressSanitizer: heap-buffer-overflow".to_string(),
        };

        let entry = compare_checks(&normal, &sanitized);

        assert!(entry.disagrees);
        assert_eq!(entry.name, "fsck_vs_sanitized_fsck");
        assert_eq!(entry.verdict, "disagree");
        assert_eq!(entry.left_classification, "accepted");
        assert_eq!(entry.right_classification, "sanitizer_crash");
    }

    #[test]
    fn tolerant_parser_check_surfaces_recoverable_parse_errors() {
        let mut image = read_image(fixture("single.erofs")).unwrap();
        let report = parse_image(&image, ParseMode::FuzzTolerant).unwrap();
        let dirent_offset = report
            .dirents
            .iter()
            .find_map(|entry| entry.as_ref().ok().map(|dirent| dirent.offset))
            .unwrap();
        image
            .write_field(dirent_offset + 0x0A, FieldWidth::U8, 0xFF)
            .unwrap();

        let strict = run_rust_strict_parser(&image);
        let tolerant = run_rust_tolerant_parser(&image);
        let entry = compare_checks(&strict, &tolerant);

        assert_eq!(strict.status, OracleStatus::Accepted);
        assert_eq!(strict.classification, "accepted");
        assert_eq!(tolerant.status, OracleStatus::Accepted);
        assert_eq!(tolerant.classification, "accepted_with_errors");
        assert!(tolerant.reason.contains("recoverable error"));
        assert!(entry.disagrees);
        assert_eq!(entry.name, "rust_strict_parser_vs_rust_tolerant_parser");
        assert_eq!(entry.left_classification, "accepted");
        assert_eq!(entry.right_classification, "accepted_with_errors");
    }
}
