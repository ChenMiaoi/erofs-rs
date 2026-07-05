use crate::checksum::fix_checksum;
use crate::cli::OracleArgs;
use crate::dirent::locate_dirents_in_image;
use crate::fsck::{ExecLimits, FsckResult, run_fsck_with_limits};
use crate::image::{Image, read_image, write_image};
use crate::inode::locate_inodes;
use crate::parse::{ParseMode, parse_image};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
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
    #[error("oracle JSON report field {field} has invalid status: {status}")]
    InvalidStatus { field: &'static str, status: String },
    #[error("oracle JSON report field {field} has invalid verdict: {verdict}")]
    InvalidVerdict {
        field: &'static str,
        verdict: String,
    },
    #[error("oracle JSON report matrix entry {0} has inconsistent verdict")]
    InconsistentVerdict(String),
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
    if report.checks.is_empty() {
        return Err(OracleJsonReportError::EmptyList("checks"));
    }
    for check in &report.checks {
        validate_json_check(check)?;
    }
    for entry in &report.matrix {
        validate_matrix_entry(entry)?;
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

fn validate_json_check(check: &OracleJsonCheck) -> std::result::Result<(), OracleJsonReportError> {
    require_nonempty("checks.name", &check.name)?;
    require_status("checks.status", &check.status)?;
    require_nonempty("checks.classification", &check.classification)?;
    require_nonempty("checks.reason", &check.reason)?;
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
    checks: &[OracleCheck],
    matrix: &[OracleMatrixEntry],
) -> OracleJsonReport {
    OracleJsonReport {
        schema: ORACLE_REPORT_SCHEMA.to_string(),
        input: input.to_string_lossy().to_string(),
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

pub fn run(args: &OracleArgs) -> Result<()> {
    let input = Path::new(&args.input);
    if !input.exists() {
        bail!("Input file not found: {}", args.input);
    }

    let image = read_image(input).with_context(|| format!("failed to read {}", input.display()))?;
    let limits = limits_from_args(args);
    let checks = vec![
        run_rust_parser(&image),
        run_rust_strict_parser(&image),
        run_rust_tolerant_parser(&image),
        fsck_check(args, input, limits).context("failed to run fsck oracle")?,
        sanitized_fsck_check(args, input, limits).context("failed to run sanitized fsck oracle")?,
        dump_check(args, input, limits).context("failed to run dump oracle")?,
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
        let json = json_report(input, &checks, &matrix);
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
        assert_eq!(report.checks.len(), 2);
        assert_eq!(report.interesting_findings, 1);
    }

    #[test]
    fn oracle_json_report_parser_rejects_unknown_schema() {
        let report =
            VALID_JSON_REPORT.replace("erofs-rs.oracle-report.v1", "erofs-rs.oracle-report.v0");

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(error, OracleJsonReportError::UnsupportedSchema(_)));
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
    fn oracle_json_report_parser_rejects_inconsistent_verdict() {
        let report = VALID_JSON_REPORT.replace(r#""verdict": "disagree""#, r#""verdict": "agree""#);

        let error = parse_oracle_json_report(&report).unwrap_err();

        assert!(matches!(
            error,
            OracleJsonReportError::InconsistentVerdict(_)
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
