use crate::cli::KernelReportArgs;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const KERNEL_REPLAY_REPORT_SCHEMA: &str = "erofs-rs.kernel-replay.v1";
pub const KERNEL_REPLAY_SUMMARY_SCHEMA: &str = "erofs-rs.kernel-replay-summary.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelReplayOutcome {
    Accepted,
    Rejected,
    Unsafe,
    Timeout,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KernelReplayReport {
    pub schema: String,
    pub artifact_sha256: Option<String>,
    pub kernel_git: Option<String>,
    pub qemu_exit_code: i32,
    pub outcome: KernelReplayOutcome,
    pub message: String,
    pub signature: String,
    pub dangerous_pattern: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KernelReplaySummary {
    pub schema: String,
    pub queue: String,
    pub candidate_count: usize,
    pub failure_count: usize,
    pub reports: Vec<KernelReplaySummaryEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KernelReplaySummaryEntry {
    pub candidate: String,
    pub artifact_sha256: String,
    pub qemu_exit_code: i32,
    pub replay_status: String,
    pub report_status: String,
    pub report_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelReplayVerdict {
    pub outcome: KernelReplayOutcome,
    pub message: String,
    pub signature: String,
    pub dangerous_pattern: Option<String>,
}

#[derive(Debug, Error)]
pub enum KernelReplayReportError {
    #[error("failed to decode kernel replay report: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unsupported kernel replay report schema: {0}")]
    UnsupportedSchema(String),
    #[error("unsupported kernel replay summary schema: {0}")]
    UnsupportedSummarySchema(String),
    #[error("kernel replay report field {0} is empty")]
    EmptyField(&'static str),
    #[error("kernel replay report field {field} has invalid SHA-256 digest: {sha256}")]
    InvalidSha256 { field: &'static str, sha256: String },
    #[error("unsafe kernel replay report is missing dangerous_pattern")]
    MissingDangerousPattern,
    #[error("non-unsafe kernel replay report includes dangerous_pattern")]
    UnexpectedDangerousPattern,
    #[error("kernel replay report signature {signature:?} does not match {outcome:?} outcome")]
    InvalidSignaturePrefix {
        outcome: KernelReplayOutcome,
        signature: String,
    },
    #[error("kernel replay summary field {field} has invalid status: {status}")]
    InvalidSummaryStatus { field: &'static str, status: String },
    #[error("kernel replay summary contains duplicate candidate: {0}")]
    DuplicateSummaryCandidate(String),
    #[error("kernel replay summary contains duplicate report path: {0}")]
    DuplicateSummaryReportPath(String),
    #[error(
        "kernel replay summary count mismatch for {field}: expected {expected}, actual {actual}"
    )]
    SummaryCountMismatch {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}

pub fn build_kernel_replay_report(
    dmesg: &str,
    qemu_exit_code: i32,
    artifact_sha256: Option<String>,
    kernel_git: Option<String>,
) -> KernelReplayReport {
    let verdict = classify_dmesg_text(dmesg, qemu_exit_code);
    KernelReplayReport {
        schema: KERNEL_REPLAY_REPORT_SCHEMA.to_string(),
        artifact_sha256,
        kernel_git,
        qemu_exit_code,
        outcome: verdict.outcome,
        message: verdict.message,
        signature: verdict.signature,
        dangerous_pattern: verdict.dangerous_pattern,
    }
}

pub fn parse_kernel_replay_report(
    content: &str,
) -> std::result::Result<KernelReplayReport, KernelReplayReportError> {
    let report: KernelReplayReport = serde_json::from_str(content)?;
    validate_kernel_replay_report(&report)?;
    Ok(report)
}

pub fn parse_kernel_replay_summary(
    content: &str,
) -> std::result::Result<KernelReplaySummary, KernelReplayReportError> {
    let summary: KernelReplaySummary = serde_json::from_str(content)?;
    validate_kernel_replay_summary(&summary)?;
    Ok(summary)
}

pub fn validate_kernel_replay_report(
    report: &KernelReplayReport,
) -> std::result::Result<(), KernelReplayReportError> {
    if report.schema != KERNEL_REPLAY_REPORT_SCHEMA {
        return Err(KernelReplayReportError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    if let Some(sha256) = &report.artifact_sha256 {
        require_sha256("artifact_sha256", sha256)?;
    }
    if let Some(kernel_git) = &report.kernel_git {
        require_nonempty("kernel_git", kernel_git)?;
    }
    require_nonempty("message", &report.message)?;
    require_nonempty("signature", &report.signature)?;
    if !report
        .signature
        .starts_with(signature_prefix(&report.outcome))
    {
        return Err(KernelReplayReportError::InvalidSignaturePrefix {
            outcome: report.outcome.clone(),
            signature: report.signature.clone(),
        });
    }
    match (&report.outcome, &report.dangerous_pattern) {
        (KernelReplayOutcome::Unsafe, Some(pattern)) => {
            require_nonempty("dangerous_pattern", pattern)?;
        }
        (KernelReplayOutcome::Unsafe, None) => {
            return Err(KernelReplayReportError::MissingDangerousPattern);
        }
        (_, Some(_)) => {
            return Err(KernelReplayReportError::UnexpectedDangerousPattern);
        }
        (_, None) => {}
    }
    Ok(())
}

pub fn validate_kernel_replay_summary(
    summary: &KernelReplaySummary,
) -> std::result::Result<(), KernelReplayReportError> {
    if summary.schema != KERNEL_REPLAY_SUMMARY_SCHEMA {
        return Err(KernelReplayReportError::UnsupportedSummarySchema(
            summary.schema.clone(),
        ));
    }
    require_nonempty("queue", &summary.queue)?;
    let mut candidates = HashSet::new();
    let mut report_paths = HashSet::new();
    let mut failures = 0usize;
    for report in &summary.reports {
        validate_summary_entry(report)?;
        if !candidates.insert(report.candidate.as_str()) {
            return Err(KernelReplayReportError::DuplicateSummaryCandidate(
                report.candidate.clone(),
            ));
        }
        if !report_paths.insert(report.report_path.as_str()) {
            return Err(KernelReplayReportError::DuplicateSummaryReportPath(
                report.report_path.clone(),
            ));
        }
        if report.replay_status != "rejected" || report.report_status != "written" {
            failures = failures.saturating_add(1);
        }
    }
    require_summary_count(
        "candidate_count",
        summary.reports.len(),
        summary.candidate_count,
    )?;
    require_summary_count("failure_count", failures, summary.failure_count)
}

fn validate_summary_entry(
    entry: &KernelReplaySummaryEntry,
) -> std::result::Result<(), KernelReplayReportError> {
    require_nonempty("reports.candidate", &entry.candidate)?;
    require_sha256("reports.artifact_sha256", &entry.artifact_sha256)?;
    require_summary_status(
        "reports.replay_status",
        &entry.replay_status,
        &["rejected", "needs-triage"],
    )?;
    require_summary_status(
        "reports.report_status",
        &entry.report_status,
        &["written", "failed"],
    )?;
    require_nonempty("reports.report_path", &entry.report_path)
}

fn require_summary_status(
    field: &'static str,
    status: &str,
    allowed: &[&str],
) -> std::result::Result<(), KernelReplayReportError> {
    if allowed.contains(&status) {
        return Ok(());
    }
    Err(KernelReplayReportError::InvalidSummaryStatus {
        field,
        status: status.to_string(),
    })
}

fn require_summary_count(
    field: &'static str,
    expected: usize,
    actual: usize,
) -> std::result::Result<(), KernelReplayReportError> {
    if expected == actual {
        return Ok(());
    }
    Err(KernelReplayReportError::SummaryCountMismatch {
        field,
        expected,
        actual,
    })
}

fn signature_prefix(outcome: &KernelReplayOutcome) -> &'static str {
    match outcome {
        KernelReplayOutcome::Accepted => "kernel_accepted:",
        KernelReplayOutcome::Rejected => "kernel_rejected:",
        KernelReplayOutcome::Unsafe => "kernel_unsafe:",
        KernelReplayOutcome::Timeout => "kernel_timeout:",
        KernelReplayOutcome::Unknown => "kernel_unknown:",
    }
}

fn require_nonempty(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), KernelReplayReportError> {
    if value.is_empty() {
        return Err(KernelReplayReportError::EmptyField(field));
    }
    Ok(())
}

fn require_sha256(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), KernelReplayReportError> {
    if !is_sha256_digest(value) {
        return Err(KernelReplayReportError::InvalidSha256 {
            field,
            sha256: value.to_string(),
        });
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to hash {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn resolve_artifact_sha256(args: &KernelReportArgs) -> Result<Option<String>> {
    let expected = args.artifact_sha256.as_deref();
    if let Some(digest) = expected {
        if !is_sha256_digest(digest) {
            bail!("invalid artifact SHA-256 digest: {digest}");
        }
    }

    let Some(path) = &args.artifact else {
        return Ok(expected.map(ToOwned::to_owned));
    };
    let artifact_path = PathBuf::from(path);
    if !artifact_path.exists() {
        bail!("artifact file not found: {}", artifact_path.display());
    }

    let actual = sha256_file(&artifact_path)?;
    if let Some(expected) = expected {
        if actual != expected {
            bail!(
                "artifact SHA-256 mismatch for {}: expected {}, got {}",
                artifact_path.display(),
                expected,
                actual
            );
        }
    }
    Ok(Some(actual))
}

fn write_report(path: &Path, report: &KernelReplayReport) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json =
        serde_json::to_string_pretty(report).context("failed to serialize kernel replay report")?;
    fs::write(path, format!("{json}\n"))
        .with_context(|| format!("failed to write kernel replay report {}", path.display()))
}

pub fn run(args: &KernelReportArgs) -> Result<()> {
    let dmesg_path = Path::new(&args.dmesg);
    let dmesg = fs::read_to_string(dmesg_path)
        .with_context(|| format!("failed to read dmesg log {}", dmesg_path.display()))?;
    let artifact_sha256 = resolve_artifact_sha256(args)?;
    let report = build_kernel_replay_report(
        &dmesg,
        args.qemu_exit_code,
        artifact_sha256,
        args.kernel_git.clone(),
    );
    let output_path = Path::new(&args.output);
    write_report(output_path, &report)?;

    println!("Wrote kernel replay report to {}", output_path.display());
    println!("  Outcome: {:?}", report.outcome);
    println!("  Signature: {}", report.signature);
    Ok(())
}

pub fn classify_dmesg_text(dmesg: &str, qemu_exit_code: i32) -> KernelReplayVerdict {
    if let Some((pattern, line)) = dangerous_line(dmesg) {
        let detail = normalize_signature_detail(line);
        return KernelReplayVerdict {
            outcome: KernelReplayOutcome::Unsafe,
            message: "KERNEL BUG/OOPS/KASAN DETECTED".to_string(),
            signature: format!("kernel_unsafe: {detail}"),
            dangerous_pattern: Some(pattern.to_string()),
        };
    }

    if dmesg.contains("== erofs mount rejected safely ==") {
        let message = erofs_rejection_message(dmesg)
            .unwrap_or_else(|| "rejected without message".to_string());
        return KernelReplayVerdict {
            outcome: KernelReplayOutcome::Rejected,
            signature: format!("kernel_rejected: {}", normalize_signature_detail(&message)),
            message,
            dangerous_pattern: None,
        };
    }

    if dmesg.contains("== erofs traversal complete ==") {
        return KernelReplayVerdict {
            outcome: KernelReplayOutcome::Accepted,
            message: "mounted and traversed successfully".to_string(),
            signature: "kernel_accepted: mounted and traversed successfully".to_string(),
            dangerous_pattern: None,
        };
    }

    if qemu_exit_code == 124 {
        return KernelReplayVerdict {
            outcome: KernelReplayOutcome::Timeout,
            message: "QEMU timeout".to_string(),
            signature: "kernel_timeout: QEMU timeout".to_string(),
            dangerous_pattern: None,
        };
    }

    KernelReplayVerdict {
        outcome: KernelReplayOutcome::Unknown,
        message: format!("exit_code={qemu_exit_code}"),
        signature: format!("kernel_unknown: exit_code={qemu_exit_code}"),
        dangerous_pattern: None,
    }
}

fn dangerous_line(dmesg: &str) -> Option<(&'static str, &str)> {
    dmesg.lines().find_map(|line| {
        dangerous_pattern(line).map(|pattern| {
            let trimmed = line.trim();
            (pattern, if trimmed.is_empty() { line } else { trimmed })
        })
    })
}

fn dangerous_pattern(line: &str) -> Option<&'static str> {
    let lower = line.to_lowercase();
    let patterns = [
        ("kernel BUG", "kernel bug"),
        ("BUG:", "bug:"),
        ("Oops:", "oops:"),
        ("KASAN", "kasan"),
        ("KMSAN", "kmsan"),
        ("KFENCE", "kfence"),
        ("UBSAN", "ubsan"),
        ("Kernel panic", "kernel panic"),
        ("general protection fault", "general protection fault"),
        ("stack-protector", "stack-protector"),
        ("WARNING:", "warning:"),
        ("lockdep", "lockdep"),
        ("hung task", "hung task"),
        ("RCU stall", "rcu stall"),
        ("rcu_sched detected stalls", "rcu_sched detected stalls"),
        ("Unable to handle kernel", "unable to handle kernel"),
        (
            "kernel NULL pointer dereference",
            "kernel null pointer dereference",
        ),
        ("invalid opcode", "invalid opcode"),
    ];

    patterns
        .iter()
        .find_map(|(label, needle)| lower.contains(needle).then_some(*label))
        .or_else(|| {
            (lower.contains("info: task ") && lower.contains("blocked for more than"))
                .then_some("INFO: task blocked for more than")
        })
}

fn erofs_rejection_message(dmesg: &str) -> Option<String> {
    dmesg
        .lines()
        .filter_map(|line| line.split_once("erofs (device vda): "))
        .map(|(_, message)| message.trim())
        .rfind(|message| !message.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_signature_detail(detail: &str) -> String {
    const MAX_SIGNATURE_DETAIL_CHARS: usize = 160;
    detail
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_SIGNATURE_DETAIL_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        KERNEL_REPLAY_REPORT_SCHEMA, KERNEL_REPLAY_SUMMARY_SCHEMA, KernelReplayOutcome,
        KernelReplayReportError, build_kernel_replay_report, classify_dmesg_text,
        parse_kernel_replay_report, parse_kernel_replay_summary, run,
    };
    use crate::cli::KernelReportArgs;
    use sha2::{Digest, Sha256};
    use std::fs;

    const VALID_REPORT: &str = r#"{
  "schema": "erofs-rs.kernel-replay.v1",
  "artifact_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "kernel_git": "linux-test-rev",
  "qemu_exit_code": 0,
  "outcome": "rejected",
  "message": "failed to verify superblock checksum",
  "signature": "kernel_rejected: failed to verify superblock checksum",
  "dangerous_pattern": null
}"#;

    const VALID_SUMMARY: &str = r#"{
  "schema": "erofs-rs.kernel-replay-summary.v1",
  "queue": "corpus/crashes/kernel-candidates",
  "candidate_count": 2,
  "failure_count": 1,
  "reports": [
    {
      "candidate": "corpus/crashes/kernel-candidates/a.erofs",
      "artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "qemu_exit_code": 0,
      "replay_status": "rejected",
      "report_status": "written",
      "report_path": "kernel-replay/reports/a.kernel-report.json"
    },
    {
      "candidate": "corpus/crashes/kernel-candidates/b.erofs",
      "artifact_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "qemu_exit_code": 1,
      "replay_status": "needs-triage",
      "report_status": "failed",
      "report_path": "kernel-replay/reports/b.kernel-report.json"
    }
  ]
}"#;

    #[test]
    fn dmesg_classification_prioritizes_unsafe_output() {
        let dmesg = "\
== erofs mount rejected safely ==\n\
[  1.0] erofs (device vda): invalid checksum\n\
[  1.1] BUG: KASAN: slab-out-of-bounds in erofs_read_inode\n";

        let verdict = classify_dmesg_text(dmesg, 0);

        assert_eq!(verdict.outcome, KernelReplayOutcome::Unsafe);
        assert_eq!(verdict.message, "KERNEL BUG/OOPS/KASAN DETECTED");
        assert_eq!(verdict.dangerous_pattern.as_deref(), Some("BUG:"));
        assert!(verdict.signature.contains("KASAN"));
    }

    #[test]
    fn dmesg_classification_extracts_rejection_message() {
        let dmesg = "\
[  1.0] erofs (device vda): failed to verify superblock checksum\n\
== erofs mount rejected safely ==\n";

        let verdict = classify_dmesg_text(dmesg, 0);

        assert_eq!(verdict.outcome, KernelReplayOutcome::Rejected);
        assert_eq!(verdict.message, "failed to verify superblock checksum");
        assert_eq!(
            verdict.signature,
            "kernel_rejected: failed to verify superblock checksum"
        );
    }

    #[test]
    fn dmesg_classification_requires_traversal_for_accept() {
        let booted_only = "== erofs qemu booted ==\n";
        let accepted = "== erofs qemu booted ==\n== erofs traversal complete ==\n";

        assert_eq!(
            classify_dmesg_text(booted_only, 0).outcome,
            KernelReplayOutcome::Unknown
        );
        assert_eq!(
            classify_dmesg_text(accepted, 0).outcome,
            KernelReplayOutcome::Accepted
        );
    }

    #[test]
    fn dmesg_classification_records_timeout() {
        let verdict = classify_dmesg_text("", 124);

        assert_eq!(verdict.outcome, KernelReplayOutcome::Timeout);
        assert_eq!(verdict.signature, "kernel_timeout: QEMU timeout");
    }

    #[test]
    fn kernel_replay_report_round_trips_json() {
        let report = build_kernel_replay_report(
            "== erofs traversal complete ==\n",
            0,
            Some("a".repeat(64)),
            Some("linux-rev".to_string()),
        );
        let json = serde_json::to_string(&report).unwrap();
        let decoded: super::KernelReplayReport = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, report);
        assert_eq!(decoded.schema, KERNEL_REPLAY_REPORT_SCHEMA);
        assert_eq!(decoded.outcome, KernelReplayOutcome::Accepted);
    }

    #[test]
    fn kernel_replay_report_parser_accepts_valid_report() {
        let report = parse_kernel_replay_report(VALID_REPORT).unwrap();

        assert_eq!(report.schema, KERNEL_REPLAY_REPORT_SCHEMA);
        assert_eq!(report.outcome, KernelReplayOutcome::Rejected);
        assert_eq!(report.kernel_git.as_deref(), Some("linux-test-rev"));
    }

    #[test]
    fn kernel_replay_summary_parser_accepts_valid_report() {
        let summary = parse_kernel_replay_summary(VALID_SUMMARY).unwrap();

        assert_eq!(summary.schema, KERNEL_REPLAY_SUMMARY_SCHEMA);
        assert_eq!(summary.queue, "corpus/crashes/kernel-candidates");
        assert_eq!(summary.candidate_count, 2);
        assert_eq!(summary.failure_count, 1);
        assert_eq!(summary.reports.len(), 2);
    }

    #[test]
    fn kernel_replay_summary_parser_rejects_count_mismatch() {
        let summary = VALID_SUMMARY.replace(r#""failure_count": 1"#, r#""failure_count": 0"#);

        let error = parse_kernel_replay_summary(&summary).unwrap_err();

        assert!(matches!(
            error,
            KernelReplayReportError::SummaryCountMismatch {
                field: "failure_count",
                expected: 1,
                actual: 0
            }
        ));
    }

    #[test]
    fn kernel_replay_summary_parser_rejects_duplicate_candidate() {
        let summary = VALID_SUMMARY.replace(
            "corpus/crashes/kernel-candidates/b.erofs",
            "corpus/crashes/kernel-candidates/a.erofs",
        );

        let error = parse_kernel_replay_summary(&summary).unwrap_err();

        assert!(matches!(
            error,
            KernelReplayReportError::DuplicateSummaryCandidate(candidate)
                if candidate == "corpus/crashes/kernel-candidates/a.erofs"
        ));
    }

    #[test]
    fn kernel_replay_summary_parser_rejects_invalid_status() {
        let summary = VALID_SUMMARY.replace(
            r#""replay_status": "needs-triage""#,
            r#""replay_status": "unsafe""#,
        );

        let error = parse_kernel_replay_summary(&summary).unwrap_err();

        assert!(matches!(
            error,
            KernelReplayReportError::InvalidSummaryStatus {
                field: "reports.replay_status",
                ..
            }
        ));
    }

    #[test]
    fn kernel_replay_report_parser_rejects_unknown_schema() {
        let report = VALID_REPORT.replace("erofs-rs.kernel-replay.v1", "erofs-rs.kernel-replay.v0");

        let error = parse_kernel_replay_report(&report).unwrap_err();

        assert!(matches!(
            error,
            KernelReplayReportError::UnsupportedSchema(_)
        ));
    }

    #[test]
    fn kernel_replay_report_parser_rejects_invalid_artifact_hash() {
        let report = VALID_REPORT.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "not-a-sha256",
        );

        let error = parse_kernel_replay_report(&report).unwrap_err();

        assert!(matches!(
            error,
            KernelReplayReportError::InvalidSha256 {
                field: "artifact_sha256",
                ..
            }
        ));
    }

    #[test]
    fn kernel_replay_report_parser_rejects_mismatched_signature_prefix() {
        let report = VALID_REPORT.replace(
            r#""signature": "kernel_rejected: failed to verify superblock checksum""#,
            r#""signature": "kernel_unsafe: failed to verify superblock checksum""#,
        );

        let error = parse_kernel_replay_report(&report).unwrap_err();

        assert!(matches!(
            error,
            KernelReplayReportError::InvalidSignaturePrefix {
                outcome: KernelReplayOutcome::Rejected,
                ..
            }
        ));
    }

    #[test]
    fn kernel_replay_report_parser_rejects_unsafe_without_pattern() {
        let report = VALID_REPORT
            .replace(r#""outcome": "rejected""#, r#""outcome": "unsafe""#)
            .replace(
                r#""signature": "kernel_rejected: failed to verify superblock checksum""#,
                r#""signature": "kernel_unsafe: BUG: KASAN""#,
            );

        let error = parse_kernel_replay_report(&report).unwrap_err();

        assert!(matches!(
            error,
            KernelReplayReportError::MissingDangerousPattern
        ));
    }

    #[test]
    fn kernel_replay_report_parser_rejects_non_unsafe_pattern() {
        let report = VALID_REPORT.replace(
            r#""dangerous_pattern": null"#,
            r#""dangerous_pattern": "BUG:""#,
        );

        let error = parse_kernel_replay_report(&report).unwrap_err();

        assert!(matches!(
            error,
            KernelReplayReportError::UnexpectedDangerousPattern
        ));
    }

    #[test]
    fn kernel_replay_report_parser_rejects_empty_kernel_git() {
        let report =
            VALID_REPORT.replace(r#""kernel_git": "linux-test-rev""#, r#""kernel_git": """#);

        let error = parse_kernel_replay_report(&report).unwrap_err();

        assert!(matches!(
            error,
            KernelReplayReportError::EmptyField("kernel_git")
        ));
    }

    #[test]
    fn kernel_replay_report_parser_rejects_unknown_fields() {
        let report = VALID_REPORT.replace(
            r#""dangerous_pattern": null"#,
            r#""dangerous_pattern": null,
  "unexpected": true"#,
        );

        let error = parse_kernel_replay_report(&report).unwrap_err();

        assert!(matches!(error, KernelReplayReportError::Decode(_)));
    }

    #[test]
    fn kernel_report_command_writes_classified_json() {
        let tempdir = tempfile::tempdir().unwrap();
        let dmesg = tempdir.path().join("qemu-dmesg.log");
        let artifact = tempdir.path().join("artifact.erofs");
        let output = tempdir.path().join("reports").join("kernel-report.json");
        fs::write(
            &dmesg,
            "[ 1.0] erofs (device vda): failed to verify superblock checksum\n\
== erofs mount rejected safely ==\n",
        )
        .unwrap();
        fs::write(&artifact, b"artifact bytes").unwrap();
        let artifact_sha256 = hex::encode(Sha256::digest(b"artifact bytes"));
        let args = KernelReportArgs {
            dmesg: dmesg.to_string_lossy().into_owned(),
            artifact: Some(artifact.to_string_lossy().into_owned()),
            artifact_sha256: Some(artifact_sha256.clone()),
            kernel_git: Some("linux-test-rev".to_string()),
            qemu_exit_code: 0,
            output: output.to_string_lossy().into_owned(),
        };

        run(&args).unwrap();

        let json = fs::read_to_string(output).unwrap();
        let report: super::KernelReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.schema, KERNEL_REPLAY_REPORT_SCHEMA);
        assert_eq!(
            report.artifact_sha256.as_deref(),
            Some(artifact_sha256.as_str())
        );
        assert_eq!(report.kernel_git.as_deref(), Some("linux-test-rev"));
        assert_eq!(report.outcome, KernelReplayOutcome::Rejected);
        assert_eq!(
            report.signature,
            "kernel_rejected: failed to verify superblock checksum"
        );
    }

    #[test]
    fn kernel_report_command_rejects_artifact_hash_mismatch() {
        let tempdir = tempfile::tempdir().unwrap();
        let dmesg = tempdir.path().join("qemu-dmesg.log");
        let artifact = tempdir.path().join("artifact.erofs");
        let output = tempdir.path().join("kernel-report.json");
        fs::write(&dmesg, "== erofs traversal complete ==\n").unwrap();
        fs::write(&artifact, b"artifact bytes").unwrap();
        let args = KernelReportArgs {
            dmesg: dmesg.to_string_lossy().into_owned(),
            artifact: Some(artifact.to_string_lossy().into_owned()),
            artifact_sha256: Some("0".repeat(64)),
            kernel_git: None,
            qemu_exit_code: 0,
            output: output.to_string_lossy().into_owned(),
        };

        let error = run(&args).unwrap_err();

        assert!(error.to_string().contains("artifact SHA-256 mismatch"));
        assert!(!output.exists());
    }
}
