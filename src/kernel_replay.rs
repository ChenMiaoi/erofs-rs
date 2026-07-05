use serde::{Deserialize, Serialize};

pub const KERNEL_REPLAY_REPORT_SCHEMA: &str = "erofs-rs.kernel-replay.v1";

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelReplayVerdict {
    pub outcome: KernelReplayOutcome,
    pub message: String,
    pub signature: String,
    pub dangerous_pattern: Option<String>,
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
        KERNEL_REPLAY_REPORT_SCHEMA, KernelReplayOutcome, build_kernel_replay_report,
        classify_dmesg_text,
    };

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
}
