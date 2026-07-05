use crate::fsck::FsckResult;
use crate::fuzz::OutcomeKind;
use crate::image::Image;
use crate::kernel_replay::{KernelReplayOutcome, KernelReplayReport};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleDetail {
    pub name: String,
    pub kind: String,
    pub left: String,
    pub right: String,
    pub field: Option<String>,
    pub left_value: Option<String>,
    pub right_value: Option<String>,
    pub verdict: String,
    pub disagrees: bool,
    pub summary: String,
}

impl OracleDetail {
    fn new(
        name: impl Into<String>,
        kind: &'static str,
        left: &'static str,
        right: &'static str,
        field: Option<String>,
        verdict: &'static str,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kind: kind.to_string(),
            left: left.to_string(),
            right: right.to_string(),
            field,
            left_value: None,
            right_value: None,
            verdict: verdict.to_string(),
            disagrees: verdict == "disagree",
            summary: summary.into(),
        }
    }

    fn with_values(
        mut self,
        left_value: impl Into<String>,
        right_value: impl Into<String>,
    ) -> Self {
        self.left_value = Some(left_value.into());
        self.right_value = Some(right_value.into());
        self
    }
}

pub fn detail_disagreement_count(details: &[OracleDetail]) -> usize {
    details.iter().filter(|detail| detail.disagrees).count()
}

pub fn parser_vs_dump_details(
    image: &Image,
    dump_result: Option<&FsckResult>,
) -> Vec<OracleDetail> {
    let Some(dump_result) = dump_result else {
        return Vec::new();
    };
    if dump_result.timed_out || dump_result.classification != "accepted" {
        return vec![OracleDetail::new(
            "parser_vs_dump_fields",
            "field_diff",
            "rust_tolerant_parser",
            "dump",
            Some("superblock".to_string()),
            "skipped",
            format!(
                "dump output was not accepted for field comparison: {}",
                dump_result.reason
            ),
        )];
    }

    let Ok(rust_fields) = rust_superblock_fields(image) else {
        return vec![OracleDetail::new(
            "parser_vs_dump_fields",
            "field_diff",
            "rust_tolerant_parser",
            "dump",
            Some("superblock".to_string()),
            "skipped",
            "Rust parser could not decode superblock fields",
        )];
    };
    let dump_fields = dump_superblock_fields(&dump_result.stdout);
    if dump_fields.is_empty() {
        return vec![OracleDetail::new(
            "parser_vs_dump_fields",
            "field_diff",
            "rust_tolerant_parser",
            "dump",
            Some("superblock".to_string()),
            "skipped",
            "dump output did not contain comparable superblock fields",
        )];
    }

    let mut comparable = 0usize;
    let mut details = Vec::new();
    for (field, rust_value) in &rust_fields {
        let Some(dump_value) = dump_fields.get(field) else {
            continue;
        };
        comparable += 1;
        if rust_value != dump_value {
            details.push(
                OracleDetail::new(
                    format!("parser_vs_dump_field_{field}"),
                    "field_diff",
                    "rust_tolerant_parser",
                    "dump",
                    Some(field.clone()),
                    "disagree",
                    format!("field {field} differs between Rust parser and dump.erofs"),
                )
                .with_values(rust_value.clone(), dump_value.clone()),
            );
        }
    }

    if !details.is_empty() {
        return details;
    }
    if comparable == 0 {
        return vec![OracleDetail::new(
            "parser_vs_dump_fields",
            "field_diff",
            "rust_tolerant_parser",
            "dump",
            Some("superblock".to_string()),
            "skipped",
            "dump output and Rust parser had no overlapping comparable fields",
        )];
    }
    vec![
        OracleDetail::new(
            "parser_vs_dump_fields",
            "field_diff",
            "rust_tolerant_parser",
            "dump",
            Some("superblock".to_string()),
            "agree",
            format!("{comparable} comparable superblock field(s) matched"),
        )
        .with_values(
            format!("{comparable} field(s)"),
            format!("{comparable} field(s)"),
        ),
    ]
}

pub fn fsck_vs_kernel_details(
    fsck_result: &FsckResult,
    kernel_report: Option<&KernelReplayReport>,
) -> Vec<OracleDetail> {
    let Some(kernel_report) = kernel_report else {
        return Vec::new();
    };
    let fsck_behavior = fsck_behavior(fsck_result);
    let kernel_behavior = kernel_behavior(kernel_report);
    let verdict = if fsck_behavior == kernel_behavior {
        "agree"
    } else {
        "disagree"
    };
    vec![
        OracleDetail::new(
            "fsck_vs_kernel_behavior",
            "behavior_diff",
            "fsck",
            "kernel_replay",
            Some("behavior".to_string()),
            verdict,
            format!("fsck behavior {fsck_behavior} vs kernel behavior {kernel_behavior}"),
        )
        .with_values(fsck_behavior, kernel_behavior),
    ]
}

fn rust_superblock_fields(image: &Image) -> anyhow::Result<BTreeMap<String, String>> {
    let sb = image.superblock()?;
    let mut fields = BTreeMap::new();
    fields.insert("magic".to_string(), format!("0x{:08X}", sb.magic));
    fields.insert("block_size".to_string(), sb.block_size.to_string());
    fields.insert("blocks".to_string(), sb.blocks_lo.to_string());
    fields.insert("meta_blkaddr".to_string(), sb.meta_blkaddr.to_string());
    fields.insert("xattr_blkaddr".to_string(), sb.xattr_blkaddr.to_string());
    fields.insert("rootnid".to_string(), sb.rootnid.to_string());
    fields.insert("sb_size".to_string(), sb.sb_size.to_string());
    fields.insert("inos".to_string(), sb.inos.to_string());
    Ok(fields)
}

fn dump_superblock_fields(output: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for line in output.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let Some(field) = dump_field_name(label.trim()) else {
            continue;
        };
        let Some(value) = normalize_dump_value(field, value.trim()) else {
            continue;
        };
        fields.insert(field.to_string(), value);
    }
    fields
}

fn dump_field_name(label: &str) -> Option<&'static str> {
    match label {
        "Filesystem magic number" => Some("magic"),
        "Filesystem blocksize" => Some("block_size"),
        "Filesystem blocks" => Some("blocks"),
        "Filesystem inode metadata start block" => Some("meta_blkaddr"),
        "Filesystem shared xattr metadata start block" => Some("xattr_blkaddr"),
        "Filesystem root nid" => Some("rootnid"),
        "Filesystem sb_size" => Some("sb_size"),
        "Filesystem inode count" => Some("inos"),
        _ => None,
    }
}

fn normalize_dump_value(field: &str, value: &str) -> Option<String> {
    let first = value.split_whitespace().next()?;
    let number = if let Some(hex) = first
        .strip_prefix("0x")
        .or_else(|| first.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        first.parse::<u64>().ok()?
    };
    if field == "magic" {
        Some(format!("0x{number:08X}"))
    } else {
        Some(number.to_string())
    }
}

fn fsck_behavior(result: &FsckResult) -> &'static str {
    if result.timed_out || result.classification == "rejected_timeout" {
        return "timeout";
    }
    match OutcomeKind::from_classification(&result.classification) {
        OutcomeKind::NormalAccept => "accepted",
        OutcomeKind::ExpectedReject => "rejected",
        OutcomeKind::InterestingSemantic => "interesting",
        OutcomeKind::UnsafeCrash => "unsafe",
        OutcomeKind::UnsafeTimeout => "timeout",
        OutcomeKind::ToolingError => "unknown",
    }
}

fn kernel_behavior(report: &KernelReplayReport) -> &'static str {
    match report.outcome {
        KernelReplayOutcome::Accepted => "accepted",
        KernelReplayOutcome::Rejected => "rejected",
        KernelReplayOutcome::Unsafe => "unsafe",
        KernelReplayOutcome::Timeout => "timeout",
        KernelReplayOutcome::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{fsck_vs_kernel_details, parser_vs_dump_details};
    use crate::fsck::FsckResult;
    use crate::image::Image;
    use crate::kernel_replay::{KernelReplayOutcome, KernelReplayReport};

    #[test]
    fn parser_vs_dump_details_detects_field_mismatch() {
        let mut data = vec![0u8; 4096];
        let sb = 1024;
        data[sb..sb + 4].copy_from_slice(&0xE0F5E1E2u32.to_le_bytes());
        data[sb + 0x0C] = 12;
        data[sb + 0x0E..sb + 0x10].copy_from_slice(&36u16.to_le_bytes());
        data[sb + 0x10..sb + 0x18].copy_from_slice(&2u64.to_le_bytes());
        data[sb + 0x24..sb + 0x28].copy_from_slice(&1u32.to_le_bytes());
        let image = Image::new(data);
        let dump = FsckResult {
            classification: "accepted".to_string(),
            stdout: "Filesystem blocksize: 1024\nFilesystem inode count: 2\n".to_string(),
            ..FsckResult::default()
        };

        let details = parser_vs_dump_details(&image, Some(&dump));

        assert_eq!(details.len(), 1);
        assert_eq!(details[0].name, "parser_vs_dump_field_block_size");
        assert!(details[0].disagrees);
        assert_eq!(details[0].left_value.as_deref(), Some("4096"));
        assert_eq!(details[0].right_value.as_deref(), Some("1024"));
    }

    #[test]
    fn fsck_vs_kernel_details_detects_behavior_mismatch() {
        let fsck = FsckResult {
            classification: "rejected_invalid".to_string(),
            reason: "invalid image".to_string(),
            ..FsckResult::default()
        };
        let kernel = KernelReplayReport {
            schema: crate::kernel_replay::KERNEL_REPLAY_REPORT_SCHEMA.to_string(),
            artifact_sha256: None,
            kernel_git: None,
            qemu_exit_code: 0,
            outcome: KernelReplayOutcome::Unsafe,
            message: "dangerous kernel output matched BUG".to_string(),
            signature: "kernel_unsafe: BUG: test".to_string(),
            dangerous_pattern: Some("BUG:".to_string()),
        };

        let details = fsck_vs_kernel_details(&fsck, Some(&kernel));

        assert_eq!(details.len(), 1);
        assert_eq!(details[0].name, "fsck_vs_kernel_behavior");
        assert_eq!(details[0].left_value.as_deref(), Some("rejected"));
        assert_eq!(details[0].right_value.as_deref(), Some("unsafe"));
        assert!(details[0].disagrees);
    }
}
