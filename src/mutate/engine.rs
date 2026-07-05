use super::fields::Z_EROFS_FRAGMENT_INODE_MASK;
use crate::checksum::fix_checksum;
use crate::cli::MutateArgs;
use crate::fsck::{ExecLimits, run_fsck_with_limits};
use crate::image::{FieldWidth, Image, write_image};
use crate::parse::{ParseMode, parse_image};
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

pub(super) struct MutatedEntry {
    pub(super) output_name: String,
    pub(super) family: String,
    pub(super) target_desc: String,
    pub(super) field_name: String,
    pub(super) mutation_name: String,
    pub(super) value_hex: String,
    pub(super) parser_outcome: String,
    pub(super) classification: String,
    pub(super) reason: String,
}

pub(super) struct CrossFieldMutation {
    pub(super) output_name: String,
    pub(super) target_desc: String,
    pub(super) field_name: &'static str,
    pub(super) mutation_name: &'static str,
    pub(super) abs_offset: usize,
    pub(super) width: FieldWidth,
    pub(super) new_value: u64,
}

#[derive(Clone, Copy)]
pub(super) struct FieldWrite {
    pub(super) abs_offset: usize,
    pub(super) width: FieldWidth,
    pub(super) value: u64,
}

pub(super) struct XattrMutation {
    pub(super) output_name: String,
    pub(super) target_desc: String,
    pub(super) field_name: &'static str,
    pub(super) mutation_name: &'static str,
    pub(super) value_width: FieldWidth,
    pub(super) value: u64,
    pub(super) writes: Vec<FieldWrite>,
}

pub(super) struct ChunkMutation {
    pub(super) output_name: String,
    pub(super) target_desc: String,
    pub(super) field_name: &'static str,
    pub(super) mutation_name: &'static str,
    pub(super) value_width: FieldWidth,
    pub(super) value: u64,
    pub(super) writes: Vec<FieldWrite>,
}

pub(super) struct CompressionMutation {
    pub(super) output_name: String,
    pub(super) target_desc: String,
    pub(super) field_name: &'static str,
    pub(super) mutation_name: &'static str,
    pub(super) value_width: FieldWidth,
    pub(super) value: u64,
    pub(super) writes: Vec<FieldWrite>,
}

pub(super) struct FragmentMutation {
    pub(super) output_name: String,
    pub(super) target_desc: String,
    pub(super) field_name: &'static str,
    pub(super) mutation_name: &'static str,
    pub(super) value_width: FieldWidth,
    pub(super) value: u64,
    pub(super) writes: Vec<FieldWrite>,
}

pub(super) struct DeviceMutation {
    pub(super) output_name: String,
    pub(super) target_desc: String,
    pub(super) field_name: &'static str,
    pub(super) mutation_name: &'static str,
    pub(super) value_width: FieldWidth,
    pub(super) value: u64,
    pub(super) writes: Vec<FieldWrite>,
}

pub(super) fn seed_name(input: &str) -> String {
    Path::new(input)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "seed".to_string())
}

pub(super) fn sha256_hex(image: &Image) -> String {
    let mut hasher = Sha256::new();
    hasher.update(image.as_bytes());
    hex::encode(hasher.finalize())
}

pub(super) fn round_up_for_mutation(value: usize, align: usize) -> Result<usize> {
    if align == 0 || !align.is_power_of_two() {
        bail!("invalid alignment {align}");
    }
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
        .ok_or_else(|| anyhow::anyhow!("round_up({value}, {align}) overflows"))
}

pub(super) fn packed_fragment_writes(
    inode_offset: usize,
    i_xattr_offset: usize,
    map_offset: usize,
    compact_layout: u64,
) -> Vec<FieldWrite> {
    vec![
        FieldWrite {
            abs_offset: inode_offset,
            width: FieldWidth::U16,
            value: compact_layout,
        },
        FieldWrite {
            abs_offset: i_xattr_offset,
            width: FieldWidth::U16,
            value: 0,
        },
        FieldWrite {
            abs_offset: map_offset,
            width: FieldWidth::U64,
            value: Z_EROFS_FRAGMENT_INODE_MASK,
        },
    ]
}

pub(super) fn parser_outcome(image: &Image) -> String {
    let strict_accepted = parse_image(image, ParseMode::Strict).is_ok();
    match parse_image(image, ParseMode::FuzzTolerant) {
        Ok(report) => match (strict_accepted, report.errors.is_empty()) {
            (true, true) => "strict_accepted_tolerant_clean",
            (true, false) => "strict_accepted_tolerant_errors",
            (false, true) => "strict_rejected_tolerant_clean",
            (false, false) => "strict_rejected_tolerant_errors",
        }
        .to_string(),
        Err(_) if strict_accepted => "strict_accepted_tolerant_failed".to_string(),
        Err(_) => "strict_rejected_tolerant_failed".to_string(),
    }
}

fn fsck_limits(args: &MutateArgs) -> ExecLimits {
    ExecLimits {
        timeout: Duration::from_secs(args.exec_timeout),
        max_output_bytes: args.max_output_bytes,
        kill_process_group: !args.no_kill_process_group,
        rss_limit_mb: args.rss_limit_mb,
    }
}

pub(super) fn classify_mutated_image(
    args: &MutateArgs,
    output_path: &Path,
) -> Result<(String, String)> {
    let result = run_fsck_with_limits(&args.fsck, output_path, &[], fsck_limits(args))?;
    Ok((result.classification, result.reason))
}

pub(super) fn add_cross_field_mutation(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    mutation: CrossFieldMutation,
) -> Result<bool> {
    let original_value = image.read_field(mutation.abs_offset, mutation.width)?;
    if original_value == mutation.new_value {
        return Ok(false);
    }

    let mut mutated = image.clone();
    mutated.write_field(mutation.abs_offset, mutation.width, mutation.new_value)?;

    if args.fix_checksum {
        fix_checksum(&mut mutated)?;
    }

    let output_path = Path::new(&args.output_dir).join(&mutation.output_name);
    write_image(&output_path, &mutated)?;

    let (classification, reason) = classify_mutated_image(args, &output_path)?;
    let parser_outcome = parser_outcome(&mutated);

    entries.push(MutatedEntry {
        output_name: mutation.output_name,
        family: "cross".to_string(),
        target_desc: mutation.target_desc,
        field_name: mutation.field_name.to_string(),
        mutation_name: mutation.mutation_name.to_string(),
        value_hex: format!(
            "0x{:0width$X}",
            mutation.new_value,
            width = mutation.width.bytes() * 2
        ),
        parser_outcome,
        classification: classification.to_string(),
        reason: reason.to_string(),
    });

    println!(
        "[{classification:>20}] {:>15}.{:<25} -> {reason}",
        mutation.field_name, mutation.mutation_name
    );

    Ok(true)
}

pub(super) fn add_chunk_mutation(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    mutation: ChunkMutation,
) -> Result<bool> {
    let mut changed = false;
    for write in &mutation.writes {
        if image.read_field(write.abs_offset, write.width)? != write.value {
            changed = true;
            break;
        }
    }
    if !changed {
        return Ok(false);
    }

    let mut mutated = image.clone();
    for write in &mutation.writes {
        mutated.write_field(write.abs_offset, write.width, write.value)?;
    }

    if args.fix_checksum {
        fix_checksum(&mut mutated)?;
    }

    let output_path = Path::new(&args.output_dir).join(&mutation.output_name);
    write_image(&output_path, &mutated)?;

    let (classification, reason) = classify_mutated_image(args, &output_path)?;
    let parser_outcome = parser_outcome(&mutated);

    entries.push(MutatedEntry {
        output_name: mutation.output_name,
        family: "chunk".to_string(),
        target_desc: mutation.target_desc,
        field_name: mutation.field_name.to_string(),
        mutation_name: mutation.mutation_name.to_string(),
        value_hex: format!(
            "0x{:0width$X}",
            mutation.value,
            width = mutation.value_width.bytes() * 2
        ),
        parser_outcome,
        classification: classification.to_string(),
        reason: reason.to_string(),
    });

    println!(
        "[{classification:>20}] {:>15}.{:<25} -> {reason}",
        mutation.field_name, mutation.mutation_name
    );

    Ok(true)
}

pub(super) fn add_xattr_mutation(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    mutation: XattrMutation,
) -> Result<bool> {
    let mut changed = false;
    for write in &mutation.writes {
        if image.read_field(write.abs_offset, write.width)? != write.value {
            changed = true;
            break;
        }
    }
    if !changed {
        return Ok(false);
    }

    let mut mutated = image.clone();
    for write in &mutation.writes {
        mutated.write_field(write.abs_offset, write.width, write.value)?;
    }

    if args.fix_checksum {
        fix_checksum(&mut mutated)?;
    }

    let output_path = Path::new(&args.output_dir).join(&mutation.output_name);
    write_image(&output_path, &mutated)?;

    let (classification, reason) = classify_mutated_image(args, &output_path)?;
    let parser_outcome = parser_outcome(&mutated);

    entries.push(MutatedEntry {
        output_name: mutation.output_name,
        family: "xattr".to_string(),
        target_desc: mutation.target_desc,
        field_name: mutation.field_name.to_string(),
        mutation_name: mutation.mutation_name.to_string(),
        value_hex: format!(
            "0x{:0width$X}",
            mutation.value,
            width = mutation.value_width.bytes() * 2
        ),
        parser_outcome,
        classification: classification.to_string(),
        reason: reason.to_string(),
    });

    println!(
        "[{classification:>20}] {:>15}.{:<25} -> {reason}",
        mutation.field_name, mutation.mutation_name
    );

    Ok(true)
}

pub(super) fn add_compression_mutation(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    mutation: CompressionMutation,
) -> Result<bool> {
    let mut changed = false;
    for write in &mutation.writes {
        if image.read_field(write.abs_offset, write.width)? != write.value {
            changed = true;
            break;
        }
    }
    if !changed {
        return Ok(false);
    }

    let mut mutated = image.clone();
    for write in &mutation.writes {
        mutated.write_field(write.abs_offset, write.width, write.value)?;
    }

    if args.fix_checksum {
        fix_checksum(&mut mutated)?;
    }

    let output_path = Path::new(&args.output_dir).join(&mutation.output_name);
    write_image(&output_path, &mutated)?;

    let (classification, reason) = classify_mutated_image(args, &output_path)?;
    let parser_outcome = parser_outcome(&mutated);

    entries.push(MutatedEntry {
        output_name: mutation.output_name,
        family: "compression".to_string(),
        target_desc: mutation.target_desc,
        field_name: mutation.field_name.to_string(),
        mutation_name: mutation.mutation_name.to_string(),
        value_hex: format!(
            "0x{:0width$X}",
            mutation.value,
            width = mutation.value_width.bytes() * 2
        ),
        parser_outcome,
        classification: classification.to_string(),
        reason: reason.to_string(),
    });

    println!(
        "[{classification:>20}] {:>15}.{:<25} -> {reason}",
        mutation.field_name, mutation.mutation_name
    );

    Ok(true)
}

pub(super) fn add_fragment_mutation(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    mutation: FragmentMutation,
) -> Result<bool> {
    let mut changed = false;
    for write in &mutation.writes {
        if image.read_field(write.abs_offset, write.width)? != write.value {
            changed = true;
            break;
        }
    }
    if !changed {
        return Ok(false);
    }

    let mut mutated = image.clone();
    for write in &mutation.writes {
        mutated.write_field(write.abs_offset, write.width, write.value)?;
    }

    if args.fix_checksum {
        fix_checksum(&mut mutated)?;
    }

    let output_path = Path::new(&args.output_dir).join(&mutation.output_name);
    write_image(&output_path, &mutated)?;

    let (classification, reason) = classify_mutated_image(args, &output_path)?;
    let parser_outcome = parser_outcome(&mutated);

    entries.push(MutatedEntry {
        output_name: mutation.output_name,
        family: "fragment".to_string(),
        target_desc: mutation.target_desc,
        field_name: mutation.field_name.to_string(),
        mutation_name: mutation.mutation_name.to_string(),
        value_hex: format!(
            "0x{:0width$X}",
            mutation.value,
            width = mutation.value_width.bytes() * 2
        ),
        parser_outcome,
        classification: classification.to_string(),
        reason: reason.to_string(),
    });

    println!(
        "[{classification:>20}] {:>15}.{:<25} -> {reason}",
        mutation.field_name, mutation.mutation_name
    );

    Ok(true)
}

pub(super) fn add_device_mutation(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    mutation: DeviceMutation,
) -> Result<bool> {
    let mut changed = false;
    for write in &mutation.writes {
        if image.read_field(write.abs_offset, write.width)? != write.value {
            changed = true;
            break;
        }
    }
    if !changed {
        return Ok(false);
    }

    let mut mutated = image.clone();
    for write in &mutation.writes {
        mutated.write_field(write.abs_offset, write.width, write.value)?;
    }

    if args.fix_checksum {
        fix_checksum(&mut mutated)?;
    }

    let output_path = Path::new(&args.output_dir).join(&mutation.output_name);
    write_image(&output_path, &mutated)?;

    let (classification, reason) = classify_mutated_image(args, &output_path)?;
    let parser_outcome = parser_outcome(&mutated);

    entries.push(MutatedEntry {
        output_name: mutation.output_name,
        family: "device".to_string(),
        target_desc: mutation.target_desc,
        field_name: mutation.field_name.to_string(),
        mutation_name: mutation.mutation_name.to_string(),
        value_hex: format!(
            "0x{:0width$X}",
            mutation.value,
            width = mutation.value_width.bytes() * 2
        ),
        parser_outcome,
        classification: classification.to_string(),
        reason: reason.to_string(),
    });

    println!(
        "[{classification:>20}] {:>15}.{:<25} -> {reason}",
        mutation.field_name, mutation.mutation_name
    );

    Ok(true)
}
