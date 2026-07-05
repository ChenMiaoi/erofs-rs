use crate::checksum::fix_checksum;
use crate::cli::MutateArgs;
use crate::dirent::locate_dirents_in_image;
use crate::fsck::{classify_fsck_result, run_fsck};
use crate::image::{EROFS_SUPER_OFFSET, FieldWidth, Image, read_image, write_image};
use crate::inode::{inode_data_offset, is_directory_inode, is_extended_inode, locate_inodes};
use crate::parse::{ParseMode, parse_image};
use anyhow::{Result, bail};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const EROFS_FEATURE_INCOMPAT_48BIT: u32 = 0x00000080;

/// A single field mutation definition.
struct MutationDef {
    field_offset: usize,
    width: FieldWidth,
    field_name: &'static str,
    values: &'static [(u64, &'static str)],
}

/// Superblock mutation table.
const SUPERBLOCK_FIELDS: &[MutationDef] = &[
    MutationDef {
        field_offset: 0x00,
        width: FieldWidth::U32,
        field_name: "magic",
        values: &[
            (0x00000000, "zero"),
            (0xFFFFFFFF, "all_ones"),
            (0xE0F5E1E1, "off_by_one_low"),
            (0xE0F5E1E3, "off_by_one_high"),
            (0xE1F5E0E2, "byte_swap"),
            (0x12345678, "random"),
        ],
    },
    MutationDef {
        field_offset: 0x04,
        width: FieldWidth::U32,
        field_name: "checksum",
        values: &[
            (0x00000000, "zero"),
            (0xFFFFFFFF, "all_ones"),
            (0x12345678, "random"),
        ],
    },
    MutationDef {
        field_offset: 0x08,
        width: FieldWidth::U32,
        field_name: "feature_compat",
        values: &[
            (0x00000000, "clear_all"),
            (0xFFFFFFFF, "all_ones"),
            (0x00000004, "set_unknown_bit"),
            (0x00000010, "set_xattr_filter"),
        ],
    },
    MutationDef {
        field_offset: 0x0C,
        width: FieldWidth::U8,
        field_name: "blkszbits",
        values: &[
            (0x00, "zero"),
            (0x01, "one"),
            (0x0B, "2048_bytes"),
            (0x0D, "8192_bytes"),
            (0x1F, "max"),
            (0x20, "overflow"),
        ],
    },
    MutationDef {
        field_offset: 0x0D,
        width: FieldWidth::U8,
        field_name: "sb_extslots",
        values: &[(0x00, "zero"), (0x01, "one"), (0xFF, "max")],
    },
    MutationDef {
        field_offset: 0x0E,
        width: FieldWidth::U16,
        field_name: "rootnid",
        values: &[(0x0000, "zero"), (0x0001, "one"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x10,
        width: FieldWidth::U64,
        field_name: "inos",
        values: &[
            (0x0000000000000000, "zero"),
            (0xFFFFFFFFFFFFFFFF, "max"),
            (0x0000000000000001, "one_less"),
            (0x0000000000000003, "one_more"),
        ],
    },
    MutationDef {
        field_offset: 0x18,
        width: FieldWidth::U64,
        field_name: "epoch",
        values: &[
            (0x0000000000000000, "zero"),
            (0x0000000000000001, "one"),
            (0xFFFFFFFFFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x20,
        width: FieldWidth::U32,
        field_name: "fixed_nsec",
        values: &[
            (0x00000000, "zero"),
            (0x3B9AC9FF, "max_valid_nsec"),
            (0x3B9ACA00, "one_billion"),
            (0xFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x24,
        width: FieldWidth::U32,
        field_name: "blocks_lo",
        values: &[
            (0x00000000, "zero"),
            (0xFFFFFFFF, "max"),
            (0x00000002, "one_more"),
        ],
    },
    MutationDef {
        field_offset: 0x28,
        width: FieldWidth::U32,
        field_name: "meta_blkaddr",
        values: &[
            (0x00000000, "zero"),
            (0xFFFFFFFF, "max"),
            (0x00000001, "point_to_data"),
        ],
    },
    MutationDef {
        field_offset: 0x2C,
        width: FieldWidth::U32,
        field_name: "xattr_blkaddr",
        values: &[(0x00000001, "point_to_data"), (0xFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x30,
        width: FieldWidth::U64,
        field_name: "uuid_lo",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x38,
        width: FieldWidth::U64,
        field_name: "uuid_hi",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x40,
        width: FieldWidth::U64,
        field_name: "volume_name_lo",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x48,
        width: FieldWidth::U64,
        field_name: "volume_name_hi",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x50,
        width: FieldWidth::U32,
        field_name: "feature_incompat",
        values: &[
            (0x00000000, "clear_all"),
            (0x00000004, "chunked_file"),
            (0x00000008, "device_or_compr_head2"),
            (0x00000020, "fragments_or_dedupe"),
            (0x00000040, "xattr_prefixes"),
            (0x00000080, "48bit"),
            (0x00000100, "metabox"),
            (0x00000200, "unknown_bit"),
            (0xFFFFFFFF, "all_ones"),
        ],
    },
    MutationDef {
        field_offset: 0x54,
        width: FieldWidth::U16,
        field_name: "available_compr_algs",
        values: &[
            (0x0000, "zero"),
            (0x0001, "lz4"),
            (0x0002, "secondary"),
            (0xFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x56,
        width: FieldWidth::U16,
        field_name: "extra_devices",
        values: &[(0x0000, "zero"), (0x0001, "one"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x58,
        width: FieldWidth::U16,
        field_name: "devt_slotoff",
        values: &[(0x0000, "zero"), (0x0001, "one"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x5A,
        width: FieldWidth::U8,
        field_name: "dirblkbits",
        values: &[
            (0x00, "zero"),
            (0x01, "one"),
            (0x0C, "block_bits"),
            (0xFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x5B,
        width: FieldWidth::U8,
        field_name: "xattr_prefix_count",
        values: &[(0x00, "zero"), (0x01, "one"), (0xFF, "max")],
    },
    MutationDef {
        field_offset: 0x5C,
        width: FieldWidth::U32,
        field_name: "xattr_prefix_start",
        values: &[
            (0x00000000, "zero"),
            (0x00000001, "one"),
            (0xFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x60,
        width: FieldWidth::U64,
        field_name: "packed_nid",
        values: &[
            (0x0000000000000000, "zero"),
            (0x0000000000000001, "one"),
            (0xFFFFFFFFFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x68,
        width: FieldWidth::U8,
        field_name: "xattr_filter_reserved",
        values: &[(0x00, "zero"), (0x01, "one"), (0xFF, "max")],
    },
    MutationDef {
        field_offset: 0x69,
        width: FieldWidth::U8,
        field_name: "ishare_xattr_prefix_id",
        values: &[(0x00, "zero"), (0x01, "one"), (0xFF, "max")],
    },
    MutationDef {
        field_offset: 0x6A,
        width: FieldWidth::U16,
        field_name: "reserved",
        values: &[(0x0000, "zero"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x6C,
        width: FieldWidth::U32,
        field_name: "build_time",
        values: &[
            (0x00000000, "zero"),
            (0x00000001, "one"),
            (0xFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x70,
        width: FieldWidth::U64,
        field_name: "root_nid_8b",
        values: &[
            (0x0000000000000000, "zero"),
            (0x0000000000000001, "one"),
            (0xFFFFFFFFFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x78,
        width: FieldWidth::U64,
        field_name: "reserved2",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x80,
        width: FieldWidth::U64,
        field_name: "metabox_nid",
        values: &[
            (0x0000000000000000, "zero"),
            (0x0000000000000001, "one"),
            (0xFFFFFFFFFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x88,
        width: FieldWidth::U64,
        field_name: "reserved3",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
];

/// Inode mutation table.
const INODE_FIELDS: &[MutationDef] = &[
    MutationDef {
        field_offset: 0x00,
        width: FieldWidth::U16,
        field_name: "i_format",
        values: &[
            (0x0000, "version_compact_datalayout_plain"),
            (0x0001, "version_extended_datalayout_plain"),
            (0x0002, "version_compact_datalayout_compressed_full"),
            (0x0003, "version_extended_datalayout_compressed_full"),
            (0x0004, "version_compact_datalayout_flat_inline"),
            (0x0005, "version_extended_datalayout_flat_inline"),
            (0x0006, "version_compact_datalayout_compressed_compact"),
            (0x0007, "version_extended_datalayout_compressed_compact"),
            (0x0008, "version_compact_datalayout_chunk_based"),
            (0x0009, "version_extended_datalayout_chunk_based"),
            (0x0010, "nlink_1_bit_set"),
            (0x00FF, "all_ones"),
        ],
    },
    MutationDef {
        field_offset: 0x02,
        width: FieldWidth::U16,
        field_name: "i_xattr_icount",
        values: &[(0x0000, "zero"), (0x0001, "one"), (0x00FF, "max")],
    },
    MutationDef {
        field_offset: 0x04,
        width: FieldWidth::U16,
        field_name: "i_mode",
        values: &[
            (0x0000, "zero"),
            (0x1000, "fifo"),
            (0x2000, "chrdev"),
            (0x4000, "dir"),
            (0x6000, "blkdev"),
            (0x8000, "regular"),
            (0xA000, "symlink"),
            (0xC000, "socket"),
            (0x81A4, "reg_0644"),
            (0x41C0, "dir_0700"),
            (0xFFFF, "all_ones"),
        ],
    },
    MutationDef {
        field_offset: 0x06,
        width: FieldWidth::U16,
        field_name: "i_nb.nlink",
        values: &[(0x0000, "zero"), (0x0001, "one"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x08,
        width: FieldWidth::U32,
        field_name: "i_size",
        values: &[
            (0x00000000, "zero"),
            (0x00000001, "one"),
            (0xFFFFFFFF, "max"),
            (0x00001000, "one_block"),
            (0x00100000, "one_mb"),
        ],
    },
    MutationDef {
        field_offset: 0x0C,
        width: FieldWidth::U32,
        field_name: "i_mtime",
        values: &[(0x00000000, "zero"), (0xFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x10,
        width: FieldWidth::U32,
        field_name: "i_u.startblk_lo",
        values: &[
            (0x00000000, "zero"),
            (0x00000001, "block_1"),
            (0xFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x14,
        width: FieldWidth::U32,
        field_name: "i_ino",
        values: &[(0x00000000, "zero"), (0xFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x18,
        width: FieldWidth::U16,
        field_name: "i_uid",
        values: &[(0x0000, "zero"), (0x03E8, "original_1000"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x1A,
        width: FieldWidth::U16,
        field_name: "i_gid",
        values: &[(0x0000, "zero"), (0x03E8, "original_1000"), (0xFFFF, "max")],
    },
];

fn inode_field_location(field_name: &str, extended: bool) -> Option<(usize, FieldWidth)> {
    let location = match field_name {
        "i_format" => (0x00, FieldWidth::U16),
        "i_xattr_icount" => (0x02, FieldWidth::U16),
        "i_mode" => (0x04, FieldWidth::U16),
        "i_nb.nlink" if extended => (0x28, FieldWidth::U32),
        "i_nb.nlink" => (0x06, FieldWidth::U16),
        "i_size" if extended => (0x08, FieldWidth::U64),
        "i_size" => (0x08, FieldWidth::U32),
        "i_mtime" if extended => (0x20, FieldWidth::U64),
        "i_mtime" => (0x0C, FieldWidth::U32),
        "i_u.startblk_lo" => (0x10, FieldWidth::U32),
        "i_ino" => (0x14, FieldWidth::U32),
        "i_uid" if extended => (0x18, FieldWidth::U32),
        "i_uid" => (0x18, FieldWidth::U16),
        "i_gid" if extended => (0x1C, FieldWidth::U32),
        "i_gid" => (0x1A, FieldWidth::U16),
        _ => return None,
    };
    Some(location)
}

/// Directory entry mutation table.
const DIRENT_FIELDS: &[MutationDef] = &[
    MutationDef {
        field_offset: 0x00,
        width: FieldWidth::U64,
        field_name: "nid",
        values: &[
            (0x0000000000000000, "zero"),
            (0x0000000000000001, "one"),
            (0x00000000000000FF, "small"),
            (0xFFFFFFFFFFFFFFFF, "max"),
            (0x0000000000000024, "self_ref"),
        ],
    },
    MutationDef {
        field_offset: 0x08,
        width: FieldWidth::U16,
        field_name: "nameoff",
        values: &[
            (0x0000, "zero"),
            (0x0001, "one"),
            (0x00FF, "max_byte"),
            (0x0FFF, "max_4k"),
            (0xFFFF, "max"),
            (0x0028, "point_to_inode"),
            (0x1000, "beyond_block"),
        ],
    },
    MutationDef {
        field_offset: 0x0A,
        width: FieldWidth::U8,
        field_name: "file_type",
        values: &[
            (0x00, "unknown"),
            (0x01, "reg_file"),
            (0x02, "dir"),
            (0x03, "chrdev"),
            (0x04, "blkdev"),
            (0x05, "fifo"),
            (0x06, "sock"),
            (0x07, "symlink"),
            (0x08, "invalid_8"),
            (0x0F, "invalid_15"),
            (0xFF, "invalid_max"),
        ],
    },
    MutationDef {
        field_offset: 0x0B,
        width: FieldWidth::U8,
        field_name: "reserved",
        values: &[(0x00, "zero"), (0xFF, "max")],
    },
];

struct MutatedEntry {
    output_name: String,
    family: String,
    target_desc: String,
    field_name: String,
    mutation_name: String,
    value_hex: String,
    parser_outcome: String,
    classification: String,
    reason: String,
}

struct CrossFieldMutation {
    output_name: String,
    target_desc: String,
    field_name: &'static str,
    mutation_name: &'static str,
    abs_offset: usize,
    width: FieldWidth,
    new_value: u64,
}

#[derive(Clone, Copy)]
struct FieldWrite {
    abs_offset: usize,
    width: FieldWidth,
    value: u64,
}

struct XattrMutation {
    output_name: String,
    target_desc: String,
    field_name: &'static str,
    mutation_name: &'static str,
    value_width: FieldWidth,
    value: u64,
    writes: Vec<FieldWrite>,
}

fn seed_name(input: &str) -> String {
    Path::new(input)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "seed".to_string())
}

fn parser_outcome(image: &Image) -> String {
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

fn add_cross_field_mutation(
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

    let result = run_fsck(&args.fsck, &output_path, &[])?;
    let (classification, reason) =
        classify_fsck_result(result.exit_code, &result.stderr, &result.stdout);
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

fn add_xattr_mutation(
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

    let result = run_fsck(&args.fsck, &output_path, &[])?;
    let (classification, reason) =
        classify_fsck_result(result.exit_code, &result.stderr, &result.stdout);
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

fn mutate_superblock(image: &Image, args: &MutateArgs) -> Result<Vec<MutatedEntry>> {
    let seed = seed_name(&args.input);
    let mut entries = Vec::new();

    for def in SUPERBLOCK_FIELDS {
        let abs_offset = EROFS_SUPER_OFFSET
            .checked_add(def.field_offset)
            .ok_or_else(|| anyhow::anyhow!("superblock field offset overflows"))?;
        let original_value = image.read_field(abs_offset, def.width)?;
        for (new_value, mutation_name) in def.values {
            if *new_value == original_value {
                continue;
            }
            let mut mutated = image.clone();
            mutated.write_field(abs_offset, def.width, *new_value)?;

            if args.fix_checksum && def.field_name != "checksum" {
                fix_checksum(&mut mutated)?;
            }

            let output_name = format!("{seed}_sb_{}_{mutation_name}.erofs", def.field_name);
            let output_path = Path::new(&args.output_dir).join(&output_name);
            write_image(&output_path, &mutated)?;

            let result = run_fsck(&args.fsck, &output_path, &[])?;
            let (classification, reason) =
                classify_fsck_result(result.exit_code, &result.stderr, &result.stdout);
            let parser_outcome = parser_outcome(&mutated);

            entries.push(MutatedEntry {
                output_name,
                family: "superblock".to_string(),
                target_desc: "superblock".to_string(),
                field_name: def.field_name.to_string(),
                mutation_name: mutation_name.to_string(),
                value_hex: format!("0x{new_value:0width$X}", width = def.width.bytes() * 2),
                parser_outcome,
                classification: classification.to_string(),
                reason: reason.to_string(),
            });

            println!(
                "[{classification:>20}] {:>15}.{mutation_name:<20} -> {reason}",
                def.field_name
            );
        }
    }

    Ok(entries)
}

fn mutate_inodes(image: &Image, args: &MutateArgs) -> Result<Vec<MutatedEntry>> {
    let seed = seed_name(&args.input);
    let sb = image.superblock()?;
    let inodes = locate_inodes(image, &sb)?;
    println!(
        "Superblock: magic=0x{:08X}, blkszbits={}, meta_offset=0x{:X}, rootnid={}",
        sb.magic, sb.blkszbits, sb.meta_offset, sb.rootnid
    );
    println!("Found {} inodes", inodes.len());

    let mut entries = Vec::new();

    for inode in &inodes {
        let extended = is_extended_inode(image, inode.offset)?;
        for def in INODE_FIELDS {
            let (rel_offset, width) = inode_field_location(def.field_name, extended)
                .ok_or_else(|| anyhow::anyhow!("unsupported inode field {}", def.field_name))?;
            let abs_offset = inode
                .offset
                .checked_add(rel_offset)
                .ok_or_else(|| anyhow::anyhow!("inode field offset overflows"))?;
            let original_value = image.read_field(abs_offset, width)?;
            for (new_value, mutation_name) in def.values {
                if *new_value == original_value {
                    continue;
                }
                let mut mutated = image.clone();
                mutated.write_field(abs_offset, width, *new_value)?;

                if args.fix_checksum {
                    fix_checksum(&mut mutated)?;
                }

                let output_name = format!(
                    "{seed}_nid{}_{}_{mutation_name}.erofs",
                    inode.nid, def.field_name
                );
                let output_path = Path::new(&args.output_dir).join(&output_name);
                write_image(&output_path, &mutated)?;

                let result = run_fsck(&args.fsck, &output_path, &[])?;
                let (classification, reason) =
                    classify_fsck_result(result.exit_code, &result.stderr, &result.stdout);
                let parser_outcome = parser_outcome(&mutated);

                entries.push(MutatedEntry {
                    output_name,
                    family: "inode".to_string(),
                    target_desc: inode.desc.clone(),
                    field_name: def.field_name.to_string(),
                    mutation_name: mutation_name.to_string(),
                    value_hex: format!("0x{new_value:0width$X}", width = width.bytes() * 2),
                    parser_outcome,
                    classification: classification.to_string(),
                    reason: reason.to_string(),
                });

                println!(
                    "[{classification:>20}] nid={:>3} {:>15}.{mutation_name:<25} -> {reason}",
                    inode.nid, def.field_name
                );
            }
        }
    }

    Ok(entries)
}

fn mutate_dirents(image: &Image, args: &MutateArgs) -> Result<Vec<MutatedEntry>> {
    let seed = seed_name(&args.input);
    let sb = image.superblock()?;
    let inodes = locate_inodes(image, &sb)?;
    let dirents = locate_dirents_in_image(image, &sb, &inodes)?;
    println!(
        "Found {} inodes, {} directory entries",
        inodes.len(),
        dirents.len()
    );

    if dirents.is_empty() {
        println!("WARNING: No directory entries found. Skipping.");
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();

    for dirent in &dirents {
        for def in DIRENT_FIELDS {
            let abs_offset = dirent
                .offset
                .checked_add(def.field_offset)
                .ok_or_else(|| anyhow::anyhow!("dirent field offset overflows"))?;
            let original_value = image.read_field(abs_offset, def.width)?;
            for (new_value, mutation_name) in def.values {
                if *new_value == original_value {
                    continue;
                }
                let mut mutated = image.clone();
                mutated.write_field(abs_offset, def.width, *new_value)?;

                if args.fix_checksum {
                    fix_checksum(&mut mutated)?;
                }

                let output_name = format!(
                    "{seed}_nid{}_dirent{}_{}_{mutation_name}.erofs",
                    dirent.parent_nid, dirent.entry_idx, def.field_name
                );
                let output_path = Path::new(&args.output_dir).join(&output_name);
                write_image(&output_path, &mutated)?;

                let result = run_fsck(&args.fsck, &output_path, &[])?;
                let (classification, reason) =
                    classify_fsck_result(result.exit_code, &result.stderr, &result.stdout);
                let parser_outcome = parser_outcome(&mutated);

                entries.push(MutatedEntry {
                    output_name,
                    family: "dirent".to_string(),
                    target_desc: dirent.desc.clone(),
                    field_name: def.field_name.to_string(),
                    mutation_name: mutation_name.to_string(),
                    value_hex: format!("0x{new_value:0width$X}", width = def.width.bytes() * 2),
                    parser_outcome,
                    classification: classification.to_string(),
                    reason: reason.to_string(),
                });

                println!(
                    "[{classification:>20}] {:>10} {:>10}.{mutation_name:<20} -> {reason}",
                    dirent.desc, def.field_name
                );
            }
        }
    }

    Ok(entries)
}

fn mutate_xattrs(image: &Image, args: &MutateArgs) -> Result<Vec<MutatedEntry>> {
    let seed = seed_name(&args.input);
    let sb = image.superblock()?;
    let inodes = locate_inodes(image, &sb)?;
    let mut entries = Vec::new();

    println!("Found {} inodes for xattr mutations", inodes.len());

    for inode in &inodes {
        let inode_size = if is_extended_inode(image, inode.offset)? {
            64usize
        } else {
            32usize
        };
        let i_xattr_offset = inode
            .offset
            .checked_add(0x02)
            .ok_or_else(|| anyhow::anyhow!("inode xattr count offset overflows"))?;
        let xattr_offset = inode
            .offset
            .checked_add(inode_size)
            .ok_or_else(|| anyhow::anyhow!("inline xattr header offset overflows"))?;
        if xattr_offset
            .checked_add(12)
            .is_none_or(|end| end > image.len())
        {
            continue;
        }

        let header_writes = vec![FieldWrite {
            abs_offset: i_xattr_offset,
            width: FieldWidth::U16,
            value: 1,
        }];
        let _ = add_xattr_mutation(
            &mut entries,
            image,
            args,
            XattrMutation {
                output_name: format!("{seed}_nid{}_xattr_advertise_header.erofs", inode.nid),
                target_desc: inode.desc.clone(),
                field_name: "i_xattr_icount",
                mutation_name: "advertise_header",
                value_width: FieldWidth::U16,
                value: 1,
                writes: header_writes,
            },
        )?;

        let shared_slot_writes = vec![FieldWrite {
            abs_offset: i_xattr_offset,
            width: FieldWidth::U16,
            value: 2,
        }];
        let _ = add_xattr_mutation(
            &mut entries,
            image,
            args,
            XattrMutation {
                output_name: format!("{seed}_nid{}_xattr_advertise_shared_slot.erofs", inode.nid),
                target_desc: inode.desc.clone(),
                field_name: "i_xattr_icount",
                mutation_name: "advertise_shared_slot",
                value_width: FieldWidth::U16,
                value: 2,
                writes: shared_slot_writes,
            },
        )?;

        let shared_count_offset = xattr_offset
            .checked_add(0x04)
            .ok_or_else(|| anyhow::anyhow!("inline xattr shared count offset overflows"))?;
        let shared_count_writes = vec![
            FieldWrite {
                abs_offset: i_xattr_offset,
                width: FieldWidth::U16,
                value: 1,
            },
            FieldWrite {
                abs_offset: shared_count_offset,
                width: FieldWidth::U8,
                value: 1,
            },
        ];
        let _ = add_xattr_mutation(
            &mut entries,
            image,
            args,
            XattrMutation {
                output_name: format!("{seed}_nid{}_xattr_shared_count_exceeds.erofs", inode.nid),
                target_desc: inode.desc.clone(),
                field_name: "h_shared_count",
                mutation_name: "shared_count_exceeds_region",
                value_width: FieldWidth::U8,
                value: 1,
                writes: shared_count_writes,
            },
        )?;

        let reserved_offset = xattr_offset
            .checked_add(0x05)
            .ok_or_else(|| anyhow::anyhow!("inline xattr reserved offset overflows"))?;
        let reserved_writes = vec![
            FieldWrite {
                abs_offset: i_xattr_offset,
                width: FieldWidth::U16,
                value: 1,
            },
            FieldWrite {
                abs_offset: reserved_offset,
                width: FieldWidth::U8,
                value: 0xFF,
            },
        ];
        let _ = add_xattr_mutation(
            &mut entries,
            image,
            args,
            XattrMutation {
                output_name: format!("{seed}_nid{}_xattr_reserved_nonzero.erofs", inode.nid),
                target_desc: inode.desc.clone(),
                field_name: "h_reserved",
                mutation_name: "reserved_nonzero",
                value_width: FieldWidth::U8,
                value: 0xFF,
                writes: reserved_writes,
            },
        )?;

        let name_filter_writes = vec![
            FieldWrite {
                abs_offset: i_xattr_offset,
                width: FieldWidth::U16,
                value: 1,
            },
            FieldWrite {
                abs_offset: xattr_offset,
                width: FieldWidth::U32,
                value: 0,
            },
        ];
        let _ = add_xattr_mutation(
            &mut entries,
            image,
            args,
            XattrMutation {
                output_name: format!("{seed}_nid{}_xattr_zero_name_filter.erofs", inode.nid),
                target_desc: inode.desc.clone(),
                field_name: "h_name_filter",
                mutation_name: "zero_name_filter",
                value_width: FieldWidth::U32,
                value: 0,
                writes: name_filter_writes,
            },
        )?;
    }

    if entries.is_empty() {
        println!("WARNING: No xattr mutations generated. Skipping.");
    }

    Ok(entries)
}

fn mutate_cross_fields(image: &Image, args: &MutateArgs) -> Result<Vec<MutatedEntry>> {
    let seed = seed_name(&args.input);
    let sb = image.superblock()?;
    let inodes = locate_inodes(image, &sb)?;
    let dirents = locate_dirents_in_image(image, &sb, &inodes)?;
    let block_size = usize::try_from(sb.block_size)
        .map_err(|_| anyhow::anyhow!("block size does not fit host usize"))?;
    let mut entries = Vec::new();

    println!(
        "Found {} inodes, {} directory entries for cross-field mutations",
        inodes.len(),
        dirents.len()
    );

    for inode in &inodes {
        if inode.nid == sb.rootnid || is_directory_inode(image, inode.offset)? {
            continue;
        }
        let (root_rel_offset, root_width, root_field) =
            if sb.feature_incompat & EROFS_FEATURE_INCOMPAT_48BIT != 0 {
                (0x70usize, FieldWidth::U64, "root_nid_8b")
            } else {
                (0x0Eusize, FieldWidth::U16, "rootnid")
            };
        if inode.nid > root_width.max_value() {
            break;
        }
        let root_offset = EROFS_SUPER_OFFSET
            .checked_add(root_rel_offset)
            .ok_or_else(|| anyhow::anyhow!("root nid field offset overflows"))?;
        if add_cross_field_mutation(
            &mut entries,
            image,
            args,
            CrossFieldMutation {
                output_name: format!("{seed}_cross_rootnid_to_non_directory.erofs"),
                target_desc: format!("superblock->{}", inode.desc),
                field_name: root_field,
                mutation_name: "rootnid_to_non_directory",
                abs_offset: root_offset,
                width: root_width,
                new_value: inode.nid,
            },
        )? {
            break;
        }
    }

    let block_padding = block_size
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("block size must be nonzero"))?;
    let image_blocks = image
        .len()
        .checked_add(block_padding)
        .ok_or_else(|| anyhow::anyhow!("image block count overflows"))?
        / block_size;
    if image_blocks > 1 && image_blocks - 1 <= u32::MAX as usize {
        let blocks_offset = EROFS_SUPER_OFFSET
            .checked_add(0x24)
            .ok_or_else(|| anyhow::anyhow!("blocks_lo field offset overflows"))?;
        let _ = add_cross_field_mutation(
            &mut entries,
            image,
            args,
            CrossFieldMutation {
                output_name: format!("{seed}_cross_blocks_below_image_extent.erofs"),
                target_desc: "superblock".to_string(),
                field_name: "blocks_lo",
                mutation_name: "blocks_below_image_extent",
                abs_offset: blocks_offset,
                width: FieldWidth::U32,
                new_value: (image_blocks - 1) as u64,
            },
        )?;
    }

    for inode in &inodes {
        let Ok(data_offset) = inode_data_offset(image, &sb, inode.offset) else {
            continue;
        };
        let data_block = data_offset / block_size;
        if data_block > u32::MAX as usize {
            continue;
        }
        let meta_offset = EROFS_SUPER_OFFSET
            .checked_add(0x28)
            .ok_or_else(|| anyhow::anyhow!("meta_blkaddr field offset overflows"))?;
        if add_cross_field_mutation(
            &mut entries,
            image,
            args,
            CrossFieldMutation {
                output_name: format!("{seed}_cross_meta_blkaddr_to_file_data.erofs"),
                target_desc: format!("superblock->{}", inode.desc),
                field_name: "meta_blkaddr",
                mutation_name: "meta_blkaddr_to_file_data",
                abs_offset: meta_offset,
                width: FieldWidth::U32,
                new_value: data_block as u64,
            },
        )? {
            break;
        }
    }

    for dirent in dirents.iter().filter(|dirent| dirent.entry_idx == 0) {
        let nameoff_offset = dirent
            .offset
            .checked_add(0x08)
            .ok_or_else(|| anyhow::anyhow!("dirent nameoff offset overflows"))?;
        if add_cross_field_mutation(
            &mut entries,
            image,
            args,
            CrossFieldMutation {
                output_name: format!("{seed}_cross_nameoff_over_header.erofs"),
                target_desc: dirent.desc.clone(),
                field_name: "nameoff",
                mutation_name: "nameoff_over_header",
                abs_offset: nameoff_offset,
                width: FieldWidth::U16,
                new_value: 12,
            },
        )? {
            break;
        }
    }

    for inode in &inodes {
        let i_format = image.read_field(inode.offset, FieldWidth::U16)?;
        let datalayout = (i_format >> 1) & 0x7;
        if datalayout != 2 {
            continue;
        }
        let extended = is_extended_inode(image, inode.offset)?;
        let width = if extended {
            FieldWidth::U64
        } else {
            FieldWidth::U32
        };
        let i_size_offset = inode
            .offset
            .checked_add(0x08)
            .ok_or_else(|| anyhow::anyhow!("inode i_size offset overflows"))?;
        let new_size = u64::from(sb.block_size)
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("inline size mutation overflows"))?;
        if add_cross_field_mutation(
            &mut entries,
            image,
            args,
            CrossFieldMutation {
                output_name: format!("{seed}_cross_inline_size_mismatch.erofs"),
                target_desc: inode.desc.clone(),
                field_name: "i_size",
                mutation_name: "inline_size_mismatch",
                abs_offset: i_size_offset,
                width,
                new_value: new_size,
            },
        )? {
            break;
        }
    }

    if entries.is_empty() {
        println!("WARNING: No cross-field mutations generated. Skipping.");
    }

    Ok(entries)
}

fn write_manifest<P: AsRef<Path>>(
    path: P,
    args: &MutateArgs,
    entries: &[MutatedEntry],
) -> Result<()> {
    let seed = seed_name(&args.input);
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut family_counts: HashMap<String, usize> = HashMap::new();
    let mut parser_counts: HashMap<String, usize> = HashMap::new();
    for e in entries {
        *counts.entry(e.classification.clone()).or_insert(0) += 1;
        *family_counts.entry(e.family.clone()).or_insert(0) += 1;
        *parser_counts.entry(e.parser_outcome.clone()).or_insert(0) += 1;
    }

    let mut lines = vec![
        format!("# EROFS Mutation Manifest"),
        format!("# Input: {}", args.input),
        format!("# Seed: {seed}"),
        format!("# Fix checksum: {}", args.fix_checksum),
        format!("# Total mutations: {}", entries.len()),
        String::new(),
        format!(
            "{:<60} {:<15} {:<20} {:<25} {:<20} {:<20} {}",
            "output_file", "target", "field", "mutation", "value", "result", "classification"
        ),
        "-".repeat(135),
    ];

    for e in entries {
        lines.push(format!(
            "{:<60} {:<15} {:<20} {:<25} {:<20} {:<20} {}",
            e.output_name,
            e.target_desc,
            e.field_name,
            e.mutation_name,
            e.value_hex,
            e.classification,
            e.reason
        ));
    }

    lines.push(String::new());
    let summary = sorted_counts(&counts)
        .into_iter()
        .map(|(classification, count)| format!("{classification}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!("# Summary: total={}, {summary}", entries.len()));
    lines.push(format!("# Oracle: {summary}"));
    let families = sorted_counts(&family_counts)
        .into_iter()
        .map(|(family, count)| format!("{family}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!("# Families: {families}"));
    let parser = sorted_counts(&parser_counts)
        .into_iter()
        .map(|(outcome, count)| format!("{outcome}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!("# Parser: {parser}"));

    fs::write(path.as_ref(), lines.join("\n") + "\n").map_err(|e| {
        anyhow::anyhow!("failed to write manifest {}: {e}", path.as_ref().display())
    })?;
    Ok(())
}

fn sorted_counts(counts: &HashMap<String, usize>) -> Vec<(&str, usize)> {
    let mut items = counts
        .iter()
        .map(|(name, count)| (name.as_str(), *count))
        .collect::<Vec<_>>();
    items.sort_by(|a, b| a.0.cmp(b.0));
    items
}

pub fn run(args: &MutateArgs) -> Result<()> {
    if !Path::new(&args.input).exists() {
        bail!("Input file not found: {}", args.input);
    }

    fs::create_dir_all(&args.output_dir)
        .map_err(|e| anyhow::anyhow!("failed to create output directory: {e}"))?;

    let image = read_image(&args.input)?;

    let mut all_entries = Vec::new();

    match args.target.as_str() {
        "superblock" => all_entries.extend(mutate_superblock(&image, args)?),
        "inode" => all_entries.extend(mutate_inodes(&image, args)?),
        "dirent" => all_entries.extend(mutate_dirents(&image, args)?),
        "xattr" => all_entries.extend(mutate_xattrs(&image, args)?),
        "cross" => all_entries.extend(mutate_cross_fields(&image, args)?),
        "all" => {
            all_entries.extend(mutate_superblock(&image, args)?);
            all_entries.extend(mutate_inodes(&image, args)?);
            all_entries.extend(mutate_dirents(&image, args)?);
            all_entries.extend(mutate_xattrs(&image, args)?);
            all_entries.extend(mutate_cross_fields(&image, args)?);
        }
        _ => bail!(
            "unknown mutation target: {} (expected superblock|inode|dirent|xattr|cross|all)",
            args.target
        ),
    }

    write_manifest(&args.manifest, args, &all_entries)?;

    println!(
        "\nDone. Generated {} mutations in {}",
        all_entries.len(),
        args.output_dir
    );
    let mut counts: HashMap<String, usize> = HashMap::new();
    for e in &all_entries {
        *counts.entry(e.classification.clone()).or_insert(0) += 1;
    }
    for (k, v) in {
        let mut items: Vec<_> = counts.iter().collect();
        items.sort_by(|a, b| a.0.cmp(b.0));
        items
    } {
        println!("  {k}: {v}");
    }
    println!("  Manifest: {}", args.manifest);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::SUPERBLOCK_FIELDS;

    #[test]
    fn superblock_mutations_cover_late_format_fields() {
        let names: Vec<_> = SUPERBLOCK_FIELDS
            .iter()
            .map(|field| field.field_name)
            .collect();

        for expected in [
            "epoch",
            "fixed_nsec",
            "uuid_lo",
            "uuid_hi",
            "volume_name_lo",
            "volume_name_hi",
            "feature_incompat",
            "available_compr_algs",
            "extra_devices",
            "devt_slotoff",
            "dirblkbits",
            "xattr_prefix_count",
            "xattr_prefix_start",
            "packed_nid",
            "xattr_filter_reserved",
            "ishare_xattr_prefix_id",
            "reserved",
            "build_time",
            "root_nid_8b",
            "reserved2",
            "metabox_nid",
            "reserved3",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
    }
}
