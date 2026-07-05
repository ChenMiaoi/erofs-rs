use crate::checksum::fix_checksum;
use crate::cli::InjectArgs;
use crate::dirent::locate_dirents_in_image;
use crate::image::{EROFS_SUPER_OFFSET, FieldWidth, Image, read_image, write_image};
use crate::inode::{is_extended_inode, locate_inodes};
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Named superblock fields: (name, offset_from_superblock, width).
const SUPERBLOCK_FIELDS: &[(&str, usize, FieldWidth)] = &[
    ("superblock.magic", 0x00, FieldWidth::U32),
    ("superblock.checksum", 0x04, FieldWidth::U32),
    ("superblock.feature_compat", 0x08, FieldWidth::U32),
    ("superblock.blkszbits", 0x0C, FieldWidth::U8),
    ("superblock.sb_extslots", 0x0D, FieldWidth::U8),
    ("superblock.root_nid", 0x0E, FieldWidth::U16),
    ("superblock.inos", 0x10, FieldWidth::U64),
    ("superblock.epoch", 0x18, FieldWidth::U64),
    ("superblock.fixed_nsec", 0x20, FieldWidth::U32),
    ("superblock.blocks_lo", 0x24, FieldWidth::U32),
    ("superblock.meta_blkaddr", 0x28, FieldWidth::U32),
    ("superblock.xattr_blkaddr", 0x2C, FieldWidth::U32),
    ("superblock.uuid_lo", 0x30, FieldWidth::U64),
    ("superblock.uuid_hi", 0x38, FieldWidth::U64),
    ("superblock.volume_name_lo", 0x40, FieldWidth::U64),
    ("superblock.volume_name_hi", 0x48, FieldWidth::U64),
    ("superblock.feature_incompat", 0x50, FieldWidth::U32),
    ("superblock.available_compr_algs", 0x54, FieldWidth::U16),
    ("superblock.extra_devices", 0x56, FieldWidth::U16),
    ("superblock.devt_slotoff", 0x58, FieldWidth::U16),
    ("superblock.dirblkbits", 0x5A, FieldWidth::U8),
    ("superblock.xattr_prefix_count", 0x5B, FieldWidth::U8),
    ("superblock.xattr_prefix_start", 0x5C, FieldWidth::U32),
    ("superblock.packed_nid", 0x60, FieldWidth::U64),
    ("superblock.xattr_filter_reserved", 0x68, FieldWidth::U8),
    ("superblock.ishare_xattr_prefix_id", 0x69, FieldWidth::U8),
    ("superblock.reserved", 0x6A, FieldWidth::U16),
    ("superblock.build_time", 0x6C, FieldWidth::U32),
    ("superblock.root_nid_8b", 0x70, FieldWidth::U64),
    ("superblock.reserved2", 0x78, FieldWidth::U64),
    ("superblock.metabox_nid", 0x80, FieldWidth::U64),
    ("superblock.reserved3", 0x88, FieldWidth::U64),
];

/// Named inode fields for compact and extended inode layouts.
#[derive(Clone, Copy)]
struct InodeField {
    name: &'static str,
    compact: (usize, FieldWidth),
    extended: (usize, FieldWidth),
}

impl InodeField {
    fn location(&self, extended: bool) -> (usize, FieldWidth) {
        if extended {
            self.extended
        } else {
            self.compact
        }
    }
}

const INODE_FIELDS: &[InodeField] = &[
    InodeField {
        name: "inode.format",
        compact: (0x00, FieldWidth::U16),
        extended: (0x00, FieldWidth::U16),
    },
    InodeField {
        name: "inode.xattr_icount",
        compact: (0x02, FieldWidth::U16),
        extended: (0x02, FieldWidth::U16),
    },
    InodeField {
        name: "inode.mode",
        compact: (0x04, FieldWidth::U16),
        extended: (0x04, FieldWidth::U16),
    },
    InodeField {
        name: "inode.nlink",
        compact: (0x06, FieldWidth::U16),
        extended: (0x28, FieldWidth::U32),
    },
    InodeField {
        name: "inode.size",
        compact: (0x08, FieldWidth::U32),
        extended: (0x08, FieldWidth::U64),
    },
    InodeField {
        name: "inode.mtime",
        compact: (0x0C, FieldWidth::U32),
        extended: (0x20, FieldWidth::U64),
    },
    InodeField {
        name: "inode.startblk_lo",
        compact: (0x10, FieldWidth::U32),
        extended: (0x10, FieldWidth::U32),
    },
    InodeField {
        name: "inode.ino",
        compact: (0x14, FieldWidth::U32),
        extended: (0x14, FieldWidth::U32),
    },
    InodeField {
        name: "inode.uid",
        compact: (0x18, FieldWidth::U16),
        extended: (0x18, FieldWidth::U32),
    },
    InodeField {
        name: "inode.gid",
        compact: (0x1A, FieldWidth::U16),
        extended: (0x1C, FieldWidth::U32),
    },
];

/// Named dirent fields: (name, offset_from_dirent_start, width).
const DIRENT_FIELDS: &[(&str, usize, FieldWidth)] = &[
    ("dirent.nid", 0x00, FieldWidth::U64),
    ("dirent.nameoff", 0x08, FieldWidth::U16),
    ("dirent.file_type", 0x0A, FieldWidth::U8),
    ("dirent.reserved", 0x0B, FieldWidth::U8),
];

/// Parse a value string as hex or decimal integer.
pub fn parse_value(value_str: &str) -> Result<u64> {
    let s = value_str.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| anyhow::anyhow!("invalid hex value {s}: {e}"))
    } else {
        s.parse::<u64>()
            .map_err(|e| anyhow::anyhow!("invalid decimal value {s}: {e}"))
    }
}

struct ResolvedField {
    offset: usize,
    width: FieldWidth,
    old_value: u64,
    target: String,
}

fn resolve_field(
    image: &Image,
    field_name: &str,
    target_hint: Option<&str>,
) -> Result<ResolvedField> {
    // Superblock fields are absolute offsets.
    if let Some((_, rel_offset, width)) =
        SUPERBLOCK_FIELDS.iter().find(|(n, _, _)| *n == field_name)
    {
        let offset = EROFS_SUPER_OFFSET + rel_offset;
        let old_value = image.read_field(offset, *width)?;
        return Ok(ResolvedField {
            offset,
            width: *width,
            old_value,
            target: "superblock".to_string(),
        });
    }

    // Inode fields.
    if let Some(field) = INODE_FIELDS.iter().find(|field| field.name == field_name) {
        let sb = image.superblock()?;
        let inodes = locate_inodes(image, &sb)?;
        if inodes.is_empty() {
            bail!("No inodes found in image");
        }
        let target = match target_hint {
            Some(hint) => inodes
                .iter()
                .find(|i| i.desc == hint)
                .ok_or_else(|| anyhow::anyhow!("Target inode not found: {hint}"))?
                .clone(),
            None => {
                // Preserve historical default: second inode when available.
                if inodes.len() > 1 {
                    inodes[1].clone()
                } else {
                    inodes[0].clone()
                }
            }
        };
        let (rel_offset, width) = field.location(is_extended_inode(image, target.offset)?);
        let offset = target
            .offset
            .checked_add(rel_offset)
            .ok_or_else(|| anyhow::anyhow!("target field offset overflows"))?;
        let old_value = image.read_field(offset, width)?;
        return Ok(ResolvedField {
            offset,
            width,
            old_value,
            target: target.desc,
        });
    }

    // Dirent fields.
    if let Some((_, rel_offset, width)) = DIRENT_FIELDS.iter().find(|(n, _, _)| *n == field_name) {
        let sb = image.superblock()?;
        let inodes = locate_inodes(image, &sb)?;
        let dirents = locate_dirents_in_image(image, &sb, &inodes)?;
        if dirents.is_empty() {
            bail!("No directory entries found in image");
        }
        let target = match target_hint {
            Some(hint) => dirents
                .iter()
                .find(|d| d.desc == hint)
                .ok_or_else(|| anyhow::anyhow!("Target dirent not found: {hint}"))?
                .clone(),
            None => dirents[0].clone(),
        };
        let offset = target
            .offset
            .checked_add(*rel_offset)
            .ok_or_else(|| anyhow::anyhow!("target field offset overflows"))?;
        let old_value = image.read_field(offset, *width)?;
        return Ok(ResolvedField {
            offset,
            width: *width,
            old_value,
            target: target.desc,
        });
    }

    bail!("Unknown field: {field_name}")
}

fn sha256_hex(image: &Image) -> String {
    let mut hasher = Sha256::new();
    hasher.update(image.as_bytes());
    hex::encode(hasher.finalize())
}

#[allow(clippy::too_many_arguments)]
fn write_manifest<P: AsRef<Path>>(
    path: P,
    args: &InjectArgs,
    operation: &str,
    offset: usize,
    target: &str,
    old_value: u64,
    new_value: u64,
    input_sha256: &str,
    width: FieldWidth,
) -> Result<()> {
    let mut lines = vec![
        format!("input: {}", args.input),
        format!("input_sha256: {input_sha256}"),
        format!("output: {}", args.output),
        format!("operation: {operation}"),
        format!("tool_version: {VERSION}"),
        format!("target: {target}"),
        format!("absolute_offset: 0x{offset:X}"),
    ];

    if operation == "field" {
        lines.push(format!("field: {}", args.field.as_ref().unwrap()));
        lines.push(format!(
            "old_value: 0x{old_value:0width$X}",
            width = width.bytes() * 2
        ));
        lines.push(format!(
            "new_value: 0x{new_value:0width$X}",
            width = width.bytes() * 2
        ));
    } else {
        lines.push(format!("offset: 0x{}", args.offset.as_ref().unwrap()));
        lines.push(format!("width: {}", args.width.as_ref().unwrap()));
        lines.push(format!(
            "old_value: 0x{old_value:0width$X}",
            width = width.bytes() * 2
        ));
        lines.push(format!(
            "new_value: 0x{new_value:0width$X}",
            width = width.bytes() * 2
        ));
    }

    if args.fix_checksum {
        lines.push("checksum: recalculated".to_string());
    }

    fs::write(path.as_ref(), lines.join("\n") + "\n").map_err(|e| {
        anyhow::anyhow!("failed to write manifest {}: {e}", path.as_ref().display())
    })?;
    Ok(())
}

pub fn run(args: &InjectArgs) -> Result<()> {
    if !Path::new(&args.input).exists() {
        bail!("Input file not found: {}", args.input);
    }

    let field_mode = args.field.is_some();
    let offset_mode = args.offset.is_some();
    if field_mode == offset_mode {
        bail!("Specify exactly one of --field or --offset");
    }
    if offset_mode && args.width.is_none() {
        bail!("--width is required with --offset");
    }

    let mut image = read_image(&args.input)?;
    let input_sha256 = sha256_hex(&image);
    let new_value = parse_value(&args.value)?;

    let (operation, offset, width, old_value, target) = if let Some(field_name) = &args.field {
        let resolved = resolve_field(&image, field_name, args.target.as_deref())?;
        (
            "field",
            resolved.offset,
            resolved.width,
            resolved.old_value,
            resolved.target,
        )
    } else {
        let width: FieldWidth = args.width.as_ref().unwrap().parse()?;
        let offset = usize::try_from(parse_value(args.offset.as_ref().unwrap())?)
            .map_err(|_| anyhow::anyhow!("offset does not fit host usize"))?;
        let old_value = image.read_field(offset, width)?;
        (
            "offset",
            offset,
            width,
            old_value,
            format!("offset_0x{offset:X}"),
        )
    };

    image.write_field(offset, width, new_value)?;

    if args.fix_checksum {
        fix_checksum(&mut image)?;
    }

    write_image(&args.output, &image)?;
    println!("Injected: {} -> {}", args.input, args.output);
    println!(
        "  target={target}, offset=0x{offset:X}: 0x{old_value:0width$X} -> 0x{new_value:0width$X}",
        width = width.bytes() * 2
    );

    if let Some(manifest_path) = &args.manifest {
        write_manifest(
            manifest_path,
            args,
            operation,
            offset,
            &target,
            old_value,
            new_value,
            &input_sha256,
            width,
        )?;
        println!("  Manifest: {manifest_path}");
    }

    Ok(())
}
