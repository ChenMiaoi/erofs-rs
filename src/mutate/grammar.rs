use super::engine::{
    FieldWrite, GrammarMutation, MutatedEntry, add_grammar_mutation, round_up_for_mutation,
    seed_name,
};
use super::fields::{
    EROFS_DEVT_SLOT_SIZE, EROFS_FEATURE_COMPAT_XATTR_FILTER, EROFS_FEATURE_INCOMPAT_DEVICE_TABLE,
    EROFS_FEATURE_INCOMPAT_FRAGMENTS, EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES,
    EROFS_INODE_COMPRESSED_COMPACT, EROFS_XATTR_FILTER_DEFAULT, EROFS_XATTR_LONG_PREFIX,
    Z_EROFS_ADVISE_BIG_PCLUSTER_1, Z_EROFS_ADVISE_BIG_PCLUSTER_2, Z_EROFS_CLUSTERBITS_RESERVED_BIT,
    Z_EROFS_FRAGMENT_INODE_MASK,
};
use crate::cli::MutateArgs;
use crate::image::{EROFS_SUPER_OFFSET, FieldWidth, Image};
use crate::inode::{Inode, is_directory_inode, is_extended_inode, locate_inodes};
use anyhow::Result;
use std::collections::BTreeSet;

const XATTR_HEADER_SIZE: usize = 12;
const XATTR_FIRST_ENTRY_OFFSET: usize = XATTR_HEADER_SIZE;
const DEVICE_SLOT_RESERVED_OFFSET: usize = 0x4C;

pub(super) struct GrammarCoverage {
    pub(super) feature: &'static str,
    pub(super) case_name: &'static str,
}

pub(super) const GRAMMAR_COVERAGE_MODEL: &[GrammarCoverage] = &[
    GrammarCoverage {
        feature: "xattr_shared_area",
        case_name: "xattr_shared_area_valid",
    },
    GrammarCoverage {
        feature: "xattr_shared_area",
        case_name: "xattr_shared_area_overrun",
    },
    GrammarCoverage {
        feature: "xattr_long_prefix",
        case_name: "xattr_long_prefix_entry",
    },
    GrammarCoverage {
        feature: "xattr_filter",
        case_name: "xattr_filter_enabled",
    },
    GrammarCoverage {
        feature: "xattr_filter",
        case_name: "xattr_filter_reserved_nonzero",
    },
    GrammarCoverage {
        feature: "packed_fragments",
        case_name: "packed_fragment_featured",
    },
    GrammarCoverage {
        feature: "packed_fragments",
        case_name: "packed_fragment_without_feature",
    },
    GrammarCoverage {
        feature: "device_table",
        case_name: "device_table_semantic",
    },
    GrammarCoverage {
        feature: "device_table",
        case_name: "device_table_slot_overrun",
    },
    GrammarCoverage {
        feature: "compressed_layout",
        case_name: "compressed_layout_compact",
    },
    GrammarCoverage {
        feature: "compressed_layout",
        case_name: "compressed_layout_big_pcluster_pair",
    },
    GrammarCoverage {
        feature: "compressed_layout",
        case_name: "compressed_layout_reserved_clusterbits",
    },
];

#[derive(Clone, Copy)]
enum GrammarBase {
    Superblock,
    Inode,
    InlineXattr,
    CompressionMap,
    DeviceSlot,
}

#[derive(Clone, Copy)]
struct GrammarField {
    name: &'static str,
    base: GrammarBase,
    rel_offset: usize,
    width: FieldWidth,
}

impl GrammarField {
    fn write(self, ctx: &GrammarContext, value: u64) -> Result<FieldWrite> {
        let base = match self.base {
            GrammarBase::Superblock => EROFS_SUPER_OFFSET,
            GrammarBase::Inode => ctx
                .inode_offset
                .ok_or_else(|| anyhow::anyhow!("grammar field {} needs inode base", self.name))?,
            GrammarBase::InlineXattr => ctx.inline_xattr_offset.ok_or_else(|| {
                anyhow::anyhow!("grammar field {} needs inline xattr base", self.name)
            })?,
            GrammarBase::CompressionMap => ctx.compression_map_offset.ok_or_else(|| {
                anyhow::anyhow!("grammar field {} needs compression map base", self.name)
            })?,
            GrammarBase::DeviceSlot => ctx.device_slot_offset.ok_or_else(|| {
                anyhow::anyhow!("grammar field {} needs device slot base", self.name)
            })?,
        };
        let abs_offset = base
            .checked_add(self.rel_offset)
            .ok_or_else(|| anyhow::anyhow!("grammar field {} offset overflows", self.name))?;
        Ok(FieldWrite {
            abs_offset,
            width: self.width,
            value,
        })
    }
}

#[derive(Default)]
struct GrammarContext {
    inode_offset: Option<usize>,
    inline_xattr_offset: Option<usize>,
    compression_map_offset: Option<usize>,
    device_slot_offset: Option<usize>,
}

#[derive(Clone, Copy)]
enum GrammarFeature {
    XattrSharedArea,
    XattrLongPrefix,
    XattrFilter,
    PackedFragments,
    DeviceTable,
    CompressedLayout,
}

impl GrammarFeature {
    fn label(self) -> &'static str {
        match self {
            Self::XattrSharedArea => "xattr_shared_area",
            Self::XattrLongPrefix => "xattr_long_prefix",
            Self::XattrFilter => "xattr_filter",
            Self::PackedFragments => "packed_fragments",
            Self::DeviceTable => "device_table",
            Self::CompressedLayout => "compressed_layout",
        }
    }
}

struct GrammarPlan {
    feature: GrammarFeature,
    scope: String,
    output_suffix: String,
    primary: GrammarField,
    mutation_name: &'static str,
    value: u64,
    writes: Vec<FieldWrite>,
}

const SB_FEATURE_COMPAT: GrammarField = GrammarField {
    name: "feature_compat",
    base: GrammarBase::Superblock,
    rel_offset: 0x08,
    width: FieldWidth::U32,
};
const SB_FEATURE_INCOMPAT: GrammarField = GrammarField {
    name: "feature_incompat",
    base: GrammarBase::Superblock,
    rel_offset: 0x50,
    width: FieldWidth::U32,
};
const SB_AVAILABLE_COMPR_ALGS: GrammarField = GrammarField {
    name: "available_compr_algs",
    base: GrammarBase::Superblock,
    rel_offset: 0x54,
    width: FieldWidth::U16,
};
const SB_EXTRA_DEVICES: GrammarField = GrammarField {
    name: "extra_devices",
    base: GrammarBase::Superblock,
    rel_offset: 0x56,
    width: FieldWidth::U16,
};
const SB_DEVT_SLOTOFF: GrammarField = GrammarField {
    name: "devt_slotoff",
    base: GrammarBase::Superblock,
    rel_offset: 0x58,
    width: FieldWidth::U16,
};
const SB_XATTR_PREFIX_COUNT: GrammarField = GrammarField {
    name: "xattr_prefix_count",
    base: GrammarBase::Superblock,
    rel_offset: 0x5B,
    width: FieldWidth::U8,
};
const SB_XATTR_PREFIX_START: GrammarField = GrammarField {
    name: "xattr_prefix_start",
    base: GrammarBase::Superblock,
    rel_offset: 0x5C,
    width: FieldWidth::U32,
};
const SB_PACKED_NID: GrammarField = GrammarField {
    name: "packed_nid",
    base: GrammarBase::Superblock,
    rel_offset: 0x60,
    width: FieldWidth::U64,
};
const SB_XATTR_FILTER_RESERVED: GrammarField = GrammarField {
    name: "xattr_filter_reserved",
    base: GrammarBase::Superblock,
    rel_offset: 0x68,
    width: FieldWidth::U8,
};
const SB_ISHARE_XATTR_PREFIX_ID: GrammarField = GrammarField {
    name: "ishare_xattr_prefix_id",
    base: GrammarBase::Superblock,
    rel_offset: 0x69,
    width: FieldWidth::U8,
};
const INODE_FORMAT: GrammarField = GrammarField {
    name: "i_format",
    base: GrammarBase::Inode,
    rel_offset: 0x00,
    width: FieldWidth::U16,
};
const INODE_XATTR_ICOUNT: GrammarField = GrammarField {
    name: "i_xattr_icount",
    base: GrammarBase::Inode,
    rel_offset: 0x02,
    width: FieldWidth::U16,
};
const XATTR_NAME_FILTER: GrammarField = GrammarField {
    name: "h_name_filter",
    base: GrammarBase::InlineXattr,
    rel_offset: 0x00,
    width: FieldWidth::U32,
};
const XATTR_SHARED_COUNT: GrammarField = GrammarField {
    name: "h_shared_count",
    base: GrammarBase::InlineXattr,
    rel_offset: 0x04,
    width: FieldWidth::U8,
};
const XATTR_SHARED_REF0: GrammarField = GrammarField {
    name: "h_shared_xattrs[0]",
    base: GrammarBase::InlineXattr,
    rel_offset: XATTR_FIRST_ENTRY_OFFSET,
    width: FieldWidth::U32,
};
const XATTR_ENTRY_NAME_LEN: GrammarField = GrammarField {
    name: "e_name_len",
    base: GrammarBase::InlineXattr,
    rel_offset: XATTR_FIRST_ENTRY_OFFSET,
    width: FieldWidth::U8,
};
const XATTR_ENTRY_NAME_INDEX: GrammarField = GrammarField {
    name: "e_name_index",
    base: GrammarBase::InlineXattr,
    rel_offset: XATTR_FIRST_ENTRY_OFFSET + 1,
    width: FieldWidth::U8,
};
const XATTR_ENTRY_VALUE_SIZE: GrammarField = GrammarField {
    name: "e_value_size",
    base: GrammarBase::InlineXattr,
    rel_offset: XATTR_FIRST_ENTRY_OFFSET + 2,
    width: FieldWidth::U16,
};
const XATTR_ENTRY_NAME0: GrammarField = GrammarField {
    name: "e_name[0]",
    base: GrammarBase::InlineXattr,
    rel_offset: XATTR_FIRST_ENTRY_OFFSET + 4,
    width: FieldWidth::U8,
};
const ZMAP_HEADER: GrammarField = GrammarField {
    name: "z_erofs_map_header",
    base: GrammarBase::CompressionMap,
    rel_offset: 0x00,
    width: FieldWidth::U64,
};
const ZMAP_ADVISE: GrammarField = GrammarField {
    name: "h_advise",
    base: GrammarBase::CompressionMap,
    rel_offset: 0x04,
    width: FieldWidth::U16,
};
const ZMAP_CLUSTERBITS: GrammarField = GrammarField {
    name: "h_clusterbits",
    base: GrammarBase::CompressionMap,
    rel_offset: 0x07,
    width: FieldWidth::U8,
};
const DEVICE_TAG: GrammarField = GrammarField {
    name: "tag",
    base: GrammarBase::DeviceSlot,
    rel_offset: 0x00,
    width: FieldWidth::U64,
};
const DEVICE_BLOCKS_LO: GrammarField = GrammarField {
    name: "blocks_lo",
    base: GrammarBase::DeviceSlot,
    rel_offset: 0x40,
    width: FieldWidth::U32,
};
const DEVICE_UNIADDR_LO: GrammarField = GrammarField {
    name: "uniaddr_lo",
    base: GrammarBase::DeviceSlot,
    rel_offset: 0x44,
    width: FieldWidth::U32,
};
const DEVICE_BLOCKS_HI: GrammarField = GrammarField {
    name: "blocks_hi",
    base: GrammarBase::DeviceSlot,
    rel_offset: 0x48,
    width: FieldWidth::U16,
};
const DEVICE_UNIADDR_HI: GrammarField = GrammarField {
    name: "uniaddr_hi",
    base: GrammarBase::DeviceSlot,
    rel_offset: 0x4A,
    width: FieldWidth::U16,
};
pub(super) fn mutate_grammar(image: &Image, args: &MutateArgs) -> Result<Vec<MutatedEntry>> {
    let seed = seed_name(&args.input);
    let sb = image.superblock()?;
    let inodes = locate_inodes(image, &sb)?;
    let mut entries = Vec::new();
    let modeled_features = validate_grammar_model()?;

    println!(
        "Planning {} grammar-aware cases across {} semantic areas and {} inodes",
        GRAMMAR_COVERAGE_MODEL.len(),
        modeled_features,
        inodes.len()
    );

    let feature_compat = image.read_field(
        EROFS_SUPER_OFFSET
            .checked_add(SB_FEATURE_COMPAT.rel_offset)
            .ok_or_else(|| anyhow::anyhow!("feature_compat offset overflows"))?,
        FieldWidth::U32,
    )?;
    let feature_incompat = image.read_field(
        EROFS_SUPER_OFFSET
            .checked_add(SB_FEATURE_INCOMPAT.rel_offset)
            .ok_or_else(|| anyhow::anyhow!("feature_incompat offset overflows"))?,
        FieldWidth::U32,
    )?;

    for inode in &inodes {
        let ctx = inode_context(image, inode)?;
        emit_xattr_shared_plans(&mut entries, image, args, &seed, inode, &ctx)?;
        emit_xattr_prefix_plans(
            &mut entries,
            image,
            args,
            &seed,
            inode,
            &ctx,
            feature_incompat,
        )?;
        emit_xattr_filter_plans(
            &mut entries,
            image,
            args,
            &seed,
            inode,
            &ctx,
            feature_compat,
        )?;
        emit_compressed_layout_plans(&mut entries, image, args, &seed, inode, &ctx)?;
    }

    for inode in fragment_inodes(image, &inodes)? {
        let ctx = inode_context(image, inode)?;
        emit_packed_fragment_plans(
            &mut entries,
            image,
            args,
            &seed,
            inode,
            &ctx,
            feature_incompat,
        )?;
    }

    emit_device_table_plans(
        &mut entries,
        image,
        args,
        &seed,
        feature_incompat,
        u64::from(sb.blocks_lo),
    )?;

    if entries.is_empty() {
        println!("WARNING: No grammar-aware mutations generated. Skipping.");
    }

    Ok(entries)
}

fn validate_grammar_model() -> Result<usize> {
    let mut features = BTreeSet::new();
    let mut cases = BTreeSet::new();
    for case in GRAMMAR_COVERAGE_MODEL {
        if case.feature.is_empty() || case.case_name.is_empty() {
            anyhow::bail!("grammar coverage model contains an empty feature or case name");
        }
        if !cases.insert(case.case_name) {
            anyhow::bail!("duplicate grammar case {}", case.case_name);
        }
        features.insert(case.feature);
    }
    Ok(features.len())
}

fn inode_context(image: &Image, inode: &Inode) -> Result<GrammarContext> {
    let inode_size = if is_extended_inode(image, inode.offset)? {
        64usize
    } else {
        32usize
    };
    let inline_xattr_offset = inode
        .offset
        .checked_add(inode_size)
        .ok_or_else(|| anyhow::anyhow!("inline xattr offset overflows"))?;
    let compression_map_offset = round_up_for_mutation(inline_xattr_offset, 8)?;

    Ok(GrammarContext {
        inode_offset: Some(inode.offset),
        inline_xattr_offset: Some(inline_xattr_offset),
        compression_map_offset: Some(compression_map_offset),
        device_slot_offset: None,
    })
}

fn fragment_inodes<'a>(image: &Image, inodes: &'a [Inode]) -> Result<Vec<&'a Inode>> {
    let mut non_directories = Vec::new();
    for inode in inodes {
        if !is_directory_inode(image, inode.offset)? {
            non_directories.push(inode);
        }
    }
    if non_directories.is_empty() {
        Ok(inodes.iter().collect())
    } else {
        Ok(non_directories)
    }
}

fn emit_xattr_shared_plans(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    seed: &str,
    inode: &Inode,
    ctx: &GrammarContext,
) -> Result<()> {
    let mut valid_writes = vec![
        INODE_XATTR_ICOUNT.write(ctx, 2)?,
        XATTR_NAME_FILTER.write(ctx, EROFS_XATTR_FILTER_DEFAULT)?,
        XATTR_SHARED_COUNT.write(ctx, 1)?,
        XATTR_SHARED_REF0.write(ctx, 0)?,
    ];
    valid_writes.extend(xattr_reserved_zero_writes(ctx)?);
    emit_plan(
        entries,
        image,
        args,
        seed,
        GrammarPlan {
            feature: GrammarFeature::XattrSharedArea,
            scope: inode.desc.clone(),
            output_suffix: format!("nid{}_grammar_xattr_shared_valid", inode.nid),
            primary: XATTR_SHARED_COUNT,
            mutation_name: "xattr_shared_area_valid",
            value: 1,
            writes: valid_writes,
        },
    )?;

    let mut overrun_writes = vec![
        INODE_XATTR_ICOUNT.write(ctx, 1)?,
        XATTR_NAME_FILTER.write(ctx, EROFS_XATTR_FILTER_DEFAULT)?,
        XATTR_SHARED_COUNT.write(ctx, 1)?,
    ];
    overrun_writes.extend(xattr_reserved_zero_writes(ctx)?);
    emit_plan(
        entries,
        image,
        args,
        seed,
        GrammarPlan {
            feature: GrammarFeature::XattrSharedArea,
            scope: inode.desc.clone(),
            output_suffix: format!("nid{}_grammar_xattr_shared_overrun", inode.nid),
            primary: XATTR_SHARED_COUNT,
            mutation_name: "xattr_shared_area_overrun",
            value: 1,
            writes: overrun_writes,
        },
    )?;

    Ok(())
}

fn emit_xattr_prefix_plans(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    seed: &str,
    inode: &Inode,
    ctx: &GrammarContext,
    feature_incompat: u64,
) -> Result<()> {
    let prefix_feature = feature_incompat | EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES;
    let mut writes = vec![
        SB_FEATURE_INCOMPAT.write(ctx, prefix_feature)?,
        SB_XATTR_PREFIX_COUNT.write(ctx, 1)?,
        SB_XATTR_PREFIX_START.write(ctx, 1)?,
        SB_ISHARE_XATTR_PREFIX_ID.write(ctx, 1)?,
        INODE_XATTR_ICOUNT.write(ctx, 3)?,
        XATTR_NAME_FILTER.write(ctx, EROFS_XATTR_FILTER_DEFAULT)?,
        XATTR_SHARED_COUNT.write(ctx, 0)?,
        XATTR_ENTRY_NAME_LEN.write(ctx, 1)?,
        XATTR_ENTRY_NAME_INDEX.write(ctx, EROFS_XATTR_LONG_PREFIX)?,
        XATTR_ENTRY_VALUE_SIZE.write(ctx, 0)?,
        XATTR_ENTRY_NAME0.write(ctx, u64::from(b'a'))?,
    ];
    writes.extend(xattr_reserved_zero_writes(ctx)?);
    emit_plan(
        entries,
        image,
        args,
        seed,
        GrammarPlan {
            feature: GrammarFeature::XattrLongPrefix,
            scope: format!("superblock->{}", inode.desc),
            output_suffix: format!("nid{}_grammar_xattr_long_prefix", inode.nid),
            primary: XATTR_ENTRY_NAME_INDEX,
            mutation_name: "xattr_long_prefix_entry",
            value: EROFS_XATTR_LONG_PREFIX,
            writes,
        },
    )?;
    Ok(())
}

fn emit_xattr_filter_plans(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    seed: &str,
    inode: &Inode,
    ctx: &GrammarContext,
    feature_compat: u64,
) -> Result<()> {
    let filter_feature = feature_compat | EROFS_FEATURE_COMPAT_XATTR_FILTER;
    let mut enabled_writes = vec![
        SB_FEATURE_COMPAT.write(ctx, filter_feature)?,
        SB_XATTR_FILTER_RESERVED.write(ctx, 0)?,
        INODE_XATTR_ICOUNT.write(ctx, 1)?,
        XATTR_NAME_FILTER.write(ctx, EROFS_XATTR_FILTER_DEFAULT - 1)?,
        XATTR_SHARED_COUNT.write(ctx, 0)?,
    ];
    enabled_writes.extend(xattr_reserved_zero_writes(ctx)?);
    emit_plan(
        entries,
        image,
        args,
        seed,
        GrammarPlan {
            feature: GrammarFeature::XattrFilter,
            scope: format!("superblock->{}", inode.desc),
            output_suffix: format!("nid{}_grammar_xattr_filter_enabled", inode.nid),
            primary: XATTR_NAME_FILTER,
            mutation_name: "xattr_filter_enabled",
            value: EROFS_XATTR_FILTER_DEFAULT - 1,
            writes: enabled_writes,
        },
    )?;

    let mut reserved_writes = vec![
        SB_FEATURE_COMPAT.write(ctx, filter_feature)?,
        SB_XATTR_FILTER_RESERVED.write(ctx, 0xFF)?,
        INODE_XATTR_ICOUNT.write(ctx, 1)?,
        XATTR_NAME_FILTER.write(ctx, EROFS_XATTR_FILTER_DEFAULT - 1)?,
    ];
    reserved_writes.extend(xattr_reserved_zero_writes(ctx)?);
    emit_plan(
        entries,
        image,
        args,
        seed,
        GrammarPlan {
            feature: GrammarFeature::XattrFilter,
            scope: format!("superblock->{}", inode.desc),
            output_suffix: format!("nid{}_grammar_xattr_filter_reserved", inode.nid),
            primary: SB_XATTR_FILTER_RESERVED,
            mutation_name: "xattr_filter_reserved_nonzero",
            value: 0xFF,
            writes: reserved_writes,
        },
    )?;

    Ok(())
}

fn emit_packed_fragment_plans(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    seed: &str,
    inode: &Inode,
    ctx: &GrammarContext,
    feature_incompat: u64,
) -> Result<()> {
    let original_format = image.read_field(inode.offset, FieldWidth::U16)?;
    let compact_layout = (original_format & 0x01) | (EROFS_INODE_COMPRESSED_COMPACT << 1);
    let fragment_feature = feature_incompat | EROFS_FEATURE_INCOMPAT_FRAGMENTS;

    emit_plan(
        entries,
        image,
        args,
        seed,
        GrammarPlan {
            feature: GrammarFeature::PackedFragments,
            scope: format!("superblock->{}", inode.desc),
            output_suffix: format!("nid{}_grammar_packed_fragment_featured", inode.nid),
            primary: ZMAP_CLUSTERBITS,
            mutation_name: "packed_fragment_featured",
            value: 0x80,
            writes: vec![
                SB_FEATURE_INCOMPAT.write(ctx, fragment_feature)?,
                SB_PACKED_NID.write(ctx, inode.nid)?,
                INODE_FORMAT.write(ctx, compact_layout)?,
                INODE_XATTR_ICOUNT.write(ctx, 0)?,
                ZMAP_HEADER.write(ctx, Z_EROFS_FRAGMENT_INODE_MASK)?,
            ],
        },
    )?;

    emit_plan(
        entries,
        image,
        args,
        seed,
        GrammarPlan {
            feature: GrammarFeature::PackedFragments,
            scope: format!("superblock->{}", inode.desc),
            output_suffix: format!("nid{}_grammar_packed_fragment_without_feature", inode.nid),
            primary: SB_PACKED_NID,
            mutation_name: "packed_fragment_without_feature",
            value: 0,
            writes: vec![
                SB_FEATURE_INCOMPAT
                    .write(ctx, feature_incompat & !EROFS_FEATURE_INCOMPAT_FRAGMENTS)?,
                SB_PACKED_NID.write(ctx, 0)?,
                INODE_FORMAT.write(ctx, compact_layout)?,
                INODE_XATTR_ICOUNT.write(ctx, 0)?,
                ZMAP_HEADER.write(ctx, Z_EROFS_FRAGMENT_INODE_MASK)?,
            ],
        },
    )?;

    Ok(())
}

fn emit_compressed_layout_plans(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    seed: &str,
    inode: &Inode,
    ctx: &GrammarContext,
) -> Result<()> {
    let original_format = image.read_field(inode.offset, FieldWidth::U16)?;
    let compact_layout = (original_format & 0x01) | (EROFS_INODE_COMPRESSED_COMPACT << 1);

    emit_plan(
        entries,
        image,
        args,
        seed,
        GrammarPlan {
            feature: GrammarFeature::CompressedLayout,
            scope: inode.desc.clone(),
            output_suffix: format!("nid{}_grammar_compressed_compact", inode.nid),
            primary: INODE_FORMAT,
            mutation_name: "compressed_layout_compact",
            value: compact_layout,
            writes: vec![
                SB_AVAILABLE_COMPR_ALGS.write(ctx, 1)?,
                INODE_FORMAT.write(ctx, compact_layout)?,
                INODE_XATTR_ICOUNT.write(ctx, 0)?,
                ZMAP_HEADER.write(ctx, 0)?,
            ],
        },
    )?;

    let big_pcluster_pair = Z_EROFS_ADVISE_BIG_PCLUSTER_1 | Z_EROFS_ADVISE_BIG_PCLUSTER_2;
    emit_plan(
        entries,
        image,
        args,
        seed,
        GrammarPlan {
            feature: GrammarFeature::CompressedLayout,
            scope: inode.desc.clone(),
            output_suffix: format!("nid{}_grammar_compressed_big_pcluster_pair", inode.nid),
            primary: ZMAP_ADVISE,
            mutation_name: "compressed_layout_big_pcluster_pair",
            value: big_pcluster_pair,
            writes: vec![
                SB_AVAILABLE_COMPR_ALGS.write(ctx, 1)?,
                INODE_FORMAT.write(ctx, compact_layout)?,
                INODE_XATTR_ICOUNT.write(ctx, 0)?,
                ZMAP_HEADER.write(ctx, 0)?,
                ZMAP_ADVISE.write(ctx, big_pcluster_pair)?,
            ],
        },
    )?;

    emit_plan(
        entries,
        image,
        args,
        seed,
        GrammarPlan {
            feature: GrammarFeature::CompressedLayout,
            scope: inode.desc.clone(),
            output_suffix: format!("nid{}_grammar_compressed_reserved_clusterbits", inode.nid),
            primary: ZMAP_CLUSTERBITS,
            mutation_name: "compressed_layout_reserved_clusterbits",
            value: Z_EROFS_CLUSTERBITS_RESERVED_BIT,
            writes: vec![
                SB_AVAILABLE_COMPR_ALGS.write(ctx, 1)?,
                INODE_FORMAT.write(ctx, compact_layout)?,
                INODE_XATTR_ICOUNT.write(ctx, 0)?,
                ZMAP_HEADER.write(ctx, 0)?,
                ZMAP_CLUSTERBITS.write(ctx, Z_EROFS_CLUSTERBITS_RESERVED_BIT)?,
            ],
        },
    )?;

    Ok(())
}

fn emit_device_table_plans(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    seed: &str,
    feature_incompat: u64,
    primary_blocks: u64,
) -> Result<()> {
    let slot_offset = EROFS_SUPER_OFFSET
        .checked_add(2 * EROFS_DEVT_SLOT_SIZE)
        .ok_or_else(|| anyhow::anyhow!("grammar device slot offset overflows"))?;
    let slot_number = u64::try_from(slot_offset / EROFS_DEVT_SLOT_SIZE)
        .map_err(|_| anyhow::anyhow!("grammar device slot number does not fit u64"))?;
    let device_feature = feature_incompat | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE;
    let ctx = GrammarContext {
        inode_offset: None,
        inline_xattr_offset: None,
        compression_map_offset: None,
        device_slot_offset: Some(slot_offset),
    };
    let device_prefix = || -> Result<Vec<FieldWrite>> {
        let mut writes = vec![
            SB_FEATURE_INCOMPAT.write(&ctx, device_feature)?,
            SB_EXTRA_DEVICES.write(&ctx, 1)?,
            SB_DEVT_SLOTOFF.write(&ctx, slot_number)?,
            DEVICE_TAG.write(&ctx, u64::from(b'e'))?,
            DEVICE_BLOCKS_LO.write(&ctx, 1)?,
            DEVICE_UNIADDR_LO.write(&ctx, primary_blocks)?,
            DEVICE_BLOCKS_HI.write(&ctx, 0)?,
            DEVICE_UNIADDR_HI.write(&ctx, 0)?,
        ];
        writes.extend(device_reserved_zero_writes(&ctx)?);
        Ok(writes)
    };

    emit_plan(
        entries,
        image,
        args,
        seed,
        GrammarPlan {
            feature: GrammarFeature::DeviceTable,
            scope: "device_table".to_string(),
            output_suffix: "grammar_device_table_semantic".to_string(),
            primary: SB_EXTRA_DEVICES,
            mutation_name: "device_table_semantic",
            value: 1,
            writes: device_prefix()?,
        },
    )?;

    let out_of_bounds_slot = image
        .len()
        .checked_add(EROFS_DEVT_SLOT_SIZE - 1)
        .map(|len| len / EROFS_DEVT_SLOT_SIZE)
        .filter(|slot| *slot <= u16::MAX as usize);
    if let Some(out_of_bounds_slot) = out_of_bounds_slot {
        emit_plan(
            entries,
            image,
            args,
            seed,
            GrammarPlan {
                feature: GrammarFeature::DeviceTable,
                scope: "device_table".to_string(),
                output_suffix: "grammar_device_table_slot_overrun".to_string(),
                primary: SB_DEVT_SLOTOFF,
                mutation_name: "device_table_slot_overrun",
                value: out_of_bounds_slot as u64,
                writes: vec![
                    SB_FEATURE_INCOMPAT.write(&ctx, device_feature)?,
                    SB_EXTRA_DEVICES.write(&ctx, 1)?,
                    SB_DEVT_SLOTOFF.write(&ctx, out_of_bounds_slot as u64)?,
                ],
            },
        )?;
    }

    Ok(())
}

fn emit_plan(
    entries: &mut Vec<MutatedEntry>,
    image: &Image,
    args: &MutateArgs,
    seed: &str,
    plan: GrammarPlan,
) -> Result<bool> {
    if !writes_fit(image, &plan.writes) {
        return Ok(false);
    }

    add_grammar_mutation(
        entries,
        image,
        args,
        GrammarMutation {
            output_name: format!("{seed}_{}.erofs", plan.output_suffix),
            target_desc: format!("grammar:{}:{}", plan.feature.label(), plan.scope),
            field_name: plan.primary.name,
            mutation_name: plan.mutation_name,
            value_width: plan.primary.width,
            value: plan.value,
            writes: plan.writes,
        },
    )
}

fn xattr_reserved_zero_writes(ctx: &GrammarContext) -> Result<Vec<FieldWrite>> {
    let base = ctx
        .inline_xattr_offset
        .ok_or_else(|| anyhow::anyhow!("xattr reserved writes need inline xattr base"))?;
    (5..XATTR_HEADER_SIZE)
        .map(|rel| {
            let abs_offset = base
                .checked_add(rel)
                .ok_or_else(|| anyhow::anyhow!("xattr reserved offset overflows"))?;
            Ok(FieldWrite {
                abs_offset,
                width: FieldWidth::U8,
                value: 0,
            })
        })
        .collect()
}

fn device_reserved_zero_writes(ctx: &GrammarContext) -> Result<Vec<FieldWrite>> {
    let base = ctx
        .device_slot_offset
        .ok_or_else(|| anyhow::anyhow!("device reserved writes need device slot base"))?;
    (DEVICE_SLOT_RESERVED_OFFSET..EROFS_DEVT_SLOT_SIZE)
        .map(|rel| {
            let abs_offset = base
                .checked_add(rel)
                .ok_or_else(|| anyhow::anyhow!("device reserved offset overflows"))?;
            Ok(FieldWrite {
                abs_offset,
                width: FieldWidth::U8,
                value: 0,
            })
        })
        .collect()
}

fn writes_fit(image: &Image, writes: &[FieldWrite]) -> bool {
    writes.iter().all(|write| {
        write
            .abs_offset
            .checked_add(write.width.bytes())
            .is_some_and(|end| end <= image.len())
            && write.value <= write.width.max_value()
    })
}
