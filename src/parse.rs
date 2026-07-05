use crate::dirent::{Dirent, locate_dirents_in_image};
use crate::image::{EROFS_SUPER_OFFSET, Image, Superblock};
use crate::inode::{
    Inode, inode_data_offset, inode_file_size, is_directory_inode, is_plausible_inode,
    locate_inodes,
};
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;

/// Parsing policy for callers that need either strict validation or fuzzing reach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseMode {
    Strict,
    FuzzTolerant,
}

/// High-level parsing stage that produced a recoverable parse report error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseStage {
    Superblock,
    Inode,
    Xattr,
    Chunk,
    Compression,
    Device,
    Dirent,
}

impl fmt::Display for ParseStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Superblock => f.write_str("superblock"),
            Self::Inode => f.write_str("inode"),
            Self::Xattr => f.write_str("xattr"),
            Self::Chunk => f.write_str("chunk"),
            Self::Compression => f.write_str("compression"),
            Self::Device => f.write_str("device"),
            Self::Dirent => f.write_str("dirent"),
        }
    }
}

/// Recoverable error recorded by tolerant parsing.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{stage} parse error: {reason}")]
pub struct ParseError {
    pub stage: ParseStage,
    pub offset: Option<usize>,
    pub reason: String,
}

impl ParseError {
    fn new(stage: ParseStage, offset: Option<usize>, reason: impl ToString) -> Self {
        Self {
            stage,
            offset,
            reason: reason.to_string(),
        }
    }
}

/// Partial parse output for structure-aware fuzzing and later mutation planning.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParseReport {
    pub superblock: Option<Superblock>,
    pub inodes: Vec<std::result::Result<Inode, ParseError>>,
    pub xattrs: Vec<std::result::Result<XattrRegion, ParseError>>,
    pub chunks: Vec<std::result::Result<ChunkMap, ParseError>>,
    pub compressions: Vec<std::result::Result<CompressionMap, ParseError>>,
    pub devices: Vec<std::result::Result<DeviceSlot, ParseError>>,
    pub dirents: Vec<std::result::Result<Dirent, ParseError>>,
    pub errors: Vec<ParseError>,
    pub offsets_seen: BTreeSet<usize>,
}

/// Located inline xattr region for a parsed inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrRegion {
    pub inode_nid: u64,
    pub offset: usize,
    pub size: usize,
    pub shared_count: u8,
    pub desc: String,
}

/// Located chunk map for a chunk-based inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkMap {
    pub inode_nid: u64,
    pub offset: usize,
    pub entry_size: usize,
    pub entry_count: usize,
    pub chunk_bits: u8,
    pub desc: String,
}

/// Located compressed inode map header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompressionMap {
    pub inode_nid: u64,
    pub offset: usize,
    pub advise: u16,
    pub algorithm_head1: u8,
    pub algorithm_head2: u8,
    pub cluster_bits: u8,
    pub fragment_packed: bool,
    pub desc: String,
}

/// Located extra-device table slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceSlot {
    pub index: u16,
    pub offset: usize,
    pub blocks: u64,
    pub uniaddr: u64,
    pub tag_first: u8,
    pub desc: String,
}

const INODE_SLOT_SIZE: usize = 32;
const XATTR_HEADER_SIZE: usize = 12;
const XATTR_SHARED_ENTRY_SIZE: usize = 4;
const EROFS_FEATURE_INCOMPAT_DEVICE_TABLE: u32 = 0x00000008;
const EROFS_FEATURE_INCOMPAT_48BIT: u32 = 0x00000080;
const EROFS_DEVT_SLOT_SIZE: usize = 128;
const EROFS_DEVT_SLOT_RESERVED_OFFSET: usize = 0x4C;
const EROFS_INODE_COMPRESSED_FULL: u16 = 1;
const EROFS_INODE_COMPRESSED_COMPACT: u16 = 3;
const EROFS_INODE_CHUNK_BASED: u16 = 4;
const EROFS_CHUNK_FORMAT_BLKBITS_MASK: u16 = 0x001F;
const EROFS_CHUNK_FORMAT_INDEXES: u16 = 0x0020;
const EROFS_CHUNK_FORMAT_ALL: u16 = 0x007F;
const EROFS_BLOCK_MAP_ENTRY_SIZE: usize = 4;
const EROFS_CHUNK_INDEX_ENTRY_SIZE: usize = 8;
const Z_EROFS_MAP_HEADER_SIZE: usize = 8;
const Z_EROFS_COMPRESSION_MAX: u8 = 4;
const Z_EROFS_ADVISE_BIG_PCLUSTER_1: u16 = 0x0002;
const Z_EROFS_ADVISE_BIG_PCLUSTER_2: u16 = 0x0004;
const Z_EROFS_ADVISE_FRAGMENT_PCLUSTER: u16 = 0x0020;
const Z_EROFS_ADVISE_KNOWN_MASK: u16 = 0x003F;
const Z_EROFS_CLUSTERBITS_MASK: u8 = 0x0F;
const Z_EROFS_CLUSTERBITS_RESERVED_MASK: u8 = 0x70;
const Z_EROFS_FRAGMENT_INODE_BIT: u8 = 0x80;

/// Parse an image with either strict CLI-style failure or fuzz-tolerant reporting.
pub fn parse_image(image: &Image, mode: ParseMode) -> Result<ParseReport> {
    let mut report = ParseReport::default();
    report.offsets_seen.insert(EROFS_SUPER_OFFSET);

    let superblock = match image.superblock() {
        Ok(superblock) => superblock,
        Err(error) => {
            if mode == ParseMode::Strict {
                return Err(error).context("strict superblock parse failed");
            }
            report.errors.push(ParseError::new(
                ParseStage::Superblock,
                Some(EROFS_SUPER_OFFSET),
                error,
            ));
            return Ok(report);
        }
    };
    report.superblock = Some(superblock.clone());

    if mode == ParseMode::FuzzTolerant {
        if let Some(error) = validate_root_inode_tolerant(image, &superblock) {
            if let Some(offset) = error.offset {
                report.offsets_seen.insert(offset);
            }
            report.inodes.push(Err(error.clone()));
            report.errors.push(error);
        }
    }

    let inodes = match locate_inodes(image, &superblock) {
        Ok(inodes) => inodes,
        Err(error) => {
            if mode == ParseMode::Strict {
                return Err(error).context("strict inode location failed");
            }
            let parse_error = ParseError::new(ParseStage::Inode, None, error);
            report.inodes.push(Err(parse_error.clone()));
            report.errors.push(parse_error);
            Vec::new()
        }
    };

    for inode in inodes {
        report.offsets_seen.insert(inode.offset);
        report.inodes.push(Ok(inode));
    }

    let parsed_inodes: Vec<Inode> = report
        .inodes
        .iter()
        .filter_map(|entry| entry.as_ref().ok().cloned())
        .collect();
    if mode == ParseMode::FuzzTolerant {
        report.xattrs = locate_xattrs_tolerant(image, &parsed_inodes);
        for entry in &report.xattrs {
            match entry {
                Ok(region) => {
                    report.offsets_seen.insert(region.offset);
                }
                Err(error) => {
                    if let Some(offset) = error.offset {
                        report.offsets_seen.insert(offset);
                    }
                    report.errors.push(error.clone());
                }
            }
        }

        report.chunks = locate_chunks_tolerant(image, &superblock, &parsed_inodes);
        for entry in &report.chunks {
            match entry {
                Ok(map) => {
                    report.offsets_seen.insert(map.offset);
                }
                Err(error) => {
                    if let Some(offset) = error.offset {
                        report.offsets_seen.insert(offset);
                    }
                    report.errors.push(error.clone());
                }
            }
        }

        report.compressions = locate_compressions_tolerant(image, &superblock, &parsed_inodes);
        for entry in &report.compressions {
            match entry {
                Ok(map) => {
                    report.offsets_seen.insert(map.offset);
                }
                Err(error) => {
                    if let Some(offset) = error.offset {
                        report.offsets_seen.insert(offset);
                    }
                    report.errors.push(error.clone());
                }
            }
        }

        report.devices = locate_devices_tolerant(image, &superblock);
        for entry in &report.devices {
            match entry {
                Ok(slot) => {
                    report.offsets_seen.insert(slot.offset);
                }
                Err(error) => {
                    if let Some(offset) = error.offset {
                        report.offsets_seen.insert(offset);
                    }
                    report.errors.push(error.clone());
                }
            }
        }

        report.dirents = locate_dirents_tolerant(image, &superblock, &parsed_inodes);
        for entry in &report.dirents {
            match entry {
                Ok(dirent) => {
                    report.offsets_seen.insert(dirent.offset);
                }
                Err(error) => {
                    if let Some(offset) = error.offset {
                        report.offsets_seen.insert(offset);
                    }
                    report.errors.push(error.clone());
                }
            }
        }
    } else {
        let dirents = match locate_dirents_in_image(image, &superblock, &parsed_inodes) {
            Ok(dirents) => dirents,
            Err(error) => {
                return Err(error).context("strict dirent location failed");
            }
        };

        for dirent in dirents {
            report.offsets_seen.insert(dirent.offset);
            report.dirents.push(Ok(dirent));
        }
    }

    Ok(report)
}

fn validate_root_inode_tolerant(image: &Image, sb: &Superblock) -> Option<ParseError> {
    let root_slot = match usize::try_from(sb.rootnid) {
        Ok(slot) => slot,
        Err(_) => {
            return Some(ParseError::new(
                ParseStage::Inode,
                None,
                format!("root nid {} does not fit host usize", sb.rootnid),
            ));
        }
    };
    let root_offset = match root_slot
        .checked_mul(INODE_SLOT_SIZE)
        .and_then(|offset| sb.meta_offset.checked_add(offset))
    {
        Some(offset) => offset,
        None => {
            return Some(ParseError::new(
                ParseStage::Inode,
                None,
                format!("root nid {} inode offset overflows", sb.rootnid),
            ));
        }
    };

    if root_offset
        .checked_add(INODE_SLOT_SIZE)
        .is_none_or(|end| end > image.len())
    {
        return Some(ParseError::new(
            ParseStage::Inode,
            Some(root_offset),
            "root inode header out of bounds",
        ));
    }

    if !is_plausible_inode(image, root_offset, Some(1)) {
        return Some(ParseError::new(
            ParseStage::Inode,
            Some(root_offset),
            "root inode is not plausible",
        ));
    }

    match is_directory_inode(image, root_offset) {
        Ok(true) => None,
        Ok(false) => Some(ParseError::new(
            ParseStage::Inode,
            Some(root_offset),
            "root inode is not a directory",
        )),
        Err(error) => Some(ParseError::new(
            ParseStage::Inode,
            Some(root_offset),
            format!("failed to classify root inode: {error}"),
        )),
    }
}

fn locate_xattrs_tolerant(
    image: &Image,
    inodes: &[Inode],
) -> Vec<std::result::Result<XattrRegion, ParseError>> {
    let mut regions = Vec::new();

    for inode in inodes {
        match validate_xattr_region_tolerant(image, inode) {
            Ok(Some(region)) => regions.push(Ok(region)),
            Ok(None) => {}
            Err(errors) => regions.extend(errors.into_iter().map(Err)),
        }
    }

    regions
}

fn validate_xattr_region_tolerant(
    image: &Image,
    inode: &Inode,
) -> std::result::Result<Option<XattrRegion>, Vec<ParseError>> {
    let mut errors = Vec::new();

    if inode
        .offset
        .checked_add(4)
        .is_none_or(|end| end > image.len())
    {
        return Err(vec![ParseError::new(
            ParseStage::Xattr,
            Some(inode.offset),
            "inode xattr count out of bounds",
        )]);
    }

    let data = image.as_bytes();
    let i_xattr_icount = u16::from_le_bytes([data[inode.offset + 2], data[inode.offset + 3]]);
    if i_xattr_icount == 0 {
        return Ok(None);
    }

    let xattr_size = xattr_ibody_size_tolerant(i_xattr_icount).map_err(|reason| {
        vec![ParseError::new(
            ParseStage::Xattr,
            Some(inode.offset + 2),
            reason,
        )]
    })?;
    let inode_size = inode_size_tolerant(image, inode.offset).map_err(|reason| {
        vec![ParseError::new(
            ParseStage::Xattr,
            Some(inode.offset),
            reason,
        )]
    })?;
    let xattr_offset = match inode.offset.checked_add(inode_size) {
        Some(offset) => offset,
        None => {
            return Err(vec![ParseError::new(
                ParseStage::Xattr,
                Some(inode.offset),
                "inline xattr offset overflows",
            )]);
        }
    };
    let xattr_end = match xattr_offset.checked_add(xattr_size) {
        Some(end) => end,
        None => {
            return Err(vec![ParseError::new(
                ParseStage::Xattr,
                Some(xattr_offset),
                "inline xattr size overflows",
            )]);
        }
    };
    if xattr_end > image.len() {
        return Err(vec![ParseError::new(
            ParseStage::Xattr,
            Some(xattr_offset),
            format!(
                "inline xattr region out of bounds (size={xattr_size}, image_len={})",
                image.len()
            ),
        )]);
    }

    let shared_count = data[xattr_offset + 4];
    let shared_bytes = (shared_count as usize)
        .checked_mul(XATTR_SHARED_ENTRY_SIZE)
        .ok_or_else(|| {
            vec![ParseError::new(
                ParseStage::Xattr,
                Some(xattr_offset + 4),
                format!("inline xattr shared count {shared_count} overflows"),
            )]
        })?;
    let shared_end = XATTR_HEADER_SIZE.checked_add(shared_bytes).ok_or_else(|| {
        vec![ParseError::new(
            ParseStage::Xattr,
            Some(xattr_offset + 4),
            format!("inline xattr shared count {shared_count} overflows"),
        )]
    })?;
    if shared_end > xattr_size {
        errors.push(ParseError::new(
            ParseStage::Xattr,
            Some(xattr_offset),
            format!("inline xattr shared entries exceed region size (shared_count={shared_count}, size={xattr_size})"),
        ));
    }

    for rel in 5..XATTR_HEADER_SIZE {
        if data[xattr_offset + rel] != 0 {
            errors.push(ParseError::new(
                ParseStage::Xattr,
                Some(xattr_offset + rel),
                "inline xattr header reserved byte is nonzero",
            ));
            break;
        }
    }

    if errors.is_empty() {
        Ok(Some(XattrRegion {
            inode_nid: inode.nid,
            offset: xattr_offset,
            size: xattr_size,
            shared_count,
            desc: format!("{}_xattr", inode.desc),
        }))
    } else {
        Err(errors)
    }
}

fn xattr_ibody_size_tolerant(i_xattr_icount: u16) -> std::result::Result<usize, String> {
    if i_xattr_icount == 0 {
        return Ok(0);
    }

    XATTR_HEADER_SIZE
        .checked_add(
            ((i_xattr_icount as usize) - 1)
                .checked_mul(XATTR_SHARED_ENTRY_SIZE)
                .ok_or_else(|| format!("inode xattr body size overflows: {i_xattr_icount}"))?,
        )
        .ok_or_else(|| format!("inode xattr body size overflows: {i_xattr_icount}"))
}

fn inode_size_tolerant(image: &Image, inode_offset: usize) -> std::result::Result<usize, String> {
    if inode_offset
        .checked_add(2)
        .is_none_or(|end| end > image.len())
    {
        return Err("inode format out of bounds".to_string());
    }
    let data = image.as_bytes();
    let i_format = u16::from_le_bytes([data[inode_offset], data[inode_offset + 1]]);
    Ok(if (i_format & 0x01) != 0 { 64 } else { 32 })
}

fn round_up_tolerant(value: usize, align: usize) -> std::result::Result<usize, String> {
    if align == 0 || !align.is_power_of_two() {
        return Err(format!("invalid alignment {align}"));
    }
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
        .ok_or_else(|| format!("round_up({value}, {align}) overflows"))
}

fn locate_chunks_tolerant(
    image: &Image,
    sb: &Superblock,
    inodes: &[Inode],
) -> Vec<std::result::Result<ChunkMap, ParseError>> {
    let mut chunks = Vec::new();

    for inode in inodes {
        match validate_chunk_map_tolerant(image, sb, inode) {
            Ok(Some(map)) => chunks.push(Ok(map)),
            Ok(None) => {}
            Err(errors) => chunks.extend(errors.into_iter().map(Err)),
        }
    }

    chunks
}

fn validate_chunk_map_tolerant(
    image: &Image,
    sb: &Superblock,
    inode: &Inode,
) -> std::result::Result<Option<ChunkMap>, Vec<ParseError>> {
    let mut errors = Vec::new();

    if inode
        .offset
        .checked_add(0x14)
        .is_none_or(|end| end > image.len())
    {
        return Err(vec![ParseError::new(
            ParseStage::Chunk,
            Some(inode.offset),
            "chunk inode header out of bounds",
        )]);
    }

    let data = image.as_bytes();
    let i_format = u16::from_le_bytes([data[inode.offset], data[inode.offset + 1]]);
    let datalayout = (i_format >> 1) & 0x7;
    if datalayout != EROFS_INODE_CHUNK_BASED {
        return Ok(None);
    }

    let chunk_format = u16::from_le_bytes([data[inode.offset + 0x10], data[inode.offset + 0x11]]);
    if chunk_format & !EROFS_CHUNK_FORMAT_ALL != 0 {
        errors.push(ParseError::new(
            ParseStage::Chunk,
            Some(inode.offset + 0x10),
            format!("unsupported chunk format bits 0x{chunk_format:04X}"),
        ));
    }
    let reserved = u16::from_le_bytes([data[inode.offset + 0x12], data[inode.offset + 0x13]]);
    if reserved != 0 {
        errors.push(ParseError::new(
            ParseStage::Chunk,
            Some(inode.offset + 0x12),
            "chunk info reserved field is nonzero",
        ));
    }

    let chunk_extra_bits = chunk_format & EROFS_CHUNK_FORMAT_BLKBITS_MASK;
    let chunk_bits = u16::from(sb.blkszbits)
        .checked_add(chunk_extra_bits)
        .ok_or_else(|| {
            vec![ParseError::new(
                ParseStage::Chunk,
                Some(inode.offset + 0x10),
                "chunk bits overflow",
            )]
        })?;
    if chunk_bits >= usize::BITS as u16 {
        errors.push(ParseError::new(
            ParseStage::Chunk,
            Some(inode.offset + 0x10),
            format!("chunk bits {chunk_bits} exceed host usize width"),
        ));
    }

    let inode_size = match inode_size_tolerant(image, inode.offset) {
        Ok(size) => size,
        Err(reason) => {
            errors.push(ParseError::new(
                ParseStage::Chunk,
                Some(inode.offset),
                reason,
            ));
            0
        }
    };
    let xattr_size = if inode
        .offset
        .checked_add(4)
        .is_none_or(|end| end > image.len())
    {
        errors.push(ParseError::new(
            ParseStage::Chunk,
            Some(inode.offset),
            "chunk inode xattr count out of bounds",
        ));
        0
    } else {
        let i_xattr_icount = u16::from_le_bytes([data[inode.offset + 2], data[inode.offset + 3]]);
        match xattr_ibody_size_tolerant(i_xattr_icount) {
            Ok(size) => size,
            Err(reason) => {
                errors.push(ParseError::new(
                    ParseStage::Chunk,
                    Some(inode.offset + 2),
                    reason,
                ));
                0
            }
        }
    };
    let map_offset = match inode
        .offset
        .checked_add(inode_size)
        .and_then(|offset| offset.checked_add(xattr_size))
    {
        Some(offset) => offset,
        None => {
            return Err(vec![ParseError::new(
                ParseStage::Chunk,
                Some(inode.offset),
                "chunk map offset overflows",
            )]);
        }
    };

    let i_size = match inode_file_size(image, inode.offset) {
        Ok(size) => size,
        Err(error) => {
            errors.push(ParseError::new(
                ParseStage::Chunk,
                Some(inode.offset),
                format!("failed to read chunk inode size: {error}"),
            ));
            0
        }
    };
    let chunk_size = if chunk_bits < usize::BITS as u16 {
        1usize.checked_shl(u32::from(chunk_bits)).unwrap_or(0)
    } else {
        0
    };
    let entry_count = if i_size == 0 || chunk_size == 0 {
        0
    } else {
        let chunk_size_u64 = u64::try_from(chunk_size).map_err(|_| {
            vec![ParseError::new(
                ParseStage::Chunk,
                Some(inode.offset + 0x10),
                "chunk size does not fit u64",
            )]
        })?;
        let chunks = i_size.checked_add(chunk_size_u64 - 1).ok_or_else(|| {
            vec![ParseError::new(
                ParseStage::Chunk,
                Some(inode.offset),
                "chunk count overflows",
            )]
        })? / chunk_size_u64;
        match usize::try_from(chunks) {
            Ok(count) => count,
            Err(_) => {
                errors.push(ParseError::new(
                    ParseStage::Chunk,
                    Some(inode.offset),
                    "chunk count does not fit host usize",
                ));
                0
            }
        }
    };
    let entry_size = if chunk_format & EROFS_CHUNK_FORMAT_INDEXES != 0 {
        EROFS_CHUNK_INDEX_ENTRY_SIZE
    } else {
        EROFS_BLOCK_MAP_ENTRY_SIZE
    };
    let map_size = match entry_count.checked_mul(entry_size) {
        Some(size) => size,
        None => {
            return Err(vec![ParseError::new(
                ParseStage::Chunk,
                Some(map_offset),
                "chunk map size overflows",
            )]);
        }
    };
    if map_offset
        .checked_add(map_size)
        .is_none_or(|end| end > image.len())
    {
        errors.push(ParseError::new(
            ParseStage::Chunk,
            Some(map_offset),
            format!("chunk map out of bounds (entries={entry_count}, entry_size={entry_size})"),
        ));
    }

    if errors.is_empty() {
        Ok(Some(ChunkMap {
            inode_nid: inode.nid,
            offset: map_offset,
            entry_size,
            entry_count,
            chunk_bits: u8::try_from(chunk_bits).unwrap_or(u8::MAX),
            desc: format!("{}_chunk_map", inode.desc),
        }))
    } else {
        Err(errors)
    }
}

fn locate_compressions_tolerant(
    image: &Image,
    sb: &Superblock,
    inodes: &[Inode],
) -> Vec<std::result::Result<CompressionMap, ParseError>> {
    let mut maps = Vec::new();

    for inode in inodes {
        match validate_compression_map_tolerant(image, sb, inode) {
            Ok(Some(map)) => maps.push(Ok(map)),
            Ok(None) => {}
            Err(errors) => maps.extend(errors.into_iter().map(Err)),
        }
    }

    maps
}

fn validate_compression_map_tolerant(
    image: &Image,
    sb: &Superblock,
    inode: &Inode,
) -> std::result::Result<Option<CompressionMap>, Vec<ParseError>> {
    let mut errors = Vec::new();

    if inode
        .offset
        .checked_add(2)
        .is_none_or(|end| end > image.len())
    {
        return Err(vec![ParseError::new(
            ParseStage::Compression,
            Some(inode.offset),
            "compressed inode format out of bounds",
        )]);
    }

    let data = image.as_bytes();
    let i_format = u16::from_le_bytes([data[inode.offset], data[inode.offset + 1]]);
    let datalayout = (i_format >> 1) & 0x7;
    if datalayout != EROFS_INODE_COMPRESSED_FULL && datalayout != EROFS_INODE_COMPRESSED_COMPACT {
        return Ok(None);
    }

    let inode_size = match inode_size_tolerant(image, inode.offset) {
        Ok(size) => size,
        Err(reason) => {
            errors.push(ParseError::new(
                ParseStage::Compression,
                Some(inode.offset),
                reason,
            ));
            0
        }
    };
    let xattr_size = if inode
        .offset
        .checked_add(4)
        .is_none_or(|end| end > image.len())
    {
        errors.push(ParseError::new(
            ParseStage::Compression,
            Some(inode.offset),
            "compressed inode xattr count out of bounds",
        ));
        0
    } else {
        let i_xattr_icount = u16::from_le_bytes([data[inode.offset + 2], data[inode.offset + 3]]);
        match xattr_ibody_size_tolerant(i_xattr_icount) {
            Ok(size) => size,
            Err(reason) => {
                errors.push(ParseError::new(
                    ParseStage::Compression,
                    Some(inode.offset + 2),
                    reason,
                ));
                0
            }
        }
    };
    let map_end = match inode
        .offset
        .checked_add(inode_size)
        .and_then(|offset| offset.checked_add(xattr_size))
    {
        Some(offset) => offset,
        None => {
            return Err(vec![ParseError::new(
                ParseStage::Compression,
                Some(inode.offset),
                "compressed map header offset overflows",
            )]);
        }
    };
    let map_offset = match round_up_tolerant(map_end, 8) {
        Ok(offset) => offset,
        Err(reason) => {
            return Err(vec![ParseError::new(
                ParseStage::Compression,
                Some(map_end),
                reason,
            )]);
        }
    };

    if map_offset
        .checked_add(Z_EROFS_MAP_HEADER_SIZE)
        .is_none_or(|end| end > image.len())
    {
        return Err(vec![ParseError::new(
            ParseStage::Compression,
            Some(map_offset),
            "compressed map header out of bounds",
        )]);
    }

    let advise = u16::from_le_bytes([data[map_offset + 0x04], data[map_offset + 0x05]]);
    let algorithmtype = data[map_offset + 0x06];
    let h_clusterbits = data[map_offset + 0x07];
    let fragment_packed = h_clusterbits & Z_EROFS_FRAGMENT_INODE_BIT != 0;

    if fragment_packed {
        return Ok(Some(CompressionMap {
            inode_nid: inode.nid,
            offset: map_offset,
            advise: Z_EROFS_ADVISE_FRAGMENT_PCLUSTER,
            algorithm_head1: 0,
            algorithm_head2: 0,
            cluster_bits: sb.blkszbits,
            fragment_packed,
            desc: format!("{}_compression", inode.desc),
        }));
    }

    if advise & !Z_EROFS_ADVISE_KNOWN_MASK != 0 {
        errors.push(ParseError::new(
            ParseStage::Compression,
            Some(map_offset + 0x04),
            format!("unsupported compression advise bits 0x{advise:04X}"),
        ));
    }
    let algorithm_head1 = algorithmtype & 0x0F;
    let algorithm_head2 = algorithmtype >> 4;
    if algorithm_head1 >= Z_EROFS_COMPRESSION_MAX {
        errors.push(ParseError::new(
            ParseStage::Compression,
            Some(map_offset + 0x06),
            format!("invalid HEAD1 compression algorithm {algorithm_head1}"),
        ));
    }
    if algorithm_head2 >= Z_EROFS_COMPRESSION_MAX {
        errors.push(ParseError::new(
            ParseStage::Compression,
            Some(map_offset + 0x06),
            format!("invalid HEAD2 compression algorithm {algorithm_head2}"),
        ));
    }

    if h_clusterbits & Z_EROFS_CLUSTERBITS_RESERVED_MASK != 0 {
        errors.push(ParseError::new(
            ParseStage::Compression,
            Some(map_offset + 0x07),
            format!("reserved compression cluster bits 0x{h_clusterbits:02X}"),
        ));
    }
    let cluster_extra_bits = h_clusterbits & Z_EROFS_CLUSTERBITS_MASK;
    let cluster_bits = match sb.blkszbits.checked_add(cluster_extra_bits) {
        Some(bits) => bits,
        None => {
            errors.push(ParseError::new(
                ParseStage::Compression,
                Some(map_offset + 0x07),
                "compression cluster bits overflow",
            ));
            u8::MAX
        }
    };
    if cluster_bits >= usize::BITS as u8 {
        errors.push(ParseError::new(
            ParseStage::Compression,
            Some(map_offset + 0x07),
            format!("compression cluster bits {cluster_bits} exceed host usize width"),
        ));
    }

    if datalayout == EROFS_INODE_COMPRESSED_COMPACT {
        let big1 = advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1 != 0;
        let big2 = advise & Z_EROFS_ADVISE_BIG_PCLUSTER_2 != 0;
        if big1 ^ big2 {
            errors.push(ParseError::new(
                ParseStage::Compression,
                Some(map_offset + 0x04),
                "compact compression big pcluster bits are inconsistent",
            ));
        }
    }

    if errors.is_empty() {
        Ok(Some(CompressionMap {
            inode_nid: inode.nid,
            offset: map_offset,
            advise,
            algorithm_head1,
            algorithm_head2,
            cluster_bits,
            fragment_packed,
            desc: format!("{}_compression", inode.desc),
        }))
    } else {
        Err(errors)
    }
}

fn locate_devices_tolerant(
    image: &Image,
    sb: &Superblock,
) -> Vec<std::result::Result<DeviceSlot, ParseError>> {
    let mut slots = Vec::new();
    let has_device_table = sb.feature_incompat & EROFS_FEATURE_INCOMPAT_DEVICE_TABLE != 0;

    if !has_device_table {
        if sb.extra_devices != 0 {
            slots.push(Err(ParseError::new(
                ParseStage::Device,
                Some(EROFS_SUPER_OFFSET + 0x56),
                "extra devices advertised without device table feature",
            )));
        }
        return slots;
    }
    if sb.extra_devices == 0 {
        return slots;
    }

    let slot_count = usize::from(sb.extra_devices);
    let table_offset = match usize::from(sb.devt_slotoff).checked_mul(EROFS_DEVT_SLOT_SIZE) {
        Some(offset) => offset,
        None => {
            return vec![Err(ParseError::new(
                ParseStage::Device,
                Some(EROFS_SUPER_OFFSET + 0x58),
                "device table offset overflows",
            ))];
        }
    };
    let table_size = match slot_count.checked_mul(EROFS_DEVT_SLOT_SIZE) {
        Some(size) => size,
        None => {
            return vec![Err(ParseError::new(
                ParseStage::Device,
                Some(table_offset),
                "device table size overflows",
            ))];
        }
    };
    if table_offset
        .checked_add(table_size)
        .is_none_or(|end| end > image.len())
    {
        return vec![Err(ParseError::new(
            ParseStage::Device,
            Some(table_offset),
            format!(
                "device table out of bounds (slots={}, image_len={})",
                sb.extra_devices,
                image.len()
            ),
        ))];
    }

    for index in 0..slot_count {
        let offset = match index
            .checked_mul(EROFS_DEVT_SLOT_SIZE)
            .and_then(|relative| table_offset.checked_add(relative))
        {
            Some(offset) => offset,
            None => {
                slots.push(Err(ParseError::new(
                    ParseStage::Device,
                    Some(table_offset),
                    "device slot offset overflows",
                )));
                break;
            }
        };
        match validate_device_slot_tolerant(image, sb, index, offset) {
            Ok(slot) => slots.push(Ok(slot)),
            Err(errors) => slots.extend(errors.into_iter().map(Err)),
        }
    }

    slots
}

fn validate_device_slot_tolerant(
    image: &Image,
    sb: &Superblock,
    index: usize,
    offset: usize,
) -> std::result::Result<DeviceSlot, Vec<ParseError>> {
    let mut errors = Vec::new();
    let data = image.as_bytes();

    let blocks_lo_offset = offset.checked_add(0x40).ok_or_else(|| {
        vec![ParseError::new(
            ParseStage::Device,
            Some(offset),
            "device blocks_lo offset overflows",
        )]
    })?;
    let uniaddr_lo_offset = offset.checked_add(0x44).ok_or_else(|| {
        vec![ParseError::new(
            ParseStage::Device,
            Some(offset),
            "device uniaddr_lo offset overflows",
        )]
    })?;
    let blocks_hi_offset = offset.checked_add(0x48).ok_or_else(|| {
        vec![ParseError::new(
            ParseStage::Device,
            Some(offset),
            "device blocks_hi offset overflows",
        )]
    })?;
    let uniaddr_hi_offset = offset.checked_add(0x4A).ok_or_else(|| {
        vec![ParseError::new(
            ParseStage::Device,
            Some(offset),
            "device uniaddr_hi offset overflows",
        )]
    })?;
    let reserved_offset = offset
        .checked_add(EROFS_DEVT_SLOT_RESERVED_OFFSET)
        .ok_or_else(|| {
            vec![ParseError::new(
                ParseStage::Device,
                Some(offset),
                "device reserved offset overflows",
            )]
        })?;

    let tag_first = data[offset];
    if tag_first == 0 {
        errors.push(ParseError::new(
            ParseStage::Device,
            Some(offset),
            "device slot tag is empty",
        ));
    }

    let read_u16 =
        |field_offset: usize, field: &str| -> std::result::Result<u16, Vec<ParseError>> {
            let end = field_offset.checked_add(2).ok_or_else(|| {
                vec![ParseError::new(
                    ParseStage::Device,
                    Some(field_offset),
                    format!("device {field} field end overflows"),
                )]
            })?;
            let bytes = data.get(field_offset..end).ok_or_else(|| {
                vec![ParseError::new(
                    ParseStage::Device,
                    Some(field_offset),
                    format!("device {field} field out of bounds"),
                )]
            })?;
            Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
        };
    let read_u32 =
        |field_offset: usize, field: &str| -> std::result::Result<u32, Vec<ParseError>> {
            let end = field_offset.checked_add(4).ok_or_else(|| {
                vec![ParseError::new(
                    ParseStage::Device,
                    Some(field_offset),
                    format!("device {field} field end overflows"),
                )]
            })?;
            let bytes = data.get(field_offset..end).ok_or_else(|| {
                vec![ParseError::new(
                    ParseStage::Device,
                    Some(field_offset),
                    format!("device {field} field out of bounds"),
                )]
            })?;
            Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        };

    let blocks_lo = read_u32(blocks_lo_offset, "blocks_lo")?;
    let uniaddr_lo = read_u32(uniaddr_lo_offset, "uniaddr_lo")?;
    let has_48bit = sb.feature_incompat & EROFS_FEATURE_INCOMPAT_48BIT != 0;
    let blocks = u64::from(blocks_lo)
        | if has_48bit {
            u64::from(read_u16(blocks_hi_offset, "blocks_hi")?) << 32
        } else {
            0
        };
    let uniaddr = u64::from(uniaddr_lo)
        | if has_48bit {
            u64::from(read_u16(uniaddr_hi_offset, "uniaddr_hi")?) << 32
        } else {
            0
        };
    if blocks == 0 {
        errors.push(ParseError::new(
            ParseStage::Device,
            Some(blocks_lo_offset),
            "device slot has zero blocks",
        ));
    }

    let reserved_end = offset.checked_add(EROFS_DEVT_SLOT_SIZE).ok_or_else(|| {
        vec![ParseError::new(
            ParseStage::Device,
            Some(offset),
            "device slot end overflows",
        )]
    })?;
    if let Some((rel, _)) = data[reserved_offset..reserved_end]
        .iter()
        .enumerate()
        .find(|(_, byte)| **byte != 0)
    {
        errors.push(ParseError::new(
            ParseStage::Device,
            Some(reserved_offset + rel),
            "device slot reserved byte is nonzero",
        ));
    }

    if errors.is_empty() {
        let index = u16::try_from(index).map_err(|_| {
            vec![ParseError::new(
                ParseStage::Device,
                Some(offset),
                "device slot index does not fit u16",
            )]
        })?;
        Ok(DeviceSlot {
            index,
            offset,
            blocks,
            uniaddr,
            tag_first,
            desc: format!("device_slot_{index}"),
        })
    } else {
        Err(errors)
    }
}

fn locate_dirents_tolerant(
    image: &Image,
    sb: &Superblock,
    inodes: &[Inode],
) -> Vec<std::result::Result<Dirent, ParseError>> {
    let mut dirents = Vec::new();

    for inode in inodes {
        match is_directory_inode(image, inode.offset) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                dirents.push(Err(ParseError::new(
                    ParseStage::Dirent,
                    Some(inode.offset),
                    format!("failed to classify directory inode: {error}"),
                )));
                continue;
            }
        }

        let data_start = match inode_data_offset(image, sb, inode.offset) {
            Ok(offset) => offset,
            Err(error) => {
                dirents.push(Err(ParseError::new(
                    ParseStage::Dirent,
                    Some(inode.offset),
                    format!("failed to locate directory data: {error}"),
                )));
                continue;
            }
        };
        let data = image.as_bytes();
        if data_start
            .checked_add(12)
            .is_none_or(|end| end > data.len())
        {
            dirents.push(Err(ParseError::new(
                ParseStage::Dirent,
                Some(data_start),
                "directory data header out of bounds",
            )));
            continue;
        }

        let i_size = match inode_file_size(image, inode.offset) {
            Ok(size) => size,
            Err(error) => {
                dirents.push(Err(ParseError::new(
                    ParseStage::Dirent,
                    Some(inode.offset),
                    format!("failed to read directory size: {error}"),
                )));
                continue;
            }
        };
        let available = data.len().saturating_sub(data_start);
        let dir_len = usize::try_from(i_size).unwrap_or(usize::MAX).min(available);
        let block_size = sb.block_size as usize;

        let mut entry_idx = 0u32;
        let mut block_rel = 0usize;
        while block_rel < dir_len {
            let block_start = match data_start.checked_add(block_rel) {
                Some(offset) => offset,
                None => {
                    dirents.push(Err(ParseError::new(
                        ParseStage::Dirent,
                        Some(data_start),
                        "directory block offset overflows",
                    )));
                    break;
                }
            };
            let maxsize = (dir_len - block_rel).min(block_size);
            if maxsize < 12
                || block_start
                    .checked_add(12)
                    .is_none_or(|end| end > data.len())
            {
                dirents.push(Err(ParseError::new(
                    ParseStage::Dirent,
                    Some(block_start),
                    "directory block too small for dirent header",
                )));
                break;
            }

            let nameoff =
                u16::from_le_bytes([data[block_start + 8], data[block_start + 9]]) as usize;
            if nameoff == 0 || nameoff >= block_size || nameoff % 12 != 0 || nameoff > maxsize {
                dirents.push(Err(ParseError::new(
                    ParseStage::Dirent,
                    Some(block_start + 8),
                    format!(
                        "invalid dirent nameoff {nameoff} (block_size={block_size}, maxsize={maxsize})"
                    ),
                )));
                block_rel = match block_rel.checked_add(block_size) {
                    Some(next) => next,
                    None => break,
                };
                continue;
            }

            let Some(headers_end) = block_start.checked_add(nameoff) else {
                dirents.push(Err(ParseError::new(
                    ParseStage::Dirent,
                    Some(block_start),
                    "dirent header end overflows",
                )));
                break;
            };
            let mut offset = block_start;
            while offset
                .checked_add(12)
                .is_some_and(|end| end <= headers_end && end <= data.len())
            {
                let mut valid_dirent = true;
                if let Some(error) = validate_dirent_nid_tolerant(image, sb, offset) {
                    dirents.push(Err(error));
                    valid_dirent = false;
                }
                let file_type = data[offset + 10];
                if file_type > 7 {
                    dirents.push(Err(ParseError::new(
                        ParseStage::Dirent,
                        Some(offset),
                        format!("invalid dirent file_type {file_type}"),
                    )));
                    valid_dirent = false;
                }
                if valid_dirent {
                    dirents.push(Ok(Dirent {
                        offset,
                        parent_nid: inode.nid,
                        entry_idx,
                        desc: format!("{}_entry{entry_idx}", inode.desc),
                    }));
                }
                offset += 12;
                entry_idx += 1;
            }

            let Some(next_block) = block_rel.checked_add(block_size) else {
                break;
            };
            block_rel = next_block;
        }
    }

    dirents
}

fn validate_dirent_nid_tolerant(
    image: &Image,
    sb: &Superblock,
    offset: usize,
) -> Option<ParseError> {
    if offset.checked_add(8).is_none_or(|end| end > image.len()) {
        return Some(ParseError::new(
            ParseStage::Dirent,
            Some(offset),
            "dirent nid out of bounds",
        ));
    }

    let data = image.as_bytes();
    let nid = u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);
    let nid_slot = match usize::try_from(nid) {
        Ok(slot) => slot,
        Err(_) => {
            return Some(ParseError::new(
                ParseStage::Dirent,
                Some(offset),
                format!("dirent nid {nid} does not fit host usize"),
            ));
        }
    };
    let inode_offset = match nid_slot
        .checked_mul(INODE_SLOT_SIZE)
        .and_then(|slot_offset| sb.meta_offset.checked_add(slot_offset))
    {
        Some(inode_offset) => inode_offset,
        None => {
            return Some(ParseError::new(
                ParseStage::Dirent,
                Some(offset),
                format!("dirent nid {nid} inode offset overflows"),
            ));
        }
    };

    if inode_offset
        .checked_add(INODE_SLOT_SIZE)
        .is_none_or(|end| end > image.len())
    {
        return Some(ParseError::new(
            ParseStage::Dirent,
            Some(offset),
            format!("dirent nid {nid} inode header out of bounds"),
        ));
    }

    if !is_plausible_inode(image, inode_offset, None) {
        return Some(ParseError::new(
            ParseStage::Dirent,
            Some(offset),
            format!("dirent nid {nid} is not a plausible inode"),
        ));
    }

    None
}
