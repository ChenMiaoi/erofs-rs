use crate::dirent::{Dirent, locate_dirents_in_image};
use crate::image::{EROFS_SUPER_OFFSET, Image, Superblock};
use crate::inode::{Inode, inode_data_offset, inode_file_size, is_directory_inode, locate_inodes};
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
    Dirent,
}

impl fmt::Display for ParseStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Superblock => f.write_str("superblock"),
            Self::Inode => f.write_str("inode"),
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
    pub dirents: Vec<std::result::Result<Dirent, ParseError>>,
    pub errors: Vec<ParseError>,
    pub offsets_seen: BTreeSet<usize>,
}

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
                let file_type = data[offset + 10];
                if file_type > 7 {
                    dirents.push(Err(ParseError::new(
                        ParseStage::Dirent,
                        Some(offset),
                        format!("invalid dirent file_type {file_type}"),
                    )));
                } else {
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
