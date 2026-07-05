use crate::dirent::{Dirent, locate_dirents_in_image};
use crate::image::{EROFS_SUPER_OFFSET, Image, Superblock};
use crate::inode::{Inode, locate_inodes};
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
    let dirents = match locate_dirents_in_image(image, &superblock, &parsed_inodes) {
        Ok(dirents) => dirents,
        Err(error) => {
            if mode == ParseMode::Strict {
                return Err(error).context("strict dirent location failed");
            }
            let parse_error = ParseError::new(ParseStage::Dirent, None, error);
            report.dirents.push(Err(parse_error.clone()));
            report.errors.push(parse_error);
            Vec::new()
        }
    };

    for dirent in dirents {
        report.offsets_seen.insert(dirent.offset);
        report.dirents.push(Ok(dirent));
    }

    Ok(report)
}
