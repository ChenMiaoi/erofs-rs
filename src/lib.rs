//! erofs-rs: Advanced EROFS fuzzing and image injection tool.
//!
//! This crate provides a reusable library for parsing, mutating, and validating
//! EROFS filesystem images, plus a CLI front-end in `src/main.rs`.

pub mod checksum;
pub mod cli;
pub mod corpus;
pub mod dirent;
pub mod fsck;
pub mod fuzz;
pub mod image;
pub mod info;
pub mod inject;
pub mod inode;
pub mod mutate;
pub(crate) mod tui;

pub use checksum::{crc32c, fix_checksum};
pub use dirent::{Dirent, locate_dirents_in_image};
pub use fsck::{
    ExecLimits, FsckResult, classify_fsck_result, run_fsck, run_fsck_with_limits,
    run_fsck_with_timeout,
};
pub use image::{FieldWidth, Image, Superblock, read_image, write_image};
pub use inode::{Inode, locate_inodes};
