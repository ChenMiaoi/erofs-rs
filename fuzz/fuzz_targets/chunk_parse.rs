#![no_main]

mod common;

use erofs_rs::{Image, ParseMode, parse_image};
use libfuzzer_sys::fuzz_target;

const EROFS_INODE_CHUNK_BASED: u16 = 4;

fuzz_target!(|data: &[u8]| {
    let mut bytes = common::seed_image();
    let Some(inode) = common::first_non_root_inode(&bytes) else {
        return;
    };
    let Some(original_format) = common::read_u16_le(&bytes, inode.offset) else {
        return;
    };
    let Some(xattr_count_offset) = inode.offset.checked_add(0x02) else {
        return;
    };
    let Some(chunk_info_offset) = inode.offset.checked_add(0x10) else {
        return;
    };

    let chunk_layout = (original_format & 0x01) | (EROFS_INODE_CHUNK_BASED << 1);
    if !common::write_u16_le(&mut bytes, inode.offset, chunk_layout) {
        return;
    }
    if !common::write_u16_le(&mut bytes, xattr_count_offset, 0) {
        return;
    }
    common::overlay(&mut bytes, chunk_info_offset, data);

    let image = Image::new(bytes);
    let _ = parse_image(&image, ParseMode::FuzzTolerant);
});
