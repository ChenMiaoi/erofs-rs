#![no_main]

mod common;

use erofs_rs::{Image, ParseMode, parse_image};
use libfuzzer_sys::fuzz_target;

const EROFS_INODE_COMPRESSED_COMPACT: u16 = 3;

fn inode_size(bytes: &[u8], inode_offset: usize) -> Option<usize> {
    let format = common::read_u16_le(bytes, inode_offset)?;
    Some(if format & 0x01 != 0 { 64 } else { 32 })
}

fn fill(bytes: &mut [u8], offset: usize, len: usize, value: u8) -> bool {
    let Some(end) = offset.checked_add(len) else {
        return false;
    };
    let Some(field) = bytes.get_mut(offset..end) else {
        return false;
    };
    field.fill(value);
    true
}

fn round_up(value: usize, align: usize) -> Option<usize> {
    if align == 0 || !align.is_power_of_two() {
        return None;
    }
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
}

fuzz_target!(|data: &[u8]| {
    let mut bytes = common::seed_image();
    let Some(inode) = common::first_non_root_inode(&bytes) else {
        return;
    };
    let Some(original_format) = common::read_u16_le(&bytes, inode.offset) else {
        return;
    };
    let Some(inode_size) = inode_size(&bytes, inode.offset) else {
        return;
    };
    let Some(xattr_count_offset) = inode.offset.checked_add(0x02) else {
        return;
    };
    let Some(map_end) = inode.offset.checked_add(inode_size) else {
        return;
    };
    let Some(map_offset) = round_up(map_end, 8) else {
        return;
    };

    let compressed_layout = (original_format & 0x01) | (EROFS_INODE_COMPRESSED_COMPACT << 1);
    if !common::write_u16_le(&mut bytes, inode.offset, compressed_layout) {
        return;
    }
    if !common::write_u16_le(&mut bytes, xattr_count_offset, 0) {
        return;
    }
    fill(&mut bytes, map_offset, 8, 0);
    common::overlay(&mut bytes, map_offset, data);

    let image = Image::new(bytes);
    let _ = parse_image(&image, ParseMode::FuzzTolerant);
});
