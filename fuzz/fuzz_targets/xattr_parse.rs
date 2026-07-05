#![no_main]

mod common;

use erofs_rs::{Image, ParseMode, parse_image};
use libfuzzer_sys::fuzz_target;

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

fuzz_target!(|data: &[u8]| {
    let mut bytes = common::seed_image();
    let Some(inode) = common::first_non_root_inode(&bytes) else {
        return;
    };
    let Some(inode_size) = inode_size(&bytes, inode.offset) else {
        return;
    };
    let Some(xattr_count_offset) = inode.offset.checked_add(0x02) else {
        return;
    };
    let Some(xattr_offset) = inode.offset.checked_add(inode_size) else {
        return;
    };

    let xattr_count = u16::from(data.first().copied().unwrap_or(0) % 4) + 1;
    if !common::write_u16_le(&mut bytes, xattr_count_offset, xattr_count) {
        return;
    }
    fill(&mut bytes, xattr_offset, 24, 0);
    common::overlay(&mut bytes, xattr_offset, data);

    let image = Image::new(bytes);
    let _ = parse_image(&image, ParseMode::FuzzTolerant);
});
