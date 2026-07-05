use erofs_rs::{Image, Inode, ParseMode, parse_image};

const SINGLE_EROFS: &[u8] = include_bytes!("../../tests/fixtures/single.erofs");

pub fn seed_image() -> Vec<u8> {
    SINGLE_EROFS.to_vec()
}

pub fn first_non_root_inode(bytes: &[u8]) -> Option<Inode> {
    let image = Image::new(bytes.to_vec());
    let report = parse_image(&image, ParseMode::FuzzTolerant).ok()?;
    report
        .inodes
        .into_iter()
        .filter_map(Result::ok)
        .find(|inode| inode.desc != "root_directory")
}

pub fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let field = bytes.get(offset..end)?;
    Some(u16::from_le_bytes([field[0], field[1]]))
}

pub fn write_u16_le(bytes: &mut [u8], offset: usize, value: u16) -> bool {
    let Some(end) = offset.checked_add(2) else {
        return false;
    };
    let Some(field) = bytes.get_mut(offset..end) else {
        return false;
    };
    field.copy_from_slice(&value.to_le_bytes());
    true
}

pub fn overlay(bytes: &mut [u8], offset: usize, data: &[u8]) {
    if offset >= bytes.len() {
        return;
    }
    let len = data.len().min(bytes.len() - offset);
    bytes[offset..offset + len].copy_from_slice(&data[..len]);
}
