#![no_main]

use erofs_rs::{FieldWidth, Image, inject::inject_named_field};
use libfuzzer_sys::fuzz_target;

const SINGLE_EROFS: &[u8] = include_bytes!("../../tests/fixtures/single.erofs");

const FIELD_CASES: &[(&str, FieldWidth)] = &[
    ("superblock.magic", FieldWidth::U32),
    ("superblock.root_nid", FieldWidth::U16),
    ("superblock.feature_incompat", FieldWidth::U32),
    ("superblock.extra_devices", FieldWidth::U16),
    ("superblock.dirblkbits", FieldWidth::U8),
    ("superblock.root_nid_8b", FieldWidth::U64),
    ("inode.format", FieldWidth::U16),
    ("inode.xattr_icount", FieldWidth::U16),
    ("inode.mode", FieldWidth::U16),
    ("inode.ino", FieldWidth::U32),
    ("dirent.nid", FieldWidth::U64),
    ("dirent.nameoff", FieldWidth::U16),
    ("dirent.file_type", FieldWidth::U8),
];

const TARGET_HINTS: &[Option<&str>] = &[
    None,
    Some("root_directory"),
    Some("inode_39"),
    Some("root_directory_entry0"),
    Some("missing_target"),
];

fn fuzz_value(data: &[u8], width: FieldWidth) -> u64 {
    let mut bytes = [0; 8];
    let len = data.len().min(bytes.len());
    bytes[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(bytes) & width.max_value()
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let (field_name, width) = FIELD_CASES[data[0] as usize % FIELD_CASES.len()];
    let target_hint = TARGET_HINTS[data.get(1).copied().unwrap_or(0) as usize % TARGET_HINTS.len()];
    let value = fuzz_value(data.get(2..).unwrap_or(&[]), width);

    let mut seed_image = Image::new(SINGLE_EROFS.to_vec());
    let _ = inject_named_field(&mut seed_image, field_name, target_hint, value);

    let mut arbitrary_image = Image::new(data.to_vec());
    let _ = inject_named_field(&mut arbitrary_image, field_name, target_hint, value);
});
