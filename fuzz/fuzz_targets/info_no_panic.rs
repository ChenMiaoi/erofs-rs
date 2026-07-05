#![no_main]

use erofs_rs::{Image, fix_checksum, locate_dirents_in_image, locate_inodes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let image = Image::new(data.to_vec());

    if let Ok(sb) = image.superblock()
        && let Ok(inodes) = locate_inodes(&image, &sb)
    {
        let _ = locate_dirents_in_image(&image, &sb, &inodes);
    }

    let mut checksum_image = image.clone();
    let _ = fix_checksum(&mut checksum_image);
});
