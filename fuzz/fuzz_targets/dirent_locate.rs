#![no_main]

use erofs_rs::{Image, locate_dirents_in_image, locate_inodes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let image = Image::new(data.to_vec());
    if let Ok(superblock) = image.superblock() {
        if let Ok(inodes) = locate_inodes(&image, &superblock) {
            let _ = locate_dirents_in_image(&image, &superblock, &inodes);
        }
    }
});
