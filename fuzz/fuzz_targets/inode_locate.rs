#![no_main]

use erofs_rs::{Image, locate_inodes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let image = Image::new(data.to_vec());
    if let Ok(superblock) = image.superblock() {
        let _ = locate_inodes(&image, &superblock);
    }
});
