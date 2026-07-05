#![no_main]

use erofs_rs::Image;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let image = Image::new(data.to_vec());
    let _ = image.superblock();
});
