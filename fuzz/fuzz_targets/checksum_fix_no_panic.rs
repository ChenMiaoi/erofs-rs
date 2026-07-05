#![no_main]

use erofs_rs::{Image, fix_checksum};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut image = Image::new(data.to_vec());
    let _ = fix_checksum(&mut image);
});
