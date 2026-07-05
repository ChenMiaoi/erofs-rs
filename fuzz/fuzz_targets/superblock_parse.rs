#![no_main]

use erofs_rs::{Image, ParseMode, parse_image};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let image = Image::new(data.to_vec());
    let _ = parse_image(&image, ParseMode::FuzzTolerant);
});
