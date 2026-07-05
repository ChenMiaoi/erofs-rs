#![no_main]

use erofs_rs::{Image, ParseMode, parse_image};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let image = Image::new(data.to_vec());
    let strict = parse_image(&image, ParseMode::Strict);
    let tolerant = parse_image(&image, ParseMode::FuzzTolerant);

    if strict.is_ok() && tolerant.is_err() {
        panic!("tolerant parser rejected an image accepted by strict parser");
    }
});
