#![no_main]

use erofs_rs::classify_fsck_result;
use libfuzzer_sys::fuzz_target;

fn exit_code(selector: u8) -> i32 {
    match selector % 8 {
        0 => 0,
        1 => 1,
        2 => 124,
        3 => 134,
        4 => 135,
        5 => 136,
        6 => 139,
        _ => -1,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };

    let split = rest
        .first()
        .map(|byte| usize::from(*byte) % rest.len().max(1))
        .unwrap_or(0);
    let stdout = String::from_utf8_lossy(&rest[..split]);
    let stderr = String::from_utf8_lossy(&rest[split..]);
    let (classification, reason) = classify_fsck_result(exit_code(selector), &stderr, &stdout);

    assert!(!classification.is_empty());
    assert!(!reason.is_empty());
});
