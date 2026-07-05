#![no_main]

use erofs_rs::kernel_replay::{build_kernel_replay_report, classify_dmesg_text};
use libfuzzer_sys::fuzz_target;

fn qemu_exit_code(selector: u8) -> i32 {
    match selector % 4 {
        0 => 0,
        1 => 1,
        2 => 124,
        _ => -1,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, dmesg_bytes)) = data.split_first() else {
        return;
    };

    let qemu_exit_code = qemu_exit_code(selector);
    let dmesg = String::from_utf8_lossy(dmesg_bytes);
    let verdict = classify_dmesg_text(&dmesg, qemu_exit_code);
    let report = build_kernel_replay_report(&dmesg, qemu_exit_code, None, None);

    assert_eq!(report.qemu_exit_code, qemu_exit_code);
    assert_eq!(report.outcome, verdict.outcome);
    assert_eq!(report.message, verdict.message);
    assert_eq!(report.signature, verdict.signature);
    assert_eq!(report.dangerous_pattern, verdict.dangerous_pattern);
});
