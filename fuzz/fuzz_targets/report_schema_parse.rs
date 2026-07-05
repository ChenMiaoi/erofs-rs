#![no_main]

use erofs_rs::{
    corpus::{parse_cmin_summary_report, parse_coverage_manifest},
    finding_bundle::parse_finding_bundle_manifest,
    fuzz::parse_fuzz_artifact_sidecar,
    kernel_replay::{parse_kernel_replay_report, parse_kernel_replay_summary},
    minimized::parse_minimized_manifest,
    oracle::parse_oracle_json_report,
    replay::parse_replay_report,
    seed_manifest::parse_seed_matrix_manifest,
    triage::{parse_bucket_database, parse_fuzz_bucket_report},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, content)) = data.split_first() else {
        return;
    };
    let content = String::from_utf8_lossy(content);

    match selector % 12 {
        0 => {
            let _ = parse_fuzz_artifact_sidecar(&content);
        }
        1 => {
            let _ = parse_fuzz_bucket_report(&content);
        }
        2 => {
            let _ = parse_bucket_database(&content);
        }
        3 => {
            let _ = parse_replay_report(&content);
        }
        4 => {
            let _ = parse_oracle_json_report(&content);
        }
        5 => {
            let _ = parse_kernel_replay_report(&content);
        }
        6 => {
            let _ = parse_kernel_replay_summary(&content);
        }
        7 => {
            let _ = parse_finding_bundle_manifest(&content);
        }
        8 => {
            let _ = parse_coverage_manifest(&content);
        }
        9 => {
            let _ = parse_cmin_summary_report(&content);
        }
        10 => {
            let _ = parse_seed_matrix_manifest(&content);
        }
        _ => {
            let _ = parse_minimized_manifest(&content);
        }
    }
});
