use erofs_rs::{
    checksum::{crc32c, fix_checksum},
    dirent::locate_dirents_in_image,
    fsck::{ExecLimits, run_fsck, run_fsck_with_limits, run_fsck_with_timeout},
    image::{EROFS_SUPER_OFFSET, FieldWidth, Image, read_image, write_image},
    inode::locate_inodes,
    parse::{ParseMode, ParseStage, parse_image},
};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn fsck_path() -> PathBuf {
    fixture("fsck.erofs")
}

#[test]
fn test_crc32c_known() {
    assert_eq!(crc32c(0xFFFFFFFF, b"123456789"), 486108540);
}

#[test]
fn test_fix_checksum_idempotent() {
    let mut img = read_image(fixture("single.erofs")).unwrap();
    let (old1, new1) = fix_checksum(&mut img).unwrap();
    assert_eq!(old1, new1);
    let (old2, new2) = fix_checksum(&mut img).unwrap();
    assert_eq!(new1, new2);
    assert_eq!(old2, new2);
}

#[test]
fn test_single_inodes() {
    let img = read_image(fixture("single.erofs")).unwrap();
    let info = img.superblock().unwrap();
    let inodes = locate_inodes(&img, &info).unwrap();
    assert_eq!(inodes.len(), 2);
    assert_eq!(inodes[0].nid, 36);
    assert_eq!(inodes[1].nid, 39);
}

#[test]
fn test_tree_inodes() {
    let img = read_image(fixture("tree.erofs")).unwrap();
    let info = img.superblock().unwrap();
    let inodes = locate_inodes(&img, &info).unwrap();
    assert_eq!(inodes.len() as u64, info.inos);
}

#[test]
fn test_dirents_single() {
    let img = read_image(fixture("single.erofs")).unwrap();
    let info = img.superblock().unwrap();
    let inodes = locate_inodes(&img, &info).unwrap();
    let dirents = locate_dirents_in_image(&img, &info, &inodes).unwrap();
    assert!(dirents.len() >= 3);
}

#[test]
fn test_valid_image_accepted() {
    let result = run_fsck(fsck_path(), fixture("single.erofs"), &[]).unwrap();
    assert_eq!(result.classification, "accepted");
}

#[test]
fn test_bad_magic_rejected() {
    let mut img = read_image(fixture("single.erofs")).unwrap();
    img.write_field(EROFS_SUPER_OFFSET, FieldWidth::U32, 0xDEADBEEF)
        .unwrap();

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("bad_magic.erofs");
    write_image(&path, &img).unwrap();

    let result = run_fsck(fsck_path(), &path, &[]).unwrap();
    assert!(
        ["rejected_io_error", "rejected_checksum", "rejected_other"]
            .contains(&result.classification.as_str())
    );
}

#[test]
fn test_invalid_blkszbits_returns_error() {
    let mut img = read_image(fixture("single.erofs")).unwrap();
    img.write_field(EROFS_SUPER_OFFSET + 0x0C, FieldWidth::U8, 0x20)
        .unwrap();

    let err = img.superblock().unwrap_err().to_string();
    assert!(err.contains("unsupported EROFS blkszbits"));
}

#[test]
fn test_zero_blkszbits_returns_error() {
    let mut img = read_image(fixture("single.erofs")).unwrap();
    img.write_field(EROFS_SUPER_OFFSET + 0x0C, FieldWidth::U8, 0)
        .unwrap();

    let err = img.superblock().unwrap_err().to_string();
    assert!(err.contains("unsupported EROFS blkszbits"));
}

#[test]
fn test_strict_parse_rejects_invalid_superblock() {
    let img = Image::new(vec![0; EROFS_SUPER_OFFSET + 0x5C]);
    let err = parse_image(&img, ParseMode::Strict)
        .unwrap_err()
        .to_string();
    assert!(err.contains("strict superblock parse failed"));
}

#[test]
fn test_tolerant_parse_records_superblock_error() {
    let img = Image::new(vec![0; EROFS_SUPER_OFFSET + 0x5C]);
    let report = parse_image(&img, ParseMode::FuzzTolerant).unwrap();

    assert!(report.superblock.is_none());
    assert_eq!(report.errors.len(), 1);
    assert_eq!(report.errors[0].stage, ParseStage::Superblock);
    assert_eq!(report.errors[0].offset, Some(EROFS_SUPER_OFFSET));
    assert!(report.offsets_seen.contains(&EROFS_SUPER_OFFSET));
}

#[test]
fn test_tolerant_parse_reports_valid_fixture_offsets() {
    let img = read_image(fixture("single.erofs")).unwrap();
    let report = parse_image(&img, ParseMode::FuzzTolerant).unwrap();

    assert!(report.superblock.is_some());
    assert!(report.errors.is_empty());
    assert_eq!(
        report.inodes.iter().filter(|entry| entry.is_ok()).count(),
        2
    );
    assert!(report.dirents.iter().filter(|entry| entry.is_ok()).count() >= 3);
    assert!(report.offsets_seen.contains(&EROFS_SUPER_OFFSET));
}

#[test]
fn test_read_field_rejects_offset_overflow() {
    let img = Image::new(vec![0; 8]);
    let err = img
        .read_field(usize::MAX, FieldWidth::U64)
        .unwrap_err()
        .to_string();
    assert!(err.contains("overflows"));
}

#[test]
fn test_write_field_rejects_truncating_value() {
    let mut img = Image::new(vec![0; 8]);
    let err = img
        .write_field(0, FieldWidth::U8, 0x100)
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not fit"));
}

#[test]
fn test_fsck_timeout_classified() {
    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("slow-fsck.sh");
    fs::write(&script, "sleep 2\n").unwrap();

    let extra_args = vec![script.to_string_lossy().to_string()];
    let result = run_fsck_with_timeout(
        "/bin/sh",
        fixture("single.erofs"),
        &extra_args,
        Duration::from_millis(50),
    )
    .unwrap();
    assert_eq!(result.classification, "rejected_timeout");
    assert!(result.timed_out);
}

#[test]
fn test_fsck_output_is_capped() {
    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("noisy-fsck.sh");
    fs::write(
        &script,
        "i=0\n\
         while [ \"$i\" -lt 200 ]; do printf x; i=$((i + 1)); done\n\
         i=0\n\
         while [ \"$i\" -lt 200 ]; do printf y >&2; i=$((i + 1)); done\n\
         exit 1\n",
    )
    .unwrap();

    let extra_args = vec![script.to_string_lossy().to_string()];
    let result = run_fsck_with_limits(
        "/bin/sh",
        fixture("single.erofs"),
        &extra_args,
        ExecLimits {
            timeout: Duration::from_secs(1),
            max_output_bytes: 32,
            ..ExecLimits::default()
        },
    )
    .unwrap();

    assert!(result.stdout_truncated);
    assert!(result.stderr_truncated);
    assert!(result.stdout.contains("truncated to 32 bytes"));
    assert!(result.stderr.contains("truncated to 32 bytes"));
}

#[cfg(unix)]
#[test]
fn test_fsck_timeout_kills_process_group() {
    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("spawns-child-fsck.sh");
    let pid_file = tmp.path().join("child.pid");
    fs::write(
        &script,
        "sleep 30 &\n\
         echo $! > \"$1\"\n\
         sleep 30\n",
    )
    .unwrap();

    let extra_args = vec![
        script.to_string_lossy().to_string(),
        pid_file.to_string_lossy().to_string(),
    ];
    let result = run_fsck_with_limits(
        "/bin/sh",
        fixture("single.erofs"),
        &extra_args,
        ExecLimits {
            timeout: Duration::from_millis(200),
            max_output_bytes: 1024,
            kill_process_group: true,
            rss_limit_mb: None,
        },
    )
    .unwrap();

    assert_eq!(result.classification, "rejected_timeout");
    assert!(result.timed_out);
    assert!(result.killed_process_group);

    let child_pid = fs::read_to_string(&pid_file).unwrap().trim().to_string();
    for _ in 0..20 {
        let status = std::process::Command::new("kill")
            .arg("-0")
            .arg(&child_pid)
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        if !status.success() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = std::process::Command::new("kill")
        .arg("-9")
        .arg(&child_pid)
        .status();
    panic!("fsck child process {child_pid} survived process-group timeout kill");
}

#[cfg(target_os = "linux")]
#[test]
fn test_fsck_rss_limit_sets_address_space_limit() {
    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("print-limit-fsck.sh");
    fs::write(&script, "ulimit -v\n").unwrap();

    let extra_args = vec![script.to_string_lossy().to_string()];
    let result = run_fsck_with_limits(
        "/bin/sh",
        fixture("single.erofs"),
        &extra_args,
        ExecLimits {
            timeout: Duration::from_secs(1),
            max_output_bytes: 1024,
            kill_process_group: true,
            rss_limit_mb: Some(64),
        },
    )
    .unwrap();

    assert_eq!(result.classification, "accepted");
    assert_eq!(result.rss_limit_mb, Some(64));
    assert_eq!(result.stdout.trim(), "65536");
}

#[test]
fn test_inject_field() {
    let tmp = TempDir::new().unwrap();
    let output = tmp.path().join("out.erofs");
    let manifest = tmp.path().join("out.manifest");

    let args = erofs_rs::cli::InjectArgs {
        input: fixture("single.erofs").to_string_lossy().to_string(),
        output: output.to_string_lossy().to_string(),
        field: Some("superblock.root_nid".to_string()),
        target: None,
        offset: None,
        width: None,
        value: "0x1234".to_string(),
        fix_checksum: true,
        manifest: Some(manifest.to_string_lossy().to_string()),
    };
    erofs_rs::inject::run(&args).unwrap();

    assert!(output.exists());
    assert!(manifest.exists());
}

#[test]
fn test_inject_late_superblock_field() {
    let tmp = TempDir::new().unwrap();
    let output = tmp.path().join("out.erofs");

    let args = erofs_rs::cli::InjectArgs {
        input: fixture("single.erofs").to_string_lossy().to_string(),
        output: output.to_string_lossy().to_string(),
        field: Some("superblock.feature_incompat".to_string()),
        target: None,
        offset: None,
        width: None,
        value: "0x80".to_string(),
        fix_checksum: true,
        manifest: None,
    };
    erofs_rs::inject::run(&args).unwrap();

    let img = read_image(&output).unwrap();
    assert_eq!(
        img.read_field(EROFS_SUPER_OFFSET + 0x50, FieldWidth::U32)
            .unwrap(),
        0x80
    );
}

#[test]
fn test_inject_offset() {
    let tmp = TempDir::new().unwrap();
    let output = tmp.path().join("out.erofs");

    let args = erofs_rs::cli::InjectArgs {
        input: fixture("single.erofs").to_string_lossy().to_string(),
        output: output.to_string_lossy().to_string(),
        field: None,
        target: None,
        offset: Some("0x40E".to_string()),
        width: Some("u16".to_string()),
        value: "0xFFFF".to_string(),
        fix_checksum: true,
        manifest: None,
    };
    erofs_rs::inject::run(&args).unwrap();

    assert!(output.exists());
}

#[test]
fn test_mutate_superblock() {
    let tmp = TempDir::new().unwrap();
    let out_dir = tmp.path().join("sb");
    let manifest = tmp.path().join("manifest.txt");

    let args = erofs_rs::cli::MutateArgs {
        input: fixture("single.erofs").to_string_lossy().to_string(),
        output_dir: out_dir.to_string_lossy().to_string(),
        manifest: manifest.to_string_lossy().to_string(),
        fsck: fsck_path().to_string_lossy().to_string(),
        target: "superblock".to_string(),
        fix_checksum: true,
    };
    erofs_rs::mutate::run(&args).unwrap();

    assert!(manifest.exists());
    assert!(fs::read_dir(&out_dir).unwrap().count() > 0);
}

#[test]
fn test_mutate_inode() {
    let tmp = TempDir::new().unwrap();
    let out_dir = tmp.path().join("inode");
    let manifest = tmp.path().join("manifest.txt");

    let args = erofs_rs::cli::MutateArgs {
        input: fixture("single.erofs").to_string_lossy().to_string(),
        output_dir: out_dir.to_string_lossy().to_string(),
        manifest: manifest.to_string_lossy().to_string(),
        fsck: fsck_path().to_string_lossy().to_string(),
        target: "inode".to_string(),
        fix_checksum: true,
    };
    erofs_rs::mutate::run(&args).unwrap();

    assert!(manifest.exists());
}

#[test]
fn test_mutate_dirent() {
    let tmp = TempDir::new().unwrap();
    let out_dir = tmp.path().join("dirent");
    let manifest = tmp.path().join("manifest.txt");

    let args = erofs_rs::cli::MutateArgs {
        input: fixture("single.erofs").to_string_lossy().to_string(),
        output_dir: out_dir.to_string_lossy().to_string(),
        manifest: manifest.to_string_lossy().to_string(),
        fsck: fsck_path().to_string_lossy().to_string(),
        target: "dirent".to_string(),
        fix_checksum: true,
    };
    erofs_rs::mutate::run(&args).unwrap();

    assert!(manifest.exists());
}

#[test]
fn test_corpus_manager() {
    let tmp = TempDir::new().unwrap();
    let mutated = tmp.path().join("mutated");
    let artifacts = tmp.path().join("artifacts");
    let report = tmp.path().join("report.txt");
    fs::create_dir(&mutated).unwrap();

    let img = read_image(fixture("single.erofs")).unwrap();
    let mut mutated_img = img.clone();
    mutated_img
        .write_field(EROFS_SUPER_OFFSET, FieldWidth::U32, 0)
        .unwrap();
    let img_path = mutated.join("dummy_sb_magic_zero.erofs");
    write_image(&img_path, &mutated_img).unwrap();

    fs::write(
        mutated.join("manifest.txt"),
        "dummy_sb_magic_zero.erofs magic zero 0x00000000 rejected_io_error I/O error\n",
    )
    .unwrap();

    let args = erofs_rs::cli::CorpusArgs {
        input_dir: mutated.to_string_lossy().to_string(),
        output_dir: artifacts.to_string_lossy().to_string(),
        report: report.to_string_lossy().to_string(),
    };
    erofs_rs::corpus::run(&args).unwrap();

    assert!(report.exists());
}

#[test]
fn test_oracle_report_with_dump_check() {
    let tmp = TempDir::new().unwrap();
    let report = tmp.path().join("oracle-report.txt");

    let args = erofs_rs::cli::OracleArgs {
        input: fixture("single.erofs").to_string_lossy().to_string(),
        fsck: fsck_path().to_string_lossy().to_string(),
        dump: Some("/bin/true".to_string()),
        report: Some(report.to_string_lossy().to_string()),
        exec_timeout: 1,
        max_output_bytes: 1024,
        no_kill_process_group: false,
        rss_limit_mb: None,
    };
    erofs_rs::oracle::run(&args).unwrap();

    let content = fs::read_to_string(&report).unwrap();
    assert!(content.contains("rust_parser: accepted"));
    assert!(content.contains("fsck: accepted"));
    assert!(content.contains("dump: accepted"));
    assert!(content.contains("rust_parser_vs_fsck: agree"));
    assert!(content.contains("interesting_findings: 0"));
}
