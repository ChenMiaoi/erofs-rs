use erofs_rs::{
    checksum::{crc32c, fix_checksum},
    dirent::locate_dirents_in_image,
    fsck::{run_fsck, run_fsck_with_timeout},
    image::{EROFS_SUPER_OFFSET, FieldWidth, Image, read_image, write_image},
    inode::locate_inodes,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
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
    fs::write(&script, "#!/bin/sh\nsleep 2\n").unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script, perms).unwrap();

    let result = run_fsck_with_timeout(
        &script,
        fixture("single.erofs"),
        &[],
        Duration::from_millis(50),
    )
    .unwrap();
    assert_eq!(result.classification, "rejected_timeout");
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
