use crate::cli::{BundleArgs, BundleCheckArgs};
use crate::finding_bundle::{
    BundleArtifact, BundleFileRef, FINDING_BUNDLE_SCHEMA, FindingBundleManifest,
    parse_finding_bundle_manifest, validate_finding_bundle_manifest,
};
use crate::fuzz::{FuzzArtifactSidecar, parse_fuzz_artifact_sidecar};
use crate::kernel_replay::parse_kernel_replay_report;
use crate::oracle::parse_oracle_json_report;
use crate::replay::parse_replay_report;
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug)]
enum OptionalReportKind {
    Replay,
    Oracle,
    Kernel,
}

impl OptionalReportKind {
    fn field(self) -> &'static str {
        match self {
            Self::Replay => "replay_report",
            Self::Oracle => "oracle_report",
            Self::Kernel => "kernel_report",
        }
    }
}

fn read_sidecar(path: &Path) -> Result<FuzzArtifactSidecar> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read bundle sidecar {}", path.display()))?;
    parse_fuzz_artifact_sidecar(&content)
        .with_context(|| format!("failed to parse bundle sidecar {}", path.display()))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to hash {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn require_existing(path: PathBuf, field: &str) -> Result<PathBuf> {
    if !path.exists() {
        bail!("{field} file not found: {}", path.display());
    }
    Ok(path)
}

fn resolve_recorded_path(sidecar_path: &Path, recorded_path: &str, field: &str) -> Result<PathBuf> {
    let recorded = PathBuf::from(recorded_path);
    if recorded.exists() {
        return Ok(recorded);
    }

    if let Some(file_name) = recorded.file_name() {
        let sibling = sidecar_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(file_name);
        if sibling.exists() {
            return Ok(sibling);
        }
    }

    require_existing(recorded, field)
}

fn resolve_artifact(
    sidecar_path: &Path,
    sidecar: &FuzzArtifactSidecar,
    override_path: Option<&str>,
) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return require_existing(PathBuf::from(path), "artifact");
    }
    resolve_recorded_path(sidecar_path, &sidecar.artifact_path, "artifact")
}

fn resolve_optional_sidecar_file(
    sidecar_path: &Path,
    recorded_path: Option<&str>,
    override_path: Option<&str>,
    field: &str,
) -> Result<Option<PathBuf>> {
    if let Some(path) = override_path {
        return require_existing(PathBuf::from(path), field).map(Some);
    }
    recorded_path
        .filter(|path| !path.is_empty())
        .map(|path| resolve_recorded_path(sidecar_path, path, field))
        .transpose()
}

fn resolve_optional_report(path: Option<&str>, field: &str) -> Result<Option<PathBuf>> {
    path.map(|path| require_existing(PathBuf::from(path), field))
        .transpose()
}

fn validate_optional_json_report(
    path: Option<&PathBuf>,
    kind: OptionalReportKind,
    artifact_sha256: &str,
) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read {} {}", kind.field(), path.display()))?;
    if !content.trim_start().starts_with('{') {
        return Ok(());
    }

    match kind {
        OptionalReportKind::Replay => {
            let report = parse_replay_report(&content)
                .with_context(|| format!("failed to parse replay_report {}", path.display()))?;
            validate_report_sha256(
                "replay_report",
                path,
                artifact_sha256,
                &report.artifact_sha256,
            )
        }
        OptionalReportKind::Oracle => {
            let report = parse_oracle_json_report(&content)
                .with_context(|| format!("failed to parse oracle_report {}", path.display()))?;
            let Some(report_sha256) = report.input_sha256.as_deref() else {
                bail!("oracle_report missing input SHA-256 for {}", path.display());
            };
            validate_report_sha256("oracle_report", path, artifact_sha256, report_sha256)
        }
        OptionalReportKind::Kernel => {
            let report = parse_kernel_replay_report(&content)
                .with_context(|| format!("failed to parse kernel_report {}", path.display()))?;
            let Some(report_sha256) = report.artifact_sha256.as_deref() else {
                bail!(
                    "kernel_report missing artifact SHA-256 for {}",
                    path.display()
                );
            };
            validate_report_sha256("kernel_report", path, artifact_sha256, report_sha256)
        }
    }
}

fn validate_report_sha256(
    field: &str,
    path: &Path,
    bundle_sha256: &str,
    report_sha256: &str,
) -> Result<()> {
    if bundle_sha256 != report_sha256 {
        bail!(
            "{field} artifact SHA-256 mismatch for {}: bundle={}, report={}",
            path.display(),
            bundle_sha256,
            report_sha256
        );
    }
    Ok(())
}

fn validate_file_sha256(field: &str, path: &Path, expected_sha256: &str) -> Result<()> {
    let actual_sha256 = sha256_file(path)?;
    if actual_sha256 != expected_sha256 {
        bail!(
            "{field} SHA-256 mismatch for {}: expected={}, actual={}",
            path.display(),
            expected_sha256,
            actual_sha256
        );
    }
    Ok(())
}

fn portable_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn manifest_path(output_path: &Path, file_path: &Path) -> String {
    let base = output_path.parent().unwrap_or_else(|| Path::new("."));
    portable_path(file_path.strip_prefix(base).unwrap_or(file_path))
}

fn file_ref(output_path: &Path, path: &Path) -> Result<BundleFileRef> {
    Ok(BundleFileRef {
        path: manifest_path(output_path, path),
        sha256: Some(sha256_file(path)?),
    })
}

fn optional_file_ref(output_path: &Path, path: Option<&PathBuf>) -> Result<Option<BundleFileRef>> {
    path.map(|path| file_ref(output_path, path)).transpose()
}

fn resolve_bundle_path(manifest_path: &Path, recorded_path: &str, field: &str) -> Result<PathBuf> {
    let recorded = PathBuf::from(recorded_path);
    let path = if recorded.is_absolute() {
        recorded
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(recorded)
    };
    require_existing(path, field)
}

fn resolve_bundle_file_ref(
    manifest_path: &Path,
    field: &str,
    file_ref: &BundleFileRef,
) -> Result<PathBuf> {
    let path = resolve_bundle_path(manifest_path, &file_ref.path, field)?;
    if let Some(expected_sha256) = &file_ref.sha256 {
        validate_file_sha256(field, &path, expected_sha256)?;
    }
    Ok(path)
}

fn resolve_optional_bundle_file_ref(
    manifest_path: &Path,
    field: &str,
    file_ref: Option<&BundleFileRef>,
) -> Result<Option<PathBuf>> {
    file_ref
        .map(|file_ref| resolve_bundle_file_ref(manifest_path, field, file_ref))
        .transpose()
}

fn build_manifest(args: &BundleArgs) -> Result<FindingBundleManifest> {
    let sidecar_path = Path::new(&args.sidecar);
    let output_path = Path::new(&args.output);
    let sidecar = read_sidecar(sidecar_path)?;
    let artifact_path = resolve_artifact(sidecar_path, &sidecar, args.artifact.as_deref())?;
    let artifact_sha256 = sha256_file(&artifact_path)?;
    if artifact_sha256 != sidecar.artifact_sha256 {
        bail!(
            "artifact SHA-256 mismatch for {}: sidecar={}, actual={}",
            artifact_path.display(),
            sidecar.artifact_sha256,
            artifact_sha256
        );
    }

    let stdout_path = resolve_optional_sidecar_file(
        sidecar_path,
        Some(sidecar.stdout_path.as_str()),
        args.stdout.as_deref(),
        "stdout",
    )?;
    let stderr_path = resolve_optional_sidecar_file(
        sidecar_path,
        Some(sidecar.stderr_path.as_str()),
        args.stderr.as_deref(),
        "stderr",
    )?;
    let replay_report = resolve_optional_report(args.replay_report.as_deref(), "replay_report")?;
    let oracle_report = resolve_optional_report(args.oracle_report.as_deref(), "oracle_report")?;
    let kernel_report = resolve_optional_report(args.kernel_report.as_deref(), "kernel_report")?;
    validate_optional_json_report(
        replay_report.as_ref(),
        OptionalReportKind::Replay,
        &artifact_sha256,
    )?;
    validate_optional_json_report(
        oracle_report.as_ref(),
        OptionalReportKind::Oracle,
        &artifact_sha256,
    )?;
    validate_optional_json_report(
        kernel_report.as_ref(),
        OptionalReportKind::Kernel,
        &artifact_sha256,
    )?;

    let artifact_size = fs::metadata(&artifact_path)
        .with_context(|| format!("failed to stat artifact {}", artifact_path.display()))?
        .len();
    let manifest = FindingBundleManifest {
        schema: FINDING_BUNDLE_SCHEMA.to_string(),
        artifact: BundleArtifact {
            path: manifest_path(output_path, &artifact_path),
            sha256: artifact_sha256,
            size_bytes: Some(artifact_size),
        },
        sidecar: file_ref(output_path, sidecar_path)?,
        stdout: optional_file_ref(output_path, stdout_path.as_ref())?,
        stderr: optional_file_ref(output_path, stderr_path.as_ref())?,
        replay_report: optional_file_ref(output_path, replay_report.as_ref())?,
        oracle_report: optional_file_ref(output_path, oracle_report.as_ref())?,
        kernel_report: optional_file_ref(output_path, kernel_report.as_ref())?,
        classification: sidecar.classification,
        signature: sidecar.signature,
    };
    validate_finding_bundle_manifest(&manifest).map_err(|error| {
        anyhow::anyhow!("generated finding bundle manifest is invalid: {error}")
    })?;
    Ok(manifest)
}

pub fn run(args: &BundleArgs) -> Result<()> {
    let manifest = build_manifest(args)?;
    let output_path = Path::new(&args.output);
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create bundle manifest directory {}",
                parent.display()
            )
        })?;
    }
    let json = serde_json::to_string_pretty(&manifest)
        .context("failed to serialize finding bundle manifest")?;
    fs::write(output_path, json + "\n").with_context(|| {
        format!(
            "failed to write finding bundle manifest {}",
            output_path.display()
        )
    })?;

    println!("Finding bundle manifest: {}", output_path.display());
    println!("  Artifact: {}", manifest.artifact.path);
    println!("  Classification: {}", manifest.classification);
    println!("  Signature: {}", manifest.signature);
    Ok(())
}

pub fn check(args: &BundleCheckArgs) -> Result<()> {
    let manifest_path = Path::new(&args.manifest);
    let content = fs::read_to_string(manifest_path)
        .with_context(|| format!("failed to read finding bundle {}", manifest_path.display()))?;
    let manifest = parse_finding_bundle_manifest(&content)
        .with_context(|| format!("failed to parse finding bundle {}", manifest_path.display()))?;

    let artifact_path = resolve_bundle_path(manifest_path, &manifest.artifact.path, "artifact")?;
    validate_file_sha256("artifact", &artifact_path, &manifest.artifact.sha256)?;
    if let Some(expected_size) = manifest.artifact.size_bytes {
        let actual_size = fs::metadata(&artifact_path)
            .with_context(|| format!("failed to stat artifact {}", artifact_path.display()))?
            .len();
        if actual_size != expected_size {
            bail!(
                "artifact size mismatch for {}: expected={}, actual={}",
                artifact_path.display(),
                expected_size,
                actual_size
            );
        }
    }

    let sidecar_path = resolve_bundle_file_ref(manifest_path, "sidecar", &manifest.sidecar)?;
    let sidecar = read_sidecar(&sidecar_path)?;
    if sidecar.artifact_sha256 != manifest.artifact.sha256 {
        bail!(
            "sidecar artifact SHA-256 mismatch for {}: bundle={}, sidecar={}",
            sidecar_path.display(),
            manifest.artifact.sha256,
            sidecar.artifact_sha256
        );
    }

    resolve_optional_bundle_file_ref(manifest_path, "stdout", manifest.stdout.as_ref())?;
    resolve_optional_bundle_file_ref(manifest_path, "stderr", manifest.stderr.as_ref())?;
    let replay_report = resolve_optional_bundle_file_ref(
        manifest_path,
        "replay_report",
        manifest.replay_report.as_ref(),
    )?;
    let oracle_report = resolve_optional_bundle_file_ref(
        manifest_path,
        "oracle_report",
        manifest.oracle_report.as_ref(),
    )?;
    let kernel_report = resolve_optional_bundle_file_ref(
        manifest_path,
        "kernel_report",
        manifest.kernel_report.as_ref(),
    )?;

    validate_optional_json_report(
        replay_report.as_ref(),
        OptionalReportKind::Replay,
        &manifest.artifact.sha256,
    )?;
    validate_optional_json_report(
        oracle_report.as_ref(),
        OptionalReportKind::Oracle,
        &manifest.artifact.sha256,
    )?;
    validate_optional_json_report(
        kernel_report.as_ref(),
        OptionalReportKind::Kernel,
        &manifest.artifact.sha256,
    )?;

    println!("Finding bundle OK: {}", manifest_path.display());
    println!("  Artifact: {}", manifest.artifact.path);
    println!("  Classification: {}", manifest.classification);
    println!("  Signature: {}", manifest.signature);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_manifest, check, sha256_file};
    use crate::cli::{BundleArgs, BundleCheckArgs};
    use crate::finding_bundle::FindingBundleManifest;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn write_sidecar_fixture(
        sidecar: &Path,
        artifact: &Path,
        stdout: &Path,
        stderr: &Path,
        artifact_sha256: &str,
        classification: &str,
        signature: &str,
    ) {
        let sidecar_json = serde_json::json!({
            "schema": "erofs-rs.fuzz-artifact.v1",
            "tool": "erofs-rs",
            "tool_version": "0.1.0",
            "rng_seed": 1,
            "iteration": 1,
            "strategy": "mutation",
            "seed_name": "seed.erofs",
            "seed_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "artifact_sha256": artifact_sha256,
            "artifact_path": artifact.to_string_lossy(),
            "mutations": [
                {
                    "kind": "byte",
                    "offset": 7,
                    "width": "u8",
                    "old": "0x00",
                    "new": "0xff"
                }
            ],
            "commands": {
                "fsck": ["fsck.erofs", artifact.to_string_lossy()],
                "dump": ["dump.erofs", "-s", artifact.to_string_lossy()],
                "kernel_replay": [
                    "make",
                    "smoke-malformed",
                    format!("MALFORMED_IMG={}", artifact.display())
                ]
            },
            "versions": {
                "tool_git": null,
                "erofs_utils_git": null,
                "linux_git": null
            },
            "fsck_exit_code": 0,
            "fsck_timed_out": false,
            "fsck_kill_process_group": true,
            "fsck_killed_process_group": false,
            "fsck_rss_limit_mb": null,
            "stdout_truncated": false,
            "stderr_truncated": false,
            "classification": classification,
            "reason": "fsck accepted the image",
            "signature": signature,
            "stdout_path": stdout.to_string_lossy(),
            "stderr_path": stderr.to_string_lossy()
        });
        fs::write(
            sidecar,
            serde_json::to_string_pretty(&sidecar_json).unwrap(),
        )
        .unwrap();
    }

    fn write_replay_report_fixture(
        replay_report: &Path,
        sidecar: &Path,
        artifact: &Path,
        artifact_sha256: &str,
    ) {
        fs::write(
            replay_report,
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": "erofs-rs.replay-report.v1",
                "sidecar_path": sidecar.to_string_lossy(),
                "artifact_path": artifact.to_string_lossy(),
                "artifact_sha256": artifact_sha256,
                "fsck_path": "fsck.erofs",
                "rng_seed": 1,
                "iteration": 1,
                "strategy": "mutation",
                "seed_name": "seed.erofs",
                "original": {
                    "classification": "accepted_with_errors",
                    "reason": "fsck accepted the image",
                    "exit_code": 0,
                    "timed_out": false,
                    "signature": "accepted_with_errors: fsck printed errors"
                },
                "replay": {
                    "classification": "accepted_with_errors",
                    "reason": "fsck accepted the image",
                    "exit_code": 0,
                    "signal": null,
                    "timed_out": false,
                    "killed_process_group": false,
                    "rss_limit_mb": null,
                    "stdout_truncated": false,
                    "stderr_truncated": false
                },
                "comparison": {
                    "classification_match": true,
                    "exit_code_match": true,
                    "timeout_match": true,
                    "replay_match": true
                }
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn write_kernel_report_fixture(kernel_report: &Path, artifact_sha256: Option<&str>) {
        fs::write(
            kernel_report,
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": "erofs-rs.kernel-replay.v1",
                "artifact_sha256": artifact_sha256,
                "kernel_git": null,
                "qemu_exit_code": 0,
                "outcome": "accepted",
                "message": "mounted and traversed",
                "signature": "kernel_accepted: mounted and traversed",
                "dangerous_pattern": null
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn write_oracle_report_fixture(oracle_report: &Path, input_sha256: Option<&str>) {
        fs::write(
            oracle_report,
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": "erofs-rs.oracle-report.v1",
                "input": "fuzz_seed_iter1.erofs",
                "input_sha256": input_sha256,
                "checks": [
                    {
                        "name": "rust_parser",
                        "status": "accepted",
                        "classification": "accepted",
                        "reason": "ok"
                    }
                ],
                "matrix": [],
                "interesting_findings": 0
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn bundle_manifest_uses_sidecar_metadata_and_sibling_files() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let stdout = tmp.path().join("fuzz_seed_iter1.stdout.txt");
        let stderr = tmp.path().join("fuzz_seed_iter1.stderr.txt");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&stdout, b"stdout").unwrap();
        fs::write(&stderr, b"stderr").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        write_sidecar_fixture(
            &sidecar,
            Path::new("/stale/path/fuzz_seed_iter1.erofs"),
            Path::new("/stale/path/fuzz_seed_iter1.stdout.txt"),
            Path::new("/stale/path/fuzz_seed_iter1.stderr.txt"),
            &artifact_sha256,
            "sanitizer_crash",
            "sanitizer_crash: AddressSanitizer",
        );

        let args = BundleArgs {
            sidecar: sidecar.to_string_lossy().to_string(),
            artifact: None,
            stdout: None,
            stderr: None,
            replay_report: None,
            oracle_report: None,
            kernel_report: None,
            output: output.to_string_lossy().to_string(),
        };
        let manifest = build_manifest(&args).unwrap();

        assert_eq!(manifest.artifact.path, "fuzz_seed_iter1.erofs");
        assert_eq!(manifest.artifact.sha256, artifact_sha256);
        assert_eq!(manifest.artifact.size_bytes, Some(5));
        assert_eq!(manifest.sidecar.path, "fuzz_seed_iter1.json");
        assert_eq!(
            manifest.stdout.as_ref().unwrap().path,
            "fuzz_seed_iter1.stdout.txt"
        );
        assert_eq!(
            manifest.stderr.as_ref().unwrap().path,
            "fuzz_seed_iter1.stderr.txt"
        );
        assert_eq!(manifest.classification, "sanitizer_crash");
        assert_eq!(manifest.signature, "sanitizer_crash: AddressSanitizer");

        super::run(&args).unwrap();
        let written: FindingBundleManifest =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(written, manifest);
    }

    #[test]
    fn bundle_manifest_validates_json_replay_report() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let stdout = tmp.path().join("fuzz_seed_iter1.stdout.txt");
        let stderr = tmp.path().join("fuzz_seed_iter1.stderr.txt");
        let replay_report = tmp.path().join("replay-report.json");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&stdout, b"stdout").unwrap();
        fs::write(&stderr, b"stderr").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        write_sidecar_fixture(
            &sidecar,
            &artifact,
            &stdout,
            &stderr,
            &artifact_sha256,
            "accepted_with_errors",
            "accepted_with_errors: fsck printed errors",
        );
        write_replay_report_fixture(&replay_report, &sidecar, &artifact, &artifact_sha256);

        let args = BundleArgs {
            sidecar: sidecar.to_string_lossy().to_string(),
            artifact: None,
            stdout: None,
            stderr: None,
            replay_report: Some(replay_report.to_string_lossy().to_string()),
            oracle_report: None,
            kernel_report: None,
            output: output.to_string_lossy().to_string(),
        };
        let manifest = build_manifest(&args).unwrap();

        assert_eq!(
            manifest.replay_report.as_ref().unwrap().path,
            "replay-report.json"
        );
    }

    #[test]
    fn bundle_manifest_rejects_replay_report_hash_mismatch() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let stdout = tmp.path().join("fuzz_seed_iter1.stdout.txt");
        let stderr = tmp.path().join("fuzz_seed_iter1.stderr.txt");
        let replay_report = tmp.path().join("replay-report.json");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&stdout, b"stdout").unwrap();
        fs::write(&stderr, b"stderr").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        write_sidecar_fixture(
            &sidecar,
            &artifact,
            &stdout,
            &stderr,
            &artifact_sha256,
            "accepted_with_errors",
            "accepted_with_errors: fsck printed errors",
        );
        write_replay_report_fixture(&replay_report, &sidecar, &artifact, &"0".repeat(64));

        let args = BundleArgs {
            sidecar: sidecar.to_string_lossy().to_string(),
            artifact: None,
            stdout: None,
            stderr: None,
            replay_report: Some(replay_report.to_string_lossy().to_string()),
            oracle_report: None,
            kernel_report: None,
            output: output.to_string_lossy().to_string(),
        };

        let error = build_manifest(&args).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("replay_report artifact SHA-256 mismatch")
        );
    }

    #[test]
    fn bundle_manifest_validates_json_kernel_report_hash() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let stdout = tmp.path().join("fuzz_seed_iter1.stdout.txt");
        let stderr = tmp.path().join("fuzz_seed_iter1.stderr.txt");
        let kernel_report = tmp.path().join("kernel-replay.json");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&stdout, b"stdout").unwrap();
        fs::write(&stderr, b"stderr").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        write_sidecar_fixture(
            &sidecar,
            &artifact,
            &stdout,
            &stderr,
            &artifact_sha256,
            "accepted_with_errors",
            "accepted_with_errors: fsck printed errors",
        );
        write_kernel_report_fixture(&kernel_report, Some(&artifact_sha256));

        let args = BundleArgs {
            sidecar: sidecar.to_string_lossy().to_string(),
            artifact: None,
            stdout: None,
            stderr: None,
            replay_report: None,
            oracle_report: None,
            kernel_report: Some(kernel_report.to_string_lossy().to_string()),
            output: output.to_string_lossy().to_string(),
        };
        let manifest = build_manifest(&args).unwrap();

        assert_eq!(
            manifest.kernel_report.as_ref().unwrap().path,
            "kernel-replay.json"
        );
    }

    #[test]
    fn bundle_manifest_rejects_kernel_report_without_artifact_hash() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let stdout = tmp.path().join("fuzz_seed_iter1.stdout.txt");
        let stderr = tmp.path().join("fuzz_seed_iter1.stderr.txt");
        let kernel_report = tmp.path().join("kernel-replay.json");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&stdout, b"stdout").unwrap();
        fs::write(&stderr, b"stderr").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        write_sidecar_fixture(
            &sidecar,
            &artifact,
            &stdout,
            &stderr,
            &artifact_sha256,
            "accepted_with_errors",
            "accepted_with_errors: fsck printed errors",
        );
        write_kernel_report_fixture(&kernel_report, None);

        let args = BundleArgs {
            sidecar: sidecar.to_string_lossy().to_string(),
            artifact: None,
            stdout: None,
            stderr: None,
            replay_report: None,
            oracle_report: None,
            kernel_report: Some(kernel_report.to_string_lossy().to_string()),
            output: output.to_string_lossy().to_string(),
        };

        let error = build_manifest(&args).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("kernel_report missing artifact SHA-256")
        );
    }

    #[test]
    fn bundle_manifest_validates_json_oracle_report_hash() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let stdout = tmp.path().join("fuzz_seed_iter1.stdout.txt");
        let stderr = tmp.path().join("fuzz_seed_iter1.stderr.txt");
        let oracle_report = tmp.path().join("oracle-report.json");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&stdout, b"stdout").unwrap();
        fs::write(&stderr, b"stderr").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        write_sidecar_fixture(
            &sidecar,
            &artifact,
            &stdout,
            &stderr,
            &artifact_sha256,
            "accepted_with_errors",
            "accepted_with_errors: fsck printed errors",
        );
        write_oracle_report_fixture(&oracle_report, Some(&artifact_sha256));

        let args = BundleArgs {
            sidecar: sidecar.to_string_lossy().to_string(),
            artifact: None,
            stdout: None,
            stderr: None,
            replay_report: None,
            oracle_report: Some(oracle_report.to_string_lossy().to_string()),
            kernel_report: None,
            output: output.to_string_lossy().to_string(),
        };
        let manifest = build_manifest(&args).unwrap();

        assert_eq!(
            manifest.oracle_report.as_ref().unwrap().path,
            "oracle-report.json"
        );
    }

    #[test]
    fn bundle_manifest_rejects_oracle_report_without_input_hash() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let stdout = tmp.path().join("fuzz_seed_iter1.stdout.txt");
        let stderr = tmp.path().join("fuzz_seed_iter1.stderr.txt");
        let oracle_report = tmp.path().join("oracle-report.json");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&stdout, b"stdout").unwrap();
        fs::write(&stderr, b"stderr").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        write_sidecar_fixture(
            &sidecar,
            &artifact,
            &stdout,
            &stderr,
            &artifact_sha256,
            "accepted_with_errors",
            "accepted_with_errors: fsck printed errors",
        );
        write_oracle_report_fixture(&oracle_report, None);

        let args = BundleArgs {
            sidecar: sidecar.to_string_lossy().to_string(),
            artifact: None,
            stdout: None,
            stderr: None,
            replay_report: None,
            oracle_report: Some(oracle_report.to_string_lossy().to_string()),
            kernel_report: None,
            output: output.to_string_lossy().to_string(),
        };

        let error = build_manifest(&args).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("oracle_report missing input SHA-256")
        );
    }

    #[test]
    fn bundle_manifest_rejects_invalid_json_report() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let stdout = tmp.path().join("fuzz_seed_iter1.stdout.txt");
        let stderr = tmp.path().join("fuzz_seed_iter1.stderr.txt");
        let oracle_report = tmp.path().join("oracle-report.json");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&stdout, b"stdout").unwrap();
        fs::write(&stderr, b"stderr").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        write_sidecar_fixture(
            &sidecar,
            &artifact,
            &stdout,
            &stderr,
            &artifact_sha256,
            "accepted_with_errors",
            "accepted_with_errors: fsck printed errors",
        );
        fs::write(&oracle_report, r#"{"schema":"erofs-rs.oracle-report.v0"}"#).unwrap();

        let args = BundleArgs {
            sidecar: sidecar.to_string_lossy().to_string(),
            artifact: None,
            stdout: None,
            stderr: None,
            replay_report: None,
            oracle_report: Some(oracle_report.to_string_lossy().to_string()),
            kernel_report: None,
            output: output.to_string_lossy().to_string(),
        };

        let error = build_manifest(&args).unwrap_err();
        assert!(error.to_string().contains("failed to parse oracle_report"));
    }

    #[test]
    fn bundle_manifest_keeps_text_replay_reports_as_opaque_files() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let stdout = tmp.path().join("fuzz_seed_iter1.stdout.txt");
        let stderr = tmp.path().join("fuzz_seed_iter1.stderr.txt");
        let replay_report = tmp.path().join("replay-report.txt");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&stdout, b"stdout").unwrap();
        fs::write(&stderr, b"stderr").unwrap();
        fs::write(&replay_report, "# EROFS Fuzz Artifact Replay Report\n").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        write_sidecar_fixture(
            &sidecar,
            &artifact,
            &stdout,
            &stderr,
            &artifact_sha256,
            "accepted_with_errors",
            "accepted_with_errors: fsck printed errors",
        );

        let args = BundleArgs {
            sidecar: sidecar.to_string_lossy().to_string(),
            artifact: None,
            stdout: None,
            stderr: None,
            replay_report: Some(replay_report.to_string_lossy().to_string()),
            oracle_report: None,
            kernel_report: None,
            output: output.to_string_lossy().to_string(),
        };
        let manifest = build_manifest(&args).unwrap();

        assert_eq!(
            manifest.replay_report.as_ref().unwrap().path,
            "replay-report.txt"
        );
    }

    #[test]
    fn bundle_check_validates_written_bundle_attachments() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let stdout = tmp.path().join("fuzz_seed_iter1.stdout.txt");
        let stderr = tmp.path().join("fuzz_seed_iter1.stderr.txt");
        let replay_report = tmp.path().join("replay-report.json");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&stdout, b"stdout").unwrap();
        fs::write(&stderr, b"stderr").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        write_sidecar_fixture(
            &sidecar,
            &artifact,
            &stdout,
            &stderr,
            &artifact_sha256,
            "accepted_with_errors",
            "accepted_with_errors: fsck printed errors",
        );
        write_replay_report_fixture(&replay_report, &sidecar, &artifact, &artifact_sha256);

        let args = BundleArgs {
            sidecar: sidecar.to_string_lossy().to_string(),
            artifact: None,
            stdout: None,
            stderr: None,
            replay_report: Some(replay_report.to_string_lossy().to_string()),
            oracle_report: None,
            kernel_report: None,
            output: output.to_string_lossy().to_string(),
        };
        super::run(&args).unwrap();

        let check_args = BundleCheckArgs {
            manifest: output.to_string_lossy().to_string(),
        };
        check(&check_args).unwrap();
    }

    #[test]
    fn bundle_check_rejects_attachment_hash_mismatch() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let stdout = tmp.path().join("fuzz_seed_iter1.stdout.txt");
        let stderr = tmp.path().join("fuzz_seed_iter1.stderr.txt");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&stdout, b"stdout").unwrap();
        fs::write(&stderr, b"stderr").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        write_sidecar_fixture(
            &sidecar,
            &artifact,
            &stdout,
            &stderr,
            &artifact_sha256,
            "rejected_crash",
            "rejected_crash: SIGSEGV",
        );

        let args = BundleArgs {
            sidecar: sidecar.to_string_lossy().to_string(),
            artifact: None,
            stdout: None,
            stderr: None,
            replay_report: None,
            oracle_report: None,
            kernel_report: None,
            output: output.to_string_lossy().to_string(),
        };
        super::run(&args).unwrap();
        fs::write(&stdout, b"changed").unwrap();

        let check_args = BundleCheckArgs {
            manifest: output.to_string_lossy().to_string(),
        };
        let error = check(&check_args).unwrap_err();

        assert!(error.to_string().contains("stdout SHA-256 mismatch"));
    }
}
