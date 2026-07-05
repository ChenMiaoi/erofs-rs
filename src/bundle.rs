use crate::cli::BundleArgs;
use crate::finding_bundle::{
    BundleArtifact, BundleFileRef, FINDING_BUNDLE_SCHEMA, FindingBundleManifest,
    validate_finding_bundle_manifest,
};
use crate::kernel_replay::parse_kernel_replay_report;
use crate::oracle::parse_oracle_json_report;
use crate::replay::parse_replay_report;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

const FUZZ_ARTIFACT_SCHEMA: &str = "erofs-rs.fuzz-artifact.v1";

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

#[derive(Clone, Debug, Deserialize)]
struct BundleSidecar {
    schema: String,
    artifact_path: String,
    artifact_sha256: String,
    classification: String,
    signature: String,
    stdout_path: Option<String>,
    stderr_path: Option<String>,
}

fn read_sidecar(path: &Path) -> Result<BundleSidecar> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read bundle sidecar {}", path.display()))?;
    let sidecar: BundleSidecar = serde_json::from_str(&content)
        .with_context(|| format!("failed to decode bundle sidecar {}", path.display()))?;
    if sidecar.schema != FUZZ_ARTIFACT_SCHEMA {
        bail!(
            "unsupported fuzz sidecar schema {} in {}",
            sidecar.schema,
            path.display()
        );
    }
    Ok(sidecar)
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
    sidecar: &BundleSidecar,
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

fn validate_optional_json_report(path: Option<&PathBuf>, kind: OptionalReportKind) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read {} {}", kind.field(), path.display()))?;
    if !content.trim_start().starts_with('{') {
        return Ok(());
    }

    match kind {
        OptionalReportKind::Replay => parse_replay_report(&content)
            .map(|_| ())
            .with_context(|| format!("failed to parse replay_report {}", path.display())),
        OptionalReportKind::Oracle => parse_oracle_json_report(&content)
            .map(|_| ())
            .with_context(|| format!("failed to parse oracle_report {}", path.display())),
        OptionalReportKind::Kernel => parse_kernel_replay_report(&content)
            .map(|_| ())
            .with_context(|| format!("failed to parse kernel_report {}", path.display())),
    }
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
        sidecar.stdout_path.as_deref(),
        args.stdout.as_deref(),
        "stdout",
    )?;
    let stderr_path = resolve_optional_sidecar_file(
        sidecar_path,
        sidecar.stderr_path.as_deref(),
        args.stderr.as_deref(),
        "stderr",
    )?;
    let replay_report = resolve_optional_report(args.replay_report.as_deref(), "replay_report")?;
    let oracle_report = resolve_optional_report(args.oracle_report.as_deref(), "oracle_report")?;
    let kernel_report = resolve_optional_report(args.kernel_report.as_deref(), "kernel_report")?;
    validate_optional_json_report(replay_report.as_ref(), OptionalReportKind::Replay)?;
    validate_optional_json_report(oracle_report.as_ref(), OptionalReportKind::Oracle)?;
    validate_optional_json_report(kernel_report.as_ref(), OptionalReportKind::Kernel)?;

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

#[cfg(test)]
mod tests {
    use super::{build_manifest, sha256_file};
    use crate::cli::BundleArgs;
    use crate::finding_bundle::FindingBundleManifest;
    use std::fs;
    use tempfile::TempDir;

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
        let sidecar_json = serde_json::json!({
            "schema": "erofs-rs.fuzz-artifact.v1",
            "artifact_path": "/stale/path/fuzz_seed_iter1.erofs",
            "artifact_sha256": artifact_sha256,
            "classification": "sanitizer_crash",
            "signature": "sanitizer_crash: AddressSanitizer",
            "stdout_path": "/stale/path/fuzz_seed_iter1.stdout.txt",
            "stderr_path": "/stale/path/fuzz_seed_iter1.stderr.txt"
        });
        fs::write(
            &sidecar,
            serde_json::to_string_pretty(&sidecar_json).unwrap(),
        )
        .unwrap();

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
        let replay_report = tmp.path().join("replay-report.json");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        fs::write(
            &sidecar,
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": "erofs-rs.fuzz-artifact.v1",
                "artifact_path": artifact.to_string_lossy(),
                "artifact_sha256": artifact_sha256,
                "classification": "accepted",
                "signature": "accepted: fsck accepted the image"
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &replay_report,
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
                    "classification": "accepted",
                    "reason": "fsck accepted the image",
                    "exit_code": 0,
                    "timed_out": false,
                    "signature": "accepted: fsck accepted the image"
                },
                "replay": {
                    "classification": "accepted",
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
    fn bundle_manifest_rejects_invalid_json_report() {
        let tmp = TempDir::new().unwrap();
        let artifact = tmp.path().join("fuzz_seed_iter1.erofs");
        let sidecar = tmp.path().join("fuzz_seed_iter1.json");
        let oracle_report = tmp.path().join("oracle-report.json");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        fs::write(
            &sidecar,
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": "erofs-rs.fuzz-artifact.v1",
                "artifact_path": artifact.to_string_lossy(),
                "artifact_sha256": artifact_sha256,
                "classification": "accepted",
                "signature": "accepted: fsck accepted the image"
            }))
            .unwrap(),
        )
        .unwrap();
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
        let replay_report = tmp.path().join("replay-report.txt");
        let output = tmp.path().join("bundle.json");
        fs::write(&artifact, b"image").unwrap();
        fs::write(&replay_report, "# EROFS Fuzz Artifact Replay Report\n").unwrap();
        let artifact_sha256 = sha256_file(&artifact).unwrap();
        fs::write(
            &sidecar,
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": "erofs-rs.fuzz-artifact.v1",
                "artifact_path": artifact.to_string_lossy(),
                "artifact_sha256": artifact_sha256,
                "classification": "accepted",
                "signature": "accepted: fsck accepted the image"
            }))
            .unwrap(),
        )
        .unwrap();

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
}
