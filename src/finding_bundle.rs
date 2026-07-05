use crate::fuzz::OutcomeKind;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

pub const FINDING_BUNDLE_SCHEMA: &str = "erofs-rs.finding-bundle.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingBundleManifest {
    pub schema: String,
    pub artifact: BundleArtifact,
    pub sidecar: BundleFileRef,
    pub stdout: Option<BundleFileRef>,
    pub stderr: Option<BundleFileRef>,
    pub replay_report: Option<BundleFileRef>,
    pub oracle_report: Option<BundleFileRef>,
    pub kernel_report: Option<BundleFileRef>,
    pub classification: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleArtifact {
    pub path: String,
    pub sha256: String,
    pub size_bytes: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFileRef {
    pub path: String,
    pub sha256: Option<String>,
}

#[derive(Debug, Error)]
pub enum FindingBundleError {
    #[error("failed to decode finding bundle manifest: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unsupported finding bundle schema: {0}")]
    UnsupportedSchema(String),
    #[error("finding bundle field {0} is empty")]
    EmptyField(&'static str),
    #[error("finding bundle field {field} has invalid SHA-256 digest: {sha256}")]
    InvalidSha256 { field: &'static str, sha256: String },
    #[error("finding bundle manifest contains duplicate path: {0}")]
    DuplicatePath(String),
    #[error("finding bundle classification {classification} is not actionable")]
    NonActionableClassification { classification: String },
    #[error("finding bundle signature {signature} does not match classification {classification}")]
    SignatureClassificationMismatch {
        classification: String,
        signature: String,
    },
}

pub fn parse_finding_bundle_manifest(
    content: &str,
) -> Result<FindingBundleManifest, FindingBundleError> {
    let manifest: FindingBundleManifest = serde_json::from_str(content)?;
    validate_finding_bundle_manifest(&manifest)?;
    Ok(manifest)
}

pub fn validate_finding_bundle_manifest(
    manifest: &FindingBundleManifest,
) -> Result<(), FindingBundleError> {
    if manifest.schema != FINDING_BUNDLE_SCHEMA {
        return Err(FindingBundleError::UnsupportedSchema(
            manifest.schema.clone(),
        ));
    }
    require_nonempty("artifact.path", &manifest.artifact.path)?;
    require_sha256("artifact.sha256", &manifest.artifact.sha256)?;
    validate_file_ref("sidecar", &manifest.sidecar)?;
    validate_optional_file_ref("stdout", manifest.stdout.as_ref())?;
    validate_optional_file_ref("stderr", manifest.stderr.as_ref())?;
    validate_optional_file_ref("replay_report", manifest.replay_report.as_ref())?;
    validate_optional_file_ref("oracle_report", manifest.oracle_report.as_ref())?;
    validate_optional_file_ref("kernel_report", manifest.kernel_report.as_ref())?;
    validate_unique_paths(manifest)?;
    require_nonempty("classification", &manifest.classification)?;
    require_nonempty("signature", &manifest.signature)?;
    validate_finding_identity(&manifest.classification, &manifest.signature)?;
    Ok(())
}

fn validate_finding_identity(
    classification: &str,
    signature: &str,
) -> Result<(), FindingBundleError> {
    if !OutcomeKind::from_classification(classification).is_finding() {
        return Err(FindingBundleError::NonActionableClassification {
            classification: classification.to_string(),
        });
    }

    let signature_prefix = format!("{classification}: ");
    if signature != classification && !signature.starts_with(&signature_prefix) {
        return Err(FindingBundleError::SignatureClassificationMismatch {
            classification: classification.to_string(),
            signature: signature.to_string(),
        });
    }
    Ok(())
}

fn validate_unique_paths(manifest: &FindingBundleManifest) -> Result<(), FindingBundleError> {
    let mut paths = HashSet::new();
    record_path(&mut paths, &manifest.artifact.path)?;
    record_path(&mut paths, &manifest.sidecar.path)?;
    record_optional_path(&mut paths, manifest.stdout.as_ref())?;
    record_optional_path(&mut paths, manifest.stderr.as_ref())?;
    record_optional_path(&mut paths, manifest.replay_report.as_ref())?;
    record_optional_path(&mut paths, manifest.oracle_report.as_ref())?;
    record_optional_path(&mut paths, manifest.kernel_report.as_ref())
}

fn record_optional_path<'a>(
    paths: &mut HashSet<&'a str>,
    file_ref: Option<&'a BundleFileRef>,
) -> Result<(), FindingBundleError> {
    if let Some(file_ref) = file_ref {
        record_path(paths, &file_ref.path)?;
    }
    Ok(())
}

fn record_path<'a>(paths: &mut HashSet<&'a str>, path: &'a str) -> Result<(), FindingBundleError> {
    if !paths.insert(path) {
        return Err(FindingBundleError::DuplicatePath(path.to_string()));
    }
    Ok(())
}

fn validate_optional_file_ref(
    field: &'static str,
    file_ref: Option<&BundleFileRef>,
) -> Result<(), FindingBundleError> {
    if let Some(file_ref) = file_ref {
        validate_file_ref(field, file_ref)?;
    }
    Ok(())
}

fn validate_file_ref(
    field: &'static str,
    file_ref: &BundleFileRef,
) -> Result<(), FindingBundleError> {
    require_nonempty(file_ref_path_field(field), &file_ref.path)?;
    if let Some(sha256) = &file_ref.sha256 {
        require_sha256(file_ref_sha_field(field), sha256)?;
    }
    Ok(())
}

fn file_ref_path_field(field: &'static str) -> &'static str {
    match field {
        "sidecar" => "sidecar.path",
        "stdout" => "stdout.path",
        "stderr" => "stderr.path",
        "replay_report" => "replay_report.path",
        "oracle_report" => "oracle_report.path",
        "kernel_report" => "kernel_report.path",
        _ => "file.path",
    }
}

fn file_ref_sha_field(field: &'static str) -> &'static str {
    match field {
        "sidecar" => "sidecar.sha256",
        "stdout" => "stdout.sha256",
        "stderr" => "stderr.sha256",
        "replay_report" => "replay_report.sha256",
        "oracle_report" => "oracle_report.sha256",
        "kernel_report" => "kernel_report.sha256",
        _ => "file.sha256",
    }
}

fn require_nonempty(field: &'static str, value: &str) -> Result<(), FindingBundleError> {
    if value.is_empty() {
        return Err(FindingBundleError::EmptyField(field));
    }
    Ok(())
}

fn require_sha256(field: &'static str, value: &str) -> Result<(), FindingBundleError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(FindingBundleError::InvalidSha256 {
            field,
            sha256: value.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FINDING_BUNDLE_SCHEMA, FindingBundleError, FindingBundleManifest,
        parse_finding_bundle_manifest,
    };

    const VALID_MANIFEST: &str = r#"{
  "schema": "erofs-rs.finding-bundle.v1",
  "artifact": {
    "path": "fuzz_seed_iter42.erofs",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "size_bytes": 4096
  },
  "sidecar": {
    "path": "fuzz_seed_iter42.json",
    "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
  },
  "stdout": {
    "path": "fuzz_seed_iter42.stdout.txt",
    "sha256": null
  },
  "stderr": {
    "path": "fuzz_seed_iter42.stderr.txt",
    "sha256": null
  },
  "replay_report": {
    "path": "replay-report.txt",
    "sha256": "2222222222222222222222222222222222222222222222222222222222222222"
  },
  "oracle_report": null,
  "kernel_report": null,
  "classification": "rejected_crash",
  "signature": "rejected_crash: SIGSEGV"
}"#;

    #[test]
    fn finding_bundle_manifest_round_trips_json() {
        let manifest = parse_finding_bundle_manifest(VALID_MANIFEST).unwrap();
        let json = serde_json::to_string(&manifest).unwrap();
        let decoded: FindingBundleManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, manifest);
        assert_eq!(decoded.schema, FINDING_BUNDLE_SCHEMA);
        assert_eq!(decoded.artifact.size_bytes, Some(4096));
        assert_eq!(decoded.classification, "rejected_crash");
    }

    #[test]
    fn finding_bundle_manifest_rejects_unknown_schema() {
        let manifest =
            VALID_MANIFEST.replace("erofs-rs.finding-bundle.v1", "erofs-rs.finding-bundle.v0");

        let error = parse_finding_bundle_manifest(&manifest).unwrap_err();

        assert!(matches!(error, FindingBundleError::UnsupportedSchema(_)));
    }

    #[test]
    fn finding_bundle_manifest_rejects_invalid_artifact_hash() {
        let manifest = VALID_MANIFEST.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "short",
        );

        let error = parse_finding_bundle_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            FindingBundleError::InvalidSha256 {
                field: "artifact.sha256",
                ..
            }
        ));
    }

    #[test]
    fn finding_bundle_manifest_rejects_empty_optional_path() {
        let manifest = VALID_MANIFEST.replace(r#""path": "replay-report.txt""#, r#""path": """#);

        let error = parse_finding_bundle_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            FindingBundleError::EmptyField("replay_report.path")
        ));
    }

    #[test]
    fn finding_bundle_manifest_rejects_duplicate_paths() {
        let manifest = VALID_MANIFEST.replace(
            r#""path": "fuzz_seed_iter42.stderr.txt""#,
            r#""path": "fuzz_seed_iter42.stdout.txt""#,
        );

        let error = parse_finding_bundle_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            FindingBundleError::DuplicatePath(path)
                if path == "fuzz_seed_iter42.stdout.txt"
        ));
    }

    #[test]
    fn finding_bundle_manifest_rejects_non_actionable_classification() {
        let manifest = VALID_MANIFEST
            .replace(
                r#""classification": "rejected_crash""#,
                r#""classification": "accepted""#,
            )
            .replace(
                r#""signature": "rejected_crash: SIGSEGV""#,
                r#""signature": "accepted: fsck accepted the image""#,
            );

        let error = parse_finding_bundle_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            FindingBundleError::NonActionableClassification { classification }
                if classification == "accepted"
        ));
    }

    #[test]
    fn finding_bundle_manifest_rejects_signature_mismatch() {
        let manifest = VALID_MANIFEST.replace(
            r#""signature": "rejected_crash: SIGSEGV""#,
            r#""signature": "sanitizer_crash: AddressSanitizer""#,
        );

        let error = parse_finding_bundle_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            FindingBundleError::SignatureClassificationMismatch {
                classification,
                signature,
            } if classification == "rejected_crash"
                && signature == "sanitizer_crash: AddressSanitizer"
        ));
    }
}
