use serde::Deserialize;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SeedMatrixEntry {
    pub seed: String,
    pub path: String,
    pub sha256: String,
    pub source_profile: String,
    #[serde(default)]
    pub requirement: SeedRequirement,
    pub mkfs: String,
    pub mkfs_version: String,
    pub erofs_utils_git: String,
    pub features: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SeedRequirement {
    #[default]
    Required,
    BestEffort,
}

#[derive(Debug, Error)]
pub enum SeedManifestError {
    #[error("failed to decode seed matrix manifest: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("seed matrix manifest is empty")]
    EmptyManifest,
    #[error("seed matrix entry {index} has empty {field}")]
    EmptyField { index: usize, field: &'static str },
    #[error("seed matrix entry {index} has invalid SHA-256 digest: {sha256}")]
    InvalidSha256 { index: usize, sha256: String },
    #[error("seed matrix entry {index} has no feature tags")]
    EmptyFeatures { index: usize },
    #[error("seed matrix entry {index} has an empty feature tag at index {feature_index}")]
    EmptyFeature { index: usize, feature_index: usize },
    #[error(
        "seed matrix entry {index} has invalid feature tag at index {feature_index}: {feature}"
    )]
    InvalidFeature {
        index: usize,
        feature_index: usize,
        feature: String,
    },
}

pub fn parse_seed_matrix_manifest(
    content: &str,
) -> Result<Vec<SeedMatrixEntry>, SeedManifestError> {
    let entries: Vec<SeedMatrixEntry> = serde_json::from_str(content)?;
    validate_seed_matrix_manifest(&entries)?;
    Ok(entries)
}

pub fn validate_seed_matrix_manifest(entries: &[SeedMatrixEntry]) -> Result<(), SeedManifestError> {
    if entries.is_empty() {
        return Err(SeedManifestError::EmptyManifest);
    }

    for (index, entry) in entries.iter().enumerate() {
        require_nonempty(index, "seed", &entry.seed)?;
        require_nonempty(index, "path", &entry.path)?;
        require_nonempty(index, "source_profile", &entry.source_profile)?;
        require_nonempty(index, "mkfs", &entry.mkfs)?;
        require_nonempty(index, "mkfs_version", &entry.mkfs_version)?;

        if !is_sha256_digest(&entry.sha256) {
            return Err(SeedManifestError::InvalidSha256 {
                index,
                sha256: entry.sha256.clone(),
            });
        }

        if entry.features.is_empty() {
            return Err(SeedManifestError::EmptyFeatures { index });
        }
        for (feature_index, feature) in entry.features.iter().enumerate() {
            if feature.is_empty() {
                return Err(SeedManifestError::EmptyFeature {
                    index,
                    feature_index,
                });
            }
            if !is_feature_tag(feature) {
                return Err(SeedManifestError::InvalidFeature {
                    index,
                    feature_index,
                    feature: feature.clone(),
                });
            }
        }
    }

    Ok(())
}

fn require_nonempty(
    index: usize,
    field: &'static str,
    value: &str,
) -> Result<(), SeedManifestError> {
    if value.is_empty() {
        return Err(SeedManifestError::EmptyField { index, field });
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_feature_tag(value: &str) -> bool {
    let Some((namespace, tag_value)) = value.split_once(':') else {
        return false;
    };
    !namespace.is_empty() && !tag_value.is_empty()
}

#[cfg(test)]
mod tests {
    use super::{SeedManifestError, SeedRequirement, parse_seed_matrix_manifest};

    const VALID_MANIFEST: &str = r#"[
  {
    "seed": "block-4096-plain.erofs",
    "path": "/tmp/seed-matrix/block-4096-plain.erofs",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "source_profile": "basic",
    "requirement": "required",
    "mkfs": "mkfs.erofs -b4096 /tmp/seed-matrix/block-4096-plain.erofs <source:basic>",
    "mkfs_version": "mkfs.erofs 1.8.0",
    "erofs_utils_git": "",
    "features": [
      "block_size:4096",
      "compression:none",
      "layout:plain",
      "dir_size:small"
    ]
  }
]"#;

    #[test]
    fn seed_matrix_manifest_accepts_script_shape() {
        let entries = parse_seed_matrix_manifest(VALID_MANIFEST).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].seed, "block-4096-plain.erofs");
        assert_eq!(entries[0].source_profile, "basic");
        assert_eq!(entries[0].requirement, SeedRequirement::Required);
        assert!(entries[0].features.contains(&"block_size:4096".to_string()));
    }

    #[test]
    fn seed_matrix_manifest_accepts_best_effort_entries() {
        let manifest = VALID_MANIFEST.replace(
            r#""requirement": "required""#,
            r#""requirement": "best_effort""#,
        );

        let entries = parse_seed_matrix_manifest(&manifest).unwrap();

        assert_eq!(entries[0].requirement, SeedRequirement::BestEffort);
    }

    #[test]
    fn seed_matrix_manifest_defaults_missing_requirement_to_required() {
        let manifest = VALID_MANIFEST.replace("    \"requirement\": \"required\",\n", "");

        let entries = parse_seed_matrix_manifest(&manifest).unwrap();

        assert_eq!(entries[0].requirement, SeedRequirement::Required);
    }

    #[test]
    fn seed_matrix_manifest_rejects_missing_required_fields() {
        let manifest = r#"[
  {
    "seed": "block-4096-plain.erofs",
    "path": "/tmp/seed-matrix/block-4096-plain.erofs",
    "source_profile": "basic",
    "mkfs": "mkfs.erofs -b4096 image source",
    "mkfs_version": "mkfs.erofs 1.8.0",
    "erofs_utils_git": "",
    "features": ["block_size:4096"]
  }
]"#;

        let error = parse_seed_matrix_manifest(manifest).unwrap_err();

        assert!(error.to_string().contains("missing field `sha256`"));
    }

    #[test]
    fn seed_matrix_manifest_rejects_invalid_sha256() {
        let manifest = VALID_MANIFEST.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "not-a-sha256",
        );

        let error = parse_seed_matrix_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            SeedManifestError::InvalidSha256 { index: 0, .. }
        ));
    }

    #[test]
    fn seed_matrix_manifest_rejects_empty_feature_list() {
        let manifest = VALID_MANIFEST.replace(
            r#""features": [
      "block_size:4096",
      "compression:none",
      "layout:plain",
      "dir_size:small"
    ]"#,
            r#""features": []"#,
        );

        let error = parse_seed_matrix_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            SeedManifestError::EmptyFeatures { index: 0 }
        ));
    }

    #[test]
    fn seed_matrix_manifest_rejects_invalid_feature_tag() {
        let manifest = VALID_MANIFEST.replace("block_size:4096", "block_size");

        let error = parse_seed_matrix_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            SeedManifestError::InvalidFeature {
                index: 0,
                feature_index: 0,
                ..
            }
        ));
    }
}
