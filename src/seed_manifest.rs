use crate::cli::SeedManifestArgs;
use anyhow::{Context, Result as AnyhowResult};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path};
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
    #[error("seed matrix entry {index} has invalid seed file name: {seed}")]
    InvalidSeedName { index: usize, seed: String },
    #[error("seed matrix entry {index} field {field} has invalid path: {path}")]
    InvalidPath {
        index: usize,
        field: &'static str,
        path: String,
    },
    #[error("seed matrix entry {index} path does not end with seed file name {seed}: {path}")]
    PathSeedMismatch {
        index: usize,
        seed: String,
        path: String,
    },
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
    #[error("seed matrix entry {index} duplicates {field}: {value}")]
    DuplicateField {
        index: usize,
        field: &'static str,
        value: String,
    },
    #[error("seed matrix entry {index} duplicates feature tag at index {feature_index}: {feature}")]
    DuplicateFeature {
        index: usize,
        feature_index: usize,
        feature: String,
    },
    #[error("seed matrix missing required semantic feature: {feature}")]
    MissingRequiredFeature { feature: &'static str },
    #[error("seed matrix missing required semantic combination: {combination}")]
    MissingRequiredCombination { combination: &'static str },
    #[error(
        "seed matrix entry {index} source_profile {source_profile} is missing semantic feature {feature}"
    )]
    MissingProfileFeature {
        index: usize,
        source_profile: String,
        feature: &'static str,
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

    let mut seeds = HashSet::new();
    let mut paths = HashSet::new();
    let mut hashes = HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        require_nonempty(index, "seed", &entry.seed)?;
        require_nonempty(index, "path", &entry.path)?;
        require_nonempty(index, "source_profile", &entry.source_profile)?;
        require_nonempty(index, "mkfs", &entry.mkfs)?;
        require_nonempty(index, "mkfs_version", &entry.mkfs_version)?;
        require_seed_name(index, &entry.seed)?;
        require_seed_path(index, &entry.path, &entry.seed)?;
        require_unique(index, "seed", &entry.seed, &mut seeds)?;
        require_unique(index, "path", &entry.path, &mut paths)?;

        if !is_sha256_digest(&entry.sha256) {
            return Err(SeedManifestError::InvalidSha256 {
                index,
                sha256: entry.sha256.clone(),
            });
        }
        require_unique(index, "sha256", &entry.sha256, &mut hashes)?;

        if entry.features.is_empty() {
            return Err(SeedManifestError::EmptyFeatures { index });
        }
        let mut features = HashSet::new();
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
            if !features.insert(feature.as_str()) {
                return Err(SeedManifestError::DuplicateFeature {
                    index,
                    feature_index,
                    feature: feature.clone(),
                });
            }
        }
    }

    Ok(())
}

pub fn validate_seed_matrix_semantic_coverage(
    entries: &[SeedMatrixEntry],
) -> Result<(), SeedManifestError> {
    require_required_feature(entries, "block_size:4096")?;
    require_required_feature(entries, "compression:none")?;

    for (combination, features) in REQUIRED_COMBINATIONS {
        require_required_combination(entries, combination, features)?;
    }

    for (index, entry) in entries.iter().enumerate() {
        let expected_features = match entry.source_profile.as_str() {
            "large_dir" => &["dir_size:multiblock"][..],
            "xattr_user" => &["xattrs:user"][..],
            "xattr_long_prefix" => &["xattrs:user", "xattrs:long_prefix"][..],
            "xattr_shared" => &["xattrs:user", "xattrs:shared"][..],
            "xattr_name_filter" => &["xattrs:user", "xattrs:name_filter"][..],
            "xattr_combo" => &[
                "xattrs:user",
                "xattrs:shared",
                "xattrs:long_prefix",
                "xattrs:name_filter",
                "feature_combo:xattr_all",
            ][..],
            "acl_posix" => &["acl:posix"][..],
            "special_files" => &["hardlink:true", "fifo:true", "symlink:true"][..],
            "socket" => &["socket:true"][..],
            "device_node" => &["device:char"][..],
            "android_profile" => &["workload:android", "profile:generated"][..],
            "container_profile" => &["workload:container", "profile:generated"][..],
            "rootfs_profile" => &["workload:rootfs", "profile:generated"][..],
            "android_real" => &["workload:android", "sample:real"][..],
            "container_real" => &["workload:container", "sample:real"][..],
            "rootfs_real" => &["workload:rootfs", "sample:real"][..],
            _ => &[][..],
        };
        for feature in expected_features {
            if !entry_has_feature(entry, feature) {
                return Err(SeedManifestError::MissingProfileFeature {
                    index,
                    source_profile: entry.source_profile.clone(),
                    feature,
                });
            }
        }
    }

    Ok(())
}

pub fn run(args: &SeedManifestArgs) -> AnyhowResult<()> {
    let content = fs::read_to_string(&args.manifest)
        .with_context(|| format!("failed to read seed matrix manifest {}", args.manifest))?;
    let entries = parse_seed_matrix_manifest(&content)
        .with_context(|| format!("failed to validate seed matrix manifest {}", args.manifest))?;
    validate_seed_matrix_semantic_coverage(&entries)
        .with_context(|| format!("failed to validate seed matrix coverage {}", args.manifest))?;

    println!("Seed matrix manifest OK: {} entries", entries.len());
    Ok(())
}

const REQUIRED_COMBINATIONS: &[(&str, &[&str])] = &[
    (
        "plain uncompressed small-directory seed",
        &["layout:plain", "compression:none", "dir_size:small"],
    ),
    (
        "multiblock directory seed",
        &["layout:plain", "compression:none", "dir_size:multiblock"],
    ),
    ("chunked seed", &["layout:chunked", "chunksize:4096"]),
    (
        "packed fragment seed",
        &["layout:fragment", "packed_inode:true", "compression:lz4"],
    ),
    (
        "special-file seed",
        &["hardlink:true", "fifo:true", "symlink:true"],
    ),
    (
        "android profile seed",
        &["workload:android", "profile:generated", "dir_size:profile"],
    ),
    (
        "container profile seed",
        &[
            "workload:container",
            "profile:generated",
            "dir_size:profile",
        ],
    ),
    (
        "rootfs profile seed",
        &["workload:rootfs", "profile:generated", "dir_size:profile"],
    ),
];

fn require_required_feature(
    entries: &[SeedMatrixEntry],
    feature: &'static str,
) -> Result<(), SeedManifestError> {
    if entries.iter().any(|entry| {
        entry.requirement == SeedRequirement::Required && entry_has_feature(entry, feature)
    }) {
        return Ok(());
    }
    Err(SeedManifestError::MissingRequiredFeature { feature })
}

fn require_required_combination(
    entries: &[SeedMatrixEntry],
    combination: &'static str,
    features: &[&'static str],
) -> Result<(), SeedManifestError> {
    if entries.iter().any(|entry| {
        entry.requirement == SeedRequirement::Required
            && features
                .iter()
                .all(|feature| entry_has_feature(entry, feature))
    }) {
        return Ok(());
    }
    Err(SeedManifestError::MissingRequiredCombination { combination })
}

fn entry_has_feature(entry: &SeedMatrixEntry, feature: &str) -> bool {
    entry.features.iter().any(|candidate| candidate == feature)
}

fn require_seed_name(index: usize, seed: &str) -> Result<(), SeedManifestError> {
    if !seed.ends_with(".erofs") || !is_portable_path_component(seed) {
        return Err(SeedManifestError::InvalidSeedName {
            index,
            seed: seed.to_string(),
        });
    }
    Ok(())
}

fn require_seed_path(index: usize, path: &str, seed: &str) -> Result<(), SeedManifestError> {
    if path.contains('\\')
        || Path::new(path)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SeedManifestError::InvalidPath {
            index,
            field: "path",
            path: path.to_string(),
        });
    }

    let file_name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| SeedManifestError::InvalidPath {
            index,
            field: "path",
            path: path.to_string(),
        })?;
    if file_name != seed {
        return Err(SeedManifestError::PathSeedMismatch {
            index,
            seed: seed.to_string(),
            path: path.to_string(),
        });
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

fn require_unique<'a>(
    index: usize,
    field: &'static str,
    value: &'a str,
    seen: &mut HashSet<&'a str>,
) -> Result<(), SeedManifestError> {
    if !seen.insert(value) {
        return Err(SeedManifestError::DuplicateField {
            index,
            field,
            value: value.to_string(),
        });
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

fn is_portable_path_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{
        SeedManifestError, SeedMatrixEntry, SeedRequirement, parse_seed_matrix_manifest, run,
        validate_seed_matrix_semantic_coverage,
    };
    use crate::cli::SeedManifestArgs;
    use tempfile::TempDir;

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
    fn seed_matrix_manifest_accepts_current_directory_path() {
        let manifest = VALID_MANIFEST.replace(
            r#""path": "/tmp/seed-matrix/block-4096-plain.erofs""#,
            r#""path": "./seed-matrix/block-4096-plain.erofs""#,
        );

        let entries = parse_seed_matrix_manifest(&manifest).unwrap();

        assert_eq!(entries[0].path, "./seed-matrix/block-4096-plain.erofs");
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
    fn seed_matrix_manifest_rejects_seed_name_with_path_separator() {
        let manifest = VALID_MANIFEST.replace(
            r#""seed": "block-4096-plain.erofs""#,
            r#""seed": "../block-4096-plain.erofs""#,
        );

        let error = parse_seed_matrix_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            SeedManifestError::InvalidSeedName { index: 0, .. }
        ));
    }

    #[test]
    fn seed_matrix_manifest_rejects_parent_directory_path() {
        let manifest = VALID_MANIFEST.replace(
            r#""path": "/tmp/seed-matrix/block-4096-plain.erofs""#,
            r#""path": "/tmp/seed-matrix/../block-4096-plain.erofs""#,
        );

        let error = parse_seed_matrix_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            SeedManifestError::InvalidPath {
                index: 0,
                field: "path",
                ..
            }
        ));
    }

    #[test]
    fn seed_matrix_manifest_rejects_path_seed_mismatch() {
        let manifest = VALID_MANIFEST.replace(
            r#""path": "/tmp/seed-matrix/block-4096-plain.erofs""#,
            r#""path": "/tmp/seed-matrix/other.erofs""#,
        );

        let error = parse_seed_matrix_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            SeedManifestError::PathSeedMismatch {
                index: 0,
                seed,
                path,
            } if seed == "block-4096-plain.erofs" && path == "/tmp/seed-matrix/other.erofs"
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

    #[test]
    fn seed_matrix_manifest_rejects_duplicate_seed() {
        let mut manifest: serde_json::Value = serde_json::from_str(VALID_MANIFEST).unwrap();
        let entry = manifest[0].clone();
        manifest.as_array_mut().unwrap().push(entry);
        let manifest = serde_json::to_string(&manifest).unwrap();

        let error = parse_seed_matrix_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            SeedManifestError::DuplicateField {
                index: 1,
                field: "seed",
                value,
            } if value == "block-4096-plain.erofs"
        ));
    }

    #[test]
    fn seed_matrix_manifest_rejects_duplicate_feature_tag() {
        let mut manifest: serde_json::Value = serde_json::from_str(VALID_MANIFEST).unwrap();
        manifest[0]["features"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("block_size:4096"));
        let manifest = serde_json::to_string(&manifest).unwrap();

        let error = parse_seed_matrix_manifest(&manifest).unwrap_err();

        assert!(matches!(
            error,
            SeedManifestError::DuplicateFeature {
                index: 0,
                feature_index: 4,
                feature,
            } if feature == "block_size:4096"
        ));
    }

    fn semantic_entry(
        seed: &str,
        source_profile: &str,
        requirement: SeedRequirement,
        features: &[&str],
    ) -> SeedMatrixEntry {
        SeedMatrixEntry {
            seed: format!("{seed}.erofs"),
            path: format!("/tmp/seed-matrix/{seed}.erofs"),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            source_profile: source_profile.to_string(),
            requirement,
            mkfs: format!("mkfs.erofs /tmp/seed-matrix/{seed}.erofs <source:{source_profile}>"),
            mkfs_version: "mkfs.erofs 1.8.0".to_string(),
            erofs_utils_git: String::new(),
            features: features
                .iter()
                .map(|feature| (*feature).to_string())
                .collect(),
        }
    }

    fn semantic_entries() -> Vec<SeedMatrixEntry> {
        vec![
            semantic_entry(
                "block-4096-plain",
                "basic",
                SeedRequirement::Required,
                &[
                    "block_size:4096",
                    "compression:none",
                    "layout:plain",
                    "dir_size:small",
                ],
            ),
            semantic_entry(
                "large-dir-multiblock-4k",
                "large_dir",
                SeedRequirement::Required,
                &[
                    "block_size:4096",
                    "compression:none",
                    "layout:plain",
                    "dir_size:multiblock",
                ],
            ),
            semantic_entry(
                "hardlink-fifo-symlink-4k",
                "special_files",
                SeedRequirement::Required,
                &[
                    "block_size:4096",
                    "compression:none",
                    "layout:plain",
                    "hardlink:true",
                    "fifo:true",
                    "symlink:true",
                ],
            ),
            semantic_entry(
                "chunked-4k",
                "basic",
                SeedRequirement::Required,
                &[
                    "block_size:4096",
                    "compression:none",
                    "layout:chunked",
                    "chunksize:4096",
                ],
            ),
            semantic_entry(
                "fragment-packed-lz4-4k",
                "basic",
                SeedRequirement::Required,
                &[
                    "block_size:4096",
                    "compression:lz4",
                    "layout:fragment",
                    "packed_inode:true",
                ],
            ),
            semantic_entry(
                "android-profile-4k",
                "android_profile",
                SeedRequirement::Required,
                &[
                    "block_size:4096",
                    "compression:none",
                    "layout:plain",
                    "dir_size:profile",
                    "workload:android",
                    "profile:generated",
                ],
            ),
            semantic_entry(
                "container-profile-4k",
                "container_profile",
                SeedRequirement::Required,
                &[
                    "block_size:4096",
                    "compression:none",
                    "layout:plain",
                    "dir_size:profile",
                    "workload:container",
                    "profile:generated",
                ],
            ),
            semantic_entry(
                "rootfs-profile-4k",
                "rootfs_profile",
                SeedRequirement::Required,
                &[
                    "block_size:4096",
                    "compression:none",
                    "layout:plain",
                    "dir_size:profile",
                    "workload:rootfs",
                    "profile:generated",
                ],
            ),
        ]
    }

    #[test]
    fn seed_matrix_semantics_accept_generated_required_coverage() {
        let entries = semantic_entries();

        validate_seed_matrix_semantic_coverage(&entries).unwrap();
    }

    #[test]
    fn seed_matrix_semantics_reject_missing_required_combination() {
        let mut entries = semantic_entries();
        entries.retain(|entry| !entry.features.contains(&"layout:chunked".to_string()));

        let error = validate_seed_matrix_semantic_coverage(&entries).unwrap_err();

        assert!(matches!(
            error,
            SeedManifestError::MissingRequiredCombination { combination }
                if combination == "chunked seed"
        ));
    }

    #[test]
    fn seed_matrix_semantics_reject_profile_feature_mismatch() {
        let mut entries = semantic_entries();
        entries.push(semantic_entry(
            "xattr-shared-4k",
            "xattr_shared",
            SeedRequirement::BestEffort,
            &[
                "block_size:4096",
                "compression:none",
                "xattrs:user",
                "layout:plain",
                "dir_size:small",
            ],
        ));

        let error = validate_seed_matrix_semantic_coverage(&entries).unwrap_err();

        assert!(matches!(
            error,
            SeedManifestError::MissingProfileFeature {
                index: 8,
                source_profile,
                feature: "xattrs:shared",
            } if source_profile == "xattr_shared"
        ));
    }

    #[test]
    fn seed_matrix_semantics_accept_xattr_combo_profile() {
        let mut entries = semantic_entries();
        entries.push(semantic_entry(
            "xattr-combo-4k",
            "xattr_combo",
            SeedRequirement::BestEffort,
            &[
                "block_size:4096",
                "compression:none",
                "layout:plain",
                "dir_size:small",
                "xattrs:user",
                "xattrs:shared",
                "xattrs:long_prefix",
                "xattrs:name_filter",
                "feature_combo:xattr_all",
            ],
        ));

        validate_seed_matrix_semantic_coverage(&entries).unwrap();
    }

    #[test]
    fn seed_matrix_semantics_reject_real_profile_feature_mismatch() {
        let mut entries = semantic_entries();
        entries.push(semantic_entry(
            "android-real-4k",
            "android_real",
            SeedRequirement::BestEffort,
            &[
                "block_size:4096",
                "compression:none",
                "layout:plain",
                "dir_size:real_world",
                "sample:real",
            ],
        ));

        let error = validate_seed_matrix_semantic_coverage(&entries).unwrap_err();

        assert!(matches!(
            error,
            SeedManifestError::MissingProfileFeature {
                index: 8,
                source_profile,
                feature: "workload:android",
            } if source_profile == "android_real"
        ));
    }

    #[test]
    fn seed_manifest_command_rejects_shape_only_manifest() {
        let tmp = TempDir::new().unwrap();
        let manifest = tmp.path().join("manifest.json");
        std::fs::write(&manifest, VALID_MANIFEST).unwrap();
        let args = SeedManifestArgs {
            manifest: manifest.to_string_lossy().to_string(),
        };

        let error = run(&args).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("failed to validate seed matrix coverage")
        );
    }
}
