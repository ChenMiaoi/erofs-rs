use crate::cli::{MinimizedCheckArgs, MinimizedImportArgs};
use crate::corpus::parse_coverage_manifest;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Component, Path};
use thiserror::Error;
use walkdir::WalkDir;

pub const MINIMIZED_CORPUS_SCHEMA: &str = "erofs-rs.minimized-corpus.v1";
pub const DEFAULT_MINIMIZED_IMPORT_ROOT: &str = "corpus/seeds/minimized";
const MINIMIZED_MANIFEST_FILE: &str = "manifest.json";
const MINIMIZED_README_FILE: &str = "README.md";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizedCorpusManifest {
    pub schema: String,
    pub import_root: String,
    pub total_units: usize,
    pub total_size_bytes: u64,
    pub targets: Vec<MinimizedTargetSummary>,
    pub units: Vec<MinimizedCorpusUnit>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizedTargetSummary {
    pub target: String,
    pub unit_count: usize,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizedCorpusUnit {
    pub target: String,
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub source_coverage_manifest: String,
    pub source_path: String,
    pub coverage_copied_path: String,
    pub lifecycle: String,
}

#[derive(Debug, Error)]
pub enum MinimizedManifestError {
    #[error("failed to decode minimized corpus manifest: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unsupported minimized corpus manifest schema: {0}")]
    UnsupportedSchema(String),
    #[error("minimized corpus manifest field {0} is empty")]
    EmptyField(&'static str),
    #[error("minimized corpus manifest field {field} has invalid path: {path}")]
    InvalidPath { field: &'static str, path: String },
    #[error("minimized corpus unit has invalid SHA-256 digest: {sha256}")]
    InvalidSha256 { sha256: String },
    #[error("minimized corpus contains duplicate target summary: {0}")]
    DuplicateTarget(String),
    #[error("minimized corpus contains duplicate unit path: {0}")]
    DuplicateUnitPath(String),
    #[error("minimized corpus contains duplicate unit digest for target {target}: {sha256}")]
    DuplicateTargetDigest { target: String, sha256: String },
    #[error("minimized corpus unit target has no summary: {0}")]
    MissingTargetSummary(String),
    #[error("minimized corpus count mismatch for {field}: expected {expected}, actual {actual}")]
    CountMismatch {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("minimized corpus size mismatch for {field}: expected {expected}, actual {actual}")]
    SizeMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    #[error("minimized corpus size overflow for {0}")]
    SizeOverflow(&'static str),
    #[error("minimized corpus file is missing: {path}")]
    MissingFile { path: String },
    #[error(
        "minimized corpus file has unexpected SHA-256 digest for {path}: expected {expected}, actual {actual}"
    )]
    FileShaMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error(
        "minimized corpus file has unexpected size for {path}: expected {expected}, actual {actual}"
    )]
    FileSizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    #[error("minimized corpus import root contains file not listed in manifest: {path}")]
    UnexpectedFile { path: String },
}

pub fn parse_minimized_manifest(
    content: &str,
) -> std::result::Result<MinimizedCorpusManifest, MinimizedManifestError> {
    let manifest: MinimizedCorpusManifest = serde_json::from_str(content)?;
    validate_minimized_manifest(&manifest)?;
    Ok(manifest)
}

pub fn validate_minimized_manifest(
    manifest: &MinimizedCorpusManifest,
) -> std::result::Result<(), MinimizedManifestError> {
    if manifest.schema != MINIMIZED_CORPUS_SCHEMA {
        return Err(MinimizedManifestError::UnsupportedSchema(
            manifest.schema.clone(),
        ));
    }

    require_nonempty("import_root", &manifest.import_root)?;
    require_safe_path("import_root", &manifest.import_root)?;
    require_count("total_units", manifest.units.len(), manifest.total_units)?;

    let total_size = size_sum(
        "total_size_bytes",
        manifest.units.iter().map(|unit| unit.size_bytes),
    )?;
    require_size("total_size_bytes", total_size, manifest.total_size_bytes)?;

    let mut unit_counts: HashMap<&str, usize> = HashMap::new();
    let mut unit_sizes: HashMap<&str, u64> = HashMap::new();
    let mut unit_paths = HashSet::new();
    let mut unit_target_digests = HashSet::new();
    for unit in &manifest.units {
        validate_minimized_unit(unit, &manifest.import_root)?;
        if !unit_paths.insert(unit.path.as_str()) {
            return Err(MinimizedManifestError::DuplicateUnitPath(unit.path.clone()));
        }
        if !unit_target_digests.insert((unit.target.as_str(), unit.sha256.as_str())) {
            return Err(MinimizedManifestError::DuplicateTargetDigest {
                target: unit.target.clone(),
                sha256: unit.sha256.clone(),
            });
        }
        *unit_counts.entry(unit.target.as_str()).or_insert(0) += 1;
        let size = unit_sizes.entry(unit.target.as_str()).or_insert(0);
        *size = size
            .checked_add(unit.size_bytes)
            .ok_or(MinimizedManifestError::SizeOverflow("targets.size_bytes"))?;
    }

    let mut target_names = HashSet::new();
    for target in &manifest.targets {
        validate_minimized_target(target, &unit_counts, &unit_sizes)?;
        if !target_names.insert(target.target.as_str()) {
            return Err(MinimizedManifestError::DuplicateTarget(
                target.target.clone(),
            ));
        }
    }

    for target in unit_counts.keys() {
        if !target_names.contains(target) {
            return Err(MinimizedManifestError::MissingTargetSummary(
                (*target).to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_minimized_target(
    target: &MinimizedTargetSummary,
    unit_counts: &HashMap<&str, usize>,
    unit_sizes: &HashMap<&str, u64>,
) -> std::result::Result<(), MinimizedManifestError> {
    require_nonempty("targets.target", &target.target)?;
    require_path_component("targets.target", &target.target)?;
    require_count(
        "targets.unit_count",
        *unit_counts.get(target.target.as_str()).unwrap_or(&0),
        target.unit_count,
    )?;
    require_size(
        "targets.size_bytes",
        *unit_sizes.get(target.target.as_str()).unwrap_or(&0),
        target.size_bytes,
    )?;
    Ok(())
}

fn validate_minimized_unit(
    unit: &MinimizedCorpusUnit,
    import_root: &str,
) -> std::result::Result<(), MinimizedManifestError> {
    require_nonempty("units.target", &unit.target)?;
    require_nonempty("units.path", &unit.path)?;
    require_nonempty(
        "units.source_coverage_manifest",
        &unit.source_coverage_manifest,
    )?;
    require_nonempty("units.source_path", &unit.source_path)?;
    require_nonempty("units.coverage_copied_path", &unit.coverage_copied_path)?;
    require_nonempty("units.lifecycle", &unit.lifecycle)?;
    require_path_component("units.target", &unit.target)?;
    require_safe_path(
        "units.source_coverage_manifest",
        &unit.source_coverage_manifest,
    )?;
    require_safe_path("units.source_path", &unit.source_path)?;

    if !is_sha256_digest(&unit.sha256) {
        return Err(MinimizedManifestError::InvalidSha256 {
            sha256: unit.sha256.clone(),
        });
    }

    let copied_name = coverage_copied_file_name(&unit.coverage_copied_path).map_err(|_| {
        MinimizedManifestError::InvalidPath {
            field: "units.coverage_copied_path",
            path: unit.coverage_copied_path.clone(),
        }
    })?;
    let expected_path = import_path(import_root, &unit.target, copied_name);
    if unit.path != expected_path {
        return Err(MinimizedManifestError::InvalidPath {
            field: "units.path",
            path: unit.path.clone(),
        });
    }
    Ok(())
}

fn require_nonempty(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), MinimizedManifestError> {
    if value.is_empty() {
        return Err(MinimizedManifestError::EmptyField(field));
    }
    Ok(())
}

fn require_count(
    field: &'static str,
    expected: usize,
    actual: usize,
) -> std::result::Result<(), MinimizedManifestError> {
    if expected != actual {
        return Err(MinimizedManifestError::CountMismatch {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

fn require_size(
    field: &'static str,
    expected: u64,
    actual: u64,
) -> std::result::Result<(), MinimizedManifestError> {
    if expected != actual {
        return Err(MinimizedManifestError::SizeMismatch {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

fn size_sum(
    field: &'static str,
    values: impl IntoIterator<Item = u64>,
) -> std::result::Result<u64, MinimizedManifestError> {
    let mut total = 0u64;
    for value in values {
        total = total
            .checked_add(value)
            .ok_or(MinimizedManifestError::SizeOverflow(field))?;
    }
    Ok(total)
}

fn require_path_component(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), MinimizedManifestError> {
    if !is_portable_path_component(value) {
        return Err(MinimizedManifestError::InvalidPath {
            field,
            path: value.to_string(),
        });
    }
    Ok(())
}

fn require_safe_path(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), MinimizedManifestError> {
    if value.contains('\\')
        || Path::new(value)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(MinimizedManifestError::InvalidPath {
            field,
            path: value.to_string(),
        });
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_portable_path_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn coverage_copied_file_name(path: &str) -> Result<&str> {
    let mut components = path.split('/');
    match (components.next(), components.next(), components.next()) {
        (Some("coverage-interesting"), Some(copied_name), None)
            if is_portable_path_component(copied_name) =>
        {
            Ok(copied_name)
        }
        _ => bail!("invalid coverage copied path: {path}"),
    }
}

fn portable_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn normalize_path_string(value: &str) -> String {
    let mut normalized = portable_path(Path::new(value));
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

fn import_path(import_root: &str, target: &str, copied_name: &str) -> String {
    portable_path(&Path::new(import_root).join(target).join(copied_name))
}

fn manifest_path(args: &MinimizedImportArgs, import_root: &str) -> String {
    args.manifest
        .clone()
        .unwrap_or_else(|| portable_path(&Path::new(import_root).join(MINIMIZED_MANIFEST_FILE)))
}

fn file_hash(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    hasher.update(data);
    Ok(hex::encode(hasher.finalize()))
}

fn build_target_summaries(units: &[MinimizedCorpusUnit]) -> Result<Vec<MinimizedTargetSummary>> {
    let mut targets: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    for unit in units {
        let entry = targets.entry(unit.target.clone()).or_insert((0, 0));
        entry.0 = entry
            .0
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("minimized unit count overflows"))?;
        entry.1 = entry
            .1
            .checked_add(unit.size_bytes)
            .ok_or_else(|| anyhow::anyhow!("minimized unit size overflows"))?;
    }

    Ok(targets
        .into_iter()
        .map(
            |(target, (unit_count, size_bytes))| MinimizedTargetSummary {
                target,
                unit_count,
                size_bytes,
            },
        )
        .collect())
}

fn build_manifest(
    import_root: String,
    mut units: Vec<MinimizedCorpusUnit>,
) -> Result<MinimizedCorpusManifest> {
    units.sort_by(|a, b| a.target.cmp(&b.target).then_with(|| a.path.cmp(&b.path)));
    let total_size_bytes = units.iter().try_fold(0u64, |total, unit| {
        total
            .checked_add(unit.size_bytes)
            .ok_or_else(|| anyhow::anyhow!("minimized unit size overflows"))
    })?;
    let targets = build_target_summaries(&units)?;
    Ok(MinimizedCorpusManifest {
        schema: MINIMIZED_CORPUS_SCHEMA.to_string(),
        import_root,
        total_units: units.len(),
        total_size_bytes,
        targets,
        units,
    })
}

fn load_existing_manifest(
    path: &Path,
    import_root: &str,
) -> Result<Option<MinimizedCorpusManifest>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read minimized corpus manifest {}",
            path.display()
        )
    })?;
    let manifest = parse_minimized_manifest(&content).with_context(|| {
        format!(
            "failed to validate minimized corpus manifest {}",
            path.display()
        )
    })?;
    if manifest.import_root != import_root {
        bail!(
            "minimized corpus manifest {} uses import root {}, expected {}",
            path.display(),
            manifest.import_root,
            import_root
        );
    }
    verify_minimized_manifest_files(&manifest).with_context(|| {
        format!(
            "failed to verify minimized corpus manifest {}",
            path.display()
        )
    })?;
    Ok(Some(manifest))
}

fn write_manifest(path: &Path, manifest: &MinimizedCorpusManifest) -> Result<()> {
    validate_minimized_manifest(manifest).map_err(|error| {
        anyhow::anyhow!("generated minimized corpus manifest is invalid: {error}")
    })?;
    verify_minimized_manifest_files(manifest).map_err(|error| {
        anyhow::anyhow!("generated minimized corpus files are invalid: {error}")
    })?;
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| anyhow::anyhow!("failed to encode minimized corpus manifest: {e}"))?;
    fs::write(path, json + "\n").with_context(|| {
        format!(
            "failed to write minimized corpus manifest {}",
            path.display()
        )
    })?;
    Ok(())
}

pub fn verify_minimized_manifest_files(
    manifest: &MinimizedCorpusManifest,
) -> std::result::Result<(), MinimizedManifestError> {
    let expected_paths: HashSet<&str> = manifest
        .units
        .iter()
        .map(|unit| unit.path.as_str())
        .collect();
    for unit in &manifest.units {
        let path = Path::new(&unit.path);
        if !path.is_file() {
            return Err(MinimizedManifestError::MissingFile {
                path: unit.path.clone(),
            });
        }
        let metadata = fs::metadata(path).map_err(|_| MinimizedManifestError::MissingFile {
            path: unit.path.clone(),
        })?;
        let actual_size = metadata.len();
        if actual_size != unit.size_bytes {
            return Err(MinimizedManifestError::FileSizeMismatch {
                path: unit.path.clone(),
                expected: unit.size_bytes,
                actual: actual_size,
            });
        }
        let actual_hash = file_hash(path).map_err(|_| MinimizedManifestError::MissingFile {
            path: unit.path.clone(),
        })?;
        if actual_hash != unit.sha256 {
            return Err(MinimizedManifestError::FileShaMismatch {
                path: unit.path.clone(),
                expected: unit.sha256.clone(),
                actual: actual_hash,
            });
        }
    }

    let root = Path::new(&manifest.import_root);
    if !root.exists() {
        return Ok(());
    }
    for entry in WalkDir::new(root)
        .min_depth(1)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.parent() == Some(root)
            && matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some(MINIMIZED_MANIFEST_FILE | MINIMIZED_README_FILE)
            )
        {
            continue;
        }
        let path_string = portable_path(path);
        if !expected_paths.contains(path_string.as_str()) {
            return Err(MinimizedManifestError::UnexpectedFile { path: path_string });
        }
    }

    Ok(())
}

pub fn run_import(args: &MinimizedImportArgs) -> Result<()> {
    let import_root = normalize_path_string(&args.import_root);
    let manifest_path_string = normalize_path_string(&manifest_path(args, &import_root));
    let manifest_path = Path::new(&manifest_path_string);
    let coverage_content = fs::read_to_string(&args.coverage_manifest).with_context(|| {
        format!(
            "failed to read coverage manifest {}",
            args.coverage_manifest
        )
    })?;
    let coverage_manifest = parse_coverage_manifest(&coverage_content).with_context(|| {
        format!(
            "failed to validate coverage manifest {}",
            args.coverage_manifest
        )
    })?;
    let source_root = normalize_path_string(
        args.source_root
            .as_deref()
            .unwrap_or(&coverage_manifest.output_dir),
    );

    fs::create_dir_all(&import_root)
        .with_context(|| format!("failed to create minimized import root {import_root}"))?;

    let existing_manifest = load_existing_manifest(manifest_path, &import_root)?;
    let mut units_by_path: BTreeMap<String, MinimizedCorpusUnit> = existing_manifest
        .map(|manifest| {
            manifest
                .units
                .into_iter()
                .map(|unit| (unit.path.clone(), unit))
                .collect()
        })
        .unwrap_or_default();

    let mut imported = 0usize;
    let mut already_present = 0usize;
    for unit in &coverage_manifest.units {
        let copied_name = coverage_copied_file_name(&unit.copied_path)?;
        let source_path = Path::new(&source_root).join(&unit.copied_path);
        if !source_path.is_file() {
            bail!(
                "coverage manifest unit {} points to missing copied unit {}",
                unit.source_path,
                source_path.display()
            );
        }
        let source_hash = file_hash(&source_path)?;
        if source_hash != unit.sha256 {
            bail!(
                "coverage manifest unit {} digest mismatch: expected {}, actual {}",
                source_path.display(),
                unit.sha256,
                source_hash
            );
        }
        let source_size = fs::metadata(&source_path)
            .with_context(|| format!("failed to stat {}", source_path.display()))?
            .len();
        if source_size != unit.size_bytes {
            bail!(
                "coverage manifest unit {} size mismatch: expected {}, actual {}",
                source_path.display(),
                unit.size_bytes,
                source_size
            );
        }

        let target_dir = Path::new(&import_root).join(&unit.target);
        fs::create_dir_all(&target_dir).with_context(|| {
            format!(
                "failed to create minimized target dir {}",
                target_dir.display()
            )
        })?;
        let dest_path = target_dir.join(copied_name);
        let dest_path_string = portable_path(&dest_path);
        if dest_path.exists() {
            let existing_hash = file_hash(&dest_path)?;
            if existing_hash != unit.sha256 {
                bail!(
                    "refusing to overwrite existing minimized unit {}: expected {}, actual {}",
                    dest_path.display(),
                    unit.sha256,
                    existing_hash
                );
            }
            already_present = already_present
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("minimized import count overflows"))?;
        } else {
            fs::copy(&source_path, &dest_path).with_context(|| {
                format!(
                    "failed to import minimized unit {} to {}",
                    source_path.display(),
                    dest_path.display()
                )
            })?;
            imported = imported
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("minimized import count overflows"))?;
        }

        let manifest_unit = MinimizedCorpusUnit {
            target: unit.target.clone(),
            path: dest_path_string.clone(),
            sha256: unit.sha256.clone(),
            size_bytes: unit.size_bytes,
            source_coverage_manifest: normalize_path_string(&args.coverage_manifest),
            source_path: unit.source_path.clone(),
            coverage_copied_path: unit.copied_path.clone(),
            lifecycle: unit.lifecycle.clone(),
        };
        if let Some(existing_unit) = units_by_path.get(&dest_path_string) {
            if existing_unit.sha256 != manifest_unit.sha256 {
                bail!(
                    "minimized manifest path {} already records digest {}, refusing {}",
                    dest_path_string,
                    existing_unit.sha256,
                    manifest_unit.sha256
                );
            }
        }
        units_by_path.insert(dest_path_string, manifest_unit);
    }

    let manifest = build_manifest(import_root.clone(), units_by_path.into_values().collect())?;
    write_manifest(manifest_path, &manifest)?;

    println!(
        "Imported minimized corpus: {} new, {} already present, {} total unit(s)",
        imported, already_present, manifest.total_units
    );
    println!("  Import root: {}", manifest.import_root);
    println!("  Manifest: {}", manifest_path.display());
    for target in &manifest.targets {
        println!(
            "  {}: {} unit(s), {} byte(s)",
            target.target, target.unit_count, target.size_bytes
        );
    }

    Ok(())
}

pub fn run_check(args: &MinimizedCheckArgs) -> Result<()> {
    let content = fs::read_to_string(&args.manifest)
        .with_context(|| format!("failed to read minimized corpus manifest {}", args.manifest))?;
    let manifest = parse_minimized_manifest(&content).with_context(|| {
        format!(
            "failed to validate minimized corpus manifest {}",
            args.manifest
        )
    })?;
    verify_minimized_manifest_files(&manifest)
        .with_context(|| format!("failed to verify minimized corpus files {}", args.manifest))?;

    println!(
        "Minimized corpus manifest OK: {} target(s), {} unit(s)",
        manifest.targets.len(),
        manifest.total_units
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_MINIMIZED_IMPORT_ROOT, MINIMIZED_CORPUS_SCHEMA, MinimizedCheckArgs,
        MinimizedCorpusManifest, MinimizedImportArgs, MinimizedManifestError, file_hash,
        parse_minimized_manifest, run_check, run_import, verify_minimized_manifest_files,
    };
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    fn coverage_manifest(output_dir: &str, sha256: &str, size: u64) -> String {
        json!({
            "schema": "erofs-rs.coverage-corpus.v1",
            "mode": "coverage",
            "input_dir": "corpus/rust-fuzz",
            "output_dir": output_dir,
            "total_input_units": 1,
            "collected_units": 1,
            "unique_hashes": 1,
            "duplicates_removed": 0,
            "recommended_import_root": DEFAULT_MINIMIZED_IMPORT_ROOT,
            "targets": [
                {
                    "target": "superblock_parse",
                    "input_units": 1,
                    "collected_units": 1,
                    "unique_hashes": 1,
                    "duplicates_removed": 0,
                    "recommended_import_dir": "corpus/seeds/minimized/superblock_parse"
                }
            ],
            "units": [
                {
                    "target": "superblock_parse",
                    "source_path": "superblock_parse/corpus/unit-a",
                    "copied_path": "coverage-interesting/unit-a",
                    "sha256": sha256,
                    "size_bytes": size,
                    "lifecycle": "queue/userspace",
                    "recommended_import_path": "corpus/seeds/minimized/superblock_parse/unit-a"
                }
            ]
        })
        .to_string()
    }

    #[test]
    fn minimized_import_copies_units_and_writes_manifest() {
        let tmp = TempDir::new().unwrap();
        let coverage_root = tmp.path().join("coverage-output");
        let coverage_units = coverage_root.join("coverage-interesting");
        fs::create_dir_all(&coverage_units).unwrap();
        let source_unit = coverage_units.join("unit-a");
        fs::write(&source_unit, b"coverage unit").unwrap();
        let sha256 = file_hash(&source_unit).unwrap();
        let size = fs::metadata(&source_unit).unwrap().len();
        let coverage_manifest_path = coverage_root.join("coverage-manifest.json");
        fs::write(
            &coverage_manifest_path,
            coverage_manifest(&coverage_root.to_string_lossy(), &sha256, size),
        )
        .unwrap();

        let import_root = tmp.path().join("minimized");
        let manifest_path = import_root.join("manifest.json");
        let args = MinimizedImportArgs {
            coverage_manifest: coverage_manifest_path.to_string_lossy().to_string(),
            source_root: None,
            import_root: import_root.to_string_lossy().to_string(),
            manifest: None,
        };

        run_import(&args).unwrap();
        run_import(&args).unwrap();

        let imported = import_root.join("superblock_parse").join("unit-a");
        assert_eq!(fs::read(&imported).unwrap(), b"coverage unit");
        let manifest_content = fs::read_to_string(&manifest_path).unwrap();
        let manifest = parse_minimized_manifest(&manifest_content).unwrap();
        assert_eq!(manifest.schema, MINIMIZED_CORPUS_SCHEMA);
        assert_eq!(manifest.total_units, 1);
        assert_eq!(manifest.targets[0].target, "superblock_parse");
        assert_eq!(manifest.units[0].sha256, sha256);
        assert_eq!(
            manifest.units[0].source_path,
            "superblock_parse/corpus/unit-a"
        );

        run_check(&MinimizedCheckArgs {
            manifest: manifest_path.to_string_lossy().to_string(),
        })
        .unwrap();
    }

    #[test]
    fn minimized_import_rejects_existing_path_with_different_digest() {
        let tmp = TempDir::new().unwrap();
        let coverage_root = tmp.path().join("coverage-output");
        let coverage_units = coverage_root.join("coverage-interesting");
        fs::create_dir_all(&coverage_units).unwrap();
        let source_unit = coverage_units.join("unit-a");
        fs::write(&source_unit, b"new unit").unwrap();
        let sha256 = file_hash(&source_unit).unwrap();
        let size = fs::metadata(&source_unit).unwrap().len();
        let coverage_manifest_path = coverage_root.join("coverage-manifest.json");
        fs::write(
            &coverage_manifest_path,
            coverage_manifest(&coverage_root.to_string_lossy(), &sha256, size),
        )
        .unwrap();

        let import_root = tmp.path().join("minimized");
        fs::create_dir_all(import_root.join("superblock_parse")).unwrap();
        fs::write(
            import_root.join("superblock_parse").join("unit-a"),
            b"old unit",
        )
        .unwrap();
        let args = MinimizedImportArgs {
            coverage_manifest: coverage_manifest_path.to_string_lossy().to_string(),
            source_root: None,
            import_root: import_root.to_string_lossy().to_string(),
            manifest: None,
        };

        let error = run_import(&args).unwrap_err();

        assert!(error.to_string().contains("refusing to overwrite"));
    }

    #[test]
    fn minimized_manifest_rejects_unlisted_files() {
        let tmp = TempDir::new().unwrap();
        let import_root = tmp.path().join("minimized");
        fs::create_dir_all(import_root.join("superblock_parse")).unwrap();
        fs::write(import_root.join("superblock_parse").join("extra"), b"extra").unwrap();
        let manifest = MinimizedCorpusManifest {
            schema: MINIMIZED_CORPUS_SCHEMA.to_string(),
            import_root: import_root.to_string_lossy().to_string(),
            total_units: 0,
            total_size_bytes: 0,
            targets: Vec::new(),
            units: Vec::new(),
        };

        let error = verify_minimized_manifest_files(&manifest).unwrap_err();

        assert!(matches!(
            error,
            MinimizedManifestError::UnexpectedFile { .. }
        ));
    }
}
