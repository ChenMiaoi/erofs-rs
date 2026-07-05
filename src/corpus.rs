use crate::cli::{CorpusArgs, CorpusMode};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

const COVERAGE_CATEGORY: &str = "coverage-interesting";
const COVERAGE_MANIFEST_FILE: &str = "coverage-manifest.json";
pub const COVERAGE_MANIFEST_SCHEMA: &str = "erofs-rs.coverage-corpus.v1";
pub const CMIN_SUMMARY_SCHEMA: &str = "erofs-rs.cmin-summary.v1";
const DEFAULT_COVERAGE_TARGET: &str = "unassigned";
const MINIMIZED_IMPORT_ROOT: &str = "corpus/seeds/minimized";
const RUST_FUZZ_CORPUS_ROOT: &str = "corpus/rust-fuzz";

const KNOWN_RESULTS: &[&str] = &[
    "accepted",
    "accepted_with_errors",
    "rejected_checksum",
    "rejected_io_error",
    "rejected_corruption",
    "rejected_invalid",
    "rejected_other",
    "rejected_timeout",
    "rejected_crash",
    "sanitizer_crash",
];

#[derive(Clone, Debug, Default)]
struct ManifestEntry {
    file: String,
    result: String,
}

#[derive(Clone, Debug)]
struct ArtifactRecord {
    file: String,
    category: String,
    lifecycle: String,
    hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageManifest {
    pub schema: String,
    pub mode: String,
    pub input_dir: String,
    pub output_dir: String,
    pub total_input_units: usize,
    pub collected_units: usize,
    pub unique_hashes: usize,
    pub duplicates_removed: usize,
    pub recommended_import_root: String,
    pub targets: Vec<CoverageTargetSummary>,
    pub units: Vec<CoverageManifestUnit>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageTargetSummary {
    pub target: String,
    pub input_units: usize,
    pub collected_units: usize,
    pub unique_hashes: usize,
    pub duplicates_removed: usize,
    pub recommended_import_dir: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageManifestUnit {
    pub target: String,
    pub source_path: String,
    pub copied_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub lifecycle: String,
    pub recommended_import_path: String,
}

#[derive(Clone, Debug, Default)]
struct CoverageTargetStats {
    input_units: usize,
    collected_units: usize,
    duplicates_removed: usize,
    hashes: HashSet<String>,
}

#[derive(Debug, Error)]
pub enum CoverageManifestError {
    #[error("failed to decode coverage manifest: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unsupported coverage manifest schema: {0}")]
    UnsupportedSchema(String),
    #[error("coverage manifest mode is {0}, expected coverage")]
    UnsupportedMode(String),
    #[error("coverage manifest field {0} is empty")]
    EmptyField(&'static str),
    #[error("coverage manifest field {field} has invalid SHA-256 digest: {sha256}")]
    InvalidSha256 { field: &'static str, sha256: String },
    #[error("coverage manifest contains duplicate target summary: {0}")]
    DuplicateTarget(String),
    #[error("coverage manifest contains duplicate unit SHA-256 digest: {0}")]
    DuplicateUnitSha256(String),
    #[error("coverage manifest contains duplicate unit {field}: {path}")]
    DuplicateUnitPath { field: &'static str, path: String },
    #[error("coverage manifest unit target has no summary: {0}")]
    MissingTargetSummary(String),
    #[error("coverage manifest field {field} has invalid path: {path}")]
    InvalidPath { field: &'static str, path: String },
    #[error(
        "coverage manifest {field} mismatch for target {target}: expected {expected}, actual {actual}"
    )]
    ImportPathMismatch {
        field: &'static str,
        target: String,
        expected: String,
        actual: String,
    },
    #[error("coverage manifest count mismatch for {field}: expected {expected}, actual {actual}")]
    CountMismatch {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}

pub fn parse_coverage_manifest(
    content: &str,
) -> std::result::Result<CoverageManifest, CoverageManifestError> {
    let manifest: CoverageManifest = serde_json::from_str(content)?;
    validate_coverage_manifest(&manifest)?;
    Ok(manifest)
}

pub fn validate_coverage_manifest(
    manifest: &CoverageManifest,
) -> std::result::Result<(), CoverageManifestError> {
    if manifest.schema != COVERAGE_MANIFEST_SCHEMA {
        return Err(CoverageManifestError::UnsupportedSchema(
            manifest.schema.clone(),
        ));
    }
    if manifest.mode != "coverage" {
        return Err(CoverageManifestError::UnsupportedMode(
            manifest.mode.clone(),
        ));
    }

    require_coverage_nonempty("input_dir", &manifest.input_dir)?;
    require_coverage_nonempty("output_dir", &manifest.output_dir)?;
    require_coverage_nonempty("recommended_import_root", &manifest.recommended_import_root)?;

    require_coverage_count(
        "collected_units",
        manifest.units.len(),
        manifest.collected_units,
    )?;
    let unique_unit_hashes = manifest
        .units
        .iter()
        .map(|unit| unit.sha256.as_str())
        .collect::<HashSet<_>>()
        .len();
    require_coverage_count("unique_hashes", unique_unit_hashes, manifest.unique_hashes)?;
    require_coverage_count(
        "total_input_units",
        manifest
            .unique_hashes
            .checked_add(manifest.duplicates_removed)
            .ok_or(CoverageManifestError::CountMismatch {
                field: "total_input_units",
                expected: usize::MAX,
                actual: manifest.total_input_units,
            })?,
        manifest.total_input_units,
    )?;

    let mut units_by_target: HashMap<&str, usize> = HashMap::new();
    let mut hashes_by_target: HashMap<&str, HashSet<&str>> = HashMap::new();
    let mut unit_hashes = HashSet::new();
    let mut copied_paths = HashSet::new();
    let mut recommended_import_paths = HashSet::new();
    for unit in &manifest.units {
        validate_coverage_unit(unit, &manifest.recommended_import_root)?;
        if !unit_hashes.insert(unit.sha256.as_str()) {
            return Err(CoverageManifestError::DuplicateUnitSha256(
                unit.sha256.clone(),
            ));
        }
        if !copied_paths.insert(unit.copied_path.as_str()) {
            return Err(CoverageManifestError::DuplicateUnitPath {
                field: "copied_path",
                path: unit.copied_path.clone(),
            });
        }
        if !recommended_import_paths.insert(unit.recommended_import_path.as_str()) {
            return Err(CoverageManifestError::DuplicateUnitPath {
                field: "recommended_import_path",
                path: unit.recommended_import_path.clone(),
            });
        }
        *units_by_target.entry(unit.target.as_str()).or_insert(0) += 1;
        hashes_by_target
            .entry(unit.target.as_str())
            .or_default()
            .insert(unit.sha256.as_str());
    }

    let mut target_names = HashSet::new();
    for target in &manifest.targets {
        validate_coverage_target_summary(
            target,
            &manifest.recommended_import_root,
            &units_by_target,
            &hashes_by_target,
        )?;
        if !target_names.insert(target.target.as_str()) {
            return Err(CoverageManifestError::DuplicateTarget(
                target.target.clone(),
            ));
        }
    }

    for target in units_by_target.keys() {
        if !target_names.contains(target) {
            return Err(CoverageManifestError::MissingTargetSummary(
                (*target).to_string(),
            ));
        }
    }

    require_coverage_sum(
        "targets.input_units",
        manifest.targets.iter().map(|target| target.input_units),
        manifest.total_input_units,
    )?;
    require_coverage_sum(
        "targets.collected_units",
        manifest.targets.iter().map(|target| target.collected_units),
        manifest.collected_units,
    )?;
    require_coverage_sum(
        "targets.duplicates_removed",
        manifest
            .targets
            .iter()
            .map(|target| target.duplicates_removed),
        manifest.duplicates_removed,
    )?;

    Ok(())
}

fn validate_coverage_target_summary(
    target: &CoverageTargetSummary,
    recommended_import_root: &str,
    units_by_target: &HashMap<&str, usize>,
    hashes_by_target: &HashMap<&str, HashSet<&str>>,
) -> std::result::Result<(), CoverageManifestError> {
    require_coverage_nonempty("targets.target", &target.target)?;
    require_coverage_path_component("targets.target", &target.target)?;
    require_coverage_nonempty(
        "targets.recommended_import_dir",
        &target.recommended_import_dir,
    )?;
    let expected_import_dir = recommended_import_dir_under(recommended_import_root, &target.target);
    if target.recommended_import_dir != expected_import_dir {
        return Err(CoverageManifestError::ImportPathMismatch {
            field: "targets.recommended_import_dir",
            target: target.target.clone(),
            expected: expected_import_dir,
            actual: target.recommended_import_dir.clone(),
        });
    }
    require_coverage_count(
        "targets.collected_units",
        *units_by_target.get(target.target.as_str()).unwrap_or(&0),
        target.collected_units,
    )?;
    require_coverage_count(
        "targets.unique_hashes",
        hashes_by_target
            .get(target.target.as_str())
            .map(HashSet::len)
            .unwrap_or(0),
        target.unique_hashes,
    )?;
    require_coverage_count(
        "targets.input_units",
        target
            .unique_hashes
            .checked_add(target.duplicates_removed)
            .ok_or(CoverageManifestError::CountMismatch {
                field: "targets.input_units",
                expected: usize::MAX,
                actual: target.input_units,
            })?,
        target.input_units,
    )?;
    Ok(())
}

fn validate_coverage_unit(
    unit: &CoverageManifestUnit,
    recommended_import_root: &str,
) -> std::result::Result<(), CoverageManifestError> {
    require_coverage_nonempty("units.target", &unit.target)?;
    require_coverage_path_component("units.target", &unit.target)?;
    require_coverage_nonempty("units.source_path", &unit.source_path)?;
    require_coverage_nonempty("units.copied_path", &unit.copied_path)?;
    require_coverage_nonempty("units.lifecycle", &unit.lifecycle)?;
    require_coverage_nonempty(
        "units.recommended_import_path",
        &unit.recommended_import_path,
    )?;
    if !is_sha256_digest(&unit.sha256) {
        return Err(CoverageManifestError::InvalidSha256 {
            field: "units.sha256",
            sha256: unit.sha256.clone(),
        });
    }
    let copied_name = coverage_copied_file_name(&unit.copied_path)?;
    let expected_import_path =
        recommended_import_path_under(recommended_import_root, &unit.target, copied_name);
    if unit.recommended_import_path != expected_import_path {
        return Err(CoverageManifestError::ImportPathMismatch {
            field: "units.recommended_import_path",
            target: unit.target.clone(),
            expected: expected_import_path,
            actual: unit.recommended_import_path.clone(),
        });
    }
    Ok(())
}

fn require_coverage_nonempty(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), CoverageManifestError> {
    if value.is_empty() {
        return Err(CoverageManifestError::EmptyField(field));
    }
    Ok(())
}

fn require_coverage_count(
    field: &'static str,
    expected: usize,
    actual: usize,
) -> std::result::Result<(), CoverageManifestError> {
    if expected != actual {
        return Err(CoverageManifestError::CountMismatch {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

fn require_coverage_sum(
    field: &'static str,
    values: impl IntoIterator<Item = usize>,
    actual: usize,
) -> std::result::Result<(), CoverageManifestError> {
    let mut expected = 0usize;
    for value in values {
        expected = expected
            .checked_add(value)
            .ok_or(CoverageManifestError::CountMismatch {
                field,
                expected: usize::MAX,
                actual,
            })?;
    }
    require_coverage_count(field, expected, actual)
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn require_coverage_path_component(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), CoverageManifestError> {
    if !is_portable_path_component(value) {
        return Err(CoverageManifestError::InvalidPath {
            field,
            path: value.to_string(),
        });
    }
    Ok(())
}

fn coverage_copied_file_name(path: &str) -> std::result::Result<&str, CoverageManifestError> {
    let mut components = path.split('/');
    match (components.next(), components.next(), components.next()) {
        (Some(category), Some(copied_name), None)
            if category == COVERAGE_CATEGORY && is_portable_path_component(copied_name) =>
        {
            Ok(copied_name)
        }
        _ => Err(CoverageManifestError::InvalidPath {
            field: "units.copied_path",
            path: path.to_string(),
        }),
    }
}

fn is_portable_path_component(value: &str) -> bool {
    !value.is_empty() && value != "." && value != ".." && !value.contains(['/', '\\'])
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CminSummaryReport {
    pub schema: String,
    pub engine: String,
    pub engine_version: String,
    pub toolchain: String,
    pub run_flags: Vec<String>,
    pub cmin_flags: Vec<String>,
    pub regression_flags: Vec<String>,
    #[serde(default)]
    pub total_before_cmin_units: Option<usize>,
    #[serde(default)]
    pub total_after_cmin_units: Option<usize>,
    #[serde(default)]
    pub total_removed_units: Option<usize>,
    #[serde(default)]
    pub total_artifact_count: Option<usize>,
    pub targets: Vec<CminTargetSummary>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CminTargetSummary {
    pub target: String,
    pub corpus_dir: String,
    pub artifact_dir: String,
    pub before_cmin_units: usize,
    pub after_cmin_units: usize,
    pub artifact_count: usize,
    pub run_log: String,
    pub cmin_log: String,
    pub regression_log: String,
}

#[derive(Debug, Error)]
pub enum CminSummaryError {
    #[error("failed to decode cmin summary: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unsupported cmin summary schema: {0}")]
    UnsupportedSchema(String),
    #[error("cmin summary field {0} is empty")]
    EmptyField(&'static str),
    #[error("cmin summary list {0} is empty")]
    EmptyList(&'static str),
    #[error(
        "cmin summary target {target} increased units after cmin: before={before}, after={after}"
    )]
    CminIncreased {
        target: String,
        before: usize,
        after: usize,
    },
    #[error("cmin summary field {field} has invalid path: {path}")]
    InvalidPath { field: &'static str, path: String },
    #[error(
        "cmin summary {field} mismatch for target {target}: expected {expected}, actual {actual}"
    )]
    PathMismatch {
        field: &'static str,
        target: String,
        expected: String,
        actual: String,
    },
    #[error("cmin summary count {0} is missing")]
    MissingCount(&'static str),
    #[error("cmin summary count mismatch for {field}: expected {expected}, actual {actual}")]
    CountMismatch {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("cmin summary count overflow for {0}")]
    CountOverflow(&'static str),
    #[error("cmin summary contains duplicate target: {0}")]
    DuplicateTarget(String),
}

pub fn parse_cmin_summary_report(
    content: &str,
) -> std::result::Result<CminSummaryReport, CminSummaryError> {
    let report: CminSummaryReport = serde_json::from_str(content)?;
    validate_cmin_summary_report(&report)?;
    Ok(report)
}

pub fn validate_cmin_summary_report(
    report: &CminSummaryReport,
) -> std::result::Result<(), CminSummaryError> {
    if report.schema != CMIN_SUMMARY_SCHEMA {
        return Err(CminSummaryError::UnsupportedSchema(report.schema.clone()));
    }

    require_cmin_nonempty("engine", &report.engine)?;
    require_cmin_nonempty("engine_version", &report.engine_version)?;
    require_cmin_nonempty("toolchain", &report.toolchain)?;
    require_cmin_list("run_flags", &report.run_flags)?;
    require_cmin_list("cmin_flags", &report.cmin_flags)?;
    require_cmin_list("regression_flags", &report.regression_flags)?;
    if report.targets.is_empty() {
        return Err(CminSummaryError::EmptyList("targets"));
    }

    let mut target_names = HashSet::new();
    for target in &report.targets {
        validate_cmin_target(target)?;
        if !target_names.insert(target.target.as_str()) {
            return Err(CminSummaryError::DuplicateTarget(target.target.clone()));
        }
    }

    let total_before = cmin_count_sum(
        "total_before_cmin_units",
        report.targets.iter().map(|target| target.before_cmin_units),
    )?;
    let total_after = cmin_count_sum(
        "total_after_cmin_units",
        report.targets.iter().map(|target| target.after_cmin_units),
    )?;
    let total_removed =
        total_before
            .checked_sub(total_after)
            .ok_or(CminSummaryError::CountMismatch {
                field: "total_removed_units",
                expected: total_before,
                actual: total_after,
            })?;
    let total_artifacts = cmin_count_sum(
        "total_artifact_count",
        report.targets.iter().map(|target| target.artifact_count),
    )?;
    validate_cmin_optional_totals(
        report,
        total_before,
        total_after,
        total_removed,
        total_artifacts,
    )?;

    Ok(())
}

fn validate_cmin_target(target: &CminTargetSummary) -> std::result::Result<(), CminSummaryError> {
    require_cmin_nonempty("targets.target", &target.target)?;
    require_cmin_path_component("targets.target", &target.target)?;
    require_cmin_nonempty("targets.corpus_dir", &target.corpus_dir)?;
    require_cmin_nonempty("targets.artifact_dir", &target.artifact_dir)?;
    require_cmin_nonempty("targets.run_log", &target.run_log)?;
    require_cmin_nonempty("targets.cmin_log", &target.cmin_log)?;
    require_cmin_nonempty("targets.regression_log", &target.regression_log)?;
    require_cmin_path(
        "targets.corpus_dir",
        &target.target,
        &target.corpus_dir,
        cmin_target_path(&target.target, "corpus"),
    )?;
    require_cmin_path(
        "targets.artifact_dir",
        &target.target,
        &target.artifact_dir,
        cmin_target_path(&target.target, "artifacts"),
    )?;
    require_cmin_path(
        "targets.run_log",
        &target.target,
        &target.run_log,
        cmin_target_path(&target.target, "run.log"),
    )?;
    require_cmin_path(
        "targets.cmin_log",
        &target.target,
        &target.cmin_log,
        cmin_target_path(&target.target, "cmin.log"),
    )?;
    require_cmin_path(
        "targets.regression_log",
        &target.target,
        &target.regression_log,
        cmin_target_path(&target.target, "regression.log"),
    )?;

    if target.after_cmin_units > target.before_cmin_units {
        return Err(CminSummaryError::CminIncreased {
            target: target.target.clone(),
            before: target.before_cmin_units,
            after: target.after_cmin_units,
        });
    }

    Ok(())
}

fn require_cmin_path_component(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), CminSummaryError> {
    if !is_portable_path_component(value) {
        return Err(CminSummaryError::InvalidPath {
            field,
            path: value.to_string(),
        });
    }
    Ok(())
}

fn require_cmin_path(
    field: &'static str,
    target: &str,
    actual: &str,
    expected: String,
) -> std::result::Result<(), CminSummaryError> {
    if actual != expected {
        return Err(CminSummaryError::PathMismatch {
            field,
            target: target.to_string(),
            expected,
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn cmin_target_path(target: &str, leaf: &str) -> String {
    portable_path(&Path::new(RUST_FUZZ_CORPUS_ROOT).join(target).join(leaf))
}

fn validate_cmin_optional_totals(
    report: &CminSummaryReport,
    total_before: usize,
    total_after: usize,
    total_removed: usize,
    total_artifacts: usize,
) -> std::result::Result<(), CminSummaryError> {
    let totals_present = report.total_before_cmin_units.is_some()
        || report.total_after_cmin_units.is_some()
        || report.total_removed_units.is_some()
        || report.total_artifact_count.is_some();
    if !totals_present {
        return Ok(());
    }

    require_cmin_count(
        "total_before_cmin_units",
        total_before,
        report
            .total_before_cmin_units
            .ok_or(CminSummaryError::MissingCount("total_before_cmin_units"))?,
    )?;
    require_cmin_count(
        "total_after_cmin_units",
        total_after,
        report
            .total_after_cmin_units
            .ok_or(CminSummaryError::MissingCount("total_after_cmin_units"))?,
    )?;
    require_cmin_count(
        "total_removed_units",
        total_removed,
        report
            .total_removed_units
            .ok_or(CminSummaryError::MissingCount("total_removed_units"))?,
    )?;
    require_cmin_count(
        "total_artifact_count",
        total_artifacts,
        report
            .total_artifact_count
            .ok_or(CminSummaryError::MissingCount("total_artifact_count"))?,
    )?;
    Ok(())
}

fn cmin_count_sum(
    field: &'static str,
    values: impl IntoIterator<Item = usize>,
) -> std::result::Result<usize, CminSummaryError> {
    let mut total = 0usize;
    for value in values {
        total = total
            .checked_add(value)
            .ok_or(CminSummaryError::CountOverflow(field))?;
    }
    Ok(total)
}

fn require_cmin_count(
    field: &'static str,
    expected: usize,
    actual: usize,
) -> std::result::Result<(), CminSummaryError> {
    if expected != actual {
        return Err(CminSummaryError::CountMismatch {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

fn require_cmin_nonempty(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), CminSummaryError> {
    if value.is_empty() {
        return Err(CminSummaryError::EmptyField(field));
    }
    Ok(())
}

fn require_cmin_list(
    field: &'static str,
    values: &[String],
) -> std::result::Result<(), CminSummaryError> {
    if values.is_empty() {
        return Err(CminSummaryError::EmptyList(field));
    }
    for value in values {
        require_cmin_nonempty(field, value)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct CorpusSummary {
    mode: CorpusMode,
    manifests_processed: usize,
    total_files: usize,
    copied_artifacts: usize,
    unique_hashes: usize,
    duplicates_removed: usize,
    coverage_interesting: usize,
    crashes: usize,
    timeouts: usize,
}

fn file_hash(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let data =
        fs::read(path).map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
    hasher.update(data);
    Ok(hex::encode(hasher.finalize()))
}

fn read_manifest(path: &Path) -> Result<Vec<ManifestEntry>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read mutation manifest {}", path.display()))?;
    let mut entries = Vec::new();
    for (line_index, line) in content.lines().enumerate() {
        let line = line.trim();
        if should_skip_manifest_line(line) {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(result_idx) = parts.iter().rposition(|p| KNOWN_RESULTS.contains(p)) else {
            bail!(
                "malformed manifest row {}:{}: missing known classification",
                path.display(),
                line_index + 1
            );
        };
        if result_idx < 2 {
            bail!(
                "malformed manifest row {}:{}: expected artifact path before classification",
                path.display(),
                line_index + 1
            );
        }
        let file = parts[0];
        if file.is_empty() {
            bail!(
                "malformed manifest row {}:{}: empty artifact path",
                path.display(),
                line_index + 1
            );
        };
        entries.push(ManifestEntry {
            file: file.to_string(),
            result: parts[result_idx].to_string(),
        });
    }
    Ok(entries)
}

fn should_skip_manifest_line(line: &str) -> bool {
    line.is_empty()
        || line.starts_with('#')
        || line.starts_with("output_file")
        || line.bytes().all(|byte| byte == b'-')
}

fn classify_artifact(entry: &ManifestEntry) -> String {
    entry.result.clone()
}

fn lifecycle_bucket(category: &str) -> &'static str {
    match category {
        COVERAGE_CATEGORY | "accepted" | "accepted_with_errors" => "queue/userspace",
        "rejected_checksum" => "rejects/checksum",
        "rejected_corruption" => "rejects/corruption",
        "rejected_invalid" => "rejects/invalid",
        "rejected_io_error" | "rejected_other" => "rejects/other",
        "rejected_timeout" => "timeouts/userspace",
        "rejected_crash" => "crashes/userspace",
        _ if category.contains("sanitizer") => "crashes/sanitizer",
        _ if category.contains("kernel") && category.contains("timeout") => "timeouts/kernel",
        _ if category.contains("kernel") => "crashes/kernel",
        _ => "queue/userspace",
    }
}

fn corpus_mode_name(mode: CorpusMode) -> &'static str {
    match mode {
        CorpusMode::Hash => "hash",
        CorpusMode::Coverage => "coverage",
        CorpusMode::Classification => "classification",
    }
}

fn ensure_category_dirs(output_dir: &Path) -> Result<HashMap<String, PathBuf>> {
    let mut categories = HashMap::new();
    for category in KNOWN_RESULTS {
        let dir = output_dir.join(category);
        fs::create_dir_all(&dir).map_err(|e| {
            anyhow::anyhow!("failed to create category directory {}: {e}", dir.display())
        })?;
        categories.insert((*category).to_string(), dir);
    }
    Ok(categories)
}

fn safe_file_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .map(|file| file.to_string_lossy().to_string())
        .filter(|file| !file.is_empty())
        .unwrap_or_else(|| "artifact".to_string())
}

fn unique_destination(dir: &Path, source_name: &str, hash: &str) -> PathBuf {
    let base = safe_file_name(source_name);
    let first = dir.join(&base);
    if !first.exists() {
        return first;
    }

    let hash_prefix = &hash[..16];
    let hashed = dir.join(format!("{hash_prefix}-{base}"));
    if !hashed.exists() {
        return hashed;
    }

    for idx in 1usize.. {
        let candidate = dir.join(format!("{hash_prefix}-{idx}-{base}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("unbounded destination suffix search should always return");
}

fn copy_artifact(
    source: &Path,
    category_dir: &Path,
    source_name: &str,
    hash: &str,
) -> Result<String> {
    let dest_path = unique_destination(category_dir, source_name, hash);
    fs::copy(source, &dest_path)
        .map_err(|e| anyhow::anyhow!("failed to copy {}: {e}", source.display()))?;
    Ok(dest_path
        .file_name()
        .map(|file| file.to_string_lossy().to_string())
        .unwrap_or_else(|| dest_path.display().to_string()))
}

fn find_manifests(input_dir: &Path) -> Vec<PathBuf> {
    let mut manifests = Vec::new();
    for entry in WalkDir::new(input_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_name() == "manifest.txt" {
            manifests.push(entry.path().to_path_buf());
        }
    }
    manifests.sort();
    manifests
}

fn collect_manifest_artifacts(
    args: &CorpusArgs,
    output_dir: &Path,
) -> Result<(CorpusSummary, Vec<ArtifactRecord>)> {
    let categories = ensure_category_dirs(output_dir)?;
    let manifests = find_manifests(Path::new(&args.input_dir));

    println!("Found {} manifest files", manifests.len());

    let mut records = Vec::new();
    let mut seen_hashes = HashSet::new();
    let mut total_files = 0usize;
    let mut duplicates_removed = 0usize;

    for manifest_path in &manifests {
        let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));
        let entries = read_manifest(manifest_path)?;
        total_files = total_files
            .checked_add(entries.len())
            .ok_or_else(|| anyhow::anyhow!("corpus file count overflows"))?;

        for entry in entries {
            let file_path = manifest_dir.join(&entry.file);
            if !file_path.exists() {
                bail!(
                    "mutation manifest {} references missing artifact {}",
                    manifest_path.display(),
                    file_path.display()
                );
            }

            let hash = file_hash(&file_path)?;
            if args.mode == CorpusMode::Hash && !seen_hashes.insert(hash.clone()) {
                duplicates_removed = duplicates_removed
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("duplicate count overflows"))?;
                continue;
            }
            seen_hashes.insert(hash.clone());

            let category = classify_artifact(&entry);
            let category_dir = categories
                .get(&category)
                .or_else(|| categories.get("rejected_other"))
                .ok_or_else(|| anyhow::anyhow!("missing rejected_other category"))?;
            let copied_name = copy_artifact(&file_path, category_dir, &entry.file, &hash)?;
            records.push(ArtifactRecord {
                file: copied_name,
                lifecycle: lifecycle_bucket(&category).to_string(),
                category,
                hash,
            });
        }
    }

    let summary = build_summary(
        args.mode,
        manifests.len(),
        total_files,
        records.len(),
        seen_hashes.len(),
        duplicates_removed,
        &records,
    );
    Ok((summary, records))
}

fn has_component(path: &Path, expected: &str) -> bool {
    path.components().any(|component| match component {
        std::path::Component::Normal(part) => part == expected,
        _ => false,
    })
}

fn should_collect_coverage_file(path: &Path) -> bool {
    if has_component(path, "artifacts") {
        return false;
    }

    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if matches!(file_name, "manifest.txt" | "report.txt") {
        return false;
    }
    !matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("json" | "jsonl" | "log" | "stdout" | "stderr")
    )
}

fn portable_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn relative_path_string(root: &Path, path: &Path) -> String {
    portable_path(path.strip_prefix(root).unwrap_or(path))
}

fn recommended_import_dir(target: &str) -> String {
    recommended_import_dir_under(MINIMIZED_IMPORT_ROOT, target)
}

fn recommended_import_path(target: &str, copied_name: &str) -> String {
    recommended_import_path_under(MINIMIZED_IMPORT_ROOT, target, copied_name)
}

fn recommended_import_dir_under(root: &str, target: &str) -> String {
    portable_path(&Path::new(root).join(target))
}

fn recommended_import_path_under(root: &str, target: &str, copied_name: &str) -> String {
    portable_path(&Path::new(root).join(target).join(copied_name))
}

fn infer_coverage_target(input_dir: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(input_dir).unwrap_or(path);
    let components: Vec<String> = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();

    if let Some(corpus_idx) = components
        .iter()
        .position(|component| component == "corpus")
    {
        if corpus_idx > 0 {
            return components[corpus_idx - 1].clone();
        }
        return input_dir
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| DEFAULT_COVERAGE_TARGET.to_string());
    }

    if components.len() > 1 {
        return components[0].clone();
    }

    DEFAULT_COVERAGE_TARGET.to_string()
}

fn coverage_target_summaries(
    stats: BTreeMap<String, CoverageTargetStats>,
) -> Vec<CoverageTargetSummary> {
    stats
        .into_iter()
        .map(|(target, stats)| CoverageTargetSummary {
            recommended_import_dir: recommended_import_dir(&target),
            target,
            input_units: stats.input_units,
            collected_units: stats.collected_units,
            unique_hashes: stats.hashes.len(),
            duplicates_removed: stats.duplicates_removed,
        })
        .collect()
}

fn collect_coverage_artifacts(
    args: &CorpusArgs,
    output_dir: &Path,
) -> Result<(CorpusSummary, Vec<ArtifactRecord>, CoverageManifest)> {
    let coverage_dir = output_dir.join(COVERAGE_CATEGORY);
    fs::create_dir_all(&coverage_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to create coverage directory {}: {e}",
            coverage_dir.display()
        )
    })?;

    let mut inputs = Vec::new();
    for entry in WalkDir::new(&args.input_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() && should_collect_coverage_file(entry.path()) {
            inputs.push(entry.path().to_path_buf());
        }
    }
    inputs.sort();

    let mut records = Vec::new();
    let mut manifest_units = Vec::new();
    let mut target_stats: BTreeMap<String, CoverageTargetStats> = BTreeMap::new();
    let mut seen_hashes = HashSet::new();
    let mut duplicates_removed = 0usize;
    let input_root = Path::new(&args.input_dir);

    for path in &inputs {
        let target = infer_coverage_target(input_root, path);
        let stats = target_stats.entry(target.clone()).or_default();
        stats.input_units = stats
            .input_units
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("coverage input count overflows for {target}"))?;

        let hash = file_hash(path)?;
        if !seen_hashes.insert(hash.clone()) {
            duplicates_removed = duplicates_removed
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("duplicate count overflows"))?;
            stats.duplicates_removed = stats
                .duplicates_removed
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("duplicate count overflows for {target}"))?;
            continue;
        }

        let copied_name = copy_artifact(
            path,
            &coverage_dir,
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("coverage-unit"),
            &hash,
        )?;
        stats.collected_units = stats
            .collected_units
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("coverage unit count overflows for {target}"))?;
        stats.hashes.insert(hash.clone());

        let copied_path = Path::new(COVERAGE_CATEGORY).join(&copied_name);
        let recommended_import_path = recommended_import_path(&target, &copied_name);
        let size_bytes = fs::metadata(path)
            .map_err(|e| anyhow::anyhow!("failed to stat {}: {e}", path.display()))?
            .len();
        manifest_units.push(CoverageManifestUnit {
            target,
            source_path: relative_path_string(input_root, path),
            copied_path: portable_path(&copied_path),
            sha256: hash.clone(),
            size_bytes,
            lifecycle: lifecycle_bucket(COVERAGE_CATEGORY).to_string(),
            recommended_import_path,
        });

        records.push(ArtifactRecord {
            file: copied_name,
            category: COVERAGE_CATEGORY.to_string(),
            lifecycle: lifecycle_bucket(COVERAGE_CATEGORY).to_string(),
            hash,
        });
    }

    let summary = build_summary(
        CorpusMode::Coverage,
        0,
        inputs.len(),
        records.len(),
        seen_hashes.len(),
        duplicates_removed,
        &records,
    );
    let manifest = CoverageManifest {
        schema: COVERAGE_MANIFEST_SCHEMA.to_string(),
        mode: "coverage".to_string(),
        input_dir: portable_path(input_root),
        output_dir: portable_path(output_dir),
        total_input_units: summary.total_files,
        collected_units: summary.copied_artifacts,
        unique_hashes: summary.unique_hashes,
        duplicates_removed: summary.duplicates_removed,
        recommended_import_root: MINIMIZED_IMPORT_ROOT.to_string(),
        targets: coverage_target_summaries(target_stats),
        units: manifest_units,
    };
    Ok((summary, records, manifest))
}

fn build_summary(
    mode: CorpusMode,
    manifests_processed: usize,
    total_files: usize,
    copied_artifacts: usize,
    unique_hashes: usize,
    duplicates_removed: usize,
    records: &[ArtifactRecord],
) -> CorpusSummary {
    CorpusSummary {
        mode,
        manifests_processed,
        total_files,
        copied_artifacts,
        unique_hashes,
        duplicates_removed,
        coverage_interesting: records
            .iter()
            .filter(|record| record.category == COVERAGE_CATEGORY)
            .count(),
        crashes: records
            .iter()
            .filter(|record| {
                record.category.contains("crash") || record.category.contains("sanitizer")
            })
            .count(),
        timeouts: records
            .iter()
            .filter(|record| record.category.contains("timeout"))
            .count(),
    }
}

fn category_counts(records: &[ArtifactRecord]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for record in records {
        *counts.entry(record.category.clone()).or_insert(0) += 1;
    }
    let mut sorted_counts: Vec<_> = counts.into_iter().collect();
    sorted_counts.sort_by(|a, b| a.0.cmp(&b.0));
    sorted_counts
}

fn lifecycle_counts(records: &[ArtifactRecord]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for record in records {
        *counts.entry(record.lifecycle.clone()).or_insert(0) += 1;
    }
    let mut sorted_counts: Vec<_> = counts.into_iter().collect();
    sorted_counts.sort_by(|a, b| a.0.cmp(&b.0));
    sorted_counts
}

fn write_report(path: &Path, summary: &CorpusSummary, records: &[ArtifactRecord]) -> Result<()> {
    let counts = category_counts(records);
    let lifecycles = lifecycle_counts(records);
    let mut report_lines = vec![
        "# EROFS Fuzzing Corpus Report".to_string(),
        String::new(),
        format!("Mode: {}", corpus_mode_name(summary.mode)),
        format!("Total manifests processed: {}", summary.manifests_processed),
        format!("Total files: {}", summary.total_files),
        format!("Unique hashes: {}", summary.unique_hashes),
        format!("Collected artifacts: {}", summary.copied_artifacts),
        format!("Duplicates removed: {}", summary.duplicates_removed),
        format!(
            "Coverage-interesting units: {}",
            summary.coverage_interesting
        ),
        format!("Crashes: {}", summary.crashes),
        format!("Timeouts: {}", summary.timeouts),
        String::new(),
        "## Classification Summary".to_string(),
        String::new(),
    ];

    if summary.mode == CorpusMode::Hash {
        report_lines.insert(5, format!("Total mutations: {}", summary.total_files));
        report_lines.insert(7, format!("Unique artifacts: {}", summary.copied_artifacts));
    }

    for (cat, count) in &counts {
        report_lines.push(format!("- {cat}: {count}"));
    }

    report_lines.extend([
        String::new(),
        "## Lifecycle Summary".to_string(),
        String::new(),
    ]);

    for (lifecycle, count) in &lifecycles {
        report_lines.push(format!("- {lifecycle}: {count}"));
    }

    report_lines.extend([
        String::new(),
        "## Notes".to_string(),
        String::new(),
        "- `hash` mode reads mutation manifests and deduplicates by full SHA-256.".to_string(),
        "- `classification` mode reads mutation manifests and preserves every listed artifact.".to_string(),
        "- `coverage` mode consumes corpus units already selected by a coverage-guided engine.".to_string(),
        "- `rejected_checksum`: fsck/kernel rejected because the superblock checksum no longer matches.".to_string(),
        "  This is expected for any mutation that changes bytes covered by the checksum.".to_string(),
        "- `accepted`: fsck accepted with no errors printed.".to_string(),
        "- `accepted_with_errors`: fsck exited 0 but printed errors (rare).".to_string(),
        "- `rejected_io_error` / `rejected_corruption` / `rejected_invalid`: clean rejection paths.".to_string(),
        "- `rejected_timeout`: fsck exceeded the configured timeout.".to_string(),
        "- `rejected_crash`: fsck terminated because of a fatal signal.".to_string(),
        "- Lifecycle buckets map artifacts into queue, rejects, crashes, and timeouts for triage.".to_string(),
        String::new(),
        "## All Collected Artifacts".to_string(),
        String::new(),
        format!(
            "{:<50} {:<25} {:<22} {:<64}",
            "file", "category", "lifecycle", "hash"
        ),
        "-".repeat(164),
    ]);

    for record in records {
        report_lines.push(format!(
            "{:<50} {:<25} {:<22} {}",
            record.file, record.category, record.lifecycle, record.hash
        ));
    }

    fs::write(path, report_lines.join("\n") + "\n")
        .map_err(|e| anyhow::anyhow!("failed to write report {}: {e}", path.display()))?;
    Ok(())
}

fn write_coverage_manifest(path: &Path, manifest: &CoverageManifest) -> Result<()> {
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| anyhow::anyhow!("failed to encode coverage manifest: {e}"))?;
    fs::write(path, json + "\n").map_err(|e| {
        anyhow::anyhow!("failed to write coverage manifest {}: {e}", path.display())
    })?;
    Ok(())
}

pub fn run(args: &CorpusArgs) -> Result<()> {
    if !Path::new(&args.input_dir).exists() {
        bail!("Input directory not found: {}", args.input_dir);
    }

    let output_dir = Path::new(&args.output_dir);
    fs::create_dir_all(output_dir)
        .map_err(|e| anyhow::anyhow!("failed to create output directory: {e}"))?;

    let (summary, records, coverage_manifest) = match args.mode {
        CorpusMode::Hash | CorpusMode::Classification => {
            let (summary, records) = collect_manifest_artifacts(args, output_dir)?;
            (summary, records, None)
        }
        CorpusMode::Coverage => {
            let (summary, records, manifest) = collect_coverage_artifacts(args, output_dir)?;
            (summary, records, Some(manifest))
        }
    };

    if let Some(manifest) = &coverage_manifest {
        write_coverage_manifest(&output_dir.join(COVERAGE_MANIFEST_FILE), manifest)?;
    }
    write_report(Path::new(&args.report), &summary, &records)?;

    println!(
        "\nDone. Collected {} artifact(s).",
        summary.copied_artifacts
    );
    println!("  Mode: {}", corpus_mode_name(summary.mode));
    println!("  Unique hashes: {}", summary.unique_hashes);
    println!("  Deduplicated: {}", summary.duplicates_removed);
    println!("  Coverage-interesting: {}", summary.coverage_interesting);
    println!("  Crashes: {}", summary.crashes);
    println!("  Timeouts: {}", summary.timeouts);
    println!("  Report: {}", args.report);
    if coverage_manifest.is_some() {
        println!(
            "  Coverage manifest: {}",
            output_dir.join(COVERAGE_MANIFEST_FILE).display()
        );
    }
    println!("\nCategories:");
    for (cat, count) in category_counts(&records) {
        println!("  {cat}: {count}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CMIN_SUMMARY_SCHEMA, COVERAGE_MANIFEST_SCHEMA, CminSummaryError, CoverageManifestError,
        DEFAULT_COVERAGE_TARGET, collect_manifest_artifacts, file_hash, infer_coverage_target,
        lifecycle_bucket, parse_cmin_summary_report, parse_coverage_manifest, read_manifest,
        should_collect_coverage_file,
    };
    use crate::cli::{CorpusArgs, CorpusMode};
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn file_hash_returns_full_sha256_digest() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("input.erofs");
        fs::write(&path, b"abc").unwrap();

        assert_eq!(
            file_hash(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn lifecycle_bucket_maps_fsck_classifications() {
        assert_eq!(lifecycle_bucket("accepted"), "queue/userspace");
        assert_eq!(lifecycle_bucket("coverage-interesting"), "queue/userspace");
        assert_eq!(lifecycle_bucket("rejected_checksum"), "rejects/checksum");
        assert_eq!(
            lifecycle_bucket("rejected_corruption"),
            "rejects/corruption"
        );
        assert_eq!(lifecycle_bucket("rejected_invalid"), "rejects/invalid");
        assert_eq!(lifecycle_bucket("rejected_io_error"), "rejects/other");
        assert_eq!(lifecycle_bucket("rejected_timeout"), "timeouts/userspace");
        assert_eq!(lifecycle_bucket("rejected_crash"), "crashes/userspace");
        assert_eq!(lifecycle_bucket("sanitizer_crash"), "crashes/sanitizer");
        assert_eq!(lifecycle_bucket("asan_sanitizer"), "crashes/sanitizer");
        assert_eq!(lifecycle_bucket("kernel_oops"), "crashes/kernel");
    }

    #[test]
    fn coverage_mode_skips_logs_and_manifests() {
        assert!(!should_collect_coverage_file(Path::new("manifest.txt")));
        assert!(!should_collect_coverage_file(Path::new("run.log")));
        assert!(!should_collect_coverage_file(Path::new("sidecar.json")));
        assert!(!should_collect_coverage_file(Path::new(
            "cmin-summary.jsonl"
        )));
        assert!(!should_collect_coverage_file(Path::new(
            "superblock_parse/artifacts/crash-unit"
        )));
        assert!(should_collect_coverage_file(Path::new("fuzz-unit")));
        assert!(should_collect_coverage_file(Path::new("input.erofs")));
    }

    #[test]
    fn coverage_target_infers_cargo_fuzz_layout() {
        let root = Path::new("corpus/rust-fuzz");

        assert_eq!(
            infer_coverage_target(
                root,
                Path::new("corpus/rust-fuzz/superblock_parse/corpus/a")
            ),
            "superblock_parse"
        );
        assert_eq!(
            infer_coverage_target(root, Path::new("corpus/rust-fuzz/inode_locate/a")),
            "inode_locate"
        );
        assert_eq!(
            infer_coverage_target(root, Path::new("corpus/rust-fuzz/unit-a")),
            DEFAULT_COVERAGE_TARGET
        );
    }

    #[test]
    fn mutation_manifest_rejects_malformed_rows() {
        let tmp = TempDir::new().unwrap();
        let manifest = tmp.path().join("manifest.txt");
        fs::write(&manifest, "not enough columns\n").unwrap();

        let error = read_manifest(&manifest).unwrap_err();

        assert!(error.to_string().contains("malformed manifest row"));
        assert!(error.to_string().contains("missing known classification"));
    }

    #[test]
    fn corpus_collection_rejects_missing_manifest_artifacts() {
        let tmp = TempDir::new().unwrap();
        let input = tmp.path().join("input");
        let output = tmp.path().join("output");
        fs::create_dir_all(&input).unwrap();
        fs::write(
            input.join("manifest.txt"),
            "missing.erofs target field mutation value class checksum accepted reason\n",
        )
        .unwrap();
        let args = CorpusArgs {
            input_dir: input.to_string_lossy().to_string(),
            output_dir: output.to_string_lossy().to_string(),
            report: tmp.path().join("report.txt").to_string_lossy().to_string(),
            mode: CorpusMode::Hash,
        };

        let error = collect_manifest_artifacts(&args, &output).unwrap_err();

        assert!(error.to_string().contains("references missing artifact"));
    }

    const VALID_COVERAGE_MANIFEST: &str = r#"{
  "schema": "erofs-rs.coverage-corpus.v1",
  "mode": "coverage",
  "input_dir": "corpus/rust-fuzz",
  "output_dir": "corpus/minimized/rust-fuzz",
  "total_input_units": 2,
  "collected_units": 1,
  "unique_hashes": 1,
  "duplicates_removed": 1,
  "recommended_import_root": "corpus/seeds/minimized",
  "targets": [
    {
      "target": "superblock_parse",
      "input_units": 2,
      "collected_units": 1,
      "unique_hashes": 1,
      "duplicates_removed": 1,
      "recommended_import_dir": "corpus/seeds/minimized/superblock_parse"
    }
  ],
  "units": [
    {
      "target": "superblock_parse",
      "source_path": "superblock_parse/corpus/unit-a",
      "copied_path": "coverage-interesting/unit-a",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "size_bytes": 10,
      "lifecycle": "queue/userspace",
      "recommended_import_path": "corpus/seeds/minimized/superblock_parse/unit-a"
    }
  ]
}"#;

    #[test]
    fn coverage_manifest_accepts_valid_report() {
        let report = parse_coverage_manifest(VALID_COVERAGE_MANIFEST).unwrap();

        assert_eq!(report.schema, COVERAGE_MANIFEST_SCHEMA);
        assert_eq!(report.mode, "coverage");
        assert_eq!(report.targets[0].target, "superblock_parse");
    }

    #[test]
    fn coverage_manifest_rejects_unknown_schema() {
        let report = VALID_COVERAGE_MANIFEST
            .replace(COVERAGE_MANIFEST_SCHEMA, "erofs-rs.coverage-corpus.v0");

        let error = parse_coverage_manifest(&report).unwrap_err();

        assert!(matches!(error, CoverageManifestError::UnsupportedSchema(_)));
    }

    #[test]
    fn coverage_manifest_rejects_invalid_digest() {
        let report = VALID_COVERAGE_MANIFEST.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "not-sha",
        );

        let error = parse_coverage_manifest(&report).unwrap_err();

        assert!(matches!(
            error,
            CoverageManifestError::InvalidSha256 {
                field: "units.sha256",
                ..
            }
        ));
    }

    #[test]
    fn coverage_manifest_rejects_target_path_component() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_COVERAGE_MANIFEST).unwrap();
        report["targets"][0]["target"] = serde_json::json!("../superblock_parse");
        report["units"][0]["target"] = serde_json::json!("../superblock_parse");
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_coverage_manifest(&report).unwrap_err();

        assert!(matches!(
            error,
            CoverageManifestError::InvalidPath {
                field: "units.target",
                path,
            } if path == "../superblock_parse"
        ));
    }

    #[test]
    fn coverage_manifest_rejects_copied_path_outside_category() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_COVERAGE_MANIFEST).unwrap();
        report["units"][0]["copied_path"] = serde_json::json!("other/unit-a");
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_coverage_manifest(&report).unwrap_err();

        assert!(matches!(
            error,
            CoverageManifestError::InvalidPath {
                field: "units.copied_path",
                path,
            } if path == "other/unit-a"
        ));
    }

    #[test]
    fn coverage_manifest_rejects_total_count_mismatch() {
        let report = VALID_COVERAGE_MANIFEST
            .replace(r#""total_input_units": 2"#, r#""total_input_units": 3"#);

        let error = parse_coverage_manifest(&report).unwrap_err();

        assert!(matches!(
            error,
            CoverageManifestError::CountMismatch {
                field: "total_input_units",
                expected: 2,
                actual: 3,
            }
        ));
    }

    #[test]
    fn coverage_manifest_rejects_unit_without_target_summary() {
        let report = VALID_COVERAGE_MANIFEST.replace(
            r#"  "targets": [
    {
      "target": "superblock_parse",
      "input_units": 2,
      "collected_units": 1,
      "unique_hashes": 1,
      "duplicates_removed": 1,
      "recommended_import_dir": "corpus/seeds/minimized/superblock_parse"
    }
  ],"#,
            r#"  "targets": [],"#,
        );

        let error = parse_coverage_manifest(&report).unwrap_err();

        assert!(matches!(
            error,
            CoverageManifestError::MissingTargetSummary(target)
                if target == "superblock_parse"
        ));
    }

    #[test]
    fn coverage_manifest_rejects_duplicate_target_summary() {
        let report = VALID_COVERAGE_MANIFEST.replace(
            r#"      "duplicates_removed": 1,
      "recommended_import_dir": "corpus/seeds/minimized/superblock_parse"
    }"#,
            r#"      "duplicates_removed": 1,
      "recommended_import_dir": "corpus/seeds/minimized/superblock_parse"
    },
    {
      "target": "superblock_parse",
      "input_units": 2,
      "collected_units": 1,
      "unique_hashes": 1,
      "duplicates_removed": 1,
      "recommended_import_dir": "corpus/seeds/minimized/superblock_parse"
    }"#,
        );

        let error = parse_coverage_manifest(&report).unwrap_err();

        assert!(matches!(
            error,
            CoverageManifestError::DuplicateTarget(target) if target == "superblock_parse"
        ));
    }

    #[test]
    fn coverage_manifest_rejects_duplicate_unit_hash() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_COVERAGE_MANIFEST).unwrap();
        report["collected_units"] = serde_json::json!(2);
        report["targets"][0]["collected_units"] = serde_json::json!(2);
        let unit = report["units"][0].clone();
        report["units"].as_array_mut().unwrap().push(unit);
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_coverage_manifest(&report).unwrap_err();

        assert!(matches!(
            error,
            CoverageManifestError::DuplicateUnitSha256(sha)
                if sha == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
    }

    #[test]
    fn coverage_manifest_rejects_duplicate_unit_path() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_COVERAGE_MANIFEST).unwrap();
        report["total_input_units"] = serde_json::json!(2);
        report["collected_units"] = serde_json::json!(2);
        report["unique_hashes"] = serde_json::json!(2);
        report["duplicates_removed"] = serde_json::json!(0);
        report["targets"][0]["collected_units"] = serde_json::json!(2);
        report["targets"][0]["unique_hashes"] = serde_json::json!(2);
        report["targets"][0]["duplicates_removed"] = serde_json::json!(0);
        let mut unit = report["units"][0].clone();
        unit["sha256"] =
            serde_json::json!("1111111111111111111111111111111111111111111111111111111111111111");
        report["units"].as_array_mut().unwrap().push(unit);
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_coverage_manifest(&report).unwrap_err();

        assert!(matches!(
            error,
            CoverageManifestError::DuplicateUnitPath {
                field: "copied_path",
                path,
            } if path == "coverage-interesting/unit-a"
        ));
    }

    #[test]
    fn coverage_manifest_rejects_recommended_import_dir_mismatch() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_COVERAGE_MANIFEST).unwrap();
        report["targets"][0]["recommended_import_dir"] =
            serde_json::json!("corpus/seeds/minimized/inode_locate");
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_coverage_manifest(&report).unwrap_err();

        assert!(matches!(
            error,
            CoverageManifestError::ImportPathMismatch {
                field: "targets.recommended_import_dir",
                target,
                expected,
                actual,
            } if target == "superblock_parse"
                && expected == "corpus/seeds/minimized/superblock_parse"
                && actual == "corpus/seeds/minimized/inode_locate"
        ));
    }

    #[test]
    fn coverage_manifest_rejects_recommended_import_path_mismatch() {
        let report = VALID_COVERAGE_MANIFEST.replace(
            "corpus/seeds/minimized/superblock_parse/unit-a",
            "corpus/seeds/minimized/inode_locate/unit-a",
        );

        let error = parse_coverage_manifest(&report).unwrap_err();

        assert!(matches!(
            error,
            CoverageManifestError::ImportPathMismatch {
                field: "units.recommended_import_path",
                target,
                expected,
                actual,
            } if target == "superblock_parse"
                && expected == "corpus/seeds/minimized/superblock_parse/unit-a"
                && actual == "corpus/seeds/minimized/inode_locate/unit-a"
        ));
    }

    const VALID_CMIN_SUMMARY: &str = r#"{
  "schema": "erofs-rs.cmin-summary.v1",
  "engine": "cargo-fuzz",
  "engine_version": "cargo-fuzz 0.13.1",
  "toolchain": "rustc 1.86.0-nightly",
  "run_flags": [
    "-max_total_time=30",
    "-artifact_prefix=<target-artifact-dir>/",
    "-print_final_stats=1"
  ],
  "cmin_flags": [
    "-max_total_time=30"
  ],
  "regression_flags": [
    "-runs=0",
    "-artifact_prefix=<target-artifact-dir>/"
  ],
  "total_before_cmin_units": 3,
  "total_after_cmin_units": 2,
  "total_removed_units": 1,
  "total_artifact_count": 1,
  "targets": [
    {
      "target": "superblock_parse",
      "corpus_dir": "corpus/rust-fuzz/superblock_parse/corpus",
      "artifact_dir": "corpus/rust-fuzz/superblock_parse/artifacts",
      "before_cmin_units": 3,
      "after_cmin_units": 2,
      "artifact_count": 1,
      "run_log": "corpus/rust-fuzz/superblock_parse/run.log",
      "cmin_log": "corpus/rust-fuzz/superblock_parse/cmin.log",
      "regression_log": "corpus/rust-fuzz/superblock_parse/regression.log"
    }
  ]
}"#;

    #[test]
    fn cmin_summary_report_accepts_valid_report() {
        let report = parse_cmin_summary_report(VALID_CMIN_SUMMARY).unwrap();

        assert_eq!(report.schema, CMIN_SUMMARY_SCHEMA);
        assert_eq!(report.engine, "cargo-fuzz");
        assert_eq!(report.total_before_cmin_units, Some(3));
        assert_eq!(report.total_removed_units, Some(1));
        assert_eq!(report.targets[0].target, "superblock_parse");
    }

    #[test]
    fn cmin_summary_report_accepts_legacy_report_without_totals() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_CMIN_SUMMARY).unwrap();
        report
            .as_object_mut()
            .unwrap()
            .remove("total_before_cmin_units");
        report
            .as_object_mut()
            .unwrap()
            .remove("total_after_cmin_units");
        report
            .as_object_mut()
            .unwrap()
            .remove("total_removed_units");
        report
            .as_object_mut()
            .unwrap()
            .remove("total_artifact_count");
        let report = serde_json::to_string(&report).unwrap();

        let report = parse_cmin_summary_report(&report).unwrap();

        assert_eq!(report.total_before_cmin_units, None);
        assert_eq!(report.total_removed_units, None);
    }

    #[test]
    fn cmin_summary_report_rejects_unknown_schema() {
        let report = VALID_CMIN_SUMMARY.replace(CMIN_SUMMARY_SCHEMA, "erofs-rs.cmin-summary.v0");

        let error = parse_cmin_summary_report(&report).unwrap_err();

        assert!(matches!(error, CminSummaryError::UnsupportedSchema(_)));
    }

    #[test]
    fn cmin_summary_report_rejects_empty_flags() {
        let report = VALID_CMIN_SUMMARY.replace(
            r#""cmin_flags": [
    "-max_total_time=30"
  ]"#,
            r#""cmin_flags": []"#,
        );

        let error = parse_cmin_summary_report(&report).unwrap_err();

        assert!(matches!(error, CminSummaryError::EmptyList("cmin_flags")));
    }

    #[test]
    fn cmin_summary_report_rejects_target_path_component() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_CMIN_SUMMARY).unwrap();
        report["targets"][0]["target"] = serde_json::json!("../superblock_parse");
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_cmin_summary_report(&report).unwrap_err();

        assert!(matches!(
            error,
            CminSummaryError::InvalidPath {
                field: "targets.target",
                path,
            } if path == "../superblock_parse"
        ));
    }

    #[test]
    fn cmin_summary_report_rejects_corpus_dir_mismatch() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_CMIN_SUMMARY).unwrap();
        report["targets"][0]["corpus_dir"] =
            serde_json::json!("corpus/rust-fuzz/inode_locate/corpus");
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_cmin_summary_report(&report).unwrap_err();

        assert!(matches!(
            error,
            CminSummaryError::PathMismatch {
                field: "targets.corpus_dir",
                target,
                expected,
                actual,
            } if target == "superblock_parse"
                && expected == "corpus/rust-fuzz/superblock_parse/corpus"
                && actual == "corpus/rust-fuzz/inode_locate/corpus"
        ));
    }

    #[test]
    fn cmin_summary_report_rejects_regression_log_mismatch() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_CMIN_SUMMARY).unwrap();
        report["targets"][0]["regression_log"] =
            serde_json::json!("corpus/rust-fuzz/inode_locate/regression.log");
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_cmin_summary_report(&report).unwrap_err();

        assert!(matches!(
            error,
            CminSummaryError::PathMismatch {
                field: "targets.regression_log",
                target,
                expected,
                actual,
            } if target == "superblock_parse"
                && expected == "corpus/rust-fuzz/superblock_parse/regression.log"
                && actual == "corpus/rust-fuzz/inode_locate/regression.log"
        ));
    }

    #[test]
    fn cmin_summary_report_rejects_total_count_mismatch() {
        let report = VALID_CMIN_SUMMARY
            .replace(r#""total_removed_units": 1"#, r#""total_removed_units": 2"#);

        let error = parse_cmin_summary_report(&report).unwrap_err();

        assert!(matches!(
            error,
            CminSummaryError::CountMismatch {
                field: "total_removed_units",
                expected: 1,
                actual: 2,
            }
        ));
    }

    #[test]
    fn cmin_summary_report_rejects_partial_total_counts() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_CMIN_SUMMARY).unwrap();
        report
            .as_object_mut()
            .unwrap()
            .remove("total_removed_units");
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_cmin_summary_report(&report).unwrap_err();

        assert!(matches!(
            error,
            CminSummaryError::MissingCount("total_removed_units")
        ));
    }

    #[test]
    fn cmin_summary_report_rejects_unit_count_growth() {
        let report =
            VALID_CMIN_SUMMARY.replace(r#""after_cmin_units": 2"#, r#""after_cmin_units": 4"#);

        let error = parse_cmin_summary_report(&report).unwrap_err();

        assert!(matches!(
            error,
            CminSummaryError::CminIncreased {
                target,
                before: 3,
                after: 4,
            } if target == "superblock_parse"
        ));
    }

    #[test]
    fn cmin_summary_report_rejects_duplicate_target() {
        let mut report: serde_json::Value = serde_json::from_str(VALID_CMIN_SUMMARY).unwrap();
        let target = report["targets"][0].clone();
        report["targets"].as_array_mut().unwrap().push(target);
        let report = serde_json::to_string(&report).unwrap();

        let error = parse_cmin_summary_report(&report).unwrap_err();

        assert!(matches!(
            error,
            CminSummaryError::DuplicateTarget(target) if target == "superblock_parse"
        ));
    }
}
