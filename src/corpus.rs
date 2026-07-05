use crate::cli::{CorpusArgs, CorpusMode};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

const COVERAGE_CATEGORY: &str = "coverage-interesting";
const COVERAGE_MANIFEST_FILE: &str = "coverage-manifest.json";
const COVERAGE_MANIFEST_SCHEMA: &str = "erofs-rs.coverage-corpus.v1";
pub const CMIN_SUMMARY_SCHEMA: &str = "erofs-rs.cmin-summary.v1";
const DEFAULT_COVERAGE_TARGET: &str = "unassigned";
const MINIMIZED_IMPORT_ROOT: &str = "corpus/seeds/minimized";

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

#[derive(Clone, Debug, Serialize)]
struct CoverageManifest {
    schema: &'static str,
    mode: &'static str,
    input_dir: String,
    output_dir: String,
    total_input_units: usize,
    collected_units: usize,
    unique_hashes: usize,
    duplicates_removed: usize,
    recommended_import_root: String,
    targets: Vec<CoverageTargetSummary>,
    units: Vec<CoverageManifestUnit>,
}

#[derive(Clone, Debug, Serialize)]
struct CoverageTargetSummary {
    target: String,
    input_units: usize,
    collected_units: usize,
    unique_hashes: usize,
    duplicates_removed: usize,
    recommended_import_dir: String,
}

#[derive(Clone, Debug, Serialize)]
struct CoverageManifestUnit {
    target: String,
    source_path: String,
    copied_path: String,
    sha256: String,
    size_bytes: u64,
    lifecycle: String,
    recommended_import_path: String,
}

#[derive(Clone, Debug, Default)]
struct CoverageTargetStats {
    input_units: usize,
    collected_units: usize,
    duplicates_removed: usize,
    hashes: HashSet<String>,
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

    for target in &report.targets {
        validate_cmin_target(target)?;
    }

    Ok(())
}

fn validate_cmin_target(target: &CminTargetSummary) -> std::result::Result<(), CminSummaryError> {
    require_cmin_nonempty("targets.target", &target.target)?;
    require_cmin_nonempty("targets.corpus_dir", &target.corpus_dir)?;
    require_cmin_nonempty("targets.artifact_dir", &target.artifact_dir)?;
    require_cmin_nonempty("targets.run_log", &target.run_log)?;
    require_cmin_nonempty("targets.cmin_log", &target.cmin_log)?;
    require_cmin_nonempty("targets.regression_log", &target.regression_log)?;

    if target.after_cmin_units > target.before_cmin_units {
        return Err(CminSummaryError::CminIncreased {
            target: target.target.clone(),
            before: target.before_cmin_units,
            after: target.after_cmin_units,
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

fn read_manifest(path: &Path) -> Vec<ManifestEntry> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let result_idx = parts.iter().rposition(|p| KNOWN_RESULTS.contains(p));
        let result_idx = match result_idx {
            Some(i) if i >= 2 => i,
            _ => continue,
        };
        entries.push(ManifestEntry {
            file: parts[0].to_string(),
            result: parts[result_idx].to_string(),
        });
    }
    entries
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
        let entries = read_manifest(manifest_path);
        total_files = total_files
            .checked_add(entries.len())
            .ok_or_else(|| anyhow::anyhow!("corpus file count overflows"))?;

        for entry in entries {
            let file_path = manifest_dir.join(&entry.file);
            if !file_path.exists() {
                continue;
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
    portable_path(&Path::new(MINIMIZED_IMPORT_ROOT).join(target))
}

fn recommended_import_path(target: &str, copied_name: &str) -> String {
    portable_path(
        &Path::new(MINIMIZED_IMPORT_ROOT)
            .join(target)
            .join(copied_name),
    )
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
        schema: COVERAGE_MANIFEST_SCHEMA,
        mode: "coverage",
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
        CMIN_SUMMARY_SCHEMA, CminSummaryError, DEFAULT_COVERAGE_TARGET, file_hash,
        infer_coverage_target, lifecycle_bucket, parse_cmin_summary_report,
        should_collect_coverage_file,
    };
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
        assert_eq!(report.targets[0].target, "superblock_parse");
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
}
