use crate::cli::CorpusArgs;
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const KNOWN_RESULTS: &[&str] = &[
    "accepted",
    "accepted_with_errors",
    "rejected_checksum",
    "rejected_io_error",
    "rejected_corruption",
    "rejected_invalid",
    "rejected_other",
    "rejected_timeout",
];

#[derive(Clone, Debug, Default)]
struct ManifestEntry {
    file: String,
    result: String,
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

pub fn run(args: &CorpusArgs) -> Result<()> {
    if !Path::new(&args.input_dir).exists() {
        bail!("Input directory not found: {}", args.input_dir);
    }

    fs::create_dir_all(&args.output_dir)
        .map_err(|e| anyhow::anyhow!("failed to create output directory: {e}"))?;

    let categories: Vec<(String, PathBuf)> = KNOWN_RESULTS
        .iter()
        .map(|c| (c.to_string(), Path::new(&args.output_dir).join(c)))
        .collect();

    for (_, dir) in &categories {
        fs::create_dir_all(dir).map_err(|e| {
            anyhow::anyhow!("failed to create category directory {}: {e}", dir.display())
        })?;
    }

    let mut manifests = Vec::new();
    for entry in WalkDir::new(&args.input_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_name() == "manifest.txt" {
            manifests.push(entry.path().to_path_buf());
        }
    }

    println!("Found {} manifest files", manifests.len());

    let mut all_entries: Vec<(ManifestEntry, String, String)> = Vec::new();
    let mut seen_hashes = HashSet::new();
    let mut dedup_count = 0;
    let mut total_mutations = 0;

    for manifest_path in &manifests {
        let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));
        let entries = read_manifest(manifest_path);
        total_mutations += entries.len();

        for entry in entries {
            let file_path = manifest_dir.join(&entry.file);
            if !file_path.exists() {
                continue;
            }

            let h = file_hash(&file_path)?;
            if seen_hashes.contains(&h) {
                dedup_count += 1;
                continue;
            }
            seen_hashes.insert(h.clone());

            let category = classify_artifact(&entry);
            let category_dir = categories
                .iter()
                .find(|(c, _)| *c == category)
                .map(|(_, d)| d.clone())
                .unwrap_or_else(|| categories.last().unwrap().1.clone());

            let dest_path = category_dir.join(&entry.file);
            fs::copy(&file_path, &dest_path)
                .map_err(|e| anyhow::anyhow!("failed to copy {}: {e}", file_path.display()))?;

            all_entries.push((entry, category, h));
        }
    }

    let mut category_counts: HashMap<String, usize> = HashMap::new();
    for (_, cat, _) in &all_entries {
        *category_counts.entry(cat.clone()).or_insert(0) += 1;
    }

    let mut report_lines = vec![
        "# EROFS Fuzzing Corpus Report".to_string(),
        String::new(),
        format!("Total manifests processed: {}", manifests.len()),
        format!("Total mutations: {total_mutations}"),
        format!("Unique artifacts: {}", all_entries.len()),
        format!("Duplicates removed: {dedup_count}"),
        String::new(),
        "## Classification Summary".to_string(),
        String::new(),
    ];

    let mut sorted_counts: Vec<_> = category_counts.iter().collect();
    sorted_counts.sort_by(|a, b| a.0.cmp(b.0));
    for (cat, count) in &sorted_counts {
        report_lines.push(format!("- {cat}: {count}"));
    }

    report_lines.extend([
        String::new(),
        "## Notes".to_string(),
        String::new(),
        "- `rejected_checksum`: fsck/kernel rejected because the superblock checksum no longer matches.".to_string(),
        "  This is expected for any mutation that changes bytes covered by the checksum.".to_string(),
        "- `accepted`: fsck accepted with no errors printed.".to_string(),
        "- `accepted_with_errors`: fsck exited 0 but printed errors (rare).".to_string(),
        "- `rejected_io_error` / `rejected_corruption` / `rejected_invalid`: clean rejection paths.".to_string(),
        "- `rejected_timeout`: fsck exceeded the configured timeout.".to_string(),
        String::new(),
        "## All Unique Artifacts".to_string(),
        String::new(),
        format!("{:<50} {:<25} {:<64}", "file", "category", "hash"),
        "-".repeat(141),
    ]);

    for (entry, cat, h) in &all_entries {
        report_lines.push(format!("{:<50} {:<25} {h}", entry.file, cat));
    }

    fs::write(&args.report, report_lines.join("\n") + "\n")
        .map_err(|e| anyhow::anyhow!("failed to write report {}: {e}", args.report))?;

    println!("\nDone. Processed {} unique artifacts.", all_entries.len());
    println!("  Deduplicated: {dedup_count}");
    println!("  Report: {}", args.report);
    println!("\nCategories:");
    for (cat, count) in sorted_counts {
        println!("  {cat}: {count}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::file_hash;
    use std::fs;
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
}
