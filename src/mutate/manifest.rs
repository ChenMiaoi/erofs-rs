use super::engine::{MutatedEntry, seed_name};
use crate::cli::MutateArgs;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(super) fn write_manifest<P: AsRef<Path>>(
    path: P,
    args: &MutateArgs,
    entries: &[MutatedEntry],
    input_sha256: &str,
) -> Result<()> {
    let seed = seed_name(&args.input);
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut family_counts: HashMap<String, usize> = HashMap::new();
    let mut parser_counts: HashMap<String, usize> = HashMap::new();
    let mut class_counts: HashMap<String, usize> = HashMap::new();
    let mut checksum_counts: HashMap<String, usize> = HashMap::new();
    for e in entries {
        *counts.entry(e.classification.clone()).or_insert(0) += 1;
        *family_counts.entry(e.family.clone()).or_insert(0) += 1;
        *parser_counts.entry(e.parser_outcome.clone()).or_insert(0) += 1;
        *class_counts.entry(e.mutation_class.clone()).or_insert(0) += 1;
        *checksum_counts
            .entry(e.checksum_policy.clone())
            .or_insert(0) += 1;
    }

    let mut lines = vec![
        format!("# EROFS Mutation Manifest"),
        format!("# Input: {}", args.input),
        format!("# Input SHA-256: {input_sha256}"),
        format!("# Seed: {seed}"),
        format!("# Tool version: {VERSION}"),
        format!("# Target: {}", args.target),
        format!("# Output directory: {}", args.output_dir),
        format!("# fsck: {}", args.fsck),
        format!("# fsck timeout seconds: {}", args.exec_timeout),
        format!("# fsck max output bytes: {}", args.max_output_bytes),
        format!("# fsck kill process group: {}", !args.no_kill_process_group),
        format!(
            "# fsck rss limit MiB: {}",
            args.rss_limit_mb
                .map(|limit| limit.to_string())
                .unwrap_or_else(|| "none".to_string())
        ),
        format!("# Fix checksum: {}", args.fix_checksum),
        format!("# Total mutations: {}", entries.len()),
        String::new(),
        format!(
            "{:<60} {:<15} {:<20} {:<25} {:<20} {:<20} {:<18} {:<20} {}",
            "output_file",
            "target",
            "field",
            "mutation",
            "value",
            "class",
            "checksum",
            "result",
            "classification"
        ),
        "-".repeat(175),
    ];

    for e in entries {
        lines.push(format!(
            "{:<60} {:<15} {:<20} {:<25} {:<20} {:<20} {:<18} {:<20} {}",
            e.output_name,
            e.target_desc,
            e.field_name,
            e.mutation_name,
            e.value_hex,
            e.mutation_class,
            e.checksum_policy,
            e.classification,
            e.reason
        ));
    }

    lines.push(String::new());
    let summary = sorted_counts(&counts)
        .into_iter()
        .map(|(classification, count)| format!("{classification}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!("# Summary: total={}, {summary}", entries.len()));
    lines.push(format!("# Oracle: {summary}"));
    let families = sorted_counts(&family_counts)
        .into_iter()
        .map(|(family, count)| format!("{family}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!("# Families: {families}"));
    let parser = sorted_counts(&parser_counts)
        .into_iter()
        .map(|(outcome, count)| format!("{outcome}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!("# Parser: {parser}"));
    let classes = sorted_counts(&class_counts)
        .into_iter()
        .map(|(mutation_class, count)| format!("{mutation_class}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!("# Mutation classes: {classes}"));
    let checksum_policies = sorted_counts(&checksum_counts)
        .into_iter()
        .map(|(policy, count)| format!("{policy}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!("# Checksum policies: {checksum_policies}"));

    fs::write(path.as_ref(), lines.join("\n") + "\n").map_err(|e| {
        anyhow::anyhow!("failed to write manifest {}: {e}", path.as_ref().display())
    })?;
    Ok(())
}

fn sorted_counts(counts: &HashMap<String, usize>) -> Vec<(&str, usize)> {
    let mut items = counts
        .iter()
        .map(|(name, count)| (name.as_str(), *count))
        .collect::<Vec<_>>();
    items.sort_by(|a, b| a.0.cmp(b.0));
    items
}
