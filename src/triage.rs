use crate::cli::TriageArgs;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

const FUZZ_BUCKET_REPORT_SCHEMA: &str = "erofs-rs.fuzz-buckets.v1";
const BUCKET_DATABASE_SCHEMA: &str = "erofs-rs.bucket-db.v1";

#[derive(Clone, Debug, Deserialize)]
struct FuzzBucketReport {
    schema: String,
    rng_seed: u64,
    iterations: u64,
    text_report_path: String,
    buckets: Vec<FuzzBucket>,
}

#[derive(Clone, Debug, Deserialize)]
struct FuzzBucket {
    signature: String,
    classification: String,
    outcome_kind: String,
    count: u64,
    first_iteration: u64,
    example_seed_name: String,
    reason: String,
}

#[derive(Clone, Debug)]
struct BucketReportInput {
    path: String,
    report: FuzzBucketReport,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct BucketDatabase {
    schema: String,
    source_reports: Vec<BucketDatabaseSource>,
    buckets: Vec<BucketDatabaseEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct BucketDatabaseSource {
    path: String,
    rng_seed: u64,
    iterations: u64,
    text_report_path: String,
    bucket_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct BucketDatabaseEntry {
    signature: String,
    classification: String,
    outcome_kind: String,
    total_count: u64,
    campaign_count: u64,
    examples: Vec<BucketExample>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct BucketExample {
    bucket_report_path: String,
    rng_seed: u64,
    first_iteration: u64,
    example_seed_name: String,
    reason: String,
}

fn require_nonempty(path: &str, field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("empty {field} in bucket report {path}");
    }
    Ok(())
}

fn validate_report(input: &BucketReportInput) -> Result<()> {
    if input.report.schema != FUZZ_BUCKET_REPORT_SCHEMA {
        bail!(
            "unsupported fuzz bucket report schema {} in {}",
            input.report.schema,
            input.path
        );
    }

    let mut signatures = HashSet::new();
    for bucket in &input.report.buckets {
        require_nonempty(&input.path, "signature", &bucket.signature)?;
        require_nonempty(&input.path, "classification", &bucket.classification)?;
        require_nonempty(&input.path, "outcome_kind", &bucket.outcome_kind)?;
        if bucket.count == 0 {
            bail!(
                "zero count for bucket signature {} in {}",
                bucket.signature,
                input.path
            );
        }
        if !signatures.insert(bucket.signature.as_str()) {
            bail!(
                "duplicate bucket signature {} in {}",
                bucket.signature,
                input.path
            );
        }
    }

    Ok(())
}

fn read_bucket_report(path: &Path) -> Result<BucketReportInput> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read bucket report {}", path.display()))?;
    let report: FuzzBucketReport = serde_json::from_str(&content)
        .with_context(|| format!("failed to decode bucket report {}", path.display()))?;
    let input = BucketReportInput {
        path: path.display().to_string(),
        report,
    };
    validate_report(&input)?;
    Ok(input)
}

fn bucket_example(path: &str, report: &FuzzBucketReport, bucket: &FuzzBucket) -> BucketExample {
    BucketExample {
        bucket_report_path: path.to_string(),
        rng_seed: report.rng_seed,
        first_iteration: bucket.first_iteration,
        example_seed_name: bucket.example_seed_name.clone(),
        reason: bucket.reason.clone(),
    }
}

fn insert_bucket(
    entries: &mut BTreeMap<String, BucketDatabaseEntry>,
    input: &BucketReportInput,
    bucket: &FuzzBucket,
) -> Result<()> {
    let example = bucket_example(&input.path, &input.report, bucket);
    match entries.entry(bucket.signature.clone()) {
        Entry::Vacant(entry) => {
            entry.insert(BucketDatabaseEntry {
                signature: bucket.signature.clone(),
                classification: bucket.classification.clone(),
                outcome_kind: bucket.outcome_kind.clone(),
                total_count: bucket.count,
                campaign_count: 1,
                examples: vec![example],
            });
        }
        Entry::Occupied(mut entry) => {
            let merged = entry.get_mut();
            if merged.classification != bucket.classification
                || merged.outcome_kind != bucket.outcome_kind
            {
                bail!(
                    "bucket signature {} changed classification or outcome in {}",
                    bucket.signature,
                    input.path
                );
            }
            merged.total_count = merged
                .total_count
                .checked_add(bucket.count)
                .context("bucket total count overflow")?;
            merged.campaign_count = merged
                .campaign_count
                .checked_add(1)
                .context("bucket campaign count overflow")?;
            merged.examples.push(example);
        }
    }
    Ok(())
}

fn build_bucket_database(mut reports: Vec<BucketReportInput>) -> Result<BucketDatabase> {
    if reports.is_empty() {
        bail!("at least one bucket report is required");
    }
    reports.sort_by(|a, b| a.path.cmp(&b.path));

    let mut source_paths = HashSet::new();
    let mut source_reports = Vec::with_capacity(reports.len());
    let mut entries = BTreeMap::new();

    for input in &reports {
        validate_report(input)?;
        if !source_paths.insert(input.path.as_str()) {
            bail!("duplicate bucket report input {}", input.path);
        }
        source_reports.push(BucketDatabaseSource {
            path: input.path.clone(),
            rng_seed: input.report.rng_seed,
            iterations: input.report.iterations,
            text_report_path: input.report.text_report_path.clone(),
            bucket_count: input.report.buckets.len(),
        });

        for bucket in &input.report.buckets {
            insert_bucket(&mut entries, input, bucket)?;
        }
    }

    let mut buckets: Vec<_> = entries.into_values().collect();
    for bucket in &mut buckets {
        bucket.examples.sort_by(|a, b| {
            a.bucket_report_path
                .cmp(&b.bucket_report_path)
                .then_with(|| a.first_iteration.cmp(&b.first_iteration))
                .then_with(|| a.rng_seed.cmp(&b.rng_seed))
                .then_with(|| a.example_seed_name.cmp(&b.example_seed_name))
        });
    }
    buckets.sort_by(|a, b| {
        b.total_count
            .cmp(&a.total_count)
            .then_with(|| a.signature.cmp(&b.signature))
    });

    Ok(BucketDatabase {
        schema: BUCKET_DATABASE_SCHEMA.to_string(),
        source_reports,
        buckets,
    })
}

fn write_bucket_database(path: &Path, database: &BucketDatabase) -> Result<()> {
    let json =
        serde_json::to_string_pretty(database).context("failed to serialize bucket database")?;
    fs::write(path, json + "\n")
        .with_context(|| format!("failed to write bucket database {}", path.display()))
}

pub fn run(args: &TriageArgs) -> Result<()> {
    let reports = args
        .bucket_reports
        .iter()
        .map(|path| read_bucket_report(Path::new(path)))
        .collect::<Result<Vec<_>>>()?;
    let database = build_bucket_database(reports)?;
    write_bucket_database(Path::new(&args.output), &database)?;

    println!(
        "Merged {} bucket reports into {}",
        database.source_reports.len(),
        args.output
    );
    println!("  Signatures: {}", database.buckets.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BUCKET_DATABASE_SCHEMA, BucketReportInput, FuzzBucket, FuzzBucketReport,
        build_bucket_database,
    };

    fn bucket(signature: &str, classification: &str, count: u64) -> FuzzBucket {
        FuzzBucket {
            signature: signature.to_string(),
            classification: classification.to_string(),
            outcome_kind: "interesting_semantic".to_string(),
            count,
            first_iteration: 7,
            example_seed_name: "seed".to_string(),
            reason: "reason".to_string(),
        }
    }

    fn report(path: &str, rng_seed: u64, buckets: Vec<FuzzBucket>) -> BucketReportInput {
        BucketReportInput {
            path: path.to_string(),
            report: FuzzBucketReport {
                schema: "erofs-rs.fuzz-buckets.v1".to_string(),
                rng_seed,
                iterations: 10,
                text_report_path: format!("{path}.txt"),
                buckets,
            },
        }
    }

    #[test]
    fn bucket_database_merges_reports_by_signature() {
        let database = build_bucket_database(vec![
            report(
                "campaign-b/fuzz-buckets.json",
                22,
                vec![
                    bucket("accepted_with_errors: shared", "accepted_with_errors", 1),
                    bucket("tool_failed: other", "tool_failed", 4),
                ],
            ),
            report(
                "campaign-a/fuzz-buckets.json",
                11,
                vec![bucket(
                    "accepted_with_errors: shared",
                    "accepted_with_errors",
                    2,
                )],
            ),
        ])
        .unwrap();

        assert_eq!(database.schema, BUCKET_DATABASE_SCHEMA);
        assert_eq!(database.source_reports.len(), 2);
        assert_eq!(
            database.source_reports[0].path,
            "campaign-a/fuzz-buckets.json"
        );
        assert_eq!(database.buckets.len(), 2);
        assert_eq!(database.buckets[0].signature, "tool_failed: other");
        assert_eq!(database.buckets[0].total_count, 4);
        assert_eq!(database.buckets[0].campaign_count, 1);
        assert_eq!(
            database.buckets[1].signature,
            "accepted_with_errors: shared"
        );
        assert_eq!(database.buckets[1].total_count, 3);
        assert_eq!(database.buckets[1].campaign_count, 2);
        assert_eq!(database.buckets[1].examples.len(), 2);
        assert_eq!(
            database.buckets[1].examples[0].bucket_report_path,
            "campaign-a/fuzz-buckets.json"
        );
    }

    #[test]
    fn bucket_database_rejects_unknown_report_schema() {
        let mut input = report(
            "campaign/fuzz-buckets.json",
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
        );
        input.report.schema = "wrong".to_string();

        let error = build_bucket_database(vec![input]).unwrap_err();
        assert!(error.to_string().contains("unsupported fuzz bucket"));
    }

    #[test]
    fn bucket_database_rejects_duplicate_signature_in_report() {
        let error = build_bucket_database(vec![report(
            "campaign/fuzz-buckets.json",
            11,
            vec![
                bucket("accepted_with_errors: shared", "accepted_with_errors", 1),
                bucket("accepted_with_errors: shared", "accepted_with_errors", 2),
            ],
        )])
        .unwrap_err();

        assert!(error.to_string().contains("duplicate bucket signature"));
    }
}
