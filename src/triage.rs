use crate::cli::TriageArgs;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;
use thiserror::Error;

const FUZZ_BUCKET_REPORT_SCHEMA: &str = "erofs-rs.fuzz-buckets.v1";
pub const BUCKET_DATABASE_SCHEMA: &str = "erofs-rs.bucket-db.v1";

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BucketDatabase {
    pub schema: String,
    pub source_reports: Vec<BucketDatabaseSource>,
    pub buckets: Vec<BucketDatabaseEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BucketDatabaseSource {
    pub path: String,
    pub rng_seed: u64,
    pub iterations: u64,
    pub text_report_path: String,
    pub bucket_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BucketDatabaseEntry {
    pub signature: String,
    pub classification: String,
    pub outcome_kind: String,
    pub total_count: u64,
    pub campaign_count: u64,
    pub examples: Vec<BucketExample>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BucketExample {
    pub bucket_report_path: String,
    pub rng_seed: u64,
    pub first_iteration: u64,
    pub example_seed_name: String,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum BucketDatabaseError {
    #[error("failed to decode bucket database: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unsupported bucket database schema: {0}")]
    UnsupportedSchema(String),
    #[error("bucket database field {0} is empty")]
    EmptyField(&'static str),
    #[error("bucket database list {0} is empty")]
    EmptyList(&'static str),
    #[error("bucket database contains duplicate source report: {0}")]
    DuplicateSource(String),
    #[error("bucket database contains duplicate signature: {0}")]
    DuplicateSignature(String),
    #[error("bucket database signature contains duplicate example source: {0}")]
    DuplicateExampleSource(String),
    #[error("bucket database example references unknown source report: {0}")]
    UnknownExampleSource(String),
    #[error("bucket database count mismatch for {field}: expected {expected}, actual {actual}")]
    CountMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
}

pub fn parse_bucket_database(
    content: &str,
) -> std::result::Result<BucketDatabase, BucketDatabaseError> {
    let database: BucketDatabase = serde_json::from_str(content)?;
    validate_bucket_database(&database)?;
    Ok(database)
}

pub fn validate_bucket_database(
    database: &BucketDatabase,
) -> std::result::Result<(), BucketDatabaseError> {
    if database.schema != BUCKET_DATABASE_SCHEMA {
        return Err(BucketDatabaseError::UnsupportedSchema(
            database.schema.clone(),
        ));
    }
    if database.source_reports.is_empty() {
        return Err(BucketDatabaseError::EmptyList("source_reports"));
    }

    let mut source_paths = HashSet::new();
    for source in &database.source_reports {
        require_database_nonempty("source_reports.path", &source.path)?;
        require_database_nonempty("source_reports.text_report_path", &source.text_report_path)?;
        if !source_paths.insert(source.path.as_str()) {
            return Err(BucketDatabaseError::DuplicateSource(source.path.clone()));
        }
    }

    let mut signatures = HashSet::new();
    let mut source_bucket_counts: HashMap<&str, u64> = HashMap::new();
    for bucket in &database.buckets {
        validate_bucket_database_entry(bucket, &source_paths, &mut source_bucket_counts)?;
        if !signatures.insert(bucket.signature.as_str()) {
            return Err(BucketDatabaseError::DuplicateSignature(
                bucket.signature.clone(),
            ));
        }
    }

    for source in &database.source_reports {
        require_database_count(
            "source_reports.bucket_count",
            *source_bucket_counts.get(source.path.as_str()).unwrap_or(&0),
            usize_to_u64_count("source_reports.bucket_count", source.bucket_count)?,
        )?;
    }

    Ok(())
}

fn validate_bucket_database_entry<'a>(
    bucket: &'a BucketDatabaseEntry,
    source_paths: &HashSet<&'a str>,
    source_bucket_counts: &mut HashMap<&'a str, u64>,
) -> std::result::Result<(), BucketDatabaseError> {
    require_database_nonempty("buckets.signature", &bucket.signature)?;
    require_database_nonempty("buckets.classification", &bucket.classification)?;
    require_database_nonempty("buckets.outcome_kind", &bucket.outcome_kind)?;
    if bucket.total_count == 0 {
        return Err(BucketDatabaseError::CountMismatch {
            field: "buckets.total_count",
            expected: 1,
            actual: 0,
        });
    }
    if bucket.campaign_count == 0 {
        return Err(BucketDatabaseError::CountMismatch {
            field: "buckets.campaign_count",
            expected: 1,
            actual: 0,
        });
    }
    if bucket.total_count < bucket.campaign_count {
        return Err(BucketDatabaseError::CountMismatch {
            field: "buckets.total_count",
            expected: bucket.campaign_count,
            actual: bucket.total_count,
        });
    }
    if bucket.examples.is_empty() {
        return Err(BucketDatabaseError::EmptyList("buckets.examples"));
    }
    require_database_count(
        "buckets.campaign_count",
        usize_to_u64_count("buckets.examples", bucket.examples.len())?,
        bucket.campaign_count,
    )?;

    let mut example_sources = HashSet::new();
    for example in &bucket.examples {
        require_database_nonempty(
            "buckets.examples.bucket_report_path",
            &example.bucket_report_path,
        )?;
        if !source_paths.contains(example.bucket_report_path.as_str()) {
            return Err(BucketDatabaseError::UnknownExampleSource(
                example.bucket_report_path.clone(),
            ));
        }
        if !example_sources.insert(example.bucket_report_path.as_str()) {
            return Err(BucketDatabaseError::DuplicateExampleSource(
                example.bucket_report_path.clone(),
            ));
        }
        let count = source_bucket_counts
            .entry(example.bucket_report_path.as_str())
            .or_insert(0);
        *count = count
            .checked_add(1)
            .ok_or(BucketDatabaseError::CountMismatch {
                field: "source_reports.bucket_count",
                expected: u64::MAX,
                actual: *count,
            })?;
    }

    Ok(())
}

fn require_database_nonempty(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), BucketDatabaseError> {
    if value.is_empty() {
        return Err(BucketDatabaseError::EmptyField(field));
    }
    Ok(())
}

fn require_database_count(
    field: &'static str,
    expected: u64,
    actual: u64,
) -> std::result::Result<(), BucketDatabaseError> {
    if expected != actual {
        return Err(BucketDatabaseError::CountMismatch {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

fn usize_to_u64_count(
    field: &'static str,
    value: usize,
) -> std::result::Result<u64, BucketDatabaseError> {
    u64::try_from(value).map_err(|_| BucketDatabaseError::CountMismatch {
        field,
        expected: u64::MAX,
        actual: u64::MAX,
    })
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
    validate_bucket_database(database)
        .map_err(|error| anyhow::anyhow!("generated bucket database is invalid: {error}"))?;
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
        BUCKET_DATABASE_SCHEMA, BucketDatabaseError, BucketReportInput, FuzzBucket,
        FuzzBucketReport, build_bucket_database, parse_bucket_database, validate_bucket_database,
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

    #[test]
    fn bucket_database_parser_accepts_generated_database() {
        let database = build_bucket_database(vec![report(
            "campaign/fuzz-buckets.json",
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
        )])
        .unwrap();
        let content = serde_json::to_string(&database).unwrap();

        let parsed = parse_bucket_database(&content).unwrap();

        assert_eq!(parsed, database);
    }

    #[test]
    fn bucket_database_parser_rejects_unknown_schema() {
        let mut database = build_bucket_database(vec![report(
            "campaign/fuzz-buckets.json",
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
        )])
        .unwrap();
        database.schema = "erofs-rs.bucket-db.v0".to_string();

        let error = validate_bucket_database(&database).unwrap_err();

        assert!(matches!(error, BucketDatabaseError::UnsupportedSchema(_)));
    }

    #[test]
    fn bucket_database_parser_rejects_source_count_mismatch() {
        let mut database = build_bucket_database(vec![report(
            "campaign/fuzz-buckets.json",
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
        )])
        .unwrap();
        database.source_reports[0].bucket_count = 2;

        let error = validate_bucket_database(&database).unwrap_err();

        assert!(matches!(
            error,
            BucketDatabaseError::CountMismatch {
                field: "source_reports.bucket_count",
                expected: 1,
                actual: 2,
            }
        ));
    }

    #[test]
    fn bucket_database_parser_rejects_unknown_example_source() {
        let mut database = build_bucket_database(vec![report(
            "campaign/fuzz-buckets.json",
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
        )])
        .unwrap();
        database.buckets[0].examples[0].bucket_report_path =
            "missing/fuzz-buckets.json".to_string();

        let error = validate_bucket_database(&database).unwrap_err();

        assert!(matches!(
            error,
            BucketDatabaseError::UnknownExampleSource(path)
                if path == "missing/fuzz-buckets.json"
        ));
    }

    #[test]
    fn bucket_database_parser_rejects_duplicate_example_source() {
        let mut database = build_bucket_database(vec![report(
            "campaign/fuzz-buckets.json",
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
        )])
        .unwrap();
        let duplicate = database.buckets[0].examples[0].clone();
        database.buckets[0].examples.push(duplicate);
        database.buckets[0].campaign_count = 2;
        database.buckets[0].total_count = 2;

        let error = validate_bucket_database(&database).unwrap_err();

        assert!(matches!(
            error,
            BucketDatabaseError::DuplicateExampleSource(path)
                if path == "campaign/fuzz-buckets.json"
        ));
    }
}
