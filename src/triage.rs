use crate::cli::TriageArgs;
use crate::fuzz::OutcomeKind;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;
use thiserror::Error;

pub const FUZZ_BUCKET_REPORT_SCHEMA: &str = "erofs-rs.fuzz-buckets.v1";
pub const BUCKET_DATABASE_SCHEMA: &str = "erofs-rs.bucket-db.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzBucketReport {
    pub schema: String,
    pub tool: String,
    pub tool_version: String,
    pub rng_seed: u64,
    pub duration_millis: u64,
    pub iterations: u64,
    pub unique_images: u64,
    pub seed_count: u64,
    pub actionable_findings: u64,
    pub text_report_path: String,
    pub buckets: Vec<FuzzBucket>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzBucket {
    pub signature: String,
    pub classification: String,
    pub outcome_kind: String,
    pub count: u64,
    pub first_iteration: u64,
    pub example_seed_name: String,
    pub reason: String,
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
    #[error("bucket database field {field} has invalid outcome kind: {outcome_kind}")]
    InvalidOutcomeKind {
        field: &'static str,
        outcome_kind: String,
    },
    #[error(
        "bucket database classification {classification} has outcome kind {outcome_kind}, expected {expected}"
    )]
    OutcomeKindMismatch {
        classification: String,
        outcome_kind: String,
        expected: String,
    },
    #[error("bucket database classification {classification} is not actionable")]
    NonActionableOutcome { classification: String },
    #[error("bucket database signature {signature} does not match classification {classification}")]
    SignatureMismatch {
        classification: String,
        signature: String,
    },
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

#[derive(Debug, Error)]
pub enum FuzzBucketReportError {
    #[error("failed to decode fuzz bucket report: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unsupported fuzz bucket report schema: {0}")]
    UnsupportedSchema(String),
    #[error("fuzz bucket report field {0} is empty")]
    EmptyField(&'static str),
    #[error("fuzz bucket report bucket {0} has zero count")]
    ZeroCount(String),
    #[error("fuzz bucket report contains duplicate signature: {0}")]
    DuplicateSignature(String),
    #[error("fuzz bucket report field {field} has invalid outcome kind: {outcome_kind}")]
    InvalidOutcomeKind {
        field: &'static str,
        outcome_kind: String,
    },
    #[error(
        "fuzz bucket report classification {classification} has outcome kind {outcome_kind}, expected {expected}"
    )]
    OutcomeKindMismatch {
        classification: String,
        outcome_kind: String,
        expected: String,
    },
    #[error("fuzz bucket report classification {classification} is not actionable")]
    NonActionableOutcome { classification: String },
    #[error(
        "fuzz bucket report signature {signature} does not match classification {classification}"
    )]
    SignatureMismatch {
        classification: String,
        signature: String,
    },
    #[error("fuzz bucket report count mismatch for {field}: expected {expected}, actual {actual}")]
    CountMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
}

pub fn parse_fuzz_bucket_report(
    content: &str,
) -> std::result::Result<FuzzBucketReport, FuzzBucketReportError> {
    let report: FuzzBucketReport = serde_json::from_str(content)?;
    validate_fuzz_bucket_report(&report)?;
    Ok(report)
}

pub fn validate_fuzz_bucket_report(
    report: &FuzzBucketReport,
) -> std::result::Result<(), FuzzBucketReportError> {
    if report.schema != FUZZ_BUCKET_REPORT_SCHEMA {
        return Err(FuzzBucketReportError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    require_bucket_report_nonempty("tool", &report.tool)?;
    require_bucket_report_nonempty("tool_version", &report.tool_version)?;
    require_bucket_report_nonempty("text_report_path", &report.text_report_path)?;
    if report.unique_images > report.iterations {
        return Err(FuzzBucketReportError::CountMismatch {
            field: "unique_images",
            expected: report.iterations,
            actual: report.unique_images,
        });
    }
    if report.actionable_findings > report.unique_images {
        return Err(FuzzBucketReportError::CountMismatch {
            field: "actionable_findings",
            expected: report.unique_images,
            actual: report.actionable_findings,
        });
    }

    let mut signatures = HashSet::new();
    let mut actionable_findings = 0u64;
    for bucket in &report.buckets {
        validate_fuzz_bucket(bucket)?;
        if !signatures.insert(bucket.signature.as_str()) {
            return Err(FuzzBucketReportError::DuplicateSignature(
                bucket.signature.clone(),
            ));
        }
        actionable_findings = actionable_findings.checked_add(bucket.count).ok_or(
            FuzzBucketReportError::CountMismatch {
                field: "actionable_findings",
                expected: u64::MAX,
                actual: report.actionable_findings,
            },
        )?;
    }
    require_bucket_report_count(
        "actionable_findings",
        actionable_findings,
        report.actionable_findings,
    )?;
    Ok(())
}

fn validate_fuzz_bucket(bucket: &FuzzBucket) -> std::result::Result<(), FuzzBucketReportError> {
    require_bucket_report_nonempty("buckets.signature", &bucket.signature)?;
    require_bucket_report_nonempty("buckets.classification", &bucket.classification)?;
    require_bucket_report_nonempty("buckets.outcome_kind", &bucket.outcome_kind)?;
    validate_bucket_report_signature(&bucket.classification, &bucket.signature)?;
    validate_fuzz_bucket_outcome_kind(&bucket.classification, &bucket.outcome_kind)?;
    require_bucket_report_nonempty("buckets.example_seed_name", &bucket.example_seed_name)?;
    require_bucket_report_nonempty("buckets.reason", &bucket.reason)?;
    if bucket.count == 0 {
        return Err(FuzzBucketReportError::ZeroCount(bucket.signature.clone()));
    }
    Ok(())
}

fn validate_bucket_report_signature(
    classification: &str,
    signature: &str,
) -> std::result::Result<(), FuzzBucketReportError> {
    if !signature_matches_classification(classification, signature) {
        return Err(FuzzBucketReportError::SignatureMismatch {
            classification: classification.to_string(),
            signature: signature.to_string(),
        });
    }
    Ok(())
}

fn validate_fuzz_bucket_outcome_kind(
    classification: &str,
    outcome_kind: &str,
) -> std::result::Result<(), FuzzBucketReportError> {
    if !is_known_outcome_kind(outcome_kind) {
        return Err(FuzzBucketReportError::InvalidOutcomeKind {
            field: "buckets.outcome_kind",
            outcome_kind: outcome_kind.to_string(),
        });
    }
    let expected = OutcomeKind::from_classification(classification);
    if outcome_kind != expected.label() {
        return Err(FuzzBucketReportError::OutcomeKindMismatch {
            classification: classification.to_string(),
            outcome_kind: outcome_kind.to_string(),
            expected: expected.label().to_string(),
        });
    }
    if !expected.is_finding() {
        return Err(FuzzBucketReportError::NonActionableOutcome {
            classification: classification.to_string(),
        });
    }
    Ok(())
}

fn is_known_outcome_kind(outcome_kind: &str) -> bool {
    matches!(
        outcome_kind,
        "normal_accept"
            | "expected_reject"
            | "interesting_semantic"
            | "unsafe_crash"
            | "unsafe_timeout"
            | "tooling_error"
    )
}

fn require_bucket_report_nonempty(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), FuzzBucketReportError> {
    if value.is_empty() {
        return Err(FuzzBucketReportError::EmptyField(field));
    }
    Ok(())
}

fn require_bucket_report_count(
    field: &'static str,
    expected: u64,
    actual: u64,
) -> std::result::Result<(), FuzzBucketReportError> {
    if expected != actual {
        return Err(FuzzBucketReportError::CountMismatch {
            field,
            expected,
            actual,
        });
    }
    Ok(())
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
    validate_database_signature(&bucket.classification, &bucket.signature)?;
    validate_database_outcome_kind(&bucket.classification, &bucket.outcome_kind)?;
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

fn validate_database_signature(
    classification: &str,
    signature: &str,
) -> std::result::Result<(), BucketDatabaseError> {
    if !signature_matches_classification(classification, signature) {
        return Err(BucketDatabaseError::SignatureMismatch {
            classification: classification.to_string(),
            signature: signature.to_string(),
        });
    }
    Ok(())
}

fn signature_matches_classification(classification: &str, signature: &str) -> bool {
    let signature_prefix = format!("{classification}: ");
    signature == classification || signature.starts_with(&signature_prefix)
}

fn validate_database_outcome_kind(
    classification: &str,
    outcome_kind: &str,
) -> std::result::Result<(), BucketDatabaseError> {
    if !is_known_outcome_kind(outcome_kind) {
        return Err(BucketDatabaseError::InvalidOutcomeKind {
            field: "buckets.outcome_kind",
            outcome_kind: outcome_kind.to_string(),
        });
    }
    let expected = OutcomeKind::from_classification(classification);
    if outcome_kind != expected.label() {
        return Err(BucketDatabaseError::OutcomeKindMismatch {
            classification: classification.to_string(),
            outcome_kind: outcome_kind.to_string(),
            expected: expected.label().to_string(),
        });
    }
    if !expected.is_finding() {
        return Err(BucketDatabaseError::NonActionableOutcome {
            classification: classification.to_string(),
        });
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

fn validate_report(input: &BucketReportInput) -> Result<()> {
    validate_fuzz_bucket_report(&input.report)
        .with_context(|| format!("invalid fuzz bucket report {}", input.path))
}

fn read_bucket_report(path: &Path) -> Result<BucketReportInput> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read bucket report {}", path.display()))?;
    let report = parse_fuzz_bucket_report(&content)
        .with_context(|| format!("failed to parse bucket report {}", path.display()))?;
    let input = BucketReportInput {
        path: path.display().to_string(),
        report,
    };
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
        FuzzBucketReport, FuzzBucketReportError, build_bucket_database, parse_bucket_database,
        parse_fuzz_bucket_report, validate_bucket_database, validate_fuzz_bucket_report,
    };
    use crate::fuzz::OutcomeKind;

    fn bucket(signature: &str, classification: &str, count: u64) -> FuzzBucket {
        FuzzBucket {
            signature: signature.to_string(),
            classification: classification.to_string(),
            outcome_kind: OutcomeKind::from_classification(classification)
                .label()
                .to_string(),
            count,
            first_iteration: 7,
            example_seed_name: "seed".to_string(),
            reason: "reason".to_string(),
        }
    }

    fn report(path: &str, rng_seed: u64, buckets: Vec<FuzzBucket>) -> BucketReportInput {
        BucketReportInput {
            path: path.to_string(),
            report: fuzz_report(rng_seed, buckets, format!("{path}.txt")),
        }
    }

    fn fuzz_report(
        rng_seed: u64,
        buckets: Vec<FuzzBucket>,
        text_report_path: String,
    ) -> FuzzBucketReport {
        let actionable_findings = buckets.iter().map(|bucket| bucket.count).sum();
        FuzzBucketReport {
            schema: "erofs-rs.fuzz-buckets.v1".to_string(),
            tool: "erofs-rs".to_string(),
            tool_version: "0.1.0".to_string(),
            rng_seed,
            duration_millis: 100,
            iterations: 10,
            unique_images: 10,
            seed_count: 1,
            actionable_findings,
            text_report_path,
            buckets,
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

        let error = validate_fuzz_bucket_report(&input.report).unwrap_err();
        assert!(matches!(error, FuzzBucketReportError::UnsupportedSchema(_)));
    }

    #[test]
    fn bucket_database_rejects_duplicate_signature_in_report() {
        let input = report(
            "campaign/fuzz-buckets.json",
            11,
            vec![
                bucket("accepted_with_errors: shared", "accepted_with_errors", 1),
                bucket("accepted_with_errors: shared", "accepted_with_errors", 2),
            ],
        );

        let error = validate_fuzz_bucket_report(&input.report).unwrap_err();
        assert!(matches!(
            error,
            FuzzBucketReportError::DuplicateSignature(signature)
                if signature == "accepted_with_errors: shared"
        ));
    }

    #[test]
    fn fuzz_bucket_report_parser_accepts_generated_shape() {
        let report = fuzz_report(
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
            "fuzz-report.txt".to_string(),
        );
        let content = serde_json::to_string(&report).unwrap();

        let parsed = parse_fuzz_bucket_report(&content).unwrap();

        assert_eq!(parsed, report);
    }

    #[test]
    fn fuzz_bucket_report_parser_rejects_unknown_fields() {
        let content = r#"{
  "schema": "erofs-rs.fuzz-buckets.v1",
  "tool": "erofs-rs",
  "tool_version": "0.1.0",
  "rng_seed": 11,
  "duration_millis": 100,
  "iterations": 10,
  "unique_images": 10,
  "seed_count": 1,
  "actionable_findings": 0,
  "text_report_path": "fuzz-report.txt",
  "buckets": [],
  "extra": true
}"#;

        let error = parse_fuzz_bucket_report(content).unwrap_err();

        assert!(matches!(error, FuzzBucketReportError::Decode(_)));
    }

    #[test]
    fn fuzz_bucket_report_parser_rejects_actionable_count_mismatch() {
        let mut report = fuzz_report(
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
            "fuzz-report.txt".to_string(),
        );
        report.actionable_findings = 2;

        let error = validate_fuzz_bucket_report(&report).unwrap_err();

        assert!(matches!(
            error,
            FuzzBucketReportError::CountMismatch {
                field: "actionable_findings",
                expected: 1,
                actual: 2,
            }
        ));
    }

    #[test]
    fn fuzz_bucket_report_parser_rejects_unique_images_above_iterations() {
        let mut report = fuzz_report(
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
            "fuzz-report.txt".to_string(),
        );
        report.unique_images = 11;

        let error = validate_fuzz_bucket_report(&report).unwrap_err();

        assert!(matches!(
            error,
            FuzzBucketReportError::CountMismatch {
                field: "unique_images",
                expected: 10,
                actual: 11,
            }
        ));
    }

    #[test]
    fn fuzz_bucket_report_parser_rejects_findings_above_unique_images() {
        let mut report = fuzz_report(
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
            "fuzz-report.txt".to_string(),
        );
        report.unique_images = 1;
        report.actionable_findings = 2;

        let error = validate_fuzz_bucket_report(&report).unwrap_err();

        assert!(matches!(
            error,
            FuzzBucketReportError::CountMismatch {
                field: "actionable_findings",
                expected: 1,
                actual: 2,
            }
        ));
    }

    #[test]
    fn fuzz_bucket_report_parser_rejects_unknown_outcome_kind() {
        let mut report = fuzz_report(
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
            "fuzz-report.txt".to_string(),
        );
        report.buckets[0].outcome_kind = "maybe_interesting".to_string();

        let error = validate_fuzz_bucket_report(&report).unwrap_err();

        assert!(matches!(
            error,
            FuzzBucketReportError::InvalidOutcomeKind {
                field: "buckets.outcome_kind",
                outcome_kind,
            } if outcome_kind == "maybe_interesting"
        ));
    }

    #[test]
    fn fuzz_bucket_report_parser_rejects_outcome_kind_mismatch() {
        let mut report = fuzz_report(
            11,
            vec![bucket("rejected_crash: SIGSEGV", "rejected_crash", 1)],
            "fuzz-report.txt".to_string(),
        );
        report.buckets[0].outcome_kind = "interesting_semantic".to_string();

        let error = validate_fuzz_bucket_report(&report).unwrap_err();

        assert!(matches!(
            error,
            FuzzBucketReportError::OutcomeKindMismatch {
                classification,
                outcome_kind,
                expected,
            } if classification == "rejected_crash"
                && outcome_kind == "interesting_semantic"
                && expected == "unsafe_crash"
        ));
    }

    #[test]
    fn fuzz_bucket_report_parser_rejects_signature_mismatch() {
        let mut report = fuzz_report(
            11,
            vec![bucket(
                "accepted_with_errors: shared",
                "accepted_with_errors",
                1,
            )],
            "fuzz-report.txt".to_string(),
        );
        report.buckets[0].signature = "rejected_crash: SIGSEGV".to_string();

        let error = validate_fuzz_bucket_report(&report).unwrap_err();

        assert!(matches!(
            error,
            FuzzBucketReportError::SignatureMismatch {
                classification,
                signature,
            } if classification == "accepted_with_errors"
                && signature == "rejected_crash: SIGSEGV"
        ));
    }

    #[test]
    fn fuzz_bucket_report_parser_rejects_non_actionable_bucket() {
        let report = fuzz_report(
            11,
            vec![bucket("rejected_invalid: bad inode", "rejected_invalid", 1)],
            "fuzz-report.txt".to_string(),
        );

        let error = validate_fuzz_bucket_report(&report).unwrap_err();

        assert!(matches!(
            error,
            FuzzBucketReportError::NonActionableOutcome { classification }
                if classification == "rejected_invalid"
        ));
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
    fn bucket_database_parser_rejects_outcome_kind_mismatch() {
        let mut database = build_bucket_database(vec![report(
            "campaign/fuzz-buckets.json",
            11,
            vec![bucket("rejected_crash: SIGSEGV", "rejected_crash", 1)],
        )])
        .unwrap();
        database.buckets[0].outcome_kind = "interesting_semantic".to_string();

        let error = validate_bucket_database(&database).unwrap_err();

        assert!(matches!(
            error,
            BucketDatabaseError::OutcomeKindMismatch {
                classification,
                outcome_kind,
                expected,
            } if classification == "rejected_crash"
                && outcome_kind == "interesting_semantic"
                && expected == "unsafe_crash"
        ));
    }

    #[test]
    fn bucket_database_parser_rejects_signature_mismatch() {
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
        database.buckets[0].signature = "rejected_crash: SIGSEGV".to_string();

        let error = validate_bucket_database(&database).unwrap_err();

        assert!(matches!(
            error,
            BucketDatabaseError::SignatureMismatch {
                classification,
                signature,
            } if classification == "accepted_with_errors"
                && signature == "rejected_crash: SIGSEGV"
        ));
    }

    #[test]
    fn bucket_database_parser_rejects_unknown_outcome_kind() {
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
        database.buckets[0].outcome_kind = "maybe_interesting".to_string();

        let error = validate_bucket_database(&database).unwrap_err();

        assert!(matches!(
            error,
            BucketDatabaseError::InvalidOutcomeKind {
                field: "buckets.outcome_kind",
                outcome_kind,
            } if outcome_kind == "maybe_interesting"
        ));
    }

    #[test]
    fn bucket_database_parser_rejects_non_actionable_bucket() {
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
        database.buckets[0].signature = "rejected_invalid: bad inode".to_string();
        database.buckets[0].classification = "rejected_invalid".to_string();
        database.buckets[0].outcome_kind = "expected_reject".to_string();

        let error = validate_bucket_database(&database).unwrap_err();

        assert!(matches!(
            error,
            BucketDatabaseError::NonActionableOutcome { classification }
                if classification == "rejected_invalid"
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
