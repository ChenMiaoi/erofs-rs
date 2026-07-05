use crate::checksum::fix_checksum;
use crate::cli::{FuzzArgs, FuzzStrategy};
use crate::fsck::{ExecLimits, run_fsck_with_limits};
use crate::image::{EROFS_SUPER_OFFSET, FieldWidth, Image, read_image, write_image};
use anyhow::{Result, bail};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const FUZZ_ARTIFACT_SCHEMA: &str = "erofs-rs.fuzz-artifact.v1";
const TOOL_NAME: &str = "erofs-rs";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_DUMP_PATH: &str = "./build/erofs-utils/dump/dump.erofs";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct MutationRecord {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    width: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bit: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    old: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FuzzArtifactCommands {
    fsck: Vec<String>,
    dump: Vec<String>,
    kernel_replay: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FuzzArtifactVersions {
    tool_git: Option<String>,
    erofs_utils_git: Option<String>,
    linux_git: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FuzzArtifactSidecar {
    schema: String,
    tool: String,
    tool_version: String,
    rng_seed: u64,
    iteration: u64,
    strategy: String,
    seed_name: String,
    seed_sha256: String,
    artifact_sha256: String,
    artifact_path: String,
    mutations: Vec<MutationRecord>,
    commands: FuzzArtifactCommands,
    versions: FuzzArtifactVersions,
    fsck_exit_code: i32,
    fsck_timed_out: bool,
    fsck_kill_process_group: bool,
    fsck_killed_process_group: bool,
    fsck_rss_limit_mb: Option<u64>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    classification: String,
    reason: String,
    stdout_path: String,
    stderr_path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutcomeKind {
    NormalAccept,
    ExpectedReject,
    InterestingSemantic,
    UnsafeCrash,
    UnsafeTimeout,
    ToolingError,
}

impl OutcomeKind {
    fn from_classification(classification: &str) -> Self {
        match classification {
            "accepted" => Self::NormalAccept,
            "rejected_checksum"
            | "rejected_corruption"
            | "rejected_invalid"
            | "rejected_io_error" => Self::ExpectedReject,
            "accepted_with_errors" | "rejected_other" => Self::InterestingSemantic,
            "rejected_timeout" => Self::UnsafeTimeout,
            classification
                if classification.contains("crash")
                    || classification.contains("signal")
                    || classification.contains("sanitizer") =>
            {
                Self::UnsafeCrash
            }
            _ => Self::ToolingError,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::NormalAccept => "normal_accept",
            Self::ExpectedReject => "expected_reject",
            Self::InterestingSemantic => "interesting_semantic",
            Self::UnsafeCrash => "unsafe_crash",
            Self::UnsafeTimeout => "unsafe_timeout",
            Self::ToolingError => "tooling_error",
        }
    }

    fn is_finding(self) -> bool {
        matches!(
            self,
            Self::InterestingSemantic
                | Self::UnsafeCrash
                | Self::UnsafeTimeout
                | Self::ToolingError
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FuzzRun {
    pub(crate) iteration: u64,
    pub(crate) seed_name: String,
    pub(crate) classification: String,
    pub(crate) reason: String,
}

impl FuzzRun {
    fn outcome_kind(&self) -> OutcomeKind {
        OutcomeKind::from_classification(&self.classification)
    }

    fn is_clean_accept(&self) -> bool {
        self.outcome_kind() == OutcomeKind::NormalAccept
    }

    fn is_finding(&self) -> bool {
        self.outcome_kind().is_finding()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FuzzSummary {
    pub(crate) runs: Vec<FuzzRun>,
    pub(crate) duration: Duration,
    pub(crate) iterations: u64,
    pub(crate) rng_seed: u64,
    pub(crate) seed_count: usize,
    pub(crate) report_path: String,
}

impl FuzzSummary {
    pub(crate) fn finding_count(&self) -> usize {
        self.runs.iter().filter(|run| run.is_finding()).count()
    }

    fn clean_accept_count(&self) -> usize {
        self.runs.iter().filter(|run| run.is_clean_accept()).count()
    }

    fn expected_reject_count(&self) -> usize {
        self.outcome_count(OutcomeKind::ExpectedReject)
    }

    fn interesting_finding_count(&self) -> usize {
        self.outcome_count(OutcomeKind::InterestingSemantic)
    }

    fn unsafe_finding_count(&self) -> usize {
        self.runs
            .iter()
            .filter(|run| {
                matches!(
                    run.outcome_kind(),
                    OutcomeKind::UnsafeCrash | OutcomeKind::UnsafeTimeout
                )
            })
            .count()
    }

    fn tooling_error_count(&self) -> usize {
        self.outcome_count(OutcomeKind::ToolingError)
    }

    fn outcome_count(&self, outcome: OutcomeKind) -> usize {
        self.runs
            .iter()
            .filter(|run| run.outcome_kind() == outcome)
            .count()
    }
}

fn sha256_hex(image: &Image) -> String {
    let mut hasher = Sha256::new();
    hasher.update(image.as_bytes());
    hex::encode(hasher.finalize())
}

fn field_width_name(width: FieldWidth) -> &'static str {
    match width {
        FieldWidth::U8 => "u8",
        FieldWidth::U16 => "u16",
        FieldWidth::U32 => "u32",
        FieldWidth::U64 => "u64",
    }
}

fn format_field_value(value: u64, width: FieldWidth) -> String {
    format!("0x{:0digits$X}", value, digits = width.bytes() * 2)
}

fn mutation_record(
    kind: &str,
    field: Option<&str>,
    offset: Option<usize>,
    width: Option<FieldWidth>,
    bit: Option<u8>,
    old: Option<String>,
    new: Option<String>,
) -> MutationRecord {
    MutationRecord {
        kind: kind.to_string(),
        field: field.map(ToOwned::to_owned),
        offset,
        width: width.map(field_width_name).map(ToOwned::to_owned),
        bit,
        old,
        new,
    }
}

fn load_seeds(input_dir: &str) -> Result<Vec<(String, Image)>> {
    let mut seeds = Vec::new();
    let mut paths = Vec::new();
    for entry in fs::read_dir(input_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("erofs") {
            paths.push(path);
        }
    }
    paths.sort();

    for path in paths {
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let image = read_image(&path)?;
        seeds.push((name, image));
    }
    if seeds.is_empty() {
        bail!("No .erofs seed images found in {input_dir}");
    }
    Ok(seeds)
}

fn random_bit_flip(image: &mut Image, rng: &mut StdRng) -> Option<MutationRecord> {
    if image.is_empty() {
        return None;
    }
    let idx = rng.gen_range(0..image.len());
    let bit = rng.gen_range(0..8);
    let old = image.as_bytes()[idx];
    let new = old ^ (1 << bit);
    image.as_bytes_mut()[idx] = new;
    Some(mutation_record(
        "bit_flip",
        None,
        Some(idx),
        Some(FieldWidth::U8),
        Some(bit),
        Some(format_field_value(old as u64, FieldWidth::U8)),
        Some(format_field_value(new as u64, FieldWidth::U8)),
    ))
}

fn random_byte_mutation(image: &mut Image, rng: &mut StdRng) -> Option<MutationRecord> {
    if image.is_empty() {
        return None;
    }
    let idx = rng.gen_range(0..image.len());
    let old = image.as_bytes()[idx];
    let new = rng.r#gen();
    image.as_bytes_mut()[idx] = new;
    Some(mutation_record(
        "byte",
        None,
        Some(idx),
        Some(FieldWidth::U8),
        None,
        Some(format_field_value(old as u64, FieldWidth::U8)),
        Some(format_field_value(new as u64, FieldWidth::U8)),
    ))
}

fn random_word_mutation(image: &mut Image, rng: &mut StdRng) -> Option<MutationRecord> {
    if image.len() < 8 {
        return None;
    }
    let idx = rng.gen_range(0..image.len() - 7);
    let old = image.read_field(idx, FieldWidth::U64).ok()?;
    let value: u64 = rng.r#gen();
    let bytes = value.to_le_bytes();
    image.as_bytes_mut()[idx..idx + 8].copy_from_slice(&bytes);
    Some(mutation_record(
        "word",
        None,
        Some(idx),
        Some(FieldWidth::U64),
        None,
        Some(format_field_value(old, FieldWidth::U64)),
        Some(format_field_value(value, FieldWidth::U64)),
    ))
}

fn random_arithmetic(image: &mut Image, rng: &mut StdRng) -> Option<MutationRecord> {
    if image.len() < 4 {
        return None;
    }
    let idx = rng.gen_range(0..image.len() - 3);
    let delta: i32 = rng.gen_range(-256..256);
    let current = u32::from_le_bytes([
        image.as_bytes()[idx],
        image.as_bytes()[idx + 1],
        image.as_bytes()[idx + 2],
        image.as_bytes()[idx + 3],
    ]);
    let new_value = (current as i64 + delta as i64) as u32;
    image.as_bytes_mut()[idx..idx + 4].copy_from_slice(&new_value.to_le_bytes());
    Some(mutation_record(
        "arithmetic",
        None,
        Some(idx),
        Some(FieldWidth::U32),
        None,
        Some(format_field_value(current as u64, FieldWidth::U32)),
        Some(format_field_value(new_value as u64, FieldWidth::U32)),
    ))
}

fn random_superblock_field(image: &mut Image, rng: &mut StdRng) -> Option<MutationRecord> {
    // Mutate one of a few key superblock fields deterministically.
    let fields: &[(&str, usize, FieldWidth)] = &[
        (
            "superblock.root_nid",
            EROFS_SUPER_OFFSET + 0x0E,
            FieldWidth::U16,
        ),
        (
            "superblock.blkszbits",
            EROFS_SUPER_OFFSET + 0x0C,
            FieldWidth::U8,
        ),
        (
            "superblock.blocks_lo",
            EROFS_SUPER_OFFSET + 0x24,
            FieldWidth::U32,
        ),
        (
            "superblock.meta_blkaddr",
            EROFS_SUPER_OFFSET + 0x28,
            FieldWidth::U32,
        ),
    ];
    let (field, offset, width) = fields[rng.gen_range(0..fields.len())];
    let old = image.read_field(offset, width).ok()?;
    let value: u64 = match width {
        FieldWidth::U8 => rng.r#gen::<u8>() as u64,
        FieldWidth::U16 => rng.r#gen::<u16>() as u64,
        FieldWidth::U32 => rng.r#gen::<u32>() as u64,
        FieldWidth::U64 => rng.r#gen::<u64>(),
    };
    image.write_field(offset, width, value).ok()?;
    Some(mutation_record(
        "field",
        Some(field),
        Some(offset),
        Some(width),
        None,
        Some(format_field_value(old, width)),
        Some(format_field_value(value, width)),
    ))
}

fn checksum_fix_mutation(image: &mut Image) -> Option<MutationRecord> {
    let (old, new) = fix_checksum(image).ok()?;
    Some(mutation_record(
        "fix_checksum",
        Some("superblock.checksum"),
        Some(EROFS_SUPER_OFFSET + 0x04),
        Some(FieldWidth::U32),
        None,
        Some(format_field_value(old as u64, FieldWidth::U32)),
        Some(format_field_value(new as u64, FieldWidth::U32)),
    ))
}

fn apply_random_mutation(image: &mut Image, rng: &mut StdRng) -> Option<MutationRecord> {
    let choice = rng.gen_range(0..10);
    match choice {
        0..=2 => random_bit_flip(image, rng),
        3..=5 => random_byte_mutation(image, rng),
        6 => random_word_mutation(image, rng),
        7 => random_arithmetic(image, rng),
        8 => random_superblock_field(image, rng),
        _ => {
            // With some probability, fix checksum to reach deep parsing.
            checksum_fix_mutation(image)
        }
    }
}

fn choose_seed<'a>(seeds: &'a [(String, Image)], rng: &mut StdRng) -> &'a (String, Image) {
    &seeds[rng.gen_range(0..seeds.len())]
}

fn save_artifact(
    image: &Image,
    output_dir: &Path,
    iteration: u64,
    seed_name: &str,
) -> Result<PathBuf> {
    let name = format!("fuzz_{seed_name}_iter{iteration}.erofs");
    let path = output_dir.join(&name);
    write_image(&path, image)?;
    Ok(path)
}

fn strategy_name(strategy: FuzzStrategy) -> &'static str {
    match strategy {
        FuzzStrategy::Mutation => "mutation",
        FuzzStrategy::Structured => "structured",
        FuzzStrategy::Libfuzzer => "libfuzzer",
        FuzzStrategy::Replay => "replay",
    }
}

fn artifact_text_path(artifact_path: &Path, stream: &str) -> PathBuf {
    artifact_path.with_extension(format!("{stream}.txt"))
}

fn artifact_sidecar_path(artifact_path: &Path) -> PathBuf {
    artifact_path.with_extension("json")
}

fn fsck_command(fsck_path: &str, artifact_path: &Path) -> Vec<String> {
    vec![fsck_path.to_string(), artifact_path.display().to_string()]
}

fn dump_command(artifact_path: &Path) -> Vec<String> {
    vec![
        DEFAULT_DUMP_PATH.to_string(),
        "-s".to_string(),
        artifact_path.display().to_string(),
    ]
}

fn kernel_replay_command(artifact_path: &Path) -> Vec<String> {
    vec![
        "make".to_string(),
        "smoke-malformed".to_string(),
        format!("MALFORMED_IMG={}", artifact_path.display()),
    ]
}

fn git_revision(path: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let revision = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!revision.is_empty()).then_some(revision)
}

fn collect_versions() -> FuzzArtifactVersions {
    FuzzArtifactVersions {
        tool_git: git_revision(Path::new(".")),
        erofs_utils_git: git_revision(Path::new("vendor/erofs-utils")),
        linux_git: git_revision(Path::new("vendor/linux")),
    }
}

struct FuzzSidecarInput<'a> {
    args: &'a FuzzArgs,
    rng_seed: u64,
    iteration: u64,
    seed_name: &'a str,
    seed_sha256: &'a str,
    artifact_sha256: &'a str,
    artifact_path: &'a Path,
    mutations: Vec<MutationRecord>,
    fsck_exit_code: i32,
    fsck_timed_out: bool,
    fsck_kill_process_group: bool,
    fsck_killed_process_group: bool,
    fsck_rss_limit_mb: Option<u64>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    classification: &'a str,
    reason: &'a str,
    stdout_path: &'a Path,
    stderr_path: &'a Path,
}

fn build_fuzz_sidecar(input: FuzzSidecarInput<'_>) -> FuzzArtifactSidecar {
    FuzzArtifactSidecar {
        schema: FUZZ_ARTIFACT_SCHEMA.to_string(),
        tool: TOOL_NAME.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        rng_seed: input.rng_seed,
        iteration: input.iteration,
        strategy: strategy_name(input.args.strategy).to_string(),
        seed_name: input.seed_name.to_string(),
        seed_sha256: input.seed_sha256.to_string(),
        artifact_sha256: input.artifact_sha256.to_string(),
        artifact_path: input.artifact_path.display().to_string(),
        mutations: input.mutations,
        commands: FuzzArtifactCommands {
            fsck: fsck_command(&input.args.fsck, input.artifact_path),
            dump: dump_command(input.artifact_path),
            kernel_replay: kernel_replay_command(input.artifact_path),
        },
        versions: collect_versions(),
        fsck_exit_code: input.fsck_exit_code,
        fsck_timed_out: input.fsck_timed_out,
        fsck_kill_process_group: input.fsck_kill_process_group,
        fsck_killed_process_group: input.fsck_killed_process_group,
        fsck_rss_limit_mb: input.fsck_rss_limit_mb,
        stdout_truncated: input.stdout_truncated,
        stderr_truncated: input.stderr_truncated,
        classification: input.classification.to_string(),
        reason: input.reason.to_string(),
        stdout_path: input.stdout_path.display().to_string(),
        stderr_path: input.stderr_path.display().to_string(),
    }
}

fn write_artifact_text(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents)
        .map_err(|e| anyhow::anyhow!("failed to write artifact text {}: {e}", path.display()))
}

fn write_fuzz_sidecar(path: &Path, sidecar: &FuzzArtifactSidecar) -> Result<()> {
    let json = serde_json::to_string_pretty(sidecar)
        .map_err(|e| anyhow::anyhow!("failed to serialize fuzz sidecar: {e}"))?;
    fs::write(path, json + "\n")
        .map_err(|e| anyhow::anyhow!("failed to write fuzz sidecar {}: {e}", path.display()))
}

fn write_fuzz_report(summary: &FuzzSummary) -> Result<()> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for run in &summary.runs {
        *counts.entry(run.classification.clone()).or_insert(0) += 1;
    }

    let mut lines = vec![
        "# EROFS Fuzzing Campaign Report".to_string(),
        String::new(),
        format!("RNG seed: {}", summary.rng_seed),
        format!("Duration: {:.2}s", summary.duration.as_secs_f64()),
        format!("Total iterations: {}", summary.iterations),
        format!("Unique images observed: {}", summary.runs.len()),
        format!("Actionable findings: {}", summary.finding_count()),
        format!(
            "Interesting findings: {}",
            summary.interesting_finding_count()
        ),
        format!("Unsafe findings: {}", summary.unsafe_finding_count()),
        format!("Expected rejects: {}", summary.expected_reject_count()),
        format!("Tooling errors: {}", summary.tooling_error_count()),
        format!("Clean accepts: {}", summary.clean_accept_count()),
        String::new(),
        "## Outcome Summary".to_string(),
        String::new(),
    ];

    for outcome in [
        OutcomeKind::NormalAccept,
        OutcomeKind::ExpectedReject,
        OutcomeKind::InterestingSemantic,
        OutcomeKind::UnsafeCrash,
        OutcomeKind::UnsafeTimeout,
        OutcomeKind::ToolingError,
    ] {
        lines.push(format!(
            "- {}: {}",
            outcome.label(),
            summary.outcome_count(outcome)
        ));
    }

    lines.extend([
        String::new(),
        "## Classification Summary".to_string(),
        String::new(),
    ]);

    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (cat, count) in sorted {
        lines.push(format!("- {cat}: {count}"));
    }

    lines.extend([
        String::new(),
        "## Representative Runs".to_string(),
        String::new(),
    ]);

    for run in summary.runs.iter().take(100) {
        lines.push(format!(
            "iter={:<8} seed={:<20} result={:<20} reason={}",
            run.iteration, run.seed_name, run.classification, run.reason
        ));
    }

    fs::write(&summary.report_path, lines.join("\n") + "\n")
        .map_err(|e| anyhow::anyhow!("failed to write fuzz report: {e}"))?;
    Ok(())
}

fn should_show_tui(args: &FuzzArgs) -> bool {
    !args.no_tui && std::io::stdout().is_terminal()
}

pub fn run(args: &FuzzArgs) -> Result<()> {
    match args.strategy {
        FuzzStrategy::Mutation => run_mutation_fuzz(args),
        strategy => bail!(
            "fuzz strategy '{}' is not implemented yet; use '--strategy mutation'",
            strategy_name(strategy)
        ),
    }
}

fn run_mutation_fuzz(args: &FuzzArgs) -> Result<()> {
    if !Path::new(&args.input_dir).exists() {
        bail!("Input directory not found: {}", args.input_dir);
    }

    fs::create_dir_all(&args.output_dir)
        .map_err(|e| anyhow::anyhow!("failed to create output directory: {e}"))?;

    let seeds = load_seeds(&args.input_dir)?;
    println!("Loaded {} seed image(s)", seeds.len());

    let rng_seed = args.seed.unwrap_or_else(|| rand::thread_rng().r#gen());
    let mut rng = StdRng::seed_from_u64(rng_seed);
    println!("RNG seed: {rng_seed}");
    let start = Instant::now();
    let max_duration = Duration::from_secs(args.max_time);
    let fsck_limits = ExecLimits {
        timeout: Duration::from_secs(args.exec_timeout),
        max_output_bytes: args.max_output_bytes,
        kill_process_group: !args.no_kill_process_group,
        rss_limit_mb: args.rss_limit_mb,
    };

    let mut seen_hashes = HashSet::new();
    let mut runs: Vec<FuzzRun> = Vec::new();
    let mut iteration: u64 = 0;

    while start.elapsed() < max_duration {
        iteration += 1;
        let (seed_name, seed_image) = choose_seed(&seeds, &mut rng);
        let seed_sha256 = sha256_hex(seed_image);
        let mut mutated = seed_image.clone();

        // Apply 1-5 random mutations.
        let mutation_count = rng.gen_range(1..=5);
        let mut mutations = Vec::with_capacity(mutation_count);
        for _ in 0..mutation_count {
            if let Some(mutation) = apply_random_mutation(&mut mutated, &mut rng) {
                mutations.push(mutation);
            }
        }

        let hash = sha256_hex(&mutated);
        if !seen_hashes.insert(hash.clone()) {
            continue;
        }

        let artifact_path =
            save_artifact(&mutated, Path::new(&args.output_dir), iteration, seed_name)?;
        let result = run_fsck_with_limits(&args.fsck, &artifact_path, &[], fsck_limits)?;
        let classification = result.classification.clone();
        let reason = result.reason.clone();

        let stdout_path = artifact_text_path(&artifact_path, "stdout");
        let stderr_path = artifact_text_path(&artifact_path, "stderr");
        write_artifact_text(&stdout_path, &result.stdout)?;
        write_artifact_text(&stderr_path, &result.stderr)?;
        let sidecar_path = artifact_sidecar_path(&artifact_path);
        let sidecar = build_fuzz_sidecar(FuzzSidecarInput {
            args,
            rng_seed,
            iteration,
            seed_name,
            seed_sha256: &seed_sha256,
            artifact_sha256: &hash,
            artifact_path: &artifact_path,
            mutations,
            fsck_exit_code: result.exit_code,
            fsck_timed_out: result.timed_out,
            fsck_kill_process_group: fsck_limits.kill_process_group,
            fsck_killed_process_group: result.killed_process_group,
            fsck_rss_limit_mb: result.rss_limit_mb,
            stdout_truncated: result.stdout_truncated,
            stderr_truncated: result.stderr_truncated,
            classification: &classification,
            reason: &reason,
            stdout_path: &stdout_path,
            stderr_path: &stderr_path,
        });
        write_fuzz_sidecar(&sidecar_path, &sidecar)?;

        runs.push(FuzzRun {
            iteration,
            seed_name: seed_name.clone(),
            classification: classification.clone(),
            reason: reason.clone(),
        });

        if iteration % 10 == 0 {
            println!(
                "[iter {iteration:>6}] {classification:>20} ({reason}) [{:.1}s elapsed]",
                start.elapsed().as_secs_f64()
            );
        }
    }

    let summary = FuzzSummary {
        runs,
        duration: start.elapsed(),
        iterations: iteration,
        rng_seed,
        seed_count: seeds.len(),
        report_path: Path::new(&args.output_dir)
            .join("fuzz-report.txt")
            .display()
            .to_string(),
    };

    write_fuzz_report(&summary)?;

    println!("\nFuzzing complete.");
    println!("  Iterations: {}", summary.iterations);
    println!("  Unique images: {}", summary.runs.len());
    println!("  Actionable findings: {}", summary.finding_count());
    println!("  Expected rejects: {}", summary.expected_reject_count());
    println!("  Unsafe findings: {}", summary.unsafe_finding_count());
    println!("  Report: {}", summary.report_path);

    if should_show_tui(args) {
        if let Err(error) = crate::tui::show_fuzz_summary(&summary) {
            eprintln!("warning: failed to show fuzz dashboard: {error:#}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run as run_fuzz;
    use super::{
        DEFAULT_DUMP_PATH, FUZZ_ARTIFACT_SCHEMA, FuzzArtifactSidecar, FuzzRun, FuzzSidecarInput,
        FuzzSummary, OutcomeKind, build_fuzz_sidecar, git_revision, mutation_record, sha256_hex,
        strategy_name,
    };
    use crate::cli::{FuzzArgs, FuzzStrategy};
    use crate::image::{FieldWidth, Image};
    use std::path::Path;
    use std::time::Duration;

    fn run(classification: &str) -> FuzzRun {
        FuzzRun {
            iteration: 1,
            seed_name: "seed".to_string(),
            classification: classification.to_string(),
            reason: "reason".to_string(),
        }
    }

    fn summary(runs: Vec<FuzzRun>) -> FuzzSummary {
        FuzzSummary {
            runs,
            duration: Duration::from_secs(1),
            iterations: 3,
            rng_seed: 123,
            seed_count: 1,
            report_path: "/tmp/out/fuzz-report.txt".to_string(),
        }
    }

    #[test]
    fn sha256_hex_returns_full_digest() {
        let image = Image::new(b"abc".to_vec());

        assert_eq!(
            sha256_hex(&image),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fuzz_sidecar_round_trips_json() {
        let args = FuzzArgs {
            input_dir: "seeds".to_string(),
            output_dir: "out".to_string(),
            max_time: 1,
            fsck: "fsck.erofs".to_string(),
            seed: Some(123),
            no_tui: true,
            strategy: FuzzStrategy::Mutation,
            exec_timeout: 30,
            max_output_bytes: 1024,
            no_kill_process_group: false,
            rss_limit_mb: Some(64),
        };
        let artifact_path = Path::new("out/fuzz_seed_iter1.erofs");
        let stdout_path = Path::new("out/fuzz_seed_iter1.stdout.txt");
        let stderr_path = Path::new("out/fuzz_seed_iter1.stderr.txt");
        let mutations = vec![mutation_record(
            "byte",
            None,
            Some(7),
            Some(FieldWidth::U8),
            None,
            Some("0x00".to_string()),
            Some("0xFF".to_string()),
        )];

        let sidecar = build_fuzz_sidecar(FuzzSidecarInput {
            args: &args,
            rng_seed: 123,
            iteration: 1,
            seed_name: "seed",
            seed_sha256: "seedhash",
            artifact_sha256: "artifacthash",
            artifact_path,
            mutations,
            fsck_exit_code: 1,
            fsck_timed_out: false,
            fsck_kill_process_group: true,
            fsck_killed_process_group: false,
            fsck_rss_limit_mb: Some(64),
            stdout_truncated: false,
            stderr_truncated: true,
            classification: "rejected_invalid",
            reason: "fsck rejected as invalid",
            stdout_path,
            stderr_path,
        });
        let json = serde_json::to_string(&sidecar).unwrap();
        let decoded: FuzzArtifactSidecar = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, sidecar);
        assert_eq!(decoded.schema, FUZZ_ARTIFACT_SCHEMA);
        assert_eq!(decoded.strategy, "mutation");
        assert_eq!(decoded.commands.dump[0], DEFAULT_DUMP_PATH);
        assert_eq!(decoded.commands.kernel_replay[0], "make");
        assert_eq!(decoded.fsck_exit_code, 1);
        assert!(decoded.fsck_kill_process_group);
        assert!(!decoded.fsck_killed_process_group);
        assert_eq!(decoded.fsck_rss_limit_mb, Some(64));
        assert!(decoded.stderr_truncated);
        assert_eq!(decoded.mutations[0].old.as_deref(), Some("0x00"));
    }

    #[test]
    fn unsupported_strategy_reports_explicit_error() {
        let args = FuzzArgs {
            input_dir: "seeds".to_string(),
            output_dir: "out".to_string(),
            max_time: 1,
            fsck: "fsck.erofs".to_string(),
            seed: Some(123),
            no_tui: true,
            strategy: FuzzStrategy::Libfuzzer,
            exec_timeout: 30,
            max_output_bytes: 1024,
            no_kill_process_group: false,
            rss_limit_mb: None,
        };

        let err = run_fuzz(&args).unwrap_err().to_string();

        assert!(err.contains("fuzz strategy 'libfuzzer' is not implemented yet"));
        assert!(err.contains("--strategy mutation"));
    }

    #[test]
    fn strategy_names_are_stable() {
        assert_eq!(strategy_name(FuzzStrategy::Mutation), "mutation");
        assert_eq!(strategy_name(FuzzStrategy::Structured), "structured");
        assert_eq!(strategy_name(FuzzStrategy::Libfuzzer), "libfuzzer");
        assert_eq!(strategy_name(FuzzStrategy::Replay), "replay");
    }

    #[test]
    fn git_revision_returns_none_for_missing_path() {
        assert_eq!(git_revision(Path::new("does-not-exist")), None);
    }

    #[test]
    fn outcome_kind_maps_current_fsck_classifications() {
        assert_eq!(
            OutcomeKind::from_classification("accepted"),
            OutcomeKind::NormalAccept
        );
        assert_eq!(
            OutcomeKind::from_classification("rejected_checksum"),
            OutcomeKind::ExpectedReject
        );
        assert_eq!(
            OutcomeKind::from_classification("rejected_invalid"),
            OutcomeKind::ExpectedReject
        );
        assert_eq!(
            OutcomeKind::from_classification("rejected_corruption"),
            OutcomeKind::ExpectedReject
        );
        assert_eq!(
            OutcomeKind::from_classification("rejected_io_error"),
            OutcomeKind::ExpectedReject
        );
        assert_eq!(
            OutcomeKind::from_classification("accepted_with_errors"),
            OutcomeKind::InterestingSemantic
        );
        assert_eq!(
            OutcomeKind::from_classification("rejected_other"),
            OutcomeKind::InterestingSemantic
        );
        assert_eq!(
            OutcomeKind::from_classification("rejected_timeout"),
            OutcomeKind::UnsafeTimeout
        );
        assert_eq!(
            OutcomeKind::from_classification("sanitizer_crash"),
            OutcomeKind::UnsafeCrash
        );
        assert_eq!(
            OutcomeKind::from_classification("tool_failed"),
            OutcomeKind::ToolingError
        );
    }

    #[test]
    fn finding_count_excludes_expected_rejects() {
        let summary = summary(vec![
            run("accepted"),
            run("accepted_with_errors"),
            run("rejected_checksum"),
            run("rejected_invalid"),
            run("rejected_timeout"),
        ]);

        assert_eq!(summary.finding_count(), 2);
        assert_eq!(summary.clean_accept_count(), 1);
        assert_eq!(summary.expected_reject_count(), 2);
        assert_eq!(summary.interesting_finding_count(), 1);
        assert_eq!(summary.unsafe_finding_count(), 1);
    }
}
