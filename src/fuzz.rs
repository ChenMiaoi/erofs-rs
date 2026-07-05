use crate::checksum::fix_checksum;
use crate::cli::{FuzzArgs, FuzzStrategy};
use crate::fsck::{classify_fsck_result, run_fsck};
use crate::image::{EROFS_SUPER_OFFSET, FieldWidth, Image, read_image, write_image};
use anyhow::{Result, bail};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

fn random_bit_flip(image: &mut Image, rng: &mut StdRng) {
    if image.is_empty() {
        return;
    }
    let idx = rng.gen_range(0..image.len());
    let bit = rng.gen_range(0..8);
    image.as_bytes_mut()[idx] ^= 1 << bit;
}

fn random_byte_mutation(image: &mut Image, rng: &mut StdRng) {
    if image.is_empty() {
        return;
    }
    let idx = rng.gen_range(0..image.len());
    image.as_bytes_mut()[idx] = rng.r#gen();
}

fn random_word_mutation(image: &mut Image, rng: &mut StdRng) {
    if image.len() < 8 {
        return;
    }
    let idx = rng.gen_range(0..image.len() - 7);
    let value: u64 = rng.r#gen();
    let bytes = value.to_le_bytes();
    image.as_bytes_mut()[idx..idx + 8].copy_from_slice(&bytes);
}

fn random_arithmetic(image: &mut Image, rng: &mut StdRng) {
    if image.len() < 4 {
        return;
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
}

fn random_superblock_field(image: &mut Image, rng: &mut StdRng) {
    // Mutate one of a few key superblock fields deterministically.
    let fields: &[(usize, FieldWidth)] = &[
        (EROFS_SUPER_OFFSET + 0x0E, FieldWidth::U16), // root_nid
        (EROFS_SUPER_OFFSET + 0x0C, FieldWidth::U8),  // blkszbits
        (EROFS_SUPER_OFFSET + 0x24, FieldWidth::U32), // blocks_lo
        (EROFS_SUPER_OFFSET + 0x28, FieldWidth::U32), // meta_blkaddr
    ];
    let (offset, width) = fields[rng.gen_range(0..fields.len())];
    let value: u64 = match width {
        FieldWidth::U8 => rng.r#gen::<u8>() as u64,
        FieldWidth::U16 => rng.r#gen::<u16>() as u64,
        FieldWidth::U32 => rng.r#gen::<u32>() as u64,
        FieldWidth::U64 => rng.r#gen::<u64>(),
    };
    let _ = image.write_field(offset, width, value);
}

fn apply_random_mutation(image: &mut Image, rng: &mut StdRng) {
    let choice = rng.gen_range(0..10);
    match choice {
        0..=2 => random_bit_flip(image, rng),
        3..=5 => random_byte_mutation(image, rng),
        6 => random_word_mutation(image, rng),
        7 => random_arithmetic(image, rng),
        8 => random_superblock_field(image, rng),
        _ => {
            // With some probability, fix checksum to reach deep parsing.
            let _ = fix_checksum(image);
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

    let mut seen_hashes = HashSet::new();
    let mut runs: Vec<FuzzRun> = Vec::new();
    let mut iteration: u64 = 0;

    while start.elapsed() < max_duration {
        iteration += 1;
        let (seed_name, seed_image) = choose_seed(&seeds, &mut rng);
        let mut mutated = seed_image.clone();

        // Apply 1-5 random mutations.
        let mutation_count = rng.gen_range(1..=5);
        for _ in 0..mutation_count {
            apply_random_mutation(&mut mutated, &mut rng);
        }

        let hash = sha256_hex(&mutated);
        if !seen_hashes.insert(hash.clone()) {
            continue;
        }

        let artifact_path =
            save_artifact(&mutated, Path::new(&args.output_dir), iteration, seed_name)?;
        let result = run_fsck(&args.fsck, &artifact_path, &[])?;
        let (classification, reason) =
            classify_fsck_result(result.exit_code, &result.stderr, &result.stdout);

        runs.push(FuzzRun {
            iteration,
            seed_name: seed_name.clone(),
            classification: classification.to_string(),
            reason: reason.to_string(),
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
    use super::{FuzzRun, FuzzSummary, OutcomeKind, sha256_hex};
    use crate::image::Image;
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
