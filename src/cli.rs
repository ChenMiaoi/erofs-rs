use clap::{Parser, Subcommand, ValueEnum};

/// erofs-rs: Advanced EROFS fuzzing and image injection tool.
#[derive(Parser, Debug)]
#[command(name = "erofs-rs", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Inject a specific field or raw offset mutation into an EROFS image.
    Inject(InjectArgs),
    /// Generate structured one-field-at-a-time mutations.
    Mutate(MutateArgs),
    /// Manage and classify a fuzzing corpus.
    Corpus(CorpusArgs),
    /// Validate a cargo-fuzz cmin summary report.
    CminSummary(CminSummaryArgs),
    /// Run a mutation-based fuzzing campaign.
    Fuzz(FuzzArgs),
    /// Replay a fuzz artifact from its JSON sidecar.
    Replay(ReplayArgs),
    /// Create a portable fuzz finding bundle manifest.
    Bundle(BundleArgs),
    /// Validate a portable fuzz finding bundle manifest and attachments.
    BundleCheck(BundleCheckArgs),
    /// Merge fuzz campaign triage reports.
    Triage(TriageArgs),
    /// Run userspace oracle checks over one image.
    Oracle(OracleArgs),
    /// Convert a captured QEMU dmesg log into a kernel replay report.
    KernelReport(KernelReportArgs),
    /// Validate a scheduled kernel replay summary.
    KernelSummary(KernelSummaryArgs),
    /// Merge kernel replay summaries into a signature bucket database.
    KernelBuckets(KernelBucketsArgs),
    /// Import a reviewed artifact into a curated kernel replay queue.
    KernelQueueImport(KernelQueueImportArgs),
    /// Validate a generated seed matrix manifest.
    SeedManifest(SeedManifestArgs),
    /// Import reviewed coverage-minimized units into the long-lived seed corpus.
    MinimizedImport(MinimizedImportArgs),
    /// Validate the long-lived minimized seed corpus manifest and files.
    MinimizedCheck(MinimizedCheckArgs),
    /// Print superblock, inode, and dirent information.
    Info(InfoArgs),
}

#[derive(Parser, Debug)]
pub struct InjectArgs {
    #[arg(long, help = "Input EROFS image")]
    pub input: String,
    #[arg(long, help = "Output mutated image")]
    pub output: String,
    #[arg(long, help = "Named field to mutate")]
    pub field: Option<String>,
    #[arg(long, help = "Target inode/dirent descriptor (field mode only)")]
    pub target: Option<String>,
    #[arg(long, help = "Absolute byte offset")]
    pub offset: Option<String>,
    #[arg(long, help = "Field width (u8/u16/u32/u64)")]
    pub width: Option<String>,
    #[arg(long, help = "New value (hex or decimal)")]
    pub value: String,
    #[arg(long, help = "Recalculate superblock checksum after mutation")]
    pub fix_checksum: bool,
    #[arg(long, help = "Path to per-image manifest")]
    pub manifest: Option<String>,
}

#[derive(Parser, Debug)]
pub struct MutateArgs {
    #[arg(long, help = "Input seed image")]
    pub input: String,
    #[arg(long, help = "Output directory for mutated images")]
    pub output_dir: String,
    #[arg(long, help = "Manifest output file")]
    pub manifest: String,
    #[arg(
        long,
        default_value = "./build/erofs-utils/fsck/fsck.erofs",
        help = "Path to fsck.erofs"
    )]
    pub fsck: String,
    #[arg(
        long,
        default_value = "all",
        help = "Mutation target: superblock, inode, dirent, xattr, chunk, compression, fragment, device, cross, all"
    )]
    pub target: String,
    #[arg(long, help = "Recalculate superblock checksum after each mutation")]
    pub fix_checksum: bool,
    #[arg(
        long,
        default_value = "30",
        help = "Per-mutant fsck timeout in seconds"
    )]
    pub exec_timeout: u64,
    #[arg(
        long,
        default_value = "1048576",
        help = "Maximum bytes retained from each fsck output stream"
    )]
    pub max_output_bytes: usize,
    #[arg(
        long,
        help = "Do not kill the fsck process group when an execution times out"
    )]
    pub no_kill_process_group: bool,
    #[arg(
        long,
        help = "Address-space limit in MiB for each fsck execution on Unix"
    )]
    pub rss_limit_mb: Option<u64>,
}

#[derive(Parser, Debug)]
pub struct CorpusArgs {
    #[arg(long, help = "Directory with mutated images")]
    pub input_dir: String,
    #[arg(long, help = "Output directory for artifacts")]
    pub output_dir: String,
    #[arg(long, help = "Summary report file")]
    pub report: String,
    #[arg(
        long,
        value_enum,
        default_value = "hash",
        help = "Corpus collection mode: hash, coverage, classification"
    )]
    pub mode: CorpusMode,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum CorpusMode {
    /// Deduplicate manifest artifacts by full SHA-256 before classification.
    #[default]
    Hash,
    /// Collect already coverage-minimized engine corpus units by full SHA-256.
    Coverage,
    /// Preserve every manifest artifact while grouping by classification.
    Classification,
}

#[derive(Parser, Debug)]
pub struct CminSummaryArgs {
    #[arg(long, help = "Path to a generated cmin-summary JSON report")]
    pub report: String,
}

#[derive(Parser, Debug)]
pub struct SeedManifestArgs {
    #[arg(long, help = "Path to a generated seed matrix manifest JSON file")]
    pub manifest: String,
}

#[derive(Parser, Debug)]
pub struct MinimizedImportArgs {
    #[arg(
        long,
        help = "Reviewed coverage-manifest.json produced by corpus --mode coverage"
    )]
    pub coverage_manifest: String,
    #[arg(
        long,
        help = "Override the coverage artifact root that contains coverage-interesting/"
    )]
    pub source_root: Option<String>,
    #[arg(
        long,
        default_value = "corpus/seeds/minimized",
        help = "Long-lived minimized corpus import root"
    )]
    pub import_root: String,
    #[arg(
        long,
        help = "Output minimized corpus manifest; defaults to <import-root>/manifest.json"
    )]
    pub manifest: Option<String>,
}

#[derive(Parser, Debug)]
pub struct MinimizedCheckArgs {
    #[arg(
        long,
        default_value = "corpus/seeds/minimized/manifest.json",
        help = "Long-lived minimized corpus manifest to validate"
    )]
    pub manifest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum FuzzStrategy {
    /// Random mutation of seed EROFS images.
    Mutation,
    /// Reserved for future structure-preserving image mutation.
    Structured,
    /// Reserved for cargo-fuzz/libFuzzer orchestration.
    Libfuzzer,
    /// Reserved for replaying existing fuzzing artifacts.
    Replay,
}

#[derive(Parser, Debug)]
pub struct FuzzArgs {
    #[arg(long, help = "Directory with seed images")]
    pub input_dir: String,
    #[arg(long, help = "Output directory for artifacts")]
    pub output_dir: String,
    #[arg(long, default_value = "60", help = "Maximum fuzzing time in seconds")]
    pub max_time: u64,
    #[arg(
        long,
        default_value = "./build/erofs-utils/fsck/fsck.erofs",
        help = "Path to fsck.erofs"
    )]
    pub fsck: String,
    #[arg(long, help = "RNG seed for reproducible mutation fuzzing")]
    pub seed: Option<u64>,
    #[arg(long, help = "Do not show the post-run terminal dashboard")]
    pub no_tui: bool,
    #[arg(
        long,
        value_enum,
        default_value = "mutation",
        help = "Fuzzing strategy"
    )]
    pub strategy: FuzzStrategy,
    #[arg(
        long,
        default_value = "30",
        help = "Per-artifact fsck timeout in seconds"
    )]
    pub exec_timeout: u64,
    #[arg(
        long,
        default_value = "1048576",
        help = "Maximum bytes retained from each fsck output stream"
    )]
    pub max_output_bytes: usize,
    #[arg(
        long,
        help = "Do not kill the fsck process group when an execution times out"
    )]
    pub no_kill_process_group: bool,
    #[arg(
        long,
        help = "Address-space limit in MiB for each fsck execution on Unix"
    )]
    pub rss_limit_mb: Option<u64>,
}

#[derive(Parser, Debug)]
pub struct ReplayArgs {
    #[arg(long, help = "Fuzz artifact JSON sidecar")]
    pub sidecar: String,
    #[arg(long, help = "Override artifact image path from the sidecar")]
    pub artifact: Option<String>,
    #[arg(long, help = "Override fsck.erofs path from the sidecar command")]
    pub fsck: Option<String>,
    #[arg(long, help = "Optional replay report output file")]
    pub report: Option<String>,
    #[arg(
        long,
        help = "Optional machine-readable replay JSON report output file"
    )]
    pub json_report: Option<String>,
    #[arg(long, default_value = "30", help = "Per-tool timeout in seconds")]
    pub exec_timeout: u64,
    #[arg(
        long,
        default_value = "1048576",
        help = "Maximum bytes retained from each tool output stream"
    )]
    pub max_output_bytes: usize,
    #[arg(
        long,
        help = "Do not kill the tool process group when an execution times out"
    )]
    pub no_kill_process_group: bool,
    #[arg(
        long,
        help = "Address-space limit in MiB for each tool execution on Unix"
    )]
    pub rss_limit_mb: Option<u64>,
}

#[derive(Parser, Debug)]
pub struct BundleArgs {
    #[arg(long, help = "Fuzz artifact JSON sidecar")]
    pub sidecar: String,
    #[arg(long, help = "Override artifact image path from the sidecar")]
    pub artifact: Option<String>,
    #[arg(long, help = "Override captured stdout path from the sidecar")]
    pub stdout: Option<String>,
    #[arg(long, help = "Override captured stderr path from the sidecar")]
    pub stderr: Option<String>,
    #[arg(long, help = "Optional replay report to include")]
    pub replay_report: Option<String>,
    #[arg(long, help = "Optional oracle report to include")]
    pub oracle_report: Option<String>,
    #[arg(long, help = "Optional kernel replay report to include")]
    pub kernel_report: Option<String>,
    #[arg(long, help = "Output bundle.json manifest path")]
    pub output: String,
}

#[derive(Parser, Debug)]
pub struct BundleCheckArgs {
    #[arg(long, help = "Finding bundle JSON manifest path")]
    pub manifest: String,
}

#[derive(Parser, Debug)]
pub struct TriageArgs {
    #[arg(
        long = "bucket-report",
        required = true,
        help = "Input fuzz-buckets JSON report; repeat to merge campaigns"
    )]
    pub bucket_reports: Vec<String>,
    #[arg(long, help = "Output cross-campaign bucket database JSON")]
    pub output: String,
}

#[derive(Parser, Debug)]
pub struct OracleArgs {
    #[arg(long, help = "Input EROFS image")]
    pub input: String,
    #[arg(
        long,
        default_value = "./build/erofs-utils/fsck/fsck.erofs",
        help = "Path to fsck.erofs"
    )]
    pub fsck: String,
    #[arg(long, help = "Optional sanitized fsck.erofs path")]
    pub sanitized_fsck: Option<String>,
    #[arg(long, help = "Optional path to dump.erofs")]
    pub dump: Option<String>,
    #[arg(long, help = "Optional kernel replay JSON report path")]
    pub kernel_report: Option<String>,
    #[arg(long, help = "Optional report output file")]
    pub report: Option<String>,
    #[arg(long, help = "Optional machine-readable JSON report output file")]
    pub json_report: Option<String>,
    #[arg(long, help = "Optional triage bucket report for oracle disagreements")]
    pub bucket_report: Option<String>,
    #[arg(long, default_value = "30", help = "Per-tool timeout in seconds")]
    pub exec_timeout: u64,
    #[arg(
        long,
        default_value = "1048576",
        help = "Maximum bytes retained from each tool output stream"
    )]
    pub max_output_bytes: usize,
    #[arg(
        long,
        help = "Do not kill the tool process group when an execution times out"
    )]
    pub no_kill_process_group: bool,
    #[arg(
        long,
        help = "Address-space limit in MiB for each tool execution on Unix"
    )]
    pub rss_limit_mb: Option<u64>,
}

#[derive(Parser, Debug)]
pub struct KernelReportArgs {
    #[arg(long, help = "Captured QEMU dmesg or console log")]
    pub dmesg: String,
    #[arg(long, help = "Optional replayed artifact image path")]
    pub artifact: Option<String>,
    #[arg(long, help = "Optional expected artifact SHA-256 digest")]
    pub artifact_sha256: Option<String>,
    #[arg(long, help = "Optional Linux kernel git revision")]
    pub kernel_git: Option<String>,
    #[arg(long, default_value = "0", help = "Observed QEMU exit code")]
    pub qemu_exit_code: i32,
    #[arg(long, help = "Output kernel replay JSON report path")]
    pub output: String,
}

#[derive(Parser, Debug)]
pub struct KernelSummaryArgs {
    #[arg(long, help = "Path to a generated kernel replay summary JSON file")]
    pub summary: String,
}

#[derive(Parser, Debug)]
pub struct KernelBucketsArgs {
    #[arg(
        long = "summary",
        required = true,
        help = "Input kernel replay summary JSON; repeat to merge runs"
    )]
    pub summaries: Vec<String>,
    #[arg(long, help = "Output kernel signature bucket database JSON")]
    pub output: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum KernelReplayQueue {
    /// General curated kernel replay queue.
    General,
    /// KASAN-oriented replay queue.
    Kasan,
    /// KCOV-oriented replay queue.
    Kcov,
    /// Fixed kernel crash artifacts replayed as regressions.
    Regression,
}

#[derive(Parser, Debug)]
pub struct KernelQueueImportArgs {
    #[arg(long, help = "Reviewed .erofs artifact to import")]
    pub input: String,
    #[arg(long, value_enum, help = "Destination kernel replay queue")]
    pub queue: KernelReplayQueue,
    #[arg(
        long,
        default_value = ".",
        help = "Repository root containing corpus/ queue directories"
    )]
    pub queue_root: String,
    #[arg(long, help = "Optional stable name stem for the queued artifact")]
    pub name: Option<String>,
    #[arg(long, help = "Expected SHA-256 digest for the artifact")]
    pub artifact_sha256: Option<String>,
    #[arg(long, help = "Optional kernel replay report to validate provenance")]
    pub kernel_report: Option<String>,
}

#[derive(Parser, Debug)]
pub struct InfoArgs {
    #[arg(long, help = "Input EROFS image")]
    pub input: String,
    #[arg(long, help = "Recalculate and display checksum")]
    pub fix_checksum: bool,
}
