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
    /// Run a mutation-based fuzzing campaign.
    Fuzz(FuzzArgs),
    /// Run userspace oracle checks over one image.
    Oracle(OracleArgs),
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
        help = "Mutation target: superblock, inode, dirent, xattr, chunk, compression, device, cross, all"
    )]
    pub target: String,
    #[arg(long, help = "Recalculate superblock checksum after each mutation")]
    pub fix_checksum: bool,
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
pub struct OracleArgs {
    #[arg(long, help = "Input EROFS image")]
    pub input: String,
    #[arg(
        long,
        default_value = "./build/erofs-utils/fsck/fsck.erofs",
        help = "Path to fsck.erofs"
    )]
    pub fsck: String,
    #[arg(long, help = "Optional path to dump.erofs")]
    pub dump: Option<String>,
    #[arg(long, help = "Optional report output file")]
    pub report: Option<String>,
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
pub struct InfoArgs {
    #[arg(long, help = "Input EROFS image")]
    pub input: String,
    #[arg(long, help = "Recalculate and display checksum")]
    pub fix_checksum: bool,
}
