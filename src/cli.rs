use clap::{Parser, Subcommand};

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
        help = "Mutation target: superblock, inode, dirent, all"
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
    #[arg(long, default_value = "mutation", help = "Fuzzing strategy: mutation")]
    pub strategy: String,
}

#[derive(Parser, Debug)]
pub struct InfoArgs {
    #[arg(long, help = "Input EROFS image")]
    pub input: String,
    #[arg(long, help = "Recalculate and display checksum")]
    pub fix_checksum: bool,
}
