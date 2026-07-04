use anyhow::Result;
use clap::Parser;
use erofs_rs::cli::{Cli, Commands};
use erofs_rs::{corpus, fuzz, info, inject, mutate};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Inject(args) => inject::run(args),
        Commands::Mutate(args) => mutate::run(args),
        Commands::Corpus(args) => corpus::run(args),
        Commands::Fuzz(args) => fuzz::run(args),
        Commands::Info(args) => info::run(args),
    }
}
