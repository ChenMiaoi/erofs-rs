use anyhow::Result;
use clap::Parser;
use erofs_rs::cli::{Cli, Commands};
use erofs_rs::{bundle, corpus, fuzz, info, inject, kernel_replay, mutate, oracle, replay, triage};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Inject(args) => inject::run(args),
        Commands::Mutate(args) => mutate::run(args),
        Commands::Corpus(args) => corpus::run(args),
        Commands::Fuzz(args) => fuzz::run(args),
        Commands::Replay(args) => replay::run(args),
        Commands::Bundle(args) => bundle::run(args),
        Commands::Triage(args) => triage::run(args),
        Commands::Oracle(args) => oracle::run(args),
        Commands::KernelReport(args) => kernel_replay::run(args),
        Commands::Info(args) => info::run(args),
    }
}
