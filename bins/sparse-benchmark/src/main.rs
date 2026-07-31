#![forbid(unsafe_code)]

mod files;
mod model;
mod remote;
mod runner;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::model::Materialization;

#[derive(Debug, Parser)]
#[command(
    name = "sparse-benchmark",
    about = "Run resumable local or service-attested sparse-solver benchmarks"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create and immediately prepare one independently resumable problem run.
    Start {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "runs")]
        runs_dir: PathBuf,
        #[arg(long, value_enum, default_value_t)]
        materialize: Materialization,
    },
    /// Advance a prepared run as far as its current artifacts permit.
    Resume { run: PathBuf },
    /// Inspect the durable stage and important paths for one run.
    Status { run: PathBuf },
    /// Generate or authenticate the portable result card for a completed run.
    Card { run: PathBuf },
    /// Authenticate a portable result card against an external benchmark pin.
    VerifyCard {
        card: PathBuf,
        #[arg(long)]
        benchmark: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Start {
            config,
            runs_dir,
            materialize,
        } => {
            runner::start(&config, &runs_dir, materialize)?;
            Ok(())
        }
        Command::Resume { run } => runner::resume(&run),
        Command::Status { run } => runner::status(&run),
        Command::Card { run } => runner::card(&run),
        Command::VerifyCard { card, benchmark } => runner::verify_card(&card, &benchmark),
    }
}
