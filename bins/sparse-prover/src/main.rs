use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ssv_direct::{DirectArtifact, MAX_PROOF_BYTES, maximum_artifact_bytes};
use ssv_problem::FinalizedProblem;
use ssv_service_protocol::{SignedChallenge, ValidationManifest};
use ssv_solution::Solution;

const MAX_CONTEXT_JSON_BYTES: usize = 1024 * 1024;
const MAX_SOLUTION_JSON_BYTES: usize = MAX_PROOF_BYTES;

#[derive(Debug, Parser)]
#[command(
    name = "sparse-prover",
    about = "Build a versioned validation artifact from a solution-vector file"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build the direct-reference-v1 baseline artifact (contains the complete x).
    Prove {
        #[arg(long)]
        problem: PathBuf,
        #[arg(long)]
        validation: PathBuf,
        #[arg(long)]
        solution: PathBuf,
        /// Signed challenge JSON for a hosted problem. Omit only for an
        /// explicitly literal local problem.
        #[arg(long)]
        challenge: Option<PathBuf>,
        #[arg(long)]
        proof: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Prove {
            problem,
            validation,
            solution,
            challenge,
            proof,
        } => prove(
            &problem,
            &validation,
            &solution,
            challenge.as_deref(),
            &proof,
        ),
    }
}

fn prove(
    problem_path: &Path,
    validation_path: &Path,
    solution_path: &Path,
    challenge_path: Option<&Path>,
    proof_path: &Path,
) -> Result<()> {
    let problem_bytes = read_bounded(problem_path, MAX_CONTEXT_JSON_BYTES)?;
    let problem: FinalizedProblem = serde_json::from_slice(&problem_bytes)
        .with_context(|| format!("invalid finalized problem {}", problem_path.display()))?;
    let generated = problem.compile().context("public problem is invalid")?;

    let manifest_bytes = read_bounded(validation_path, MAX_CONTEXT_JSON_BYTES)?;
    let manifest: ValidationManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("invalid validation manifest {}", validation_path.display()))?;
    manifest
        .validate()
        .context("validation manifest is invalid")?;
    if problem.dimension() > manifest.max_solution_elements {
        bail!("problem dimension exceeds the validation manifest's solution limit");
    }
    maximum_artifact_bytes(problem.dimension())
        .context("problem dimension cannot fit in a direct-reference artifact")?;

    let solution_json_limit =
        Solution::maximum_json_bytes(generated.dimension()).min(MAX_SOLUTION_JSON_BYTES);
    let solution_file = open_bounded(solution_path, solution_json_limit)?;
    let solution = Solution::from_json_reader(BufReader::new(solution_file), generated.dimension())
        .with_context(|| format!("invalid solution {}", solution_path.display()))?;

    let challenge = challenge_path
        .map(|path| {
            let bytes = read_bounded(path, MAX_CONTEXT_JSON_BYTES)?;
            serde_json::from_slice::<SignedChallenge>(&bytes)
                .with_context(|| format!("invalid signed challenge {}", path.display()))
        })
        .transpose()?;

    let encoded = DirectArtifact::create(&problem, &manifest, challenge.as_ref(), &solution)
        .context("could not construct direct-reference artifact")?;
    let prelude = DirectArtifact::preparse(&encoded)
        .context("internal error: newly created artifact did not decode")?;
    let summary = prelude.summary()?;
    std::fs::write(proof_path, &encoded)
        .with_context(|| format!("could not write {}", proof_path.display()))?;
    println!("proof_kind=direct-reference-v1");
    println!("warning=artifact_contains_complete_solution_and_is_not_succinct");
    println!("proof_digest={}", summary.proof_digest);
    println!("problem_digest={}", summary.problem_digest);
    println!(
        "validation_manifest_digest={}",
        summary.validation_manifest_digest
    );
    println!("solution_elements={}", summary.solution_elements);
    println!("artifact_bytes={}", summary.encoded_len);
    println!("proof_file={}", proof_path.display());
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read {}", path.display()))?;
    if bytes.len() > maximum {
        bail!(
            "{} exceeds the {}-byte input limit",
            path.display(),
            maximum
        );
    }
    Ok(bytes)
}

fn open_bounded(path: &Path, maximum: usize) -> Result<BoundedReader<File>> {
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let length = file
        .metadata()
        .with_context(|| format!("could not inspect {}", path.display()))?
        .len();
    if length > maximum as u64 {
        bail!(
            "{} contains {length} bytes, exceeding the {maximum}-byte input limit",
            path.display()
        );
    }
    Ok(BoundedReader {
        inner: file,
        remaining: maximum,
    })
}

struct BoundedReader<R> {
    inner: R,
    remaining: usize,
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.remaining != 0 {
            let maximum = output.len().min(self.remaining);
            let read = self.inner.read(&mut output[..maximum])?;
            self.remaining -= read;
            return Ok(read);
        }
        let mut extra = [0_u8; 1];
        match self.inner.read(&mut extra)? {
            0 => Ok(0),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "solution input exceeded its byte limit while reading",
            )),
        }
    }
}
