use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ssv_backends::{BackendProverReport, prove_single_stage};
use ssv_fast::{FastBackend, FastPrecommitment, FastProverContext, FastProverReport};
use ssv_problem::FinalizedProblem;
use ssv_service_protocol::{ProofProtocol, SignedChallenge, ValidationManifest};
use ssv_solution::Solution;
use ssv_validation::{
    ArtifactPrelude, MAX_ARTIFACT_BYTES, PublicStatement, ValidationBackend, encode_artifact,
};

const MAX_CONTEXT_JSON_BYTES: usize = 1024 * 1024;
const MAX_PRECOMMITMENT_BYTES: usize = 64 * 1024;
const MAX_SOLUTION_JSON_BYTES: usize = MAX_ARTIFACT_BYTES;

#[derive(Debug, Parser)]
#[command(
    name = "sparse-prover",
    about = "Build versioned sparse-solution validation artifacts from an x file"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build a complete proof with the manifest-selected backend.
    Prove(CommonProofArgs),
    /// Materialize the fast precommitment as a local diagnostic stage.
    FastCommit {
        #[command(flatten)]
        inputs: CommonInputArgs,
        #[arg(long)]
        precommitment: PathBuf,
    },
    /// Complete a fast proof from a local noninteractive precommitment.
    FastProve {
        #[command(flatten)]
        inputs: CommonInputArgs,
        #[arg(long)]
        precommitment: PathBuf,
        #[arg(long)]
        proof: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
struct CommonInputArgs {
    #[arg(long)]
    problem: PathBuf,
    #[arg(long)]
    validation: PathBuf,
    #[arg(long)]
    solution: PathBuf,
    /// Signed problem challenge for hosted mode. Omit for a literal local problem.
    #[arg(long)]
    challenge: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct CommonProofArgs {
    #[command(flatten)]
    inputs: CommonInputArgs,
    #[arg(long)]
    proof: PathBuf,
}

struct LoadedInputs {
    statement: PublicStatement,
    solution: Solution,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Prove(args) => prove(&args),
        Command::FastCommit {
            inputs,
            precommitment,
        } => fast_commit(&inputs, &precommitment),
        Command::FastProve {
            inputs,
            precommitment,
            proof,
        } => fast_prove(&inputs, &precommitment, &proof),
    }
}

fn prove(args: &CommonProofArgs) -> Result<()> {
    let inputs = load_inputs(&args.inputs)?;
    let (payload, report) = prove_single_stage(&inputs.statement, &inputs.solution)
        .context("the selected backend could not construct a proof")?;
    let encoded = encode_artifact(&inputs.statement, &payload)?;
    let summary = ArtifactPrelude::parse(&encoded)?.summary();
    write_bytes(&args.proof, &encoded)?;

    match report {
        BackendProverReport::Direct(report) => {
            println!("proof_kind=direct-reference-v1");
            println!("warning=artifact_contains_complete_solution_and_is_not_succinct");
            println!("solution_elements={}", report.solution_elements);
        }
        BackendProverReport::Exact(report) => {
            println!("proof_kind=whir-field192-l2-v4");
            println!(
                "residual_squared_l2_numerator={}",
                report.residual.numerator
            );
            println!(
                "residual_squared_l2_denominator_power={}",
                report.residual.denominator_power
            );
            println!("sumcheck_rounds={}", report.algebra.sumcheck_rounds);
            println!(
                "whir_opening_points={}",
                report.algebra.endpoint_digit_evaluations
            );
            println!(
                "accounted_high_watermark_bytes={}",
                report.accounted_high_watermark_bytes
            );
        }
        BackendProverReport::Fast(report) => {
            print_fast_prover_report(&report);
        }
    }
    print_artifact_summary(summary, &args.proof);
    Ok(())
}

fn fast_commit(args: &CommonInputArgs, precommitment_path: &Path) -> Result<()> {
    let inputs = load_inputs(args)?;
    require_fast(&inputs.statement)?;
    let (commitment, report) = FastBackend::commit(&inputs.statement, &inputs.solution)
        .context("could not construct noninteractive fast precommitment")?;
    write_bytes(precommitment_path, &commitment.to_bytes())?;

    println!("proof_kind=fast-binary64-unit-circle-v3");
    println!("challenge_mode=noninteractive-fiat-shamir");
    println!("precommitment_digest={}", report.precommitment_digest);
    println!(
        "packed_codeword_root={}",
        hex::encode(report.packed_codeword_root)
    );
    println!("solution_elements={}", report.logical_len);
    println!("codeword_elements={}", report.codeword_len);
    println!("precommitment_file={}", precommitment_path.display());
    Ok(())
}

fn fast_prove(args: &CommonInputArgs, precommitment_path: &Path, proof_path: &Path) -> Result<()> {
    let inputs = load_inputs(args)?;
    require_fast(&inputs.statement)?;
    let commitment =
        FastPrecommitment::from_bytes(&read_bounded(precommitment_path, MAX_PRECOMMITMENT_BYTES)?)
            .context("invalid fast precommitment")?;
    let context = FastProverContext::new(commitment);
    let (payload, report) =
        <FastBackend as ValidationBackend>::prove(&inputs.statement, &inputs.solution, &context)
            .context("could not construct fast proof")?;
    let encoded = encode_artifact(&inputs.statement, &payload)?;
    let summary = ArtifactPrelude::parse(&encoded)?.summary();
    write_bytes(proof_path, &encoded)?;

    print_fast_prover_report(&report);
    print_artifact_summary(summary, proof_path);
    Ok(())
}

fn print_fast_prover_report(report: &FastProverReport) {
    println!("proof_kind=fast-binary64-unit-circle-v3");
    println!("challenge_mode=noninteractive-fiat-shamir");
    println!("precommitment_digest={}", report.precommitment_digest);
    println!("residual_squared_l2={:.17e}", report.residual_squared_l2);
    println!(
        "recursive_query_trajectories={}",
        report.proximity_queries_per_round
    );
    println!("prover_rows_scanned={}", report.rows_scanned);
    println!("prover_nonzeros_scanned={}", report.nonzeros_scanned);
}

fn load_inputs(args: &CommonInputArgs) -> Result<LoadedInputs> {
    let problem: FinalizedProblem =
        serde_json::from_slice(&read_bounded(&args.problem, MAX_CONTEXT_JSON_BYTES)?)
            .with_context(|| format!("invalid finalized problem {}", args.problem.display()))?;
    let manifest: ValidationManifest =
        serde_json::from_slice(&read_bounded(&args.validation, MAX_CONTEXT_JSON_BYTES)?)
            .with_context(|| {
                format!("invalid validation manifest {}", args.validation.display())
            })?;
    let challenge = args
        .challenge
        .as_deref()
        .map(|path| {
            serde_json::from_slice::<SignedChallenge>(&read_bounded(path, MAX_CONTEXT_JSON_BYTES)?)
                .with_context(|| format!("invalid signed challenge {}", path.display()))
        })
        .transpose()?;
    let statement = PublicStatement::new(problem, manifest, challenge)
        .context("public validation statement is invalid")?;
    let solution_json_limit = Solution::maximum_json_bytes(statement.generated().dimension())
        .min(MAX_SOLUTION_JSON_BYTES);
    let solution_file = open_bounded(&args.solution, solution_json_limit)?;
    let solution = Solution::from_json_reader(
        BufReader::new(solution_file),
        statement.generated().dimension(),
    )
    .with_context(|| format!("invalid solution {}", args.solution.display()))?;
    Ok(LoadedInputs {
        statement,
        solution,
    })
}

fn require_fast(statement: &PublicStatement) -> Result<()> {
    if statement.manifest().protocol != ProofProtocol::FastBinary64UnitCircleV3 {
        bail!("fast command requires a fast-binary64-unit-circle-v3 validation manifest");
    }
    Ok(())
}

fn print_artifact_summary(summary: ssv_validation::ArtifactSummary, path: &Path) {
    println!("proof_digest={}", summary.proof_digest);
    println!("problem_digest={}", summary.problem_digest);
    println!(
        "validation_manifest_digest={}",
        summary.validation_manifest_digest
    );
    println!("payload_bytes={}", summary.payload_bytes);
    println!("artifact_bytes={}", summary.artifact_bytes);
    println!("proof_file={}", path.display());
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("could not write {}", path.display()))
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
