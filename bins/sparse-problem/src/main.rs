use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use ssv_canonical::Digest;
use ssv_problem::{FinalizedProblem, ProblemTemplate, RhsSpec};
use ssv_service_protocol::{SignedChallenge, ValidationManifest};
use ssv_solution::Solution;

const MAX_JSON_BYTES: usize = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "sparse-problem",
    about = "Finalize, inspect, and export generated sparse linear systems"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a template and print its canonical identity.
    InspectTemplate {
        #[arg(long)]
        template: PathBuf,
    },
    /// Finalize an explicitly literal-seeded local template.
    FinalizeLocal {
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        problem: PathBuf,
    },
    /// Verify a signed challenge and finalize its challenge-derived template.
    FinalizeChallenge {
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        challenge: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        key_id: String,
        #[arg(long, default_value_t = 30)]
        maximum_future_skew_seconds: i64,
        #[arg(long)]
        problem: PathBuf,
    },
    /// Print trusted generator metadata derived from a finalized problem.
    Inspect {
        #[arg(long)]
        problem: PathBuf,
    },
    /// Stream A and b to Matrix Market files.
    Export {
        #[arg(long)]
        problem: PathBuf,
        #[arg(long)]
        matrix: PathBuf,
        #[arg(long)]
        rhs: PathBuf,
    },
    /// Write the direct-reference-v1 validation manifest.
    InitValidation {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        max_solution_elements: u64,
    },
    /// Write x=1 for a manufactured-ones-v1 problem (development helper).
    ManufacturedSolution {
        #[arg(long)]
        problem: PathBuf,
        #[arg(long)]
        solution: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::InspectTemplate { template } => inspect_template(&template),
        Command::FinalizeLocal { template, problem } => finalize_local(&template, &problem),
        Command::FinalizeChallenge {
            template,
            challenge,
            public_key,
            issuer,
            key_id,
            maximum_future_skew_seconds,
            problem,
        } => finalize_challenge(
            &template,
            &challenge,
            &public_key,
            &issuer,
            &key_id,
            maximum_future_skew_seconds,
            &problem,
        ),
        Command::Inspect { problem } => inspect(&problem),
        Command::Export {
            problem,
            matrix,
            rhs,
        } => export(&problem, &matrix, &rhs),
        Command::InitValidation {
            output,
            max_solution_elements,
        } => init_validation(&output, max_solution_elements),
        Command::ManufacturedSolution { problem, solution } => {
            manufactured_solution(&problem, &solution)
        }
    }
}

fn inspect_template(path: &Path) -> Result<()> {
    let template = load_template(path)?;
    println!("template_digest={}", template.digest()?);
    println!("dimension={}", template.dimension());
    println!("matrix={:?}", template.matrix);
    println!("rhs={:?}", template.rhs);
    println!("randomness={:?}", template.randomness);
    Ok(())
}

fn finalize_local(template_path: &Path, problem_path: &Path) -> Result<()> {
    let template = load_template(template_path)?;
    let problem = template
        .finalize_literal()
        .context("template is not an explicit literal-v1 problem")?;
    write_problem(&problem, problem_path)
}

#[allow(clippy::too_many_arguments)]
fn finalize_challenge(
    template_path: &Path,
    challenge_path: &Path,
    public_key_path: &Path,
    issuer: &str,
    key_id: &str,
    maximum_future_skew_seconds: i64,
    problem_path: &Path,
) -> Result<()> {
    let template = load_template(template_path)?;
    let challenge: SignedChallenge =
        serde_json::from_slice(&read_bounded(challenge_path, MAX_JSON_BYTES)?)
            .with_context(|| format!("invalid challenge JSON {}", challenge_path.display()))?;
    let public_key = load_verifying_key(public_key_path)?;
    challenge
        .verify(
            &public_key,
            issuer,
            key_id,
            now_unix_seconds()?,
            maximum_future_skew_seconds,
        )
        .context("challenge signature or timestamp is invalid")?;
    let template_digest = Digest::from_bytes(template.digest()?.into_bytes());
    if challenge.payload.problem_template_digest != template_digest {
        bail!("challenge is signed for a different problem template");
    }
    let context = challenge.payload_canonical_bytes();
    let problem = template
        .finalize_with_challenge_context(&context)
        .context("could not finalize challenge-derived problem")?;
    write_problem(&problem, problem_path)
}

fn write_problem(problem: &FinalizedProblem, path: &Path) -> Result<()> {
    std::fs::write(path, problem.to_pretty_json()?)
        .with_context(|| format!("could not write {}", path.display()))?;
    println!("problem_digest={}", problem.digest()?);
    println!("instance_seed={}", problem.instance_seed());
    println!("problem_file={}", path.display());
    Ok(())
}

fn inspect(path: &Path) -> Result<()> {
    let problem = load_problem(path)?;
    let generated = problem.compile()?;
    println!("problem_digest={}", problem.digest()?);
    println!("instance_seed={}", problem.instance_seed());
    println!("dimension={}", generated.dimension());
    println!("structural_nonzeros={}", generated.structural_nonzeros());
    println!("randomness={:?}", problem.randomness());
    println!("generator_certificate={:#?}", generated.certificate());
    Ok(())
}

fn export(problem_path: &Path, matrix_path: &Path, rhs_path: &Path) -> Result<()> {
    let problem = load_problem(problem_path)?;
    let generated = problem.compile()?;
    let digest = problem.digest()?;

    let matrix_file = File::create(matrix_path)
        .with_context(|| format!("could not create {}", matrix_path.display()))?;
    let mut matrix = BufWriter::new(matrix_file);
    writeln!(matrix, "%%MatrixMarket matrix coordinate real general")?;
    writeln!(matrix, "% problem_digest {digest}")?;
    writeln!(
        matrix,
        "% coefficient_fractional_bits {}",
        generated.certificate().coefficient_fractional_bits
    )?;
    writeln!(
        matrix,
        "% indices one-based; values binary64 round-trip decimal"
    )?;
    writeln!(
        matrix,
        "{} {} {}",
        generated.dimension(),
        generated.dimension(),
        generated.structural_nonzeros()
    )?;
    for row_index in 0..generated.dimension() {
        for entry in generated.row(row_index).expect("bounded row") {
            writeln!(
                matrix,
                "{} {} {}",
                row_index + 1,
                entry.column + 1,
                entry.value.to_f64()
            )?;
        }
    }
    matrix.flush()?;

    let rhs_file = File::create(rhs_path)
        .with_context(|| format!("could not create {}", rhs_path.display()))?;
    let mut rhs = BufWriter::new(rhs_file);
    writeln!(rhs, "%%MatrixMarket matrix array real general")?;
    writeln!(rhs, "% problem_digest {digest}")?;
    writeln!(
        rhs,
        "% rhs_fractional_bits {}",
        generated.certificate().rhs_fractional_bits
    )?;
    writeln!(rhs, "% values binary64 round-trip decimal")?;
    writeln!(rhs, "{} 1", generated.dimension())?;
    for row_index in 0..generated.dimension() {
        writeln!(
            rhs,
            "{}",
            generated.rhs_f64(row_index).expect("bounded RHS index")
        )?;
    }
    rhs.flush()?;

    println!("problem_digest={digest}");
    println!("matrix_file={}", matrix_path.display());
    println!("rhs_file={}", rhs_path.display());
    println!("structural_nonzeros={}", generated.structural_nonzeros());
    println!(
        "coefficient_fractional_bits={}",
        generated.certificate().coefficient_fractional_bits
    );
    println!(
        "rhs_fractional_bits={}",
        generated.certificate().rhs_fractional_bits
    );
    println!("matrix_market_index_base=1");
    Ok(())
}

fn init_validation(path: &Path, max_solution_elements: u64) -> Result<()> {
    let manifest = ValidationManifest {
        max_solution_elements,
        ..ValidationManifest::default()
    };
    manifest.validate()?;
    let mut json = serde_json::to_string_pretty(&manifest)?;
    json.push('\n');
    std::fs::write(path, json).with_context(|| format!("could not write {}", path.display()))?;
    println!("validation_manifest_digest={}", manifest.digest()?);
    println!("validation_file={}", path.display());
    Ok(())
}

fn manufactured_solution(problem_path: &Path, solution_path: &Path) -> Result<()> {
    let problem = load_problem(problem_path)?;
    if problem.rhs != RhsSpec::ManufacturedOnesV1 {
        bail!("problem RHS is not manufactured-ones-v1");
    }
    let dimension = usize::try_from(problem.dimension()).context("dimension does not fit usize")?;
    let file = File::create(solution_path)
        .with_context(|| format!("could not create {}", solution_path.display()))?;
    let mut output = BufWriter::new(file);
    Solution::write_repeated_json(&mut output, 1.0, dimension)?;
    output.flush()?;
    println!("solution_elements={dimension}");
    println!("solution_file={}", solution_path.display());
    Ok(())
}

fn load_template(path: &Path) -> Result<ProblemTemplate> {
    ProblemTemplate::from_json_slice(&read_bounded(path, MAX_JSON_BYTES)?)
        .with_context(|| format!("invalid problem template {}", path.display()))
}

fn load_problem(path: &Path) -> Result<FinalizedProblem> {
    FinalizedProblem::from_json_slice(&read_bounded(path, MAX_JSON_BYTES)?)
        .with_context(|| format!("invalid finalized problem {}", path.display()))
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let encoded = std::str::from_utf8(&read_bounded(path, 256)?)
        .context("public-key file is not UTF-8")?
        .trim()
        .to_owned();
    if encoded.len() != 64 {
        bail!("public key must contain exactly 64 hexadecimal characters");
    }
    let bytes: [u8; 32] = hex::decode(&encoded)
        .context("public key is not hexadecimal")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("public key is not a valid Ed25519 point")
}

fn now_unix_seconds() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    i64::try_from(duration.as_secs()).context("Unix timestamp does not fit i64")
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
