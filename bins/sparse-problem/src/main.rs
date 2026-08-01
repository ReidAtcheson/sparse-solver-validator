use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::VerifyingKey;
use ssv_canonical::Digest;
use ssv_problem::{FinalizedProblem, ProblemTemplate, RhsSpec};
use ssv_service_protocol::{ProofProtocol, SignedChallenge, ValidationManifest};
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
    /// Write a validation manifest for a registered backend.
    InitValidation {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = ProtocolArg::Direct)]
        protocol: ProtocolArg,
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
    /// Solve an SPD generated problem with unpreconditioned conjugate gradients.
    CgSolution {
        #[arg(long)]
        problem: PathBuf,
        #[arg(long)]
        solution: PathBuf,
        #[arg(long, default_value_t = 1.0e-12)]
        relative_tolerance: f64,
        #[arg(long)]
        maximum_iterations: Option<usize>,
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
            protocol,
            max_solution_elements,
        } => init_validation(&output, protocol.into(), max_solution_elements),
        Command::ManufacturedSolution { problem, solution } => {
            manufactured_solution(&problem, &solution)
        }
        Command::CgSolution {
            problem,
            solution,
            relative_tolerance,
            maximum_iterations,
        } => cg_solution(&problem, &solution, relative_tolerance, maximum_iterations),
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

fn cg_solution(
    problem_path: &Path,
    solution_path: &Path,
    relative_tolerance: f64,
    maximum_iterations: Option<usize>,
) -> Result<()> {
    if !relative_tolerance.is_finite() || relative_tolerance <= 0.0 {
        bail!("relative tolerance must be finite and positive");
    }
    let problem = load_problem(problem_path)?;
    let generated = problem.compile()?;
    let dimension = generated.dimension();
    let iteration_limit = maximum_iterations.unwrap_or(
        dimension
            .checked_mul(4)
            .context("default CG iteration limit overflow")?,
    );
    if iteration_limit == 0 {
        bail!("maximum CG iterations must be positive");
    }

    fn dot(left: &[f64], right: &[f64]) -> f64 {
        left.iter()
            .zip(right)
            .map(|(&left, &right)| left * right)
            .sum()
    }

    let mut x = vec![0.0; dimension];
    let mut residual = (0..dimension)
        .map(|row| {
            generated
                .rhs_f64(row)
                .context("generated RHS row is missing")
        })
        .collect::<Result<Vec<_>>>()?;
    let mut direction = residual.clone();
    let mut image = vec![0.0; dimension];
    let initial_squared_norm = dot(&residual, &residual);
    let target_squared_norm = initial_squared_norm * relative_tolerance * relative_tolerance;
    let mut squared_norm = initial_squared_norm;
    let mut iterations = 0_usize;

    while squared_norm > target_squared_norm && iterations < iteration_limit {
        for (row_index, row) in generated.rows().enumerate() {
            image[row_index] = row
                .map(|entry| entry.value.to_f64() * direction[entry.column])
                .sum();
        }
        let denominator = dot(&direction, &image);
        if !denominator.is_finite() || denominator <= 0.0 {
            bail!("CG encountered a non-positive or non-finite curvature");
        }
        let step = squared_norm / denominator;
        for ((x_value, residual_value), (&direction_value, &image_value)) in x
            .iter_mut()
            .zip(&mut residual)
            .zip(direction.iter().zip(&image))
        {
            *x_value += step * direction_value;
            *residual_value -= step * image_value;
        }
        let next_squared_norm = dot(&residual, &residual);
        iterations += 1;
        if next_squared_norm <= target_squared_norm {
            squared_norm = next_squared_norm;
            break;
        }
        let beta = next_squared_norm / squared_norm;
        for (direction_value, &residual_value) in direction.iter_mut().zip(&residual) {
            *direction_value = residual_value + beta * *direction_value;
        }
        squared_norm = next_squared_norm;
    }
    if squared_norm > target_squared_norm {
        bail!(
            "CG did not converge in {iteration_limit} iterations: relative residual={}",
            (squared_norm / initial_squared_norm).sqrt()
        );
    }
    for value in &mut x {
        if *value == 0.0 {
            *value = 0.0;
        }
    }
    let solution = Solution::new(x, dimension)?;
    let output = File::create(solution_path)
        .with_context(|| format!("could not create {}", solution_path.display()))?;
    solution
        .write_json(BufWriter::new(output))
        .with_context(|| format!("could not write {}", solution_path.display()))?;
    println!("cg_iterations={iterations}");
    println!(
        "cg_relative_residual={:.17e}",
        if initial_squared_norm == 0.0 {
            0.0
        } else {
            (squared_norm / initial_squared_norm).sqrt()
        }
    );
    println!("solution_file={}", solution_path.display());
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

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProtocolArg {
    Direct,
    Exact,
    Fast,
    FastChunked,
}

impl From<ProtocolArg> for ProofProtocol {
    fn from(value: ProtocolArg) -> Self {
        match value {
            ProtocolArg::Direct => Self::DirectReferenceV1,
            ProtocolArg::Exact => Self::WhirField192L2V4,
            ProtocolArg::Fast => Self::FastBinary64UnitCircleV5,
            ProtocolArg::FastChunked => Self::FastBinary64UnitCircleChunkedV6,
        }
    }
}

fn init_validation(path: &Path, protocol: ProofProtocol, max_solution_elements: u64) -> Result<()> {
    let manifest = ValidationManifest {
        protocol,
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
