use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use ssv_backends::{BackendVerifierReport, verify as verify_backend};
use ssv_canonical::Digest;
use ssv_direct::{DirectArtifact, MAX_PROOF_BYTES};
use ssv_fast::{FastBackend, FastNonceMode};
use ssv_problem::{FinalizedRandomness, SuccinctPublicEvaluator};
use ssv_service_protocol::{CertifiedScore, SignedCertificate};
use ssv_validation::{ArtifactPrelude, MAX_ARTIFACT_BYTES};

const MAX_CERTIFICATE_JSON_BYTES: usize = 1024 * 1024;
const COMMON_MAGIC: &[u8; 8] = b"SSVART\0\0";
const LEGACY_DIRECT_MAGIC: &[u8; 8] = b"SSVPRF\0\0";

#[derive(Debug, Parser)]
#[command(
    name = "sparse-validator",
    about = "Inspect or independently validate sparse-solution artifacts"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Decode bounded metadata without claiming proof validity.
    Inspect {
        #[arg(long)]
        proof: PathBuf,
    },
    /// Validate framing, provenance, backend proof, and fixed consistency policy.
    Verify {
        #[arg(long)]
        proof: PathBuf,
        /// Explicitly permit an unsigned literal-v1 local problem.
        #[arg(long)]
        allow_literal: bool,
        /// Explicitly permit fast mode without an externally timestamped nonce.
        #[arg(long)]
        allow_offline_fast: bool,
        #[arg(long)]
        public_key: Option<PathBuf>,
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long)]
        key_id: Option<String>,
        #[arg(long, default_value_t = 30)]
        maximum_future_skew_seconds: i64,
        #[arg(long, default_value_t = 3600)]
        maximum_challenge_lifetime_seconds: i64,
    },
    /// Authenticate a signed certificate against an external trust anchor.
    VerifyCertificate {
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        key_id: String,
    },
}

struct VerificationPolicy<'a> {
    allow_literal: bool,
    allow_offline_fast: bool,
    public_key_path: Option<&'a Path>,
    issuer: Option<&'a str>,
    key_id: Option<&'a str>,
    maximum_future_skew_seconds: i64,
    maximum_challenge_lifetime_seconds: i64,
    now_unix_seconds: i64,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Inspect { proof } => inspect(&proof),
        Command::Verify {
            proof,
            allow_literal,
            allow_offline_fast,
            public_key,
            issuer,
            key_id,
            maximum_future_skew_seconds,
            maximum_challenge_lifetime_seconds,
        } => verify(
            &proof,
            VerificationPolicy {
                allow_literal,
                allow_offline_fast,
                public_key_path: public_key.as_deref(),
                issuer: issuer.as_deref(),
                key_id: key_id.as_deref(),
                maximum_future_skew_seconds,
                maximum_challenge_lifetime_seconds,
                now_unix_seconds: now_unix_seconds()?,
            },
        ),
        Command::VerifyCertificate {
            certificate,
            public_key,
            issuer,
            key_id,
        } => verify_certificate(&certificate, &public_key, &issuer, &key_id),
    }
}

fn inspect(path: &Path) -> Result<()> {
    let bytes = read_bounded(path, MAX_ARTIFACT_BYTES.max(MAX_PROOF_BYTES))?;
    if bytes.starts_with(COMMON_MAGIC) {
        inspect_common(path, &bytes)
    } else if bytes.starts_with(LEGACY_DIRECT_MAGIC) {
        inspect_legacy_direct(path, &bytes)
    } else {
        bail!(
            "{} has an unrecognized proof-container magic",
            path.display()
        );
    }
}

fn inspect_common(path: &Path, bytes: &[u8]) -> Result<()> {
    let prelude = ArtifactPrelude::parse(bytes)
        .with_context(|| format!("could not decode envelope {}", path.display()))?;
    let summary = prelude.summary();
    let generated = prelude.statement().generated();
    let evaluation = generated.public_evaluation_plan().metadata();
    println!("verified=false");
    println!("warning=inspection_does_not_validate_the_proof_or_signatures");
    println!("proof_kind={:?}", summary.protocol);
    println!("proof_digest={}", summary.proof_digest);
    println!("problem_digest={}", summary.problem_digest);
    println!(
        "validation_manifest_digest={}",
        summary.validation_manifest_digest
    );
    println!("artifact_bytes={}", summary.artifact_bytes);
    println!("payload_bytes={}", summary.payload_bytes);
    println!(
        "has_signed_problem_challenge={}",
        summary.has_signed_problem_challenge
    );
    println!("dimension={}", generated.dimension());
    println!("structural_nonzeros={}", generated.structural_nonzeros());
    println!("public_evaluator_version={}", evaluation.evaluator_version);
    println!(
        "public_matrix_period_terms={}",
        evaluation.matrix_period_terms
    );
    println!("public_rhs_period_terms={}", evaluation.rhs_period_terms);
    println!("generator_certificate={:#?}", generated.certificate());
    if let Some(challenge) = prelude.statement().challenge() {
        print_problem_challenge(challenge);
    }
    if summary.protocol == ssv_service_protocol::ProofProtocol::FastBinary64UnitCircleV2 {
        let preflight =
            FastBackend::preflight(&prelude.statement().verifier_statement(), prelude.payload())
                .context("fast payload preflight failed")?;
        println!("fast_nonce_mode={:?}", preflight.nonce_mode);
        println!(
            "fast_precommitment_digest={}",
            preflight.precommitment_digest
        );
        println!("fast_payload_digest={}", preflight.payload_digest);
        println!(
            "has_signed_commitment_challenge={}",
            preflight.external_challenge.is_some()
        );
    }
    Ok(())
}

fn inspect_legacy_direct(path: &Path, bytes: &[u8]) -> Result<()> {
    let prelude = DirectArtifact::preparse(bytes)
        .with_context(|| format!("could not decode legacy envelope {}", path.display()))?;
    let summary = prelude.summary()?;
    let generated = prelude.problem().compile()?;
    println!("verified=false");
    println!("warning=inspection_does_not_validate_the_solution_or_signature");
    println!("proof_kind=direct-reference-v1-legacy-container");
    println!("warning=artifact_contains_complete_solution_and_is_not_succinct");
    println!("proof_digest={}", summary.proof_digest);
    println!("problem_digest={}", summary.problem_digest);
    println!(
        "validation_manifest_digest={}",
        summary.validation_manifest_digest
    );
    println!("artifact_bytes={}", summary.encoded_len);
    println!("solution_elements={}", summary.solution_elements);
    println!("has_signed_challenge={}", summary.has_signed_challenge);
    println!("dimension={}", generated.dimension());
    println!("structural_nonzeros={}", generated.structural_nonzeros());
    println!("generator_certificate={:#?}", generated.certificate());
    if let Some(challenge) = prelude.challenge() {
        print_problem_challenge(challenge);
    }
    Ok(())
}

fn verify(path: &Path, policy: VerificationPolicy<'_>) -> Result<()> {
    let bytes = read_bounded(path, MAX_ARTIFACT_BYTES.max(MAX_PROOF_BYTES))?;
    if bytes.starts_with(COMMON_MAGIC) {
        verify_common(path, &bytes, &policy)
    } else if bytes.starts_with(LEGACY_DIRECT_MAGIC) {
        verify_legacy_direct(path, bytes, &policy)
    } else {
        bail!(
            "{} has an unrecognized proof-container magic",
            path.display()
        );
    }
}

fn verify_common(path: &Path, bytes: &[u8], policy: &VerificationPolicy<'_>) -> Result<()> {
    let prelude = ArtifactPrelude::parse(bytes)
        .with_context(|| format!("could not decode envelope {}", path.display()))?;
    authenticate_problem_statement(prelude.statement(), policy)?;

    // Hosted fast challenges are authenticated before the expensive proof
    // path. The backend verifier reuses this exact structural preflight.
    if prelude.statement().manifest().protocol
        == ssv_service_protocol::ProofProtocol::FastBinary64UnitCircleV2
    {
        let preflight =
            FastBackend::preflight(&prelude.statement().verifier_statement(), prelude.payload())
                .context("fast payload preflight failed")?;
        authenticate_fast_preflight(&preflight, prelude.statement().challenge(), policy)?;
    }

    let report = verify_backend(&prelude).context("backend proof verification failed")?;
    if matches!(&report, BackendVerifierReport::Fast(fast) if !fast.passes_policy()) {
        println!("verified=false");
        print_backend_report(&report);
        bail!("fast proof exceeded frozen policy-2 consistency tolerances");
    }
    let accepted = report.accept()?;
    let summary = prelude.summary();
    println!("verified=true");
    println!("proof_digest={}", summary.proof_digest);
    println!("problem_digest={}", summary.problem_digest);
    println!(
        "validation_manifest_digest={}",
        summary.validation_manifest_digest
    );
    print_backend_report(accepted.report());
    println!("quality_threshold_applied=false");
    Ok(())
}

fn print_backend_report(report: &BackendVerifierReport) {
    match report {
        BackendVerifierReport::Direct(report) => {
            println!("proof_kind=direct-reference-v1");
            println!("warning=artifact_contains_complete_solution_and_is_not_succinct");
            print_residual(report.residual);
            println!("rows_visited={}", report.rows_visited);
            println!("nonzeros_visited={}", report.nonzeros_visited);
            println!(
                "solution_elements_materialized={}",
                report.solution_elements_materialized
            );
        }
        BackendVerifierReport::Exact(report) => {
            println!("proof_kind=whir-field192-l2-v4");
            println!(
                "residual_squared_l2_numerator={}",
                report.residual.numerator
            );
            println!(
                "residual_squared_l2_denominator_power={}",
                report.residual.denominator_power
            );
            if let Some(value) = report.residual.squared_l2_approx() {
                println!("residual_squared_l2_approx={value:.17e}");
            }
            println!("sumcheck_rounds={}", report.algebra.sumcheck_rounds);
            println!(
                "sumcheck_field_elements={}",
                report.algebra.sumcheck_field_elements
            );
            println!("whir_opening_points={}", report.pcs.opening_points);
            println!(
                "public_matrix_period_terms={}",
                report.algebra.public_matrix.periodic_terms
            );
            println!(
                "public_rhs_period_terms={}",
                report.algebra.public_rhs.periodic_terms
            );
            print_succinct_materialization(
                report.algebra.generator_row_queries,
                report.algebra.solution_elements_materialized,
                report.algebra.residual_elements_materialized,
                0,
                report.algebra.accounted_high_watermark_bytes,
            );
        }
        BackendVerifierReport::Fast(report) => {
            println!("proof_kind=fast-binary64-unit-circle-v2");
            println!("warning=provisional_metric_certificate_not_exact_field_soundness");
            println!("fast_nonce_mode={:?}", report.nonce_mode);
            println!(
                "residual_squared_l2={:.17e}",
                report.score.residual_squared_l2
            );
            println!("residual_l2={:.17e}", report.score.residual_l2);
            println!("residual_rms={:.17e}", report.score.residual_rms);
            print_defects("norm_sumcheck", report.score.norm_sumcheck);
            print_defects("matvec_sumcheck", report.score.matvec_sumcheck);
            print_defects("linear_opening", report.score.linear_opening_sumcheck);
            print_defects("unit_circle_folds", report.score.unit_circle_folds);
            println!(
                "recursive_query_trajectories={}",
                report.score.proximity_queries_per_round
            );
            println!(
                "conditional_miss_probability_bad_fraction_1_percent={:.17e}",
                report.score.conditional_miss_probability_upper_bound[0]
            );
            println!("sumcheck_rounds={}", report.work.sumcheck_rounds);
            println!("merkle_hashes={}", report.work.merkle_hashes);
            println!(
                "public_matrix_period_terms={}",
                report.work.public_matrix_period_terms
            );
            println!(
                "public_rhs_period_terms={}",
                report.work.public_rhs_period_terms
            );
            print_succinct_materialization(
                report.work.generator_row_queries,
                report.work.solution_elements_materialized,
                report.work.residual_elements_materialized,
                report.work.codeword_elements_materialized,
                report.work.accounted_high_watermark_bytes,
            );
        }
    }
}

fn print_defects(prefix: &str, summary: ssv_fast::DefectSummary) {
    println!(
        "{prefix}_maximum_absolute_defect={:.17e}",
        summary.max_absolute
    );
    println!(
        "{prefix}_maximum_normalized_defect={:.17e}",
        summary.max_normalized
    );
    println!(
        "{prefix}_rms_normalized_defect={:.17e}",
        summary.rms_normalized
    );
    println!(
        "{prefix}_threshold_exceedances={}",
        summary.threshold_exceedances
    );
}

fn print_succinct_materialization(
    rows: u64,
    solution: u64,
    residual: u64,
    codeword: u64,
    high_watermark: usize,
) {
    println!("generator_row_queries={rows}");
    println!("solution_elements_materialized={solution}");
    println!("residual_elements_materialized={residual}");
    println!("codeword_elements_materialized={codeword}");
    println!("accounted_high_watermark_bytes={high_watermark}");
}

fn authenticate_problem_statement(
    statement: &ssv_validation::PublicStatement,
    policy: &VerificationPolicy<'_>,
) -> Result<()> {
    match (statement.problem().randomness(), statement.challenge()) {
        (FinalizedRandomness::LiteralV1 { .. }, None) => {
            if !policy.allow_literal {
                bail!("literal local proof requires --allow-literal");
            }
        }
        (FinalizedRandomness::ChallengeDerivedV1 { .. }, Some(challenge)) => {
            let (key, issuer, key_id) = trust_anchor(policy)?;
            challenge
                .verify(
                    &key,
                    issuer,
                    key_id,
                    policy.now_unix_seconds,
                    policy.maximum_future_skew_seconds,
                )
                .context("signed problem challenge is invalid")?;
            validate_lifetime(
                challenge.payload.issued_at_unix_seconds,
                challenge.payload.expires_at_unix_seconds,
                policy.maximum_challenge_lifetime_seconds,
            )?;
        }
        _ => bail!("problem randomness and application challenge header disagree"),
    }
    Ok(())
}

fn authenticate_fast_preflight(
    preflight: &ssv_fast::FastPreflight,
    problem_challenge: Option<&ssv_service_protocol::SignedChallenge>,
    policy: &VerificationPolicy<'_>,
) -> Result<()> {
    match (preflight.nonce_mode, preflight.external_challenge.as_ref()) {
        (FastNonceMode::OfflineFiatShamir, None) => {
            if !policy.allow_offline_fast {
                bail!("offline fast proof requires --allow-offline-fast");
            }
        }
        (FastNonceMode::ExternalSigned, Some(challenge)) => {
            let (key, issuer, key_id) = trust_anchor(policy)?;
            challenge
                .verify(
                    &key,
                    issuer,
                    key_id,
                    policy.now_unix_seconds,
                    policy.maximum_future_skew_seconds,
                )
                .context("signed fast commitment challenge is invalid")?;
            validate_lifetime(
                challenge.payload.issued_at_unix_seconds,
                challenge.payload.expires_at_unix_seconds,
                policy.maximum_challenge_lifetime_seconds,
            )?;
            if let Some(problem_challenge) = problem_challenge
                && challenge.payload.issued_at_unix_seconds
                    < problem_challenge.payload.issued_at_unix_seconds
            {
                bail!("fast commitment challenge predates the problem challenge");
            }
        }
        _ => bail!("fast nonce mode and commitment challenge disagree"),
    }
    Ok(())
}

fn trust_anchor<'a>(
    policy: &'a VerificationPolicy<'a>,
) -> Result<(VerifyingKey, &'a str, &'a str)> {
    let path = policy
        .public_key_path
        .context("signed challenge verification requires --public-key")?;
    let issuer = policy
        .issuer
        .context("signed challenge verification requires --issuer")?;
    let key_id = policy
        .key_id
        .context("signed challenge verification requires --key-id")?;
    Ok((load_verifying_key(path)?, issuer, key_id))
}

fn validate_lifetime(issued: i64, expires: i64, maximum: i64) -> Result<()> {
    let lifetime = expires
        .checked_sub(issued)
        .context("challenge timestamp interval underflow")?;
    if lifetime <= 0 || lifetime > maximum {
        bail!("challenge lifetime exceeds local verification policy");
    }
    Ok(())
}

fn verify_legacy_direct(
    path: &Path,
    bytes: Vec<u8>,
    policy: &VerificationPolicy<'_>,
) -> Result<()> {
    let prelude = DirectArtifact::preparse(&bytes)
        .with_context(|| format!("could not decode legacy envelope {}", path.display()))?;
    match (prelude.problem().randomness(), prelude.challenge()) {
        (FinalizedRandomness::LiteralV1 { .. }, None) => {
            if !policy.allow_literal {
                bail!("literal local proof requires --allow-literal");
            }
        }
        (FinalizedRandomness::ChallengeDerivedV1 { .. }, Some(challenge)) => {
            let (key, issuer, key_id) = trust_anchor(policy)?;
            challenge.verify(
                &key,
                issuer,
                key_id,
                policy.now_unix_seconds,
                policy.maximum_future_skew_seconds,
            )?;
            validate_lifetime(
                challenge.payload.issued_at_unix_seconds,
                challenge.payload.expires_at_unix_seconds,
                policy.maximum_challenge_lifetime_seconds,
            )?;
            let template_digest =
                Digest::from_bytes(prelude.problem().template().digest()?.into_bytes());
            if challenge.payload.problem_template_digest != template_digest {
                bail!("challenge is bound to a different problem template");
            }
        }
        _ => bail!("problem randomness and application challenge header disagree"),
    }
    let artifact = prelude.decode()?;
    drop(bytes);
    let output = artifact.verify_relation()?;
    println!("verified=true");
    println!("proof_kind=direct-reference-v1-legacy-container");
    println!("warning=artifact_contains_complete_solution_and_is_not_succinct");
    println!("problem_digest={}", output.problem_digest);
    println!(
        "validation_manifest_digest={}",
        output.validation_manifest_digest
    );
    println!("proof_digest={}", output.proof_digest);
    print_residual(output.residual);
    println!("rows_visited={}", output.rows_visited);
    println!("nonzeros_visited={}", output.nonzeros_visited);
    println!("quality_threshold_applied=false");
    Ok(())
}

fn print_residual(residual: ssv_service_protocol::ResidualMetrics) {
    println!("residual_squared_l2={:.17e}", residual.squared_l2);
    println!("residual_l2={:.17e}", residual.l2);
    println!("residual_rms={:.17e}", residual.rms);
    println!("residual_max_abs={:.17e}", residual.max_abs);
}

fn print_problem_challenge(challenge: &ssv_service_protocol::SignedChallenge) {
    println!("challenge_issuer={}", challenge.payload.issuer);
    println!("challenge_key_id={}", challenge.payload.key_id);
    println!(
        "challenge_issued_at_unix_seconds={}",
        challenge.payload.issued_at_unix_seconds
    );
    println!(
        "challenge_expires_at_unix_seconds={}",
        challenge.payload.expires_at_unix_seconds
    );
}

fn verify_certificate(
    certificate_path: &Path,
    public_key_path: &Path,
    issuer: &str,
    key_id: &str,
) -> Result<()> {
    let certificate: SignedCertificate =
        serde_json::from_slice(&read_bounded(certificate_path, MAX_CERTIFICATE_JSON_BYTES)?)
            .with_context(|| format!("invalid certificate JSON {}", certificate_path.display()))?;
    certificate
        .verify(&load_verifying_key(public_key_path)?, issuer, key_id)
        .context("certificate signature is invalid")?;
    println!("certificate_signature_valid=true");
    println!("certificate_digest={}", certificate.digest());
    println!("problem_digest={}", certificate.payload.problem_digest);
    println!("proof_digest={}", certificate.payload.proof_digest);
    println!(
        "validation_manifest_digest={}",
        certificate.payload.validation_manifest_digest
    );
    println!(
        "issued_at_unix_seconds={}",
        certificate.payload.issued_at_unix_seconds
    );
    match &certificate.payload.score {
        CertifiedScore::DirectBinary64ResidualV1 { residual } => {
            println!("score_kind=direct-binary64-residual-v1");
            print_residual(*residual);
        }
        CertifiedScore::ExactDyadicSquaredL2V1 {
            numerator,
            denominator_power,
        } => {
            println!("score_kind=exact-dyadic-squared-l2-v1");
            println!("residual_squared_l2_numerator={numerator}");
            println!("residual_squared_l2_denominator_power={denominator_power}");
        }
        CertifiedScore::FastBinary64SquaredL2V1 {
            squared_l2,
            consistency,
        } => {
            println!("score_kind=fast-binary64-squared-l2-v1");
            println!("residual_squared_l2={squared_l2:.17e}");
            println!(
                "maximum_normalized_defect={:.17e}",
                [
                    consistency.norm_sumcheck.maximum_normalized_defect,
                    consistency.matvec_sumcheck.maximum_normalized_defect,
                    consistency.linear_opening.maximum_normalized_defect,
                    consistency.unit_circle_folds.maximum_normalized_defect,
                ]
                .into_iter()
                .fold(0.0_f64, f64::max)
            );
        }
    }
    println!("quality_threshold_applied=false");
    Ok(())
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
