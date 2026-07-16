use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use ssv_canonical::Digest;
use ssv_direct::{DirectArtifact, MAX_PROOF_BYTES};
use ssv_problem::FinalizedRandomness;
use ssv_service_protocol::SignedCertificate;

const MAX_CERTIFICATE_JSON_BYTES: usize = 1024 * 1024;

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
    /// Decode metadata without validating the submitted numerical relation.
    Inspect {
        #[arg(long)]
        proof: PathBuf,
    },
    /// Validate framing, provenance, and the complete direct relation.
    Verify {
        #[arg(long)]
        proof: PathBuf,
        /// Explicitly permit an unsigned literal-v1 local problem.
        #[arg(long)]
        allow_literal: bool,
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

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Inspect { proof } => inspect(&proof),
        Command::Verify {
            proof,
            allow_literal,
            public_key,
            issuer,
            key_id,
            maximum_future_skew_seconds,
            maximum_challenge_lifetime_seconds,
        } => verify(
            &proof,
            allow_literal,
            public_key.as_deref(),
            issuer.as_deref(),
            key_id.as_deref(),
            maximum_future_skew_seconds,
            maximum_challenge_lifetime_seconds,
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
    let bytes = read_bounded(path, MAX_PROOF_BYTES)?;
    let prelude = DirectArtifact::preparse(&bytes)
        .with_context(|| format!("could not decode envelope {}", path.display()))?;
    let summary = prelude.summary()?;
    let generated = prelude.problem().compile()?;
    println!("verified=false");
    println!("warning=inspection_does_not_validate_the_solution_or_signature");
    println!("proof_kind=direct-reference-v1");
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
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify(
    path: &Path,
    allow_literal: bool,
    public_key_path: Option<&Path>,
    issuer: Option<&str>,
    key_id: Option<&str>,
    maximum_future_skew_seconds: i64,
    maximum_challenge_lifetime_seconds: i64,
) -> Result<()> {
    let bytes = read_bounded(path, MAX_PROOF_BYTES)?;
    let prelude = DirectArtifact::preparse(&bytes)
        .with_context(|| format!("could not decode envelope {}", path.display()))?;
    match (prelude.problem().randomness(), prelude.challenge()) {
        (FinalizedRandomness::LiteralV1 { .. }, None) => {
            if !allow_literal {
                bail!(
                    "literal local proof requires --allow-literal; absence of a challenge is not an implicit fallback"
                );
            }
        }
        (FinalizedRandomness::ChallengeDerivedV1 { .. }, Some(challenge)) => {
            let public_key_path =
                public_key_path.context("hosted proof verification requires --public-key")?;
            let issuer = issuer.context("hosted proof verification requires --issuer")?;
            let key_id = key_id.context("hosted proof verification requires --key-id")?;
            let public_key = load_verifying_key(public_key_path)?;
            challenge
                .verify(
                    &public_key,
                    issuer,
                    key_id,
                    now_unix_seconds()?,
                    maximum_future_skew_seconds,
                )
                .context("signed challenge is invalid")?;
            let lifetime = challenge
                .payload
                .expires_at_unix_seconds
                .checked_sub(challenge.payload.issued_at_unix_seconds)
                .context("challenge timestamp interval underflow")?;
            if lifetime <= 0 || lifetime > maximum_challenge_lifetime_seconds {
                bail!("challenge lifetime exceeds local verification policy");
            }
            let template_digest =
                Digest::from_bytes(prelude.problem().template().digest()?.into_bytes());
            if challenge.payload.problem_template_digest != template_digest {
                bail!("challenge is bound to a different problem template");
            }
            prelude
                .problem()
                .verify_challenge_context(&challenge.payload_canonical_bytes())
                .context("finalized problem does not match the signed challenge payload")?;
        }
        _ => bail!("problem randomness and application challenge header disagree"),
    }

    let artifact = prelude
        .decode()
        .context("could not decode submitted solution")?;
    drop(bytes);
    let output = artifact
        .verify_relation()
        .context("submitted direct relation is invalid")?;
    println!("verified=true");
    println!("proof_kind=direct-reference-v1");
    println!("warning=verified_artifact_contains_complete_solution_and_is_not_succinct");
    println!("problem_digest={}", output.problem_digest);
    println!(
        "validation_manifest_digest={}",
        output.validation_manifest_digest
    );
    println!("proof_digest={}", output.proof_digest);
    println!("residual_squared_l2={:.17e}", output.residual.squared_l2);
    println!("residual_l2={:.17e}", output.residual.l2);
    println!("residual_rms={:.17e}", output.residual.rms);
    println!("residual_max_abs={:.17e}", output.residual.max_abs);
    println!("rows_visited={}", output.rows_visited);
    println!("nonzeros_visited={}", output.nonzeros_visited);
    println!("quality_threshold_applied=false");
    Ok(())
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
    println!(
        "residual_squared_l2={:.17e}",
        certificate.payload.residual.squared_l2
    );
    println!("residual_l2={:.17e}", certificate.payload.residual.l2);
    println!("residual_rms={:.17e}", certificate.payload.residual.rms);
    println!(
        "residual_max_abs={:.17e}",
        certificate.payload.residual.max_abs
    );
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
