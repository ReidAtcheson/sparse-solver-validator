use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use ssv_canonical::{CanonicalEncode, Digest, Encoder, domain_separated_digest};
use ssv_problem::{
    FinalizedProblem, InstanceSeed, ProblemTemplate, ProblemTemplateDigest, TemplateRandomness,
};
use ssv_service_protocol::{
    CertifiedScore, ProofProtocol, SignedCertificate, SignedChallenge, ValidationManifest,
    validate_identifier,
};

const BENCHMARK_DIGEST_DOMAIN: &[u8] = b"sparse-solve/benchmark-configuration/v1";
const CARD_DIGEST_DOMAIN: &[u8] = b"sparse-solve/benchmark-result-card/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub(crate) enum BenchmarkSchema {
    #[serde(rename = "sparse-solve/benchmark/v1")]
    V1,
}

/// Immutable benchmark policy snapshotted into every run directory.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchmarkConfig {
    pub schema: BenchmarkSchema,
    pub benchmark_id: String,
    pub authority: AuthorityConfig,
    pub problem_template: ProblemTemplate,
    pub validation: ValidationManifest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum AuthorityConfig {
    /// A service issues signed problem randomness and certifies a submitted proof.
    #[serde(rename = "remote-v1")]
    RemoteV1 {
        service_url: String,
        issuer: String,
        key_id: String,
        public_key: String,
        #[serde(default)]
        authentication: RemoteAuthentication,
        #[serde(default = "default_future_skew_seconds")]
        maximum_future_skew_seconds: i64,
        #[serde(default = "default_challenge_lifetime_seconds")]
        maximum_challenge_lifetime_seconds: i64,
    },
    /// Literal problem randomness and unsigned local validation.
    #[serde(rename = "local-v1")]
    LocalV1,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum RemoteAuthentication {
    #[default]
    #[serde(rename = "none-v1")]
    NoneV1,
    /// Fetch a fresh Cloud Run identity token immediately before every request.
    #[serde(rename = "gcloud-identity-token-v1")]
    GcloudIdentityTokenV1 {
        #[serde(default)]
        audience: Option<String>,
    },
}

const fn default_future_skew_seconds() -> i64 {
    30
}

const fn default_challenge_lifetime_seconds() -> i64 {
    3_600
}

impl BenchmarkConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_identifier("benchmark_id", &self.benchmark_id)
            .context("benchmark_id is invalid")?;
        self.problem_template.validate()?;
        self.validation.validate()?;

        let dimension = self.problem_template.dimension();
        if dimension > self.validation.max_solution_elements {
            bail!("problem dimension exceeds the validation manifest's solution limit");
        }
        let terms = self.problem_template.public_evaluation_terms()?;
        if terms.matrix_period_terms > self.validation.max_public_matrix_terms
            || terms.rhs_period_terms > self.validation.max_public_rhs_terms
        {
            bail!("problem evaluator terms exceed the validation manifest's limits");
        }

        match &self.authority {
            AuthorityConfig::LocalV1 => {
                if !matches!(
                    self.problem_template.randomness,
                    TemplateRandomness::LiteralV1 { .. }
                ) {
                    bail!("local-v1 authority requires literal-v1 template randomness");
                }
            }
            AuthorityConfig::RemoteV1 {
                service_url,
                issuer,
                key_id,
                public_key,
                authentication,
                maximum_future_skew_seconds,
                maximum_challenge_lifetime_seconds,
            } => {
                if !matches!(
                    self.problem_template.randomness,
                    TemplateRandomness::ChallengeDerivedV1 { .. }
                ) {
                    bail!("remote-v1 authority requires challenge-derived-v1 template randomness");
                }
                validate_service_url(service_url)?;
                validate_identifier("issuer", issuer)?;
                validate_identifier("key_id", key_id)?;
                parse_verifying_key(public_key)?;
                if *maximum_future_skew_seconds < 0 {
                    bail!("maximum_future_skew_seconds must not be negative");
                }
                if *maximum_challenge_lifetime_seconds <= 0 {
                    bail!("maximum_challenge_lifetime_seconds must be positive");
                }
                if let RemoteAuthentication::GcloudIdentityTokenV1 {
                    audience: Some(audience),
                } = authentication
                    && (audience.is_empty()
                        || audience.len() > 2_048
                        || audience.chars().any(char::is_control))
                {
                    bail!("gcloud identity-token audience is invalid");
                }
            }
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> Result<Digest> {
        self.validate()?;
        let mut output = Encoder::new();
        output.write_u16(1);
        output.write_str(&self.benchmark_id);
        encode_authority(&self.authority, &mut output)?;
        self.problem_template.encode(&mut output);
        self.validation.encode(&mut output);
        Ok(domain_separated_digest(
            BENCHMARK_DIGEST_DOMAIN,
            &output.into_bytes(),
        ))
    }

    pub(crate) fn remote(&self) -> Option<RemoteAuthorityRef<'_>> {
        match &self.authority {
            AuthorityConfig::LocalV1 => None,
            AuthorityConfig::RemoteV1 {
                service_url,
                issuer,
                key_id,
                public_key,
                authentication,
                maximum_future_skew_seconds,
                maximum_challenge_lifetime_seconds,
            } => Some(RemoteAuthorityRef {
                service_url,
                issuer,
                key_id,
                public_key,
                authentication,
                maximum_future_skew_seconds: *maximum_future_skew_seconds,
                maximum_challenge_lifetime_seconds: *maximum_challenge_lifetime_seconds,
            }),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RemoteAuthorityRef<'a> {
    pub service_url: &'a str,
    pub issuer: &'a str,
    pub key_id: &'a str,
    pub public_key: &'a str,
    pub authentication: &'a RemoteAuthentication,
    pub maximum_future_skew_seconds: i64,
    pub maximum_challenge_lifetime_seconds: i64,
}

impl RemoteAuthorityRef<'_> {
    pub(crate) fn verifying_key(self) -> Result<VerifyingKey> {
        parse_verifying_key(self.public_key)
    }
}

fn encode_authority(authority: &AuthorityConfig, output: &mut Encoder) -> Result<()> {
    match authority {
        AuthorityConfig::LocalV1 => output.write_u16(1),
        AuthorityConfig::RemoteV1 {
            service_url,
            issuer,
            key_id,
            public_key,
            authentication,
            maximum_future_skew_seconds,
            maximum_challenge_lifetime_seconds,
        } => {
            output.write_u16(2);
            output.write_str(service_url);
            output.write_str(issuer);
            output.write_str(key_id);
            output.write_fixed_bytes(parse_verifying_key(public_key)?.as_bytes());
            match authentication {
                RemoteAuthentication::NoneV1 => output.write_u16(1),
                RemoteAuthentication::GcloudIdentityTokenV1 { audience } => {
                    output.write_u16(2);
                    match audience {
                        None => output.write_u16(0),
                        Some(value) => {
                            output.write_u16(1);
                            output.write_str(value);
                        }
                    }
                }
            }
            output.write_i64(*maximum_future_skew_seconds);
            output.write_i64(*maximum_challenge_lifetime_seconds);
        }
    }
    Ok(())
}

fn validate_service_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).context("service_url is not a valid URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("service_url must use http or https");
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("service_url must not contain credentials, a query, or a fragment");
    }
    if !matches!(url.path(), "" | "/") {
        bail!("service_url must identify an origin without an application path");
    }
    Ok(())
}

pub(crate) fn parse_verifying_key(encoded: &str) -> Result<VerifyingKey> {
    if encoded.len() != 64
        || encoded
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
    {
        bail!("public_key must contain exactly 64 lowercase hexadecimal characters");
    }
    let bytes: [u8; 32] = hex::decode(encoded)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public_key must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("public_key is not a valid Ed25519 point")
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum, Deserialize, Serialize)]
pub(crate) enum Materialization {
    #[default]
    #[serde(rename = "matrix-and-rhs")]
    MatrixAndRhs,
    #[serde(rename = "matrix-only")]
    MatrixOnly,
    #[serde(rename = "rhs-only")]
    RhsOnly,
    #[serde(rename = "none")]
    None,
}

impl Materialization {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::MatrixAndRhs => "matrix-and-rhs",
            Self::MatrixOnly => "matrix-only",
            Self::RhsOnly => "rhs-only",
            Self::None => "none",
        }
    }

    pub(crate) const fn writes_matrix(self) -> bool {
        matches!(self, Self::MatrixAndRhs | Self::MatrixOnly)
    }

    pub(crate) const fn writes_rhs(self) -> bool {
        matches!(self, Self::MatrixAndRhs | Self::RhsOnly)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub(crate) enum RunStateSchema {
    #[serde(rename = "sparse-solve/benchmark-run/v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub(crate) enum RunStage {
    #[serde(rename = "created")]
    Created,
    #[serde(rename = "challenge-issued")]
    ChallengeIssued,
    #[serde(rename = "problem-ready")]
    ProblemReady,
    #[serde(rename = "awaiting-solution")]
    AwaitingSolution,
    #[serde(rename = "proof-ready")]
    ProofReady,
    #[serde(rename = "certificate-received")]
    CertificateReceived,
    #[serde(rename = "complete")]
    Complete,
}

impl RunStage {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::ChallengeIssued => "challenge-issued",
            Self::ProblemReady => "problem-ready",
            Self::AwaitingSolution => "awaiting-solution",
            Self::ProofReady => "proof-ready",
            Self::CertificateReceived => "certificate-received",
            Self::Complete => "complete",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunState {
    pub schema: RunStateSchema,
    pub stage: RunStage,
    pub benchmark_digest: Digest,
    pub created_at_unix_seconds: i64,
    pub updated_at_unix_seconds: i64,
    pub materialization: Materialization,
    pub challenge_digest: Option<Digest>,
    pub problem_digest: Option<Digest>,
    pub solution_file_digest: Option<Digest>,
    pub validation_manifest_digest: Option<Digest>,
    pub proof_digest: Option<Digest>,
    pub certificate_digest: Option<Digest>,
}

impl RunState {
    pub(crate) fn new(
        benchmark_digest: Digest,
        materialization: Materialization,
        now: i64,
    ) -> Self {
        Self {
            schema: RunStateSchema::V1,
            stage: RunStage::Created,
            benchmark_digest,
            created_at_unix_seconds: now,
            updated_at_unix_seconds: now,
            materialization,
            challenge_digest: None,
            problem_digest: None,
            solution_file_digest: None,
            validation_manifest_digest: None,
            proof_digest: None,
            certificate_digest: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub(crate) enum ResultCardSchema {
    #[serde(rename = "sparse-solve/benchmark-result-card/v1")]
    V1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProblemSummary {
    pub template_digest: ProblemTemplateDigest,
    pub problem_digest: Digest,
    pub instance_seed: InstanceSeed,
    pub dimension: u64,
    pub structural_nonzeros: u64,
    pub public_matrix_terms: u64,
    pub public_rhs_terms: u64,
}

impl ProblemSummary {
    pub(crate) fn from_problem(problem: &FinalizedProblem) -> Result<Self> {
        let generated = problem.compile()?;
        let terms = problem.public_evaluation_terms()?;
        Ok(Self {
            template_digest: problem.template().digest()?,
            problem_digest: Digest::from_bytes(problem.digest()?.into_bytes()),
            instance_seed: problem.instance_seed(),
            dimension: problem.dimension(),
            structural_nonzeros: u64::try_from(generated.structural_nonzeros())
                .context("structural nonzero count does not fit u64")?,
            public_matrix_terms: terms.matrix_period_terms,
            public_rhs_terms: terms.rhs_period_terms,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum CardAuthorityEvidence {
    #[serde(rename = "remote-v1")]
    RemoteV1 {
        challenge: Box<SignedChallenge>,
        certificate: Box<SignedCertificate>,
    },
    #[serde(rename = "local-v1")]
    LocalV1 {
        validated_at_unix_seconds: i64,
        protocol: ProofProtocol,
        score: CertifiedScore,
        validator_build: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResultCard {
    pub schema: ResultCardSchema,
    pub benchmark: BenchmarkConfig,
    pub benchmark_digest: Digest,
    pub problem: ProblemSummary,
    pub proof_digest: Digest,
    pub authority: CardAuthorityEvidence,
}

impl ResultCard {
    pub(crate) fn digest(&self) -> Result<Digest> {
        let bytes = serde_json::to_vec(self)?;
        Ok(domain_separated_digest(CARD_DIGEST_DOMAIN, &bytes))
    }
}
