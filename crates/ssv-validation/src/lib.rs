//! Backend-neutral validation statements, proof framing, and lifecycle traits.
//!
//! Exact, fast, and future proof systems share this layer. A backend receives a
//! validated [`PublicStatement`] and only its own opaque payload. It does not
//! reparse application provenance, select a matrix family, or invent resource
//! policy. This keeps protocol-specific algebra out of transport and statement
//! handling while avoiding a lowest-common-denominator commitment abstraction.

#![forbid(unsafe_code)]

use ssv_canonical::{DecodeLimits, Digest, Encoder, Reader, domain_separated_digest};
use ssv_problem::{
    FinalizedProblem, FinalizedRandomness, GeneratedProblem, ProblemError, PublicEvaluationPlan,
    SuccinctPublicEvaluator,
};
use ssv_service_protocol::{
    MAX_CHALLENGE_BYTES, MAX_SOLUTION_ELEMENTS_LIMIT, ProofProtocol, ProtocolError,
    SignedChallenge, ValidationManifest,
};
use ssv_solution::Solution;
use thiserror::Error;

const MAGIC: &[u8; 8] = b"SSVART\0\0";
const CONTAINER_VERSION: u16 = 1;
const FLAG_SIGNED_PROBLEM_CHALLENGE: u32 = 1;
const PAYLOAD_FRAME: u16 = 1;
const FINAL_FRAME: u16 = u16::MAX;
const FRAME_VERSION: u16 = 1;
const ARTIFACT_DIGEST_DOMAIN: &[u8] = b"sparse-solve/proof-artifact/v1";

pub const MAX_PUBLIC_STATEMENT_BYTES: usize = 1024 * 1024;
/// Container ceiling. Registered succinct backends apply their tighter 64 MiB
/// decoders before allocating protocol material; the direct oracle may carry x.
pub const MAX_BACKEND_PAYLOAD_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_SUCCINCT_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
/// Maximum common-container size for a registered succinct backend.
pub const MAX_SUCCINCT_ARTIFACT_BYTES: usize =
    MAX_CHALLENGE_BYTES + MAX_PUBLIC_STATEMENT_BYTES + MAX_SUCCINCT_PAYLOAD_BYTES + 128;
pub const MAX_ARTIFACT_BYTES: usize =
    MAX_CHALLENGE_BYTES + MAX_PUBLIC_STATEMENT_BYTES + MAX_BACKEND_PAYLOAD_BYTES + 128;

/// Validated public input shared by every proof backend.
#[derive(Clone, Debug)]
pub struct PublicStatement {
    problem: FinalizedProblem,
    generated: GeneratedProblem,
    manifest: ValidationManifest,
    challenge: Option<SignedChallenge>,
    problem_digest: Digest,
    manifest_digest: Digest,
}

/// Restricted statement view supplied to succinct validators.
///
/// It deliberately exposes the generator-owned public-MLE capability but no
/// sparse row or RHS-entry API. Provers retain [`PublicStatement::generated`]
/// for their allowed `O(nnz)` scans.
#[derive(Clone, Copy, Debug)]
pub struct VerifierStatement<'a> {
    protocol: ProofProtocol,
    problem_digest: Digest,
    manifest_digest: Digest,
    transcript_digest: Digest,
    dimension: usize,
    public_evaluator: PublicEvaluationPlan<'a>,
}

/// Borrowed backend payload after strict common framing and statement parsing.
#[derive(Debug)]
pub struct ArtifactPrelude<'a> {
    statement: PublicStatement,
    payload: &'a [u8],
    encoded: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactSummary {
    pub protocol: ProofProtocol,
    pub problem_digest: Digest,
    pub validation_manifest_digest: Digest,
    pub proof_digest: Digest,
    pub artifact_bytes: usize,
    pub payload_bytes: usize,
    pub has_signed_problem_challenge: bool,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("invalid proof framing: {0}")]
    Framing(String),
    #[error("unsupported proof-container, frame, flag, or protocol version")]
    UnsupportedVersion,
    #[error("proof artifact exceeds a configured resource limit")]
    ResourceLimit,
    #[error("public problem is invalid: {0}")]
    Problem(#[from] ProblemError),
    #[error("validation manifest is invalid: {0}")]
    Manifest(#[from] ProtocolError),
    #[error("signed problem-challenge payload is invalid: {0}")]
    Challenge(ProtocolError),
    #[error("public statement JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("public statement JSON is not in its canonical compact encoding")]
    NonCanonicalJson,
    #[error("problem randomness and signed problem challenge are inconsistent")]
    ProblemChallengeMismatch,
    #[error("proof header and validation manifest select different backends")]
    ProtocolMismatch,
    #[error("problem dimension exceeds the validation manifest's element limit")]
    DimensionLimit,
    #[error("compiled public evaluator exceeds the validation manifest's term budget")]
    PublicEvaluationLimit,
}

/// Common proving/verification contract for a complete backend.
///
/// Commitment-first protocols may add [`PrecommitBackend`] when exposing the
/// commitment as a separate local computation stage is useful. Whether that
/// commitment is followed by Fiat--Shamir or interaction is a property of the
/// concrete backend, not this common statement/framing layer.
pub trait ValidationBackend {
    type ProverContext;
    type ProverReport;
    type VerifierReport;
    type Error;

    const PROTOCOL: ProofProtocol;

    fn prove(
        statement: &PublicStatement,
        solution: &Solution,
        context: &Self::ProverContext,
    ) -> Result<(Vec<u8>, Self::ProverReport), Self::Error>;

    fn verify(
        statement: &VerifierStatement<'_>,
        payload: &[u8],
    ) -> Result<Self::VerifierReport, Self::Error>;
}

/// Contract for a deliberately non-succinct reference backend.
///
/// Reference validators are allowed to stream public matrix rows and RHS
/// entries, so they receive the complete [`PublicStatement`]. Succinct
/// backends must implement [`ValidationBackend`] instead; its restricted
/// [`VerifierStatement`] makes an accidental `O(nnz(A))` verifier scan
/// impossible at the API boundary.
pub trait ReferenceValidationBackend {
    type ProverContext;
    type ProverReport;
    type VerifierReport;
    type Error;

    const PROTOCOL: ProofProtocol;

    fn prove(
        statement: &PublicStatement,
        solution: &Solution,
        context: &Self::ProverContext,
    ) -> Result<(Vec<u8>, Self::ProverReport), Self::Error>;

    fn verify(
        statement: &PublicStatement,
        payload: &[u8],
    ) -> Result<Self::VerifierReport, Self::Error>;
}

/// Optional local lifecycle stage for protocols that commit before proving.
///
/// A commitment returned here need not cross a trust boundary. In particular,
/// a noninteractive backend can absorb it into its Fiat--Shamir transcript and
/// expose this stage only for memory accounting, checkpointing, or tooling.
pub trait PrecommitBackend: ValidationBackend {
    type Commitment;
    type CommitmentReport;

    fn commit(
        statement: &PublicStatement,
        solution: &Solution,
    ) -> Result<(Self::Commitment, Self::CommitmentReport), Self::Error>;
}

impl PublicStatement {
    pub fn new(
        problem: FinalizedProblem,
        manifest: ValidationManifest,
        challenge: Option<SignedChallenge>,
    ) -> Result<Self, ValidationError> {
        problem.validate()?;
        manifest.validate()?;
        if let Some(challenge) = challenge.as_ref() {
            challenge
                .payload
                .validate()
                .map_err(ValidationError::Challenge)?;
        }
        validate_problem_challenge(&problem, challenge.as_ref())?;
        if problem.dimension() > manifest.max_solution_elements {
            return Err(ValidationError::DimensionLimit);
        }
        let generated = problem.compile()?;
        let evaluation = generated.public_evaluation_plan().metadata();
        if evaluation.matrix_period_terms as u64 > manifest.max_public_matrix_terms
            || evaluation.rhs_period_terms as u64 > manifest.max_public_rhs_terms
        {
            return Err(ValidationError::PublicEvaluationLimit);
        }
        let problem_digest = Digest::from_bytes(generated.problem_digest().into_bytes());
        let manifest_digest = manifest.digest()?;
        Ok(Self {
            problem,
            generated,
            manifest,
            challenge,
            problem_digest,
            manifest_digest,
        })
    }

    #[must_use]
    pub const fn problem(&self) -> &FinalizedProblem {
        &self.problem
    }

    #[must_use]
    pub const fn generated(&self) -> &GeneratedProblem {
        &self.generated
    }

    #[must_use]
    pub const fn manifest(&self) -> &ValidationManifest {
        &self.manifest
    }

    #[must_use]
    pub fn challenge(&self) -> Option<&SignedChallenge> {
        self.challenge.as_ref()
    }

    #[must_use]
    pub const fn problem_digest(&self) -> Digest {
        self.problem_digest
    }

    #[must_use]
    pub const fn manifest_digest(&self) -> Digest {
        self.manifest_digest
    }

    /// Digest bound into backend transcripts before any prover message.
    #[must_use]
    pub fn transcript_digest(&self) -> Digest {
        let mut encoded = Encoder::with_capacity(2 + 32 + 32);
        encoded.write_u16(self.manifest.protocol.wire_id());
        encoded.write_digest(&self.problem_digest);
        encoded.write_digest(&self.manifest_digest);
        domain_separated_digest(b"sparse-solve/public-statement/v1", &encoded.into_bytes())
    }

    #[must_use]
    pub fn verifier_statement(&self) -> VerifierStatement<'_> {
        VerifierStatement {
            protocol: self.manifest.protocol,
            problem_digest: self.problem_digest,
            manifest_digest: self.manifest_digest,
            transcript_digest: self.transcript_digest(),
            dimension: self.generated.dimension(),
            public_evaluator: self.generated.public_evaluation_plan(),
        }
    }
}

impl VerifierStatement<'_> {
    #[must_use]
    pub const fn protocol(&self) -> ProofProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn problem_digest(&self) -> Digest {
        self.problem_digest
    }

    #[must_use]
    pub const fn manifest_digest(&self) -> Digest {
        self.manifest_digest
    }

    #[must_use]
    pub const fn transcript_digest(&self) -> Digest {
        self.transcript_digest
    }

    #[must_use]
    pub const fn dimension(&self) -> usize {
        self.dimension
    }

    #[must_use]
    pub const fn public_evaluator(&self) -> PublicEvaluationPlan<'_> {
        self.public_evaluator
    }
}

impl<'a> ArtifactPrelude<'a> {
    pub fn parse(encoded: &'a [u8]) -> Result<Self, ValidationError> {
        Self::parse_with_limits(
            encoded,
            MAX_SOLUTION_ELEMENTS_LIMIT,
            MAX_BACKEND_PAYLOAD_BYTES,
        )
    }

    pub fn parse_with_limits(
        encoded: &'a [u8],
        maximum_solution_elements: u64,
        maximum_payload_bytes: usize,
    ) -> Result<Self, ValidationError> {
        if maximum_solution_elements == 0
            || maximum_solution_elements > MAX_SOLUTION_ELEMENTS_LIMIT
            || maximum_payload_bytes > MAX_BACKEND_PAYLOAD_BYTES
            || encoded.len() > MAX_ARTIFACT_BYTES
        {
            return Err(ValidationError::ResourceLimit);
        }
        let limits = DecodeLimits {
            max_input_bytes: MAX_ARTIFACT_BYTES,
            max_field_bytes: MAX_ARTIFACT_BYTES,
        };
        let mut input = Reader::new(encoded, limits).map_err(framing)?;
        if input.read_fixed_bytes(MAGIC.len()).map_err(framing)? != MAGIC {
            return Err(ValidationError::Framing("bad proof magic".to_owned()));
        }
        if input.read_u16().map_err(framing)? != CONTAINER_VERSION {
            return Err(ValidationError::UnsupportedVersion);
        }
        let protocol = ProofProtocol::from_wire_id(input.read_u16().map_err(framing)?)
            .ok_or(ValidationError::UnsupportedVersion)?;
        let flags = input.read_u32().map_err(framing)?;
        if flags & !FLAG_SIGNED_PROBLEM_CHALLENGE != 0 {
            return Err(ValidationError::UnsupportedVersion);
        }
        let challenge_bytes = input.read_bytes().map_err(framing)?;
        if challenge_bytes.len() > MAX_CHALLENGE_BYTES
            || challenge_bytes.is_empty() == (flags & FLAG_SIGNED_PROBLEM_CHALLENGE != 0)
        {
            return Err(ValidationError::Framing(
                "challenge flag and challenge frame disagree".to_owned(),
            ));
        }
        let challenge = if challenge_bytes.is_empty() {
            None
        } else {
            Some(SignedChallenge::from_canonical_bytes(challenge_bytes)?)
        };

        let problem_json = input.read_bytes().map_err(framing)?;
        let manifest_json = input.read_bytes().map_err(framing)?;
        if problem_json.len() + manifest_json.len() > MAX_PUBLIC_STATEMENT_BYTES {
            return Err(ValidationError::ResourceLimit);
        }
        let problem: FinalizedProblem = serde_json::from_slice(problem_json)?;
        let manifest: ValidationManifest = serde_json::from_slice(manifest_json)?;
        if serde_json::to_vec(&problem)? != problem_json
            || serde_json::to_vec(&manifest)? != manifest_json
        {
            return Err(ValidationError::NonCanonicalJson);
        }
        if manifest.protocol != protocol {
            return Err(ValidationError::ProtocolMismatch);
        }
        if manifest.max_solution_elements > maximum_solution_elements {
            return Err(ValidationError::DimensionLimit);
        }
        let statement = PublicStatement::new(problem, manifest, challenge)?;

        if input.read_u16().map_err(framing)? != PAYLOAD_FRAME
            || input.read_u16().map_err(framing)? != FRAME_VERSION
        {
            return Err(ValidationError::UnsupportedVersion);
        }
        let payload_len = usize::try_from(input.read_u64().map_err(framing)?)
            .map_err(|_| ValidationError::ResourceLimit)?;
        if payload_len > maximum_payload_bytes {
            return Err(ValidationError::ResourceLimit);
        }
        let payload = input.read_fixed_bytes(payload_len).map_err(framing)?;
        if input.read_u16().map_err(framing)? != FINAL_FRAME
            || input.read_u16().map_err(framing)? != FRAME_VERSION
            || input.read_u64().map_err(framing)? != 0
        {
            return Err(ValidationError::Framing(
                "missing canonical final proof frame".to_owned(),
            ));
        }
        input.finish().map_err(framing)?;
        Ok(Self {
            statement,
            payload,
            encoded,
        })
    }

    #[must_use]
    pub const fn statement(&self) -> &PublicStatement {
        &self.statement
    }

    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    #[must_use]
    pub fn summary(&self) -> ArtifactSummary {
        ArtifactSummary {
            protocol: self.statement.manifest.protocol,
            problem_digest: self.statement.problem_digest,
            validation_manifest_digest: self.statement.manifest_digest,
            proof_digest: domain_separated_digest(ARTIFACT_DIGEST_DOMAIN, self.encoded),
            artifact_bytes: self.encoded.len(),
            payload_bytes: self.payload.len(),
            has_signed_problem_challenge: self.statement.challenge.is_some(),
        }
    }

    pub fn verify_with<B: ValidationBackend>(&self) -> Result<B::VerifierReport, B::Error> {
        assert_eq!(
            self.statement.manifest.protocol,
            B::PROTOCOL,
            "backend dispatch must follow the already validated manifest"
        );
        B::verify(&self.statement.verifier_statement(), self.payload)
    }

    /// Dispatches a non-succinct oracle backend with explicit full-problem
    /// access. Keeping this separate from [`Self::verify_with`] prevents a
    /// future succinct backend from silently growing a row-scanning path.
    pub fn verify_reference_with<B: ReferenceValidationBackend>(
        &self,
    ) -> Result<B::VerifierReport, B::Error> {
        assert_eq!(
            self.statement.manifest.protocol,
            B::PROTOCOL,
            "backend dispatch must follow the already validated manifest"
        );
        B::verify(&self.statement, self.payload)
    }
}

pub fn encode_artifact(
    statement: &PublicStatement,
    payload: &[u8],
) -> Result<Vec<u8>, ValidationError> {
    if payload.len() > MAX_BACKEND_PAYLOAD_BYTES {
        return Err(ValidationError::ResourceLimit);
    }
    let challenge = statement
        .challenge
        .as_ref()
        .map(SignedChallenge::to_canonical_bytes)
        .unwrap_or_default();
    let problem_json = serde_json::to_vec(&statement.problem)?;
    let manifest_json = serde_json::to_vec(&statement.manifest)?;
    if challenge.len() > MAX_CHALLENGE_BYTES
        || problem_json.len() + manifest_json.len() > MAX_PUBLIC_STATEMENT_BYTES
    {
        return Err(ValidationError::ResourceLimit);
    }
    let mut output = Encoder::with_capacity(
        challenge.len() + problem_json.len() + manifest_json.len() + payload.len() + 96,
    );
    output.write_fixed_bytes(MAGIC);
    output.write_u16(CONTAINER_VERSION);
    output.write_u16(statement.manifest.protocol.wire_id());
    output.write_u32(if statement.challenge.is_some() {
        FLAG_SIGNED_PROBLEM_CHALLENGE
    } else {
        0
    });
    output.write_bytes(&challenge);
    output.write_bytes(&problem_json);
    output.write_bytes(&manifest_json);
    output.write_u16(PAYLOAD_FRAME);
    output.write_u16(FRAME_VERSION);
    output.write_u64(payload.len() as u64);
    output.write_fixed_bytes(payload);
    output.write_u16(FINAL_FRAME);
    output.write_u16(FRAME_VERSION);
    output.write_u64(0);
    let encoded = output.into_bytes();
    if encoded.len() > MAX_ARTIFACT_BYTES {
        return Err(ValidationError::ResourceLimit);
    }
    Ok(encoded)
}

fn validate_problem_challenge(
    problem: &FinalizedProblem,
    challenge: Option<&SignedChallenge>,
) -> Result<(), ValidationError> {
    match (problem.randomness(), challenge) {
        (FinalizedRandomness::LiteralV1 { .. }, None) => Ok(()),
        (FinalizedRandomness::ChallengeDerivedV1 { .. }, Some(challenge)) => {
            let template_digest = Digest::from_bytes(problem.template().digest()?.into_bytes());
            if challenge.payload.problem_template_digest != template_digest {
                return Err(ValidationError::ProblemChallengeMismatch);
            }
            problem
                .verify_challenge_context(&challenge.payload_canonical_bytes())
                .map_err(|_| ValidationError::ProblemChallengeMismatch)
        }
        _ => Err(ValidationError::ProblemChallengeMismatch),
    }
}

fn framing(error: impl std::fmt::Display) -> ValidationError {
    ValidationError::Framing(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssv_problem::{
        BoundaryRule, DiagonalConstruction, InstanceSeed, MatrixSpec, OffDiagonalValues,
        ProblemTemplate, RequestedOutput, RhsSpec, TemplateRandomness, TemplateSchema,
    };

    fn statement(protocol: ProofProtocol) -> PublicStatement {
        let problem = ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness: TemplateRandomness::LiteralV1 {
                seed: InstanceSeed::from_bytes([7; 32]),
            },
            matrix: MatrixSpec::SeededSymmetricTridiagonalV1 {
                dimension: 8,
                boundary: BoundaryRule::TruncateV1,
                off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                    period_bits: 2,
                    fractional_bits: 4,
                    minimum_magnitude_mantissa: 1,
                    maximum_magnitude_mantissa: 2,
                },
                diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 { margin_mantissa: 8 },
            },
            rhs: RhsSpec::ManufacturedOnesV1,
            requested_outputs: vec![RequestedOutput::SquaredL2ResidualV1],
        }
        .finalize_literal()
        .unwrap();
        PublicStatement::new(
            problem,
            ValidationManifest {
                protocol,
                max_solution_elements: 8,
                ..ValidationManifest::default()
            },
            None,
        )
        .unwrap()
    }

    #[test]
    fn every_registered_backend_uses_the_same_strict_container() {
        for protocol in [
            ProofProtocol::DirectReferenceV1,
            ProofProtocol::WhirField192L2V4,
            ProofProtocol::FastBinary64UnitCircleV3,
        ] {
            let statement = statement(protocol);
            let encoded = encode_artifact(&statement, &[1, 2, 3]).unwrap();
            let decoded = ArtifactPrelude::parse(&encoded).unwrap();
            assert_eq!(decoded.statement().manifest().protocol, protocol);
            assert_eq!(decoded.payload(), &[1, 2, 3]);
            assert_eq!(decoded.summary().artifact_bytes, encoded.len());

            let mut trailing = encoded;
            trailing.push(0);
            assert!(ArtifactPrelude::parse(&trailing).is_err());
        }
    }

    #[test]
    fn manifest_and_header_cannot_select_different_backends() {
        let statement = statement(ProofProtocol::WhirField192L2V4);
        let mut encoded = encode_artifact(&statement, &[]).unwrap();
        encoded[10..12].copy_from_slice(&ProofProtocol::DirectReferenceV1.wire_id().to_be_bytes());
        assert!(matches!(
            ArtifactPrelude::parse(&encoded),
            Err(ValidationError::ProtocolMismatch)
        ));
    }
}
