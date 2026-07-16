//! Direct relation-check baseline and its strict artifact container.
//!
//! This backend deliberately carries the complete solution. It is useful for
//! integration, protocol framing, and as an independent correctness oracle for
//! future succinct backends. It is not a succinct proof and offers no witness
//! privacy.

#![forbid(unsafe_code)]

use serde_json::Error as JsonError;
use ssv_canonical::{DecodeLimits, Digest, Encoder, Reader, domain_separated_digest};
use ssv_problem::{FinalizedProblem, FinalizedRandomness, GeneratedProblem, ProblemError};
use ssv_service_protocol::{
    MAX_CHALLENGE_BYTES, ProofProtocol, ResidualMetrics, SignedChallenge, ValidationManifest,
};
use ssv_solution::{Solution, SolutionError};
use ssv_validation::{MAX_BACKEND_PAYLOAD_BYTES, PublicStatement, ReferenceValidationBackend};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"SSVPRF\0\0";
const CONTAINER_VERSION: u16 = 1;
const DIRECT_PROOF_KIND: u16 = 1;
const DIRECT_PROOF_VERSION: u16 = 1;
const NO_TRANSCRIPT_SUITE: u16 = 0;
const FLAG_SIGNED_CHALLENGE: u32 = 1;
const SOLUTION_FRAME: u16 = 1;
const FINAL_FRAME: u16 = u16::MAX;
const FRAME_VERSION: u16 = 1;
const PROOF_DIGEST_DOMAIN: &[u8] = b"sparse-solve/direct-proof-artifact/v1";

// Backend payloads live inside the common `SSVART` envelope. Keep this codec
// independent of the legacy `SSVPRF` container above so migrating transports
// does not silently change historical artifact bytes.
const BACKEND_PAYLOAD_MAGIC: &[u8; 8] = b"SSVDIR\0\0";
const BACKEND_PAYLOAD_VERSION: u16 = 1;
const BACKEND_SOLUTION_FRAME: u16 = 1;
const BACKEND_FRAME_VERSION: u16 = 1;
const BACKEND_FINAL_FRAME: u16 = u16::MAX;
const BACKEND_FIXED_BYTES: usize = 8 // magic
    + 2 // payload version
    + 2 + 2 + 8 // solution frame tag, version, and byte length
    + 8 // solution element count
    + 2 + 2 + 8; // final frame tag, version, and zero length

pub const MAX_APPLICATION_HEADER_BYTES: usize = MAX_CHALLENGE_BYTES;
pub const MAX_PUBLIC_CONTEXT_BYTES: usize = 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = 512 * 1024 * 1024;
const MAX_ENVELOPE_BYTES_WITHOUT_SOLUTION: usize = 8 // magic
    + 4 * 2 // version and protocol tags
    + 4 // flags
    + 8 + MAX_APPLICATION_HEADER_BYTES // framed application header
    + 8 + MAX_PUBLIC_CONTEXT_BYTES // framed public context
    + 2 + 2 + 8 + 8 // solution frame header and count
    + 2 + 2 + 8; // final frame

/// Largest possible canonical direct artifact for an admitted solution count.
///
/// Returns `None` if the count lies outside protocol limits, does not fit the
/// current target, or would exceed the global direct-artifact byte limit.
#[must_use]
pub fn maximum_artifact_bytes(maximum_solution_elements: u64) -> Option<usize> {
    if maximum_solution_elements == 0
        || maximum_solution_elements > ssv_service_protocol::MAX_SOLUTION_ELEMENTS_LIMIT
    {
        return None;
    }
    let elements = usize::try_from(maximum_solution_elements).ok()?;
    let bytes = MAX_ENVELOPE_BYTES_WITHOUT_SOLUTION.checked_add(elements.checked_mul(8)?)?;
    (bytes <= MAX_PROOF_BYTES).then_some(bytes)
}

/// Exact common-envelope payload size for a direct solution vector.
///
/// The result is absent if the count cannot be represented within the common
/// backend payload ceiling. This check is performed before allocating or
/// decoding a dimension-sized vector.
#[must_use]
pub fn maximum_backend_payload_bytes(solution_elements: usize) -> Option<usize> {
    let bytes = BACKEND_FIXED_BYTES.checked_add(solution_elements.checked_mul(8)?)?;
    (bytes <= MAX_BACKEND_PAYLOAD_BYTES).then_some(bytes)
}

#[derive(Debug, Error)]
pub enum DirectError {
    #[error("invalid proof framing: {0}")]
    Framing(String),
    #[error("unsupported container, proof, transcript, flags, or frame version")]
    UnsupportedVersion,
    #[error("public context JSON is invalid: {0}")]
    Json(#[from] JsonError),
    #[error("problem is invalid: {0}")]
    Problem(#[from] ProblemError),
    #[error("validation manifest is invalid: {0}")]
    Manifest(#[from] ssv_service_protocol::ProtocolError),
    #[error("solution is invalid: {0}")]
    Solution(#[from] SolutionError),
    #[error("manifest selected a proof protocol other than direct-reference-v1")]
    WrongProtocol,
    #[error("problem dimension exceeds the manifest's solution-element limit")]
    ResourceLimit,
    #[error("signed-challenge flag and application-header presence disagree")]
    HeaderFlagMismatch,
    #[error("application header is not a canonical signed challenge: {0}")]
    Challenge(String),
    #[error("problem randomness and signed challenge header are inconsistent")]
    ProblemChallengeMismatch,
    #[error("non-finite arithmetic occurred while evaluating row {row}")]
    NonFiniteArithmetic { row: usize },
    #[error("the residual metrics are outside their representable binary64 range")]
    UnrepresentableResidualNorm,
}

/// Non-succinct baseline implemented through the backend-neutral lifecycle.
///
/// Unlike succinct backends, verification intentionally receives a full
/// [`PublicStatement`] through [`ReferenceValidationBackend`] and scans every
/// generated sparse row. This keeps that cost visible in the type system.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectBackend;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectProverReport {
    pub solution_elements: usize,
    pub payload_bytes: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DirectVerifierReport {
    pub residual: ResidualMetrics,
    pub rows_visited: u64,
    pub nonzeros_visited: u64,
    pub solution_elements_materialized: u64,
    pub solution_bytes_materialized: usize,
}

impl ReferenceValidationBackend for DirectBackend {
    type ProverContext = ();
    type ProverReport = DirectProverReport;
    type VerifierReport = DirectVerifierReport;
    type Error = DirectError;

    const PROTOCOL: ProofProtocol = ProofProtocol::DirectReferenceV1;

    fn prove(
        statement: &PublicStatement,
        solution: &Solution,
        _context: &Self::ProverContext,
    ) -> Result<(Vec<u8>, Self::ProverReport), Self::Error> {
        prove_backend_payload(statement, solution)
    }

    fn verify(
        statement: &PublicStatement,
        payload: &[u8],
    ) -> Result<Self::VerifierReport, Self::Error> {
        verify_backend_payload(statement, payload)
    }
}

/// A fully parsed direct-reference artifact.
#[derive(Debug)]
pub struct DirectArtifact {
    problem: FinalizedProblem,
    generated: GeneratedProblem,
    manifest: ValidationManifest,
    challenge: Option<SignedChallenge>,
    solution: Solution,
    problem_digest: Digest,
    validation_manifest_digest: Digest,
    digest: Digest,
    encoded_len: usize,
}

/// A fully framed artifact whose large solution payload is still borrowed.
///
/// Parsing this type validates all framing, EOF, public metadata, provenance,
/// and resource bounds without allocating the dimension-sized solution. A
/// hosted service can therefore authenticate the challenge before calling
/// [`Self::decode`].
pub struct DirectArtifactPrelude<'a> {
    problem: FinalizedProblem,
    manifest: ValidationManifest,
    challenge: Option<SignedChallenge>,
    solution_payload: &'a [u8],
    encoded: &'a [u8],
    solution_elements: usize,
}

impl std::fmt::Debug for DirectArtifactPrelude<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DirectArtifactPrelude")
            .field("problem", &self.problem)
            .field("manifest", &self.manifest)
            .field("challenge", &self.challenge)
            .field("solution_elements", &self.solution_elements)
            .field("encoded_len", &self.encoded.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct DirectArtifactSummary {
    pub proof_digest: Digest,
    pub encoded_len: usize,
    pub problem_digest: Digest,
    pub validation_manifest_digest: Digest,
    pub solution_elements: usize,
    pub has_signed_challenge: bool,
    pub protocol: ProofProtocol,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedDirectOutput {
    pub problem_digest: Digest,
    pub validation_manifest_digest: Digest,
    pub proof_digest: Digest,
    pub residual: ResidualMetrics,
    pub rows_visited: u64,
    pub nonzeros_visited: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct RelationEvaluation {
    residual: ResidualMetrics,
    rows_visited: u64,
    nonzeros_visited: u64,
}

fn prove_backend_payload(
    statement: &PublicStatement,
    solution: &Solution,
) -> Result<(Vec<u8>, DirectProverReport), DirectError> {
    validate_backend_statement(statement)?;
    let dimension = statement.generated().dimension();
    if solution.as_slice().len() != dimension {
        return Err(SolutionError::WrongLength {
            expected: dimension,
            actual: solution.as_slice().len(),
        }
        .into());
    }
    // `Solution` already enforces this policy at construction. Rechecking the
    // security boundary here makes the backend contract explicit and robust
    // if the representation later gains another trusted constructor.
    validate_solution_values(solution.as_slice())?;

    let payload_bytes =
        maximum_backend_payload_bytes(dimension).ok_or(DirectError::ResourceLimit)?;
    let solution_frame_bytes = 8_usize
        .checked_add(dimension.checked_mul(8).ok_or(DirectError::ResourceLimit)?)
        .ok_or(DirectError::ResourceLimit)?;
    let mut output = Encoder::with_capacity(payload_bytes);
    output.write_fixed_bytes(BACKEND_PAYLOAD_MAGIC);
    output.write_u16(BACKEND_PAYLOAD_VERSION);
    output.write_u16(BACKEND_SOLUTION_FRAME);
    output.write_u16(BACKEND_FRAME_VERSION);
    output.write_u64(solution_frame_bytes as u64);
    output.write_u64(dimension as u64);
    for &value in solution.as_slice() {
        output.write_u64(value.to_bits());
    }
    output.write_u16(BACKEND_FINAL_FRAME);
    output.write_u16(BACKEND_FRAME_VERSION);
    output.write_u64(0);
    let payload = output.into_bytes();
    debug_assert_eq!(payload.len(), payload_bytes);
    Ok((
        payload,
        DirectProverReport {
            solution_elements: dimension,
            payload_bytes,
        },
    ))
}

fn verify_backend_payload(
    statement: &PublicStatement,
    payload: &[u8],
) -> Result<DirectVerifierReport, DirectError> {
    validate_backend_statement(statement)?;
    let dimension = statement.generated().dimension();
    let expected_payload =
        maximum_backend_payload_bytes(dimension).ok_or(DirectError::ResourceLimit)?;
    if payload.len() != expected_payload {
        return Err(DirectError::Framing(
            "direct payload length does not match the public dimension".to_owned(),
        ));
    }

    let limits = DecodeLimits {
        max_input_bytes: MAX_BACKEND_PAYLOAD_BYTES,
        max_field_bytes: MAX_BACKEND_PAYLOAD_BYTES,
    };
    let mut input = Reader::new(payload, limits).map_err(framing)?;
    if input
        .read_fixed_bytes(BACKEND_PAYLOAD_MAGIC.len())
        .map_err(framing)?
        != BACKEND_PAYLOAD_MAGIC
    {
        return Err(DirectError::Framing(
            "bad direct backend payload magic".to_owned(),
        ));
    }
    if input.read_u16().map_err(framing)? != BACKEND_PAYLOAD_VERSION
        || input.read_u16().map_err(framing)? != BACKEND_SOLUTION_FRAME
        || input.read_u16().map_err(framing)? != BACKEND_FRAME_VERSION
    {
        return Err(DirectError::UnsupportedVersion);
    }
    let solution_frame_bytes = input.read_u64().map_err(framing)?;
    let count = usize::try_from(input.read_u64().map_err(framing)?)
        .map_err(|_| DirectError::ResourceLimit)?;
    if count != dimension {
        return Err(SolutionError::WrongLength {
            expected: dimension,
            actual: count,
        }
        .into());
    }
    let expected_solution_frame_bytes = 8_u64
        .checked_add(
            u64::try_from(count)
                .map_err(|_| DirectError::ResourceLimit)?
                .checked_mul(8)
                .ok_or(DirectError::ResourceLimit)?,
        )
        .ok_or(DirectError::ResourceLimit)?;
    if solution_frame_bytes != expected_solution_frame_bytes {
        return Err(DirectError::Framing(
            "direct solution frame length does not match its element count".to_owned(),
        ));
    }

    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| DirectError::ResourceLimit)?;
    for _ in 0..count {
        values.push(f64::from_bits(input.read_u64().map_err(framing)?));
    }
    if input.read_u16().map_err(framing)? != BACKEND_FINAL_FRAME
        || input.read_u16().map_err(framing)? != BACKEND_FRAME_VERSION
        || input.read_u64().map_err(framing)? != 0
    {
        return Err(DirectError::Framing(
            "missing canonical final direct payload frame".to_owned(),
        ));
    }
    input.finish().map_err(framing)?;
    let solution = Solution::new(values, dimension)?;
    let relation = evaluate_relation(statement.generated(), solution.as_slice())?;
    Ok(DirectVerifierReport {
        residual: relation.residual,
        rows_visited: relation.rows_visited,
        nonzeros_visited: relation.nonzeros_visited,
        solution_elements_materialized: dimension as u64,
        solution_bytes_materialized: dimension
            .checked_mul(std::mem::size_of::<f64>())
            .ok_or(DirectError::ResourceLimit)?,
    })
}

fn validate_backend_statement(statement: &PublicStatement) -> Result<(), DirectError> {
    if statement.manifest().protocol != ProofProtocol::DirectReferenceV1 {
        return Err(DirectError::WrongProtocol);
    }
    if statement.generated().dimension() as u64 > statement.manifest().max_solution_elements {
        return Err(DirectError::ResourceLimit);
    }
    Ok(())
}

fn validate_solution_values(values: &[f64]) -> Result<(), DirectError> {
    for (index, &value) in values.iter().enumerate() {
        if !value.is_finite() {
            return Err(SolutionError::NonFinite { index }.into());
        }
        if value.to_bits() == (-0.0_f64).to_bits() {
            return Err(SolutionError::NegativeZero { index }.into());
        }
        if value != 0.0 && !value.is_normal() {
            return Err(SolutionError::Subnormal { index }.into());
        }
    }
    Ok(())
}

fn evaluate_relation(
    generated: &GeneratedProblem,
    solution: &[f64],
) -> Result<RelationEvaluation, DirectError> {
    if solution.len() != generated.dimension() {
        return Err(SolutionError::WrongLength {
            expected: generated.dimension(),
            actual: solution.len(),
        }
        .into());
    }
    let mut squared_l2 = 0.0_f64;
    let mut max_abs = 0.0_f64;
    let mut nonzeros_visited = 0_u64;

    for row_index in 0..generated.dimension() {
        let mut ax = 0.0_f64;
        let row = generated
            .row(row_index)
            .ok_or_else(|| DirectError::Framing("compiled generator omitted a row".to_owned()))?;
        for entry in row {
            let product = entry.value.to_f64() * solution[entry.column];
            ax += product;
            nonzeros_visited = nonzeros_visited
                .checked_add(1)
                .ok_or(DirectError::ResourceLimit)?;
        }
        let rhs = generated
            .rhs(row_index)
            .ok_or_else(|| {
                DirectError::Framing("compiled generator omitted an RHS entry".to_owned())
            })?
            .to_f64();
        let residual = ax - rhs;
        if !ax.is_finite() || !residual.is_finite() {
            return Err(DirectError::NonFiniteArithmetic { row: row_index });
        }
        let absolute = residual.abs();
        max_abs = max_abs.max(absolute);
        let square = residual * residual;
        if !square.is_finite() || (residual != 0.0 && square == 0.0) {
            return Err(DirectError::UnrepresentableResidualNorm);
        }
        squared_l2 += square;
        if !squared_l2.is_finite() {
            return Err(DirectError::UnrepresentableResidualNorm);
        }
    }
    let l2 = squared_l2.sqrt();
    let mean_square = squared_l2 / generated.dimension() as f64;
    if squared_l2 != 0.0 && mean_square == 0.0 {
        return Err(DirectError::UnrepresentableResidualNorm);
    }
    let rms = mean_square.sqrt();
    let residual = ResidualMetrics {
        squared_l2,
        l2,
        rms,
        max_abs,
    };
    residual.validate()?;
    Ok(RelationEvaluation {
        residual,
        rows_visited: generated.dimension() as u64,
        nonzeros_visited,
    })
}

impl DirectArtifact {
    pub fn create(
        problem: &FinalizedProblem,
        manifest: &ValidationManifest,
        challenge: Option<&SignedChallenge>,
        solution: &Solution,
    ) -> Result<Vec<u8>, DirectError> {
        manifest.validate()?;
        if manifest.protocol != ProofProtocol::DirectReferenceV1 {
            return Err(DirectError::WrongProtocol);
        }
        if let Some(challenge) = challenge {
            challenge
                .payload
                .validate()
                .map_err(|error| DirectError::Challenge(error.to_string()))?;
        }
        validate_problem_challenge(problem, challenge)?;
        problem.validate()?;
        let dimension =
            usize::try_from(problem.dimension()).map_err(|_| DirectError::ResourceLimit)?;
        if dimension as u64 > manifest.max_solution_elements {
            return Err(DirectError::ResourceLimit);
        }
        if solution.as_slice().len() != dimension {
            return Err(SolutionError::WrongLength {
                expected: dimension,
                actual: solution.as_slice().len(),
            }
            .into());
        }

        let application_header = challenge
            .map(SignedChallenge::to_canonical_bytes)
            .unwrap_or_default();
        let problem_json = serde_json::to_vec(problem)?;
        let manifest_json = serde_json::to_vec(manifest)?;
        let mut context = Encoder::with_capacity(problem_json.len() + manifest_json.len() + 16);
        context.write_bytes(&problem_json);
        context.write_bytes(&manifest_json);
        let context = context.into_bytes();
        if application_header.len() > MAX_APPLICATION_HEADER_BYTES
            || context.len() > MAX_PUBLIC_CONTEXT_BYTES
        {
            return Err(DirectError::ResourceLimit);
        }

        let payload_len = 8_usize
            .checked_add(
                solution
                    .as_slice()
                    .len()
                    .checked_mul(8)
                    .ok_or(DirectError::ResourceLimit)?,
            )
            .ok_or(DirectError::ResourceLimit)?;
        if payload_len > MAX_PROOF_BYTES {
            return Err(DirectError::ResourceLimit);
        }
        let mut output =
            Encoder::with_capacity(64 + application_header.len() + context.len() + payload_len);
        output.write_fixed_bytes(MAGIC);
        output.write_u16(CONTAINER_VERSION);
        output.write_u16(DIRECT_PROOF_KIND);
        output.write_u16(DIRECT_PROOF_VERSION);
        output.write_u16(NO_TRANSCRIPT_SUITE);
        output.write_u32(if challenge.is_some() {
            FLAG_SIGNED_CHALLENGE
        } else {
            0
        });
        output.write_bytes(&application_header);
        output.write_bytes(&context);
        output.write_u16(SOLUTION_FRAME);
        output.write_u16(FRAME_VERSION);
        output.write_u64(payload_len as u64);
        output.write_u64(solution.as_slice().len() as u64);
        for value in solution.as_slice() {
            output.write_u64(value.to_bits());
        }
        output.write_u16(FINAL_FRAME);
        output.write_u16(FRAME_VERSION);
        output.write_u64(0);
        let bytes = output.into_bytes();
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(DirectError::ResourceLimit);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DirectError> {
        Self::preparse(bytes)?.decode()
    }

    /// Decodes with an application-supplied cap applied before solution allocation.
    pub fn from_bytes_with_solution_limit(
        bytes: &[u8],
        maximum_solution_elements: u64,
    ) -> Result<Self, DirectError> {
        Self::preparse_with_solution_limit(bytes, maximum_solution_elements)?.decode()
    }

    /// Validates the envelope while borrowing, rather than allocating, `x`.
    pub fn preparse(bytes: &[u8]) -> Result<DirectArtifactPrelude<'_>, DirectError> {
        Self::preparse_with_solution_limit(bytes, ssv_service_protocol::MAX_SOLUTION_ELEMENTS_LIMIT)
    }

    /// Validates the envelope with a service cap applied before allocating `x`.
    pub fn preparse_with_solution_limit(
        bytes: &[u8],
        maximum_solution_elements: u64,
    ) -> Result<DirectArtifactPrelude<'_>, DirectError> {
        DirectArtifactPrelude::parse(bytes, maximum_solution_elements)
    }

    #[must_use]
    pub fn problem(&self) -> &FinalizedProblem {
        &self.problem
    }

    #[must_use]
    pub fn manifest(&self) -> &ValidationManifest {
        &self.manifest
    }

    #[must_use]
    pub fn challenge(&self) -> Option<&SignedChallenge> {
        self.challenge.as_ref()
    }

    pub fn summary(&self) -> Result<DirectArtifactSummary, DirectError> {
        Ok(DirectArtifactSummary {
            proof_digest: self.digest,
            encoded_len: self.encoded_len,
            problem_digest: self.problem_digest,
            validation_manifest_digest: self.validation_manifest_digest,
            solution_elements: self.solution.as_slice().len(),
            has_signed_challenge: self.challenge.is_some(),
            protocol: self.manifest.protocol,
        })
    }

    /// Recomputes `Ax-b` in the generator's canonical row/column order.
    pub fn verify_relation(&self) -> Result<ValidatedDirectOutput, DirectError> {
        let relation = evaluate_relation(&self.generated, self.solution.as_slice())?;
        Ok(ValidatedDirectOutput {
            problem_digest: self.problem_digest,
            validation_manifest_digest: self.validation_manifest_digest,
            proof_digest: self.digest,
            residual: relation.residual,
            rows_visited: relation.rows_visited,
            nonzeros_visited: relation.nonzeros_visited,
        })
    }
}

impl<'a> DirectArtifactPrelude<'a> {
    fn parse(bytes: &'a [u8], maximum_solution_elements: u64) -> Result<Self, DirectError> {
        if maximum_solution_elements == 0
            || maximum_solution_elements > ssv_service_protocol::MAX_SOLUTION_ELEMENTS_LIMIT
        {
            return Err(DirectError::ResourceLimit);
        }
        let limits = DecodeLimits {
            max_input_bytes: MAX_PROOF_BYTES,
            max_field_bytes: MAX_PROOF_BYTES,
        };
        let mut input = Reader::new(bytes, limits).map_err(framing)?;
        if input.read_fixed_bytes(MAGIC.len()).map_err(framing)? != MAGIC {
            return Err(DirectError::Framing("bad proof magic".to_owned()));
        }
        let container_version = input.read_u16().map_err(framing)?;
        let proof_kind = input.read_u16().map_err(framing)?;
        let proof_version = input.read_u16().map_err(framing)?;
        let transcript_suite = input.read_u16().map_err(framing)?;
        let flags = input.read_u32().map_err(framing)?;
        if container_version != CONTAINER_VERSION
            || proof_kind != DIRECT_PROOF_KIND
            || proof_version != DIRECT_PROOF_VERSION
            || transcript_suite != NO_TRANSCRIPT_SUITE
            || flags & !FLAG_SIGNED_CHALLENGE != 0
        {
            return Err(DirectError::UnsupportedVersion);
        }
        let application_header = input.read_bytes().map_err(framing)?;
        if application_header.len() > MAX_APPLICATION_HEADER_BYTES {
            return Err(DirectError::ResourceLimit);
        }
        let has_header = !application_header.is_empty();
        if has_header != (flags & FLAG_SIGNED_CHALLENGE != 0) {
            return Err(DirectError::HeaderFlagMismatch);
        }
        let challenge = if has_header {
            Some(
                SignedChallenge::from_canonical_bytes(application_header)
                    .map_err(|error| DirectError::Challenge(error.to_string()))?,
            )
        } else {
            None
        };

        let context = input.read_bytes().map_err(framing)?;
        if context.len() > MAX_PUBLIC_CONTEXT_BYTES {
            return Err(DirectError::ResourceLimit);
        }
        let context_limits = DecodeLimits {
            max_input_bytes: MAX_PUBLIC_CONTEXT_BYTES,
            max_field_bytes: MAX_PUBLIC_CONTEXT_BYTES,
        };
        let mut context_input = Reader::new(context, context_limits).map_err(framing)?;
        let problem: FinalizedProblem =
            serde_json::from_slice(context_input.read_bytes().map_err(framing)?)?;
        let manifest: ValidationManifest =
            serde_json::from_slice(context_input.read_bytes().map_err(framing)?)?;
        context_input.finish().map_err(framing)?;
        problem.validate()?;
        validate_problem_challenge(&problem, challenge.as_ref())?;
        manifest.validate()?;
        if manifest.protocol != ProofProtocol::DirectReferenceV1 {
            return Err(DirectError::WrongProtocol);
        }
        if manifest.max_solution_elements > maximum_solution_elements {
            return Err(DirectError::ResourceLimit);
        }
        let dimension =
            usize::try_from(problem.dimension()).map_err(|_| DirectError::ResourceLimit)?;
        if problem.dimension() > manifest.max_solution_elements {
            return Err(DirectError::ResourceLimit);
        }

        let frame_tag = input.read_u16().map_err(framing)?;
        let frame_version = input.read_u16().map_err(framing)?;
        let payload_len = input.read_u64().map_err(framing)?;
        if frame_tag != SOLUTION_FRAME || frame_version != FRAME_VERSION {
            return Err(DirectError::UnsupportedVersion);
        }
        let count = input.read_u64().map_err(framing)?;
        let count = usize::try_from(count).map_err(|_| DirectError::ResourceLimit)?;
        if count != dimension || count as u64 > manifest.max_solution_elements {
            return Err(SolutionError::WrongLength {
                expected: dimension,
                actual: count,
            }
            .into());
        }
        let expected_payload = 8_u64
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| DirectError::ResourceLimit)?
                    .checked_mul(8)
                    .ok_or(DirectError::ResourceLimit)?,
            )
            .ok_or(DirectError::ResourceLimit)?;
        if payload_len != expected_payload {
            return Err(DirectError::Framing(
                "solution frame length does not match its element count".to_owned(),
            ));
        }
        let solution_payload_len = count.checked_mul(8).ok_or(DirectError::ResourceLimit)?;
        if solution_payload_len > MAX_PROOF_BYTES {
            return Err(DirectError::ResourceLimit);
        }
        let solution_payload = input
            .read_fixed_bytes(solution_payload_len)
            .map_err(framing)?;
        let final_tag = input.read_u16().map_err(framing)?;
        let final_version = input.read_u16().map_err(framing)?;
        let final_len = input.read_u64().map_err(framing)?;
        if final_tag != FINAL_FRAME || final_version != FRAME_VERSION || final_len != 0 {
            return Err(DirectError::Framing(
                "missing canonical final proof frame".to_owned(),
            ));
        }
        input.finish().map_err(framing)?;

        Ok(DirectArtifactPrelude {
            problem,
            manifest,
            challenge,
            solution_payload,
            encoded: bytes,
            solution_elements: count,
        })
    }

    #[must_use]
    pub fn problem(&self) -> &FinalizedProblem {
        &self.problem
    }

    #[must_use]
    pub fn manifest(&self) -> &ValidationManifest {
        &self.manifest
    }

    #[must_use]
    pub fn challenge(&self) -> Option<&SignedChallenge> {
        self.challenge.as_ref()
    }

    #[must_use]
    pub const fn solution_elements(&self) -> usize {
        self.solution_elements
    }

    /// Computes public identities without allocating or validating `x`.
    pub fn summary(&self) -> Result<DirectArtifactSummary, DirectError> {
        Ok(DirectArtifactSummary {
            proof_digest: domain_separated_digest(PROOF_DIGEST_DOMAIN, self.encoded),
            encoded_len: self.encoded.len(),
            problem_digest: Digest::from_bytes(self.problem.digest()?.into_bytes()),
            validation_manifest_digest: self.manifest.digest()?,
            solution_elements: self.solution_elements,
            has_signed_challenge: self.challenge.is_some(),
            protocol: self.manifest.protocol,
        })
    }

    /// Allocates and validates the solution only after callers authenticate metadata.
    pub fn decode(self) -> Result<DirectArtifact, DirectError> {
        let generated = self.problem.compile()?;
        let problem_digest = Digest::from_bytes(generated.problem_digest().into_bytes());
        let validation_manifest_digest = self.manifest.digest()?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(self.solution_elements)
            .map_err(|_| DirectError::ResourceLimit)?;
        for chunk in self.solution_payload.chunks_exact(8) {
            let bits = u64::from_be_bytes(
                <[u8; 8]>::try_from(chunk).expect("preparsed solution payload has 8-byte chunks"),
            );
            values.push(f64::from_bits(bits));
        }
        let solution = Solution::new(values, self.solution_elements)?;
        Ok(DirectArtifact {
            problem: self.problem,
            generated,
            manifest: self.manifest,
            challenge: self.challenge,
            solution,
            problem_digest,
            validation_manifest_digest,
            digest: domain_separated_digest(PROOF_DIGEST_DOMAIN, self.encoded),
            encoded_len: self.encoded.len(),
        })
    }
}

fn framing(error: impl std::fmt::Display) -> DirectError {
    DirectError::Framing(error.to_string())
}

fn validate_problem_challenge(
    problem: &FinalizedProblem,
    challenge: Option<&SignedChallenge>,
) -> Result<(), DirectError> {
    match (problem.randomness(), challenge) {
        (FinalizedRandomness::LiteralV1 { .. }, None) => Ok(()),
        (FinalizedRandomness::ChallengeDerivedV1 { .. }, Some(challenge)) => {
            let template_digest = Digest::from_bytes(problem.template().digest()?.into_bytes());
            if challenge.payload.problem_template_digest != template_digest {
                return Err(DirectError::ProblemChallengeMismatch);
            }
            problem
                .verify_challenge_context(&challenge.payload_canonical_bytes())
                .map_err(|_| DirectError::ProblemChallengeMismatch)
        }
        _ => Err(DirectError::ProblemChallengeMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssv_problem::{
        BoundaryRule, DiagonalConstruction, FinalizedProblem, InstanceSeed, MatrixSpec,
        OffDiagonalValues, ProblemTemplate, RequestedOutput, RhsSpec, TemplateRandomness,
        TemplateSchema,
    };
    use ssv_validation::{ArtifactPrelude, encode_artifact};

    fn two_by_two_zero_rhs(fractional_bits: u8) -> FinalizedProblem {
        ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness: TemplateRandomness::LiteralV1 {
                seed: InstanceSeed::from_bytes([1; 32]),
            },
            matrix: MatrixSpec::SeededSymmetricTridiagonalV1 {
                dimension: 2,
                boundary: BoundaryRule::TruncateV1,
                off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                    period_bits: 0,
                    fractional_bits,
                    minimum_magnitude_mantissa: 1,
                    maximum_magnitude_mantissa: 1,
                },
                diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 { margin_mantissa: 1 },
            },
            rhs: RhsSpec::SeededPeriodicDyadicV1 {
                period_bits: 0,
                fractional_bits,
                minimum_mantissa: 0,
                maximum_mantissa: 0,
            },
            requested_outputs: vec![RequestedOutput::SquaredL2ResidualV1],
        }
        .finalize_literal()
        .unwrap()
    }

    #[test]
    fn bad_magic_and_trailing_bytes_are_rejected_without_panics() {
        assert!(DirectArtifact::from_bytes(b"not a proof").is_err());

        // A complete integration round trip lives in tests/e2e.rs where the
        // concrete problem fixture is shared with the CLI workflow.
    }

    #[test]
    fn nonzero_norm_that_would_square_to_zero_is_rejected() {
        let problem = two_by_two_zero_rhs(52);
        let solution = Solution::new(vec![f64::MIN_POSITIVE, 0.0], 2).unwrap();
        let manifest = ValidationManifest {
            max_solution_elements: 2,
            ..ValidationManifest::default()
        };
        let bytes = DirectArtifact::create(&problem, &manifest, None, &solution).unwrap();
        assert!(bytes.len() <= maximum_artifact_bytes(2).unwrap());
        assert!(
            maximum_artifact_bytes(ssv_service_protocol::MAX_SOLUTION_ELEMENTS_LIMIT).is_none()
        );
        let prelude = DirectArtifact::preparse(&bytes).unwrap();
        assert_eq!(prelude.solution_elements(), 2);
        assert!(!format!("{prelude:?}").contains("solution_payload"));
        assert!(matches!(
            prelude.decode().unwrap().verify_relation(),
            Err(DirectError::UnrepresentableResidualNorm)
        ));
    }

    #[test]
    fn nonzero_residual_metric_bits_are_frozen() {
        let problem = two_by_two_zero_rhs(0);
        let solution = Solution::new(vec![1.0, 0.0], 2).unwrap();
        let manifest = ValidationManifest {
            max_solution_elements: 2,
            ..ValidationManifest::default()
        };
        let bytes = DirectArtifact::create(&problem, &manifest, None, &solution).unwrap();
        let prelude = DirectArtifact::preparse(&bytes).unwrap();
        assert_eq!(prelude.summary().unwrap().solution_elements, 2);
        let output = prelude.decode().unwrap().verify_relation().unwrap();
        assert_eq!(output.residual.squared_l2.to_bits(), 5.0_f64.to_bits());
        assert_eq!(output.residual.l2.to_bits(), 0x4001_e377_9b97_f4a8);
        assert_eq!(output.residual.rms.to_bits(), 0x3ff9_4c58_3ada_5b53);
        assert_eq!(output.residual.max_abs.to_bits(), 2.0_f64.to_bits());
    }

    #[test]
    fn common_backend_round_trip_matches_legacy_relation_oracle() {
        let problem = two_by_two_zero_rhs(0);
        let solution = Solution::new(vec![1.0, 0.0], 2).unwrap();
        let manifest = ValidationManifest {
            max_solution_elements: 2,
            ..ValidationManifest::default()
        };
        let statement = PublicStatement::new(problem.clone(), manifest.clone(), None).unwrap();
        let (payload, prover_report) =
            <DirectBackend as ReferenceValidationBackend>::prove(&statement, &solution, &())
                .unwrap();
        assert_eq!(prover_report.solution_elements, 2);
        assert_eq!(prover_report.payload_bytes, payload.len());
        assert_eq!(payload.len(), maximum_backend_payload_bytes(2).unwrap());

        let artifact = encode_artifact(&statement, &payload).unwrap();
        let prelude = ArtifactPrelude::parse(&artifact).unwrap();
        let report = prelude.verify_reference_with::<DirectBackend>().unwrap();
        let legacy = DirectArtifact::from_bytes(
            &DirectArtifact::create(&problem, &manifest, None, &solution).unwrap(),
        )
        .unwrap()
        .verify_relation()
        .unwrap();
        assert_eq!(report.residual, legacy.residual);
        assert_eq!(report.rows_visited, 2);
        assert_eq!(report.nonzeros_visited, 4);
        assert_eq!(report.solution_elements_materialized, 2);
        assert_eq!(report.solution_bytes_materialized, 16);
    }

    #[test]
    fn common_backend_rejects_wrong_protocol_and_solution_length() {
        let problem = two_by_two_zero_rhs(0);
        let wrong_manifest = ValidationManifest {
            protocol: ProofProtocol::WhirField192L2V4,
            max_solution_elements: 3,
            ..ValidationManifest::default()
        };
        let wrong_statement = PublicStatement::new(problem.clone(), wrong_manifest, None).unwrap();
        let solution = Solution::new(vec![0.0, 0.0], 2).unwrap();
        assert!(matches!(
            <DirectBackend as ReferenceValidationBackend>::prove(&wrong_statement, &solution, &()),
            Err(DirectError::WrongProtocol)
        ));

        let statement = PublicStatement::new(
            problem,
            ValidationManifest {
                max_solution_elements: 3,
                ..ValidationManifest::default()
            },
            None,
        )
        .unwrap();
        let wrong_length = Solution::new(vec![0.0, 0.0, 0.0], 3).unwrap();
        assert!(matches!(
            <DirectBackend as ReferenceValidationBackend>::prove(&statement, &wrong_length, &()),
            Err(DirectError::Solution(SolutionError::WrongLength { .. }))
        ));
    }

    #[test]
    fn common_backend_payload_is_strict_and_bounded() {
        let statement = PublicStatement::new(
            two_by_two_zero_rhs(0),
            ValidationManifest {
                max_solution_elements: 2,
                ..ValidationManifest::default()
            },
            None,
        )
        .unwrap();
        let solution = Solution::new(vec![1.0, 0.0], 2).unwrap();
        let (payload, _) =
            <DirectBackend as ReferenceValidationBackend>::prove(&statement, &solution, &())
                .unwrap();

        for end in 0..payload.len() {
            assert!(verify_backend_payload(&statement, &payload[..end]).is_err());
        }

        let mut bad_magic = payload.clone();
        bad_magic[0] ^= 1;
        assert!(verify_backend_payload(&statement, &bad_magic).is_err());

        let mut bad_version = payload.clone();
        bad_version[9] ^= 1;
        assert!(matches!(
            verify_backend_payload(&statement, &bad_version),
            Err(DirectError::UnsupportedVersion)
        ));

        let mut bad_count = payload.clone();
        bad_count[22..30].copy_from_slice(&3_u64.to_be_bytes());
        assert!(matches!(
            verify_backend_payload(&statement, &bad_count),
            Err(DirectError::Solution(SolutionError::WrongLength { .. }))
        ));

        let mut non_finite = payload.clone();
        non_finite[30..38].copy_from_slice(&f64::NAN.to_bits().to_be_bytes());
        assert!(matches!(
            verify_backend_payload(&statement, &non_finite),
            Err(DirectError::Solution(SolutionError::NonFinite { index: 0 }))
        ));

        let mut bad_final = payload.clone();
        let final_offset = payload.len() - 12;
        bad_final[final_offset] ^= 1;
        assert!(verify_backend_payload(&statement, &bad_final).is_err());

        let mut trailing = payload;
        trailing.push(0);
        assert!(verify_backend_payload(&statement, &trailing).is_err());

        let maximum_count = (MAX_BACKEND_PAYLOAD_BYTES - BACKEND_FIXED_BYTES) / 8;
        assert!(maximum_backend_payload_bytes(maximum_count).is_some());
        assert!(maximum_backend_payload_bytes(maximum_count + 1).is_none());
    }
}
