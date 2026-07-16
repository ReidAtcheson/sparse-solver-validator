//! Complete experimental binary64 validation backend.
//!
//! This module composes the reusable primitives in this crate into the three-
//! sumcheck, coefficient-aligned unit-circle protocol described in the project
//! design.  Sparse rows are available only while proving.  Verification is
//! intentionally expressed against [`VerifierStatement`] and its registered
//! public-MLE capability, so adding a matrix family cannot add a family match
//! to this backend.
//!
//! The algebra and transcript order are derived from
//! `fast-validation/src/protocol.rs` at research revision
//! `be8b67b74da54d162df2e6e0a9d813779959bb60`.  The implementation here
//! separates statement binding, precommitment framing, witness preparation,
//! proof composition, and query verification so future metric validators can
//! reuse the lower layers without cloning a whole validator.

use std::collections::BTreeSet;

use ssv_canonical::{DecodeLimits, Digest, Encoder, Reader, domain_separated_digest};
use ssv_problem::{
    BooleanCoordinateOrder, GeneratedProblem, MleEvaluationError, PublicEvaluationMetadata,
    SuccinctPublicEvaluator,
};
use ssv_relation::{FixedWitness, RelationError};
use ssv_service_protocol::{
    MAX_COMMITMENT_CHALLENGE_BYTES, ProofProtocol, ProtocolError, SignedCommitmentChallenge,
};
use ssv_solution::Solution;
use ssv_validation::{PrecommitBackend, PublicStatement, ValidationBackend, VerifierStatement};
use thiserror::Error;

use crate::float_contract::{
    FloatContractError, canonical_bits, canonicalize_arithmetic, canonicalize_source,
    decode_canonical_bits, i128_vector_digest, vector_digest,
};
use crate::merkle::{
    ComplexMultiProof, MerkleError, MerkleRoot, streaming_complex_root,
    streaming_complex_root_and_multiproof_iter, streaming_complex_root_iter,
    verify_complex_multiproof,
};
use crate::score::{
    DefectAccumulator, FastValidationScore, POLICY_2, Policy2, conditional_miss_probabilities,
};
use crate::sumcheck::{
    ProductSumcheckProof, QuadraticBernstein, SumcheckError, product_sum, prove_product_owned,
    verify_product, verify_product_endpoint,
};
use crate::transcript::{Transcript, TranscriptError};
use crate::unit_circle::{ComplexValue, UnitCircleCodeword, UnitCircleError, fold_pair_at_index};

const PRECOMMIT_MAGIC: &[u8; 8] = b"SSVFCM\0\0";
const PRECOMMIT_VERSION: u16 = 3;
const PAYLOAD_MAGIC: &[u8; 8] = b"SSVFST\0\0";
const PAYLOAD_VERSION: u16 = 3;
const PROOF_VERSION: u16 = 3;
const FINAL_FRAME: u16 = u16::MAX;
const PRECOMMIT_DIGEST_DOMAIN: &[u8] = b"sparse-solve/fast-precommitment/v3";
const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"sparse-solve/fast-backend-payload/v3";
const OFFLINE_NONCE_DOMAIN: &[u8] = b"sparse-solve/fast-offline-fiat-shamir-nonce/v1";
const PROTOCOL_LABEL: &[u8] = b"sparse-solve/fast/coefficient-unit-circle-linear-opening/v3";
const PUBLIC_EVALUATOR_ID: &[u8] = b"ssv-problem/succinct-public-evaluator/msb-mle/v1";
const FLOAT_CONTRACT: &[u8] =
    b"binary64/rne/no-fma/reject-nan-inf-negzero-subnormal/unit-circle-coeff/v2";
const CODE_BASIS: &[u8] =
    b"packed-[x||R]/msb-mle/bit-reversed-monomial-coefficients/unit-circle-rate-1/2";
const ORACLE_TREE_LABEL: &[u8] = b"ssv-fast/v3/packed-unit-circle-oracle";
const MAX_PRECOMMITMENT_BYTES: usize = 4096;
const MAX_PROOF_BYTES: usize = ssv_validation::MAX_SUCCINCT_PAYLOAD_BYTES;

/// Explicit source of the challenge issued after the packed oracle is fixed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FastNonceMode {
    /// A service records the precommitment and signs fresh entropy and time.
    ExternalSigned,
    /// The initial nonce is derived from the precommitment itself.  This mode
    /// has no external timestamp and offers weaker practical grinding defense.
    OfflineFiatShamir,
}

impl FastNonceMode {
    const fn wire_id(self) -> u16 {
        match self {
            Self::ExternalSigned => 1,
            Self::OfflineFiatShamir => 2,
        }
    }

    const fn from_wire_id(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::ExternalSigned),
            2 => Some(Self::OfflineFiatShamir),
            _ => None,
        }
    }
}

/// Digests of the exact and binary64 sources used to create the packed oracle.
///
/// They are timestamp/linkage metadata.  Soundness of the query-only verifier
/// comes from the packed root and the linear opening, not from trusting these
/// digest labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FastSourceDigests {
    pub exact_witness: [u8; 32],
    pub binary64_solution: [u8; 32],
    pub binary64_residual: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EvaluatorBinding {
    logical_dimension: usize,
    padded_dimension: usize,
    variables: usize,
    matrix_period_terms: usize,
    rhs_period_terms: usize,
    matrix_fractional_bits: u8,
    rhs_fractional_bits: u8,
    maximum_absolute_row_sum_mantissa: u64,
    maximum_absolute_rhs_mantissa: u64,
}

impl EvaluatorBinding {
    fn from_metadata(metadata: PublicEvaluationMetadata) -> Result<Self, FastError> {
        if metadata.domain.coordinate_order != BooleanCoordinateOrder::MostSignificantFirst {
            return Err(FastError::TranscriptShape);
        }
        Ok(Self {
            logical_dimension: metadata.domain.logical_dimension,
            padded_dimension: metadata.domain.padded_dimension,
            variables: metadata.domain.variables,
            matrix_period_terms: metadata.matrix_period_terms,
            rhs_period_terms: metadata.rhs_period_terms,
            matrix_fractional_bits: metadata.exact_bounds.matrix_fractional_bits,
            rhs_fractional_bits: metadata.exact_bounds.rhs_fractional_bits,
            maximum_absolute_row_sum_mantissa: metadata
                .exact_bounds
                .maximum_absolute_row_sum_mantissa,
            maximum_absolute_rhs_mantissa: metadata.exact_bounds.maximum_absolute_rhs_mantissa,
        })
    }

    fn encode(&self, output: &mut Encoder) -> Result<(), FastError> {
        write_usize(output, self.logical_dimension)?;
        write_usize(output, self.padded_dimension)?;
        write_usize(output, self.variables)?;
        output.write_u16(1); // MostSignificantFirst
        write_usize(output, self.matrix_period_terms)?;
        write_usize(output, self.rhs_period_terms)?;
        output.write_u8(self.matrix_fractional_bits);
        output.write_u8(self.rhs_fractional_bits);
        output.write_u64(self.maximum_absolute_row_sum_mantissa);
        output.write_u64(self.maximum_absolute_rhs_mantissa);
        Ok(())
    }

    fn decode(input: &mut Reader<'_>) -> Result<Self, FastError> {
        let result = Self {
            logical_dimension: read_usize(input)?,
            padded_dimension: read_usize(input)?,
            variables: read_usize(input)?,
            matrix_period_terms: {
                if input.read_u16().map_err(framing)? != 1 {
                    return Err(FastError::UnsupportedVersion);
                }
                read_usize(input)?
            },
            rhs_period_terms: read_usize(input)?,
            matrix_fractional_bits: input.read_u8().map_err(framing)?,
            rhs_fractional_bits: input.read_u8().map_err(framing)?,
            maximum_absolute_row_sum_mantissa: input.read_u64().map_err(framing)?,
            maximum_absolute_rhs_mantissa: input.read_u64().map_err(framing)?,
        };
        if result.logical_dimension < 2
            || result.logical_dimension.checked_next_power_of_two() != Some(result.padded_dimension)
            || result.variables != result.padded_dimension.ilog2() as usize
            || result.matrix_period_terms == 0
            || result.rhs_period_terms == 0
        {
            return Err(FastError::TranscriptShape);
        }
        Ok(result)
    }
}

/// Canonical commitment fixed before the first algebraic challenge exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FastPrecommitment {
    nonce_mode: FastNonceMode,
    statement_digest: Digest,
    problem_digest: Digest,
    manifest_digest: Digest,
    evaluator: EvaluatorBinding,
    packed_source_len: usize,
    polynomial_degree: usize,
    codeword_len: usize,
    sources: FastSourceDigests,
    packed_codeword_root: MerkleRoot,
}

impl FastPrecommitment {
    #[must_use]
    pub const fn nonce_mode(&self) -> FastNonceMode {
        self.nonce_mode
    }

    #[must_use]
    pub const fn logical_len(&self) -> usize {
        self.evaluator.logical_dimension
    }

    #[must_use]
    pub const fn codeword_len(&self) -> usize {
        self.codeword_len
    }

    #[must_use]
    pub const fn source_digests(&self) -> FastSourceDigests {
        self.sources
    }

    #[must_use]
    pub const fn packed_codeword_root(&self) -> MerkleRoot {
        self.packed_codeword_root
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        domain_separated_digest(PRECOMMIT_DIGEST_DOMAIN, &self.to_bytes())
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("validated precommitment dimensions always fit the u64 wire format")
    }

    fn try_to_bytes(&self) -> Result<Vec<u8>, FastError> {
        let policy = POLICY_2.transcript_parameters();
        let mut output = Encoder::with_capacity(384);
        output.write_fixed_bytes(PRECOMMIT_MAGIC);
        output.write_u16(PRECOMMIT_VERSION);
        output.write_u16(ProofProtocol::FastBinary64UnitCircleV2.wire_id());
        output.write_u16(self.nonce_mode.wire_id());
        output.write_u16(policy.policy_id);
        output.write_u64(policy.numeric_absolute_bits);
        output.write_u64(policy.numeric_relative_bits);
        output.write_u64(policy.fold_absolute_bits);
        output.write_u64(policy.fold_relative_bits);
        output.write_u64(policy.proximity_query_target);
        output.write_digest(&self.statement_digest);
        output.write_digest(&self.problem_digest);
        output.write_digest(&self.manifest_digest);
        output.write_bytes(PUBLIC_EVALUATOR_ID);
        output.write_bytes(CODE_BASIS);
        output.write_bytes(FLOAT_CONTRACT);
        self.evaluator.encode(&mut output)?;
        write_usize(&mut output, self.packed_source_len)?;
        write_usize(&mut output, self.polynomial_degree)?;
        write_usize(&mut output, self.codeword_len)?;
        output.write_fixed_bytes(&self.sources.exact_witness);
        output.write_fixed_bytes(&self.sources.binary64_solution);
        output.write_fixed_bytes(&self.sources.binary64_residual);
        output.write_fixed_bytes(&self.packed_codeword_root);
        output.write_u16(FINAL_FRAME);
        output.write_u16(PRECOMMIT_VERSION);
        Ok(output.into_bytes())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FastError> {
        let limits = DecodeLimits::new(MAX_PRECOMMITMENT_BYTES, MAX_PRECOMMITMENT_BYTES);
        let mut input = Reader::new(bytes, limits).map_err(framing)?;
        if input
            .read_fixed_bytes(PRECOMMIT_MAGIC.len())
            .map_err(framing)?
            != PRECOMMIT_MAGIC
        {
            return Err(FastError::BadMagic);
        }
        if input.read_u16().map_err(framing)? != PRECOMMIT_VERSION
            || input.read_u16().map_err(framing)?
                != ProofProtocol::FastBinary64UnitCircleV2.wire_id()
        {
            return Err(FastError::UnsupportedVersion);
        }
        let nonce_mode = FastNonceMode::from_wire_id(input.read_u16().map_err(framing)?)
            .ok_or(FastError::UnsupportedVersion)?;
        let expected = POLICY_2.transcript_parameters();
        let policy = (
            input.read_u16().map_err(framing)?,
            input.read_u64().map_err(framing)?,
            input.read_u64().map_err(framing)?,
            input.read_u64().map_err(framing)?,
            input.read_u64().map_err(framing)?,
            input.read_u64().map_err(framing)?,
        );
        if policy
            != (
                expected.policy_id,
                expected.numeric_absolute_bits,
                expected.numeric_relative_bits,
                expected.fold_absolute_bits,
                expected.fold_relative_bits,
                expected.proximity_query_target,
            )
        {
            return Err(FastError::PolicyMismatch);
        }
        let statement_digest = input.read_digest().map_err(framing)?;
        let problem_digest = input.read_digest().map_err(framing)?;
        let manifest_digest = input.read_digest().map_err(framing)?;
        if input.read_bytes().map_err(framing)? != PUBLIC_EVALUATOR_ID {
            return Err(FastError::EvaluatorMismatch);
        }
        if input.read_bytes().map_err(framing)? != CODE_BASIS
            || input.read_bytes().map_err(framing)? != FLOAT_CONTRACT
        {
            return Err(FastError::UnsupportedVersion);
        }
        let evaluator = EvaluatorBinding::decode(&mut input)?;
        let packed_source_len = read_usize(&mut input)?;
        let polynomial_degree = read_usize(&mut input)?;
        let codeword_len = read_usize(&mut input)?;
        let sources = FastSourceDigests {
            exact_witness: input.read_array().map_err(framing)?,
            binary64_solution: input.read_array().map_err(framing)?,
            binary64_residual: input.read_array().map_err(framing)?,
        };
        let packed_codeword_root = input.read_array().map_err(framing)?;
        if input.read_u16().map_err(framing)? != FINAL_FRAME
            || input.read_u16().map_err(framing)? != PRECOMMIT_VERSION
        {
            return Err(FastError::UnsupportedVersion);
        }
        input.finish().map_err(framing)?;
        let expected_source_len = evaluator
            .padded_dimension
            .checked_mul(2)
            .ok_or(FastError::ResourceLimit)?;
        if packed_source_len != expected_source_len
            || polynomial_degree != packed_source_len - 1
            || codeword_len
                != packed_source_len
                    .checked_mul(2)
                    .ok_or(FastError::ResourceLimit)?
        {
            return Err(FastError::TranscriptShape);
        }
        Ok(Self {
            nonce_mode,
            statement_digest,
            problem_digest,
            manifest_digest,
            evaluator,
            packed_source_len,
            polynomial_degree,
            codeword_len,
            sources,
            packed_codeword_root,
        })
    }
}

/// Post-commit context supplied to the prover.
#[derive(Clone, Debug)]
pub enum FastProverContext {
    ExternalSigned {
        commitment: FastPrecommitment,
        challenge: Box<SignedCommitmentChallenge>,
    },
    OfflineFiatShamir {
        commitment: FastPrecommitment,
    },
}

impl FastProverContext {
    #[must_use]
    pub fn external_signed(
        commitment: FastPrecommitment,
        challenge: SignedCommitmentChallenge,
    ) -> Self {
        Self::ExternalSigned {
            commitment,
            challenge: Box::new(challenge),
        }
    }

    #[must_use]
    pub fn offline_fiat_shamir(commitment: FastPrecommitment) -> Self {
        Self::OfflineFiatShamir { commitment }
    }

    const fn commitment(&self) -> &FastPrecommitment {
        match self {
            Self::ExternalSigned { commitment, .. } | Self::OfflineFiatShamir { commitment } => {
                commitment
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct FastCommitmentReport {
    pub precommitment_digest: Digest,
    pub sources: FastSourceDigests,
    pub packed_codeword_root: MerkleRoot,
    pub logical_len: usize,
    pub codeword_len: usize,
    pub nonce_mode: FastNonceMode,
}

#[derive(Clone, Debug)]
pub struct FastProverReport {
    pub payload_digest: Digest,
    pub precommitment_digest: Digest,
    pub sources: FastSourceDigests,
    pub packed_codeword_root: MerkleRoot,
    pub logical_len: usize,
    pub codeword_len: usize,
    pub proximity_queries_per_round: u32,
    pub residual_squared_l2: f64,
    pub payload_bytes: usize,
    pub rows_scanned: u64,
    pub nonzeros_scanned: u64,
}

/// Cheap, bounded authentication preflight for hosted validators.
///
/// This validates strict outer framing, the complete precommitment, nonce-mode
/// consistency, public-statement binding, and commitment-challenge linkage. It
/// deliberately does not decode or execute sumchecks and Merkle queries.  A
/// service can authenticate the returned signed challenge before spending
/// work on [`FastBackend::verify`].
#[derive(Clone, Debug)]
pub struct FastPreflight {
    pub payload_digest: Digest,
    pub precommitment_digest: Digest,
    pub nonce_mode: FastNonceMode,
    pub external_challenge: Option<SignedCommitmentChallenge>,
}

/// Verifier work counters make the succinctness boundary testable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FastVerifierWork {
    pub sumcheck_rounds: u64,
    pub sumcheck_scalar_values: u64,
    pub public_matrix_period_terms: u64,
    pub public_matrix_arithmetic_operations: u64,
    pub public_rhs_period_terms: u64,
    pub public_rhs_arithmetic_operations: u64,
    pub generator_row_queries: u64,
    pub opening_rounds: u64,
    pub opening_query_paths: u64,
    pub merkle_hashes: u64,
    pub solution_elements_materialized: u64,
    pub residual_elements_materialized: u64,
    pub codeword_elements_materialized: u64,
    pub accounted_high_watermark_bytes: usize,
}

/// Structurally authenticated metric result.
///
/// A result is returned even when numerical defects exceed policy.  The
/// certification layer must call [`Self::passes_policy`] and separately
/// authenticate/freshness-check an external challenge before signing a result.
#[derive(Clone, Debug)]
pub struct FastVerifierReport {
    pub payload_digest: Digest,
    pub precommitment_digest: Digest,
    pub sources: FastSourceDigests,
    pub packed_codeword_root: MerkleRoot,
    pub nonce_mode: FastNonceMode,
    pub external_challenge: Option<SignedCommitmentChallenge>,
    pub score: FastValidationScore,
    pub work: FastVerifierWork,
}

impl FastVerifierReport {
    #[must_use]
    pub const fn passes_policy(&self) -> bool {
        self.score.passes_consistency_policy
    }
}

#[derive(Debug, Error)]
pub enum FastError {
    #[error("fast backend requires fast-binary64-unit-circle-v2")]
    WrongProtocol,
    #[error("fast artifact has an unrecognized magic value")]
    BadMagic,
    #[error("unsupported fast precommitment, payload, policy, mode, or frame version")]
    UnsupportedVersion,
    #[error("fast artifact framing is invalid: {0}")]
    Framing(String),
    #[error("fast artifact exceeds a fixed resource bound")]
    ResourceLimit,
    #[error("fast artifact is bound to a different public statement")]
    StatementMismatch,
    #[error("fast artifact is bound to a different registered public evaluator")]
    EvaluatorMismatch,
    #[error("fast precommitment does not match the supplied solution")]
    PrecommitmentMismatch,
    #[error("signed commitment challenge does not match statement, backend, or commitment")]
    CommitmentChallengeMismatch,
    #[error("fast precommitment and post-commit nonce modes disagree")]
    NonceModeMismatch,
    #[error("fast policy parameters differ from frozen policy 2")]
    PolicyMismatch,
    #[error("fast transcript shape is inconsistent with the public statement")]
    TranscriptShape,
    #[error("fast transcript contains an unexpected Merkle opening index")]
    UnexpectedOpeningIndex,
    #[error("fixed relation failed: {0}")]
    Relation(#[from] RelationError),
    #[error("binary64 contract failed: {0}")]
    Float(#[from] FloatContractError),
    #[error("unit-circle encoding failed: {0}")]
    UnitCircle(#[from] UnitCircleError),
    #[error("Merkle authentication failed: {0}")]
    Merkle(#[from] MerkleError),
    #[error("metric sumcheck failed structurally: {0}")]
    Sumcheck(#[from] SumcheckError),
    #[error("Fiat--Shamir transcript failed: {0}")]
    Transcript(#[from] TranscriptError),
    #[error("registered public evaluator failed: {0}")]
    PublicEvaluator(#[from] MleEvaluationError),
    #[error("commitment challenge is malformed: {0}")]
    ServiceProtocol(#[from] ProtocolError),
    #[error("binary64 protocol arithmetic produced a non-finite value")]
    NonFiniteComputation,
}

/// Experimental fast backend marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct FastBackend;

struct PreparedMaterial {
    logical_len: usize,
    padded_len: usize,
    solution: Vec<f64>,
    residual: Vec<f64>,
    packed: Vec<f64>,
    codeword: UnitCircleCodeword,
    root: MerkleRoot,
    sources: FastSourceDigests,
}

struct MatVecTables {
    compressed_columns: Vec<f64>,
    solution: Vec<f64>,
}

#[derive(Clone, Debug)]
struct QueryPlan {
    indices: Vec<usize>,
}

#[derive(Clone, Debug)]
struct FastProof {
    logical_len: usize,
    residual_squared_l2: f64,
    norm_sumcheck: ProductSumcheckProof,
    residual_at_row_point: f64,
    matvec_sumcheck: ProductSumcheckProof,
    solution_at_column_point: f64,
    opening_sumcheck: ProductSumcheckProof,
    opening_endpoint: f64,
    folding: FoldingOpeningProof,
}

#[derive(Clone, Debug)]
struct FoldingOpeningProof {
    roots: Vec<MerkleRoot>,
    round_openings: Vec<ComplexMultiProof>,
    final_values: [ComplexValue; 2],
}

struct DecodedPreflight<'a> {
    report: FastPreflight,
    commitment: FastPrecommitment,
    proof_bytes: &'a [u8],
}

impl FastBackend {
    /// Builds an offline precommitment.  The trait-level [`PrecommitBackend`]
    /// entry point deliberately defaults to the externally challenged mode.
    pub fn commit_offline(
        statement: &PublicStatement,
        solution: &Solution,
    ) -> Result<(FastPrecommitment, FastCommitmentReport), FastError> {
        commit_with_mode(statement, solution, FastNonceMode::OfflineFiatShamir)
    }

    /// Builds a precommitment with an explicit nonce lifecycle.
    pub fn commit_with_mode(
        statement: &PublicStatement,
        solution: &Solution,
        nonce_mode: FastNonceMode,
    ) -> Result<(FastPrecommitment, FastCommitmentReport), FastError> {
        commit_with_mode(statement, solution, nonce_mode)
    }

    /// Performs cheap framing and authentication preflight before algebraic
    /// verification.  The returned external token still needs issuer-key and
    /// freshness authentication by the application.
    pub fn preflight(
        statement: &VerifierStatement<'_>,
        payload: &[u8],
    ) -> Result<FastPreflight, FastError> {
        Ok(preflight_backend(statement, payload)?.report)
    }
}

impl ValidationBackend for FastBackend {
    type ProverContext = FastProverContext;
    type ProverReport = FastProverReport;
    type VerifierReport = FastVerifierReport;
    type Error = FastError;

    const PROTOCOL: ProofProtocol = ProofProtocol::FastBinary64UnitCircleV2;

    fn prove(
        statement: &PublicStatement,
        solution: &Solution,
        context: &Self::ProverContext,
    ) -> Result<(Vec<u8>, Self::ProverReport), Self::Error> {
        prove_backend(statement, solution, context)
    }

    fn verify(
        statement: &VerifierStatement<'_>,
        payload: &[u8],
    ) -> Result<Self::VerifierReport, Self::Error> {
        verify_backend(statement, payload)
    }
}

impl PrecommitBackend for FastBackend {
    type Commitment = FastPrecommitment;
    type CommitmentReport = FastCommitmentReport;

    fn commit(
        statement: &PublicStatement,
        solution: &Solution,
    ) -> Result<(Self::Commitment, Self::CommitmentReport), Self::Error> {
        commit_with_mode(statement, solution, FastNonceMode::ExternalSigned)
    }
}

fn commit_with_mode(
    statement: &PublicStatement,
    solution: &Solution,
    nonce_mode: FastNonceMode,
) -> Result<(FastPrecommitment, FastCommitmentReport), FastError> {
    validate_prover_statement(statement)?;
    let material = prepare_material(statement.generated(), solution)?;
    let evaluator =
        EvaluatorBinding::from_metadata(statement.generated().public_evaluation_plan().metadata())?;
    let commitment = make_precommitment(
        statement.transcript_digest(),
        statement.problem_digest(),
        statement.manifest_digest(),
        evaluator,
        nonce_mode,
        &material,
    )?;
    let report = FastCommitmentReport {
        precommitment_digest: commitment.digest(),
        sources: commitment.sources,
        packed_codeword_root: commitment.packed_codeword_root,
        logical_len: commitment.logical_len(),
        codeword_len: commitment.codeword_len,
        nonce_mode,
    };
    Ok((commitment, report))
}

fn prove_backend(
    statement: &PublicStatement,
    solution: &Solution,
    context: &FastProverContext,
) -> Result<(Vec<u8>, FastProverReport), FastError> {
    validate_prover_statement(statement)?;
    let material = prepare_material(statement.generated(), solution)?;
    let commitment = context.commitment();
    let expected = make_precommitment(
        statement.transcript_digest(),
        statement.problem_digest(),
        statement.manifest_digest(),
        EvaluatorBinding::from_metadata(statement.generated().public_evaluation_plan().metadata())?,
        commitment.nonce_mode,
        &material,
    )?;
    if commitment != &expected {
        return Err(FastError::PrecommitmentMismatch);
    }
    let external_challenge = match context {
        FastProverContext::ExternalSigned {
            challenge,
            commitment: _,
        } => {
            if commitment.nonce_mode != FastNonceMode::ExternalSigned {
                return Err(FastError::NonceModeMismatch);
            }
            validate_external_challenge(
                statement.problem_digest(),
                statement.manifest_digest(),
                commitment,
                challenge,
            )?;
            Some(challenge.as_ref())
        }
        FastProverContext::OfflineFiatShamir { .. } => {
            if commitment.nonce_mode != FastNonceMode::OfflineFiatShamir {
                return Err(FastError::NonceModeMismatch);
            }
            None
        }
    };

    let mut transcript = initialize_transcript(commitment, external_challenge)?;

    // The norm endpoint is reused as the row-compression point, authenticating
    // one residual MLE value for both application relations.
    let padded_residual = pad_vector(&material.residual, material.padded_len);
    let residual_squared_l2 =
        canonical_protocol_float(product_sum(&padded_residual, &padded_residual)?)?;
    absorb_float(
        &mut transcript,
        b"residual-squared-l2-claim",
        residual_squared_l2,
    )?;
    let residual_right = padded_residual.clone();
    let (norm_sumcheck, norm_endpoint) = prove_product_owned(
        padded_residual,
        residual_right,
        residual_squared_l2,
        |round, polynomial| {
            sumcheck_challenge(&mut transcript, b"residual-norm", round, polynomial)
        },
    )?;
    let residual_at_row_point = norm_endpoint.left_evaluation;
    absorb_float(
        &mut transcript,
        b"residual-at-shared-row-point",
        residual_at_row_point,
    )?;

    let rhs = statement
        .generated()
        .public_evaluation_plan()
        .evaluate_rhs_mle_f64(&norm_endpoint.point)?;
    let matvec_initial_claim = canonical_protocol_float(rhs.value + residual_at_row_point)?;
    absorb_float(
        &mut transcript,
        b"matvec-initial-claim",
        matvec_initial_claim,
    )?;
    let matvec_tables = prepare_matvec_tables(
        statement.generated(),
        &material.solution,
        &norm_endpoint.point,
    )?;
    let (matvec_sumcheck, matvec_endpoint) = prove_product_owned(
        matvec_tables.compressed_columns,
        matvec_tables.solution,
        matvec_initial_claim,
        |round, polynomial| {
            sumcheck_challenge(&mut transcript, b"matvec-product", round, polynomial)
        },
    )?;
    let solution_at_column_point = matvec_endpoint.right_evaluation;
    absorb_float(
        &mut transcript,
        b"solution-at-column-point",
        solution_at_column_point,
    )?;

    // A commitment and proximity queries alone do not authenticate an
    // arbitrary MLE endpoint.  This third sumcheck is the required bridge.
    let batching_challenge =
        transcript.challenge_dyadic_f64(b"linear-opening-batching-challenge")?;
    let opening_initial_claim = canonical_protocol_float(
        solution_at_column_point + batching_challenge * residual_at_row_point,
    )?;
    absorb_float(
        &mut transcript,
        b"linear-opening-initial-claim",
        opening_initial_claim,
    )?;
    let opening_weights = combined_opening_weights(
        material.padded_len,
        &matvec_endpoint.point,
        &norm_endpoint.point,
        batching_challenge,
    )?;

    let mut fold_codeword = material.codeword.clone();
    let opening_rounds = fold_codeword.message_len().ilog2() as usize;
    let mut fold_roots = Vec::with_capacity(opening_rounds);
    let mut fold_challenges = Vec::with_capacity(opening_rounds);
    let mut fold_error = None;
    let (opening_sumcheck, opening_product_endpoint) = prove_product_owned(
        material.packed,
        opening_weights,
        opening_initial_claim,
        |round, polynomial| {
            let challenge = sumcheck_challenge(
                &mut transcript,
                b"linear-opening-product",
                round,
                polynomial,
            );
            fold_challenges.push(challenge);
            if fold_error.is_none() {
                match fold_codeword.fold(challenge).and_then(|next| {
                    let label = oracle_tree_label(round + 1, next.evaluations().len());
                    let root = complex_root(&label, next.evaluations())
                        .map_err(|_| UnitCircleError::InvalidCodewordShape)?;
                    Ok((next, root))
                }) {
                    Ok((next, root)) => {
                        // The child root is fixed before the next polynomial
                        // and challenge enter the transcript.
                        transcript.absorb_root(b"linear-opening-fold-root", &root);
                        fold_roots.push(root);
                        fold_codeword = next;
                    }
                    Err(error) => {
                        fold_error = Some(FastError::UnitCircle(error));
                        let sentinel = [0_u8; 32];
                        transcript.absorb_root(b"linear-opening-fold-root", &sentinel);
                        fold_roots.push(sentinel);
                    }
                }
            } else {
                let sentinel = [0_u8; 32];
                transcript.absorb_root(b"linear-opening-fold-root", &sentinel);
                fold_roots.push(sentinel);
            }
            challenge
        },
    )?;
    if let Some(error) = fold_error {
        return Err(error);
    }
    let opening_endpoint = opening_product_endpoint.left_evaluation;
    absorb_float(
        &mut transcript,
        b"linear-opening-source-endpoint",
        opening_endpoint,
    )?;
    if fold_codeword.message_len() != 1 || fold_codeword.evaluations().len() != 2 {
        return Err(FastError::TranscriptShape);
    }

    // Query locations are derived only after every recursive oracle is fixed.
    let query_plan = draw_query_plan(&mut transcript, material.codeword.message_len())?;
    let codeword_len = material.codeword.evaluations().len();
    let folding = build_folding_opening(
        material.codeword,
        &fold_roots,
        &fold_challenges,
        &query_plan,
    )?;
    let proof = FastProof {
        logical_len: material.logical_len,
        residual_squared_l2,
        norm_sumcheck,
        residual_at_row_point,
        matvec_sumcheck,
        solution_at_column_point,
        opening_sumcheck,
        opening_endpoint,
        folding,
    };
    let proof_bytes = encode_proof(&proof)?;
    let payload = encode_backend_payload(commitment, external_challenge, &proof_bytes)?;
    if payload.len() > MAX_PROOF_BYTES {
        return Err(FastError::ResourceLimit);
    }
    // Proof construction scans rows once for binary64 R and once for the
    // compressed matvec table. Q63.64 witness construction is row-free.
    let rows_scanned = u64::try_from(material.logical_len)
        .map_err(|_| FastError::ResourceLimit)?
        .checked_mul(2)
        .ok_or(FastError::ResourceLimit)?;
    let nonzeros_scanned = u64::try_from(statement.generated().structural_nnz())
        .map_err(|_| FastError::ResourceLimit)?
        .checked_mul(2)
        .ok_or(FastError::ResourceLimit)?;
    let report = FastProverReport {
        payload_digest: domain_separated_digest(PAYLOAD_DIGEST_DOMAIN, &payload),
        precommitment_digest: commitment.digest(),
        sources: commitment.sources,
        packed_codeword_root: commitment.packed_codeword_root,
        logical_len: material.logical_len,
        codeword_len,
        proximity_queries_per_round: query_plan.indices.len() as u32,
        residual_squared_l2,
        payload_bytes: payload.len(),
        rows_scanned,
        nonzeros_scanned,
    };
    Ok((payload, report))
}

fn verify_backend(
    statement: &VerifierStatement<'_>,
    payload_bytes: &[u8],
) -> Result<FastVerifierReport, FastError> {
    let preflight = preflight_backend(statement, payload_bytes)?;
    let proof = decode_proof(preflight.proof_bytes, statement.dimension())?;
    let commitment = preflight.commitment;
    let padded_len = commitment.evaluator.padded_dimension;
    let variables = commitment.evaluator.variables;
    let opening_variables = variables + 1;
    let mut transcript =
        initialize_transcript(&commitment, preflight.report.external_challenge.as_ref())?;

    if proof.residual_squared_l2 < 0.0 {
        return Err(FastError::TranscriptShape);
    }
    absorb_float(
        &mut transcript,
        b"residual-squared-l2-claim",
        proof.residual_squared_l2,
    )?;
    let norm_verification = verify_product(
        padded_len,
        proof.residual_squared_l2,
        &proof.norm_sumcheck,
        |round, polynomial| {
            sumcheck_challenge(&mut transcript, b"residual-norm", round, polynomial)
        },
    )?;
    let mut norm_defects = DefectAccumulator::default();
    for &observation in &norm_verification.round_defects {
        norm_defects.observe_policy2_sumcheck(observation);
    }
    norm_defects.observe_policy2_sumcheck(verify_product_endpoint(
        &norm_verification.endpoint,
        proof.residual_at_row_point,
        proof.residual_at_row_point,
    )?);
    absorb_float(
        &mut transcript,
        b"residual-at-shared-row-point",
        proof.residual_at_row_point,
    )?;

    let rhs = statement
        .public_evaluator()
        .evaluate_rhs_mle_f64(&norm_verification.endpoint.point)?;
    let matvec_initial_claim = canonical_protocol_float(rhs.value + proof.residual_at_row_point)?;
    absorb_float(
        &mut transcript,
        b"matvec-initial-claim",
        matvec_initial_claim,
    )?;
    let matvec_verification = verify_product(
        padded_len,
        matvec_initial_claim,
        &proof.matvec_sumcheck,
        |round, polynomial| {
            sumcheck_challenge(&mut transcript, b"matvec-product", round, polynomial)
        },
    )?;
    let matrix = statement.public_evaluator().evaluate_matrix_mle_f64(
        &norm_verification.endpoint.point,
        &matvec_verification.endpoint.point,
    )?;
    let mut matvec_defects = DefectAccumulator::default();
    for &observation in &matvec_verification.round_defects {
        matvec_defects.observe_policy2_sumcheck(observation);
    }
    matvec_defects.observe_policy2_sumcheck(verify_product_endpoint(
        &matvec_verification.endpoint,
        matrix.value,
        proof.solution_at_column_point,
    )?);
    absorb_float(
        &mut transcript,
        b"solution-at-column-point",
        proof.solution_at_column_point,
    )?;

    let batching_challenge =
        transcript.challenge_dyadic_f64(b"linear-opening-batching-challenge")?;
    let opening_initial_claim = canonical_protocol_float(
        proof.solution_at_column_point + batching_challenge * proof.residual_at_row_point,
    )?;
    absorb_float(
        &mut transcript,
        b"linear-opening-initial-claim",
        opening_initial_claim,
    )?;
    if proof.folding.roots.len() != opening_variables
        || proof.folding.round_openings.len() != opening_variables
    {
        return Err(FastError::TranscriptShape);
    }
    let opening_verification = verify_product(
        2 * padded_len,
        opening_initial_claim,
        &proof.opening_sumcheck,
        |round, polynomial| {
            let challenge = sumcheck_challenge(
                &mut transcript,
                b"linear-opening-product",
                round,
                polynomial,
            );
            transcript.absorb_root(b"linear-opening-fold-root", &proof.folding.roots[round]);
            challenge
        },
    )?;
    let expected_weight_endpoint = combined_form_evaluation(
        &matvec_verification.endpoint.point,
        &norm_verification.endpoint.point,
        batching_challenge,
        &opening_verification.endpoint.point,
    )?;
    let mut opening_defects = DefectAccumulator::default();
    for &observation in &opening_verification.round_defects {
        opening_defects.observe_policy2_sumcheck(observation);
    }
    opening_defects.observe_policy2_sumcheck(verify_product_endpoint(
        &opening_verification.endpoint,
        proof.opening_endpoint,
        expected_weight_endpoint,
    )?);
    absorb_float(
        &mut transcript,
        b"linear-opening-source-endpoint",
        proof.opening_endpoint,
    )?;

    let query_plan = draw_query_plan(&mut transcript, 2 * padded_len)?;
    let (fold_summary, merkle_hashes, opening_paths) = verify_folding_opening(
        commitment.packed_codeword_root,
        &proof.folding,
        &opening_verification.endpoint.point,
        proof.opening_endpoint,
        &query_plan,
    )?;

    let norm_sumcheck = norm_defects.finish();
    let matvec_sumcheck = matvec_defects.finish();
    let linear_opening_sumcheck = opening_defects.finish();
    let residual_squared_l2 = proof.residual_squared_l2;
    let residual_l2 = canonical_protocol_float(residual_squared_l2.sqrt())?;
    let residual_rms =
        canonical_protocol_float((residual_squared_l2 / statement.dimension() as f64).sqrt())?;
    let passes_consistency_policy = [
        norm_sumcheck,
        matvec_sumcheck,
        linear_opening_sumcheck,
        fold_summary,
    ]
    .into_iter()
    .all(crate::score::DefectSummary::passes);
    let score = FastValidationScore {
        norm_sumcheck,
        matvec_sumcheck,
        linear_opening_sumcheck,
        unit_circle_folds: fold_summary,
        residual_squared_l2,
        residual_l2,
        residual_rms,
        proximity_queries_per_round: query_plan.indices.len() as u32,
        conditional_miss_probability_upper_bound: conditional_miss_probabilities(
            query_plan.indices.len(),
        ),
        passes_consistency_policy,
    };

    let sumcheck_rounds = (2 * variables + opening_variables) as u64;
    let query_workspace_bytes = opening_variables
        .checked_mul(2 * Policy2::PROXIMITY_QUERY_TARGET)
        .and_then(|value| value.checked_mul(std::mem::size_of::<usize>()))
        .ok_or(FastError::ResourceLimit)?;
    let claim_bytes = opening_variables
        .checked_mul(std::mem::size_of::<f64>())
        .and_then(|value| value.checked_add(4 * std::mem::size_of::<f64>()))
        .ok_or(FastError::ResourceLimit)?;
    let accounted_high_watermark_bytes = payload_bytes
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_add(query_workspace_bytes))
        .and_then(|value| value.checked_add(claim_bytes))
        .ok_or(FastError::ResourceLimit)?;
    let work = FastVerifierWork {
        sumcheck_rounds,
        sumcheck_scalar_values: 3 * sumcheck_rounds,
        public_matrix_period_terms: matrix.work.periodic_terms,
        public_matrix_arithmetic_operations: matrix.work.arithmetic_operations(),
        public_rhs_period_terms: rhs.work.periodic_terms,
        public_rhs_arithmetic_operations: rhs.work.arithmetic_operations(),
        generator_row_queries: 0,
        opening_rounds: opening_variables as u64,
        opening_query_paths: opening_paths,
        merkle_hashes,
        solution_elements_materialized: 0,
        residual_elements_materialized: 0,
        codeword_elements_materialized: 0,
        accounted_high_watermark_bytes,
    };
    Ok(FastVerifierReport {
        payload_digest: preflight.report.payload_digest,
        precommitment_digest: preflight.report.precommitment_digest,
        sources: commitment.sources,
        packed_codeword_root: commitment.packed_codeword_root,
        nonce_mode: preflight.report.nonce_mode,
        external_challenge: preflight.report.external_challenge,
        score,
        work,
    })
}

fn preflight_backend<'a>(
    statement: &VerifierStatement<'_>,
    payload_bytes: &'a [u8],
) -> Result<DecodedPreflight<'a>, FastError> {
    if statement.protocol() != ProofProtocol::FastBinary64UnitCircleV2 {
        return Err(FastError::WrongProtocol);
    }
    if payload_bytes.len() > MAX_PROOF_BYTES {
        return Err(FastError::ResourceLimit);
    }
    let (commitment, external_challenge, proof_bytes) = decode_backend_payload(payload_bytes)?;
    let expected_evaluator =
        EvaluatorBinding::from_metadata(statement.public_evaluator().metadata())?;
    if commitment.statement_digest != statement.transcript_digest()
        || commitment.problem_digest != statement.problem_digest()
        || commitment.manifest_digest != statement.manifest_digest()
        || commitment.evaluator != expected_evaluator
        || commitment.logical_len() != statement.dimension()
    {
        return Err(FastError::StatementMismatch);
    }
    match (commitment.nonce_mode, external_challenge.as_ref()) {
        (FastNonceMode::ExternalSigned, Some(challenge)) => validate_external_challenge(
            statement.problem_digest(),
            statement.manifest_digest(),
            &commitment,
            challenge,
        )?,
        (FastNonceMode::OfflineFiatShamir, None) => {}
        _ => return Err(FastError::NonceModeMismatch),
    }
    Ok(DecodedPreflight {
        report: FastPreflight {
            payload_digest: domain_separated_digest(PAYLOAD_DIGEST_DOMAIN, payload_bytes),
            precommitment_digest: commitment.digest(),
            nonce_mode: commitment.nonce_mode,
            external_challenge,
        },
        commitment,
        proof_bytes,
    })
}

fn validate_prover_statement(statement: &PublicStatement) -> Result<(), FastError> {
    if statement.manifest().protocol != ProofProtocol::FastBinary64UnitCircleV2 {
        return Err(FastError::WrongProtocol);
    }
    validate_length(statement.generated().dimension())
}

fn validate_length(logical_len: usize) -> Result<(), FastError> {
    let wire_len = u64::try_from(logical_len).map_err(|_| FastError::ResourceLimit)?;
    if logical_len < 2
        || wire_len > ssv_service_protocol::MAX_SOLUTION_ELEMENTS_LIMIT
        || logical_len.checked_next_power_of_two().is_none()
    {
        return Err(FastError::ResourceLimit);
    }
    Ok(())
}

fn make_precommitment(
    statement_digest: Digest,
    problem_digest: Digest,
    manifest_digest: Digest,
    evaluator: EvaluatorBinding,
    nonce_mode: FastNonceMode,
    material: &PreparedMaterial,
) -> Result<FastPrecommitment, FastError> {
    if evaluator.logical_dimension != material.logical_len
        || evaluator.padded_dimension != material.padded_len
    {
        return Err(FastError::EvaluatorMismatch);
    }
    let packed_source_len = material.codeword.message_len();
    let polynomial_degree = packed_source_len
        .checked_sub(1)
        .ok_or(FastError::TranscriptShape)?;
    let codeword_len = material.codeword.evaluations().len();
    let commitment = FastPrecommitment {
        nonce_mode,
        statement_digest,
        problem_digest,
        manifest_digest,
        evaluator,
        packed_source_len,
        polynomial_degree,
        codeword_len,
        sources: material.sources,
        packed_codeword_root: material.root,
    };
    if commitment.try_to_bytes()?.len() > MAX_PRECOMMITMENT_BYTES {
        return Err(FastError::ResourceLimit);
    }
    Ok(commitment)
}

fn prepare_material(
    problem: &GeneratedProblem,
    solution: &Solution,
) -> Result<PreparedMaterial, FastError> {
    let logical_len = problem.dimension();
    validate_length(logical_len)?;
    let padded_len = logical_len
        .checked_next_power_of_two()
        .ok_or(FastError::ResourceLimit)?;

    // Quantization is shared with the exact path, but residual semantics are
    // deliberately not: the provisional backend computes R in binary64 and
    // must not inherit the exact backend's signed-69-bit residual range.
    let witness = FixedWitness::from_solution(solution, problem.dimension())?;
    let exact_witness = i128_vector_digest(b"q63.64-witness-x", witness.as_slice());
    let solution = witness
        .to_binary64()
        .into_iter()
        .map(canonicalize_source)
        .collect::<Result<Vec<_>, _>>()?;
    drop(witness);
    let residual = compute_residual(problem, &solution)?;
    let binary64_solution = vector_digest(b"solution-x", &solution)?;
    let binary64_residual = vector_digest(b"residual-r", &residual)?;
    let packed_len = padded_len.checked_mul(2).ok_or(FastError::ResourceLimit)?;
    let mut packed = Vec::new();
    packed
        .try_reserve_exact(packed_len)
        .map_err(|_| FastError::ResourceLimit)?;
    packed.resize(packed_len, 0.0);
    packed[..logical_len].copy_from_slice(&solution);
    packed[padded_len..padded_len + logical_len].copy_from_slice(&residual);
    let codeword = UnitCircleCodeword::encode(&packed)?;
    if codeword.message_len() != packed_len {
        return Err(FastError::TranscriptShape);
    }
    let label = oracle_tree_label(0, codeword.evaluations().len());
    let root = complex_root(&label, codeword.evaluations())?;
    Ok(PreparedMaterial {
        logical_len,
        padded_len,
        solution,
        residual,
        packed,
        codeword,
        root,
        sources: FastSourceDigests {
            exact_witness,
            binary64_solution,
            binary64_residual,
        },
    })
}

fn compute_residual(problem: &GeneratedProblem, solution: &[f64]) -> Result<Vec<f64>, FastError> {
    if solution.len() != problem.dimension() {
        return Err(FastError::TranscriptShape);
    }
    let mut residual = Vec::new();
    residual
        .try_reserve_exact(problem.dimension())
        .map_err(|_| FastError::ResourceLimit)?;
    for row in 0..problem.dimension() {
        let mut dot = 0.0_f64;
        for entry in problem.row(row).ok_or(FastError::TranscriptShape)? {
            // Separate statements deliberately prohibit fused multiply-add.
            let product = canonical_protocol_float(entry.value.to_f64() * solution[entry.column])?;
            dot = canonical_protocol_float(dot + product)?;
        }
        let rhs = problem.rhs_f64(row).ok_or(FastError::TranscriptShape)?;
        residual.push(canonical_protocol_float(dot - rhs)?);
    }
    Ok(residual)
}

fn prepare_matvec_tables(
    problem: &GeneratedProblem,
    solution: &[f64],
    row_point: &[f64],
) -> Result<MatVecTables, FastError> {
    let table_len = problem.dimension().next_power_of_two();
    if row_point.len() != table_len.ilog2() as usize || solution.len() != problem.dimension() {
        return Err(FastError::TranscriptShape);
    }
    let weights = equality_table(row_point)?;
    let mut compressed_columns = vec![0.0; table_len];
    for (row, &weight) in weights.iter().take(problem.dimension()).enumerate() {
        for entry in problem.row(row).ok_or(FastError::TranscriptShape)? {
            let product = canonical_protocol_float(weight * entry.value.to_f64())?;
            compressed_columns[entry.column] =
                canonical_protocol_float(compressed_columns[entry.column] + product)?;
        }
    }
    Ok(MatVecTables {
        compressed_columns,
        solution: pad_vector(solution, table_len),
    })
}

fn validate_external_challenge(
    problem_digest: Digest,
    manifest_digest: Digest,
    commitment: &FastPrecommitment,
    challenge: &SignedCommitmentChallenge,
) -> Result<(), FastError> {
    challenge.payload.validate()?;
    if challenge.payload.problem_digest != problem_digest
        || challenge.payload.validation_manifest_digest != manifest_digest
        || challenge.payload.protocol != ProofProtocol::FastBinary64UnitCircleV2
        || challenge.payload.commitment_digest != commitment.digest()
    {
        return Err(FastError::CommitmentChallengeMismatch);
    }
    Ok(())
}

fn initialize_transcript(
    commitment: &FastPrecommitment,
    external_challenge: Option<&SignedCommitmentChallenge>,
) -> Result<Transcript, FastError> {
    let commitment_bytes = commitment.try_to_bytes()?;
    let mut transcript = Transcript::new(PROTOCOL_LABEL);
    transcript.absorb_bytes(b"canonical-precommitment", &commitment_bytes);
    transcript.absorb_bytes(b"precommitment-digest", commitment.digest().as_bytes());
    transcript.absorb_bytes(b"code-basis", CODE_BASIS);
    transcript.absorb_bytes(b"float-contract", FLOAT_CONTRACT);
    match (commitment.nonce_mode, external_challenge) {
        (FastNonceMode::ExternalSigned, Some(challenge)) => {
            transcript.absorb_u64(b"nonce-mode", 1);
            transcript.absorb_bytes(
                b"signed-commitment-challenge",
                &challenge.to_canonical_bytes(),
            );
        }
        (FastNonceMode::OfflineFiatShamir, None) => {
            transcript.absorb_u64(b"nonce-mode", 2);
            let nonce = domain_separated_digest(OFFLINE_NONCE_DOMAIN, &commitment_bytes);
            transcript.absorb_bytes(b"offline-fiat-shamir-nonce", nonce.as_bytes());
        }
        _ => return Err(FastError::NonceModeMismatch),
    }
    Ok(transcript)
}

fn combined_opening_weights(
    padded_len: usize,
    solution_point: &[f64],
    residual_point: &[f64],
    batching_challenge: f64,
) -> Result<Vec<f64>, FastError> {
    if solution_point.len() != padded_len.ilog2() as usize
        || residual_point.len() != solution_point.len()
    {
        return Err(FastError::TranscriptShape);
    }
    let solution = equality_table(solution_point)?;
    let residual = equality_table(residual_point)?;
    let mut weights = vec![0.0; 2 * padded_len];
    weights[..padded_len].copy_from_slice(&solution);
    for (output, value) in weights[padded_len..].iter_mut().zip(residual) {
        *output = canonical_protocol_float(batching_challenge * value)?;
    }
    Ok(weights)
}

fn combined_form_evaluation(
    solution_point: &[f64],
    residual_point: &[f64],
    batching_challenge: f64,
    opening_point: &[f64],
) -> Result<f64, FastError> {
    if opening_point.len() != solution_point.len() + 1
        || residual_point.len() != solution_point.len()
    {
        return Err(FastError::TranscriptShape);
    }
    let selector = opening_point[0];
    let tail = &opening_point[1..];
    let solution_eq = equality_kernel(solution_point, tail)?;
    let residual_eq = equality_kernel(residual_point, tail)?;
    let solution_term = canonical_protocol_float((1.0 - selector) * solution_eq)?;
    let residual_term = canonical_protocol_float(selector * batching_challenge * residual_eq)?;
    canonical_protocol_float(solution_term + residual_term)
}

fn equality_kernel(left: &[f64], right: &[f64]) -> Result<f64, FastError> {
    if left.len() != right.len() {
        return Err(FastError::TranscriptShape);
    }
    left.iter().zip(right).try_fold(1.0, |value, (&lhs, &rhs)| {
        let one_pair = canonical_protocol_float(lhs * rhs)?;
        let zero_pair = canonical_protocol_float((1.0 - lhs) * (1.0 - rhs))?;
        canonical_protocol_float(value * canonical_protocol_float(one_pair + zero_pair)?)
    })
}

fn equality_table(point: &[f64]) -> Result<Vec<f64>, FastError> {
    let final_len = 1_usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| FastError::ResourceLimit)?)
        .ok_or(FastError::ResourceLimit)?;
    let mut table = vec![1.0];
    for &coordinate in point {
        let mut next = Vec::with_capacity(table.len() * 2);
        for &weight in &table {
            next.push(canonical_protocol_float(weight * (1.0 - coordinate))?);
            next.push(canonical_protocol_float(weight * coordinate)?);
        }
        table = next;
    }
    debug_assert_eq!(table.len(), final_len);
    Ok(table)
}

fn pad_vector(values: &[f64], len: usize) -> Vec<f64> {
    let mut padded = vec![0.0; len];
    padded[..values.len()].copy_from_slice(values);
    padded
}

fn canonical_protocol_float(value: f64) -> Result<f64, FastError> {
    canonicalize_arithmetic(value).map_err(FastError::Float)
}

fn complex_root(label: &[u8], values: &[ComplexValue]) -> Result<MerkleRoot, FastError> {
    Ok(streaming_complex_root_iter(
        label,
        values.iter().copied().map(ComplexValue::canonical_bits),
    )?)
}

fn oracle_tree_label(round: usize, domain_len: usize) -> Vec<u8> {
    let mut label = Vec::with_capacity(ORACLE_TREE_LABEL.len() + 16);
    label.extend_from_slice(ORACLE_TREE_LABEL);
    label.extend_from_slice(&(round as u64).to_le_bytes());
    label.extend_from_slice(&(domain_len as u64).to_le_bytes());
    label
}

fn sumcheck_challenge(
    transcript: &mut Transcript,
    phase: &[u8],
    round: usize,
    polynomial: &QuadraticBernstein,
) -> f64 {
    transcript.absorb_bytes(b"sumcheck-phase", phase);
    transcript.absorb_u64(b"sumcheck-round", round as u64);
    for &coefficient in &polynomial.coefficients {
        transcript.absorb_u64(b"sumcheck-bernstein-coefficient", coefficient.to_bits());
    }
    transcript
        .challenge_dyadic_f64(b"sumcheck-challenge")
        .expect("the bounded protocol transcript cannot exhaust its u64 challenge counter")
}

fn absorb_float(transcript: &mut Transcript, tag: &[u8], value: f64) -> Result<(), FastError> {
    transcript.absorb_u64(tag, canonical_bits(value)?);
    Ok(())
}

fn build_folding_opening(
    initial: UnitCircleCodeword,
    roots: &[MerkleRoot],
    challenges: &[f64],
    query_plan: &QueryPlan,
) -> Result<FoldingOpeningProof, FastError> {
    if roots.len() != challenges.len() || roots.len() != initial.message_len().ilog2() as usize {
        return Err(FastError::TranscriptShape);
    }
    let mut current = initial;
    let mut round_openings = Vec::with_capacity(challenges.len());
    for (round, &challenge) in challenges.iter().enumerate() {
        let expected_root = if round == 0 {
            let label = oracle_tree_label(0, current.evaluations().len());
            complex_root(&label, current.evaluations())?
        } else {
            roots[round - 1]
        };
        let selected = selected_indices_for_round(query_plan, current.evaluations().len())?;
        let label = oracle_tree_label(round, current.evaluations().len());
        let (actual_root, openings) = streaming_complex_root_and_multiproof_iter(
            &label,
            current
                .evaluations()
                .iter()
                .copied()
                .map(ComplexValue::canonical_bits),
            &selected,
        )?;
        if actual_root != expected_root {
            return Err(FastError::TranscriptShape);
        }
        round_openings.push(openings);
        current = current.fold(challenge)?;
        let child_label = oracle_tree_label(round + 1, current.evaluations().len());
        if complex_root(&child_label, current.evaluations())? != roots[round] {
            return Err(FastError::TranscriptShape);
        }
    }
    if current.evaluations().len() != 2 {
        return Err(FastError::TranscriptShape);
    }
    Ok(FoldingOpeningProof {
        roots: roots.to_vec(),
        round_openings,
        final_values: [current.evaluations()[0], current.evaluations()[1]],
    })
}

fn verify_folding_opening(
    initial_root: MerkleRoot,
    proof: &FoldingOpeningProof,
    challenges: &[f64],
    opening_endpoint: f64,
    query_plan: &QueryPlan,
) -> Result<(crate::score::DefectSummary, u64, u64), FastError> {
    if proof.roots.len() != challenges.len()
        || proof.round_openings.len() != challenges.len()
        || challenges.is_empty()
    {
        return Err(FastError::TranscriptShape);
    }
    let shift = u32::try_from(challenges.len() + 1).map_err(|_| FastError::ResourceLimit)?;
    let initial_domain = 1_usize.checked_shl(shift).ok_or(FastError::ResourceLimit)?;
    let final_label = oracle_tree_label(challenges.len(), 2);
    let final_bits = proof.final_values.map(ComplexValue::canonical_bits);
    let final_root = streaming_complex_root(&final_label, &final_bits)?;
    if final_root != *proof.roots.last().ok_or(FastError::TranscriptShape)? {
        return Err(FastError::TranscriptShape);
    }

    let mut domain_len = initial_domain;
    let mut merkle_hashes = 3_u64;
    let mut opening_paths = 0_u64;
    let mut round_indices = Vec::with_capacity(challenges.len());
    for round in 0..challenges.len() {
        let expected_indices = selected_indices_for_round(query_plan, domain_len)?;
        let openings = &proof.round_openings[round];
        let root = if round == 0 {
            initial_root
        } else {
            proof.roots[round - 1]
        };
        let label = oracle_tree_label(round, domain_len);
        let round_hashes =
            verify_complex_multiproof(&label, domain_len, &root, &expected_indices, openings)?;
        merkle_hashes = merkle_hashes
            .checked_add(u64::try_from(round_hashes).map_err(|_| FastError::ResourceLimit)?)
            .ok_or(FastError::ResourceLimit)?;
        opening_paths = opening_paths
            .checked_add(
                u64::try_from(expected_indices.len()).map_err(|_| FastError::ResourceLimit)?,
            )
            .ok_or(FastError::ResourceLimit)?;
        round_indices.push(expected_indices);
        domain_len /= 2;
    }
    if domain_len != 2 {
        return Err(FastError::TranscriptShape);
    }

    let mut defects = DefectAccumulator::default();
    for &base_index in &query_plan.indices {
        let mut index = base_index;
        let mut current_domain = initial_domain;
        for round in 0..challenges.len() {
            let half = current_domain / 2;
            let low_index = index % half;
            let current_openings = &proof.round_openings[round];
            let at_z = opened_value(&round_indices[round], current_openings, low_index)?;
            let at_negative_z =
                opened_value(&round_indices[round], current_openings, low_index + half)?;
            let expected = fold_pair_at_index(
                at_z,
                at_negative_z,
                low_index,
                current_domain,
                challenges[round],
            )?;
            let actual = if round + 1 == challenges.len() {
                proof.final_values[low_index]
            } else {
                opened_value(
                    &round_indices[round + 1],
                    &proof.round_openings[round + 1],
                    low_index,
                )?
            };
            defects.observe_policy2_unit_circle_fold(actual, expected, &[at_z, at_negative_z]);
            index = low_index;
            current_domain = half;
        }
    }
    let claimed = ComplexValue::from_real(opening_endpoint)?;
    for value in proof.final_values {
        defects.observe_policy2_unit_circle_fold(value, claimed, &[]);
    }
    Ok((defects.finish(), merkle_hashes, opening_paths))
}

fn selected_indices_for_round(
    plan: &QueryPlan,
    domain_len: usize,
) -> Result<Vec<usize>, FastError> {
    if domain_len < 4 || !domain_len.is_power_of_two() {
        return Err(FastError::TranscriptShape);
    }
    let half = domain_len / 2;
    let mut selected = BTreeSet::new();
    for &base in &plan.indices {
        let low = base % half;
        selected.insert(low);
        selected.insert(low + half);
    }
    Ok(selected.into_iter().collect())
}

fn opened_value(
    expected_indices: &[usize],
    openings: &ComplexMultiProof,
    index: usize,
) -> Result<ComplexValue, FastError> {
    let position = expected_indices
        .binary_search(&index)
        .map_err(|_| FastError::UnexpectedOpeningIndex)?;
    let [real_bits, imaginary_bits] = *openings
        .value_bits
        .get(position)
        .ok_or(FastError::TranscriptShape)?;
    Ok(ComplexValue::from_canonical_bits(
        real_bits,
        imaginary_bits,
    )?)
}

fn draw_query_plan(
    transcript: &mut Transcript,
    message_len: usize,
) -> Result<QueryPlan, FastError> {
    let count = Policy2::PROXIMITY_QUERY_TARGET.min(message_len);
    let indices = draw_unique_indices(
        transcript,
        b"recursive-unit-circle-path",
        message_len,
        count,
    )?;
    Ok(QueryPlan { indices })
}

fn draw_unique_indices(
    transcript: &mut Transcript,
    tag: &[u8],
    domain: usize,
    count: usize,
) -> Result<Vec<usize>, FastError> {
    if count == 0 || count > domain {
        return Err(FastError::TranscriptShape);
    }
    let mut selected = BTreeSet::new();
    let maximum_draws = count
        .checked_mul(256)
        .and_then(|value| value.checked_add(256))
        .ok_or(FastError::ResourceLimit)?;
    let mut draws = 0_usize;
    while selected.len() < count {
        if draws == maximum_draws {
            return Err(FastError::TranscriptShape);
        }
        selected.insert(transcript.challenge_usize(tag, domain)?);
        draws += 1;
    }
    Ok(selected.into_iter().collect())
}

fn encode_backend_payload(
    commitment: &FastPrecommitment,
    external_challenge: Option<&SignedCommitmentChallenge>,
    proof: &[u8],
) -> Result<Vec<u8>, FastError> {
    let commitment_bytes = commitment.try_to_bytes()?;
    let challenge_bytes = external_challenge
        .map(SignedCommitmentChallenge::to_canonical_bytes)
        .unwrap_or_default();
    if commitment_bytes.len() > MAX_PRECOMMITMENT_BYTES
        || challenge_bytes.len() > MAX_COMMITMENT_CHALLENGE_BYTES
        || proof.len() > MAX_PROOF_BYTES
    {
        return Err(FastError::ResourceLimit);
    }
    match (commitment.nonce_mode, challenge_bytes.is_empty()) {
        (FastNonceMode::ExternalSigned, false) | (FastNonceMode::OfflineFiatShamir, true) => {}
        _ => return Err(FastError::NonceModeMismatch),
    }
    let mut output =
        Encoder::with_capacity(commitment_bytes.len() + challenge_bytes.len() + proof.len() + 64);
    output.write_fixed_bytes(PAYLOAD_MAGIC);
    output.write_u16(PAYLOAD_VERSION);
    output.write_u16(commitment.nonce_mode.wire_id());
    output.write_bytes(&commitment_bytes);
    output.write_bytes(&challenge_bytes);
    output.write_bytes(proof);
    output.write_u16(FINAL_FRAME);
    output.write_u16(PAYLOAD_VERSION);
    let payload = output.into_bytes();
    if payload.len() > MAX_PROOF_BYTES {
        return Err(FastError::ResourceLimit);
    }
    Ok(payload)
}

fn decode_backend_payload(
    bytes: &[u8],
) -> Result<(FastPrecommitment, Option<SignedCommitmentChallenge>, &[u8]), FastError> {
    let limits = DecodeLimits::new(MAX_PROOF_BYTES, MAX_PROOF_BYTES);
    let mut input = Reader::new(bytes, limits).map_err(framing)?;
    if input
        .read_fixed_bytes(PAYLOAD_MAGIC.len())
        .map_err(framing)?
        != PAYLOAD_MAGIC
    {
        return Err(FastError::BadMagic);
    }
    if input.read_u16().map_err(framing)? != PAYLOAD_VERSION {
        return Err(FastError::UnsupportedVersion);
    }
    let mode = FastNonceMode::from_wire_id(input.read_u16().map_err(framing)?)
        .ok_or(FastError::UnsupportedVersion)?;
    let commitment_bytes = input.read_bytes().map_err(framing)?;
    if commitment_bytes.len() > MAX_PRECOMMITMENT_BYTES {
        return Err(FastError::ResourceLimit);
    }
    let commitment = FastPrecommitment::from_bytes(commitment_bytes)?;
    if commitment.nonce_mode != mode {
        return Err(FastError::NonceModeMismatch);
    }
    let challenge_bytes = input.read_bytes().map_err(framing)?;
    if challenge_bytes.len() > MAX_COMMITMENT_CHALLENGE_BYTES {
        return Err(FastError::ResourceLimit);
    }
    let challenge = if challenge_bytes.is_empty() {
        None
    } else {
        Some(SignedCommitmentChallenge::from_canonical_bytes(
            challenge_bytes,
        )?)
    };
    let proof = input.read_bytes().map_err(framing)?;
    if input.read_u16().map_err(framing)? != FINAL_FRAME
        || input.read_u16().map_err(framing)? != PAYLOAD_VERSION
    {
        return Err(FastError::UnsupportedVersion);
    }
    input.finish().map_err(framing)?;
    match (mode, challenge.is_some()) {
        (FastNonceMode::ExternalSigned, true) | (FastNonceMode::OfflineFiatShamir, false) => {}
        _ => return Err(FastError::NonceModeMismatch),
    }
    Ok((commitment, challenge, proof))
}

fn encode_proof(proof: &FastProof) -> Result<Vec<u8>, FastError> {
    let mut output = Encoder::new();
    output.write_u16(PROOF_VERSION);
    write_usize(&mut output, proof.logical_len)?;
    write_float(&mut output, proof.residual_squared_l2)?;
    write_sumcheck(&mut output, &proof.norm_sumcheck)?;
    write_float(&mut output, proof.residual_at_row_point)?;
    write_sumcheck(&mut output, &proof.matvec_sumcheck)?;
    write_float(&mut output, proof.solution_at_column_point)?;
    write_sumcheck(&mut output, &proof.opening_sumcheck)?;
    write_float(&mut output, proof.opening_endpoint)?;
    write_usize(&mut output, proof.folding.roots.len())?;
    for root in &proof.folding.roots {
        output.write_fixed_bytes(root);
    }
    write_usize(&mut output, proof.folding.round_openings.len())?;
    for openings in &proof.folding.round_openings {
        write_complex_multiproof(&mut output, openings)?;
    }
    write_complex(&mut output, proof.folding.final_values[0])?;
    write_complex(&mut output, proof.folding.final_values[1])?;
    output.write_u16(FINAL_FRAME);
    output.write_u16(PROOF_VERSION);
    let bytes = output.into_bytes();
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(FastError::ResourceLimit);
    }
    Ok(bytes)
}

fn decode_proof(bytes: &[u8], expected_logical_len: usize) -> Result<FastProof, FastError> {
    let limits = DecodeLimits::new(MAX_PROOF_BYTES, MAX_PROOF_BYTES);
    let mut input = Reader::new(bytes, limits).map_err(framing)?;
    if input.read_u16().map_err(framing)? != PROOF_VERSION {
        return Err(FastError::UnsupportedVersion);
    }
    let logical_len = read_usize(&mut input)?;
    if logical_len != expected_logical_len {
        return Err(FastError::TranscriptShape);
    }
    validate_length(logical_len)?;
    let padded_len = logical_len.next_power_of_two();
    let variables = padded_len.ilog2() as usize;
    let opening_variables = variables + 1;
    let residual_squared_l2 = read_float(&mut input)?;
    let norm_sumcheck = read_sumcheck(&mut input, variables)?;
    let residual_at_row_point = read_float(&mut input)?;
    let matvec_sumcheck = read_sumcheck(&mut input, variables)?;
    let solution_at_column_point = read_float(&mut input)?;
    let opening_sumcheck = read_sumcheck(&mut input, opening_variables)?;
    let opening_endpoint = read_float(&mut input)?;
    let root_count = input.read_length(opening_variables).map_err(framing)?;
    if root_count != opening_variables {
        return Err(FastError::TranscriptShape);
    }
    let mut roots = Vec::with_capacity(root_count);
    for _ in 0..root_count {
        roots.push(input.read_array().map_err(framing)?);
    }
    let opening_count = input.read_length(opening_variables).map_err(framing)?;
    if opening_count != opening_variables {
        return Err(FastError::TranscriptShape);
    }
    let query_count = Policy2::PROXIMITY_QUERY_TARGET.min(2 * padded_len);
    let mut domain_len = 4 * padded_len;
    let mut round_openings = Vec::with_capacity(opening_count);
    for _ in 0..opening_count {
        let maximum_values = (2 * query_count).min(domain_len);
        let maximum_frontier = maximum_values
            .checked_mul(domain_len.ilog2() as usize)
            .ok_or(FastError::ResourceLimit)?;
        round_openings.push(read_complex_multiproof(
            &mut input,
            maximum_values,
            maximum_frontier,
        )?);
        domain_len /= 2;
    }
    let final_values = [read_complex(&mut input)?, read_complex(&mut input)?];
    if input.read_u16().map_err(framing)? != FINAL_FRAME
        || input.read_u16().map_err(framing)? != PROOF_VERSION
    {
        return Err(FastError::UnsupportedVersion);
    }
    input.finish().map_err(framing)?;
    Ok(FastProof {
        logical_len,
        residual_squared_l2,
        norm_sumcheck,
        residual_at_row_point,
        matvec_sumcheck,
        solution_at_column_point,
        opening_sumcheck,
        opening_endpoint,
        folding: FoldingOpeningProof {
            roots,
            round_openings,
            final_values,
        },
    })
}

fn write_sumcheck(output: &mut Encoder, proof: &ProductSumcheckProof) -> Result<(), FastError> {
    write_usize(output, proof.rounds.len())?;
    for round in &proof.rounds {
        for value in round.coefficients {
            write_float(output, value)?;
        }
    }
    Ok(())
}

fn read_sumcheck(
    input: &mut Reader<'_>,
    expected_rounds: usize,
) -> Result<ProductSumcheckProof, FastError> {
    let rounds = input.read_length(expected_rounds).map_err(framing)?;
    if rounds != expected_rounds {
        return Err(FastError::TranscriptShape);
    }
    let mut result = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        result.push(QuadraticBernstein::new(
            read_float(input)?,
            read_float(input)?,
            read_float(input)?,
        ));
    }
    Ok(ProductSumcheckProof { rounds: result })
}

fn write_complex_multiproof(
    output: &mut Encoder,
    proof: &ComplexMultiProof,
) -> Result<(), FastError> {
    write_usize(output, proof.value_bits.len())?;
    for &[real_bits, imaginary_bits] in &proof.value_bits {
        ComplexValue::from_canonical_bits(real_bits, imaginary_bits)?;
        output.write_u64(real_bits);
        output.write_u64(imaginary_bits);
    }
    write_usize(output, proof.frontier.len())?;
    for root in &proof.frontier {
        output.write_fixed_bytes(root);
    }
    Ok(())
}

fn read_complex_multiproof(
    input: &mut Reader<'_>,
    maximum_values: usize,
    maximum_frontier: usize,
) -> Result<ComplexMultiProof, FastError> {
    let value_count = input.read_length(maximum_values).map_err(framing)?;
    if value_count == 0 {
        return Err(FastError::TranscriptShape);
    }
    let mut value_bits = Vec::with_capacity(value_count);
    for _ in 0..value_count {
        let real_bits = input.read_u64().map_err(framing)?;
        let imaginary_bits = input.read_u64().map_err(framing)?;
        ComplexValue::from_canonical_bits(real_bits, imaginary_bits)?;
        value_bits.push([real_bits, imaginary_bits]);
    }
    let frontier_count = input.read_length(maximum_frontier).map_err(framing)?;
    let mut frontier = Vec::with_capacity(frontier_count);
    for _ in 0..frontier_count {
        frontier.push(input.read_array().map_err(framing)?);
    }
    Ok(ComplexMultiProof {
        value_bits,
        frontier,
    })
}

fn write_complex(output: &mut Encoder, value: ComplexValue) -> Result<(), FastError> {
    write_float(output, value.real())?;
    write_float(output, value.imaginary())
}

fn read_complex(input: &mut Reader<'_>) -> Result<ComplexValue, FastError> {
    let real_bits = input.read_u64().map_err(framing)?;
    let imaginary_bits = input.read_u64().map_err(framing)?;
    Ok(ComplexValue::from_canonical_bits(
        real_bits,
        imaginary_bits,
    )?)
}

fn write_float(output: &mut Encoder, value: f64) -> Result<(), FastError> {
    output.write_u64(canonical_bits(value)?);
    Ok(())
}

fn read_float(input: &mut Reader<'_>) -> Result<f64, FastError> {
    Ok(decode_canonical_bits(input.read_u64().map_err(framing)?)?)
}

fn write_usize(output: &mut Encoder, value: usize) -> Result<(), FastError> {
    output.write_u64(u64::try_from(value).map_err(|_| FastError::ResourceLimit)?);
    Ok(())
}

fn read_usize(input: &mut Reader<'_>) -> Result<usize, FastError> {
    usize::try_from(input.read_u64().map_err(framing)?).map_err(|_| FastError::ResourceLimit)
}

fn framing(error: impl std::fmt::Display) -> FastError {
    FastError::Framing(error.to_string())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use ssv_problem::{
        BoundaryRule, DiagonalConstruction, InstanceSeed, MatrixSpec, OffDiagonalValues,
        ProblemTemplate, RequestedOutput, RhsSpec, TemplateRandomness, TemplateSchema,
    };
    use ssv_service_protocol::{
        CommitmentChallengePayload, CommitmentChallengeSchema, RetryPolicy, ValidationManifest,
    };

    use super::*;

    fn fixture(dimension: usize, period_bits: u8) -> (PublicStatement, Solution) {
        let problem = ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness: TemplateRandomness::LiteralV1 {
                seed: InstanceSeed::from_bytes([dimension as u8; 32]),
            },
            matrix: MatrixSpec::SeededSymmetricTridiagonalV1 {
                dimension: dimension as u64,
                boundary: BoundaryRule::TruncateV1,
                off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                    period_bits,
                    fractional_bits: 4,
                    minimum_magnitude_mantissa: 1,
                    maximum_magnitude_mantissa: 3,
                },
                diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 { margin_mantissa: 8 },
            },
            rhs: RhsSpec::ManufacturedOnesV1,
            requested_outputs: vec![RequestedOutput::SquaredL2ResidualV1],
        }
        .finalize_literal()
        .unwrap();
        let statement = PublicStatement::new(
            problem,
            ValidationManifest {
                protocol: ProofProtocol::FastBinary64UnitCircleV2,
                max_solution_elements: dimension as u64,
                max_public_matrix_terms: 1024,
                max_public_rhs_terms: 1024,
                ..ValidationManifest::default()
            },
            None,
        )
        .unwrap();
        let solution = Solution::new(vec![1.0; dimension], dimension).unwrap();
        (statement, solution)
    }

    fn offline_round_trip(dimension: usize) -> (Vec<u8>, FastVerifierReport) {
        let (statement, solution) = fixture(dimension, 2);
        let (commitment, _) = FastBackend::commit_offline(&statement, &solution).unwrap();
        let context = FastProverContext::offline_fiat_shamir(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        let report = FastBackend::verify(&statement.verifier_statement(), &payload).unwrap();
        (payload, report)
    }

    #[test]
    fn offline_query_only_backend_round_trips() {
        for dimension in [3, 5, 16] {
            let (_, report) = offline_round_trip(dimension);
            assert!(report.passes_policy(), "{:#?}", report.score);
            assert_eq!(report.nonce_mode, FastNonceMode::OfflineFiatShamir);
            assert!(report.external_challenge.is_none());
            assert_eq!(report.score.residual_squared_l2, 0.0);
            assert_eq!(report.work.generator_row_queries, 0);
            assert_eq!(report.work.solution_elements_materialized, 0);
            assert_eq!(report.work.residual_elements_materialized, 0);
            assert_eq!(report.work.codeword_elements_materialized, 0);
            let variables = dimension.next_power_of_two().ilog2() as u64;
            assert_eq!(report.work.sumcheck_rounds, 3 * variables + 1);
            assert_eq!(
                report.score.proximity_queries_per_round,
                (2 * dimension.next_power_of_two()).min(64) as u32
            );
        }
    }

    #[test]
    fn nonzero_residual_round_trip_checks_all_three_application_relations() {
        let (statement, _) = fixture(8, 2);
        let solution = Solution::new(vec![0.0; 8], 8).unwrap();
        let (commitment, _) = FastBackend::commit_offline(&statement, &solution).unwrap();
        let context = FastProverContext::offline_fiat_shamir(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        let report = FastBackend::verify(&statement.verifier_statement(), &payload).unwrap();
        assert!(report.passes_policy(), "{:#?}", report.score);
        assert_eq!(report.score.residual_squared_l2, 2.0);
        assert_eq!(report.score.residual_l2, 2.0_f64.sqrt());
        assert_eq!(report.score.residual_rms, 0.5);
        assert!(report.score.norm_sumcheck.checks > 0);
        assert!(report.score.matvec_sumcheck.checks > 0);
        assert!(report.score.linear_opening_sumcheck.checks > 0);
        assert!(report.score.unit_circle_folds.checks > 0);
    }

    #[test]
    fn fast_witness_does_not_inherit_the_exact_residual_range() {
        let (statement, _) = fixture(8, 2);
        let solution = Solution::new(vec![8.0; 8], 8).unwrap();
        assert!(matches!(
            ssv_relation::ExactRelation::from_solution(statement.generated(), &solution),
            Err(RelationError::ResidualOutOfRange { .. })
        ));

        let (commitment, _) = FastBackend::commit_offline(&statement, &solution).unwrap();
        let context = FastProverContext::offline_fiat_shamir(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        let report = FastBackend::verify(&statement.verifier_statement(), &payload).unwrap();
        assert!(report.passes_policy(), "{:#?}", report.score);
        assert!(report.score.residual_squared_l2 > 8.0);
    }

    #[test]
    fn external_signed_challenge_is_bound_and_returned_for_application_authentication() {
        let (statement, solution) = fixture(8, 2);
        let (commitment, _) = FastBackend::commit(&statement, &solution).unwrap();
        let challenge = SignedCommitmentChallenge::sign(
            CommitmentChallengePayload {
                schema: CommitmentChallengeSchema::V1,
                issuer: "test-issuer".to_owned(),
                key_id: "test-key".to_owned(),
                issued_at_unix_seconds: 100,
                expires_at_unix_seconds: 200,
                entropy: Digest::from_bytes([9; 32]),
                problem_digest: statement.problem_digest(),
                validation_manifest_digest: statement.manifest_digest(),
                protocol: ProofProtocol::FastBinary64UnitCircleV2,
                commitment_digest: commitment.digest(),
                retry_policy: RetryPolicy::ReplayAllowedV1,
            },
            &SigningKey::from_bytes(&[7; 32]),
        )
        .unwrap();
        let context = FastProverContext::external_signed(commitment, challenge.clone());
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        let preflight = FastBackend::preflight(&statement.verifier_statement(), &payload).unwrap();
        assert_eq!(preflight.nonce_mode, FastNonceMode::ExternalSigned);
        assert_eq!(preflight.external_challenge, Some(challenge.clone()));
        let report = FastBackend::verify(&statement.verifier_statement(), &payload).unwrap();
        assert!(report.passes_policy());
        assert_eq!(report.nonce_mode, FastNonceMode::ExternalSigned);
        assert_eq!(report.external_challenge, Some(challenge));
    }

    #[test]
    fn precommitment_and_payload_framing_are_strict_and_mutation_bound() {
        let (statement, solution) = fixture(8, 2);
        let (commitment, _) = FastBackend::commit_offline(&statement, &solution).unwrap();
        let encoded = commitment.to_bytes();
        assert_eq!(FastPrecommitment::from_bytes(&encoded).unwrap(), commitment);
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(FastPrecommitment::from_bytes(&trailing).is_err());
        for length in 0..encoded.len() {
            assert!(FastPrecommitment::from_bytes(&encoded[..length]).is_err());
        }

        let context = FastProverContext::offline_fiat_shamir(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(FastBackend::preflight(&statement.verifier_statement(), &trailing).is_err());
        assert!(FastBackend::verify(&statement.verifier_statement(), &trailing).is_err());
        let mut changed = payload;
        let offset = changed.len() / 2;
        changed[offset] ^= 1;
        let outcome = FastBackend::verify(&statement.verifier_statement(), &changed);
        assert!(outcome.is_err() || !outcome.unwrap().passes_policy());
    }

    #[test]
    fn statement_binding_and_inner_float_encoding_are_strict() {
        let (statement, solution) = fixture(8, 2);
        let (other_statement, _) = fixture(8, 3);
        let (commitment, _) = FastBackend::commit_offline(&statement, &solution).unwrap();
        let context = FastProverContext::offline_fiat_shamir(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        assert!(matches!(
            FastBackend::preflight(&other_statement.verifier_statement(), &payload),
            Err(FastError::StatementMismatch)
        ));
        assert!(matches!(
            FastBackend::verify(&other_statement.verifier_statement(), &payload),
            Err(FastError::StatementMismatch)
        ));

        let (commitment, challenge, proof) = decode_backend_payload(&payload).unwrap();
        assert!(challenge.is_none());
        let mut noncanonical = proof.to_vec();
        // proof-version u16, logical-length u64, then rho bits.
        noncanonical[10..18].copy_from_slice(&f64::NAN.to_bits().to_be_bytes());
        let changed = encode_backend_payload(&commitment, None, &noncanonical).unwrap();
        assert!(matches!(
            FastBackend::verify(&statement.verifier_statement(), &changed),
            Err(FastError::Float(FloatContractError::NonFinite))
        ));

        let mut inner_trailing = proof.to_vec();
        inner_trailing.push(0);
        let changed = encode_backend_payload(&commitment, None, &inner_trailing).unwrap();
        assert!(FastBackend::verify(&statement.verifier_statement(), &changed).is_err());
    }

    #[test]
    fn external_challenge_cannot_be_rebound_to_another_commitment() {
        let (statement, solution) = fixture(8, 2);
        let (commitment, _) = FastBackend::commit(&statement, &solution).unwrap();
        let challenge = SignedCommitmentChallenge::sign(
            CommitmentChallengePayload {
                schema: CommitmentChallengeSchema::V1,
                issuer: "test-issuer".to_owned(),
                key_id: "test-key".to_owned(),
                issued_at_unix_seconds: 100,
                expires_at_unix_seconds: 200,
                entropy: Digest::from_bytes([9; 32]),
                problem_digest: statement.problem_digest(),
                validation_manifest_digest: statement.manifest_digest(),
                protocol: ProofProtocol::FastBinary64UnitCircleV2,
                commitment_digest: Digest::from_bytes([0; 32]),
                retry_policy: RetryPolicy::ReplayAllowedV1,
            },
            &SigningKey::from_bytes(&[7; 32]),
        )
        .unwrap();
        let context = FastProverContext::external_signed(commitment, challenge);
        assert!(matches!(
            FastBackend::prove(&statement, &solution, &context),
            Err(FastError::CommitmentChallengeMismatch)
        ));
    }

    #[test]
    fn verifier_work_uses_only_the_succinct_capability_and_scales_with_description() {
        let (small_payload, small) = offline_round_trip(64);
        let (large_payload, large) = offline_round_trip(256);
        for report in [&small, &large] {
            assert_eq!(report.work.generator_row_queries, 0);
            assert_eq!(report.work.solution_elements_materialized, 0);
            assert_eq!(report.work.residual_elements_materialized, 0);
            assert_eq!(report.work.codeword_elements_materialized, 0);
            assert!(report.work.public_matrix_period_terms <= 4);
            assert_eq!(report.work.public_rhs_period_terms, 1);
        }
        assert_eq!(large.work.sumcheck_rounds - small.work.sumcheck_rounds, 6);
        assert!(large_payload.len() < small_payload.len() * 3);
        assert!(large.work.public_matrix_arithmetic_operations < 4 * 256);
    }
}
