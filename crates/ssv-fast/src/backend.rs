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
use std::mem::size_of;

use ssv_canonical::{DecodeLimits, Digest, Encoder, Reader, domain_separated_digest};
use ssv_problem::{
    BooleanCoordinateOrder, F64RoundoffDiagnostics, GeneratedProblem, MleEvaluationError,
    PublicEvaluationMetadata, SuccinctPublicEvaluator,
};
use ssv_service_protocol::ProofProtocol;
use ssv_solution::Solution;
use ssv_validation::{
    PrecommitBackend, PublicStatement, ValidationBackend, ValidationCancellation, VerifierStatement,
};
use thiserror::Error;

use crate::float_contract::{
    FloatContractError, canonical_bits, canonicalize_arithmetic, canonicalize_source,
    decode_canonical_bits,
};
use crate::merkle::{
    ChunkHashAlgorithm, ChunkedComplexTree, ComplexMultiProof, MerkleError, MerkleRoot,
    build_chunked_complex_tree_iter, chunked_complex_multiproof_from_tree_iter,
    chunked_complex_opened_value_bits, streaming_chunked_complex_root_iter,
    streaming_complex_multiproof_iter, streaming_complex_root, streaming_complex_root_iter,
    verify_chunked_complex_multiproof, verify_complex_multiproof,
};
use crate::score::{
    DefectAccumulator, FastValidationScore, POLICY_3, Policy3, RelativeErrorObservation,
    conditional_miss_probabilities,
};
use crate::sumcheck::{
    ProductSumcheckProof, QuadraticBernstein, SumcheckError, product_sum, prove_product_owned,
    verify_product, verify_product_endpoint,
};
use crate::transcript::{Transcript, TranscriptError};
use crate::unit_circle::{ComplexValue, UnitCircleCodeword, UnitCircleError, fold_pair_at_index};

const PRECOMMIT_MAGIC: &[u8; 8] = b"SSVFCM\0\0";
const PRECOMMIT_VERSION: u16 = 6;
const PAYLOAD_MAGIC: &[u8; 8] = b"SSVFST\0\0";
const PAYLOAD_VERSION: u16 = 6;
const PROOF_VERSION: u16 = 6;
const FINAL_FRAME: u16 = u16::MAX;
const PRECOMMIT_DIGEST_DOMAIN: &[u8] = b"sparse-solve/fast-precommitment/v6";
const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"sparse-solve/fast-backend-payload/v6";
const PROTOCOL_LABEL: &[u8] = b"sparse-solve/fast/coefficient-unit-circle-linear-opening/v6";
const CHUNKED_PROTOCOL_LABEL: &[u8] =
    b"sparse-solve/fast/coefficient-unit-circle-linear-opening/chunked/v1";
const CHUNKED_SHA256_PROTOCOL_LABEL: &[u8] =
    b"sparse-solve/fast/coefficient-unit-circle-linear-opening/chunked-sha256/v1";
const FLOAT_CONTRACT: &[u8] =
    b"binary64/rne/no-fma/reject-nan-inf-negzero-subnormal/unit-circle-coeff/v2";
const CODE_BASIS: &[u8] =
    b"packed-[x||R]/msb-mle/bit-reversed-monomial-coefficients/unit-circle-rate-1/2";
const ORACLE_TREE_LABEL: &[u8] = b"ssv-fast/v6/packed-unit-circle-oracle";
const CHUNKED_ORACLE_TREE_LABEL: &[u8] = b"ssv-fast/chunked-v1/packed-unit-circle-oracle";
const CHUNKED_SHA256_ORACLE_TREE_LABEL: &[u8] =
    b"ssv-fast/chunked-sha256-v1/packed-unit-circle-oracle";
const MAX_PRECOMMITMENT_BYTES: usize = 4096;
const MAX_PROOF_BYTES: usize = ssv_validation::MAX_SUCCINCT_PAYLOAD_BYTES;
/// Maximum preflight estimate for backend-owned fast-prover memory.
///
/// The estimate excludes the caller-owned problem and solution and allocator
/// metadata. Allocation failure below this deterministic ceiling is still
/// reported as [`FastError::ResourceLimit`].
pub const MAX_FAST_PROVER_ESTIMATED_BACKEND_PEAK_BYTES: usize = 1024 * 1024 * 1024;
const FAST_PROVER_FIXED_PEAK_BYTES: usize = 2 * MAX_PROOF_BYTES;
// At the opening-sumcheck peak the backend owns solution and residual tables
// (2n f64), packed values and weights (4n f64), and less than 8n retained
// complex evaluations across the geometric folding hierarchy.
const FAST_PROVER_PEAK_BYTES_PER_PADDED_ELEMENT: usize =
    6 * size_of::<f64>() + 8 * size_of::<ComplexValue>();
// Chunked V6 additionally retains fewer than 16N bytes of flat Merkle nodes
// across the geometric folding hierarchy.
const CHUNKED_TREE_PEAK_BYTES_PER_PADDED_ELEMENT: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FastFlavor {
    PerValueV5,
    ChunkedV6,
    ChunkedSha256V7,
}

impl FastFlavor {
    fn from_protocol(protocol: ProofProtocol) -> Result<Self, FastError> {
        match protocol {
            ProofProtocol::FastBinary64UnitCircleV5 => Ok(Self::PerValueV5),
            ProofProtocol::FastBinary64UnitCircleChunkedV6 => Ok(Self::ChunkedV6),
            ProofProtocol::FastBinary64UnitCircleChunkedSha256V7 => Ok(Self::ChunkedSha256V7),
            _ => Err(FastError::WrongProtocol),
        }
    }

    const fn protocol_label(self) -> &'static [u8] {
        match self {
            Self::PerValueV5 => PROTOCOL_LABEL,
            Self::ChunkedV6 => CHUNKED_PROTOCOL_LABEL,
            Self::ChunkedSha256V7 => CHUNKED_SHA256_PROTOCOL_LABEL,
        }
    }

    const fn oracle_tree_label(self) -> &'static [u8] {
        match self {
            Self::PerValueV5 => ORACLE_TREE_LABEL,
            Self::ChunkedV6 => CHUNKED_ORACLE_TREE_LABEL,
            Self::ChunkedSha256V7 => CHUNKED_SHA256_ORACLE_TREE_LABEL,
        }
    }

    const fn chunk_hash_algorithm(self) -> Option<ChunkHashAlgorithm> {
        match self {
            Self::PerValueV5 => None,
            Self::ChunkedV6 => Some(ChunkHashAlgorithm::Blake3),
            Self::ChunkedSha256V7 => Some(ChunkHashAlgorithm::Sha256),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EvaluatorBinding {
    evaluator_version: u16,
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
        if metadata.evaluator_version == 0
            || metadata.domain.coordinate_order != BooleanCoordinateOrder::MostSignificantFirst
        {
            return Err(FastError::TranscriptShape);
        }
        Ok(Self {
            evaluator_version: metadata.evaluator_version,
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
        output.write_u16(self.evaluator_version);
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
            evaluator_version: input.read_u16().map_err(framing)?,
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
        if result.evaluator_version == 0
            || result.logical_dimension < 2
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
    protocol: ProofProtocol,
    statement_digest: Digest,
    problem_digest: Digest,
    manifest_digest: Digest,
    evaluator: EvaluatorBinding,
    packed_source_len: usize,
    polynomial_degree: usize,
    codeword_len: usize,
    packed_codeword_root: MerkleRoot,
}

impl FastPrecommitment {
    #[must_use]
    pub const fn logical_len(&self) -> usize {
        self.evaluator.logical_dimension
    }

    #[must_use]
    pub const fn protocol(&self) -> ProofProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn codeword_len(&self) -> usize {
        self.codeword_len
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
        let policy = POLICY_3.transcript_parameters();
        let mut output = Encoder::with_capacity(384);
        output.write_fixed_bytes(PRECOMMIT_MAGIC);
        output.write_u16(PRECOMMIT_VERSION);
        output.write_u16(self.protocol.wire_id());
        output.write_u16(policy.policy_id);
        output.write_u64(policy.norm_zero_scale_bits);
        output.write_u64(policy.matvec_zero_scale_bits);
        output.write_u64(policy.linear_opening_zero_scale_bits);
        output.write_u64(policy.unit_circle_fold_zero_scale_bits);
        output.write_u64(policy.proximity_query_target);
        output.write_digest(&self.statement_digest);
        output.write_digest(&self.problem_digest);
        output.write_digest(&self.manifest_digest);
        output.write_bytes(CODE_BASIS);
        output.write_bytes(FLOAT_CONTRACT);
        self.evaluator.encode(&mut output)?;
        write_usize(&mut output, self.packed_source_len)?;
        write_usize(&mut output, self.polynomial_degree)?;
        write_usize(&mut output, self.codeword_len)?;
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
        if input.read_u16().map_err(framing)? != PRECOMMIT_VERSION {
            return Err(FastError::UnsupportedVersion);
        }
        let protocol = ProofProtocol::from_wire_id(input.read_u16().map_err(framing)?)
            .ok_or(FastError::UnsupportedVersion)?;
        FastFlavor::from_protocol(protocol)?;
        let expected = POLICY_3.transcript_parameters();
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
                expected.norm_zero_scale_bits,
                expected.matvec_zero_scale_bits,
                expected.linear_opening_zero_scale_bits,
                expected.unit_circle_fold_zero_scale_bits,
                expected.proximity_query_target,
            )
        {
            return Err(FastError::PolicyMismatch);
        }
        let statement_digest = input.read_digest().map_err(framing)?;
        let problem_digest = input.read_digest().map_err(framing)?;
        let manifest_digest = input.read_digest().map_err(framing)?;
        if input.read_bytes().map_err(framing)? != CODE_BASIS
            || input.read_bytes().map_err(framing)? != FLOAT_CONTRACT
        {
            return Err(FastError::UnsupportedVersion);
        }
        let evaluator = EvaluatorBinding::decode(&mut input)?;
        let packed_source_len = read_usize(&mut input)?;
        let polynomial_degree = read_usize(&mut input)?;
        let codeword_len = read_usize(&mut input)?;
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
            protocol,
            statement_digest,
            problem_digest,
            manifest_digest,
            evaluator,
            packed_source_len,
            polynomial_degree,
            codeword_len,
            packed_codeword_root,
        })
    }
}

/// Locally staged commitment supplied to the noninteractive prover.
///
/// The commitment is fixed before any algebraic challenge. Every challenge is
/// then derived by Fiat--Shamir from the public statement and transcript prefix;
/// there is no backend-specific postcommit nonce or challenge mode.
#[derive(Clone, Debug)]
pub struct FastProverContext {
    commitment: FastPrecommitment,
}

impl FastProverContext {
    #[must_use]
    pub const fn new(commitment: FastPrecommitment) -> Self {
        Self { commitment }
    }

    #[must_use]
    pub const fn commitment(&self) -> &FastPrecommitment {
        &self.commitment
    }
}

impl From<FastPrecommitment> for FastProverContext {
    fn from(commitment: FastPrecommitment) -> Self {
        Self::new(commitment)
    }
}

/// Work and identity reported by one standalone precommitment operation.
///
/// A separately invoked proof reports its own recomputation and scans; staged
/// end-to-end accounting is the sum of the two reports.
#[derive(Clone, Debug)]
pub struct FastCommitmentReport {
    pub precommitment_digest: Digest,
    pub packed_codeword_root: MerkleRoot,
    pub logical_len: usize,
    pub codeword_len: usize,
    pub material_preparations: u64,
    pub rows_scanned: u64,
    pub nonzeros_scanned: u64,
    /// Conservative preflight estimate for backend-owned prover memory.
    pub estimated_backend_peak_bytes: usize,
    pub codeword_folds: u64,
    /// Complete Merkle-root reductions, excluding root-free multiproof scans.
    pub merkle_root_computations: u64,
    /// Root-free scans that construct canonical multiproof frontiers.
    pub merkle_multiproof_passes: u64,
}

/// Work and identity reported by one proof-producing operation.
///
/// Counters cover the selected call: either the complete one-step operation or
/// the standalone proof phase, including its mandatory material recomputation.
#[derive(Clone, Debug)]
pub struct FastProverReport {
    pub payload_digest: Digest,
    pub precommitment_digest: Digest,
    pub packed_codeword_root: MerkleRoot,
    pub logical_len: usize,
    pub codeword_len: usize,
    pub proximity_queries_per_round: u32,
    pub squared_l2_claim: f64,
    pub payload_bytes: usize,
    pub material_preparations: u64,
    pub rows_scanned: u64,
    pub nonzeros_scanned: u64,
    /// Conservative preflight estimate for backend-owned prover memory.
    pub estimated_backend_peak_bytes: usize,
    pub codeword_folds: u64,
    /// Complete Merkle-root reductions, excluding root-free multiproof scans.
    pub merkle_root_computations: u64,
    /// Root-free scans that construct canonical multiproof frontiers.
    pub merkle_multiproof_passes: u64,
}

/// Cheap, bounded framing and statement-binding preflight for validators.
///
/// This validates strict outer framing and the complete precommitment against
/// the public statement. It deliberately does not decode or execute sumchecks
/// and Merkle queries.
#[derive(Clone, Debug)]
pub struct FastPreflight {
    pub payload_digest: Digest,
    pub precommitment_digest: Digest,
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

/// Stable location for one approximate relation observation.
///
/// The relation family is supplied by the owning field of
/// [`FastVerifierDiagnostics`]. Sumcheck vectors contain one entry per round
/// followed by an endpoint entry. Fold vectors identify both the transcript
/// query trajectory and fold round, plus the two final-value checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FastDiagnosticLocation {
    SumcheckRound { round: u32 },
    SumcheckEndpoint,
    UnitCircleFold { query_index: u64, round: u32 },
    UnitCircleFinalValue { value_index: u8 },
}

/// Per-check provenance for every approximate relation family.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FastDiagnosticObservation {
    pub location: FastDiagnosticLocation,
    pub observation: RelativeErrorObservation,
}

#[derive(Clone, Debug, Default)]
pub struct FastVerifierDiagnostics {
    pub norm_sumcheck: Vec<FastDiagnosticObservation>,
    pub matvec_sumcheck: Vec<FastDiagnosticObservation>,
    pub linear_opening_sumcheck: Vec<FastDiagnosticObservation>,
    pub unit_circle_folds: Vec<FastDiagnosticObservation>,
}

/// Public-MLE roundoff provenance computed while verifying the transcript.
///
/// These diagnostics retain the verifier's actual RHS and matrix evaluation
/// bounds and operand scales. They are inputs to a future a-posteriori error
/// theorem, not acceptance thresholds for the present approximate protocol.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FastPublicEvaluationDiagnostics {
    /// Diagnostics for the public RHS MLE at the shared row challenge.
    pub rhs: F64RoundoffDiagnostics,
    /// Diagnostics for the public matrix MLE at the row and column challenges.
    pub matrix: F64RoundoffDiagnostics,
}

/// Structurally and cryptographically authenticated diagnostic result.
///
/// Approximate discrepancies are reported without imposing a quality verdict.
#[derive(Clone, Debug)]
pub struct FastVerifierReport {
    pub payload_digest: Digest,
    pub precommitment_digest: Digest,
    pub packed_codeword_root: MerkleRoot,
    pub score: FastValidationScore,
    pub diagnostics: FastVerifierDiagnostics,
    pub public_evaluations: FastPublicEvaluationDiagnostics,
    pub work: FastVerifierWork,
}

#[derive(Debug, Error)]
pub enum FastError {
    #[error("fast backend requires a registered fast binary64 protocol")]
    WrongProtocol,
    #[error("fast artifact has an unrecognized magic value")]
    BadMagic,
    #[error("unsupported fast precommitment, payload, policy, or frame version")]
    UnsupportedVersion,
    #[error("fast artifact framing is invalid: {0}")]
    Framing(String),
    #[error("fast artifact exceeds a fixed resource bound")]
    ResourceLimit,
    #[error("fast verification was cancelled")]
    Cancelled,
    #[error("fast artifact is bound to a different public statement")]
    StatementMismatch,
    #[error("fast artifact is bound to a different registered public evaluator")]
    EvaluatorMismatch,
    #[error("fast precommitment does not match the supplied solution")]
    PrecommitmentMismatch,
    #[error("fast policy parameters differ from frozen policy 3")]
    PolicyMismatch,
    #[error("fast transcript shape is inconsistent with the public statement")]
    TranscriptShape,
    #[error("fast transcript contains an unexpected Merkle opening index")]
    UnexpectedOpeningIndex,
    #[error("binary64 contract failed: {0}")]
    Float(#[from] FloatContractError),
    #[error("unit-circle encoding failed: {0}")]
    UnitCircle(UnitCircleError),
    #[error("Merkle authentication failed: {0}")]
    Merkle(#[from] MerkleError),
    #[error("metric sumcheck failed structurally: {0}")]
    Sumcheck(#[from] SumcheckError),
    #[error("Fiat--Shamir transcript failed: {0}")]
    Transcript(#[from] TranscriptError),
    #[error("registered public evaluator failed: {0}")]
    PublicEvaluator(#[from] MleEvaluationError),
    #[error("binary64 protocol arithmetic produced a non-finite value")]
    NonFiniteComputation,
}

/// Experimental fast backend marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct FastBackend;

/// Experimental fast backend with 32 adjacent evaluations per Merkle leaf.
#[derive(Clone, Copy, Debug, Default)]
pub struct FastChunkedBackend;

/// Experimental fast backend using SHA-256 for chunked Merkle compression.
#[derive(Clone, Copy, Debug, Default)]
pub struct FastChunkedSha256Backend;

impl From<UnitCircleError> for FastError {
    fn from(error: UnitCircleError) -> Self {
        match error {
            UnitCircleError::AllocationFailed | UnitCircleError::SizeOverflow => {
                Self::ResourceLimit
            }
            error => Self::UnitCircle(error),
        }
    }
}

struct PreparedMaterial {
    logical_len: usize,
    padded_len: usize,
    solution: Vec<f64>,
    residual: Vec<f64>,
    packed: Vec<f64>,
    codeword: UnitCircleCodeword,
    root: MerkleRoot,
    chunked_tree: Option<ChunkedComplexTree>,
    estimated_backend_peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FastProverWork {
    material_preparations: u64,
    rows_scanned: u64,
    nonzeros_scanned: u64,
    codeword_folds: u64,
    merkle_root_computations: u64,
    merkle_multiproof_passes: u64,
}

impl FastProverWork {
    fn record_material_preparation(&mut self, problem: &GeneratedProblem) -> Result<(), FastError> {
        self.material_preparations = self
            .material_preparations
            .checked_add(1)
            .ok_or(FastError::ResourceLimit)?;
        self.record_sparse_scan(problem)
    }

    fn record_sparse_scan(&mut self, problem: &GeneratedProblem) -> Result<(), FastError> {
        self.rows_scanned = self
            .rows_scanned
            .checked_add(u64::try_from(problem.dimension()).map_err(|_| FastError::ResourceLimit)?)
            .ok_or(FastError::ResourceLimit)?;
        self.nonzeros_scanned = self
            .nonzeros_scanned
            .checked_add(
                u64::try_from(problem.structural_nnz()).map_err(|_| FastError::ResourceLimit)?,
            )
            .ok_or(FastError::ResourceLimit)?;
        Ok(())
    }

    fn record_codeword_fold(&mut self) -> Result<(), FastError> {
        self.codeword_folds = self
            .codeword_folds
            .checked_add(1)
            .ok_or(FastError::ResourceLimit)?;
        Ok(())
    }

    fn record_merkle_root_computation(&mut self) -> Result<(), FastError> {
        self.merkle_root_computations = self
            .merkle_root_computations
            .checked_add(1)
            .ok_or(FastError::ResourceLimit)?;
        Ok(())
    }

    fn record_merkle_multiproof_pass(&mut self) -> Result<(), FastError> {
        self.merkle_multiproof_passes = self
            .merkle_multiproof_passes
            .checked_add(1)
            .ok_or(FastError::ResourceLimit)?;
        Ok(())
    }
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
    /// Constructs a complete local proof while preparing private material once.
    ///
    /// The commitment is still fixed before any Fiat--Shamir challenge. Unlike
    /// the checkpointable [`ValidationBackend::prove`] path, this operation
    /// retains its private buffers between commitment and proof construction
    /// because both phases execute in the same process.
    pub fn prove_single_stage(
        statement: &PublicStatement,
        solution: &Solution,
    ) -> Result<(Vec<u8>, FastProverReport), FastError> {
        prove_single_stage_backend(statement, solution)
    }

    /// Fixes the packed oracle before any Fiat--Shamir challenge is derived.
    ///
    /// Proof construction remains a separate deterministic stage so callers
    /// may persist or inspect the commitment without introducing an external
    /// challenge lifecycle.
    pub fn commit(
        statement: &PublicStatement,
        solution: &Solution,
    ) -> Result<(FastPrecommitment, FastCommitmentReport), FastError> {
        commit_backend(statement, solution)
    }

    /// Performs cheap framing and statement-binding preflight before
    /// algebraic verification.
    pub fn preflight(
        statement: &VerifierStatement<'_>,
        payload: &[u8],
    ) -> Result<FastPreflight, FastError> {
        Ok(preflight_backend(statement, payload)?.report)
    }

    /// Verifies without a cancellation source.
    pub fn verify(
        statement: &VerifierStatement<'_>,
        payload: &[u8],
    ) -> Result<FastVerifierReport, FastError> {
        Self::verify_with_cancellation(statement, payload, &ValidationCancellation::never())
    }

    /// Verifies while polling a cooperative-cancellation signal.
    pub fn verify_with_cancellation(
        statement: &VerifierStatement<'_>,
        payload: &[u8],
        cancellation: &ValidationCancellation,
    ) -> Result<FastVerifierReport, FastError> {
        verify_backend(statement, payload, cancellation)
    }
}

impl FastChunkedBackend {
    /// Constructs a complete local chunked-leaf proof while preparing private
    /// material once.
    pub fn prove_single_stage(
        statement: &PublicStatement,
        solution: &Solution,
    ) -> Result<(Vec<u8>, FastProverReport), FastError> {
        prove_single_stage_backend(statement, solution)
    }

    /// Performs cheap framing and statement-binding preflight before
    /// algebraic verification.
    pub fn preflight(
        statement: &VerifierStatement<'_>,
        payload: &[u8],
    ) -> Result<FastPreflight, FastError> {
        Ok(preflight_backend(statement, payload)?.report)
    }
}

impl FastChunkedSha256Backend {
    /// Constructs a complete local SHA-256 chunked-leaf proof while preparing
    /// private material once.
    pub fn prove_single_stage(
        statement: &PublicStatement,
        solution: &Solution,
    ) -> Result<(Vec<u8>, FastProverReport), FastError> {
        prove_single_stage_backend(statement, solution)
    }

    /// Performs cheap framing and statement-binding preflight before
    /// algebraic verification.
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

    const PROTOCOL: ProofProtocol = ProofProtocol::FastBinary64UnitCircleV5;

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
        cancellation: &ValidationCancellation,
    ) -> Result<Self::VerifierReport, Self::Error> {
        verify_backend(statement, payload, cancellation)
    }
}

impl PrecommitBackend for FastBackend {
    type Commitment = FastPrecommitment;
    type CommitmentReport = FastCommitmentReport;

    fn commit(
        statement: &PublicStatement,
        solution: &Solution,
    ) -> Result<(Self::Commitment, Self::CommitmentReport), Self::Error> {
        commit_backend(statement, solution)
    }
}

impl ValidationBackend for FastChunkedBackend {
    type ProverContext = FastProverContext;
    type ProverReport = FastProverReport;
    type VerifierReport = FastVerifierReport;
    type Error = FastError;

    const PROTOCOL: ProofProtocol = ProofProtocol::FastBinary64UnitCircleChunkedV6;

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
        cancellation: &ValidationCancellation,
    ) -> Result<Self::VerifierReport, Self::Error> {
        verify_backend(statement, payload, cancellation)
    }
}

impl PrecommitBackend for FastChunkedBackend {
    type Commitment = FastPrecommitment;
    type CommitmentReport = FastCommitmentReport;

    fn commit(
        statement: &PublicStatement,
        solution: &Solution,
    ) -> Result<(Self::Commitment, Self::CommitmentReport), Self::Error> {
        commit_backend(statement, solution)
    }
}

impl ValidationBackend for FastChunkedSha256Backend {
    type ProverContext = FastProverContext;
    type ProverReport = FastProverReport;
    type VerifierReport = FastVerifierReport;
    type Error = FastError;

    const PROTOCOL: ProofProtocol = ProofProtocol::FastBinary64UnitCircleChunkedSha256V7;

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
        cancellation: &ValidationCancellation,
    ) -> Result<Self::VerifierReport, Self::Error> {
        verify_backend(statement, payload, cancellation)
    }
}

impl PrecommitBackend for FastChunkedSha256Backend {
    type Commitment = FastPrecommitment;
    type CommitmentReport = FastCommitmentReport;

    fn commit(
        statement: &PublicStatement,
        solution: &Solution,
    ) -> Result<(Self::Commitment, Self::CommitmentReport), Self::Error> {
        commit_backend(statement, solution)
    }
}

fn commit_backend(
    statement: &PublicStatement,
    solution: &Solution,
) -> Result<(FastPrecommitment, FastCommitmentReport), FastError> {
    let mut work = FastProverWork::default();
    let material = prepare_statement_material(statement, solution, &mut work)?;
    let commitment = make_statement_precommitment(statement, &material)?;
    let report = FastCommitmentReport {
        precommitment_digest: commitment.digest(),
        packed_codeword_root: commitment.packed_codeword_root,
        logical_len: commitment.logical_len(),
        codeword_len: commitment.codeword_len,
        material_preparations: work.material_preparations,
        rows_scanned: work.rows_scanned,
        nonzeros_scanned: work.nonzeros_scanned,
        estimated_backend_peak_bytes: material.estimated_backend_peak_bytes,
        codeword_folds: work.codeword_folds,
        merkle_root_computations: work.merkle_root_computations,
        merkle_multiproof_passes: work.merkle_multiproof_passes,
    };
    Ok((commitment, report))
}

fn prove_single_stage_backend(
    statement: &PublicStatement,
    solution: &Solution,
) -> Result<(Vec<u8>, FastProverReport), FastError> {
    let mut work = FastProverWork::default();
    let material = prepare_statement_material(statement, solution, &mut work)?;
    let commitment = make_statement_precommitment(statement, &material)?;
    prove_prepared(statement, material, &commitment, work)
}

fn prove_backend(
    statement: &PublicStatement,
    solution: &Solution,
    context: &FastProverContext,
) -> Result<(Vec<u8>, FastProverReport), FastError> {
    let mut work = FastProverWork::default();
    let material = prepare_statement_material(statement, solution, &mut work)?;
    let commitment = context.commitment();
    let expected = make_statement_precommitment(statement, &material)?;
    if commitment != &expected {
        return Err(FastError::PrecommitmentMismatch);
    }
    prove_prepared(statement, material, commitment, work)
}

fn prove_prepared(
    statement: &PublicStatement,
    material: PreparedMaterial,
    commitment: &FastPrecommitment,
    mut work: FastProverWork,
) -> Result<(Vec<u8>, FastProverReport), FastError> {
    let flavor = FastFlavor::from_protocol(commitment.protocol)?;
    let mut transcript = initialize_transcript(commitment)?;

    // The norm endpoint is reused as the row-compression point, authenticating
    // one residual MLE value for both application relations.
    let padded_residual = pad_vector(&material.residual, material.padded_len)?;
    let residual_squared_l2 =
        canonical_protocol_float(product_sum(&padded_residual, &padded_residual)?)?;
    absorb_float(
        &mut transcript,
        b"residual-squared-l2-claim",
        residual_squared_l2,
    )?;
    let residual_right = copy_f64_slice(&padded_residual)?;
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
        &mut work,
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

    let codeword_message_len = material.codeword.message_len();
    let codeword_len = material.codeword.evaluations().len();
    let opening_rounds = codeword_message_len.ilog2() as usize;
    let mut fold_levels = Vec::new();
    fold_levels
        .try_reserve_exact(
            opening_rounds
                .checked_add(1)
                .ok_or(FastError::ResourceLimit)?,
        )
        .map_err(|_| FastError::ResourceLimit)?;
    fold_levels.push(material.codeword);
    let mut fold_trees = Vec::new();
    fold_trees
        .try_reserve_exact(
            opening_rounds
                .checked_add(1)
                .ok_or(FastError::ResourceLimit)?,
        )
        .map_err(|_| FastError::ResourceLimit)?;
    fold_trees.push(material.chunked_tree);
    let mut fold_roots = Vec::new();
    fold_roots
        .try_reserve_exact(opening_rounds)
        .map_err(|_| FastError::ResourceLimit)?;
    let mut fold_challenges = Vec::new();
    fold_challenges
        .try_reserve_exact(opening_rounds)
        .map_err(|_| FastError::ResourceLimit)?;
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
                let fold_result = (|| -> Result<_, FastError> {
                    let current = fold_levels.last().ok_or(FastError::TranscriptShape)?;
                    let next = current.fold(challenge)?;
                    work.record_codeword_fold()?;
                    let label = oracle_tree_label(flavor, round + 1, next.evaluations().len());
                    let (root, tree) = complex_root_and_cache(flavor, &label, next.evaluations())?;
                    work.record_merkle_root_computation()?;
                    Ok((next, root, tree))
                })();
                match fold_result {
                    Ok((next, root, tree)) => {
                        // The child root is fixed before the next polynomial
                        // and challenge enter the transcript.
                        transcript.absorb_root(b"linear-opening-fold-root", &root);
                        fold_roots.push(root);
                        fold_levels.push(next);
                        fold_trees.push(tree);
                    }
                    Err(error) => {
                        fold_error = Some(error);
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
    let final_codeword = fold_levels.last().ok_or(FastError::TranscriptShape)?;
    if final_codeword.message_len() != 1 || final_codeword.evaluations().len() != 2 {
        return Err(FastError::TranscriptShape);
    }

    // Query locations are derived only after every recursive oracle is fixed.
    let query_plan = draw_query_plan(&mut transcript, codeword_message_len)?;
    let folding = build_folding_opening(
        flavor,
        fold_levels,
        fold_trees,
        &fold_roots,
        &fold_challenges,
        &query_plan,
        &mut work,
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
    let payload = encode_backend_payload(commitment, &proof_bytes)?;
    if payload.len() > MAX_PROOF_BYTES {
        return Err(FastError::ResourceLimit);
    }
    let report = FastProverReport {
        payload_digest: domain_separated_digest(PAYLOAD_DIGEST_DOMAIN, &payload),
        precommitment_digest: commitment.digest(),
        packed_codeword_root: commitment.packed_codeword_root,
        logical_len: material.logical_len,
        codeword_len,
        proximity_queries_per_round: query_plan.indices.len() as u32,
        squared_l2_claim: residual_squared_l2,
        payload_bytes: payload.len(),
        material_preparations: work.material_preparations,
        rows_scanned: work.rows_scanned,
        nonzeros_scanned: work.nonzeros_scanned,
        estimated_backend_peak_bytes: material.estimated_backend_peak_bytes,
        codeword_folds: work.codeword_folds,
        merkle_root_computations: work.merkle_root_computations,
        merkle_multiproof_passes: work.merkle_multiproof_passes,
    };
    Ok((payload, report))
}

fn verify_backend(
    statement: &VerifierStatement<'_>,
    payload_bytes: &[u8],
    cancellation: &ValidationCancellation,
) -> Result<FastVerifierReport, FastError> {
    require_not_cancelled(cancellation)?;
    let preflight = preflight_backend(statement, payload_bytes)?;
    require_not_cancelled(cancellation)?;
    let commitment = preflight.commitment;
    let flavor = FastFlavor::from_protocol(commitment.protocol)?;
    let proof = decode_proof(preflight.proof_bytes, statement.dimension(), flavor)?;
    require_not_cancelled(cancellation)?;
    let padded_len = commitment.evaluator.padded_dimension;
    let variables = commitment.evaluator.variables;
    let opening_variables = variables + 1;
    let mut transcript = initialize_transcript(&commitment)?;

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
    require_not_cancelled(cancellation)?;
    let mut norm_defects = DefectAccumulator::policy3_norm_sumcheck();
    let mut norm_observations = Vec::with_capacity(norm_verification.round_defects.len() + 1);
    for (round, &observation) in norm_verification.round_defects.iter().enumerate() {
        norm_observations.push(FastDiagnosticObservation {
            location: FastDiagnosticLocation::SumcheckRound {
                round: u32::try_from(round).map_err(|_| FastError::ResourceLimit)?,
            },
            observation: norm_defects.observe(observation),
        });
    }
    norm_observations.push(FastDiagnosticObservation {
        location: FastDiagnosticLocation::SumcheckEndpoint,
        observation: norm_defects.observe(verify_product_endpoint(
            &norm_verification.endpoint,
            proof.residual_at_row_point,
            proof.residual_at_row_point,
        )?),
    });
    absorb_float(
        &mut transcript,
        b"residual-at-shared-row-point",
        proof.residual_at_row_point,
    )?;

    let rhs = statement
        .public_evaluator()
        .evaluate_rhs_mle_f64(&norm_verification.endpoint.point)?;
    require_not_cancelled(cancellation)?;
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
    require_not_cancelled(cancellation)?;
    let matrix = statement.public_evaluator().evaluate_matrix_mle_f64(
        &norm_verification.endpoint.point,
        &matvec_verification.endpoint.point,
    )?;
    require_not_cancelled(cancellation)?;
    let mut matvec_defects = DefectAccumulator::policy3_matvec_sumcheck();
    let mut matvec_observations = Vec::with_capacity(matvec_verification.round_defects.len() + 1);
    for (round, &observation) in matvec_verification.round_defects.iter().enumerate() {
        matvec_observations.push(FastDiagnosticObservation {
            location: FastDiagnosticLocation::SumcheckRound {
                round: u32::try_from(round).map_err(|_| FastError::ResourceLimit)?,
            },
            observation: matvec_defects.observe(observation),
        });
    }
    matvec_observations.push(FastDiagnosticObservation {
        location: FastDiagnosticLocation::SumcheckEndpoint,
        observation: matvec_defects.observe(verify_product_endpoint(
            &matvec_verification.endpoint,
            matrix.value,
            proof.solution_at_column_point,
        )?),
    });
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
    require_not_cancelled(cancellation)?;
    let expected_weight_endpoint = combined_form_evaluation(
        &matvec_verification.endpoint.point,
        &norm_verification.endpoint.point,
        batching_challenge,
        &opening_verification.endpoint.point,
    )?;
    let mut opening_defects = DefectAccumulator::policy3_linear_opening_sumcheck();
    let mut opening_observations = Vec::with_capacity(opening_verification.round_defects.len() + 1);
    for (round, &observation) in opening_verification.round_defects.iter().enumerate() {
        opening_observations.push(FastDiagnosticObservation {
            location: FastDiagnosticLocation::SumcheckRound {
                round: u32::try_from(round).map_err(|_| FastError::ResourceLimit)?,
            },
            observation: opening_defects.observe(observation),
        });
    }
    opening_observations.push(FastDiagnosticObservation {
        location: FastDiagnosticLocation::SumcheckEndpoint,
        observation: opening_defects.observe(verify_product_endpoint(
            &opening_verification.endpoint,
            proof.opening_endpoint,
            expected_weight_endpoint,
        )?),
    });
    absorb_float(
        &mut transcript,
        b"linear-opening-source-endpoint",
        proof.opening_endpoint,
    )?;

    let query_plan = draw_query_plan(&mut transcript, 2 * padded_len)?;
    let (fold_summary, fold_observations, merkle_hashes, opening_paths) = verify_folding_opening(
        flavor,
        commitment.packed_codeword_root,
        &proof.folding,
        &opening_verification.endpoint.point,
        proof.opening_endpoint,
        &query_plan,
        cancellation,
    )?;
    require_not_cancelled(cancellation)?;

    let norm_sumcheck = norm_defects.finish();
    let matvec_sumcheck = matvec_defects.finish();
    let linear_opening_sumcheck = opening_defects.finish();
    let squared_l2_claim = proof.residual_squared_l2;
    let residual_l2_claim = canonical_protocol_float(squared_l2_claim.sqrt())?;
    let residual_rms_claim =
        canonical_protocol_float((squared_l2_claim / statement.dimension() as f64).sqrt())?;
    let score = FastValidationScore {
        norm_sumcheck,
        matvec_sumcheck,
        linear_opening_sumcheck,
        unit_circle_folds: fold_summary,
        squared_l2_claim,
        residual_l2_claim,
        residual_rms_claim,
        proximity_queries_per_round: query_plan.indices.len() as u32,
        conditional_miss_probability_upper_bound: conditional_miss_probabilities(
            query_plan.indices.len(),
        ),
    };
    let diagnostics = FastVerifierDiagnostics {
        norm_sumcheck: norm_observations,
        matvec_sumcheck: matvec_observations,
        linear_opening_sumcheck: opening_observations,
        unit_circle_folds: fold_observations,
    };
    let public_evaluations = FastPublicEvaluationDiagnostics {
        rhs: rhs.roundoff,
        matrix: matrix.roundoff,
    };

    let sumcheck_rounds = (2 * variables + opening_variables) as u64;
    let query_workspace_bytes = opening_variables
        .checked_mul(2 * Policy3::PROXIMITY_QUERY_TARGET)
        .and_then(|value| value.checked_mul(std::mem::size_of::<usize>()))
        .ok_or(FastError::ResourceLimit)?;
    let claim_bytes = opening_variables
        .checked_mul(std::mem::size_of::<f64>())
        .and_then(|value| value.checked_add(4 * std::mem::size_of::<f64>()))
        .ok_or(FastError::ResourceLimit)?;
    let diagnostic_observation_capacity = diagnostics
        .norm_sumcheck
        .capacity()
        .checked_add(diagnostics.matvec_sumcheck.capacity())
        .and_then(|value| value.checked_add(diagnostics.linear_opening_sumcheck.capacity()))
        .and_then(|value| value.checked_add(diagnostics.unit_circle_folds.capacity()))
        .ok_or(FastError::ResourceLimit)?;
    let diagnostic_bytes = diagnostic_observation_capacity
        .checked_mul(std::mem::size_of::<FastDiagnosticObservation>())
        .ok_or(FastError::ResourceLimit)?;
    let accounted_high_watermark_bytes = payload_bytes
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_add(query_workspace_bytes))
        .and_then(|value| value.checked_add(claim_bytes))
        .and_then(|value| value.checked_add(diagnostic_bytes))
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
        packed_codeword_root: commitment.packed_codeword_root,
        score,
        diagnostics,
        public_evaluations,
        work,
    })
}

fn preflight_backend<'a>(
    statement: &VerifierStatement<'_>,
    payload_bytes: &'a [u8],
) -> Result<DecodedPreflight<'a>, FastError> {
    FastFlavor::from_protocol(statement.protocol())?;
    if payload_bytes.len() > MAX_PROOF_BYTES {
        return Err(FastError::ResourceLimit);
    }
    let (commitment, proof_bytes) = decode_backend_payload(payload_bytes)?;
    let expected_evaluator =
        EvaluatorBinding::from_metadata(statement.public_evaluator().metadata())?;
    if commitment.statement_digest != statement.transcript_digest()
        || commitment.protocol != statement.protocol()
        || commitment.problem_digest != statement.problem_digest()
        || commitment.manifest_digest != statement.manifest_digest()
        || commitment.evaluator != expected_evaluator
        || commitment.logical_len() != statement.dimension()
    {
        return Err(FastError::StatementMismatch);
    }
    Ok(DecodedPreflight {
        report: FastPreflight {
            payload_digest: domain_separated_digest(PAYLOAD_DIGEST_DOMAIN, payload_bytes),
            precommitment_digest: commitment.digest(),
        },
        commitment,
        proof_bytes,
    })
}

fn validate_prover_statement(statement: &PublicStatement) -> Result<(), FastError> {
    FastFlavor::from_protocol(statement.manifest().protocol)?;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FastProverMemoryEstimate {
    padded_len: usize,
    estimated_backend_peak_bytes: usize,
}

fn fast_prover_memory_preflight(
    logical_len: usize,
    flavor: FastFlavor,
) -> Result<FastProverMemoryEstimate, FastError> {
    validate_length(logical_len)?;
    let padded_len = logical_len
        .checked_next_power_of_two()
        .ok_or(FastError::ResourceLimit)?;
    let bytes_per_element = match flavor {
        FastFlavor::PerValueV5 => FAST_PROVER_PEAK_BYTES_PER_PADDED_ELEMENT,
        FastFlavor::ChunkedV6 | FastFlavor::ChunkedSha256V7 => {
            FAST_PROVER_PEAK_BYTES_PER_PADDED_ELEMENT
                .checked_add(CHUNKED_TREE_PEAK_BYTES_PER_PADDED_ELEMENT)
                .ok_or(FastError::ResourceLimit)?
        }
    };
    let variable_bytes = padded_len
        .checked_mul(bytes_per_element)
        .ok_or(FastError::ResourceLimit)?;
    let estimated_backend_peak_bytes = variable_bytes
        .checked_add(FAST_PROVER_FIXED_PEAK_BYTES)
        .ok_or(FastError::ResourceLimit)?;
    if estimated_backend_peak_bytes > MAX_FAST_PROVER_ESTIMATED_BACKEND_PEAK_BYTES {
        return Err(FastError::ResourceLimit);
    }
    Ok(FastProverMemoryEstimate {
        padded_len,
        estimated_backend_peak_bytes,
    })
}

fn prepare_statement_material(
    statement: &PublicStatement,
    solution: &Solution,
    work: &mut FastProverWork,
) -> Result<PreparedMaterial, FastError> {
    validate_prover_statement(statement)?;
    prepare_material(
        statement.generated(),
        solution,
        work,
        FastFlavor::from_protocol(statement.manifest().protocol)?,
    )
}

fn make_statement_precommitment(
    statement: &PublicStatement,
    material: &PreparedMaterial,
) -> Result<FastPrecommitment, FastError> {
    make_precommitment(
        statement.manifest().protocol,
        statement.transcript_digest(),
        statement.problem_digest(),
        statement.manifest_digest(),
        EvaluatorBinding::from_metadata(statement.generated().public_evaluation_plan().metadata())?,
        material,
    )
}

fn make_precommitment(
    protocol: ProofProtocol,
    statement_digest: Digest,
    problem_digest: Digest,
    manifest_digest: Digest,
    evaluator: EvaluatorBinding,
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
        protocol,
        statement_digest,
        problem_digest,
        manifest_digest,
        evaluator,
        packed_source_len,
        polynomial_degree,
        codeword_len,
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
    work: &mut FastProverWork,
    flavor: FastFlavor,
) -> Result<PreparedMaterial, FastError> {
    let logical_len = problem.dimension();
    let memory = fast_prover_memory_preflight(logical_len, flavor)?;
    let padded_len = memory.padded_len;

    if solution.as_slice().len() != logical_len {
        return Err(FastError::TranscriptShape);
    }
    // The fast profile proves against the caller's canonical binary64 values.
    // Q63.64 conversion belongs exclusively to the exact profile and is not a
    // hidden admission requirement for this provisional floating-point path.
    let mut binary64_solution = Vec::new();
    binary64_solution
        .try_reserve_exact(logical_len)
        .map_err(|_| FastError::ResourceLimit)?;
    for &value in solution.as_slice() {
        binary64_solution.push(canonicalize_source(value)?);
    }
    let solution = binary64_solution;
    let residual = compute_residual(problem, &solution)?;
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
    let label = oracle_tree_label(flavor, 0, codeword.evaluations().len());
    let (root, chunked_tree) = complex_root_and_cache(flavor, &label, codeword.evaluations())?;
    work.record_merkle_root_computation()?;
    work.record_material_preparation(problem)?;
    Ok(PreparedMaterial {
        logical_len,
        padded_len,
        solution,
        residual,
        packed,
        codeword,
        root,
        chunked_tree,
        estimated_backend_peak_bytes: memory.estimated_backend_peak_bytes,
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
    work: &mut FastProverWork,
) -> Result<MatVecTables, FastError> {
    let table_len = problem.dimension().next_power_of_two();
    if row_point.len() != table_len.ilog2() as usize || solution.len() != problem.dimension() {
        return Err(FastError::TranscriptShape);
    }
    let weights = equality_table(row_point)?;
    let mut compressed_columns = zeroed_f64_vec(table_len)?;
    for (row, &weight) in weights.iter().take(problem.dimension()).enumerate() {
        for entry in problem.row(row).ok_or(FastError::TranscriptShape)? {
            let product = canonical_protocol_float(weight * entry.value.to_f64())?;
            compressed_columns[entry.column] =
                canonical_protocol_float(compressed_columns[entry.column] + product)?;
        }
    }
    work.record_sparse_scan(problem)?;
    Ok(MatVecTables {
        compressed_columns,
        solution: pad_vector(solution, table_len)?,
    })
}

fn initialize_transcript(commitment: &FastPrecommitment) -> Result<Transcript, FastError> {
    let commitment_bytes = commitment.try_to_bytes()?;
    let flavor = FastFlavor::from_protocol(commitment.protocol)?;
    let mut transcript = Transcript::new(flavor.protocol_label());
    // The semantic public statement is fixed independently (and may carry the
    // application's signed problem provenance). Absorb it before the packed
    // oracle commitment so every subsequent challenge has the canonical
    // noninteractive order `statement -> commitment -> prover message`.
    transcript.absorb_bytes(
        b"public-statement-digest",
        commitment.statement_digest.as_bytes(),
    );
    transcript.absorb_bytes(b"canonical-precommitment", &commitment_bytes);
    transcript.absorb_bytes(b"precommitment-digest", commitment.digest().as_bytes());
    transcript.absorb_bytes(b"code-basis", CODE_BASIS);
    transcript.absorb_bytes(b"float-contract", FLOAT_CONTRACT);
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
    let output_len = padded_len.checked_mul(2).ok_or(FastError::ResourceLimit)?;
    let mut weights = zeroed_f64_vec(output_len)?;
    let (solution_weights, residual_weights) = weights.split_at_mut(padded_len);
    fill_equality_table(solution_weights, solution_point)?;
    fill_equality_table(residual_weights, residual_point)?;
    for value in residual_weights {
        *value = canonical_protocol_float(batching_challenge * *value)?;
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
    let mut table = zeroed_f64_vec(final_len)?;
    fill_equality_table(&mut table, point)?;
    Ok(table)
}

fn fill_equality_table(table: &mut [f64], point: &[f64]) -> Result<(), FastError> {
    let final_len = 1_usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| FastError::ResourceLimit)?)
        .ok_or(FastError::ResourceLimit)?;
    if table.len() != final_len {
        return Err(FastError::TranscriptShape);
    }
    table.fill(0.0);
    table[0] = 1.0;
    let mut active_len = 1_usize;
    for &coordinate in point {
        for index in (0..active_len).rev() {
            let weight = table[index];
            table[2 * index] = canonical_protocol_float(weight * (1.0 - coordinate))?;
            table[2 * index + 1] = canonical_protocol_float(weight * coordinate)?;
        }
        active_len = active_len.checked_mul(2).ok_or(FastError::ResourceLimit)?;
    }
    debug_assert_eq!(active_len, final_len);
    Ok(())
}

fn pad_vector(values: &[f64], len: usize) -> Result<Vec<f64>, FastError> {
    if values.len() > len {
        return Err(FastError::TranscriptShape);
    }
    let mut padded = zeroed_f64_vec(len)?;
    padded[..values.len()].copy_from_slice(values);
    Ok(padded)
}

fn zeroed_f64_vec(len: usize) -> Result<Vec<f64>, FastError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(len)
        .map_err(|_| FastError::ResourceLimit)?;
    values.resize(len, 0.0);
    Ok(values)
}

fn copy_f64_slice(values: &[f64]) -> Result<Vec<f64>, FastError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(values.len())
        .map_err(|_| FastError::ResourceLimit)?;
    copy.extend_from_slice(values);
    Ok(copy)
}

fn canonical_protocol_float(value: f64) -> Result<f64, FastError> {
    canonicalize_arithmetic(value).map_err(FastError::Float)
}

#[cfg(test)]
fn complex_root(
    flavor: FastFlavor,
    label: &[u8],
    values: &[ComplexValue],
) -> Result<MerkleRoot, FastError> {
    let bits = values.iter().copied().map(ComplexValue::canonical_bits);
    Ok(match flavor {
        FastFlavor::PerValueV5 => streaming_complex_root_iter(label, bits)?,
        FastFlavor::ChunkedV6 | FastFlavor::ChunkedSha256V7 => streaming_chunked_complex_root_iter(
            flavor
                .chunk_hash_algorithm()
                .ok_or(FastError::TranscriptShape)?,
            label,
            bits,
        )?,
    })
}

fn complex_root_and_cache(
    flavor: FastFlavor,
    label: &[u8],
    values: &[ComplexValue],
) -> Result<(MerkleRoot, Option<ChunkedComplexTree>), FastError> {
    let bits = values.iter().copied().map(ComplexValue::canonical_bits);
    match flavor {
        FastFlavor::PerValueV5 => Ok((streaming_complex_root_iter(label, bits)?, None)),
        FastFlavor::ChunkedV6 | FastFlavor::ChunkedSha256V7 => {
            let tree = build_chunked_complex_tree_iter(
                flavor
                    .chunk_hash_algorithm()
                    .ok_or(FastError::TranscriptShape)?,
                label,
                bits,
            )?;
            Ok((tree.root(), Some(tree)))
        }
    }
}

fn oracle_tree_label(flavor: FastFlavor, round: usize, domain_len: usize) -> Vec<u8> {
    let prefix = flavor.oracle_tree_label();
    let mut label = Vec::with_capacity(prefix.len() + 16);
    label.extend_from_slice(prefix);
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
    flavor: FastFlavor,
    levels: Vec<UnitCircleCodeword>,
    trees: Vec<Option<ChunkedComplexTree>>,
    roots: &[MerkleRoot],
    challenges: &[f64],
    query_plan: &QueryPlan,
    work: &mut FastProverWork,
) -> Result<FoldingOpeningProof, FastError> {
    let initial = levels.first().ok_or(FastError::TranscriptShape)?;
    if roots.len() != challenges.len()
        || roots.len() != initial.message_len().ilog2() as usize
        || levels.len() != roots.len().checked_add(1).ok_or(FastError::ResourceLimit)?
        || trees.len() != levels.len()
    {
        return Err(FastError::TranscriptShape);
    }
    let mut round_openings = Vec::new();
    round_openings
        .try_reserve_exact(challenges.len())
        .map_err(|_| FastError::ResourceLimit)?;
    for (round, current) in levels.iter().take(challenges.len()).enumerate() {
        let child = &levels[round + 1];
        if current.message_len().checked_div(2) != Some(child.message_len())
            || current.evaluations().len().checked_div(2) != Some(child.evaluations().len())
        {
            return Err(FastError::TranscriptShape);
        }
        let selected = selected_indices_for_round(query_plan, current.evaluations().len())?;
        let label = oracle_tree_label(flavor, round, current.evaluations().len());
        let bits = current
            .evaluations()
            .iter()
            .copied()
            .map(ComplexValue::canonical_bits);
        let openings = match flavor {
            FastFlavor::PerValueV5 => streaming_complex_multiproof_iter(&label, bits, &selected)?,
            FastFlavor::ChunkedV6 | FastFlavor::ChunkedSha256V7 => {
                let tree = trees[round].as_ref().ok_or(FastError::TranscriptShape)?;
                chunked_complex_multiproof_from_tree_iter(
                    flavor
                        .chunk_hash_algorithm()
                        .ok_or(FastError::TranscriptShape)?,
                    tree,
                    &label,
                    bits,
                    &selected,
                )?
            }
        };
        work.record_merkle_multiproof_pass()?;
        round_openings.push(openings);
    }
    let final_codeword = levels.last().ok_or(FastError::TranscriptShape)?;
    if final_codeword.evaluations().len() != 2 {
        return Err(FastError::TranscriptShape);
    }
    let mut proof_roots = Vec::new();
    proof_roots
        .try_reserve_exact(roots.len())
        .map_err(|_| FastError::ResourceLimit)?;
    proof_roots.extend_from_slice(roots);
    Ok(FoldingOpeningProof {
        roots: proof_roots,
        round_openings,
        final_values: [
            final_codeword.evaluations()[0],
            final_codeword.evaluations()[1],
        ],
    })
}

fn verify_folding_opening(
    flavor: FastFlavor,
    initial_root: MerkleRoot,
    proof: &FoldingOpeningProof,
    challenges: &[f64],
    opening_endpoint: f64,
    query_plan: &QueryPlan,
    cancellation: &ValidationCancellation,
) -> Result<
    (
        crate::score::DefectSummary,
        Vec<FastDiagnosticObservation>,
        u64,
        u64,
    ),
    FastError,
> {
    if proof.roots.len() != challenges.len()
        || proof.round_openings.len() != challenges.len()
        || challenges.is_empty()
    {
        return Err(FastError::TranscriptShape);
    }
    let shift = u32::try_from(challenges.len() + 1).map_err(|_| FastError::ResourceLimit)?;
    let initial_domain = 1_usize.checked_shl(shift).ok_or(FastError::ResourceLimit)?;
    let final_label = oracle_tree_label(flavor, challenges.len(), 2);
    let final_bits = proof.final_values.map(ComplexValue::canonical_bits);
    let final_root = match flavor {
        FastFlavor::PerValueV5 => streaming_complex_root(&final_label, &final_bits)?,
        FastFlavor::ChunkedV6 | FastFlavor::ChunkedSha256V7 => streaming_chunked_complex_root_iter(
            flavor
                .chunk_hash_algorithm()
                .ok_or(FastError::TranscriptShape)?,
            &final_label,
            final_bits.into_iter(),
        )?,
    };
    if final_root != *proof.roots.last().ok_or(FastError::TranscriptShape)? {
        return Err(FastError::TranscriptShape);
    }

    let mut domain_len = initial_domain;
    let mut merkle_hashes = 3_u64;
    let mut opening_paths = 0_u64;
    let mut round_indices = Vec::with_capacity(challenges.len());
    for round in 0..challenges.len() {
        require_not_cancelled(cancellation)?;
        let expected_indices = selected_indices_for_round(query_plan, domain_len)?;
        let openings = &proof.round_openings[round];
        let root = if round == 0 {
            initial_root
        } else {
            proof.roots[round - 1]
        };
        let label = oracle_tree_label(flavor, round, domain_len);
        let round_hashes = match flavor {
            FastFlavor::PerValueV5 => {
                verify_complex_multiproof(&label, domain_len, &root, &expected_indices, openings)?
            }
            FastFlavor::ChunkedV6 | FastFlavor::ChunkedSha256V7 => {
                verify_chunked_complex_multiproof(
                    flavor
                        .chunk_hash_algorithm()
                        .ok_or(FastError::TranscriptShape)?,
                    &label,
                    domain_len,
                    &root,
                    &expected_indices,
                    openings,
                )?
            }
        };
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

    let mut defects = DefectAccumulator::policy3_unit_circle_folds();
    let observation_count = query_plan
        .indices
        .len()
        .checked_mul(challenges.len())
        .and_then(|value| value.checked_add(proof.final_values.len()))
        .ok_or(FastError::ResourceLimit)?;
    let mut observations = Vec::new();
    observations
        .try_reserve_exact(observation_count)
        .map_err(|_| FastError::ResourceLimit)?;
    for &base_index in &query_plan.indices {
        require_not_cancelled(cancellation)?;
        let query_index = u64::try_from(base_index).map_err(|_| FastError::ResourceLimit)?;
        let mut index = base_index;
        let mut current_domain = initial_domain;
        for round in 0..challenges.len() {
            let half = current_domain / 2;
            let low_index = index % half;
            let current_openings = &proof.round_openings[round];
            let at_z = opened_value(
                flavor,
                current_domain,
                &round_indices[round],
                current_openings,
                low_index,
            )?;
            let at_negative_z = opened_value(
                flavor,
                current_domain,
                &round_indices[round],
                current_openings,
                low_index + half,
            )?;
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
                    flavor,
                    current_domain / 2,
                    &round_indices[round + 1],
                    &proof.round_openings[round + 1],
                    low_index,
                )?
            };
            observations.push(FastDiagnosticObservation {
                location: FastDiagnosticLocation::UnitCircleFold {
                    query_index,
                    round: u32::try_from(round).map_err(|_| FastError::ResourceLimit)?,
                },
                observation: defects.observe_unit_circle_fold(actual, expected),
            });
            index = low_index;
            current_domain = half;
        }
    }
    let claimed = ComplexValue::from_real(opening_endpoint)?;
    for (value_index, &value) in proof.final_values.iter().enumerate() {
        observations.push(FastDiagnosticObservation {
            location: FastDiagnosticLocation::UnitCircleFinalValue {
                value_index: u8::try_from(value_index).map_err(|_| FastError::ResourceLimit)?,
            },
            observation: defects.observe_unit_circle_fold(value, claimed),
        });
    }
    debug_assert_eq!(observations.len(), observation_count);
    Ok((defects.finish(), observations, merkle_hashes, opening_paths))
}

fn require_not_cancelled(cancellation: &ValidationCancellation) -> Result<(), FastError> {
    if cancellation.is_cancelled() {
        return Err(FastError::Cancelled);
    }
    Ok(())
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
    flavor: FastFlavor,
    value_count: usize,
    expected_indices: &[usize],
    openings: &ComplexMultiProof,
    index: usize,
) -> Result<ComplexValue, FastError> {
    let [real_bits, imaginary_bits] = match flavor {
        FastFlavor::PerValueV5 => {
            let position = expected_indices
                .binary_search(&index)
                .map_err(|_| FastError::UnexpectedOpeningIndex)?;
            *openings
                .value_bits
                .get(position)
                .ok_or(FastError::TranscriptShape)?
        }
        FastFlavor::ChunkedV6 | FastFlavor::ChunkedSha256V7 => {
            chunked_complex_opened_value_bits(value_count, expected_indices, openings, index)?
        }
    };
    Ok(ComplexValue::from_canonical_bits(
        real_bits,
        imaginary_bits,
    )?)
}

fn draw_query_plan(
    transcript: &mut Transcript,
    message_len: usize,
) -> Result<QueryPlan, FastError> {
    let count = Policy3::PROXIMITY_QUERY_TARGET.min(message_len);
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
    proof: &[u8],
) -> Result<Vec<u8>, FastError> {
    let commitment_bytes = commitment.try_to_bytes()?;
    if commitment_bytes.len() > MAX_PRECOMMITMENT_BYTES || proof.len() > MAX_PROOF_BYTES {
        return Err(FastError::ResourceLimit);
    }
    let mut output = Encoder::with_capacity(commitment_bytes.len() + proof.len() + 64);
    output.write_fixed_bytes(PAYLOAD_MAGIC);
    output.write_u16(PAYLOAD_VERSION);
    output.write_bytes(&commitment_bytes);
    output.write_bytes(proof);
    output.write_u16(FINAL_FRAME);
    output.write_u16(PAYLOAD_VERSION);
    let payload = output.into_bytes();
    if payload.len() > MAX_PROOF_BYTES {
        return Err(FastError::ResourceLimit);
    }
    Ok(payload)
}

fn decode_backend_payload(bytes: &[u8]) -> Result<(FastPrecommitment, &[u8]), FastError> {
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
    let commitment_bytes = input.read_bytes().map_err(framing)?;
    if commitment_bytes.len() > MAX_PRECOMMITMENT_BYTES {
        return Err(FastError::ResourceLimit);
    }
    let commitment = FastPrecommitment::from_bytes(commitment_bytes)?;
    let proof = input.read_bytes().map_err(framing)?;
    if input.read_u16().map_err(framing)? != FINAL_FRAME
        || input.read_u16().map_err(framing)? != PAYLOAD_VERSION
    {
        return Err(FastError::UnsupportedVersion);
    }
    input.finish().map_err(framing)?;
    Ok((commitment, proof))
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

fn decode_proof(
    bytes: &[u8],
    expected_logical_len: usize,
    flavor: FastFlavor,
) -> Result<FastProof, FastError> {
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
    let query_count = Policy3::PROXIMITY_QUERY_TARGET.min(2 * padded_len);
    let mut domain_len = 4 * padded_len;
    let mut round_openings = Vec::with_capacity(opening_count);
    for _ in 0..opening_count {
        let maximum_values = match flavor {
            FastFlavor::PerValueV5 => (2 * query_count).min(domain_len),
            FastFlavor::ChunkedV6 | FastFlavor::ChunkedSha256V7 => (2 * query_count)
                .checked_mul(crate::merkle::COMPLEX_VALUES_PER_CHUNK)
                .ok_or(FastError::ResourceLimit)?
                .min(domain_len),
        };
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
    use ssv_problem::{
        BoundaryRule, DiagonalConstruction, InstanceSeed, MatrixSpec, OffDiagonalValues,
        ProblemTemplate, RequestedOutput, RhsSpec, TemplateRandomness, TemplateSchema,
    };
    use ssv_service_protocol::ValidationManifest;

    use super::*;

    fn fixture(dimension: usize, period_bits: u8) -> (PublicStatement, Solution) {
        fixture_for_protocol(
            dimension,
            period_bits,
            ProofProtocol::FastBinary64UnitCircleV5,
        )
    }

    fn fixture_for_protocol(
        dimension: usize,
        period_bits: u8,
        protocol: ProofProtocol,
    ) -> (PublicStatement, Solution) {
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
                protocol,
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

    fn reference_equality_table(point: &[f64]) -> Vec<f64> {
        let mut table = vec![1.0];
        for &coordinate in point {
            let mut next = Vec::with_capacity(table.len() * 2);
            for &weight in &table {
                next.push(canonical_protocol_float(weight * (1.0 - coordinate)).unwrap());
                next.push(canonical_protocol_float(weight * coordinate).unwrap());
            }
            table = next;
        }
        table
    }

    #[test]
    fn in_place_equality_tables_preserve_the_reference_bits() {
        let points = [
            vec![],
            vec![0.0],
            vec![1.0],
            vec![0.25, 0.75],
            vec![0.125, 0.5, 0.875],
        ];
        for point in &points {
            let expected = reference_equality_table(point);
            let actual = equality_table(point).unwrap();
            assert_eq!(
                actual
                    .iter()
                    .map(|value| value.to_bits())
                    .collect::<Vec<_>>(),
                expected
                    .iter()
                    .map(|value| value.to_bits())
                    .collect::<Vec<_>>()
            );
        }

        let solution_point = [0.25, 0.75, 0.5];
        let residual_point = [0.875, 0.125, 1.0];
        let batching_challenge = 0.375;
        let mut expected = reference_equality_table(&solution_point);
        expected.extend(
            reference_equality_table(&residual_point)
                .into_iter()
                .map(|value| canonical_protocol_float(batching_challenge * value).unwrap()),
        );
        let actual = combined_opening_weights(
            expected.len() / 2,
            &solution_point,
            &residual_point,
            batching_challenge,
        )
        .unwrap();
        assert_eq!(
            actual
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn prover_memory_preflight_has_a_checked_power_of_two_boundary() {
        let accepted = fast_prover_memory_preflight(1 << 22, FastFlavor::PerValueV5).unwrap();
        assert_eq!(accepted.padded_len, 1 << 22);
        assert_eq!(
            accepted.estimated_backend_peak_bytes,
            FAST_PROVER_FIXED_PEAK_BYTES + (1 << 22) * FAST_PROVER_PEAK_BYTES_PER_PADDED_ELEMENT
        );
        let chunked = fast_prover_memory_preflight(1 << 22, FastFlavor::ChunkedV6).unwrap();
        assert_eq!(
            chunked.estimated_backend_peak_bytes,
            accepted.estimated_backend_peak_bytes
                + (1 << 22) * CHUNKED_TREE_PEAK_BYTES_PER_PADDED_ELEMENT
        );
        assert!(
            accepted.estimated_backend_peak_bytes <= MAX_FAST_PROVER_ESTIMATED_BACKEND_PEAK_BYTES
        );
        assert!(matches!(
            fast_prover_memory_preflight(1 << 23, FastFlavor::PerValueV5),
            Err(FastError::ResourceLimit)
        ));
        assert!(matches!(
            FastError::from(UnitCircleError::AllocationFailed),
            FastError::ResourceLimit
        ));
    }

    fn round_trip(dimension: usize) -> (Vec<u8>, FastVerifierReport) {
        let (statement, solution) = fixture(dimension, 2);
        let (commitment, _) = FastBackend::commit(&statement, &solution).unwrap();
        let context = FastProverContext::new(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        let report = FastBackend::verify(&statement.verifier_statement(), &payload).unwrap();
        (payload, report)
    }

    fn calibration_fixture() -> PublicStatement {
        let problem = ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness: TemplateRandomness::LiteralV1 {
                seed: InstanceSeed::from_bytes([16; 32]),
            },
            matrix: MatrixSpec::SeededSymmetricTridiagonalV1 {
                dimension: 16,
                boundary: BoundaryRule::TruncateV1,
                off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                    period_bits: 0,
                    fractional_bits: 52,
                    minimum_magnitude_mantissa: 1,
                    maximum_magnitude_mantissa: 1,
                },
                diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 {
                    margin_mantissa: 1024,
                },
            },
            rhs: RhsSpec::ManufacturedOnesV1,
            requested_outputs: vec![RequestedOutput::SquaredL2ResidualV1],
        }
        .finalize_literal()
        .unwrap();
        PublicStatement::new(
            problem,
            ValidationManifest {
                protocol: ProofProtocol::FastBinary64UnitCircleV5,
                max_solution_elements: 16,
                max_public_matrix_terms: 1024,
                max_public_rhs_terms: 1024,
                ..ValidationManifest::default()
            },
            None,
        )
        .unwrap()
    }

    fn zero_sumcheck(rounds: usize) -> ProductSumcheckProof {
        ProductSumcheckProof {
            rounds: vec![QuadraticBernstein::new(0.0, 0.0, 0.0); rounds],
        }
    }

    #[test]
    fn noninteractive_query_only_backend_round_trips() {
        for dimension in [3, 5, 16] {
            let (payload, report) = round_trip(dimension);
            assert_eq!(report.score.squared_l2_claim, 0.0);
            assert_eq!(
                report.diagnostics.norm_sumcheck.len() as u64,
                report.score.norm_sumcheck.checks
            );
            assert_eq!(
                report.diagnostics.matvec_sumcheck.len() as u64,
                report.score.matvec_sumcheck.checks
            );
            assert_eq!(
                report.diagnostics.linear_opening_sumcheck.len() as u64,
                report.score.linear_opening_sumcheck.checks
            );
            assert_eq!(
                report.diagnostics.unit_circle_folds.len() as u64,
                report.score.unit_circle_folds.checks
            );
            assert!(matches!(
                report
                    .diagnostics
                    .norm_sumcheck
                    .last()
                    .map(|observation| observation.location),
                Some(FastDiagnosticLocation::SumcheckEndpoint)
            ));
            assert!(matches!(
                report
                    .diagnostics
                    .matvec_sumcheck
                    .last()
                    .map(|observation| observation.location),
                Some(FastDiagnosticLocation::SumcheckEndpoint)
            ));
            assert!(matches!(
                report
                    .diagnostics
                    .linear_opening_sumcheck
                    .last()
                    .map(|observation| observation.location),
                Some(FastDiagnosticLocation::SumcheckEndpoint)
            ));
            assert!(
                report
                    .diagnostics
                    .unit_circle_folds
                    .iter()
                    .any(|observation| {
                        matches!(
                            observation.location,
                            FastDiagnosticLocation::UnitCircleFold { round: 0, .. }
                        )
                    })
            );
            assert!(
                report
                    .diagnostics
                    .unit_circle_folds
                    .iter()
                    .any(|observation| {
                        matches!(
                            observation.location,
                            FastDiagnosticLocation::UnitCircleFinalValue { value_index: 1 }
                        )
                    })
            );
            assert_eq!(report.work.generator_row_queries, 0);
            assert_eq!(report.work.solution_elements_materialized, 0);
            assert_eq!(report.work.residual_elements_materialized, 0);
            assert_eq!(report.work.codeword_elements_materialized, 0);
            let variables = dimension.next_power_of_two().ilog2() as usize;
            assert_eq!(report.work.sumcheck_rounds, (3 * variables + 1) as u64);
            assert_eq!(
                report.score.proximity_queries_per_round,
                (2 * dimension.next_power_of_two()).min(64) as u32
            );

            let opening_variables = variables + 1;
            let diagnostic_capacity = report.diagnostics.norm_sumcheck.capacity()
                + report.diagnostics.matvec_sumcheck.capacity()
                + report.diagnostics.linear_opening_sumcheck.capacity()
                + report.diagnostics.unit_circle_folds.capacity();
            let expected_accounted_bytes = 2 * payload.len()
                + opening_variables
                    * (2 * Policy3::PROXIMITY_QUERY_TARGET)
                    * std::mem::size_of::<usize>()
                + (opening_variables + 4) * std::mem::size_of::<f64>()
                + diagnostic_capacity * std::mem::size_of::<FastDiagnosticObservation>();
            assert_eq!(
                report.work.accounted_high_watermark_bytes,
                expected_accounted_bytes
            );
        }
    }

    #[test]
    fn chunked_backend_round_trips_under_a_distinct_protocol() {
        let (statement, solution) =
            fixture_for_protocol(37, 2, ProofProtocol::FastBinary64UnitCircleChunkedV6);
        let (payload, prover_report) =
            FastChunkedBackend::prove_single_stage(&statement, &solution).unwrap();
        let verifier_report = FastChunkedBackend::verify(
            &statement.verifier_statement(),
            &payload,
            &ValidationCancellation::never(),
        )
        .unwrap();

        assert_eq!(prover_report.squared_l2_claim, 0.0);
        assert_eq!(verifier_report.score.squared_l2_claim, 0.0);
        let (v5_statement, _) = fixture(37, 2);
        assert!(FastBackend::verify(&v5_statement.verifier_statement(), &payload).is_err());
    }

    #[test]
    fn all_zero_dimension_sixteen_artifact_is_accepted_and_reports_calibration() {
        let statement = calibration_fixture();
        let dimension = statement.generated().dimension();
        let padded_len = dimension.next_power_of_two();
        let variables = padded_len.ilog2() as usize;
        let opening_variables = variables + 1;
        // This is deliberately a verifier-side calibration artifact: its
        // committed oracle and every prover message are zero, while the
        // public RHS supplies the one nonzero matvec claim.
        let packed = vec![0.0; 2 * padded_len];
        let codeword = UnitCircleCodeword::encode(&packed).unwrap();
        let root = complex_root(
            FastFlavor::PerValueV5,
            &oracle_tree_label(FastFlavor::PerValueV5, 0, codeword.evaluations().len()),
            codeword.evaluations(),
        )
        .unwrap();
        let material = PreparedMaterial {
            logical_len: dimension,
            padded_len,
            solution: vec![0.0; dimension],
            residual: vec![0.0; dimension],
            packed,
            codeword,
            root,
            chunked_tree: None,
            estimated_backend_peak_bytes: fast_prover_memory_preflight(
                dimension,
                FastFlavor::PerValueV5,
            )
            .unwrap()
            .estimated_backend_peak_bytes,
        };
        let evaluator = EvaluatorBinding::from_metadata(
            statement.generated().public_evaluation_plan().metadata(),
        )
        .unwrap();
        let commitment = make_precommitment(
            ProofProtocol::FastBinary64UnitCircleV5,
            statement.transcript_digest(),
            statement.problem_digest(),
            statement.manifest_digest(),
            evaluator,
            &material,
        )
        .unwrap();

        let norm_sumcheck = zero_sumcheck(variables);
        let mut transcript = initialize_transcript(&commitment).unwrap();
        absorb_float(&mut transcript, b"residual-squared-l2-claim", 0.0).unwrap();
        let mut norm_point = Vec::with_capacity(variables);
        for (round, polynomial) in norm_sumcheck.rounds.iter().enumerate() {
            norm_point.push(sumcheck_challenge(
                &mut transcript,
                b"residual-norm",
                round,
                polynomial,
            ));
        }
        absorb_float(&mut transcript, b"residual-at-shared-row-point", 0.0).unwrap();

        let rhs = statement
            .generated()
            .public_evaluation_plan()
            .evaluate_rhs_mle_f64(&norm_point)
            .unwrap();
        assert_eq!(rhs.value, 2.0_f64.powi(-42));
        absorb_float(&mut transcript, b"matvec-initial-claim", rhs.value).unwrap();
        let matvec_sumcheck = zero_sumcheck(variables);
        let mut matvec_point = Vec::with_capacity(variables);
        for (round, polynomial) in matvec_sumcheck.rounds.iter().enumerate() {
            matvec_point.push(sumcheck_challenge(
                &mut transcript,
                b"matvec-product",
                round,
                polynomial,
            ));
        }
        let matrix = statement
            .generated()
            .public_evaluation_plan()
            .evaluate_matrix_mle_f64(&norm_point, &matvec_point)
            .unwrap();
        absorb_float(&mut transcript, b"solution-at-column-point", 0.0).unwrap();

        transcript
            .challenge_dyadic_f64(b"linear-opening-batching-challenge")
            .unwrap();
        absorb_float(&mut transcript, b"linear-opening-initial-claim", 0.0).unwrap();
        let opening_sumcheck = zero_sumcheck(opening_variables);
        let mut fold_levels = vec![material.codeword.clone()];
        let mut fold_roots = Vec::with_capacity(opening_variables);
        let mut fold_challenges = Vec::with_capacity(opening_variables);
        for (round, polynomial) in opening_sumcheck.rounds.iter().enumerate() {
            let challenge = sumcheck_challenge(
                &mut transcript,
                b"linear-opening-product",
                round,
                polynomial,
            );
            fold_challenges.push(challenge);
            let fold_codeword = fold_levels.last().unwrap().fold(challenge).unwrap();
            let root = complex_root(
                FastFlavor::PerValueV5,
                &oracle_tree_label(
                    FastFlavor::PerValueV5,
                    round + 1,
                    fold_codeword.evaluations().len(),
                ),
                fold_codeword.evaluations(),
            )
            .unwrap();
            transcript.absorb_root(b"linear-opening-fold-root", &root);
            fold_roots.push(root);
            fold_levels.push(fold_codeword);
        }
        absorb_float(&mut transcript, b"linear-opening-source-endpoint", 0.0).unwrap();
        let query_plan = draw_query_plan(&mut transcript, material.codeword.message_len()).unwrap();
        let mut work = FastProverWork::default();
        let folding = build_folding_opening(
            FastFlavor::PerValueV5,
            fold_levels,
            vec![None; fold_roots.len() + 1],
            &fold_roots,
            &fold_challenges,
            &query_plan,
            &mut work,
        )
        .unwrap();
        let proof = FastProof {
            logical_len: dimension,
            residual_squared_l2: 0.0,
            norm_sumcheck,
            residual_at_row_point: 0.0,
            matvec_sumcheck,
            solution_at_column_point: 0.0,
            opening_sumcheck,
            opening_endpoint: 0.0,
            folding,
        };
        let proof_bytes = encode_proof(&proof).unwrap();
        let payload = encode_backend_payload(&commitment, &proof_bytes).unwrap();
        let report = FastBackend::verify(&statement.verifier_statement(), &payload).unwrap();

        assert_eq!(report.public_evaluations.rhs, rhs.roundoff);
        assert_eq!(report.public_evaluations.matrix, matrix.roundoff);
        for roundoff in [
            report.public_evaluations.rhs,
            report.public_evaluations.matrix,
        ] {
            assert!(roundoff.forward_absolute_error_bound.is_finite());
            assert!(roundoff.forward_absolute_error_bound >= 0.0);
            assert!(roundoff.maximum_absolute_source.is_finite());
            assert!(roundoff.maximum_absolute_source >= 0.0);
            assert!(roundoff.maximum_absolute_intermediate.is_finite());
            assert!(roundoff.maximum_absolute_intermediate >= roundoff.maximum_absolute_source);
        }
        assert_eq!(report.score.squared_l2_claim, 0.0);
        assert_eq!(report.score.matvec_sumcheck.max_relative, 1.0);
        assert_eq!(
            report.score.matvec_sumcheck.rms_relative,
            1.0 / (variables as f64 + 1.0).sqrt()
        );
        let calibration = report
            .diagnostics
            .matvec_sumcheck
            .iter()
            .find(|observation| observation.observation.relative_error == 1.0)
            .expect("the all-zero matvec round must be reported");
        assert_eq!(
            calibration.location,
            FastDiagnosticLocation::SumcheckRound { round: 0 }
        );
        assert_eq!(calibration.observation.actual_magnitude, 0.0);
        assert_eq!(
            calibration.observation.expected_magnitude,
            2.0_f64.powi(-42)
        );
        assert_eq!(calibration.observation.absolute_defect, 2.0_f64.powi(-42));
        assert_eq!(calibration.observation.normalization_scale, 0.0);
        assert_eq!(calibration.observation.zero_scale, 2.0_f64.powi(-42));
        assert_eq!(calibration.observation.relative_error, 1.0);
        assert_eq!(report.score.norm_sumcheck.max_relative, 0.0);
        assert_eq!(report.score.linear_opening_sumcheck.max_relative, 0.0);
        assert_eq!(report.score.unit_circle_folds.max_relative, 0.0);
    }

    #[test]
    fn nonzero_residual_round_trip_checks_all_three_application_relations() {
        let (statement, _) = fixture(8, 2);
        let solution = Solution::new(vec![0.0; 8], 8).unwrap();
        let (commitment, _) = FastBackend::commit(&statement, &solution).unwrap();
        let context = FastProverContext::new(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        let report = FastBackend::verify(&statement.verifier_statement(), &payload).unwrap();
        assert_eq!(report.score.squared_l2_claim, 2.0);
        assert_eq!(report.score.residual_l2_claim, 2.0_f64.sqrt());
        assert_eq!(report.score.residual_rms_claim, 0.5);
        assert!(report.score.norm_sumcheck.checks > 0);
        assert!(report.score.matvec_sumcheck.checks > 0);
        assert!(report.score.linear_opening_sumcheck.checks > 0);
        assert!(report.score.unit_circle_folds.checks > 0);
    }

    #[test]
    fn fast_solution_does_not_inherit_the_exact_residual_range() {
        let (statement, _) = fixture(8, 2);
        let solution = Solution::new(vec![8.0; 8], 8).unwrap();
        assert!(matches!(
            ssv_relation::ExactRelation::from_solution(statement.generated(), &solution),
            Err(ssv_relation::RelationError::ResidualOutOfRange { .. })
        ));

        let (commitment, _) = FastBackend::commit(&statement, &solution).unwrap();
        let context = FastProverContext::new(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        let report = FastBackend::verify(&statement.verifier_statement(), &payload).unwrap();
        assert!(report.score.squared_l2_claim > 8.0);
    }

    #[test]
    fn fast_solution_accepts_binary64_values_outside_q63_64() {
        let (statement, _) = fixture(8, 2);
        let value = 2.0_f64.powi(70);
        let solution = Solution::new(vec![value; 8], 8).unwrap();
        assert!(matches!(
            ssv_relation::FixedWitness::from_solution(&solution, 8),
            Err(ssv_relation::RelationError::WitnessOutOfRange { index: 0 })
        ));

        let material = prepare_material(
            statement.generated(),
            &solution,
            &mut FastProverWork::default(),
            FastFlavor::PerValueV5,
        )
        .unwrap();
        assert!(
            material
                .solution
                .iter()
                .all(|candidate| candidate.to_bits() == value.to_bits())
        );
        let (commitment, _) = FastBackend::commit(&statement, &solution).unwrap();
        let context = FastProverContext::new(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        let report = FastBackend::verify(&statement.verifier_statement(), &payload).unwrap();
        assert!(report.score.squared_l2_claim.is_finite());
    }

    #[test]
    fn fast_solution_preserves_values_below_the_q63_64_grid() {
        let (statement, _) = fixture(8, 2);
        let value = 2.0_f64.powi(-66);
        let solution = Solution::new(vec![value; 8], 8).unwrap();
        let fixed = ssv_relation::FixedWitness::from_solution(&solution, 8).unwrap();
        assert!(fixed.as_slice().iter().all(|&candidate| candidate == 0));

        let material = prepare_material(
            statement.generated(),
            &solution,
            &mut FastProverWork::default(),
            FastFlavor::PerValueV5,
        )
        .unwrap();
        assert!(
            material
                .solution
                .iter()
                .all(|candidate| candidate.to_bits() == value.to_bits())
        );
        assert!(
            material.packed[..8]
                .iter()
                .all(|candidate| candidate.to_bits() == value.to_bits())
        );
        let (commitment, _) = FastBackend::commit(&statement, &solution).unwrap();
        let context = FastProverContext::new(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        FastBackend::verify(&statement.verifier_statement(), &payload).unwrap();
    }

    #[test]
    fn one_step_reuses_material_and_matches_staged_bytes_and_work() {
        let (statement, solution) = fixture(8, 2);
        let (one_step_payload, one_step_report) =
            FastBackend::prove_single_stage(&statement, &solution).unwrap();

        let (commitment, commitment_report) = FastBackend::commit(&statement, &solution).unwrap();
        let context = FastProverContext::new(commitment.clone());
        let (staged_payload, staged_report) =
            FastBackend::prove(&statement, &solution, &context).unwrap();

        let (one_step_commitment, one_step_proof) =
            decode_backend_payload(&one_step_payload).unwrap();
        let (staged_commitment, staged_proof) = decode_backend_payload(&staged_payload).unwrap();
        assert_eq!(one_step_commitment.to_bytes(), commitment.to_bytes());
        assert_eq!(staged_commitment.to_bytes(), commitment.to_bytes());
        assert_eq!(one_step_proof, staged_proof);
        assert_eq!(one_step_payload, staged_payload);

        let rows = statement.generated().dimension() as u64;
        let nonzeros = statement.generated().structural_nnz() as u64;
        let opening_rounds =
            u64::from((2 * statement.generated().dimension().next_power_of_two()).ilog2());
        let expected_root_computations = 1 + opening_rounds;
        assert_eq!(one_step_report.material_preparations, 1);
        assert_eq!(one_step_report.rows_scanned, 2 * rows);
        assert_eq!(one_step_report.nonzeros_scanned, 2 * nonzeros);
        assert_eq!(one_step_report.codeword_folds, opening_rounds);
        assert_eq!(
            one_step_report.merkle_root_computations,
            expected_root_computations
        );
        assert_eq!(one_step_report.merkle_multiproof_passes, opening_rounds);

        assert_eq!(commitment_report.material_preparations, 1);
        assert_eq!(commitment_report.rows_scanned, rows);
        assert_eq!(commitment_report.nonzeros_scanned, nonzeros);
        assert_eq!(commitment_report.codeword_folds, 0);
        assert_eq!(commitment_report.merkle_root_computations, 1);
        assert_eq!(commitment_report.merkle_multiproof_passes, 0);
        assert_eq!(staged_report.material_preparations, 1);
        assert_eq!(staged_report.rows_scanned, 2 * rows);
        assert_eq!(staged_report.nonzeros_scanned, 2 * nonzeros);
        assert_eq!(staged_report.codeword_folds, opening_rounds);
        assert_eq!(
            staged_report.merkle_root_computations,
            expected_root_computations
        );
        assert_eq!(staged_report.merkle_multiproof_passes, opening_rounds);
        assert_eq!(
            one_step_report.estimated_backend_peak_bytes,
            commitment_report.estimated_backend_peak_bytes
        );
        assert_eq!(
            one_step_report.estimated_backend_peak_bytes,
            staged_report.estimated_backend_peak_bytes
        );
        assert_eq!(
            commitment_report.material_preparations + staged_report.material_preparations,
            2
        );
        assert_eq!(
            commitment_report.rows_scanned + staged_report.rows_scanned,
            3 * rows
        );
        assert_eq!(
            commitment_report.nonzeros_scanned + staged_report.nonzeros_scanned,
            3 * nonzeros
        );
    }

    #[test]
    fn staged_proving_recomputes_material_before_accepting_a_commitment() {
        let (statement, solution) = fixture(8, 2);
        let (commitment, _) = FastBackend::commit(&statement, &solution).unwrap();
        let changed_solution = Solution::new(vec![0.0; 8], 8).unwrap();
        let context = FastProverContext::new(commitment);
        assert!(matches!(
            FastBackend::prove(&statement, &changed_solution, &context),
            Err(FastError::PrecommitmentMismatch)
        ));
    }

    #[test]
    fn staged_fiat_shamir_is_deterministic_and_binds_statement_and_commitment() {
        let (statement, solution) = fixture(8, 2);
        let (commitment, commitment_report) = FastBackend::commit(&statement, &solution).unwrap();
        let (same_commitment, same_report) = FastBackend::commit(&statement, &solution).unwrap();
        assert_eq!(commitment, same_commitment);
        assert_eq!(
            commitment_report.precommitment_digest,
            same_report.precommitment_digest
        );

        let context = FastProverContext::new(commitment.clone());
        let same_context = FastProverContext::new(same_commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        let (same_payload, _) = FastBackend::prove(&statement, &solution, &same_context).unwrap();
        assert_eq!(payload, same_payload);

        let preflight = FastBackend::preflight(&statement.verifier_statement(), &payload).unwrap();
        assert_eq!(preflight.precommitment_digest, commitment.digest());
        let cancellation = ValidationCancellation::new();
        cancellation.cancel();
        assert!(matches!(
            FastBackend::verify_with_cancellation(
                &statement.verifier_statement(),
                &payload,
                &cancellation
            ),
            Err(FastError::Cancelled)
        ));
        FastBackend::verify(&statement.verifier_statement(), &payload).unwrap();

        let first_challenge = initialize_transcript(&commitment)
            .unwrap()
            .challenge_dyadic_f64(b"binding-test")
            .unwrap();
        let mut changed_commitment = commitment.clone();
        changed_commitment.packed_codeword_root[0] ^= 1;
        let changed_commitment_first_challenge = initialize_transcript(&changed_commitment)
            .unwrap()
            .challenge_dyadic_f64(b"binding-test")
            .unwrap();
        assert_ne!(first_challenge, changed_commitment_first_challenge);

        let mut changed_evaluator = commitment.clone();
        changed_evaluator.evaluator.evaluator_version += 1;
        let changed_evaluator_challenge = initialize_transcript(&changed_evaluator)
            .unwrap()
            .challenge_dyadic_f64(b"binding-test")
            .unwrap();
        assert_ne!(first_challenge, changed_evaluator_challenge);
        let (_, proof_bytes) = decode_backend_payload(&payload).unwrap();
        let changed_evaluator_payload =
            encode_backend_payload(&changed_evaluator, proof_bytes).unwrap();
        assert!(matches!(
            FastBackend::preflight(&statement.verifier_statement(), &changed_evaluator_payload),
            Err(FastError::StatementMismatch)
        ));

        let mut changed_statement = commitment;
        changed_statement.statement_digest = Digest::from_bytes([0x5a; 32]);
        let changed_statement_challenge = initialize_transcript(&changed_statement)
            .unwrap()
            .challenge_dyadic_f64(b"binding-test")
            .unwrap();
        assert_ne!(first_challenge, changed_statement_challenge);
    }

    #[test]
    fn precommitment_and_payload_framing_are_strict() {
        let (statement, solution) = fixture(8, 2);
        let (commitment, _) = FastBackend::commit(&statement, &solution).unwrap();
        let encoded = commitment.to_bytes();
        assert_eq!(FastPrecommitment::from_bytes(&encoded).unwrap(), commitment);
        let mut retired_v5 = encoded.clone();
        retired_v5[PRECOMMIT_MAGIC.len()..PRECOMMIT_MAGIC.len() + 2]
            .copy_from_slice(&5_u16.to_be_bytes());
        assert!(matches!(
            FastPrecommitment::from_bytes(&retired_v5),
            Err(FastError::UnsupportedVersion)
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(FastPrecommitment::from_bytes(&trailing).is_err());
        for length in 0..encoded.len() {
            assert!(FastPrecommitment::from_bytes(&encoded[..length]).is_err());
        }

        let context = FastProverContext::new(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(FastBackend::preflight(&statement.verifier_statement(), &trailing).is_err());
        assert!(FastBackend::verify(&statement.verifier_statement(), &trailing).is_err());
    }

    #[test]
    fn statement_binding_and_inner_float_encoding_are_strict() {
        let (statement, solution) = fixture(8, 2);
        let (other_statement, _) = fixture(8, 3);
        let (commitment, _) = FastBackend::commit(&statement, &solution).unwrap();
        let context = FastProverContext::new(commitment);
        let (payload, _) = FastBackend::prove(&statement, &solution, &context).unwrap();
        assert!(matches!(
            FastBackend::preflight(&other_statement.verifier_statement(), &payload),
            Err(FastError::StatementMismatch)
        ));
        assert!(matches!(
            FastBackend::verify(&other_statement.verifier_statement(), &payload),
            Err(FastError::StatementMismatch)
        ));

        let (commitment, proof) = decode_backend_payload(&payload).unwrap();
        let mut noncanonical = proof.to_vec();
        // proof-version u16, logical-length u64, then rho bits.
        noncanonical[10..18].copy_from_slice(&f64::NAN.to_bits().to_be_bytes());
        let changed = encode_backend_payload(&commitment, &noncanonical).unwrap();
        assert!(matches!(
            FastBackend::verify(&statement.verifier_statement(), &changed),
            Err(FastError::Float(FloatContractError::NonFinite))
        ));

        let mut inner_trailing = proof.to_vec();
        inner_trailing.push(0);
        let changed = encode_backend_payload(&commitment, &inner_trailing).unwrap();
        assert!(FastBackend::verify(&statement.verifier_statement(), &changed).is_err());
    }

    #[test]
    fn verifier_work_uses_only_the_succinct_capability_and_scales_with_description() {
        let (small_payload, small) = round_trip(64);
        let (large_payload, large) = round_trip(256);
        for report in [&small, &large] {
            assert_eq!(report.work.generator_row_queries, 0);
            assert_eq!(report.work.solution_elements_materialized, 0);
            assert_eq!(report.work.residual_elements_materialized, 0);
            assert_eq!(report.work.codeword_elements_materialized, 0);
            assert!(report.work.public_matrix_period_terms <= 4);
            assert_eq!(report.work.public_rhs_period_terms, 1);
        }
        assert_eq!(large.work.sumcheck_rounds - small.work.sumcheck_rounds, 6);
        assert!(
            large_payload.len() <= small_payload.len() * 3,
            "large payload {} bytes, small payload {} bytes",
            large_payload.len(),
            small_payload.len()
        );
        assert!(large.work.public_matrix_arithmetic_operations < 4 * 256);
    }
}
