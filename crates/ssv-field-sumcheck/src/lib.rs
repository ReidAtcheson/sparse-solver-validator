//! Streaming finite-field sumcheck over flat multilinear tables.
//!
//! This crate is the reusable algebra/transcript boundary used by exact proof
//! backends. It deliberately knows nothing about sparse matrices, residuals,
//! range constraints, or polynomial commitments. A caller supplies a trusted
//! phase label, the public claim, flat tables, and the pointwise polynomial
//! that combines those tables. Small channel traits make the same algorithm
//! usable inside the pinned WHIR transcript and in isolated protocol tests.
//!
//! The implementation is refactored from the `whir-field192-l2-v4` streaming
//! sumcheck in the sparse-solution-stark research implementation. In
//! particular, it preserves that transcript header and its coordinate order:
//! each round folds the lower and upper halves of every table, so challenges
//! bind coordinates from the most-significant index bit to the least.
//!
//! Proving consumes the tables and folds them in place. Apart from the tables,
//! memory is `O(table_count + degree + variables)` plus one fixed-size scratch
//! buffer per active Rayon worker. Verification uses `O(degree + variables)`
//! field elements. The default `parallel` feature retains the v4 prover's
//! parallel index reductions for large tables; small tables use a serial path
//! to avoid scheduling overhead. Addition in Field192 is exact and associative,
//! so reduction-tree order cannot change the algebraic result.

#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::fmt::{Debug, Display};

use ark_ff::{AdditiveGroup, Field};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use ssv_whir_pcs::transcript::{VerificationError, VerifierMessage};
use ssv_whir_pcs::{PcsField, ProverTranscript, VerifierTranscript};
use thiserror::Error;

/// Domain separator retained from the audited v4 transcript.
const SUMCHECK_TAG_DOMAIN: &[u8] = b"sparse-solution/v4/sumcheck\0";

/// Avoid Rayon setup for very small flat reductions. This is a conservative
/// policy threshold, not a claimed universal crossover; benchmark the target
/// hardware and representative combine functions before changing it.
#[cfg(feature = "parallel")]
const PARALLEL_MIN_ROWS: usize = 4_096;

/// Public, verifier-trusted parameters for one sumcheck phase.
///
/// None of these values are selected from proof bytes. The header repeats them
/// only to make transcript framing strict and self-checking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Statement<'tag> {
    phase_tag: &'tag [u8],
    degree: usize,
    variables: usize,
    initial_claim: PcsField,
}

impl<'tag> Statement<'tag> {
    /// Constructs a trusted sumcheck statement.
    ///
    /// `degree` must be at least one because every round transmits evaluations
    /// at both zero and one. A zero-variable statement is valid and represents
    /// a singleton table.
    pub fn new(
        phase_tag: &'tag [u8],
        degree: usize,
        variables: usize,
        initial_claim: PcsField,
    ) -> Result<Self, StatementError> {
        if phase_tag.is_empty() {
            return Err(StatementError::EmptyPhaseTag);
        }
        if degree == 0 {
            return Err(StatementError::DegreeTooSmall);
        }
        degree
            .checked_add(1)
            .ok_or(StatementError::DegreeOverflow)?;
        u64::try_from(degree).map_err(|_| StatementError::DegreeOverflow)?;
        u64::try_from(variables).map_err(|_| StatementError::VariableCountOverflow)?;
        Ok(Self {
            phase_tag,
            degree,
            variables,
            initial_claim,
        })
    }

    /// Trusted phase label hashed into the transcript header.
    #[must_use]
    pub const fn phase_tag(self) -> &'tag [u8] {
        self.phase_tag
    }

    /// Claimed individual degree in the currently folded coordinate.
    #[must_use]
    pub const fn degree(self) -> usize {
        self.degree
    }

    /// Number of Boolean variables, and therefore sumcheck rounds.
    #[must_use]
    pub const fn variables(self) -> usize {
        self.variables
    }

    /// Public hypercube sum at the start of this phase.
    #[must_use]
    pub const fn initial_claim(self) -> PcsField {
        self.initial_claim
    }
}

/// Invalid trusted statement configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StatementError {
    /// An empty label provides no meaningful phase separation.
    #[error("sumcheck phase tag must not be empty")]
    EmptyPhaseTag,
    /// Round consistency requires evaluations at integer points zero and one.
    #[error("sumcheck degree must be at least one")]
    DegreeTooSmall,
    /// The degree cannot be encoded or its evaluation count overflowed.
    #[error("sumcheck degree cannot be represented in the transcript")]
    DegreeOverflow,
    /// The variable count cannot be encoded in the transcript.
    #[error("sumcheck variable count cannot be represented in the transcript")]
    VariableCountOverflow,
}

/// Minimal transcript operations needed by a sumcheck prover.
///
/// The distinct methods preserve typed transcript framing. In particular, the
/// v4-compatible adapter sends header integers as canonical little-endian byte
/// arrays, exactly as the research transcript did.
pub trait ProverChannel {
    /// Transport-specific failure.
    type Error: Debug + Display + Send + Sync + 'static;

    /// Appends a 32-byte domain tag.
    fn send_tag(&mut self, value: [u8; 32]) -> Result<(), Self::Error>;

    /// Appends a canonical unsigned header value.
    fn send_u64(&mut self, value: u64) -> Result<(), Self::Error>;

    /// Appends one prover-supplied field element.
    fn send_field(&mut self, value: PcsField) -> Result<(), Self::Error>;

    /// Draws the next transcript-derived field challenge.
    fn draw_challenge(&mut self) -> Result<PcsField, Self::Error>;
}

/// Minimal transcript operations needed by a sumcheck verifier.
pub trait VerifierChannel {
    /// Transport-specific failure.
    type Error: Debug + Display + Send + Sync + 'static;

    /// Reads a 32-byte domain tag.
    fn receive_tag(&mut self) -> Result<[u8; 32], Self::Error>;

    /// Reads a canonical unsigned header value.
    fn receive_u64(&mut self) -> Result<u64, Self::Error>;

    /// Reads one prover-supplied field element.
    fn receive_field(&mut self) -> Result<PcsField, Self::Error>;

    /// Draws the next transcript-derived field challenge.
    fn draw_challenge(&mut self) -> Result<PcsField, Self::Error>;
}

impl ProverChannel for ProverTranscript {
    type Error = Infallible;

    fn send_tag(&mut self, value: [u8; 32]) -> Result<(), Self::Error> {
        self.prover_message(&value);
        Ok(())
    }

    fn send_u64(&mut self, value: u64) -> Result<(), Self::Error> {
        self.prover_message(&value.to_le_bytes());
        Ok(())
    }

    fn send_field(&mut self, value: PcsField) -> Result<(), Self::Error> {
        self.prover_message(&value);
        Ok(())
    }

    fn draw_challenge(&mut self) -> Result<PcsField, Self::Error> {
        Ok(VerifierMessage::verifier_message(self))
    }
}

impl VerifierChannel for VerifierTranscript<'_> {
    type Error = VerificationError;

    fn receive_tag(&mut self) -> Result<[u8; 32], Self::Error> {
        self.prover_message()
    }

    fn receive_u64(&mut self) -> Result<u64, Self::Error> {
        self.prover_message::<[u8; 8]>().map(u64::from_le_bytes)
    }

    fn receive_field(&mut self) -> Result<PcsField, Self::Error> {
        self.prover_message()
    }

    fn draw_challenge(&mut self) -> Result<PcsField, Self::Error> {
        Ok(VerifierMessage::verifier_message(self))
    }
}

/// Structural, transcript, or algebraic failure in one sumcheck phase.
#[derive(Debug, Error)]
pub enum SumcheckError<E>
where
    E: Debug + Display + Send + Sync + 'static,
{
    /// The underlying transcript could not send, receive, or derive a value.
    #[error("sumcheck transcript channel failed: {0}")]
    Channel(E),
    /// At least one source table is required.
    #[error("sumcheck requires at least one table")]
    NoTables,
    /// Boolean multilinear tables cannot be empty.
    #[error("sumcheck table 0 is empty")]
    EmptyTable,
    /// The common table size must describe a Boolean hypercube.
    #[error("sumcheck table length {length} is not a power of two")]
    TableLengthNotPowerOfTwo { length: usize },
    /// All pointwise inputs must share one flat shape.
    #[error("sumcheck table {table} has length {actual}, expected the common length {expected}")]
    TableLengthMismatch {
        table: usize,
        expected: usize,
        actual: usize,
    },
    /// The trusted round count and prover table shape disagree.
    #[error(
        "sumcheck tables have {actual} variables, but the trusted statement requires {expected}"
    )]
    VariableCountMismatch { expected: usize, actual: usize },
    /// The claimed initial sum is inconsistent with the supplied tables.
    #[error("sumcheck initial claim does not match the supplied tables")]
    InitialClaimMismatch,
    /// A prover-generated round failed its own Boolean sum relation.
    #[error("honest sumcheck prover produced an inconsistent round {round}")]
    ProverRoundMismatch { round: usize },
    /// A prover-generated endpoint failed its own pointwise relation.
    #[error("honest sumcheck prover produced an inconsistent endpoint")]
    ProverEndpointMismatch,
    /// The proof repeated a different phase domain separator.
    #[error("sumcheck transcript phase tag does not match the trusted statement")]
    HeaderTagMismatch,
    /// The proof repeated a different degree.
    #[error("sumcheck transcript degree {actual} does not match trusted degree {expected}")]
    HeaderDegreeMismatch { expected: usize, actual: u64 },
    /// The proof repeated a different variable count.
    #[error("sumcheck transcript variable count {actual} does not match trusted count {expected}")]
    HeaderVariableCountMismatch { expected: usize, actual: u64 },
    /// The proof repeated a different initial claim.
    #[error("sumcheck transcript initial claim does not match the trusted claim")]
    HeaderClaimMismatch,
    /// A received round polynomial violated `g(0) + g(1) = claim`.
    #[error("sumcheck round {round} does not satisfy the Boolean sum relation")]
    RoundRelationMismatch { round: usize },
    /// Integer-node interpolation failed; this indicates an unsupported field
    /// or a degree at least as large as its characteristic.
    #[error("sumcheck integer interpolation nodes are not distinct")]
    NonDistinctInterpolationNodes,
    /// A size or diagnostic work calculation overflowed.
    #[error("sumcheck size or work counter overflow")]
    SizeOverflow,
}

/// Auditable prover work independent of the caller's combine-function cost.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProverWork {
    /// Number of folding rounds.
    pub rounds: u64,
    /// Number of round-polynomial field elements sent (header excluded).
    pub round_field_elements: u64,
    /// Calls to the caller-provided pointwise combine function.
    pub combine_evaluations: u64,
    /// Scalar table interpolations used for round evaluation and folding.
    pub table_lerps: u64,
    /// Total field cells in the source tables before in-place folding.
    pub initial_table_cells: u64,
    /// Peak auxiliary field cells, excluding the owned source tables.
    pub peak_auxiliary_field_elements: u64,
}

/// Auditable verifier work independent of transcript hashing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerifierWork {
    /// Number of verified folding rounds.
    pub rounds: u64,
    /// Number of round-polynomial field elements received (header excluded).
    pub round_field_elements: u64,
    /// Number of Lagrange terms accumulated across all rounds.
    pub interpolation_terms: u64,
    /// Peak auxiliary field cells retained by verification.
    pub peak_auxiliary_field_elements: u64,
}

/// Final random point and folded source-table values produced by the prover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProverEndpoint {
    /// Challenges in MSB-to-LSB coordinate order.
    pub point: Vec<PcsField>,
    /// Final claim after all rounds.
    pub claim: PcsField,
    /// Each input table's multilinear evaluation at [`Self::point`].
    pub table_evaluations: Vec<PcsField>,
    /// Deterministic algebraic work counters.
    pub work: ProverWork,
}

/// Final random point and reduced scalar claim produced by the verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierEndpoint {
    /// Challenges in MSB-to-LSB coordinate order.
    pub point: Vec<PcsField>,
    /// Reduced scalar claim that the caller must check against authenticated
    /// endpoint table evaluations.
    pub claim: PcsField,
    /// Deterministic algebraic work counters.
    pub work: VerifierWork,
}

/// Proves one sumcheck by folding all source tables in place.
///
/// The caller's `combine` closure must be a polynomial of individual degree at
/// most `statement.degree()` in each Boolean coordinate after substituting the
/// multilinear source tables. It is evaluated over a reused scratch slice and
/// must not retain that slice. It must also be deterministic and free of
/// externally visible side effects: with the default `parallel` feature,
/// independent rows may be evaluated concurrently.
pub fn prove<C, Ch>(
    channel: &mut Ch,
    statement: Statement<'_>,
    mut tables: Vec<Vec<PcsField>>,
    combine: C,
) -> Result<ProverEndpoint, SumcheckError<Ch::Error>>
where
    C: Fn(&[PcsField]) -> PcsField + Sync,
    Ch: ProverChannel,
{
    let table_len = validate_tables(&tables, statement.variables)?;
    let work = prover_work(
        table_len,
        tables.len(),
        statement.degree,
        statement.variables,
    )?;
    let interpolator = IntegerInterpolator::new(statement.degree)?;

    let actual = sum_table_rows(&tables, table_len, &combine);
    if actual != statement.initial_claim {
        return Err(SumcheckError::InitialClaimMismatch);
    }

    send_header(channel, statement)?;
    let mut claim = statement.initial_claim;
    let mut point = Vec::with_capacity(statement.variables);
    let mut evaluations = vec![PcsField::ZERO; statement.degree + 1];

    for round in 0..statement.variables {
        let half = tables[0].len() / 2;
        for (integer_point, evaluation) in evaluations.iter_mut().enumerate() {
            let t = PcsField::from(integer_point as u64);
            *evaluation = sum_interpolated_rows(&tables, half, t, &combine);
        }

        if evaluations[0] + evaluations[1] != claim {
            return Err(SumcheckError::ProverRoundMismatch { round });
        }
        for &evaluation in &evaluations {
            channel
                .send_field(evaluation)
                .map_err(SumcheckError::Channel)?;
        }
        let challenge = channel.draw_challenge().map_err(SumcheckError::Channel)?;

        // Splitting a flat Boolean table into equal halves selects its current
        // most-significant coordinate. Truncation retains the folded lower
        // half as the next round's contiguous table.
        for table in &mut tables {
            for index in 0..half {
                let low = table[index];
                table[index] = low + challenge * (table[index + half] - low);
            }
            table.truncate(half);
        }
        claim = interpolator.evaluate(&evaluations, challenge);
        point.push(challenge);
    }

    let table_evaluations = tables.into_iter().map(|table| table[0]).collect::<Vec<_>>();
    if combine(&table_evaluations) != claim {
        return Err(SumcheckError::ProverEndpointMismatch);
    }
    Ok(ProverEndpoint {
        point,
        claim,
        table_evaluations,
        work,
    })
}

/// Verifies one sumcheck transcript through its reduced scalar endpoint.
///
/// Acceptance is not complete until the caller authenticates the endpoint
/// source-table evaluations and checks that their pointwise combination equals
/// [`VerifierEndpoint::claim`].
pub fn verify<Ch>(
    channel: &mut Ch,
    statement: Statement<'_>,
) -> Result<VerifierEndpoint, SumcheckError<Ch::Error>>
where
    Ch: VerifierChannel,
{
    receive_header(channel, statement)?;
    let interpolator = IntegerInterpolator::new(statement.degree)?;
    let work = verifier_work(statement.degree, statement.variables)?;
    let mut claim = statement.initial_claim;
    let mut point = Vec::with_capacity(statement.variables);
    let mut evaluations = vec![PcsField::ZERO; statement.degree + 1];

    for round in 0..statement.variables {
        for evaluation in &mut evaluations {
            *evaluation = channel.receive_field().map_err(SumcheckError::Channel)?;
        }
        if evaluations[0] + evaluations[1] != claim {
            return Err(SumcheckError::RoundRelationMismatch { round });
        }
        let challenge = channel.draw_challenge().map_err(SumcheckError::Channel)?;
        claim = interpolator.evaluate(&evaluations, challenge);
        point.push(challenge);
    }

    Ok(VerifierEndpoint { point, claim, work })
}

/// Slow, allocation-free reference evaluation of a flat multilinear table.
///
/// This helper is intended for tests and prover-side endpoint construction,
/// not succinct verification: it scans the full table in `O(2^k k)` work.
pub fn evaluate_mle_msb(
    table: &[PcsField],
    point: &[PcsField],
) -> Result<PcsField, EvaluationError> {
    if table.is_empty() {
        return Err(EvaluationError::EmptyTable);
    }
    if !table.len().is_power_of_two() {
        return Err(EvaluationError::TableLengthNotPowerOfTwo {
            length: table.len(),
        });
    }
    let actual_variables = table.len().ilog2() as usize;
    if point.len() != actual_variables {
        return Err(EvaluationError::PointLengthMismatch {
            expected: actual_variables,
            actual: point.len(),
        });
    }

    let mut result = PcsField::ZERO;
    for (index, &value) in table.iter().enumerate() {
        let mut weight = PcsField::ONE;
        for (coordinate, &challenge) in point.iter().enumerate() {
            let shift = actual_variables - 1 - coordinate;
            if ((index >> shift) & 1) == 0 {
                weight *= PcsField::ONE - challenge;
            } else {
                weight *= challenge;
            }
        }
        result += weight * value;
    }
    Ok(result)
}

/// Invalid input to [`evaluate_mle_msb`].
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EvaluationError {
    /// A multilinear table must contain at least one value.
    #[error("multilinear table is empty")]
    EmptyTable,
    /// The table does not describe a Boolean hypercube.
    #[error("multilinear table length {length} is not a power of two")]
    TableLengthNotPowerOfTwo { length: usize },
    /// The evaluation point and table have different dimensions.
    #[error("multilinear point has length {actual}, expected {expected}")]
    PointLengthMismatch { expected: usize, actual: usize },
}

fn validate_tables<E>(
    tables: &[Vec<PcsField>],
    expected_variables: usize,
) -> Result<usize, SumcheckError<E>>
where
    E: Debug + Display + Send + Sync + 'static,
{
    let Some(first) = tables.first() else {
        return Err(SumcheckError::NoTables);
    };
    if first.is_empty() {
        return Err(SumcheckError::EmptyTable);
    }
    if !first.len().is_power_of_two() {
        return Err(SumcheckError::TableLengthNotPowerOfTwo {
            length: first.len(),
        });
    }
    for (table, values) in tables.iter().enumerate().skip(1) {
        if values.len() != first.len() {
            return Err(SumcheckError::TableLengthMismatch {
                table,
                expected: first.len(),
                actual: values.len(),
            });
        }
    }
    let actual_variables = first.len().ilog2() as usize;
    if actual_variables != expected_variables {
        return Err(SumcheckError::VariableCountMismatch {
            expected: expected_variables,
            actual: actual_variables,
        });
    }
    Ok(first.len())
}

fn load_table_values(scratch: &mut [PcsField], tables: &[Vec<PcsField>], index: usize) {
    for (value, table) in scratch.iter_mut().zip(tables) {
        *value = table[index];
    }
}

fn sum_table_rows<C>(tables: &[Vec<PcsField>], rows: usize, combine: &C) -> PcsField
where
    C: Fn(&[PcsField]) -> PcsField + Sync,
{
    #[cfg(feature = "parallel")]
    if rows >= PARALLEL_MIN_ROWS && rayon::current_num_threads() > 1 {
        return (0..rows)
            .into_par_iter()
            .map_init(
                || vec![PcsField::ZERO; tables.len()].into_boxed_slice(),
                |scratch, index| {
                    load_table_values(scratch, tables, index);
                    combine(scratch)
                },
            )
            .sum();
    }

    sum_table_rows_serial(tables, rows, combine)
}

fn sum_table_rows_serial<C>(tables: &[Vec<PcsField>], rows: usize, combine: &C) -> PcsField
where
    C: Fn(&[PcsField]) -> PcsField,
{
    let mut scratch = vec![PcsField::ZERO; tables.len()];
    let mut sum = PcsField::ZERO;
    for index in 0..rows {
        load_table_values(&mut scratch, tables, index);
        sum += combine(&scratch);
    }
    sum
}

fn sum_interpolated_rows<C>(
    tables: &[Vec<PcsField>],
    half: usize,
    point: PcsField,
    combine: &C,
) -> PcsField
where
    C: Fn(&[PcsField]) -> PcsField + Sync,
{
    #[cfg(feature = "parallel")]
    if half >= PARALLEL_MIN_ROWS && rayon::current_num_threads() > 1 {
        return (0..half)
            .into_par_iter()
            .map_init(
                || vec![PcsField::ZERO; tables.len()].into_boxed_slice(),
                |scratch, index| {
                    load_interpolated_table_values(scratch, tables, index, half, point);
                    combine(scratch)
                },
            )
            .sum();
    }

    sum_interpolated_rows_serial(tables, half, point, combine)
}

fn sum_interpolated_rows_serial<C>(
    tables: &[Vec<PcsField>],
    half: usize,
    point: PcsField,
    combine: &C,
) -> PcsField
where
    C: Fn(&[PcsField]) -> PcsField,
{
    let mut scratch = vec![PcsField::ZERO; tables.len()];
    let mut sum = PcsField::ZERO;
    for index in 0..half {
        load_interpolated_table_values(&mut scratch, tables, index, half, point);
        sum += combine(&scratch);
    }
    sum
}

fn load_interpolated_table_values(
    scratch: &mut [PcsField],
    tables: &[Vec<PcsField>],
    index: usize,
    half: usize,
    point: PcsField,
) {
    for (value, table) in scratch.iter_mut().zip(tables) {
        let low = table[index];
        *value = low + point * (table[index + half] - low);
    }
}

fn send_header<Ch>(
    channel: &mut Ch,
    statement: Statement<'_>,
) -> Result<(), SumcheckError<Ch::Error>>
where
    Ch: ProverChannel,
{
    channel
        .send_tag(sumcheck_tag(statement.phase_tag))
        .map_err(SumcheckError::Channel)?;
    channel
        .send_u64(statement.degree as u64)
        .map_err(SumcheckError::Channel)?;
    channel
        .send_u64(statement.variables as u64)
        .map_err(SumcheckError::Channel)?;
    channel
        .send_field(statement.initial_claim)
        .map_err(SumcheckError::Channel)
}

fn receive_header<Ch>(
    channel: &mut Ch,
    statement: Statement<'_>,
) -> Result<(), SumcheckError<Ch::Error>>
where
    Ch: VerifierChannel,
{
    let tag = channel.receive_tag().map_err(SumcheckError::Channel)?;
    if tag != sumcheck_tag(statement.phase_tag) {
        return Err(SumcheckError::HeaderTagMismatch);
    }
    let degree = channel.receive_u64().map_err(SumcheckError::Channel)?;
    if degree != statement.degree as u64 {
        return Err(SumcheckError::HeaderDegreeMismatch {
            expected: statement.degree,
            actual: degree,
        });
    }
    let variables = channel.receive_u64().map_err(SumcheckError::Channel)?;
    if variables != statement.variables as u64 {
        return Err(SumcheckError::HeaderVariableCountMismatch {
            expected: statement.variables,
            actual: variables,
        });
    }
    let claim = channel.receive_field().map_err(SumcheckError::Channel)?;
    if claim != statement.initial_claim {
        return Err(SumcheckError::HeaderClaimMismatch);
    }
    Ok(())
}

fn sumcheck_tag(phase: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SUMCHECK_TAG_DOMAIN);
    hasher.update(phase);
    *hasher.finalize().as_bytes()
}

struct IntegerInterpolator {
    nodes: Vec<PcsField>,
    inverse_denominators: Vec<PcsField>,
}

impl IntegerInterpolator {
    fn new<E>(degree: usize) -> Result<Self, SumcheckError<E>>
    where
        E: Debug + Display + Send + Sync + 'static,
    {
        let nodes = (0..=degree)
            .map(|index| PcsField::from(index as u64))
            .collect::<Vec<_>>();
        let mut inverse_denominators = Vec::with_capacity(nodes.len());
        for (index, &node) in nodes.iter().enumerate() {
            let mut denominator = PcsField::ONE;
            for (other, &other_node) in nodes.iter().enumerate() {
                if other != index {
                    denominator *= node - other_node;
                }
            }
            inverse_denominators.push(
                denominator
                    .inverse()
                    .ok_or(SumcheckError::NonDistinctInterpolationNodes)?,
            );
        }
        Ok(Self {
            nodes,
            inverse_denominators,
        })
    }

    fn evaluate(&self, evaluations: &[PcsField], point: PcsField) -> PcsField {
        debug_assert_eq!(evaluations.len(), self.nodes.len());
        let mut result = PcsField::ZERO;
        for (index, (&evaluation, &inverse_denominator)) in evaluations
            .iter()
            .zip(&self.inverse_denominators)
            .enumerate()
        {
            let mut numerator = PcsField::ONE;
            for (other, &other_node) in self.nodes.iter().enumerate() {
                if other != index {
                    numerator *= point - other_node;
                }
            }
            result += evaluation * numerator * inverse_denominator;
        }
        result
    }
}

fn prover_work<E>(
    table_len: usize,
    table_count: usize,
    degree: usize,
    variables: usize,
) -> Result<ProverWork, SumcheckError<E>>
where
    E: Debug + Display + Send + Sync + 'static,
{
    let round_pairs = table_len
        .checked_sub(1)
        .ok_or(SumcheckError::SizeOverflow)?;
    let evaluation_count = degree.checked_add(1).ok_or(SumcheckError::SizeOverflow)?;
    let combine_evaluations = table_len
        .checked_add(
            evaluation_count
                .checked_mul(round_pairs)
                .ok_or(SumcheckError::SizeOverflow)?,
        )
        .and_then(|value| value.checked_add(1))
        .ok_or(SumcheckError::SizeOverflow)?;
    let table_lerps = evaluation_count
        .checked_add(1)
        .and_then(|value| value.checked_mul(table_count))
        .and_then(|value| value.checked_mul(round_pairs))
        .ok_or(SumcheckError::SizeOverflow)?;
    let round_field_elements = variables
        .checked_mul(evaluation_count)
        .ok_or(SumcheckError::SizeOverflow)?;
    let initial_table_cells = table_count
        .checked_mul(table_len)
        .ok_or(SumcheckError::SizeOverflow)?;
    // Per-worker scratch + round evaluations + point + interpolation nodes
    // and weights. The initial full-table reduction has the largest active
    // index domain, so it also upper-bounds later round scratch concurrency.
    let scratch_copies = parallel_scratch_copies(table_len);
    let scratch_workspace = table_count
        .checked_mul(scratch_copies)
        .ok_or(SumcheckError::SizeOverflow)?;
    let interpolation_workspace = evaluation_count
        .checked_mul(2)
        .ok_or(SumcheckError::SizeOverflow)?;
    let peak_auxiliary_field_elements = scratch_workspace
        .checked_add(evaluation_count)
        .and_then(|value| value.checked_add(variables))
        .and_then(|value| value.checked_add(interpolation_workspace))
        .ok_or(SumcheckError::SizeOverflow)?;

    Ok(ProverWork {
        rounds: to_u64(variables)?,
        round_field_elements: to_u64(round_field_elements)?,
        combine_evaluations: to_u64(combine_evaluations)?,
        table_lerps: to_u64(table_lerps)?,
        initial_table_cells: to_u64(initial_table_cells)?,
        peak_auxiliary_field_elements: to_u64(peak_auxiliary_field_elements)?,
    })
}

fn parallel_scratch_copies(table_len: usize) -> usize {
    #[cfg(feature = "parallel")]
    {
        if table_len >= PARALLEL_MIN_ROWS {
            return rayon::current_num_threads().min(table_len);
        }
    }
    let _ = table_len;
    1
}

fn verifier_work<E>(degree: usize, variables: usize) -> Result<VerifierWork, SumcheckError<E>>
where
    E: Debug + Display + Send + Sync + 'static,
{
    let evaluation_count = degree.checked_add(1).ok_or(SumcheckError::SizeOverflow)?;
    let round_field_elements = variables
        .checked_mul(evaluation_count)
        .ok_or(SumcheckError::SizeOverflow)?;
    let interpolation_workspace = evaluation_count
        .checked_mul(3)
        .ok_or(SumcheckError::SizeOverflow)?;
    let peak_auxiliary_field_elements = variables
        .checked_add(interpolation_workspace)
        .ok_or(SumcheckError::SizeOverflow)?;
    Ok(VerifierWork {
        rounds: to_u64(variables)?,
        round_field_elements: to_u64(round_field_elements)?,
        interpolation_terms: to_u64(round_field_elements)?,
        peak_auxiliary_field_elements: to_u64(peak_auxiliary_field_elements)?,
    })
}

fn to_u64<E>(value: usize) -> Result<u64, SumcheckError<E>>
where
    E: Debug + Display + Send + Sync + 'static,
{
    u64::try_from(value).map_err(|_| SumcheckError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use ssv_whir_pcs::{OpeningClaims, PcsProtocol};

    use super::*;

    #[derive(Clone, Debug)]
    enum Message {
        Tag([u8; 32]),
        U64(u64),
        Field(PcsField),
    }

    #[derive(Debug, Error)]
    #[error("mock transcript is truncated or has the wrong message type")]
    struct MockChannelError;

    struct MockProverChannel {
        messages: Vec<Message>,
        challenges: VecDeque<PcsField>,
    }

    impl MockProverChannel {
        fn new(challenges: Vec<PcsField>) -> Self {
            Self {
                messages: Vec::new(),
                challenges: challenges.into(),
            }
        }

        fn finish(self) -> (Vec<Message>, Vec<PcsField>) {
            assert!(self.challenges.is_empty());
            (self.messages, Vec::new())
        }
    }

    impl ProverChannel for MockProverChannel {
        type Error = MockChannelError;

        fn send_tag(&mut self, value: [u8; 32]) -> Result<(), Self::Error> {
            self.messages.push(Message::Tag(value));
            Ok(())
        }

        fn send_u64(&mut self, value: u64) -> Result<(), Self::Error> {
            self.messages.push(Message::U64(value));
            Ok(())
        }

        fn send_field(&mut self, value: PcsField) -> Result<(), Self::Error> {
            self.messages.push(Message::Field(value));
            Ok(())
        }

        fn draw_challenge(&mut self) -> Result<PcsField, Self::Error> {
            self.challenges.pop_front().ok_or(MockChannelError)
        }
    }

    struct MockVerifierChannel {
        messages: VecDeque<Message>,
        challenges: VecDeque<PcsField>,
    }

    impl MockVerifierChannel {
        fn new(messages: Vec<Message>, challenges: Vec<PcsField>) -> Self {
            Self {
                messages: messages.into(),
                challenges: challenges.into(),
            }
        }

        fn pop(&mut self) -> Result<Message, MockChannelError> {
            self.messages.pop_front().ok_or(MockChannelError)
        }

        fn assert_consumed(self) {
            assert!(self.messages.is_empty());
            assert!(self.challenges.is_empty());
        }
    }

    impl VerifierChannel for MockVerifierChannel {
        type Error = MockChannelError;

        fn receive_tag(&mut self) -> Result<[u8; 32], Self::Error> {
            match self.pop()? {
                Message::Tag(value) => Ok(value),
                _ => Err(MockChannelError),
            }
        }

        fn receive_u64(&mut self) -> Result<u64, Self::Error> {
            match self.pop()? {
                Message::U64(value) => Ok(value),
                _ => Err(MockChannelError),
            }
        }

        fn receive_field(&mut self) -> Result<PcsField, Self::Error> {
            match self.pop()? {
                Message::Field(value) => Ok(value),
                _ => Err(MockChannelError),
            }
        }

        fn draw_challenge(&mut self) -> Result<PcsField, Self::Error> {
            self.challenges.pop_front().ok_or(MockChannelError)
        }
    }

    fn f(value: u64) -> PcsField {
        PcsField::from(value)
    }

    fn hypercube_sum<C>(tables: &[Vec<PcsField>], combine: C) -> PcsField
    where
        C: Fn(&[PcsField]) -> PcsField,
    {
        let mut values = vec![PcsField::ZERO; tables.len()];
        let mut claim = PcsField::ZERO;
        for index in 0..tables[0].len() {
            load_table_values(&mut values, tables, index);
            claim += combine(&values);
        }
        claim
    }

    #[test]
    fn degree_two_round_trip_and_work_are_exact() {
        let tables = vec![
            (0..8).map(|index| f(index + 1)).collect::<Vec<_>>(),
            (0..8).map(|index| f(3 * index + 2)).collect::<Vec<_>>(),
        ];
        let combine = |values: &[PcsField]| values[0] * values[1];
        let claim = hypercube_sum(&tables, combine);
        let statement = Statement::new(b"matvec", 2, 3, claim).unwrap();
        let challenges = vec![f(19), f(23), f(29)];
        let mut prover_channel = MockProverChannel::new(challenges.clone());
        let prover = prove(&mut prover_channel, statement, tables.clone(), combine).unwrap();
        let messages = prover_channel.messages.clone();

        let mut verifier_channel = MockVerifierChannel::new(messages, challenges.clone());
        let verifier = verify(&mut verifier_channel, statement).unwrap();
        verifier_channel.assert_consumed();

        assert_eq!(prover.point, challenges);
        assert_eq!(prover.point, verifier.point);
        assert_eq!(prover.claim, verifier.claim);
        assert_eq!(
            prover.table_evaluations[0],
            evaluate_mle_msb(&tables[0], &prover.point).unwrap()
        );
        assert_eq!(
            prover.table_evaluations[1],
            evaluate_mle_msb(&tables[1], &prover.point).unwrap()
        );
        assert_eq!(combine(&prover.table_evaluations), verifier.claim);
        assert_eq!(prover.work.rounds, 3);
        assert_eq!(prover.work.round_field_elements, 9);
        assert_eq!(prover.work.combine_evaluations, 30);
        assert_eq!(prover.work.table_lerps, 56);
        assert_eq!(verifier.work.round_field_elements, 9);
        assert_eq!(verifier.work.interpolation_terms, 9);
    }

    #[test]
    fn degree_seventeen_range_polynomial_round_trip() {
        let equality = (0..32)
            .map(|index| f((index * 7 + 3) as u64))
            .collect::<Vec<_>>();
        let digits = (0..32)
            .map(|index| f((index % 16) as u64))
            .collect::<Vec<_>>();
        let tables = vec![equality, digits];
        let combine = |values: &[PcsField]| {
            let mut membership = PcsField::ONE;
            for digit in 0..16_u64 {
                membership *= values[1] - f(digit);
            }
            values[0] * membership
        };
        let statement = Statement::new(b"range", 17, 5, PcsField::ZERO).unwrap();
        let challenges = vec![f(17), f(31), f(43), f(59), f(71)];
        let mut prover_channel = MockProverChannel::new(challenges.clone());
        let prover = prove(&mut prover_channel, statement, tables, combine).unwrap();
        let mut verifier_channel = MockVerifierChannel::new(prover_channel.messages, challenges);
        let verifier = verify(&mut verifier_channel, statement).unwrap();
        verifier_channel.assert_consumed();
        assert_eq!(combine(&prover.table_evaluations), verifier.claim);
        assert_eq!(prover.work.round_field_elements, 90);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_reductions_equal_serial_reference() {
        let rows = 1 << 13;
        let tables = vec![
            (0..rows)
                .map(|index| f((index * 17 + 5) as u64))
                .collect::<Vec<_>>(),
            (0..rows)
                .map(|index| f((index * 29 + 11) as u64))
                .collect::<Vec<_>>(),
            (0..rows)
                .map(|index| f((index % 16) as u64))
                .collect::<Vec<_>>(),
        ];
        let combine = |values: &[PcsField]| values[0] * values[1] + values[2].square();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();

        pool.install(|| {
            assert_eq!(
                sum_table_rows(&tables, rows, &combine),
                sum_table_rows_serial(&tables, rows, &combine)
            );
            let half = rows / 2;
            let point = f(37);
            assert_eq!(
                sum_interpolated_rows(&tables, half, point, &combine),
                sum_interpolated_rows_serial(&tables, half, point, &combine)
            );
        });
    }

    #[test]
    fn whir_transcript_adapters_compose_with_authenticated_endpoint() {
        let vector = (0..32)
            .map(|index| f((index * 7 + 3) as u64))
            .collect::<Vec<_>>();
        let claim = vector.iter().copied().sum::<PcsField>();
        let statement = Statement::new(b"adapter", 1, 5, claim).unwrap();
        let protocol = PcsProtocol::new(32, 1).unwrap();
        let statement_digest = [0x5a; 32];

        let output = protocol
            .prove_claims_with_transcript(
                &statement_digest,
                vec![vector],
                move |transcript, vectors| {
                    let endpoint =
                        prove(transcript, statement, vec![vectors[0].to_vec()], |values| {
                            values[0]
                        })?;
                    Ok::<_, SumcheckError<Infallible>>(OpeningClaims {
                        points: vec![endpoint.point],
                        evaluations: endpoint.table_evaluations,
                    })
                },
            )
            .unwrap();

        protocol
            .verify_with_transcript(&statement_digest, &output.certificate, move |transcript| {
                let endpoint = verify(transcript, statement)?;
                Ok::<_, SumcheckError<VerificationError>>(OpeningClaims {
                    points: vec![endpoint.point],
                    evaluations: vec![endpoint.claim],
                })
            })
            .unwrap();
    }

    #[test]
    fn half_folding_is_msb_first() {
        let first_bit = vec![f(0), f(0), f(1), f(1)];
        let second_bit = vec![f(0), f(1), f(0), f(1)];
        let tables = vec![first_bit, second_bit];
        let combine = |values: &[PcsField]| values[0] + values[1];
        let statement = Statement::new(b"order", 1, 2, f(4)).unwrap();
        let challenges = vec![f(7), f(11)];
        let mut channel = MockProverChannel::new(challenges);
        let endpoint = prove(&mut channel, statement, tables, combine).unwrap();
        assert_eq!(endpoint.table_evaluations, vec![f(7), f(11)]);
        assert_eq!(endpoint.point, vec![f(7), f(11)]);
    }

    #[test]
    fn singleton_table_has_an_endpoint_and_no_rounds() {
        let statement = Statement::new(b"singleton", 2, 0, f(9)).unwrap();
        let mut prover_channel = MockProverChannel::new(Vec::new());
        let prover = prove(
            &mut prover_channel,
            statement,
            vec![vec![f(4)], vec![f(5)]],
            |values| values[0] + values[1],
        )
        .unwrap();
        assert!(prover.point.is_empty());
        assert_eq!(prover.table_evaluations, vec![f(4), f(5)]);
        assert_eq!(prover.claim, f(9));

        let mut verifier_channel = MockVerifierChannel::new(prover_channel.messages, Vec::new());
        let verifier = verify(&mut verifier_channel, statement).unwrap();
        verifier_channel.assert_consumed();
        assert!(verifier.point.is_empty());
        assert_eq!(verifier.claim, f(9));
    }

    #[test]
    fn prover_detects_a_combine_polynomial_above_declared_degree_at_endpoint() {
        let statement = Statement::new(b"degree-bound", 1, 1, f(5)).unwrap();
        let error = prove(
            &mut MockProverChannel::new(vec![f(3)]),
            statement,
            vec![vec![f(1), f(2)]],
            |values| values[0].square(),
        )
        .unwrap_err();
        assert!(matches!(error, SumcheckError::ProverEndpointMismatch));
    }

    #[test]
    fn verifier_rejects_each_untrusted_header_value() {
        let statement = Statement::new(b"header", 2, 1, f(3)).unwrap();
        let mut prover_channel = MockProverChannel::new(vec![f(13)]);
        prove(
            &mut prover_channel,
            statement,
            vec![vec![f(1), f(2)]],
            |values| values[0],
        )
        .unwrap();

        let wrong_tag = Statement::new(b"other", 2, 1, f(3)).unwrap();
        let error = verify(
            &mut MockVerifierChannel::new(prover_channel.messages.clone(), vec![f(13)]),
            wrong_tag,
        )
        .unwrap_err();
        assert!(matches!(error, SumcheckError::HeaderTagMismatch));

        let wrong_degree = Statement::new(b"header", 3, 1, f(3)).unwrap();
        let error = verify(
            &mut MockVerifierChannel::new(prover_channel.messages.clone(), vec![f(13)]),
            wrong_degree,
        )
        .unwrap_err();
        assert!(matches!(error, SumcheckError::HeaderDegreeMismatch { .. }));

        let wrong_variables = Statement::new(b"header", 2, 2, f(3)).unwrap();
        let error = verify(
            &mut MockVerifierChannel::new(prover_channel.messages.clone(), vec![f(13), f(17)]),
            wrong_variables,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            SumcheckError::HeaderVariableCountMismatch { .. }
        ));

        let wrong_claim = Statement::new(b"header", 2, 1, f(4)).unwrap();
        let error = verify(
            &mut MockVerifierChannel::new(prover_channel.messages, vec![f(13)]),
            wrong_claim,
        )
        .unwrap_err();
        assert!(matches!(error, SumcheckError::HeaderClaimMismatch));
    }

    #[test]
    fn verifier_rejects_malformed_and_truncated_rounds() {
        let statement = Statement::new(b"round", 2, 1, f(3)).unwrap();
        let mut prover_channel = MockProverChannel::new(vec![f(13)]);
        prove(
            &mut prover_channel,
            statement,
            vec![vec![f(1), f(2)]],
            |values| values[0],
        )
        .unwrap();

        let mut malformed = prover_channel.messages.clone();
        let Message::Field(first_round_value) = &mut malformed[4] else {
            panic!("round messages follow the four header messages");
        };
        *first_round_value += f(1);
        let error = verify(
            &mut MockVerifierChannel::new(malformed, vec![f(13)]),
            statement,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            SumcheckError::RoundRelationMismatch { round: 0 }
        ));

        let mut truncated = prover_channel.messages;
        truncated.pop();
        let error = verify(
            &mut MockVerifierChannel::new(truncated, vec![f(13)]),
            statement,
        )
        .unwrap_err();
        assert!(matches!(error, SumcheckError::Channel(_)));
    }

    #[test]
    fn prover_rejects_bad_table_shapes_and_claims() {
        let statement = Statement::new(b"shape", 2, 2, f(0)).unwrap();
        let error = prove(
            &mut MockProverChannel::new(vec![f(1), f(2)]),
            statement,
            Vec::new(),
            |_| PcsField::ZERO,
        )
        .unwrap_err();
        assert!(matches!(error, SumcheckError::NoTables));

        let error = prove(
            &mut MockProverChannel::new(vec![f(1), f(2)]),
            statement,
            vec![vec![f(1), f(2), f(3)]],
            |values| values[0],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            SumcheckError::TableLengthNotPowerOfTwo { length: 3 }
        ));

        let error = prove(
            &mut MockProverChannel::new(vec![f(1), f(2)]),
            statement,
            vec![vec![f(1); 4], vec![f(2); 2]],
            |values| values[0] + values[1],
        )
        .unwrap_err();
        assert!(matches!(error, SumcheckError::TableLengthMismatch { .. }));

        let wrong_variables = Statement::new(b"shape", 2, 3, f(4)).unwrap();
        let error = prove(
            &mut MockProverChannel::new(vec![f(1), f(2), f(3)]),
            wrong_variables,
            vec![vec![f(1); 4]],
            |values| values[0],
        )
        .unwrap_err();
        assert!(matches!(error, SumcheckError::VariableCountMismatch { .. }));

        let wrong_claim = Statement::new(b"shape", 2, 2, f(5)).unwrap();
        let error = prove(
            &mut MockProverChannel::new(vec![f(1), f(2)]),
            wrong_claim,
            vec![vec![f(1); 4]],
            |values| values[0],
        )
        .unwrap_err();
        assert!(matches!(error, SumcheckError::InitialClaimMismatch));
    }

    #[test]
    fn statement_and_reference_evaluator_validate_inputs() {
        assert_eq!(
            Statement::new(b"", 2, 1, f(0)).unwrap_err(),
            StatementError::EmptyPhaseTag
        );
        assert_eq!(
            Statement::new(b"phase", 0, 1, f(0)).unwrap_err(),
            StatementError::DegreeTooSmall
        );
        assert_eq!(
            evaluate_mle_msb(&[], &[]).unwrap_err(),
            EvaluationError::EmptyTable
        );
        assert!(matches!(
            evaluate_mle_msb(&[f(1), f(2), f(3)], &[f(4)]),
            Err(EvaluationError::TableLengthNotPowerOfTwo { .. })
        ));
        assert!(matches!(
            evaluate_mle_msb(&[f(1), f(2)], &[]),
            Err(EvaluationError::PointLengthMismatch { .. })
        ));
    }

    #[test]
    fn mock_finish_helper_checks_no_undrawn_challenges() {
        let channel = MockProverChannel::new(Vec::new());
        let (messages, challenges) = channel.finish();
        assert!(messages.is_empty());
        assert!(challenges.is_empty());
    }
}
