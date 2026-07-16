use std::cell::RefCell;
use std::mem::size_of;

use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use ssv_field_sumcheck::{
    Statement as SumcheckStatement, prove as prove_sumcheck, verify as verify_sumcheck,
};
use ssv_problem::{
    MleEvaluationError, MleInterpreter, PublicEvaluationMetadata, PublicEvaluationWork,
    SuccinctPublicEvaluator,
};
use ssv_relation::{ExactRelation, RESIDUAL_MAGNITUDE_BITS, RelationError, audit_field_modulus};
use ssv_service_protocol::ProofProtocol;
use ssv_solution::Solution;
use ssv_validation::{PublicStatement, ValidationBackend, VerifierStatement};
use ssv_whir_pcs::transcript::VerifierMessage;
use ssv_whir_pcs::{
    Certificate, OpeningClaims, PcsError, PcsField, PcsProtocol, ProverMetrics, ProverTranscript,
    VerifierMetrics, VerifierTranscript,
};
use thiserror::Error;

use crate::digits::{
    COMMITTED_DIGIT_COLUMNS, DigitError, RESIDUAL_NIBBLE_COLUMNS, RESIDUAL_TABLE_COLUMNS,
    ResidualDigitTables, SELECTOR_SLOTS, SELECTOR_VARIABLES, WITNESS_NIBBLE_COLUMNS,
    WITNESS_TABLE_COLUMNS, WitnessDigitTables, field_from_biguint_checked, field_from_i128,
    field_modulus, pack_digit_tables, packed_point, reconstruct_residual,
    reconstruct_residual_unchecked, reconstruct_witness, reconstruct_witness_unchecked,
};

const RANGE_DEGREE: usize = 17;
const PRODUCT_DEGREE: usize = 2;
const DIGIT_WIDTH: u64 = 4;
const MINIMUM_ROW_DOMAIN: usize = 64;
const MAX_EXACT_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const PROTOCOL_TAG: &[u8] = b"sparse-solve/whir-field192-l2-v4/nibble-range/ssv-v1";
const FIELD_BYTES: usize = size_of::<PcsField>();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SquaredResidualReport {
    pub numerator: BigUint,
    pub denominator_power: u32,
}

impl SquaredResidualReport {
    #[must_use]
    pub fn squared_l2_approx(&self) -> Option<f64> {
        self.numerator
            .to_f64()
            .map(|value| value * 2.0_f64.powi(-(self.denominator_power as i32)))
    }

    #[must_use]
    pub fn l2_approx(&self) -> Option<f64> {
        self.squared_l2_approx().map(f64::sqrt)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AlgebraicProverWork {
    pub relation_sparse_nonzeros_visited: u64,
    pub matvec_sparse_nonzeros_visited: u64,
    pub range_rows: u64,
    pub sumcheck_rounds: u64,
    pub sumcheck_field_elements: u64,
    pub sumcheck_combine_evaluations: u64,
    pub endpoint_digit_evaluations: u64,
    pub outer_workspace_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AlgebraicVerifierWork {
    pub sumcheck_rounds: u64,
    pub sumcheck_field_elements: u64,
    pub endpoint_digit_evaluations: u64,
    pub public_matrix: PublicEvaluationWork,
    pub public_rhs: PublicEvaluationWork,
    pub generator_row_queries: u64,
    pub solution_elements_materialized: u64,
    pub residual_elements_materialized: u64,
    pub accounted_high_watermark_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ExactProverReport {
    pub residual: SquaredResidualReport,
    pub algebra: AlgebraicProverWork,
    pub pcs: ProverMetrics,
    pub payload_bytes: usize,
    pub accounted_high_watermark_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ExactVerifierReport {
    pub residual: SquaredResidualReport,
    pub algebra: AlgebraicVerifierWork,
    pub pcs: VerifierMetrics,
}

#[derive(Debug, Error)]
pub enum ExactError {
    #[error("exact backend requires validation protocol whir-field192-l2-v4")]
    WrongProtocol,
    #[error("public statement dimensions or exact profile header are inconsistent")]
    ProtocolHeader,
    #[error("the generator-derived integer bounds are unsafe for Field192")]
    UnsafeIntegerBounds,
    #[error("exact transcript is malformed, truncated, or inconsistent")]
    Transcript,
    #[error("sumcheck failed: {0}")]
    Sumcheck(String),
    #[error("sumcheck endpoint does not match authenticated or public evaluations in {0}")]
    SumcheckEndpoint(&'static str),
    #[error("honest prover derived inconsistent endpoint data")]
    ProverInconsistent,
    #[error("exact payload exceeds its fixed resource limit")]
    PayloadLimit,
    #[error("size or work accounting overflow")]
    SizeOverflow,
    #[error(transparent)]
    Relation(#[from] RelationError),
    #[error(transparent)]
    Digit(#[from] DigitError),
    #[error(transparent)]
    PublicEvaluation(#[from] MleEvaluationError),
    #[error(transparent)]
    Pcs(#[from] PcsError),
}

pub struct ExactBackend;

impl ValidationBackend for ExactBackend {
    type ProverContext = ();
    type ProverReport = ExactProverReport;
    type VerifierReport = ExactVerifierReport;
    type Error = ExactError;

    const PROTOCOL: ProofProtocol = ProofProtocol::WhirField192L2V4;

    fn prove(
        statement: &PublicStatement,
        solution: &Solution,
        _context: &Self::ProverContext,
    ) -> Result<(Vec<u8>, Self::ProverReport), Self::Error> {
        prove_payload(statement, solution)
    }

    fn verify(
        statement: &VerifierStatement<'_>,
        payload: &[u8],
    ) -> Result<Self::VerifierReport, Self::Error> {
        verify_payload(statement, payload)
    }
}

struct ProverHookOutput {
    residual: SquaredResidualReport,
    work: AlgebraicProverWork,
}

struct VerifierHookOutput {
    claims: OpeningClaims,
    residual: SquaredResidualReport,
    work: AlgebraicVerifierWork,
}

#[derive(Default)]
struct ClaimAccumulator {
    points: Vec<Vec<PcsField>>,
    evaluations: Vec<PcsField>,
}

impl ClaimAccumulator {
    fn push_digit_block(
        &mut self,
        row_point: &[PcsField],
        first_column: usize,
        values: &[PcsField],
    ) -> Result<(), ExactError> {
        for (offset, &value) in values.iter().enumerate() {
            self.points
                .push(packed_point(first_column + offset, row_point)?);
            self.evaluations.push(value);
        }
        Ok(())
    }

    fn finish(self) -> OpeningClaims {
        OpeningClaims {
            points: self.points,
            evaluations: self.evaluations,
        }
    }
}

pub fn prove_payload(
    statement: &PublicStatement,
    solution: &Solution,
) -> Result<(Vec<u8>, ExactProverReport), ExactError> {
    if statement.manifest().protocol != ProofProtocol::WhirField192L2V4 {
        return Err(ExactError::WrongProtocol);
    }
    let generated = statement.generated();
    audit_field_modulus(generated, &field_modulus())?;
    let relation = ExactRelation::from_solution(generated, solution)?;
    let padded_len = padded_len(generated.dimension())?;
    let witness_digits = WitnessDigitTables::from_i128(relation.witness().as_slice(), padded_len)?;
    let residual_digits = ResidualDigitTables::from_i128(relation.residuals(), padded_len)?;
    let rho = field_from_biguint_checked(relation.squared_l2_numerator())?;
    let packed = pack_digit_tables(&witness_digits, &residual_digits)?;
    let vector_len = packed.len();
    let pcs = PcsProtocol::new(vector_len, 1)?;
    let statement_digest = statement.transcript_digest().into_bytes();
    let hook_output = RefCell::new(None);
    let hook_slot = &hook_output;
    let output = pcs.prove_claims_with_transcript(
        &statement_digest,
        vec![packed],
        |transcript, _vectors| {
            let hook = prove_hook(
                transcript,
                statement,
                &relation,
                &witness_digits,
                &residual_digits,
                rho,
            )?;
            let claims = hook.0;
            *hook_slot.borrow_mut() = Some(hook.1);
            Ok::<_, ExactError>(claims)
        },
    )?;
    let hook = hook_output
        .into_inner()
        .ok_or(ExactError::ProverInconsistent)?;
    let payload = output.certificate.encode()?;
    if payload.len() > MAX_EXACT_PAYLOAD_BYTES {
        return Err(ExactError::PayloadLimit);
    }
    let retained_digit_cells = COMMITTED_DIGIT_COLUMNS
        .checked_mul(padded_len)
        .and_then(|cells| cells.checked_mul(FIELD_BYTES))
        .ok_or(ExactError::SizeOverflow)?;
    let accounted_high_watermark_bytes = output
        .metrics
        .accounted_high_watermark_bytes
        .checked_add(hook.work.outer_workspace_bytes)
        .and_then(|value| value.checked_add(retained_digit_cells))
        .ok_or(ExactError::SizeOverflow)?;
    Ok((
        payload,
        ExactProverReport {
            residual: hook.residual,
            algebra: hook.work,
            pcs: output.metrics,
            payload_bytes: output.certificate.encoded_len()?,
            accounted_high_watermark_bytes,
        },
    ))
}

pub fn verify_payload(
    statement: &VerifierStatement<'_>,
    payload: &[u8],
) -> Result<ExactVerifierReport, ExactError> {
    if statement.protocol() != ProofProtocol::WhirField192L2V4 {
        return Err(ExactError::WrongProtocol);
    }
    if payload.len() > MAX_EXACT_PAYLOAD_BYTES {
        return Err(ExactError::PayloadLimit);
    }
    let metadata = statement.public_evaluator().metadata();
    ensure_no_wrap_metadata(metadata)?;
    let padded_len = padded_len(statement.dimension())?;
    let vector_len = SELECTOR_SLOTS
        .checked_mul(padded_len)
        .ok_or(ExactError::SizeOverflow)?;
    let pcs = PcsProtocol::new(vector_len, 1)?;
    let certificate = Certificate::decode(payload, MAX_EXACT_PAYLOAD_BYTES)?;
    let statement_digest = statement.transcript_digest().into_bytes();
    let hook_output = RefCell::new(None);
    let hook_slot = &hook_output;
    let pcs_metrics =
        pcs.verify_with_transcript(&statement_digest, &certificate, |transcript| {
            let hook = verify_hook(transcript, statement, metadata, payload.len())?;
            let claims = hook.claims.clone();
            *hook_slot.borrow_mut() = Some(hook);
            Ok::<_, ExactError>(claims)
        })?;
    let hook = hook_output.into_inner().ok_or(ExactError::Transcript)?;
    Ok(ExactVerifierReport {
        residual: hook.residual,
        algebra: hook.work,
        pcs: pcs_metrics,
    })
}

fn prove_hook(
    transcript: &mut ProverTranscript,
    statement: &PublicStatement,
    relation: &ExactRelation,
    witness_digits: &WitnessDigitTables,
    residual_digits: &ResidualDigitTables,
    rho: PcsField,
) -> Result<(OpeningClaims, ProverHookOutput), ExactError> {
    let generated = statement.generated();
    let plan = generated.public_evaluation_plan();
    let metadata = plan.metadata();
    let padded_len = witness_digits.padded_len();
    let variables = padded_len.ilog2() as usize;
    send_protocol_header(transcript, generated.dimension(), padded_len, metadata)?;
    transcript.prover_message(&rho);

    let alpha: PcsField = VerifierMessage::verifier_message(transcript);
    let beta_x: PcsField = VerifierMessage::verifier_message(transcript);
    let beta_r: PcsField = VerifierMessage::verifier_message(transcript);
    let range_random = draw_prover_point(transcript, variables);
    let alpha_powers = powers(alpha, COMMITTED_DIGIT_COLUMNS);
    let mut range_tables = witness_digits
        .ordered_tables()
        .into_iter()
        .chain(residual_digits.ordered_tables())
        .map(<[PcsField]>::to_vec)
        .collect::<Vec<_>>();
    range_tables.push(equality_table(&range_random)?);
    range_tables.push(tail_mask_table(generated.dimension(), padded_len));
    range_tables.push(tail_mask_table(generated.dimension(), padded_len));
    let range_cells = range_tables
        .len()
        .checked_mul(padded_len)
        .ok_or(ExactError::SizeOverflow)?;
    let range_statement = SumcheckStatement::new(b"range", RANGE_DEGREE, variables, PcsField::ZERO)
        .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let range_endpoint = prove_sumcheck(transcript, range_statement, range_tables, |values| {
        range_constraint(values, &alpha_powers, beta_x, beta_r)
    })
    .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let range_digit_values = &range_endpoint.table_evaluations[..COMMITTED_DIGIT_COLUMNS];
    send_fields_prover(transcript, range_digit_values);
    let mut claims = ClaimAccumulator::default();
    claims.push_digit_block(&range_endpoint.point, 0, range_digit_values)?;

    let row_point = draw_prover_point(transcript, variables);
    let residual_at_row = residual_digits.evaluate_digits(&row_point)?;
    send_fields_prover(transcript, &residual_at_row);
    claims.push_digit_block(&row_point, WITNESS_TABLE_COLUMNS, &residual_at_row)?;
    let residual_row_value = reconstruct_residual(&residual_at_row)?;
    let rhs = plan.evaluate_rhs_mle_zero_padded(&FieldInterpreter, &row_point)?;
    let initial_matvec_claim = scale_rhs(rhs.value, metadata)? + residual_row_value;
    let (matrix_rows, matvec_visits) = compress_matrix_rows(generated, &row_point, padded_len)?;
    let witness_values = witness_digits.reconstructed_table();
    let matvec_statement =
        SumcheckStatement::new(b"matvec", PRODUCT_DEGREE, variables, initial_matvec_claim)
            .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let matvec_endpoint = prove_sumcheck(
        transcript,
        matvec_statement,
        vec![matrix_rows, witness_values],
        |values| values[0] * values[1],
    )
    .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let witness_at_column = witness_digits.evaluate_digits(&matvec_endpoint.point)?;
    if reconstruct_witness(&witness_at_column)? != matvec_endpoint.table_evaluations[1] {
        return Err(ExactError::ProverInconsistent);
    }
    send_fields_prover(transcript, &witness_at_column);
    claims.push_digit_block(&matvec_endpoint.point, 0, &witness_at_column)?;

    let residual_values = residual_digits.reconstructed_table();
    let norm_statement = SumcheckStatement::new(b"norm", PRODUCT_DEGREE, variables, rho)
        .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let norm_endpoint = prove_sumcheck(
        transcript,
        norm_statement,
        vec![residual_values.clone(), residual_values],
        |values| values[0] * values[1],
    )
    .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let residual_at_norm = residual_digits.evaluate_digits(&norm_endpoint.point)?;
    if reconstruct_residual(&residual_at_norm)? != norm_endpoint.table_evaluations[0] {
        return Err(ExactError::ProverInconsistent);
    }
    send_fields_prover(transcript, &residual_at_norm);
    claims.push_digit_block(
        &norm_endpoint.point,
        WITNESS_TABLE_COLUMNS,
        &residual_at_norm,
    )?;

    let sumcheck_rounds = range_endpoint
        .work
        .rounds
        .checked_add(matvec_endpoint.work.rounds)
        .and_then(|value| value.checked_add(norm_endpoint.work.rounds))
        .ok_or(ExactError::SizeOverflow)?;
    let sumcheck_field_elements = range_endpoint
        .work
        .round_field_elements
        .checked_add(matvec_endpoint.work.round_field_elements)
        .and_then(|value| value.checked_add(norm_endpoint.work.round_field_elements))
        .ok_or(ExactError::SizeOverflow)?;
    let combine_evaluations = range_endpoint
        .work
        .combine_evaluations
        .checked_add(matvec_endpoint.work.combine_evaluations)
        .and_then(|value| value.checked_add(norm_endpoint.work.combine_evaluations))
        .ok_or(ExactError::SizeOverflow)?;
    let digit_cells = COMMITTED_DIGIT_COLUMNS
        .checked_mul(padded_len)
        .ok_or(ExactError::SizeOverflow)?;
    let outer_workspace_bytes = digit_cells
        .checked_add(range_cells)
        .and_then(|cells| cells.checked_add(4 * padded_len))
        .and_then(|cells| cells.checked_mul(FIELD_BYTES))
        .ok_or(ExactError::SizeOverflow)?;
    let relation_visits =
        u64::try_from(generated.structural_nnz()).map_err(|_| ExactError::SizeOverflow)?;
    Ok((
        claims.finish(),
        ProverHookOutput {
            residual: SquaredResidualReport {
                numerator: relation.squared_l2_numerator().clone(),
                denominator_power: relation.squared_l2_denominator_power(),
            },
            work: AlgebraicProverWork {
                relation_sparse_nonzeros_visited: relation_visits,
                matvec_sparse_nonzeros_visited: matvec_visits,
                range_rows: padded_len as u64,
                sumcheck_rounds,
                sumcheck_field_elements,
                sumcheck_combine_evaluations: combine_evaluations,
                endpoint_digit_evaluations: 120,
                outer_workspace_bytes,
            },
        },
    ))
}

fn verify_hook(
    transcript: &mut VerifierTranscript<'_>,
    statement: &VerifierStatement<'_>,
    metadata: PublicEvaluationMetadata,
    certificate_bytes: usize,
) -> Result<VerifierHookOutput, ExactError> {
    let padded_len = padded_len(statement.dimension())?;
    let variables = padded_len.ilog2() as usize;
    receive_protocol_header(transcript, statement.dimension(), padded_len, metadata)?;
    let rho: PcsField = transcript
        .prover_message()
        .map_err(|_| ExactError::Transcript)?;
    let rho_integer = field_to_biguint(rho);

    let alpha: PcsField = VerifierMessage::verifier_message(transcript);
    let beta_x: PcsField = VerifierMessage::verifier_message(transcript);
    let beta_r: PcsField = VerifierMessage::verifier_message(transcript);
    let range_random = draw_verifier_point(transcript, variables);
    let alpha_powers = powers(alpha, COMMITTED_DIGIT_COLUMNS);
    let range_statement = SumcheckStatement::new(b"range", RANGE_DEGREE, variables, PcsField::ZERO)
        .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let range_endpoint = verify_sumcheck(transcript, range_statement)
        .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let range_digit_values = read_fields(transcript, COMMITTED_DIGIT_COLUMNS)?;
    let mut claims = ClaimAccumulator::default();
    claims.push_digit_block(&range_endpoint.point, 0, &range_digit_values)?;
    let mut range_values = range_digit_values;
    range_values.push(equality_evaluation(&range_random, &range_endpoint.point)?);
    range_values.push(evaluate_tail_mask_mle(
        &range_endpoint.point,
        statement.dimension(),
    )?);
    range_values.push(evaluate_tail_mask_mle(
        &range_endpoint.point,
        statement.dimension(),
    )?);
    if range_constraint(&range_values, &alpha_powers, beta_x, beta_r) != range_endpoint.claim {
        return Err(ExactError::SumcheckEndpoint("range"));
    }

    let row_point = draw_verifier_point(transcript, variables);
    let residual_at_row = read_fields(transcript, RESIDUAL_TABLE_COLUMNS)?;
    claims.push_digit_block(&row_point, WITNESS_TABLE_COLUMNS, &residual_at_row)?;
    let residual_row_value = reconstruct_residual(&residual_at_row)?;
    let plan = statement.public_evaluator();
    let rhs = plan.evaluate_rhs_mle_zero_padded(&FieldInterpreter, &row_point)?;
    let initial_matvec_claim = scale_rhs(rhs.value, metadata)? + residual_row_value;
    let matvec_statement =
        SumcheckStatement::new(b"matvec", PRODUCT_DEGREE, variables, initial_matvec_claim)
            .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let matvec_endpoint = verify_sumcheck(transcript, matvec_statement)
        .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let witness_at_column = read_fields(transcript, WITNESS_TABLE_COLUMNS)?;
    claims.push_digit_block(&matvec_endpoint.point, 0, &witness_at_column)?;
    let witness_value = reconstruct_witness(&witness_at_column)?;
    let matrix = plan.evaluate_matrix_mle_zero_padded(
        &FieldInterpreter,
        &row_point,
        &matvec_endpoint.point,
    )?;
    if matvec_endpoint.claim != matrix.value * witness_value {
        return Err(ExactError::SumcheckEndpoint("matvec"));
    }

    let norm_statement = SumcheckStatement::new(b"norm", PRODUCT_DEGREE, variables, rho)
        .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let norm_endpoint = verify_sumcheck(transcript, norm_statement)
        .map_err(|error| ExactError::Sumcheck(error.to_string()))?;
    let residual_at_norm = read_fields(transcript, RESIDUAL_TABLE_COLUMNS)?;
    claims.push_digit_block(
        &norm_endpoint.point,
        WITNESS_TABLE_COLUMNS,
        &residual_at_norm,
    )?;
    let residual_value = reconstruct_residual(&residual_at_norm)?;
    if norm_endpoint.claim != residual_value * residual_value {
        return Err(ExactError::SumcheckEndpoint("norm"));
    }

    let sumcheck_rounds = range_endpoint
        .work
        .rounds
        .checked_add(matvec_endpoint.work.rounds)
        .and_then(|value| value.checked_add(norm_endpoint.work.rounds))
        .ok_or(ExactError::SizeOverflow)?;
    let sumcheck_field_elements = range_endpoint
        .work
        .round_field_elements
        .checked_add(matvec_endpoint.work.round_field_elements)
        .and_then(|value| value.checked_add(norm_endpoint.work.round_field_elements))
        .ok_or(ExactError::SizeOverflow)?;
    let claims = claims.finish();
    let opening_fields = claims
        .points
        .iter()
        .try_fold(0_usize, |sum, point| sum.checked_add(point.len()))
        .and_then(|value| value.checked_add(claims.evaluations.len()))
        .ok_or(ExactError::SizeOverflow)?;
    let accounted_high_watermark_bytes = certificate_bytes
        .checked_add(
            opening_fields
                .checked_mul(FIELD_BYTES)
                .ok_or(ExactError::SizeOverflow)?,
        )
        .ok_or(ExactError::SizeOverflow)?;
    Ok(VerifierHookOutput {
        claims,
        residual: SquaredResidualReport {
            numerator: rho_integer,
            denominator_power: denominator_power(metadata)?,
        },
        work: AlgebraicVerifierWork {
            sumcheck_rounds,
            sumcheck_field_elements,
            endpoint_digit_evaluations: 120,
            public_matrix: matrix.work,
            public_rhs: rhs.work,
            generator_row_queries: 0,
            solution_elements_materialized: 0,
            residual_elements_materialized: 0,
            accounted_high_watermark_bytes,
        },
    })
}

struct FieldInterpreter;

impl MleInterpreter for FieldInterpreter {
    type Scalar = PcsField;

    fn zero(&self) -> Self::Scalar {
        PcsField::ZERO
    }

    fn one(&self) -> Self::Scalar {
        PcsField::ONE
    }

    fn embed_i64(&self, value: i64) -> Self::Scalar {
        field_from_i128(i128::from(value))
    }

    fn add(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar {
        left + right
    }

    fn sub(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar {
        left - right
    }

    fn mul(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar {
        left * right
    }
}

fn range_constraint(
    values: &[PcsField],
    alpha_powers: &[PcsField],
    beta_x: PcsField,
    beta_r: PcsField,
) -> PcsField {
    debug_assert_eq!(values.len(), COMMITTED_DIGIT_COLUMNS + 3);
    let mut constraint = PcsField::ZERO;
    for index in 0..COMMITTED_DIGIT_COLUMNS {
        let range = if index < WITNESS_NIBBLE_COLUMNS {
            16
        } else if index == WITNESS_NIBBLE_COLUMNS {
            8
        } else if index == WITNESS_TABLE_COLUMNS - 1 {
            2
        } else if index < WITNESS_TABLE_COLUMNS + RESIDUAL_NIBBLE_COLUMNS {
            16
        } else {
            2
        };
        constraint += alpha_powers[index] * membership_polynomial(values[index], range);
    }
    let witness_tail = values[COMMITTED_DIGIT_COLUMNS + 1];
    let residual_tail = values[COMMITTED_DIGIT_COLUMNS + 2];
    constraint +=
        beta_x * witness_tail * reconstruct_witness_unchecked(&values[..WITNESS_TABLE_COLUMNS]);
    constraint += beta_r
        * residual_tail
        * reconstruct_residual_unchecked(&values[WITNESS_TABLE_COLUMNS..COMMITTED_DIGIT_COLUMNS]);
    values[COMMITTED_DIGIT_COLUMNS] * constraint
}

fn membership_polynomial(value: PcsField, range: usize) -> PcsField {
    (0..range)
        .map(|root| value - PcsField::from(root as u64))
        .product()
}

fn padded_len(logical_len: usize) -> Result<usize, ExactError> {
    logical_len
        .max(MINIMUM_ROW_DOMAIN)
        .checked_next_power_of_two()
        .ok_or(ExactError::SizeOverflow)
}

fn denominator_power(metadata: PublicEvaluationMetadata) -> Result<u32, ExactError> {
    64_u32
        .checked_add(u32::from(metadata.exact_bounds.matrix_fractional_bits))
        .and_then(|value| value.checked_mul(2))
        .ok_or(ExactError::SizeOverflow)
}

fn scale_rhs(
    rhs_mantissa_mle: PcsField,
    metadata: PublicEvaluationMetadata,
) -> Result<PcsField, ExactError> {
    let relation_fractional_bits = 64_u32
        .checked_add(u32::from(metadata.exact_bounds.matrix_fractional_bits))
        .ok_or(ExactError::SizeOverflow)?;
    let shift = relation_fractional_bits
        .checked_sub(u32::from(metadata.exact_bounds.rhs_fractional_bits))
        .ok_or(ExactError::ProtocolHeader)?;
    Ok(pow2_field(shift as usize) * rhs_mantissa_mle)
}

fn ensure_no_wrap_metadata(metadata: PublicEvaluationMetadata) -> Result<(), ExactError> {
    let matrix_term = BigUint::from(metadata.exact_bounds.maximum_absolute_row_sum_mantissa) << 127;
    let shift = 64_u32
        .checked_add(u32::from(metadata.exact_bounds.matrix_fractional_bits))
        .and_then(|value| value.checked_sub(u32::from(metadata.exact_bounds.rhs_fractional_bits)))
        .ok_or(ExactError::ProtocolHeader)?;
    let rhs_term =
        BigUint::from(metadata.exact_bounds.maximum_absolute_rhs_mantissa) << (shift as usize);
    let row_bound = matrix_term + rhs_term + (BigUint::from(1_u8) << RESIDUAL_MAGNITUDE_BITS);
    let rho_bound =
        BigUint::from(metadata.domain.logical_dimension) << (2 * RESIDUAL_MAGNITUDE_BITS);
    let modulus = field_modulus();
    if row_bound >= modulus || rho_bound >= modulus {
        return Err(ExactError::UnsafeIntegerBounds);
    }
    Ok(())
}

fn compress_matrix_rows(
    generated: &ssv_problem::GeneratedProblem,
    row_point: &[PcsField],
    padded_len: usize,
) -> Result<(Vec<PcsField>, u64), ExactError> {
    let weights = equality_table(row_point)?;
    let mut result = vec![PcsField::ZERO; padded_len];
    let mut visits = 0_u64;
    for (row, &weight) in weights.iter().take(generated.dimension()).enumerate() {
        for entry in generated.row(row).ok_or(ExactError::ProverInconsistent)? {
            result[entry.column] += weight * field_from_i128(i128::from(entry.value.mantissa()));
            visits = visits.checked_add(1).ok_or(ExactError::SizeOverflow)?;
        }
    }
    Ok((result, visits))
}

fn equality_table(point: &[PcsField]) -> Result<Vec<PcsField>, ExactError> {
    let size = 1_usize
        .checked_shl(point.len() as u32)
        .ok_or(ExactError::SizeOverflow)?;
    let mut table = vec![PcsField::ZERO; size];
    table[0] = PcsField::ONE;
    let mut active = 1;
    for &coordinate in point {
        for index in (0..active).rev() {
            let value = table[index];
            table[2 * index] = value * (PcsField::ONE - coordinate);
            table[2 * index + 1] = value * coordinate;
        }
        active *= 2;
    }
    Ok(table)
}

fn equality_evaluation(left: &[PcsField], right: &[PcsField]) -> Result<PcsField, ExactError> {
    if left.len() != right.len() {
        return Err(ExactError::Transcript);
    }
    Ok(left
        .iter()
        .zip(right)
        .map(|(&lhs, &rhs)| (PcsField::ONE - lhs) * (PcsField::ONE - rhs) + lhs * rhs)
        .product())
}

fn tail_mask_table(logical_len: usize, padded_len: usize) -> Vec<PcsField> {
    (0..padded_len)
        .map(|index| {
            if index < logical_len {
                PcsField::ZERO
            } else {
                PcsField::ONE
            }
        })
        .collect()
}

fn evaluate_tail_mask_mle(point: &[PcsField], logical_len: usize) -> Result<PcsField, ExactError> {
    Ok(PcsField::ONE - bounded_index_sum(point, logical_len)?)
}

fn bounded_index_sum(point: &[PcsField], limit: usize) -> Result<PcsField, ExactError> {
    let domain = 1_usize
        .checked_shl(point.len() as u32)
        .ok_or(ExactError::SizeOverflow)?;
    if limit > domain {
        return Err(ExactError::ProtocolHeader);
    }
    if limit == 0 {
        return Ok(PcsField::ZERO);
    }
    if limit == domain {
        return Ok(PcsField::ONE);
    }
    let mut states = [PcsField::ONE, PcsField::ZERO];
    for bit in 0..point.len() {
        let coordinate = point[point.len() - 1 - bit];
        let limit_bit = (limit >> bit) & 1;
        let mut next = [PcsField::ZERO; 2];
        for (borrow_in, state) in states.into_iter().enumerate() {
            for index_bit in 0..=1 {
                let borrow_out = usize::from(index_bit < limit_bit + borrow_in);
                let weight = if index_bit == 0 {
                    PcsField::ONE - coordinate
                } else {
                    coordinate
                };
                next[borrow_out] += state * weight;
            }
        }
        states = next;
    }
    Ok(states[1])
}

fn powers(base: PcsField, count: usize) -> Vec<PcsField> {
    let mut current = PcsField::ONE;
    (0..count)
        .map(|_| {
            let value = current;
            current *= base;
            value
        })
        .collect()
}

fn pow2_field(exponent: usize) -> PcsField {
    let mut value = PcsField::ONE;
    for _ in 0..exponent {
        value += value;
    }
    value
}

fn field_to_biguint(value: PcsField) -> BigUint {
    BigUint::from_bytes_le(&value.into_bigint().to_bytes_le())
}

fn protocol_header_values(
    dimension: usize,
    padded_len: usize,
    metadata: PublicEvaluationMetadata,
) -> Result<[u64; 14], ExactError> {
    Ok([
        u64::try_from(dimension).map_err(|_| ExactError::SizeOverflow)?,
        u64::try_from(dimension).map_err(|_| ExactError::SizeOverflow)?,
        u64::try_from(padded_len).map_err(|_| ExactError::SizeOverflow)?,
        SELECTOR_VARIABLES as u64,
        COMMITTED_DIGIT_COLUMNS as u64,
        WITNESS_TABLE_COLUMNS as u64,
        RESIDUAL_TABLE_COLUMNS as u64,
        DIGIT_WIDTH,
        u64::from(RESIDUAL_MAGNITUDE_BITS),
        u64::from(denominator_power(metadata)?),
        u64::from(metadata.exact_bounds.matrix_fractional_bits),
        u64::from(metadata.exact_bounds.rhs_fractional_bits),
        u64::from(metadata.evaluator_version),
        1, // MSB-first coordinate-order discriminator.
    ])
}

fn send_protocol_header(
    transcript: &mut ProverTranscript,
    dimension: usize,
    padded_len: usize,
    metadata: PublicEvaluationMetadata,
) -> Result<(), ExactError> {
    transcript.prover_message(blake3::hash(PROTOCOL_TAG).as_bytes());
    for value in protocol_header_values(dimension, padded_len, metadata)? {
        transcript.prover_message(&value.to_le_bytes());
    }
    Ok(())
}

fn receive_protocol_header(
    transcript: &mut VerifierTranscript<'_>,
    dimension: usize,
    padded_len: usize,
    metadata: PublicEvaluationMetadata,
) -> Result<(), ExactError> {
    let received: [u8; 32] = transcript
        .prover_message()
        .map_err(|_| ExactError::Transcript)?;
    if received != *blake3::hash(PROTOCOL_TAG).as_bytes() {
        return Err(ExactError::ProtocolHeader);
    }
    for expected in protocol_header_values(dimension, padded_len, metadata)? {
        let encoded: [u8; 8] = transcript
            .prover_message()
            .map_err(|_| ExactError::Transcript)?;
        if u64::from_le_bytes(encoded) != expected {
            return Err(ExactError::ProtocolHeader);
        }
    }
    Ok(())
}

fn draw_prover_point(transcript: &mut ProverTranscript, variables: usize) -> Vec<PcsField> {
    (0..variables)
        .map(|_| VerifierMessage::verifier_message(transcript))
        .collect()
}

fn draw_verifier_point(transcript: &mut VerifierTranscript<'_>, variables: usize) -> Vec<PcsField> {
    (0..variables)
        .map(|_| VerifierMessage::verifier_message(transcript))
        .collect()
}

fn send_fields_prover(transcript: &mut ProverTranscript, values: &[PcsField]) {
    for value in values {
        transcript.prover_message(value);
    }
}

fn read_fields(
    transcript: &mut VerifierTranscript<'_>,
    count: usize,
) -> Result<Vec<PcsField>, ExactError> {
    (0..count)
        .map(|_| {
            transcript
                .prover_message()
                .map_err(|_| ExactError::Transcript)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ssv_problem::{
        BoundaryRule, DiagonalConstruction, InstanceSeed, MatrixSpec, OffDiagonalValues,
        ProblemTemplate, RequestedOutput, RhsSpec, TemplateRandomness, TemplateSchema,
    };
    use ssv_service_protocol::{ValidationManifest, ValidationSchema};

    use super::*;

    fn fixture_statement(dimension: u64) -> PublicStatement {
        let problem = ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness: TemplateRandomness::LiteralV1 {
                seed: InstanceSeed::from_bytes([19; 32]),
            },
            matrix: MatrixSpec::SeededSymmetricTridiagonalV1 {
                dimension,
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
                schema: ValidationSchema::V1,
                protocol: ProofProtocol::WhirField192L2V4,
                max_solution_elements: dimension,
                max_public_matrix_terms: 64,
                max_public_rhs_terms: 64,
            },
            None,
        )
        .unwrap()
    }

    #[test]
    fn blog_minimum_domain_exact_proof_round_trips_without_verifier_scans() {
        let statement = fixture_statement(8);
        let solution = Solution::new(vec![1.0; 8], 8).unwrap();
        let (payload, prover) = prove_payload(&statement, &solution).unwrap();
        let verifier = verify_payload(&statement.verifier_statement(), &payload).unwrap();
        assert_eq!(prover.residual.numerator, BigUint::from(0_u8));
        assert_eq!(verifier.residual, prover.residual);
        assert_eq!(prover.algebra.sumcheck_rounds, 18);
        assert_eq!(verifier.algebra.sumcheck_field_elements, 144);
        assert_eq!(verifier.algebra.generator_row_queries, 0);
        assert_eq!(verifier.algebra.solution_elements_materialized, 0);
        assert_eq!(verifier.algebra.residual_elements_materialized, 0);
        assert_eq!(verifier.pcs.opening_points, 120);
    }

    #[test]
    fn payload_mutation_and_wrong_statement_are_rejected() {
        let statement = fixture_statement(8);
        let solution = Solution::new(vec![1.0; 8], 8).unwrap();
        let (payload, _) = prove_payload(&statement, &solution).unwrap();
        let mut mutated = payload.clone();
        let index = mutated.len() / 2;
        mutated[index] ^= 1;
        assert!(verify_payload(&statement.verifier_statement(), &mutated).is_err());

        let other = fixture_statement(9);
        assert!(verify_payload(&other.verifier_statement(), &payload).is_err());
    }
}
