//! Backend-neutral, verifier-cheap evaluations of registered public data.
//!
//! A random-access row generator is sufficient for a prover scan, but a
//! succinct verifier needs a stronger capability: it must evaluate the
//! multilinear extensions of the public matrix and right-hand side without
//! visiting every row.  [`PublicEvaluationPlan`] is that capability for a
//! compiled [`GeneratedProblem`].  Exact-field and binary64 callers use the
//! same plan and the same operation order; neither caller needs to inspect a
//! [`crate::MatrixSpec`] variant.
//!
//! Coordinates are **most-significant first**, matching WHIR and the research
//! implementation: `point[0]` selects the low or high half of the padded table,
//! while the last coordinate selects adjacent entries.  Logical indices occupy
//! `0..dimension`; the remainder of the next-power-of-two domain is exactly
//! zero.

use std::fmt::Debug;

use thiserror::Error;

use crate::GeneratedProblem;

/// The one registered Boolean-coordinate convention.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BooleanCoordinateOrder {
    /// Coordinate zero is the most-significant Boolean index bit.
    MostSignificantFirst,
}

/// Logical and zero-padded domain information for a public MLE.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MleDomain {
    pub logical_dimension: usize,
    pub padded_dimension: usize,
    pub variables: usize,
    pub coordinate_order: BooleanCoordinateOrder,
}

/// Exact, generator-derived coefficient bounds.
///
/// These values are recomputed from the compiled public generator.  A proof is
/// never allowed to supply or weaken them.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExactArithmeticBounds {
    pub logical_dimension: usize,
    pub matrix_fractional_bits: u8,
    pub rhs_fractional_bits: u8,
    pub maximum_absolute_row_sum_mantissa: u64,
    pub maximum_absolute_rhs_mantissa: u64,
}

/// Conservative powers-of-two bounds for an exact integer relation.
///
/// A field modulus at least `2^minimum_safe_modulus_bits` is sufficient for
/// the row-identity and residual-norm differences described here not to wrap.
/// The backend must still enforce the witness and residual ranges used as
/// inputs to [`ExactArithmeticBounds::no_wrap_diagnostics`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExactNoWrapDiagnostics {
    pub relation_fractional_bits: u32,
    pub matrix_term_alignment_shift: u32,
    pub rhs_alignment_shift: u32,
    pub matrix_vector_absolute_value_strict_bound_bits: u32,
    pub rhs_absolute_value_strict_bound_bits: u32,
    pub row_identity_difference_strict_bound_bits: u32,
    pub residual_norm_strict_bound_bits: u32,
    pub norm_identity_difference_strict_bound_bits: u32,
    pub minimum_safe_modulus_bits: u32,
}

impl ExactArithmeticBounds {
    /// Derives conservative no-wrap requirements for a fixed-point backend.
    ///
    /// `witness_magnitude_bits` means every witness integer has absolute value
    /// strictly below `2^witness_magnitude_bits`.  `residual_magnitude_bits`
    /// has the analogous meaning for the backend-constrained residual integer.
    /// The residual is represented at the returned relation scale.
    pub fn no_wrap_diagnostics(
        self,
        witness_magnitude_bits: u16,
        witness_fractional_bits: u8,
        residual_magnitude_bits: u16,
    ) -> Result<ExactNoWrapDiagnostics, MleEvaluationError> {
        let matrix_scale = u32::from(self.matrix_fractional_bits)
            .checked_add(u32::from(witness_fractional_bits))
            .ok_or(MleEvaluationError::ArithmeticBoundsOverflow)?;
        let rhs_scale = u32::from(self.rhs_fractional_bits);
        let relation_fractional_bits = matrix_scale.max(rhs_scale);
        let matrix_term_alignment_shift = relation_fractional_bits - matrix_scale;
        let rhs_alignment_shift = relation_fractional_bits - rhs_scale;

        let matrix_vector_absolute_value_strict_bound_bits =
            strict_u64_bound_bits(self.maximum_absolute_row_sum_mantissa)
                .checked_add(u32::from(witness_magnitude_bits))
                .and_then(|bits| bits.checked_add(matrix_term_alignment_shift))
                .ok_or(MleEvaluationError::ArithmeticBoundsOverflow)?;
        let rhs_absolute_value_strict_bound_bits =
            strict_u64_bound_bits(self.maximum_absolute_rhs_mantissa)
                .checked_add(rhs_alignment_shift)
                .ok_or(MleEvaluationError::ArithmeticBoundsOverflow)?;
        let residual_bits = u32::from(residual_magnitude_bits);

        // |Ax - b - R| is a sum of three quantities, each strictly below
        // 2^max_bits.  Two additional bits are a simple conservative bound.
        let row_identity_difference_strict_bound_bits =
            matrix_vector_absolute_value_strict_bound_bits
                .max(rhs_absolute_value_strict_bound_bits)
                .max(residual_bits)
                .checked_add(2)
                .ok_or(MleEvaluationError::ArithmeticBoundsOverflow)?;

        let residual_norm_strict_bound_bits = residual_bits
            .checked_mul(2)
            .and_then(|bits| bits.checked_add(ceil_log2(self.logical_dimension)))
            .ok_or(MleEvaluationError::ArithmeticBoundsOverflow)?;
        // Both the recomputed norm and the claimed, range-checked norm are
        // below the preceding bound.
        let norm_identity_difference_strict_bound_bits = residual_norm_strict_bound_bits
            .checked_add(1)
            .ok_or(MleEvaluationError::ArithmeticBoundsOverflow)?;
        let minimum_safe_modulus_bits = row_identity_difference_strict_bound_bits
            .max(norm_identity_difference_strict_bound_bits)
            .checked_add(1)
            .ok_or(MleEvaluationError::ArithmeticBoundsOverflow)?;

        Ok(ExactNoWrapDiagnostics {
            relation_fractional_bits,
            matrix_term_alignment_shift,
            rhs_alignment_shift,
            matrix_vector_absolute_value_strict_bound_bits,
            rhs_absolute_value_strict_bound_bits,
            row_identity_difference_strict_bound_bits,
            residual_norm_strict_bound_bits,
            norm_identity_difference_strict_bound_bits,
            minimum_safe_modulus_bits,
        })
    }
}

/// Public structure and cost bounds shared by all succinct backends.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PublicEvaluationMetadata {
    /// Reviewed semantics/version of the compiled public evaluator plan.
    pub evaluator_version: u16,
    pub domain: MleDomain,
    /// Maximum matrix-period patterns examined by one evaluation.
    pub matrix_period_terms: usize,
    /// Maximum RHS-period patterns examined by one evaluation.
    pub rhs_period_terms: usize,
    pub exact_bounds: ExactArithmeticBounds,
}

/// Arithmetic performed by one public evaluation.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct PublicEvaluationWork {
    pub periodic_terms: u64,
    pub additions: u64,
    pub subtractions: u64,
    pub multiplications: u64,
}

impl PublicEvaluationWork {
    #[must_use]
    pub const fn arithmetic_operations(self) -> u64 {
        self.additions + self.subtractions + self.multiplications
    }
}

/// A mantissa-valued public MLE and its common dyadic scale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MleEvaluation<T> {
    pub value: T,
    pub fractional_bits: u8,
    pub work: PublicEvaluationWork,
}

/// Forward-error and operand-scale diagnostics for the frozen binary64 path.
///
/// The error bound follows ordinary interval propagation through the exact
/// operation sequence and adds one conservative binary64 rounding allowance
/// per operation.  It is useful input to a backend's fixed tolerance policy;
/// it is not itself a global soundness theorem for an approximate proof.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct F64RoundoffDiagnostics {
    pub forward_absolute_error_bound: f64,
    pub maximum_absolute_source: f64,
    pub maximum_absolute_intermediate: f64,
}

/// A scaled binary64 public MLE evaluation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct F64MleEvaluation {
    pub value: f64,
    pub work: PublicEvaluationWork,
    pub roundoff: F64RoundoffDiagnostics,
}

/// Scalar operations required by the backend-neutral evaluator.
///
/// Exact backends normally implement this trait for their field element.  The
/// evaluator deliberately requests operations one at a time and never calls a
/// fused multiply-add, so the same plan also fixes binary64 operation order.
pub trait MleInterpreter {
    /// Scalar evaluated by this interpreter.  The interpreter, rather than
    /// the scalar type, owns the implementation so downstream crates can use
    /// field elements from third-party crates without an orphan-rule wrapper.
    type Scalar: Copy + Debug;

    fn zero(&self) -> Self::Scalar;
    fn one(&self) -> Self::Scalar;
    fn embed_i64(&self, value: i64) -> Self::Scalar;
    fn add(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar;
    fn sub(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar;
    fn mul(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MleEvaluationError {
    #[error("{point} point has {actual} coordinates; expected {expected}")]
    PointDimension {
        point: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("{point} coordinate {index} is not a canonical binary64 challenge in [0, 1]")]
    InvalidBinary64Coordinate { point: &'static str, index: usize },
    #[error("public binary64 MLE evaluation produced a non-finite value or error bound")]
    NonFiniteBinary64Evaluation,
    #[error("integer overflow while deriving exact no-wrap bounds")]
    ArithmeticBoundsOverflow,
}

/// Borrowed, allocation-free view of a compiled registered generator.
#[derive(Clone, Copy, Debug)]
pub struct PublicEvaluationPlan<'a> {
    problem: &'a GeneratedProblem,
}

impl GeneratedProblem {
    /// Returns the succinct public-evaluation capability for this compiled
    /// problem.  Creating the view does not clone periodic tables or allocate.
    #[must_use]
    pub const fn public_evaluation_plan(&self) -> PublicEvaluationPlan<'_> {
        PublicEvaluationPlan { problem: self }
    }
}

/// Capability consumed by a succinct backend.
///
/// Backend code should be generic over this interface (or call it on the
/// registry-produced [`PublicEvaluationPlan`]); it must not match matrix or RHS
/// specification variants and reproduce generator formulas itself.
pub trait SuccinctPublicEvaluator {
    fn metadata(&self) -> PublicEvaluationMetadata;

    fn evaluate_matrix_mle<I: MleInterpreter>(
        &self,
        interpreter: &I,
        row_point: &[I::Scalar],
        column_point: &[I::Scalar],
    ) -> Result<MleEvaluation<I::Scalar>, MleEvaluationError>;

    fn evaluate_rhs_mle<I: MleInterpreter>(
        &self,
        interpreter: &I,
        row_point: &[I::Scalar],
    ) -> Result<MleEvaluation<I::Scalar>, MleEvaluationError>;

    /// Evaluates the same matrix after embedding it in a larger MSB-padded
    /// Boolean domain. Extra leading index bits must be zero for active rows
    /// and columns; no generator-family knowledge is required.
    fn evaluate_matrix_mle_zero_padded<I: MleInterpreter>(
        &self,
        interpreter: &I,
        row_point: &[I::Scalar],
        column_point: &[I::Scalar],
    ) -> Result<MleEvaluation<I::Scalar>, MleEvaluationError> {
        let natural = self.metadata().domain.variables;
        if row_point.len() != column_point.len() || row_point.len() < natural {
            return Err(MleEvaluationError::PointDimension {
                point: "zero-padded matrix",
                expected: natural,
                actual: row_point.len().min(column_point.len()),
            });
        }
        let extra = row_point.len() - natural;
        let mut evaluation =
            self.evaluate_matrix_mle(interpreter, &row_point[extra..], &column_point[extra..])?;
        let mut prefix = interpreter.one();
        for (&row, &column) in row_point[..extra].iter().zip(&column_point[..extra]) {
            let row_zero = interpreter.sub(interpreter.one(), row);
            let column_zero = interpreter.sub(interpreter.one(), column);
            prefix = interpreter.mul(prefix, interpreter.mul(row_zero, column_zero));
        }
        evaluation.value = interpreter.mul(prefix, evaluation.value);
        evaluation.work.subtractions += (2 * extra) as u64;
        evaluation.work.multiplications += (2 * extra + 1) as u64;
        Ok(evaluation)
    }

    /// RHS counterpart of [`Self::evaluate_matrix_mle_zero_padded`].
    fn evaluate_rhs_mle_zero_padded<I: MleInterpreter>(
        &self,
        interpreter: &I,
        row_point: &[I::Scalar],
    ) -> Result<MleEvaluation<I::Scalar>, MleEvaluationError> {
        let natural = self.metadata().domain.variables;
        if row_point.len() < natural {
            return Err(MleEvaluationError::PointDimension {
                point: "zero-padded RHS",
                expected: natural,
                actual: row_point.len(),
            });
        }
        let extra = row_point.len() - natural;
        let mut evaluation = self.evaluate_rhs_mle(interpreter, &row_point[extra..])?;
        let mut prefix = interpreter.one();
        for &coordinate in &row_point[..extra] {
            let zero = interpreter.sub(interpreter.one(), coordinate);
            prefix = interpreter.mul(prefix, zero);
        }
        evaluation.value = interpreter.mul(prefix, evaluation.value);
        evaluation.work.subtractions += extra as u64;
        evaluation.work.multiplications += (extra + 1) as u64;
        Ok(evaluation)
    }

    fn evaluate_matrix_mle_f64(
        &self,
        row_point: &[f64],
        column_point: &[f64],
    ) -> Result<F64MleEvaluation, MleEvaluationError>;

    fn evaluate_rhs_mle_f64(
        &self,
        row_point: &[f64],
    ) -> Result<F64MleEvaluation, MleEvaluationError>;
}

impl SuccinctPublicEvaluator for PublicEvaluationPlan<'_> {
    fn metadata(&self) -> PublicEvaluationMetadata {
        let certificate = self.problem.certificate();
        let padded_dimension = self.problem.dimension().next_power_of_two();
        let variables = padded_dimension.ilog2() as usize;
        PublicEvaluationMetadata {
            evaluator_version: 1,
            domain: MleDomain {
                logical_dimension: self.problem.dimension(),
                padded_dimension,
                variables,
                coordinate_order: BooleanCoordinateOrder::MostSignificantFirst,
            },
            matrix_period_terms: certificate.matrix_period.min(padded_dimension),
            rhs_period_terms: certificate.rhs_period.min(padded_dimension),
            exact_bounds: ExactArithmeticBounds {
                logical_dimension: self.problem.dimension(),
                matrix_fractional_bits: certificate.coefficient_fractional_bits,
                rhs_fractional_bits: certificate.rhs_fractional_bits,
                maximum_absolute_row_sum_mantissa: certificate
                    .maximum_absolute_row_sum_mantissa_bound,
                maximum_absolute_rhs_mantissa: certificate.maximum_absolute_rhs_mantissa,
            },
        }
    }

    fn evaluate_matrix_mle<I: MleInterpreter>(
        &self,
        interpreter: &I,
        row_point: &[I::Scalar],
        column_point: &[I::Scalar],
    ) -> Result<MleEvaluation<I::Scalar>, MleEvaluationError> {
        evaluate_matrix(self.problem, interpreter, row_point, column_point)
    }

    fn evaluate_rhs_mle<I: MleInterpreter>(
        &self,
        interpreter: &I,
        row_point: &[I::Scalar],
    ) -> Result<MleEvaluation<I::Scalar>, MleEvaluationError> {
        evaluate_rhs(self.problem, interpreter, row_point)
    }

    fn evaluate_matrix_mle_f64(
        &self,
        row_point: &[f64],
        column_point: &[f64],
    ) -> Result<F64MleEvaluation, MleEvaluationError> {
        validate_f64_point("row", row_point, self.metadata().domain.variables)?;
        validate_f64_point("column", column_point, self.metadata().domain.variables)?;
        let row = row_point
            .iter()
            .copied()
            .map(TrackedF64::source)
            .collect::<Vec<_>>();
        let column = column_point
            .iter()
            .copied()
            .map(TrackedF64::source)
            .collect::<Vec<_>>();
        let raw = evaluate_matrix(self.problem, &TrackedF64Interpreter, &row, &column)?;
        scale_f64_evaluation(raw)
    }

    fn evaluate_rhs_mle_f64(
        &self,
        row_point: &[f64],
    ) -> Result<F64MleEvaluation, MleEvaluationError> {
        validate_f64_point("row", row_point, self.metadata().domain.variables)?;
        let row = row_point
            .iter()
            .copied()
            .map(TrackedF64::source)
            .collect::<Vec<_>>();
        let raw = evaluate_rhs(self.problem, &TrackedF64Interpreter, &row)?;
        scale_f64_evaluation(raw)
    }
}

fn evaluate_matrix<I: MleInterpreter>(
    problem: &GeneratedProblem,
    interpreter: &I,
    row_point: &[I::Scalar],
    column_point: &[I::Scalar],
) -> Result<MleEvaluation<I::Scalar>, MleEvaluationError> {
    let variables = problem.dimension().next_power_of_two().ilog2() as usize;
    check_point("row", row_point, variables)?;
    check_point("column", column_point, variables)?;
    let mut arithmetic = Arithmetic::new(interpreter);
    let dimension = problem.dimension();
    let certificate = problem.certificate();
    let margin = i64::try_from(certificate.strict_diagonal_dominance_margin_mantissa)
        .expect("validated dominance margin fits i64");
    let active_diagonal =
        bounded_equal_indices(&mut arithmetic, row_point, column_point, dimension);
    let margin = arithmetic.embed_i64(margin);
    let mut result = arithmetic.mul(margin, active_diagonal);

    let table = problem.off_diagonal_periodic_mantissas();
    let period_bits = variables.min(table.len().ilog2() as usize);
    let period = 1_usize << period_bits;
    let high_variables = variables - period_bits;
    let (row_high, row_low) = row_point.split_at(high_variables);
    let (column_high, column_low) = column_point.split_at(high_variables);
    let edge_limit = dimension - 1;
    let complete_periods = edge_limit / period;
    let partial_period = edge_limit % period;
    let active_patterns = if complete_periods == 0 {
        partial_period
    } else {
        period
    };

    for (pattern, &edge_mantissa) in table.iter().take(active_patterns).enumerate() {
        let count = complete_periods + usize::from(pattern < partial_period);
        debug_assert!(count > 0);
        let high_equal = bounded_equal_indices(&mut arithmetic, row_high, column_high, count);
        let row_current = eq_index(&mut arithmetic, row_low, pattern);
        let column_current = eq_index(&mut arithmetic, column_low, pattern);
        let next_pattern = (pattern + 1) & (period - 1);
        let row_next = eq_index(&mut arithmetic, row_low, next_pattern);
        let column_next = eq_index(&mut arithmetic, column_low, next_pattern);

        let (forward_high, reverse_high, end_diagonal_high) = if pattern + 1 < period {
            (high_equal, high_equal, high_equal)
        } else {
            let forward = bounded_successor_indices(&mut arithmetic, row_high, column_high, count);
            let reverse = bounded_successor_indices(&mut arithmetic, column_high, row_high, count);
            let shifted_prefix =
                bounded_equal_indices(&mut arithmetic, row_high, column_high, count + 1);
            let row_zero = eq_index(&mut arithmetic, row_high, 0);
            let column_zero = eq_index(&mut arithmetic, column_high, 0);
            let zero_pair = arithmetic.mul(row_zero, column_zero);
            let end_diagonal = arithmetic.sub(shifted_prefix, zero_pair);
            (forward, reverse, end_diagonal)
        };

        let forward_low = arithmetic.mul(row_current, column_next);
        let forward = arithmetic.mul(forward_low, forward_high);
        let reverse_low = arithmetic.mul(row_next, column_current);
        let reverse = arithmetic.mul(reverse_low, reverse_high);
        let start_low = arithmetic.mul(row_current, column_current);
        let start_diagonal = arithmetic.mul(start_low, high_equal);
        let end_low = arithmetic.mul(row_next, column_next);
        let end_diagonal = arithmetic.mul(end_low, end_diagonal_high);
        let off_diagonal_sum = arithmetic.add(forward, reverse);
        let without_start = arithmetic.sub(off_diagonal_sum, start_diagonal);
        let edge_basis = arithmetic.sub(without_start, end_diagonal);
        let edge_mantissa = arithmetic.embed_i64(edge_mantissa);
        let contribution = arithmetic.mul(edge_mantissa, edge_basis);
        result = arithmetic.add(result, contribution);
        arithmetic.work.periodic_terms += 1;
    }

    Ok(MleEvaluation {
        value: result,
        fractional_bits: certificate.coefficient_fractional_bits,
        work: arithmetic.work,
    })
}

fn evaluate_rhs<I: MleInterpreter>(
    problem: &GeneratedProblem,
    interpreter: &I,
    row_point: &[I::Scalar],
) -> Result<MleEvaluation<I::Scalar>, MleEvaluationError> {
    let variables = problem.dimension().next_power_of_two().ilog2() as usize;
    check_point("row", row_point, variables)?;
    let mut arithmetic = Arithmetic::new(interpreter);
    let certificate = problem.certificate();
    let mut result = arithmetic.zero();

    if let Some(table) = problem.rhs_periodic_mantissas() {
        let period_bits = variables.min(table.len().ilog2() as usize);
        let period = 1_usize << period_bits;
        let high_variables = variables - period_bits;
        let (high_point, low_point) = row_point.split_at(high_variables);
        let complete_periods = problem.dimension() / period;
        let partial_period = problem.dimension() % period;
        let complete_weight = bounded_index_sum(&mut arithmetic, high_point, complete_periods);
        let partial_weight = if partial_period == 0 {
            arithmetic.zero()
        } else {
            let through_partial =
                bounded_index_sum(&mut arithmetic, high_point, complete_periods + 1);
            arithmetic.sub(through_partial, complete_weight)
        };
        let active_patterns = if complete_periods == 0 {
            partial_period
        } else {
            period
        };
        for (pattern, &mantissa) in table.iter().take(active_patterns).enumerate() {
            let low_weight = eq_index(&mut arithmetic, low_point, pattern);
            let high_weight = if pattern < partial_period {
                arithmetic.add(complete_weight, partial_weight)
            } else {
                complete_weight
            };
            let weight = arithmetic.mul(low_weight, high_weight);
            let mantissa = arithmetic.embed_i64(mantissa);
            let contribution = arithmetic.mul(weight, mantissa);
            result = arithmetic.add(result, contribution);
            arithmetic.work.periodic_terms += 1;
        }
    } else {
        let mantissa = problem
            .rhs(0)
            .expect("validated problem has a nonempty RHS")
            .mantissa();
        let active = bounded_index_sum(&mut arithmetic, row_point, problem.dimension());
        let mantissa = arithmetic.embed_i64(mantissa);
        result = arithmetic.mul(mantissa, active);
        arithmetic.work.periodic_terms = 1;
    }

    Ok(MleEvaluation {
        value: result,
        fractional_bits: certificate.rhs_fractional_bits,
        work: arithmetic.work,
    })
}

fn bounded_index_sum<I: MleInterpreter>(
    arithmetic: &mut Arithmetic<'_, I>,
    point: &[I::Scalar],
    limit: usize,
) -> I::Scalar {
    let domain = 1_usize << point.len();
    debug_assert!(limit <= domain);
    if limit == 0 {
        return arithmetic.zero();
    }
    if limit == domain {
        return arithmetic.one();
    }

    // Subtract limit from the Boolean index, least-significant bit first.  The
    // final borrow is one exactly for indices below limit.  Point storage is
    // MSB-first, hence the reversed coordinate access.
    let mut states = [arithmetic.one(), arithmetic.zero()];
    for bit in 0..point.len() {
        let coordinate = point[point.len() - 1 - bit];
        let limit_bit = (limit >> bit) & 1;
        let mut next = [arithmetic.zero(); 2];
        for (borrow_in, state) in states.into_iter().enumerate() {
            for index_bit in 0..=1 {
                let borrow_out = usize::from(index_bit < limit_bit + borrow_in);
                let weight = bit_weight(arithmetic, coordinate, index_bit);
                let term = arithmetic.mul(state, weight);
                next[borrow_out] = arithmetic.add(next[borrow_out], term);
            }
        }
        states = next;
    }
    states[1]
}

fn bounded_equal_indices<I: MleInterpreter>(
    arithmetic: &mut Arithmetic<'_, I>,
    left: &[I::Scalar],
    right: &[I::Scalar],
    limit: usize,
) -> I::Scalar {
    debug_assert_eq!(left.len(), right.len());
    let domain = 1_usize << left.len();
    debug_assert!(limit <= domain);
    if limit == 0 {
        return arithmetic.zero();
    }
    if limit == domain {
        let mut result = arithmetic.one();
        for (&left_coordinate, &right_coordinate) in left.iter().zip(right) {
            let one = arithmetic.one();
            let left_zero = arithmetic.sub(one, left_coordinate);
            let one = arithmetic.one();
            let right_zero = arithmetic.sub(one, right_coordinate);
            let zero_pair = arithmetic.mul(left_zero, right_zero);
            let one_pair = arithmetic.mul(left_coordinate, right_coordinate);
            let equal = arithmetic.add(zero_pair, one_pair);
            result = arithmetic.mul(result, equal);
        }
        return result;
    }

    let mut states = [arithmetic.one(), arithmetic.zero()];
    for bit in 0..left.len() {
        let coordinate = left.len() - 1 - bit;
        let limit_bit = (limit >> bit) & 1;
        let mut next = [arithmetic.zero(); 2];
        for (borrow_in, state) in states.into_iter().enumerate() {
            for index_bit in 0..=1 {
                let borrow_out = usize::from(index_bit < limit_bit + borrow_in);
                let left_weight = bit_weight(arithmetic, left[coordinate], index_bit);
                let right_weight = bit_weight(arithmetic, right[coordinate], index_bit);
                let pair = arithmetic.mul(left_weight, right_weight);
                let term = arithmetic.mul(state, pair);
                next[borrow_out] = arithmetic.add(next[borrow_out], term);
            }
        }
        states = next;
    }
    states[1]
}

fn bounded_successor_indices<I: MleInterpreter>(
    arithmetic: &mut Arithmetic<'_, I>,
    left: &[I::Scalar],
    right: &[I::Scalar],
    limit: usize,
) -> I::Scalar {
    debug_assert_eq!(left.len(), right.len());
    let domain = 1_usize << left.len();
    debug_assert!(limit < domain);
    let mut states = [arithmetic.zero(); 4];
    states[state_index(1, 0)] = arithmetic.one();
    for bit in 0..left.len() {
        let coordinate = left.len() - 1 - bit;
        let limit_bit = (limit >> bit) & 1;
        let mut next = [arithmetic.zero(); 4];
        for carry_in in 0..=1 {
            for borrow_in in 0..=1 {
                let state = states[state_index(carry_in, borrow_in)];
                for index_bit in 0..=1 {
                    let successor_sum = index_bit + carry_in;
                    let successor_bit = successor_sum & 1;
                    let carry_out = successor_sum >> 1;
                    let borrow_out = usize::from(index_bit < limit_bit + borrow_in);
                    let left_weight = bit_weight(arithmetic, left[coordinate], index_bit);
                    let right_weight = bit_weight(arithmetic, right[coordinate], successor_bit);
                    let pair = arithmetic.mul(left_weight, right_weight);
                    let term = arithmetic.mul(state, pair);
                    let destination = state_index(carry_out, borrow_out);
                    next[destination] = arithmetic.add(next[destination], term);
                }
            }
        }
        states = next;
    }
    states[state_index(0, 1)]
}

fn eq_index<I: MleInterpreter>(
    arithmetic: &mut Arithmetic<'_, I>,
    point: &[I::Scalar],
    index: usize,
) -> I::Scalar {
    debug_assert!(index < (1_usize << point.len()));
    let mut result = arithmetic.one();
    for (coordinate_index, &coordinate) in point.iter().enumerate() {
        let bit = point.len() - 1 - coordinate_index;
        let weight = bit_weight(arithmetic, coordinate, (index >> bit) & 1);
        result = arithmetic.mul(result, weight);
    }
    result
}

fn bit_weight<I: MleInterpreter>(
    arithmetic: &mut Arithmetic<'_, I>,
    point: I::Scalar,
    bit: usize,
) -> I::Scalar {
    if bit == 0 {
        let one = arithmetic.one();
        arithmetic.sub(one, point)
    } else {
        point
    }
}

const fn state_index(carry: usize, borrow: usize) -> usize {
    2 * carry + borrow
}

fn check_point<S>(
    point_name: &'static str,
    point: &[S],
    expected: usize,
) -> Result<(), MleEvaluationError> {
    if point.len() != expected {
        return Err(MleEvaluationError::PointDimension {
            point: point_name,
            expected,
            actual: point.len(),
        });
    }
    Ok(())
}

fn validate_f64_point(
    point_name: &'static str,
    point: &[f64],
    expected: usize,
) -> Result<(), MleEvaluationError> {
    check_point(point_name, point, expected)?;
    for (index, &coordinate) in point.iter().enumerate() {
        let negative_zero = coordinate.to_bits() == (-0.0_f64).to_bits();
        if !coordinate.is_finite()
            || coordinate.is_subnormal()
            || negative_zero
            || !(0.0..=1.0).contains(&coordinate)
        {
            return Err(MleEvaluationError::InvalidBinary64Coordinate {
                point: point_name,
                index,
            });
        }
    }
    Ok(())
}

fn strict_u64_bound_bits(value: u64) -> u32 {
    u64::BITS - value.leading_zeros()
}

fn ceil_log2(value: usize) -> u32 {
    if value <= 1 {
        0
    } else {
        usize::BITS - (value - 1).leading_zeros()
    }
}

struct Arithmetic<'a, I> {
    interpreter: &'a I,
    work: PublicEvaluationWork,
}

impl<'a, I: MleInterpreter> Arithmetic<'a, I> {
    fn new(interpreter: &'a I) -> Self {
        Self {
            interpreter,
            work: PublicEvaluationWork::default(),
        }
    }

    fn zero(&self) -> I::Scalar {
        self.interpreter.zero()
    }

    fn one(&self) -> I::Scalar {
        self.interpreter.one()
    }

    fn embed_i64(&self, value: i64) -> I::Scalar {
        self.interpreter.embed_i64(value)
    }

    fn add(&mut self, left: I::Scalar, right: I::Scalar) -> I::Scalar {
        self.work.additions += 1;
        self.interpreter.add(left, right)
    }

    fn sub(&mut self, left: I::Scalar, right: I::Scalar) -> I::Scalar {
        self.work.subtractions += 1;
        self.interpreter.sub(left, right)
    }

    fn mul(&mut self, left: I::Scalar, right: I::Scalar) -> I::Scalar {
        self.work.multiplications += 1;
        self.interpreter.mul(left, right)
    }
}

#[derive(Clone, Copy, Debug)]
struct TrackedF64 {
    value: f64,
    error_bound: f64,
    maximum_absolute_source: f64,
    maximum_absolute_intermediate: f64,
}

impl TrackedF64 {
    fn source(value: f64) -> Self {
        let magnitude = value.abs();
        Self {
            value,
            error_bound: 0.0,
            maximum_absolute_source: magnitude,
            maximum_absolute_intermediate: magnitude,
        }
    }

    fn finish(self) -> Result<F64RoundoffDiagnostics, MleEvaluationError> {
        if !self.value.is_finite()
            || !self.error_bound.is_finite()
            || !self.maximum_absolute_source.is_finite()
            || !self.maximum_absolute_intermediate.is_finite()
        {
            return Err(MleEvaluationError::NonFiniteBinary64Evaluation);
        }
        Ok(F64RoundoffDiagnostics {
            forward_absolute_error_bound: self.error_bound,
            maximum_absolute_source: self.maximum_absolute_source,
            maximum_absolute_intermediate: self.maximum_absolute_intermediate,
        })
    }

    fn combined_sources(self, rhs: Self) -> f64 {
        self.maximum_absolute_source
            .max(rhs.maximum_absolute_source)
    }

    fn combined_intermediates(self, rhs: Self, result: f64, error: f64) -> f64 {
        self.maximum_absolute_intermediate
            .max(rhs.maximum_absolute_intermediate)
            .max(result.abs() + error)
    }
}

struct TrackedF64Interpreter;

impl MleInterpreter for TrackedF64Interpreter {
    type Scalar = TrackedF64;

    fn zero(&self) -> Self::Scalar {
        TrackedF64::source(0.0)
    }

    fn one(&self) -> Self::Scalar {
        TrackedF64::source(1.0)
    }

    fn embed_i64(&self, value: i64) -> Self::Scalar {
        TrackedF64::source(value as f64)
    }

    fn add(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar {
        let value = left.value + right.value;
        let rounding = f64::EPSILON * (left.value.abs() + right.value.abs()) + f64::from_bits(1);
        let error_bound = left.error_bound + right.error_bound + rounding;
        TrackedF64 {
            value,
            error_bound,
            maximum_absolute_source: left.combined_sources(right),
            maximum_absolute_intermediate: left.combined_intermediates(right, value, error_bound),
        }
    }

    fn sub(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar {
        let value = left.value - right.value;
        let rounding = f64::EPSILON * (left.value.abs() + right.value.abs()) + f64::from_bits(1);
        let error_bound = left.error_bound + right.error_bound + rounding;
        TrackedF64 {
            value,
            error_bound,
            maximum_absolute_source: left.combined_sources(right),
            maximum_absolute_intermediate: left.combined_intermediates(right, value, error_bound),
        }
    }

    fn mul(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar {
        let value = left.value * right.value;
        let propagated = left.value.abs() * right.error_bound
            + right.value.abs() * left.error_bound
            + left.error_bound * right.error_bound;
        let rounding = f64::EPSILON * value.abs() + f64::from_bits(1);
        let error_bound = propagated + rounding;
        TrackedF64 {
            value,
            error_bound,
            maximum_absolute_source: left.combined_sources(right),
            maximum_absolute_intermediate: left.combined_intermediates(right, value, error_bound),
        }
    }
}

fn scale_f64_evaluation(
    mut raw: MleEvaluation<TrackedF64>,
) -> Result<F64MleEvaluation, MleEvaluationError> {
    let scale = f64::from_bits((1023_u64 - u64::from(raw.fractional_bits)) << 52);
    let scaled = TrackedF64Interpreter.mul(raw.value, TrackedF64::source(scale));
    raw.work.multiplications += 1;
    let roundoff = scaled.finish()?;
    let value = if scaled.value == 0.0 {
        0.0
    } else {
        scaled.value
    };
    Ok(F64MleEvaluation {
        value,
        work: raw.work,
        roundoff,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BoundaryRule, DiagonalConstruction, InstanceSeed, MatrixSpec, OffDiagonalValues,
        ProblemTemplate, RequestedOutput, RhsSpec, TemplateRandomness, TemplateSchema,
    };

    const TEST_PRIME: u64 = (1_u64 << 61) - 1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestField(u64);

    impl TestField {
        fn new(value: u64) -> Self {
            Self(value % TEST_PRIME)
        }
    }

    struct TestInterpreter;

    impl MleInterpreter for TestInterpreter {
        type Scalar = TestField;

        fn zero(&self) -> Self::Scalar {
            TestField(0)
        }

        fn one(&self) -> Self::Scalar {
            TestField(1)
        }

        fn embed_i64(&self, value: i64) -> Self::Scalar {
            if value >= 0 {
                TestField::new(value as u64)
            } else {
                let magnitude = value.unsigned_abs() % TEST_PRIME;
                TestField((TEST_PRIME - magnitude) % TEST_PRIME)
            }
        }

        fn add(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar {
            TestField::new(left.0 + right.0)
        }

        fn sub(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar {
            TestField::new(left.0 + TEST_PRIME - right.0)
        }

        fn mul(&self, left: Self::Scalar, right: Self::Scalar) -> Self::Scalar {
            TestField(((u128::from(left.0) * u128::from(right.0)) % u128::from(TEST_PRIME)) as u64)
        }
    }

    fn template(dimension: u64, rhs: RhsSpec) -> ProblemTemplate {
        ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness: TemplateRandomness::LiteralV1 {
                seed: InstanceSeed::from_bytes([37; 32]),
            },
            matrix: MatrixSpec::SeededSymmetricTridiagonalV1 {
                dimension,
                boundary: BoundaryRule::TruncateV1,
                off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                    period_bits: 3,
                    fractional_bits: 8,
                    minimum_magnitude_mantissa: 1,
                    maximum_magnitude_mantissa: 12,
                },
                diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 {
                    margin_mantissa: 16,
                },
            },
            rhs,
            requested_outputs: vec![RequestedOutput::SquaredL2ResidualV1],
        }
    }

    fn generated(dimension: u64, rhs: RhsSpec) -> GeneratedProblem {
        template(dimension, rhs)
            .finalize_literal()
            .unwrap()
            .compile()
            .unwrap()
    }

    fn seeded_rhs() -> RhsSpec {
        RhsSpec::SeededPeriodicDyadicV1 {
            period_bits: 2,
            fractional_bits: 6,
            minimum_mantissa: -7,
            maximum_mantissa: 11,
        }
    }

    fn test_point(variables: usize, offset: i64) -> Vec<TestField> {
        (0..variables)
            .map(|coordinate| TestInterpreter.embed_i64(offset + coordinate as i64 * 3))
            .collect()
    }

    fn boolean_point(index: usize, variables: usize) -> Vec<TestField> {
        (0..variables)
            .map(|coordinate| {
                let bit = variables - 1 - coordinate;
                TestInterpreter.embed_i64(((index >> bit) & 1) as i64)
            })
            .collect()
    }

    fn direct_weight<I: MleInterpreter>(
        interpreter: &I,
        point: &[I::Scalar],
        index: usize,
    ) -> I::Scalar {
        point
            .iter()
            .enumerate()
            .fold(interpreter.one(), |weight, (coordinate, &value)| {
                let bit = point.len() - 1 - coordinate;
                let factor = if ((index >> bit) & 1) == 0 {
                    interpreter.sub(interpreter.one(), value)
                } else {
                    value
                };
                interpreter.mul(weight, factor)
            })
    }

    fn scan_matrix<I: MleInterpreter>(
        interpreter: &I,
        problem: &GeneratedProblem,
        row_point: &[I::Scalar],
        column_point: &[I::Scalar],
    ) -> I::Scalar {
        let mut result = interpreter.zero();
        for row_index in 0..problem.dimension() {
            let row_weight = direct_weight(interpreter, row_point, row_index);
            for entry in problem.row(row_index).unwrap() {
                let column_weight = direct_weight(interpreter, column_point, entry.column);
                let pair = interpreter.mul(row_weight, column_weight);
                let coefficient = interpreter.embed_i64(entry.value.mantissa());
                let term = interpreter.mul(pair, coefficient);
                result = interpreter.add(result, term);
            }
        }
        result
    }

    fn scan_rhs<I: MleInterpreter>(
        interpreter: &I,
        problem: &GeneratedProblem,
        point: &[I::Scalar],
    ) -> I::Scalar {
        (0..problem.dimension()).fold(interpreter.zero(), |result, row| {
            let weight = direct_weight(interpreter, point, row);
            let rhs = interpreter.embed_i64(problem.rhs(row).unwrap().mantissa());
            interpreter.add(result, interpreter.mul(weight, rhs))
        })
    }

    #[test]
    fn generic_evaluators_match_complete_scans_off_boolean() {
        for dimension in [2, 5, 8, 19, 33] {
            for rhs in [RhsSpec::ManufacturedOnesV1, seeded_rhs()] {
                let problem = generated(dimension, rhs);
                let plan = problem.public_evaluation_plan();
                let variables = plan.metadata().domain.variables;
                let row = test_point(variables, 2);
                let column = test_point(variables, 5);
                let matrix = plan
                    .evaluate_matrix_mle(&TestInterpreter, &row, &column)
                    .unwrap();
                let public_rhs = plan.evaluate_rhs_mle(&TestInterpreter, &row).unwrap();
                assert_eq!(
                    matrix.value,
                    scan_matrix(&TestInterpreter, &problem, &row, &column)
                );
                assert_eq!(public_rhs.value, scan_rhs(&TestInterpreter, &problem, &row));
                assert_eq!(
                    matrix.fractional_bits,
                    problem.certificate().coefficient_fractional_bits
                );
                assert_eq!(
                    public_rhs.fractional_bits,
                    problem.certificate().rhs_fractional_bits
                );
            }
        }
    }

    #[test]
    fn boolean_points_use_whir_msb_first_order_and_zero_padding() {
        let problem = generated(19, seeded_rhs());
        let plan = problem.public_evaluation_plan();
        let variables = plan.metadata().domain.variables;
        assert_eq!(variables, 5);
        assert_eq!(
            plan.metadata().domain.coordinate_order,
            BooleanCoordinateOrder::MostSignificantFirst
        );

        let row_zero = boolean_point(0, variables);
        let column_one = boolean_point(1, variables);
        let expected_edge = problem
            .row(0)
            .unwrap()
            .find(|entry| entry.column == 1)
            .unwrap()
            .value
            .mantissa();
        assert_eq!(
            plan.evaluate_matrix_mle(&TestInterpreter, &row_zero, &column_one)
                .unwrap()
                .value,
            TestInterpreter.embed_i64(expected_edge)
        );

        // Reversing the coordinate spelling of index one selects index 16,
        // which is structurally zero in row zero.  This freezes bit order.
        let reversed_column_one = column_one.iter().copied().rev().collect::<Vec<_>>();
        assert_eq!(
            plan.evaluate_matrix_mle(&TestInterpreter, &row_zero, &reversed_column_one)
                .unwrap()
                .value,
            TestInterpreter.zero()
        );

        let padded_row = boolean_point(problem.dimension(), variables);
        assert_eq!(
            plan.evaluate_matrix_mle(&TestInterpreter, &padded_row, &column_one)
                .unwrap()
                .value,
            TestInterpreter.zero()
        );
        assert_eq!(
            plan.evaluate_rhs_mle(&TestInterpreter, &padded_row)
                .unwrap()
                .value,
            TestInterpreter.zero()
        );
    }

    #[test]
    fn capability_extends_to_the_exact_profiles_minimum_64_row_domain() {
        let problem = generated(19, seeded_rhs());
        let plan = problem.public_evaluation_plan();
        let row_zero = boolean_point(0, 6);
        let column_one = boolean_point(1, 6);
        let expected_edge = problem
            .row(0)
            .unwrap()
            .find(|entry| entry.column == 1)
            .unwrap()
            .value
            .mantissa();
        assert_eq!(
            plan.evaluate_matrix_mle_zero_padded(&TestInterpreter, &row_zero, &column_one,)
                .unwrap()
                .value,
            TestInterpreter.embed_i64(expected_edge)
        );
        assert_eq!(
            plan.evaluate_rhs_mle_zero_padded(&TestInterpreter, &row_zero)
                .unwrap()
                .value,
            TestInterpreter.embed_i64(problem.rhs(0).unwrap().mantissa())
        );

        let outside_natural_domain = boolean_point(32, 6);
        assert_eq!(
            plan.evaluate_matrix_mle_zero_padded(
                &TestInterpreter,
                &outside_natural_domain,
                &column_one,
            )
            .unwrap()
            .value,
            TestInterpreter.zero()
        );
        assert_eq!(
            plan.evaluate_rhs_mle_zero_padded(&TestInterpreter, &outside_natural_domain)
                .unwrap()
                .value,
            TestInterpreter.zero()
        );
    }

    fn tracked_scan_matrix(
        problem: &GeneratedProblem,
        row_point: &[f64],
        column_point: &[f64],
    ) -> F64MleEvaluation {
        let row = row_point
            .iter()
            .copied()
            .map(TrackedF64::source)
            .collect::<Vec<_>>();
        let column = column_point
            .iter()
            .copied()
            .map(TrackedF64::source)
            .collect::<Vec<_>>();
        let mut arithmetic = Arithmetic::new(&TrackedF64Interpreter);
        let mut result = arithmetic.zero();
        for row_index in 0..problem.dimension() {
            let row_weight = eq_index(&mut arithmetic, &row, row_index);
            for entry in problem.row(row_index).unwrap() {
                let column_weight = eq_index(&mut arithmetic, &column, entry.column);
                let pair = arithmetic.mul(row_weight, column_weight);
                let coefficient = arithmetic.embed_i64(entry.value.mantissa());
                let term = arithmetic.mul(pair, coefficient);
                result = arithmetic.add(result, term);
            }
        }
        scale_f64_evaluation(MleEvaluation {
            value: result,
            fractional_bits: problem.certificate().coefficient_fractional_bits,
            work: arithmetic.work,
        })
        .unwrap()
    }

    fn tracked_scan_rhs(problem: &GeneratedProblem, row_point: &[f64]) -> F64MleEvaluation {
        let row = row_point
            .iter()
            .copied()
            .map(TrackedF64::source)
            .collect::<Vec<_>>();
        let mut arithmetic = Arithmetic::new(&TrackedF64Interpreter);
        let mut result = arithmetic.zero();
        for row_index in 0..problem.dimension() {
            let weight = eq_index(&mut arithmetic, &row, row_index);
            let rhs = arithmetic.embed_i64(problem.rhs(row_index).unwrap().mantissa());
            let term = arithmetic.mul(weight, rhs);
            result = arithmetic.add(result, term);
        }
        scale_f64_evaluation(MleEvaluation {
            value: result,
            fractional_bits: problem.certificate().rhs_fractional_bits,
            work: arithmetic.work,
        })
        .unwrap()
    }

    #[test]
    fn binary64_interpreter_overlaps_complete_scan_error_intervals() {
        for dimension in [5, 19, 32] {
            for rhs in [RhsSpec::ManufacturedOnesV1, seeded_rhs()] {
                let problem = generated(dimension, rhs);
                let plan = problem.public_evaluation_plan();
                let variables = plan.metadata().domain.variables;
                let row = (0..variables)
                    .map(|coordinate| (coordinate as f64 + 1.0) / 16.0)
                    .collect::<Vec<_>>();
                let column = (0..variables)
                    .map(|coordinate| (2.0 * coordinate as f64 + 1.0) / 32.0)
                    .collect::<Vec<_>>();
                let matrix = plan.evaluate_matrix_mle_f64(&row, &column).unwrap();
                let scanned_matrix = tracked_scan_matrix(&problem, &row, &column);
                let matrix_gap = (matrix.value - scanned_matrix.value).abs();
                assert!(
                    matrix_gap
                        <= matrix.roundoff.forward_absolute_error_bound
                            + scanned_matrix.roundoff.forward_absolute_error_bound,
                    "matrix interval mismatch at n={dimension}: gap={matrix_gap:e}"
                );

                let public_rhs = plan.evaluate_rhs_mle_f64(&row).unwrap();
                let scanned_rhs = tracked_scan_rhs(&problem, &row);
                let rhs_gap = (public_rhs.value - scanned_rhs.value).abs();
                assert!(
                    rhs_gap
                        <= public_rhs.roundoff.forward_absolute_error_bound
                            + scanned_rhs.roundoff.forward_absolute_error_bound,
                    "RHS interval mismatch at n={dimension}: gap={rhs_gap:e}"
                );
            }
        }
    }

    #[test]
    fn work_depends_on_period_and_log_dimension_not_nnz() {
        let problem = generated(1 << 20, seeded_rhs());
        let plan = problem.public_evaluation_plan();
        let metadata = plan.metadata();
        let row = vec![TestInterpreter.embed_i64(2); metadata.domain.variables];
        let column = vec![TestInterpreter.embed_i64(3); metadata.domain.variables];
        let matrix = plan
            .evaluate_matrix_mle(&TestInterpreter, &row, &column)
            .unwrap();
        let rhs = plan.evaluate_rhs_mle(&TestInterpreter, &row).unwrap();
        assert_eq!(matrix.work.periodic_terms, 8);
        assert_eq!(rhs.work.periodic_terms, 4);
        assert!(matrix.work.arithmetic_operations() < 10_000);
        assert!(rhs.work.arithmetic_operations() < 2_000);
        assert_eq!(metadata.matrix_period_terms, 8);
        assert_eq!(metadata.rhs_period_terms, 4);
    }

    #[test]
    fn exact_bounds_align_rhs_and_report_norm_growth() {
        let problem = generated(19, seeded_rhs());
        let bounds = problem.public_evaluation_plan().metadata().exact_bounds;
        let diagnostics = bounds.no_wrap_diagnostics(128, 64, 69).unwrap();
        assert_eq!(diagnostics.relation_fractional_bits, 72);
        assert_eq!(diagnostics.matrix_term_alignment_shift, 0);
        assert_eq!(diagnostics.rhs_alignment_shift, 66);
        assert_eq!(diagnostics.residual_norm_strict_bound_bits, 143);
        assert!(
            diagnostics.minimum_safe_modulus_bits
                > diagnostics.row_identity_difference_strict_bound_bits
        );
    }

    #[test]
    fn binary64_points_are_strictly_validated() {
        let problem = generated(5, RhsSpec::ManufacturedOnesV1);
        let plan = problem.public_evaluation_plan();
        let variables = plan.metadata().domain.variables;
        let valid = vec![0.5; variables];
        assert!(plan.evaluate_rhs_mle_f64(&valid).is_ok());

        for invalid in [f64::NAN, f64::INFINITY, -0.0, f64::from_bits(1), 1.5] {
            let mut point = valid.clone();
            point[0] = invalid;
            assert!(matches!(
                plan.evaluate_rhs_mle_f64(&point),
                Err(MleEvaluationError::InvalidBinary64Coordinate { .. })
            ));
        }
        assert!(matches!(
            plan.evaluate_rhs_mle(&TestInterpreter, &[]),
            Err(MleEvaluationError::PointDimension { .. })
        ));
    }
}
