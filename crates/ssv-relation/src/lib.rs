//! Proof-system-independent semantics of the canonical fixed-point relation.
//!
//! A solver may operate however it likes, but the exact backend rounds its
//! binary64 output once to signed Q63.64. Matrix and RHS values remain exact
//! dyadics. This crate owns the immutable numerical profile, derived
//! feasibility/no-wrap plan, and bounded integer residual relation. It contains
//! no transcript or commitment code.

#![forbid(unsafe_code)]

use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use ssv_problem::{ExactArithmeticBounds, GeneratedProblem, PublicEvaluationMetadata};
use ssv_solution::Solution;
use thiserror::Error;

/// Immutable numerical semantics selected by `whir-field192-l2-v4`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExactRelationProfile {
    version: u16,
    witness_fractional_bits: u32,
    witness_magnitude_bits: u32,
    residual_magnitude_bits: u32,
}

/// The one exact relation profile registered by the current exact protocol.
pub const EXACT_RELATION_PROFILE_V1: ExactRelationProfile = ExactRelationProfile {
    version: 1,
    witness_fractional_bits: 64,
    witness_magnitude_bits: 127,
    residual_magnitude_bits: 68,
};

pub const WITNESS_FRACTIONAL_BITS: u32 = EXACT_RELATION_PROFILE_V1.witness_fractional_bits();
pub const WITNESS_MAGNITUDE_BITS: u32 = EXACT_RELATION_PROFILE_V1.witness_magnitude_bits();
pub const RESIDUAL_MAGNITUDE_BITS: u32 = EXACT_RELATION_PROFILE_V1.residual_magnitude_bits();

impl ExactRelationProfile {
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }

    #[must_use]
    pub const fn witness_fractional_bits(self) -> u32 {
        self.witness_fractional_bits
    }

    #[must_use]
    pub const fn witness_magnitude_bits(self) -> u32 {
        self.witness_magnitude_bits
    }

    #[must_use]
    pub const fn residual_magnitude_bits(self) -> u32 {
        self.residual_magnitude_bits
    }
}

/// Canonical Q63.64 private witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedWitness {
    values: Box<[i128]>,
}

/// Bounded exact residual data authenticated by the exact path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactRelation {
    witness: FixedWitness,
    residuals: Box<[i128]>,
    squared_l2_numerator: BigUint,
    squared_l2_denominator_power: u32,
}

/// Public conservative integer bounds checked before accepting Field192
/// identities as integer identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoWrapBounds {
    pub maximum_matrix_term_magnitude: BigUint,
    pub maximum_scaled_rhs_magnitude: BigUint,
    pub maximum_row_identity_magnitude: BigUint,
    pub maximum_squared_l2_numerator: BigUint,
}

/// Problem-specific consequences of the immutable exact relation profile.
///
/// Construction validates scale alignment. Problem-backed construction also
/// checks the exact logical RHS period and rejects a public numeric envelope for
/// which no Q63.64 witness can place every residual in the signed 69-bit range.
/// The resulting shifts, denominator, and no-wrap bounds are shared by statement
/// admission, relation construction, and the exact protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactRelationPlan {
    profile: ExactRelationProfile,
    public_bounds: ExactArithmeticBounds,
    relation_fractional_bits: u32,
    rhs_alignment_shift: u32,
    squared_l2_denominator_power: u32,
    no_wrap_bounds: NoWrapBounds,
}

#[derive(Debug, Error)]
pub enum RelationError {
    #[error("solution length {actual} does not match public dimension {expected}")]
    WrongLength { expected: usize, actual: usize },
    #[error("solution value {index} lies outside signed Q63.64")]
    WitnessOutOfRange { index: usize },
    #[error("row {row} residual lies outside [-2^68, 2^68-1]")]
    ResidualOutOfRange { row: usize },
    #[error("public dyadic scales cannot be aligned to the fixed-point relation")]
    IncompatibleScale,
    #[error("public evaluator metadata is inconsistent with the exact relation profile")]
    InconsistentPublicBounds,
    #[error(
        "public RHS magnitude cannot be reached by a Q63.64 witness within the signed 69-bit residual range"
    )]
    InfeasiblePublicMagnitude,
    #[error("the configured field is too small for the generator-derived no-wrap bounds")]
    UnsafeFieldModulus,
    #[error("integer size arithmetic overflowed")]
    SizeOverflow,
}

impl ExactRelationPlan {
    /// Derives and validates the exact profile from a compiled public problem.
    pub fn from_problem(problem: &GeneratedProblem) -> Result<Self, RelationError> {
        let plan = Self::from_public_bounds(problem.exact_arithmetic_bounds())?;
        let maximum_absolute_logical_rhs_mantissa = maximum_absolute_logical_rhs_mantissa(problem);
        plan.ensure_feasible_public_magnitude(maximum_absolute_logical_rhs_mantissa)?;
        Ok(plan)
    }

    /// Derives the same scale and no-wrap plan from succinct-verifier metadata.
    ///
    /// Metadata bounds may include unused periodic entries, so impossibility
    /// admission is performed only by [`Self::from_problem`].
    pub fn from_metadata(metadata: PublicEvaluationMetadata) -> Result<Self, RelationError> {
        if metadata.domain.logical_dimension != metadata.exact_bounds.logical_dimension {
            return Err(RelationError::InconsistentPublicBounds);
        }
        Self::from_public_bounds(metadata.exact_bounds)
    }

    fn from_public_bounds(public_bounds: ExactArithmeticBounds) -> Result<Self, RelationError> {
        if public_bounds.logical_dimension == 0 {
            return Err(RelationError::InconsistentPublicBounds);
        }
        let profile = EXACT_RELATION_PROFILE_V1;
        let relation_fractional_bits = profile
            .witness_fractional_bits()
            .checked_add(u32::from(public_bounds.matrix_fractional_bits))
            .ok_or(RelationError::SizeOverflow)?;
        let rhs_alignment_shift = relation_fractional_bits
            .checked_sub(u32::from(public_bounds.rhs_fractional_bits))
            .ok_or(RelationError::IncompatibleScale)?;
        let squared_l2_denominator_power = relation_fractional_bits
            .checked_mul(2)
            .ok_or(RelationError::SizeOverflow)?;
        let rhs_alignment =
            usize::try_from(rhs_alignment_shift).map_err(|_| RelationError::SizeOverflow)?;
        let witness_magnitude = BigUint::from(1_u8) << profile.witness_magnitude_bits();
        let maximum_matrix_term_magnitude =
            BigUint::from(public_bounds.maximum_absolute_row_sum_mantissa) * witness_magnitude;
        let maximum_scaled_rhs_magnitude =
            BigUint::from(public_bounds.maximum_absolute_rhs_mantissa) << rhs_alignment;
        let residual_magnitude = BigUint::from(1_u8) << profile.residual_magnitude_bits();
        let maximum_row_identity_magnitude =
            &maximum_matrix_term_magnitude + &maximum_scaled_rhs_magnitude + &residual_magnitude;
        let residual_norm_shift = profile
            .residual_magnitude_bits()
            .checked_mul(2)
            .ok_or(RelationError::SizeOverflow)?;
        let maximum_squared_l2_numerator =
            BigUint::from(public_bounds.logical_dimension) << residual_norm_shift;
        Ok(Self {
            profile,
            public_bounds,
            relation_fractional_bits,
            rhs_alignment_shift,
            squared_l2_denominator_power,
            no_wrap_bounds: NoWrapBounds {
                maximum_matrix_term_magnitude,
                maximum_scaled_rhs_magnitude,
                maximum_row_identity_magnitude,
                maximum_squared_l2_numerator,
            },
        })
    }

    fn ensure_feasible_public_magnitude(
        &self,
        maximum_absolute_logical_rhs_mantissa: u64,
    ) -> Result<(), RelationError> {
        let residual_magnitude = BigUint::from(1_u8) << self.profile.residual_magnitude_bits();
        let maximum_reachable_rhs =
            &self.no_wrap_bounds.maximum_matrix_term_magnitude + residual_magnitude;
        let scaled_logical_rhs = BigUint::from(maximum_absolute_logical_rhs_mantissa)
            << usize::try_from(self.rhs_alignment_shift)
                .map_err(|_| RelationError::SizeOverflow)?;
        if scaled_logical_rhs > maximum_reachable_rhs {
            return Err(RelationError::InfeasiblePublicMagnitude);
        }
        Ok(())
    }

    #[must_use]
    pub const fn profile(&self) -> ExactRelationProfile {
        self.profile
    }

    #[must_use]
    pub const fn public_bounds(&self) -> ExactArithmeticBounds {
        self.public_bounds
    }

    #[must_use]
    pub const fn relation_fractional_bits(&self) -> u32 {
        self.relation_fractional_bits
    }

    #[must_use]
    pub const fn rhs_alignment_shift(&self) -> u32 {
        self.rhs_alignment_shift
    }

    #[must_use]
    pub const fn squared_l2_denominator_power(&self) -> u32 {
        self.squared_l2_denominator_power
    }

    #[must_use]
    pub const fn no_wrap_bounds(&self) -> &NoWrapBounds {
        &self.no_wrap_bounds
    }

    /// Rejects a field that could turn a bounded nonzero integer into zero.
    pub fn audit_field_modulus(&self, field_modulus: &BigUint) -> Result<(), RelationError> {
        if self.no_wrap_bounds.maximum_row_identity_magnitude >= *field_modulus
            || self.no_wrap_bounds.maximum_squared_l2_numerator >= *field_modulus
        {
            return Err(RelationError::UnsafeFieldModulus);
        }
        Ok(())
    }
}

fn maximum_absolute_logical_rhs_mantissa(problem: &GeneratedProblem) -> u64 {
    // Statement admission already limits the public RHS period, so this scan is
    // bounded by that period rather than by the logical dimension.
    problem.rhs_periodic_mantissas().map_or_else(
        || problem.certificate().maximum_absolute_rhs_mantissa,
        |mantissas| {
            mantissas
                .iter()
                .take(problem.dimension().min(mantissas.len()))
                .map(|value| value.unsigned_abs())
                .max()
                .expect("validated logical dimension and RHS period are nonzero")
        },
    )
}

impl FixedWitness {
    pub fn from_solution(solution: &Solution, dimension: usize) -> Result<Self, RelationError> {
        if solution.as_slice().len() != dimension {
            return Err(RelationError::WrongLength {
                expected: dimension,
                actual: solution.as_slice().len(),
            });
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(dimension)
            .map_err(|_| RelationError::SizeOverflow)?;
        for (index, &value) in solution.as_slice().iter().enumerate() {
            values
                .push(binary64_to_q63_64(value).ok_or(RelationError::WitnessOutOfRange { index })?);
        }
        Ok(Self {
            values: values.into_boxed_slice(),
        })
    }

    #[must_use]
    pub const fn as_slice(&self) -> &[i128] {
        &self.values
    }
}

impl ExactRelation {
    pub fn from_solution(
        problem: &GeneratedProblem,
        solution: &Solution,
    ) -> Result<Self, RelationError> {
        let witness = FixedWitness::from_solution(solution, problem.dimension())?;
        Self::from_witness(problem, witness)
    }

    pub fn from_witness(
        problem: &GeneratedProblem,
        witness: FixedWitness,
    ) -> Result<Self, RelationError> {
        if witness.as_slice().len() != problem.dimension() {
            return Err(RelationError::WrongLength {
                expected: problem.dimension(),
                actual: witness.as_slice().len(),
            });
        }
        let plan = ExactRelationPlan::from_problem(problem)?;
        let public_bounds = plan.public_bounds();
        let mut residuals = Vec::new();
        residuals
            .try_reserve_exact(problem.dimension())
            .map_err(|_| RelationError::SizeOverflow)?;
        let mut squared_l2_numerator = BigUint::zero();
        let minimum = -(BigInt::from(1_u8) << plan.profile().residual_magnitude_bits());
        let maximum = (BigInt::from(1_u8) << plan.profile().residual_magnitude_bits()) - 1_u8;
        let rhs_alignment_shift =
            usize::try_from(plan.rhs_alignment_shift()).map_err(|_| RelationError::SizeOverflow)?;

        for row_index in 0..problem.dimension() {
            let mut dot = BigInt::zero();
            for entry in problem
                .row(row_index)
                .expect("row index is bounded by public dimension")
            {
                debug_assert_eq!(
                    entry.value.fractional_bits(),
                    public_bounds.matrix_fractional_bits
                );
                dot += BigInt::from(entry.value.mantissa())
                    * BigInt::from(witness.as_slice()[entry.column]);
            }
            let rhs = problem
                .rhs(row_index)
                .expect("row index is bounded by public dimension");
            debug_assert_eq!(rhs.fractional_bits(), public_bounds.rhs_fractional_bits);
            let scaled_rhs = BigInt::from(rhs.mantissa()) << rhs_alignment_shift;
            let residual = dot - scaled_rhs;
            if residual < minimum || residual > maximum {
                return Err(RelationError::ResidualOutOfRange { row: row_index });
            }
            let residual = i128::try_from(residual)
                .map_err(|_| RelationError::ResidualOutOfRange { row: row_index })?;
            let magnitude = BigUint::from(residual.unsigned_abs());
            squared_l2_numerator += &magnitude * &magnitude;
            residuals.push(residual);
        }

        Ok(Self {
            witness,
            residuals: residuals.into_boxed_slice(),
            squared_l2_numerator,
            squared_l2_denominator_power: plan.squared_l2_denominator_power(),
        })
    }

    #[must_use]
    pub const fn witness(&self) -> &FixedWitness {
        &self.witness
    }

    #[must_use]
    pub const fn residuals(&self) -> &[i128] {
        &self.residuals
    }

    #[must_use]
    pub const fn squared_l2_numerator(&self) -> &BigUint {
        &self.squared_l2_numerator
    }

    #[must_use]
    pub const fn squared_l2_denominator_power(&self) -> u32 {
        self.squared_l2_denominator_power
    }

    #[must_use]
    pub fn squared_l2_approx(&self) -> Option<f64> {
        biguint_to_f64(&self.squared_l2_numerator)
            .map(|numerator| numerator * 2.0_f64.powi(-(self.squared_l2_denominator_power as i32)))
    }
}

/// Derives bounds solely from the compiled public generator certificate.
pub fn no_wrap_bounds(problem: &GeneratedProblem) -> Result<NoWrapBounds, RelationError> {
    Ok(ExactRelationPlan::from_problem(problem)?
        .no_wrap_bounds()
        .clone())
}

/// Rejects a field that could turn a nonzero bounded integer relation into zero.
pub fn audit_field_modulus(
    problem: &GeneratedProblem,
    field_modulus: &BigUint,
) -> Result<NoWrapBounds, RelationError> {
    let plan = ExactRelationPlan::from_problem(problem)?;
    plan.audit_field_modulus(field_modulus)?;
    Ok(plan.no_wrap_bounds().clone())
}

/// Bit-level Q63.64 conversion matching one binary64 round-to-nearest step.
///
/// Binary64 inputs are already validated by [`Solution`]. Ties are rounded
/// away from zero, matching the research prover's `f64::round` conversion.
fn binary64_to_q63_64(value: f64) -> Option<i128> {
    let bits = value.to_bits();
    let negative = bits >> 63 != 0;
    let exponent_bits = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1_u64 << 52) - 1);
    if exponent_bits == 0 {
        return (fraction == 0 && !negative).then_some(0);
    }
    if exponent_bits == 0x7ff {
        return None;
    }
    let significand = u128::from((1_u64 << 52) | fraction);
    let unbiased_exponent = exponent_bits - 1023;
    let shift = unbiased_exponent + 12;
    let magnitude = if shift >= 0 {
        let shift = u32::try_from(shift).ok()?;
        let scale = 1_u128.checked_shl(shift)?;
        significand.checked_mul(scale)?
    } else {
        let right = u32::try_from(-shift).ok()?;
        if right >= 128 {
            0
        } else {
            let quotient = significand >> right;
            let remainder_mask = (1_u128 << right) - 1;
            let remainder = significand & remainder_mask;
            let halfway = 1_u128 << (right - 1);
            quotient + u128::from(remainder >= halfway)
        }
    };
    if negative {
        if magnitude > (1_u128 << WITNESS_MAGNITUDE_BITS) {
            None
        } else if magnitude == (1_u128 << WITNESS_MAGNITUDE_BITS) {
            Some(i128::MIN)
        } else {
            Some(-(magnitude as i128))
        }
    } else {
        i128::try_from(magnitude).ok()
    }
}

fn biguint_to_f64(value: &BigUint) -> Option<f64> {
    if value.is_zero() {
        return Some(0.0);
    }
    let bytes = value.to_bytes_be();
    let mut result = 0.0_f64;
    for byte in bytes {
        result = result * 256.0 + f64::from(byte);
        if !result.is_finite() {
            return None;
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssv_problem::{
        BoundaryRule, DiagonalConstruction, InstanceSeed, MatrixSpec, OffDiagonalValues,
        ProblemTemplate, RequestedOutput, RhsSpec, SuccinctPublicEvaluator, TemplateRandomness,
        TemplateSchema,
    };

    fn problem(dimension: u64) -> GeneratedProblem {
        ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness: TemplateRandomness::LiteralV1 {
                seed: InstanceSeed::from_bytes([9; 32]),
            },
            matrix: MatrixSpec::SeededSymmetricTridiagonalV1 {
                dimension,
                boundary: BoundaryRule::TruncateV1,
                off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                    period_bits: 2,
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
        .unwrap()
        .compile()
        .unwrap()
    }

    fn seeded_rhs_problem(dimension: u64) -> GeneratedProblem {
        ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness: TemplateRandomness::LiteralV1 {
                seed: InstanceSeed::from_bytes([10; 32]),
            },
            matrix: MatrixSpec::SeededSymmetricTridiagonalV1 {
                dimension,
                boundary: BoundaryRule::TruncateV1,
                off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                    period_bits: 3,
                    fractional_bits: 8,
                    minimum_magnitude_mantissa: 1,
                    maximum_magnitude_mantissa: 3,
                },
                diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 { margin_mantissa: 8 },
            },
            rhs: RhsSpec::SeededPeriodicDyadicV1 {
                period_bits: 2,
                fractional_bits: 6,
                minimum_mantissa: -3,
                maximum_mantissa: 7,
            },
            requested_outputs: vec![RequestedOutput::SquaredL2ResidualV1],
        }
        .finalize_literal()
        .unwrap()
        .compile()
        .unwrap()
    }

    #[test]
    fn conversion_is_exact_for_representative_binary64_values() {
        for (value, expected) in [
            (0.0, 0),
            (1.0, 1_i128 << 64),
            (-1.0, -(1_i128 << 64)),
            (0.5, 1_i128 << 63),
            (2.0_f64.powi(-64), 1),
            (-2.0_f64.powi(-65), -1),
            (2.0_f64.powi(-66), 0),
        ] {
            assert_eq!(binary64_to_q63_64(value), Some(expected));
        }
        assert_eq!(binary64_to_q63_64(2.0_f64.powi(63)), None);
        assert!(binary64_to_q63_64(f64::from_bits(2.0_f64.powi(63).to_bits() - 1)).is_some());
        assert_eq!(binary64_to_q63_64(2.0_f64.powi(70)), None);
        assert_eq!(binary64_to_q63_64(-2.0_f64.powi(70)), None);
        assert_eq!(binary64_to_q63_64(-2.0_f64.powi(63)), Some(i128::MIN));
        assert_eq!(
            binary64_to_q63_64(f64::from_bits((-2.0_f64.powi(63)).to_bits() + 1)),
            None
        );
        assert_eq!(EXACT_RELATION_PROFILE_V1.version(), 1);
        assert_eq!(WITNESS_FRACTIONAL_BITS, 64);
        assert_eq!(WITNESS_MAGNITUDE_BITS, 127);
        assert_eq!(RESIDUAL_MAGNITUDE_BITS, 68);
    }

    #[test]
    fn manufactured_ones_relation_is_exactly_zero() {
        let problem = problem(17);
        let solution = Solution::new(vec![1.0; 17], 17).unwrap();
        let relation = ExactRelation::from_solution(&problem, &solution).unwrap();
        assert!(relation.residuals().iter().all(|&value| value == 0));
        assert!(relation.squared_l2_numerator().is_zero());
        assert_eq!(relation.squared_l2_denominator_power(), 136);
        assert!(
            relation
                .witness()
                .as_slice()
                .iter()
                .all(|&value| value == 1_i128 << 64)
        );
    }

    #[test]
    fn nonzero_residual_uses_the_plan_denominator() {
        let problem = problem(17);
        let mut values = vec![1.0; 17];
        values[0] = f64::from_bits(1.0_f64.to_bits() + 1);
        let solution = Solution::new(values, 17).unwrap();
        let relation = ExactRelation::from_solution(&problem, &solution).unwrap();
        let plan = ExactRelationPlan::from_problem(&problem).unwrap();
        assert!(relation.residuals().iter().any(|&value| value != 0));
        assert!(!relation.squared_l2_numerator().is_zero());
        assert_eq!(
            relation.squared_l2_denominator_power(),
            plan.squared_l2_denominator_power()
        );
    }

    #[test]
    fn plan_is_identical_from_problem_and_verifier_metadata() {
        let problem = seeded_rhs_problem(19);
        let from_problem = ExactRelationPlan::from_problem(&problem).unwrap();
        let metadata = problem.public_evaluation_plan().metadata();
        let from_metadata = ExactRelationPlan::from_metadata(metadata).unwrap();
        assert_eq!(from_problem, from_metadata);
        assert_eq!(from_problem.public_bounds(), metadata.exact_bounds);
        assert_eq!(from_problem.relation_fractional_bits(), 72);
        assert_eq!(from_problem.rhs_alignment_shift(), 66);
        assert_eq!(from_problem.squared_l2_denominator_power(), 144);

        let mut inconsistent = metadata;
        inconsistent.exact_bounds.logical_dimension += 1;
        assert!(matches!(
            ExactRelationPlan::from_metadata(inconsistent),
            Err(RelationError::InconsistentPublicBounds)
        ));
    }

    #[test]
    fn plan_derivation_matches_reference_arithmetic_at_scale_extrema() {
        for (dimension, matrix_fractional_bits, rhs_fractional_bits) in
            [(2, 0, 52), (19, 8, 6), (1 << 30, 52, 0)]
        {
            let public_bounds = ExactArithmeticBounds {
                logical_dimension: dimension,
                matrix_fractional_bits,
                rhs_fractional_bits,
                maximum_absolute_row_sum_mantissa: 7,
                maximum_absolute_rhs_mantissa: 3,
            };
            let plan = ExactRelationPlan::from_public_bounds(public_bounds).unwrap();
            let relation_fractional_bits = 64 + u32::from(matrix_fractional_bits);
            let rhs_alignment_shift = relation_fractional_bits - u32::from(rhs_fractional_bits);
            let maximum_matrix = BigUint::from(7_u8) << 127;
            let maximum_rhs = BigUint::from(3_u8) << rhs_alignment_shift;
            let maximum_residual = BigUint::from(1_u8) << 68;
            assert_eq!(plan.relation_fractional_bits(), relation_fractional_bits);
            assert_eq!(plan.rhs_alignment_shift(), rhs_alignment_shift);
            assert_eq!(
                plan.squared_l2_denominator_power(),
                2 * relation_fractional_bits
            );
            assert_eq!(
                plan.no_wrap_bounds().maximum_matrix_term_magnitude,
                maximum_matrix
            );
            assert_eq!(
                plan.no_wrap_bounds().maximum_scaled_rhs_magnitude,
                maximum_rhs
            );
            assert_eq!(
                plan.no_wrap_bounds().maximum_row_identity_magnitude,
                &maximum_matrix + &maximum_rhs + maximum_residual
            );
            assert_eq!(
                plan.no_wrap_bounds().maximum_squared_l2_numerator,
                BigUint::from(dimension) << 136
            );
        }
    }

    #[test]
    fn feasibility_admission_is_conservative_at_its_magnitude_boundary() {
        let public_bounds = ExactArithmeticBounds {
            logical_dimension: 2,
            matrix_fractional_bits: 52,
            rhs_fractional_bits: 0,
            maximum_absolute_row_sum_mantissa: 1,
            // No-wrap metadata may conservatively include unused period entries.
            maximum_absolute_rhs_mantissa: 9_007_199_254_740_991,
        };
        let plan = ExactRelationPlan::from_public_bounds(public_bounds).unwrap();
        assert!(plan.ensure_feasible_public_magnitude(2_048).is_ok());

        assert!(matches!(
            plan.ensure_feasible_public_magnitude(2_049),
            Err(RelationError::InfeasiblePublicMagnitude)
        ));

        assert!(matches!(
            plan.ensure_feasible_public_magnitude(9_007_199_254_740_991),
            Err(RelationError::InfeasiblePublicMagnitude)
        ));
    }

    #[test]
    fn feasibility_ignores_unused_rhs_period_entries() {
        let mut witnessed_unused_bound = false;
        for seed_byte in 0_u8..=u8::MAX {
            let problem = ProblemTemplate {
                schema: TemplateSchema::V1,
                randomness: TemplateRandomness::LiteralV1 {
                    seed: InstanceSeed::from_bytes([seed_byte; 32]),
                },
                matrix: MatrixSpec::SeededSymmetricTridiagonalV1 {
                    dimension: 2,
                    boundary: BoundaryRule::TruncateV1,
                    off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                        period_bits: 0,
                        fractional_bits: 52,
                        minimum_magnitude_mantissa: 1,
                        maximum_magnitude_mantissa: 1,
                    },
                    diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 {
                        margin_mantissa: 1,
                    },
                },
                rhs: RhsSpec::SeededPeriodicDyadicV1 {
                    period_bits: 3,
                    fractional_bits: 0,
                    minimum_mantissa: 0,
                    maximum_mantissa: 20_000,
                },
                requested_outputs: vec![RequestedOutput::SquaredL2ResidualV1],
            }
            .finalize_literal()
            .unwrap()
            .compile()
            .unwrap();
            let plan_from_metadata =
                ExactRelationPlan::from_public_bounds(problem.exact_arithmetic_bounds()).unwrap();
            let logical_maximum = maximum_absolute_logical_rhs_mantissa(&problem);
            let metadata_maximum = problem.certificate().maximum_absolute_rhs_mantissa;
            if plan_from_metadata
                .ensure_feasible_public_magnitude(logical_maximum)
                .is_ok()
                && plan_from_metadata
                    .ensure_feasible_public_magnitude(metadata_maximum)
                    .is_err()
            {
                assert!(ExactRelationPlan::from_problem(&problem).is_ok());
                witnessed_unused_bound = true;
                break;
            }
        }
        assert!(
            witnessed_unused_bound,
            "deterministic seeds should cover a loose unused-period RHS bound"
        );
    }

    #[test]
    fn no_wrap_bounds_are_public_and_conservative() {
        let problem = problem(1 << 10);
        let plan = ExactRelationPlan::from_problem(&problem).unwrap();
        let bounds = no_wrap_bounds(&problem).unwrap();
        assert_eq!(&bounds, plan.no_wrap_bounds());
        assert!(bounds.maximum_row_identity_magnitude.bits() < 192);
        assert!(bounds.maximum_squared_l2_numerator.bits() <= 147);
        let exact_boundary = bounds
            .maximum_row_identity_magnitude
            .max(bounds.maximum_squared_l2_numerator)
            .clone();
        assert!(matches!(
            audit_field_modulus(&problem, &exact_boundary),
            Err(RelationError::UnsafeFieldModulus)
        ));
        assert!(audit_field_modulus(&problem, &(exact_boundary + 1_u8)).is_ok());
    }
}
