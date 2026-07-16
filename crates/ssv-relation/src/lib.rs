//! Proof-system-independent semantics of the canonical fixed-point relation.
//!
//! A solver may operate however it likes, but succinct backends first round its
//! binary64 output once to signed Q63.64. Matrix and RHS values remain exact
//! dyadics. The exact backend consumes the bounded integer residual relation;
//! the fast backend shares only [`FixedWitness`] quantization before computing
//! its own frozen binary64 residual. This crate contains no transcript or
//! commitment code.

#![forbid(unsafe_code)]

use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use ssv_problem::GeneratedProblem;
use ssv_solution::Solution;
use thiserror::Error;

pub const WITNESS_FRACTIONAL_BITS: u32 = 64;
pub const RESIDUAL_MAGNITUDE_BITS: u32 = 68;

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
    #[error("the configured field is too small for the generator-derived no-wrap bounds")]
    UnsafeFieldModulus,
    #[error("integer size arithmetic overflowed")]
    SizeOverflow,
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

    /// Frozen conversion used by the experimental binary64 backend.
    #[must_use]
    pub fn to_binary64(&self) -> Vec<f64> {
        const SCALE: f64 = 18_446_744_073_709_551_616.0;
        self.values
            .iter()
            .map(|&value| value as f64 / SCALE)
            .collect()
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
        let coefficient_fractional_bits =
            u32::from(problem.certificate().coefficient_fractional_bits);
        let mut residuals = Vec::new();
        residuals
            .try_reserve_exact(problem.dimension())
            .map_err(|_| RelationError::SizeOverflow)?;
        let mut squared_l2_numerator = BigUint::zero();
        let minimum = -(BigInt::from(1_u8) << RESIDUAL_MAGNITUDE_BITS);
        let maximum = (BigInt::from(1_u8) << RESIDUAL_MAGNITUDE_BITS) - 1_u8;

        for row_index in 0..problem.dimension() {
            let mut dot = BigInt::zero();
            for entry in problem
                .row(row_index)
                .expect("row index is bounded by public dimension")
            {
                debug_assert_eq!(
                    u32::from(entry.value.fractional_bits()),
                    coefficient_fractional_bits
                );
                dot += BigInt::from(entry.value.mantissa())
                    * BigInt::from(witness.as_slice()[entry.column]);
            }
            let rhs = problem
                .rhs(row_index)
                .expect("row index is bounded by public dimension");
            let shift = rhs_alignment_shift(
                coefficient_fractional_bits,
                u32::from(rhs.fractional_bits()),
            )?;
            let scaled_rhs = BigInt::from(rhs.mantissa()) << shift;
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

        let denominator_power = 2_u32
            .checked_mul(
                WITNESS_FRACTIONAL_BITS
                    .checked_add(coefficient_fractional_bits)
                    .ok_or(RelationError::SizeOverflow)?,
            )
            .ok_or(RelationError::SizeOverflow)?;
        Ok(Self {
            witness,
            residuals: residuals.into_boxed_slice(),
            squared_l2_numerator,
            squared_l2_denominator_power: denominator_power,
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
    let certificate = problem.certificate();
    let witness_magnitude = BigUint::from(1_u8) << 127;
    let maximum_matrix_term_magnitude =
        BigUint::from(certificate.maximum_absolute_row_sum_mantissa_bound) * witness_magnitude;
    let rhs_shift = rhs_alignment_shift(
        u32::from(certificate.coefficient_fractional_bits),
        u32::from(certificate.rhs_fractional_bits),
    )?;
    let maximum_scaled_rhs_magnitude =
        BigUint::from(certificate.maximum_absolute_rhs_mantissa) << rhs_shift;
    let residual_magnitude = BigUint::from(1_u8) << RESIDUAL_MAGNITUDE_BITS;
    let maximum_row_identity_magnitude =
        &maximum_matrix_term_magnitude + &maximum_scaled_rhs_magnitude + residual_magnitude;
    let maximum_squared_l2_numerator =
        BigUint::from(problem.dimension()) << (2 * RESIDUAL_MAGNITUDE_BITS);
    Ok(NoWrapBounds {
        maximum_matrix_term_magnitude,
        maximum_scaled_rhs_magnitude,
        maximum_row_identity_magnitude,
        maximum_squared_l2_numerator,
    })
}

/// Rejects a field that could turn a nonzero bounded integer relation into zero.
pub fn audit_field_modulus(
    problem: &GeneratedProblem,
    field_modulus: &BigUint,
) -> Result<NoWrapBounds, RelationError> {
    let bounds = no_wrap_bounds(problem)?;
    if bounds.maximum_row_identity_magnitude >= *field_modulus
        || bounds.maximum_squared_l2_numerator >= *field_modulus
    {
        return Err(RelationError::UnsafeFieldModulus);
    }
    Ok(bounds)
}

fn rhs_alignment_shift(
    coefficient_fractional_bits: u32,
    rhs_fractional_bits: u32,
) -> Result<usize, RelationError> {
    let lhs_scale = WITNESS_FRACTIONAL_BITS
        .checked_add(coefficient_fractional_bits)
        .ok_or(RelationError::SizeOverflow)?;
    let shift = lhs_scale
        .checked_sub(rhs_fractional_bits)
        .ok_or(RelationError::IncompatibleScale)?;
    usize::try_from(shift).map_err(|_| RelationError::SizeOverflow)
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
        significand.checked_shl(u32::try_from(shift).ok()?)?
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
        if magnitude > (1_u128 << 127) {
            None
        } else if magnitude == (1_u128 << 127) {
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
        ProblemTemplate, RequestedOutput, RhsSpec, TemplateRandomness, TemplateSchema,
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
        assert_eq!(binary64_to_q63_64(-2.0_f64.powi(63)), Some(i128::MIN));
    }

    #[test]
    fn manufactured_ones_relation_is_exactly_zero() {
        let problem = problem(17);
        let solution = Solution::new(vec![1.0; 17], 17).unwrap();
        let relation = ExactRelation::from_solution(&problem, &solution).unwrap();
        assert!(relation.residuals().iter().all(|&value| value == 0));
        assert!(relation.squared_l2_numerator().is_zero());
        assert_eq!(relation.squared_l2_denominator_power(), 136);
        assert_eq!(relation.witness().to_binary64(), vec![1.0; 17]);
    }

    #[test]
    fn no_wrap_bounds_are_public_and_conservative() {
        let problem = problem(1 << 10);
        let bounds = no_wrap_bounds(&problem).unwrap();
        assert!(bounds.maximum_row_identity_magnitude.bits() < 192);
        assert!(bounds.maximum_squared_l2_numerator.bits() <= 147);
        let too_small = BigUint::from(17_u8);
        assert!(matches!(
            audit_field_modulus(&problem, &too_small),
            Err(RelationError::UnsafeFieldModulus)
        ));
    }
}
