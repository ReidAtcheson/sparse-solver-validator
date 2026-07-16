//! Binary64 product sumcheck for metric validation backends.
//!
//! This primitive reports numerical defects; it does not choose acceptance.
//! Transcript ownership is inverted through a challenge callback, so sparse
//! solve validators and future protocols can share the same algebra without
//! sharing statement formats. Provenance: refactored without changing
//! operation order from `fast-validation/src/sumcheck.rs` at research revision
//! `be8b67b74da54d162df2e6e0a9d813779959bb60`.

use thiserror::Error;

use crate::float_contract::{canonicalize_arithmetic, validate_canonical};

/// A degree-two polynomial in the Bernstein basis:
///
/// `b0 * (1-t)^2 + 2*b1*t*(1-t) + b2*t^2`.
///
/// In this basis `g(0) = b0` and `g(1) = b2`, so a round checks `b0 + b2`
/// against the preceding claim without interpolation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct QuadraticBernstein {
    pub coefficients: [f64; 3],
}

impl QuadraticBernstein {
    pub const fn new(b0: f64, b1: f64, b2: f64) -> Self {
        Self {
            coefficients: [b0, b1, b2],
        }
    }

    pub const fn b0(self) -> f64 {
        self.coefficients[0]
    }

    pub const fn b1(self) -> f64 {
        self.coefficients[1]
    }

    pub const fn b2(self) -> f64 {
        self.coefficients[2]
    }

    /// Evaluates with de Casteljau interpolation in the frozen operation order.
    pub fn evaluate(self, challenge: f64) -> Result<f64, SumcheckError> {
        validate_challenge(challenge)?;
        self.validate(None)?;
        let low = interpolate(self.b0(), self.b1(), challenge)?;
        let high = interpolate(self.b1(), self.b2(), challenge)?;
        interpolate(low, high, challenge)
    }

    fn validate(self, round: Option<usize>) -> Result<(), SumcheckError> {
        for (coefficient, value) in self.coefficients.into_iter().enumerate() {
            validate_canonical(value)
                .map_err(|_| SumcheckError::NonCanonicalCoefficient { round, coefficient })?;
        }
        Ok(())
    }
}

/// Serializable-independent proof data.
///
/// The protocol composer owns canonical encoding and challenge derivation.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProductSumcheckProof {
    pub rounds: Vec<QuadraticBernstein>,
}

/// Raw and machine-epsilon-normalized inconsistency for one relation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DefectObservation {
    pub absolute_defect: f64,
    pub scale: f64,
    pub normalized_defect: f64,
}

/// Prover-side endpoint values.
///
/// A complete protocol must authenticate both factor evaluations.
#[derive(Clone, Debug, PartialEq)]
pub struct ProductEndpoint {
    pub point: Vec<f64>,
    pub claim: f64,
    pub left_evaluation: f64,
    pub right_evaluation: f64,
    pub defect: DefectObservation,
}

/// Endpoint claim after transcript replay but before commitment authentication.
#[derive(Clone, Debug, PartialEq)]
pub struct ProductEndpointClaim {
    pub point: Vec<f64>,
    pub claim: f64,
}

/// Result of replaying one product-sumcheck transcript.
#[derive(Clone, Debug, PartialEq)]
pub struct ProductSumcheckVerification {
    pub endpoint: ProductEndpointClaim,
    pub round_defects: Vec<DefectObservation>,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum SumcheckError {
    #[error("sumcheck tables must have the same length (left {left}, right {right})")]
    UnequalTableLengths { left: usize, right: usize },
    #[error("sumcheck table length {0} must be a nonzero power of two")]
    InvalidTableLength(usize),
    #[error("sumcheck proof has {actual} rounds; expected {expected}")]
    WrongRoundCount { expected: usize, actual: usize },
    #[error("MLE point has {actual} coordinates; expected {expected}")]
    WrongPointDimension { expected: usize, actual: usize },
    #[error("table {table} contains a non-canonical value at index {index}")]
    NonCanonicalTableValue { table: &'static str, index: usize },
    #[error("the initial sumcheck claim is not a canonical finite binary64 value")]
    NonCanonicalInitialClaim,
    #[error(
        "sumcheck coefficient {coefficient} in {round_description} is not canonical",
        round_description = round.map_or_else(|| "an unnumbered round".to_owned(), |round| format!("round {round}"))
    )]
    NonCanonicalCoefficient {
        round: Option<usize>,
        coefficient: usize,
    },
    #[error("sumcheck challenge is non-canonical or outside [0, 1]")]
    InvalidChallenge,
    #[error("endpoint {factor} evaluation is not canonical")]
    NonCanonicalEndpoint { factor: &'static str },
    #[error("floating-point computation produced a non-finite value during {phase}")]
    NonFiniteComputation { phase: &'static str },
}

/// Constructs a product-sumcheck transcript from borrowed tables.
///
/// The callback must absorb the supplied round before returning the verifier's
/// challenge. Verification must replay identical callback behavior.
pub fn prove_product<C>(
    left: &[f64],
    right: &[f64],
    initial_claim: f64,
    challenge: C,
) -> Result<(ProductSumcheckProof, ProductEndpoint), SumcheckError>
where
    C: FnMut(usize, &QuadraticBernstein) -> f64,
{
    prove_product_owned(left.to_vec(), right.to_vec(), initial_claim, challenge)
}

/// Ownership-taking prover entry point that avoids cloning retained tables.
///
/// The vectors are folded and truncated in place, retaining `O(n)` total
/// storage and no per-round full-table allocation.
pub fn prove_product_owned<C>(
    mut left: Vec<f64>,
    mut right: Vec<f64>,
    initial_claim: f64,
    mut challenge: C,
) -> Result<(ProductSumcheckProof, ProductEndpoint), SumcheckError>
where
    C: FnMut(usize, &QuadraticBernstein) -> f64,
{
    let variables = validate_table_pair(&left, &right)?;
    validate_canonical(initial_claim).map_err(|_| SumcheckError::NonCanonicalInitialClaim)?;

    let mut claim = initial_claim;
    let mut point = Vec::with_capacity(variables);
    let mut rounds = Vec::with_capacity(variables);

    for round_index in 0..variables {
        let round = product_round(&left, &right)?;
        round.validate(Some(round_index))?;
        let round_challenge = challenge(round_index, &round);
        validate_challenge(round_challenge)?;
        claim = round.evaluate(round_challenge)?;
        fold_table(&mut left, round_challenge)?;
        fold_table(&mut right, round_challenge)?;
        point.push(round_challenge);
        rounds.push(round);
    }

    let left_evaluation = canonicalize_zero(left[0]);
    let right_evaluation = canonicalize_zero(right[0]);
    let actual = checked_product(left_evaluation, right_evaluation, "endpoint product")?;
    let defect = observe_relation(actual, claim, &[actual, claim])?;

    Ok((
        ProductSumcheckProof { rounds },
        ProductEndpoint {
            point,
            claim,
            left_evaluation,
            right_evaluation,
            defect,
        },
    ))
}

/// Replays a product sumcheck and reports every approximate round relation.
///
/// Success means structural and encoding validity only. The caller must score
/// all returned defects and authenticate the endpoint factors.
pub fn verify_product<C>(
    table_len: usize,
    initial_claim: f64,
    proof: &ProductSumcheckProof,
    mut challenge: C,
) -> Result<ProductSumcheckVerification, SumcheckError>
where
    C: FnMut(usize, &QuadraticBernstein) -> f64,
{
    let variables = variables_for_len(table_len)?;
    validate_canonical(initial_claim).map_err(|_| SumcheckError::NonCanonicalInitialClaim)?;
    if proof.rounds.len() != variables {
        return Err(SumcheckError::WrongRoundCount {
            expected: variables,
            actual: proof.rounds.len(),
        });
    }

    let mut claim = initial_claim;
    let mut point = Vec::with_capacity(variables);
    let mut round_defects = Vec::with_capacity(variables);
    for (round_index, &round) in proof.rounds.iter().enumerate() {
        round.validate(Some(round_index))?;
        let endpoints_sum = checked_sum(round.b0(), round.b2(), "round endpoint sum")?;
        let scale_terms = [round.b0(), round.b2(), claim];
        round_defects.push(observe_relation(endpoints_sum, claim, &scale_terms)?);

        let round_challenge = challenge(round_index, &round);
        validate_challenge(round_challenge)?;
        claim = round.evaluate(round_challenge)?;
        point.push(round_challenge);
    }

    Ok(ProductSumcheckVerification {
        endpoint: ProductEndpointClaim { point, claim },
        round_defects,
    })
}

/// Compares authenticated factor evaluations with the final sumcheck claim.
pub fn verify_product_endpoint(
    endpoint: &ProductEndpointClaim,
    left_evaluation: f64,
    right_evaluation: f64,
) -> Result<DefectObservation, SumcheckError> {
    validate_canonical(endpoint.claim)
        .map_err(|_| SumcheckError::NonCanonicalEndpoint { factor: "claim" })?;
    validate_canonical(left_evaluation)
        .map_err(|_| SumcheckError::NonCanonicalEndpoint { factor: "left" })?;
    validate_canonical(right_evaluation)
        .map_err(|_| SumcheckError::NonCanonicalEndpoint { factor: "right" })?;
    let product = checked_product(left_evaluation, right_evaluation, "endpoint product")?;
    observe_relation(product, endpoint.claim, &[product, endpoint.claim])
}

/// Evaluates an MLE using the fast path's MSB-coordinate-first convention.
///
/// The first coordinate pairs the low and high halves of the table. This
/// convention is protocol-significant: the unit-circle code's coefficient bit
/// reversal is aligned to exactly this fold order.
pub fn evaluate_mle(table: &[f64], point: &[f64]) -> Result<f64, SumcheckError> {
    let variables = validate_table("table", table)?;
    if point.len() != variables {
        return Err(SumcheckError::WrongPointDimension {
            expected: variables,
            actual: point.len(),
        });
    }
    let mut folded = table.to_vec();
    for &coordinate in point {
        validate_challenge(coordinate)?;
        fold_table(&mut folded, coordinate)?;
    }
    Ok(canonicalize_zero(folded[0]))
}

/// Deterministic compensated product sum for constructing an initial claim.
pub fn product_sum(left: &[f64], right: &[f64]) -> Result<f64, SumcheckError> {
    validate_table_pair(left, right)?;
    let mut sum = CompensatedSum::default();
    for (&lhs, &rhs) in left.iter().zip(right) {
        sum.add(checked_product(lhs, rhs, "product sum")?)?;
    }
    sum.finish("product sum")
}

fn product_round(left: &[f64], right: &[f64]) -> Result<QuadraticBernstein, SumcheckError> {
    debug_assert_eq!(left.len(), right.len());
    debug_assert!(left.len() >= 2 && left.len().is_power_of_two());
    let half = left.len() / 2;
    let mut b0 = CompensatedSum::default();
    let mut b1 = CompensatedSum::default();
    let mut b2 = CompensatedSum::default();
    for index in 0..half {
        let left_low = left[index];
        let left_high = left[index + half];
        let right_low = right[index];
        let right_high = right[index + half];
        b0.add(checked_product(left_low, right_low, "round b0")?)?;
        let cross_low = checked_product(left_low, right_high, "round b1")?;
        let cross_high = checked_product(left_high, right_low, "round b1")?;
        let cross = checked_sum(cross_low, cross_high, "round b1")? * 0.5;
        if !cross.is_finite() {
            return Err(SumcheckError::NonFiniteComputation { phase: "round b1" });
        }
        b1.add(cross)?;
        b2.add(checked_product(left_high, right_high, "round b2")?)?;
    }
    Ok(QuadraticBernstein::new(
        b0.finish("round b0")?,
        b1.finish("round b1")?,
        b2.finish("round b2")?,
    ))
}

fn fold_table(table: &mut Vec<f64>, challenge: f64) -> Result<(), SumcheckError> {
    debug_assert!(!table.is_empty() && table.len().is_power_of_two());
    if table.len() == 1 {
        return Ok(());
    }
    let half = table.len() / 2;
    for index in 0..half {
        table[index] = interpolate(table[index], table[index + half], challenge)?;
    }
    table.truncate(half);
    Ok(())
}

fn interpolate(low: f64, high: f64, challenge: f64) -> Result<f64, SumcheckError> {
    let complement = 1.0 - challenge;
    let low_term = complement * low;
    let high_term = challenge * high;
    let value = low_term + high_term;
    canonicalize_computation(value, "multilinear interpolation")
}

fn observe_relation(
    actual: f64,
    expected: f64,
    scale_terms: &[f64],
) -> Result<DefectObservation, SumcheckError> {
    let difference = actual - expected;
    if !difference.is_finite() {
        return Err(SumcheckError::NonFiniteComputation {
            phase: "defect evaluation",
        });
    }
    let absolute_defect = canonicalize_zero(difference.abs());
    let scale = saturating_absolute_sum(scale_terms);
    let denominator = f64::EPSILON * scale.max(1.0);
    let normalized = absolute_defect / denominator;
    let normalized_defect = if normalized.is_finite() {
        canonicalize_zero(normalized)
    } else {
        f64::MAX
    };
    Ok(DefectObservation {
        absolute_defect,
        scale,
        normalized_defect,
    })
}

fn saturating_absolute_sum(values: &[f64]) -> f64 {
    let mut total = 0.0;
    for value in values {
        let next = total + value.abs();
        if !next.is_finite() {
            return f64::MAX;
        }
        total = next;
    }
    canonicalize_zero(total)
}

fn checked_product(left: f64, right: f64, phase: &'static str) -> Result<f64, SumcheckError> {
    canonicalize_computation(left * right, phase)
}

fn checked_sum(left: f64, right: f64, phase: &'static str) -> Result<f64, SumcheckError> {
    canonicalize_computation(left + right, phase)
}

fn canonicalize_computation(value: f64, phase: &'static str) -> Result<f64, SumcheckError> {
    canonicalize_arithmetic(value).map_err(|_| SumcheckError::NonFiniteComputation { phase })
}

fn validate_table_pair(left: &[f64], right: &[f64]) -> Result<usize, SumcheckError> {
    if left.len() != right.len() {
        return Err(SumcheckError::UnequalTableLengths {
            left: left.len(),
            right: right.len(),
        });
    }
    let variables = validate_table("left", left)?;
    validate_table("right", right)?;
    Ok(variables)
}

fn validate_table(table_name: &'static str, table: &[f64]) -> Result<usize, SumcheckError> {
    let variables = variables_for_len(table.len())?;
    for (index, &value) in table.iter().enumerate() {
        validate_canonical(value).map_err(|_| SumcheckError::NonCanonicalTableValue {
            table: table_name,
            index,
        })?;
    }
    Ok(variables)
}

fn variables_for_len(len: usize) -> Result<usize, SumcheckError> {
    if len == 0 || !len.is_power_of_two() {
        return Err(SumcheckError::InvalidTableLength(len));
    }
    Ok(len.ilog2() as usize)
}

fn validate_challenge(challenge: f64) -> Result<(), SumcheckError> {
    validate_canonical(challenge).map_err(|_| SumcheckError::InvalidChallenge)?;
    if !(0.0..=1.0).contains(&challenge) {
        return Err(SumcheckError::InvalidChallenge);
    }
    Ok(())
}

fn canonicalize_zero(value: f64) -> f64 {
    if value == 0.0 || value.is_subnormal() {
        0.0
    } else {
        value
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct CompensatedSum {
    sum: f64,
    correction: f64,
}

impl CompensatedSum {
    fn add(&mut self, value: f64) -> Result<(), SumcheckError> {
        let next = self.sum + value;
        if !next.is_finite() {
            return Err(SumcheckError::NonFiniteComputation {
                phase: "compensated summation",
            });
        }
        let correction = if self.sum.abs() >= value.abs() {
            (self.sum - next) + value
        } else {
            (value - next) + self.sum
        };
        self.correction += correction;
        if !self.correction.is_finite() {
            return Err(SumcheckError::NonFiniteComputation {
                phase: "compensated summation",
            });
        }
        self.sum = next;
        Ok(())
    }

    fn finish(self, phase: &'static str) -> Result<f64, SumcheckError> {
        checked_sum(self.sum, self.correction, phase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGES: [f64; 3] = [0.25, 0.625, 0.375];

    fn scripted_challenge(round: usize, _: &QuadraticBernstein) -> f64 {
        CHALLENGES[round]
    }

    #[test]
    fn honest_product_sumcheck_replays_and_opens() {
        let left = [0.5, -1.25, 2.0, 0.75, -0.5, 3.0, 1.5, -2.0];
        let right = [1.5, 0.25, -0.75, 2.0, 1.25, -0.5, 0.5, 1.0];
        let initial_claim = product_sum(&left, &right).unwrap();

        let (proof, prover_endpoint) =
            prove_product(&left, &right, initial_claim, scripted_challenge).unwrap();
        let verification =
            verify_product(left.len(), initial_claim, &proof, scripted_challenge).unwrap();

        assert_eq!(verification.endpoint.point, CHALLENGES);
        assert_eq!(verification.endpoint.point, prover_endpoint.point);
        assert_eq!(verification.endpoint.claim, prover_endpoint.claim);
        assert!(
            verification
                .round_defects
                .iter()
                .all(|observation| observation.normalized_defect <= 4.0)
        );

        let left_at_point = evaluate_mle(&left, &verification.endpoint.point).unwrap();
        let right_at_point = evaluate_mle(&right, &verification.endpoint.point).unwrap();
        assert_eq!(left_at_point, prover_endpoint.left_evaluation);
        assert_eq!(right_at_point, prover_endpoint.right_evaluation);
        let endpoint_defect =
            verify_product_endpoint(&verification.endpoint, left_at_point, right_at_point).unwrap();
        assert_eq!(endpoint_defect, prover_endpoint.defect);
        assert!(endpoint_defect.normalized_defect <= 4.0);
    }

    #[test]
    fn mutated_round_is_reported_as_a_defect() {
        let left = [1.0, 2.0, 3.0, 4.0];
        let right = [0.5, -1.0, 1.5, 2.0];
        let initial_claim = product_sum(&left, &right).unwrap();
        let (mut proof, _) =
            prove_product(&left, &right, initial_claim, scripted_challenge).unwrap();
        proof.rounds[0].coefficients[0] += 0.125;

        let verification =
            verify_product(left.len(), initial_claim, &proof, scripted_challenge).unwrap();
        assert!(verification.round_defects[0].absolute_defect > 0.0);
        assert!(verification.round_defects[0].normalized_defect > 1.0);
    }

    #[test]
    fn wrong_round_count_is_rejected() {
        let proof = ProductSumcheckProof {
            rounds: vec![QuadraticBernstein::new(0.0, 0.0, 0.0)],
        };
        assert_eq!(
            verify_product(8, 0.0, &proof, scripted_challenge),
            Err(SumcheckError::WrongRoundCount {
                expected: 3,
                actual: 1,
            })
        );
    }

    #[test]
    fn endpoint_observation_detects_a_changed_opening() {
        let left = [1.0, -2.0, 0.5, 3.0];
        let right = [2.0, 1.0, -1.5, 0.25];
        let initial_claim = product_sum(&left, &right).unwrap();
        let (proof, _) = prove_product(&left, &right, initial_claim, scripted_challenge).unwrap();
        let verification =
            verify_product(left.len(), initial_claim, &proof, scripted_challenge).unwrap();
        let left_at_point = evaluate_mle(&left, &verification.endpoint.point).unwrap();
        let right_at_point = evaluate_mle(&right, &verification.endpoint.point).unwrap();

        let honest =
            verify_product_endpoint(&verification.endpoint, left_at_point, right_at_point).unwrap();
        let changed =
            verify_product_endpoint(&verification.endpoint, left_at_point + 0.25, right_at_point)
                .unwrap();
        assert!(honest.normalized_defect <= 4.0);
        assert!(changed.absolute_defect > honest.absolute_defect);
        assert!(changed.normalized_defect > 1.0);
    }

    #[test]
    fn noncanonical_values_and_bad_shapes_are_rejected() {
        assert!(matches!(
            product_sum(&[1.0, f64::NAN], &[1.0, 2.0]),
            Err(SumcheckError::NonCanonicalTableValue { .. })
        ));
        assert!(matches!(
            product_sum(&[1.0, -0.0], &[1.0, 2.0]),
            Err(SumcheckError::NonCanonicalTableValue { .. })
        ));
        assert!(matches!(
            product_sum(&[1.0, f64::from_bits(1)], &[1.0, 2.0]),
            Err(SumcheckError::NonCanonicalTableValue { .. })
        ));
        assert_eq!(
            product_sum(&[1.0, 2.0], &[1.0]),
            Err(SumcheckError::UnequalTableLengths { left: 2, right: 1 })
        );
        assert_eq!(
            evaluate_mle(&[1.0, 2.0, 3.0, 4.0], &[0.5]),
            Err(SumcheckError::WrongPointDimension {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn first_coordinate_pairs_low_and_high_table_halves() {
        let table = [0.0, 10.0, 100.0, 110.0];
        assert_eq!(evaluate_mle(&table, &[0.25, 0.0]).unwrap(), 25.0);
        assert_eq!(evaluate_mle(&table, &[0.25, 1.0]).unwrap(), 35.0);
    }
}
