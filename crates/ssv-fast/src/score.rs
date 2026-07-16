//! Versioned tolerance policy and verifier-computed numerical diagnostics.
//!
//! Provenance: defect accumulation comes from `fast-validation/src/score.rs`;
//! policy constants come from `fast-validation/src/protocol.rs` at research
//! revision `be8b67b74da54d162df2e6e0a9d813779959bb60`. Keeping the constants
//! here prevents a backend from accidentally inventing its own acceptance
//! thresholds.

use crate::sumcheck::DefectObservation;
use crate::unit_circle::ComplexValue;

/// Absolute and scale-relative allowance for one approximate relation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MetricTolerance {
    /// Fixed allowance independent of operand scale.
    pub absolute: f64,
    /// Allowance multiplied by the validator-computed operand scale.
    pub relative: f64,
}

impl MetricTolerance {
    /// Computes `absolute + relative * abs(scale)` in policy operation order.
    #[must_use]
    pub fn allowance(self, scale: f64) -> f64 {
        self.absolute + self.relative * scale.abs()
    }
}

/// Frozen fast-validation policy 2.
///
/// This zero-sized type is an explicit namespace, making it difficult to
/// confuse versioned protocol constants with proof-controlled metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Policy2;

/// The one supported instance of the frozen policy-2 namespace.
pub const POLICY_2: Policy2 = Policy2;

impl Policy2 {
    /// Identifier absorbed by the enclosing transcript.
    pub const ID: u16 = 2;

    /// Ordinary sumcheck and endpoint tolerance.
    pub const NUMERIC_TOLERANCE: MetricTolerance = MetricTolerance {
        absolute: 2.273_736_754_432_320_6e-13, // 2^-42
        relative: 4096.0 * f64::EPSILON,
    };

    /// Recursive unit-circle fold tolerance.
    pub const FOLD_TOLERANCE: MetricTolerance = MetricTolerance {
        absolute: 3.637_978_807_091_713e-12, // 2^-38
        relative: 131_072.0 * f64::EPSILON,
    };

    /// Maximum number of distinct recursive query trajectories.
    pub const PROXIMITY_QUERY_TARGET: usize = 64;

    /// Returns the exact transcript-binding tuple for this policy.
    #[must_use]
    pub const fn transcript_parameters(self) -> PolicyTranscriptParameters {
        PolicyTranscriptParameters {
            policy_id: Self::ID,
            numeric_absolute_bits: Self::NUMERIC_TOLERANCE.absolute.to_bits(),
            numeric_relative_bits: Self::NUMERIC_TOLERANCE.relative.to_bits(),
            fold_absolute_bits: Self::FOLD_TOLERANCE.absolute.to_bits(),
            fold_relative_bits: Self::FOLD_TOLERANCE.relative.to_bits(),
            proximity_query_target: Self::PROXIMITY_QUERY_TARGET as u64,
        }
    }
}

/// Exact scalar parameters that a protocol composer must bind into Fiat--Shamir.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyTranscriptParameters {
    pub policy_id: u16,
    pub numeric_absolute_bits: u64,
    pub numeric_relative_bits: u64,
    pub fold_absolute_bits: u64,
    pub fold_relative_bits: u64,
    pub proximity_query_target: u64,
}

/// Summary of a homogeneous class of approximate checks.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DefectSummary {
    pub checks: u64,
    pub threshold_exceedances: u64,
    pub max_absolute: f64,
    pub max_normalized: f64,
    pub rms_normalized: f64,
}

impl DefectSummary {
    /// Whether every observed normalized defect is at most one.
    #[must_use]
    pub fn passes(self) -> bool {
        self.max_normalized <= 1.0 && self.threshold_exceedances == 0
    }
}

/// Complete metric report produced by a fast sparse-solve validator.
#[derive(Clone, Debug, PartialEq)]
pub struct FastValidationScore {
    /// Initial-claim, round, and endpoint defects in the residual-norm sumcheck.
    pub norm_sumcheck: DefectSummary,
    /// Round and authenticated-endpoint defects in the compressed matvec sumcheck.
    pub matvec_sumcheck: DefectSummary,
    /// Defects in the committed-table linear-opening sumcheck.
    pub linear_opening_sumcheck: DefectSummary,
    /// Sampled recursive unit-circle fold discrepancies.
    pub unit_circle_folds: DefectSummary,
    pub residual_squared_l2: f64,
    pub residual_l2: f64,
    pub residual_rms: f64,
    /// Unique recursive paths checked in every folding round.
    pub proximity_queries_per_round: u32,
    /// Per-round conditional miss bounds for bad fractions 1%, 5%, and 10%.
    pub conditional_miss_probability_upper_bound: [f64; 3],
    /// Transcript consistency only; residual quality remains caller policy.
    pub passes_consistency_policy: bool,
}

/// Allocation-free accumulator for one defect class.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefectAccumulator {
    checks: u64,
    exceedances: u64,
    max_absolute: f64,
    max_normalized: f64,
    normalized_square_sum: f64,
}

impl DefectAccumulator {
    /// Scores a product-sumcheck observation under frozen policy 2.
    pub fn observe_policy2_sumcheck(&mut self, observation: DefectObservation) {
        self.observe_with(
            observation.absolute_defect,
            observation.scale,
            Policy2::NUMERIC_TOLERANCE,
        );
    }

    /// Scores one recursive complex fold relation under frozen policy 2.
    ///
    /// The scale includes authenticated parents, actual child, and expected
    /// child in the same operation order as the audited protocol. Keeping this
    /// here prevents protocol composers from normalizing only by a potentially
    /// tiny post-cancellation result.
    pub fn observe_policy2_unit_circle_fold(
        &mut self,
        actual: ComplexValue,
        expected: ComplexValue,
        authenticated_parents: &[ComplexValue],
    ) {
        let defect =
            (actual.real() - expected.real()).hypot(actual.imaginary() - expected.imaginary());
        let parent_scale = authenticated_parents
            .iter()
            .fold(0.0, |scale, value| scale + value.magnitude());
        let scale = parent_scale + actual.magnitude() + expected.magnitude();
        self.observe_with(defect, scale, Policy2::FOLD_TOLERANCE);
    }

    /// Scores one observed difference against a public scale and tolerance.
    pub fn observe_with(&mut self, defect: f64, scale: f64, tolerance: MetricTolerance) {
        self.observe(defect, scale, tolerance.absolute, tolerance.relative);
    }

    /// Scores one observed difference against explicit tolerances.
    ///
    /// This lower-level form is retained for policy conformance tests and
    /// future versioned policies. Production policy-2 code should prefer
    /// [`Self::observe_with`] and a constant from [`Policy2`].
    pub fn observe(&mut self, defect: f64, scale: f64, abs_tol: f64, rel_tol: f64) {
        let raw_absolute = defect.abs();
        let absolute = if raw_absolute.is_finite() {
            raw_absolute
        } else {
            f64::INFINITY
        };
        let allowance = abs_tol + rel_tol * scale.abs();
        let normalized = if !absolute.is_finite()
            || !scale.is_finite()
            || !allowance.is_finite()
            || allowance < 0.0
        {
            f64::INFINITY
        } else if allowance > 0.0 {
            absolute / allowance
        } else if absolute == 0.0 {
            0.0
        } else {
            f64::INFINITY
        };
        let normalized = if normalized.is_finite() {
            normalized
        } else {
            f64::INFINITY
        };
        self.checks = self.checks.saturating_add(1);
        self.exceedances = self.exceedances.saturating_add(u64::from(normalized > 1.0));
        self.max_absolute = self.max_absolute.max(absolute);
        self.max_normalized = self.max_normalized.max(normalized);
        self.normalized_square_sum =
            saturating_float_add(self.normalized_square_sum, normalized * normalized);
    }

    /// Finalizes the RMS while retaining maximum and threshold information.
    #[must_use]
    pub fn finish(self) -> DefectSummary {
        DefectSummary {
            checks: self.checks,
            threshold_exceedances: self.exceedances,
            max_absolute: self.max_absolute,
            max_normalized: self.max_normalized,
            rms_normalized: if self.checks == 0 {
                0.0
            } else {
                (self.normalized_square_sum / self.checks as f64).sqrt()
            },
        }
    }
}

fn saturating_float_add(left: f64, right: f64) -> f64 {
    let result = left + right;
    if result.is_finite() {
        result
    } else {
        f64::INFINITY
    }
}

/// Conditional per-round miss curves for hypothetical bad fractions.
///
/// These values must not be multiplied across rounds without an additional
/// theorem: recursive trajectories are reused and therefore dependent.
#[must_use]
pub fn conditional_miss_probabilities(queries: usize) -> [f64; 3] {
    [0.01_f64, 0.05, 0.10]
        .map(|bad_fraction| (1.0 - bad_fraction).powi(i32::try_from(queries).unwrap_or(i32::MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_two_constants_are_frozen() {
        assert_eq!(Policy2::NUMERIC_TOLERANCE.absolute, 2.0_f64.powi(-42));
        assert_eq!(Policy2::NUMERIC_TOLERANCE.relative, 4096.0 * f64::EPSILON);
        assert_eq!(Policy2::FOLD_TOLERANCE.absolute, 2.0_f64.powi(-38));
        assert_eq!(Policy2::FOLD_TOLERANCE.relative, 131_072.0 * f64::EPSILON);
        assert_eq!(POLICY_2.transcript_parameters().policy_id, 2);
        assert_eq!(Policy2::PROXIMITY_QUERY_TARGET, 64);
    }

    #[test]
    fn summaries_keep_max_rms_and_exceedance_information() {
        let mut accumulator = DefectAccumulator::default();
        accumulator.observe(0.5, 0.0, 1.0, 0.0);
        accumulator.observe(2.0, 0.0, 1.0, 0.0);
        let summary = accumulator.finish();
        assert_eq!(summary.checks, 2);
        assert_eq!(summary.threshold_exceedances, 1);
        assert_eq!(summary.max_normalized, 2.0);
        assert!((summary.rms_normalized - (2.125_f64).sqrt()).abs() < 1e-15);
        assert!(!summary.passes());
    }

    #[test]
    fn policy_boundary_is_inclusive_and_next_float_fails() {
        let immediately_below = f64::from_bits(1.0_f64.to_bits() - 1);
        let immediately_above = f64::from_bits(1.0_f64.to_bits() + 1);
        let mut accumulator = DefectAccumulator::default();
        accumulator.observe(immediately_below, 0.0, 1.0, 0.0);
        accumulator.observe(1.0, 0.0, 1.0, 0.0);
        accumulator.observe(immediately_above, 0.0, 1.0, 0.0);
        let summary = accumulator.finish();
        assert_eq!(summary.checks, 3);
        assert_eq!(summary.threshold_exceedances, 1);
        assert_eq!(summary.max_normalized, immediately_above);
    }

    #[test]
    fn policy_helpers_apply_the_frozen_tolerances_and_fold_scale() {
        let mut sumcheck = DefectAccumulator::default();
        sumcheck.observe_policy2_sumcheck(DefectObservation {
            absolute_defect: Policy2::NUMERIC_TOLERANCE.absolute,
            scale: 0.0,
            normalized_defect: 999.0,
        });
        assert!(sumcheck.finish().passes());

        let parent_a = ComplexValue::new(3.0, 4.0).unwrap();
        let parent_b = ComplexValue::new(0.0, -12.0).unwrap();
        let expected = ComplexValue::new(1.0, 0.0).unwrap();
        let actual = ComplexValue::new(1.0 + Policy2::FOLD_TOLERANCE.absolute, 0.0).unwrap();
        let mut fold = DefectAccumulator::default();
        fold.observe_policy2_unit_circle_fold(actual, expected, &[parent_a, parent_b]);
        let summary = fold.finish();
        assert_eq!(summary.checks, 1);
        assert!(summary.max_normalized < 1.0);
    }

    #[test]
    fn miss_probability_is_conditional_on_bad_fraction() {
        let probabilities = conditional_miss_probabilities(128);
        assert!(probabilities[0] > probabilities[1]);
        assert!(probabilities[1] > probabilities[2]);
        assert!(probabilities[2] < 2e-6);
    }

    #[test]
    fn nonfinite_or_overflowed_defects_can_never_pass() {
        for (defect, scale, abs_tol, rel_tol) in [
            (f64::INFINITY, 1.0, 1.0, 1.0),
            (f64::NAN, 1.0, 1.0, 1.0),
            (f64::MAX, f64::MAX, 1.0, 2.0),
        ] {
            let mut accumulator = DefectAccumulator::default();
            accumulator.observe(defect, scale, abs_tol, rel_tol);
            let summary = accumulator.finish();
            assert_eq!(summary.threshold_exceedances, 1);
            assert_eq!(summary.max_normalized, f64::INFINITY);
        }
    }
}
