//! Versioned normalization policy and verifier-computed numerical diagnostics.
//!
//! Approximate algebraic relations are observations, not acceptance gates.
//! Structural and cryptographic relations remain exact in the protocol
//! composer. Policy constants provide dimensionally appropriate floors for
//! comparing values near zero; they are not claimed soundness bounds.

use crate::sumcheck::DefectObservation;
use crate::unit_circle::ComplexValue;

/// Frozen fast-validation diagnostic policy 3.
///
/// This zero-sized namespace separates protocol constants from proof metadata.
/// Changing any zero scale requires a new policy identifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Policy3;

/// The one supported instance of diagnostic policy 3.
pub const POLICY_3: Policy3 = Policy3;

impl Policy3 {
    /// Identifier absorbed by the enclosing transcript.
    pub const ID: u16 = 3;

    /// Normalization floor for squared-residual norm relations.
    ///
    /// This is `(2^-42)^2`, because these relations have squared-residual
    /// units. It is a reporting scale, not a theorem-derived error allowance.
    pub const NORM_ZERO_SCALE: f64 = 5.169_878_828_456_423e-26; // 2^-84

    /// Normalization floor for matrix-vector product relations.
    pub const MATVEC_ZERO_SCALE: f64 = 2.273_736_754_432_320_6e-13; // 2^-42

    /// Normalization floor for linear-opening relations.
    pub const LINEAR_OPENING_ZERO_SCALE: f64 = 2.273_736_754_432_320_6e-13; // 2^-42

    /// Normalization floor for recursive unit-circle fold relations.
    pub const UNIT_CIRCLE_FOLD_ZERO_SCALE: f64 = 3.637_978_807_091_713e-12; // 2^-38

    /// Maximum number of distinct recursive query trajectories.
    pub const PROXIMITY_QUERY_TARGET: usize = 64;

    /// Returns the exact transcript-binding tuple for this policy.
    #[must_use]
    pub const fn transcript_parameters(self) -> PolicyTranscriptParameters {
        PolicyTranscriptParameters {
            policy_id: Self::ID,
            norm_zero_scale_bits: Self::NORM_ZERO_SCALE.to_bits(),
            matvec_zero_scale_bits: Self::MATVEC_ZERO_SCALE.to_bits(),
            linear_opening_zero_scale_bits: Self::LINEAR_OPENING_ZERO_SCALE.to_bits(),
            unit_circle_fold_zero_scale_bits: Self::UNIT_CIRCLE_FOLD_ZERO_SCALE.to_bits(),
            proximity_query_target: Self::PROXIMITY_QUERY_TARGET as u64,
        }
    }
}

/// Exact scalar parameters that a protocol composer must bind into Fiat--Shamir.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyTranscriptParameters {
    pub policy_id: u16,
    pub norm_zero_scale_bits: u64,
    pub matvec_zero_scale_bits: u64,
    pub linear_opening_zero_scale_bits: u64,
    pub unit_circle_fold_zero_scale_bits: u64,
    pub proximity_query_target: u64,
}

/// One floor-relative error together with all inputs used to derive it.
///
/// The reported error is
/// `absolute_defect / max(normalization_scale, zero_scale)`, where
/// `normalization_scale = min(actual_magnitude, expected_magnitude)`.
#[must_use = "retain the observation as provenance or explicitly discard it"]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RelativeErrorObservation {
    pub actual_magnitude: f64,
    pub expected_magnitude: f64,
    pub absolute_defect: f64,
    pub normalization_scale: f64,
    pub zero_scale: f64,
    pub relative_error: f64,
}

/// Neutral statistical summary of a homogeneous approximate relation class.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DefectSummary {
    pub checks: u64,
    pub zero_scale: f64,
    pub max_absolute: f64,
    pub max_relative: f64,
    pub rms_relative: f64,
    pub min_normalization_scale: f64,
    pub max_normalization_scale: f64,
}

/// Complete metric report produced by a fast sparse-solve validator.
#[derive(Clone, Debug, PartialEq)]
pub struct FastValidationScore {
    /// Initial-claim, round, and endpoint diagnostics for the residual norm.
    pub norm_sumcheck: DefectSummary,
    /// Round and authenticated-endpoint diagnostics for the compressed matvec.
    pub matvec_sumcheck: DefectSummary,
    /// Diagnostics for the committed-table linear opening.
    pub linear_opening_sumcheck: DefectSummary,
    /// Sampled recursive unit-circle fold diagnostics.
    pub unit_circle_folds: DefectSummary,
    /// Prover's structurally authenticated squared-L2 claim.
    ///
    /// The diagnostic policy does not itself establish an error interval for
    /// this value. A future a posteriori theorem may derive one from the
    /// observations and public evaluator bounds.
    pub squared_l2_claim: f64,
    pub residual_l2_claim: f64,
    pub residual_rms_claim: f64,
    /// Unique recursive paths checked in every folding round.
    pub proximity_queries_per_round: u32,
    /// Per-round conditional miss bounds for bad fractions 1%, 5%, and 10%.
    pub conditional_miss_probability_upper_bound: [f64; 3],
}

/// Allocation-free accumulator for one homogeneous relation class.
#[derive(Clone, Copy, Debug)]
pub struct DefectAccumulator {
    zero_scale: f64,
    checks: u64,
    max_absolute: f64,
    max_relative: f64,
    relative_square_sum: f64,
    min_normalization_scale: f64,
    max_normalization_scale: f64,
}

impl DefectAccumulator {
    /// Accumulator for residual-norm sumcheck relations.
    #[must_use]
    pub const fn policy3_norm_sumcheck() -> Self {
        Self::new(Policy3::NORM_ZERO_SCALE)
    }

    /// Accumulator for compressed matrix-vector sumcheck relations.
    #[must_use]
    pub const fn policy3_matvec_sumcheck() -> Self {
        Self::new(Policy3::MATVEC_ZERO_SCALE)
    }

    /// Accumulator for linear-opening sumcheck relations.
    #[must_use]
    pub const fn policy3_linear_opening_sumcheck() -> Self {
        Self::new(Policy3::LINEAR_OPENING_ZERO_SCALE)
    }

    /// Accumulator for recursive unit-circle fold relations.
    #[must_use]
    pub const fn policy3_unit_circle_folds() -> Self {
        Self::new(Policy3::UNIT_CIRCLE_FOLD_ZERO_SCALE)
    }

    const fn new(zero_scale: f64) -> Self {
        Self {
            zero_scale,
            checks: 0,
            max_absolute: 0.0,
            max_relative: 0.0,
            relative_square_sum: 0.0,
            min_normalization_scale: f64::INFINITY,
            max_normalization_scale: 0.0,
        }
    }

    /// Records scalar relation provenance and returns its full diagnostic.
    pub fn observe(&mut self, observation: DefectObservation) -> RelativeErrorObservation {
        let actual_magnitude = finite_magnitude(observation.actual_magnitude);
        let expected_magnitude = finite_magnitude(observation.expected_magnitude);
        let absolute_defect = finite_magnitude(observation.absolute_defect);
        let normalization_scale = actual_magnitude.min(expected_magnitude);
        let denominator = normalization_scale.max(self.zero_scale);
        let relative_error = finite_quotient(absolute_defect, denominator);

        self.record(absolute_defect, normalization_scale, relative_error);
        RelativeErrorObservation {
            actual_magnitude,
            expected_magnitude,
            absolute_defect,
            normalization_scale,
            zero_scale: self.zero_scale,
            relative_error,
        }
    }

    /// Records one recursive complex fold relation and returns its diagnostic.
    pub fn observe_unit_circle_fold(
        &mut self,
        actual: ComplexValue,
        expected: ComplexValue,
    ) -> RelativeErrorObservation {
        let defect =
            (actual.real() - expected.real()).hypot(actual.imaginary() - expected.imaginary());
        self.observe(DefectObservation {
            actual_magnitude: actual.magnitude(),
            expected_magnitude: expected.magnitude(),
            absolute_defect: defect,
            normalization_scale: actual.magnitude().min(expected.magnitude()),
        })
    }

    fn record(&mut self, absolute: f64, normalization_scale: f64, relative: f64) {
        self.checks = self.checks.saturating_add(1);
        self.max_absolute = self.max_absolute.max(absolute);
        self.max_relative = self.max_relative.max(relative);
        self.relative_square_sum =
            saturating_float_add(self.relative_square_sum, relative * relative);
        self.min_normalization_scale = self.min_normalization_scale.min(normalization_scale);
        self.max_normalization_scale = self.max_normalization_scale.max(normalization_scale);
    }

    /// Finalizes neutral maximum and RMS statistics.
    #[must_use]
    pub fn finish(self) -> DefectSummary {
        let rms_relative = if self.checks == 0 {
            0.0
        } else {
            (self.relative_square_sum / self.checks as f64)
                .sqrt()
                .min(self.max_relative)
        };
        DefectSummary {
            checks: self.checks,
            zero_scale: self.zero_scale,
            max_absolute: self.max_absolute,
            max_relative: self.max_relative,
            rms_relative,
            min_normalization_scale: if self.checks == 0 {
                0.0
            } else {
                self.min_normalization_scale
            },
            max_normalization_scale: self.max_normalization_scale,
        }
    }
}

fn finite_magnitude(value: f64) -> f64 {
    let magnitude = value.abs();
    if magnitude.is_finite() {
        magnitude
    } else {
        f64::MAX
    }
}

fn finite_quotient(numerator: f64, denominator: f64) -> f64 {
    let quotient = numerator / denominator;
    if quotient.is_finite() {
        quotient
    } else {
        f64::MAX
    }
}

fn saturating_float_add(left: f64, right: f64) -> f64 {
    let result = left + right;
    if result.is_finite() { result } else { f64::MAX }
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

    fn scalar_observation(actual: f64, expected: f64) -> DefectObservation {
        DefectObservation {
            actual_magnitude: actual.abs(),
            expected_magnitude: expected.abs(),
            absolute_defect: (actual - expected).abs(),
            normalization_scale: actual.abs().min(expected.abs()),
        }
    }

    #[test]
    fn policy_three_constants_are_frozen_and_dimensionally_distinct() {
        assert_eq!(Policy3::NORM_ZERO_SCALE, 2.0_f64.powi(-84));
        assert_eq!(Policy3::MATVEC_ZERO_SCALE, 2.0_f64.powi(-42));
        assert_eq!(Policy3::LINEAR_OPENING_ZERO_SCALE, 2.0_f64.powi(-42));
        assert_eq!(Policy3::UNIT_CIRCLE_FOLD_ZERO_SCALE, 2.0_f64.powi(-38));
        assert_eq!(POLICY_3.transcript_parameters().policy_id, 3);
        assert_eq!(Policy3::PROXIMITY_QUERY_TARGET, 64);
    }

    #[test]
    fn all_zero_matvec_calibration_reports_one_without_a_verdict() {
        let mut accumulator = DefectAccumulator::policy3_matvec_sumcheck();
        let observation = accumulator.observe(scalar_observation(0.0, 2.0_f64.powi(-42)));
        let summary = accumulator.finish();

        assert_eq!(observation.absolute_defect, 2.0_f64.powi(-42));
        assert_eq!(observation.normalization_scale, 0.0);
        assert_eq!(observation.zero_scale, 2.0_f64.powi(-42));
        assert_eq!(observation.relative_error, 1.0);
        assert_eq!(summary.checks, 1);
        assert_eq!(summary.max_relative, 1.0);
        assert_eq!(summary.rms_relative, 1.0);
    }

    #[test]
    fn floor_relative_error_uses_the_smaller_magnitude() {
        let mut accumulator = DefectAccumulator::policy3_matvec_sumcheck();
        let observation = accumulator.observe(scalar_observation(4.0, 2.0));
        assert_eq!(observation.normalization_scale, 2.0);
        assert_eq!(observation.relative_error, 1.0);
    }

    #[test]
    fn summaries_keep_raw_scale_maximum_and_rms_information() {
        let mut accumulator = DefectAccumulator::policy3_linear_opening_sumcheck();
        let _ = accumulator.observe(scalar_observation(1.5, 1.0));
        let _ = accumulator.observe(scalar_observation(4.0, 2.0));
        let summary = accumulator.finish();
        assert_eq!(summary.checks, 2);
        assert_eq!(summary.zero_scale, Policy3::LINEAR_OPENING_ZERO_SCALE);
        assert_eq!(summary.max_absolute, 2.0);
        assert_eq!(summary.max_relative, 1.0);
        assert!((summary.rms_relative - (0.625_f64).sqrt()).abs() < 1e-15);
        assert_eq!(summary.min_normalization_scale, 1.0);
        assert_eq!(summary.max_normalization_scale, 2.0);
    }

    #[test]
    fn unit_circle_fold_uses_complex_magnitudes() {
        let expected = ComplexValue::new(3.0, 4.0).unwrap();
        let actual = ComplexValue::new(0.0, 5.0).unwrap();
        let mut accumulator = DefectAccumulator::policy3_unit_circle_folds();
        let observation = accumulator.observe_unit_circle_fold(actual, expected);
        assert_eq!(observation.actual_magnitude, 5.0);
        assert_eq!(observation.expected_magnitude, 5.0);
        assert_eq!(observation.normalization_scale, 5.0);
        assert_eq!(observation.absolute_defect, 3.0_f64.hypot(1.0));
    }

    #[test]
    fn empty_summary_has_finite_neutral_statistics() {
        let summary = DefectAccumulator::policy3_norm_sumcheck().finish();
        assert_eq!(summary.checks, 0);
        assert_eq!(summary.max_absolute, 0.0);
        assert_eq!(summary.max_relative, 0.0);
        assert_eq!(summary.rms_relative, 0.0);
        assert_eq!(summary.min_normalization_scale, 0.0);
        assert_eq!(summary.max_normalization_scale, 0.0);
    }

    #[test]
    fn nonfinite_provenance_saturates_diagnostics() {
        let mut accumulator = DefectAccumulator::policy3_norm_sumcheck();
        let observation = accumulator.observe(DefectObservation {
            actual_magnitude: f64::INFINITY,
            expected_magnitude: 1.0,
            absolute_defect: f64::NAN,
            normalization_scale: 1.0,
        });
        let summary = accumulator.finish();
        assert_eq!(observation.absolute_defect, f64::MAX);
        assert_eq!(observation.relative_error, f64::MAX);
        assert_eq!(summary.max_absolute, f64::MAX);
        assert_eq!(summary.max_relative, f64::MAX);
        assert!(summary.rms_relative.is_finite());
        assert!(summary.rms_relative <= summary.max_relative);
    }

    #[test]
    fn miss_probability_is_conditional_on_bad_fraction() {
        let probabilities = conditional_miss_probabilities(128);
        assert!(probabilities[0] > probabilities[1]);
        assert!(probabilities[1] > probabilities[2]);
        assert!(probabilities[2] < 2e-6);
    }
}
