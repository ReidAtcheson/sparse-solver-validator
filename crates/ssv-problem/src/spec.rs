use serde::{Deserialize, Serialize};
use ssv_canonical::{CanonicalEncode, Encoder};
use thiserror::Error;

use crate::digest::{ProblemDigest, ProblemTemplateDigest};
use crate::generator::GeneratedProblem;
use crate::randomness::{
    CanonicalContextBytes, ChallengeContext, FinalizedRandomness, TemplateRandomness,
    challenge_context_digest, derive_instance_seed,
};

/// Largest accepted logical matrix dimension.
///
/// Besides bounding service work, this keeps `3*n - 2` representable by
/// `usize` even on a 32-bit target.
pub const MAX_DIMENSION: u64 = 1 << 30;
pub const MAX_PERIOD_BITS: u8 = 16;
pub const MAX_FRACTIONAL_BITS: u8 = 52;
pub const MAX_CHALLENGE_CONTEXT_BYTES: usize = 64 * 1024;
const MIN_DIMENSION: u64 = 2;
const MAX_EXACT_BINARY64_MANTISSA: u64 = (1_u64 << 53) - 1;
const MAX_REQUESTED_OUTPUTS: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum TemplateSchema {
    #[serde(rename = "sparse-solve/problem-template/v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ProblemSchema {
    #[serde(rename = "sparse-solve/problem/v1")]
    V1,
}

/// Boundary behavior is explicit even though v1 currently registers one rule.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum BoundaryRule {
    #[serde(rename = "truncate-v1")]
    TruncateV1,
}

/// Exact periodic off-diagonal value recipe.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum OffDiagonalValues {
    #[serde(rename = "seeded-periodic-negative-dyadic-v1")]
    SeededPeriodicNegativeDyadicV1 {
        period_bits: u8,
        fractional_bits: u8,
        #[serde(with = "decimal_u64")]
        minimum_magnitude_mantissa: u64,
        #[serde(with = "decimal_u64")]
        maximum_magnitude_mantissa: u64,
    },
}

impl OffDiagonalValues {
    pub(crate) const fn parameters(self) -> (u8, u8, u64, u64) {
        match self {
            Self::SeededPeriodicNegativeDyadicV1 {
                period_bits,
                fractional_bits,
                minimum_magnitude_mantissa,
                maximum_magnitude_mantissa,
            } => (
                period_bits,
                fractional_bits,
                minimum_magnitude_mantissa,
                maximum_magnitude_mantissa,
            ),
        }
    }
}

/// Construction of the positive main diagonal after off-diagonal generation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum DiagonalConstruction {
    #[serde(rename = "absolute-row-sum-plus-margin-v1")]
    AbsoluteRowSumPlusMarginV1 {
        #[serde(with = "decimal_u64")]
        margin_mantissa: u64,
    },
}

impl DiagonalConstruction {
    pub(crate) const fn margin_mantissa(self) -> u64 {
        match self {
            Self::AbsoluteRowSumPlusMarginV1 { margin_mantissa } => margin_mantissa,
        }
    }
}

/// Registered sparse matrix construction families.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum MatrixSpec {
    #[serde(rename = "seeded-symmetric-tridiagonal-v1")]
    SeededSymmetricTridiagonalV1 {
        dimension: u64,
        boundary: BoundaryRule,
        off_diagonal: OffDiagonalValues,
        diagonal: DiagonalConstruction,
    },
}

impl MatrixSpec {
    #[must_use]
    pub const fn dimension(self) -> u64 {
        match self {
            Self::SeededSymmetricTridiagonalV1 { dimension, .. } => dimension,
        }
    }

    pub(crate) const fn components(
        self,
    ) -> (u64, BoundaryRule, OffDiagonalValues, DiagonalConstruction) {
        match self {
            Self::SeededSymmetricTridiagonalV1 {
                dimension,
                boundary,
                off_diagonal,
                diagonal,
            } => (dimension, boundary, off_diagonal, diagonal),
        }
    }
}

/// Registered RHS construction families.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum RhsSpec {
    /// Set `b = A*1`; for this matrix family every entry is the dominance margin.
    #[serde(rename = "manufactured-ones-v1")]
    ManufacturedOnesV1,
    #[serde(rename = "seeded-periodic-dyadic-v1")]
    SeededPeriodicDyadicV1 {
        period_bits: u8,
        fractional_bits: u8,
        #[serde(with = "decimal_i64")]
        minimum_mantissa: i64,
        #[serde(with = "decimal_i64")]
        maximum_mantissa: i64,
    },
}

/// Values that the validation layer must authenticate and report.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum RequestedOutput {
    #[serde(rename = "squared-l2-residual-v1")]
    SquaredL2ResidualV1,
}

/// Exact signed dyadic used by generated matrix and RHS entries.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Dyadic {
    mantissa: i64,
    fractional_bits: u8,
}

impl Dyadic {
    #[must_use]
    pub const fn new(mantissa: i64, fractional_bits: u8) -> Self {
        Self {
            mantissa,
            fractional_bits,
        }
    }

    #[must_use]
    pub const fn mantissa(self) -> i64 {
        self.mantissa
    }

    #[must_use]
    pub const fn fractional_bits(self) -> u8 {
        self.fractional_bits
    }

    /// Converts exactly to binary64 under the validated v1 magnitude and scale caps.
    #[must_use]
    pub fn to_f64(self) -> f64 {
        let biased_exponent = 1023_u64 - u64::from(self.fractional_bits);
        let exact_scale = f64::from_bits(biased_exponent << 52);
        (self.mantissa as f64) * exact_scale
    }
}

/// Seed-free or literal-seeded problem description fixed before a challenge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemTemplate {
    pub schema: TemplateSchema,
    pub randomness: TemplateRandomness,
    pub matrix: MatrixSpec,
    pub rhs: RhsSpec,
    pub requested_outputs: Vec<RequestedOutput>,
}

/// Complete, self-contained public problem statement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedProblem {
    pub schema: ProblemSchema,
    pub randomness: FinalizedRandomness,
    pub matrix: MatrixSpec,
    pub rhs: RhsSpec,
    pub requested_outputs: Vec<RequestedOutput>,
}

#[derive(Debug, Error)]
pub enum ProblemError {
    #[error("problem JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "matrix dimension {actual} lies outside the supported interval [{MIN_DIMENSION}, {MAX_DIMENSION}]"
    )]
    InvalidDimension { actual: u64 },
    #[error("period_bits {actual} exceeds the supported maximum {MAX_PERIOD_BITS}")]
    PeriodTooLarge { actual: u8 },
    #[error("fractional_bits {actual} exceeds the supported maximum {MAX_FRACTIONAL_BITS}")]
    FractionalBitsTooLarge { actual: u8 },
    #[error("off-diagonal magnitudes must satisfy 1 <= minimum <= maximum")]
    InvalidOffDiagonalRange,
    #[error("the strict diagonal-dominance margin must be positive")]
    ZeroDominanceMargin,
    #[error(
        "a generated coefficient mantissa can exceed the exact binary64 limit {MAX_EXACT_BINARY64_MANTISSA}"
    )]
    CoefficientTooLarge,
    #[error("seeded RHS minimum_mantissa must not exceed maximum_mantissa")]
    InvalidRhsRange,
    #[error("seeded RHS range is too wide for the frozen unbiased sampler")]
    RhsRangeTooWide,
    #[error(
        "a generated RHS mantissa can exceed the exact binary64 limit {MAX_EXACT_BINARY64_MANTISSA}"
    )]
    RhsMagnitudeTooLarge,
    #[error("integer overflow while validating {0}")]
    IntegerOverflow(&'static str),
    #[error("the v1 problem must request squared-l2-residual-v1 exactly once")]
    InvalidRequestedOutputs,
    #[error("too many requested outputs: {actual}; maximum is {MAX_REQUESTED_OUTPUTS}")]
    TooManyRequestedOutputs { actual: usize },
    #[error("literal-v1 finalization does not accept challenge-context bytes")]
    UnexpectedChallengeContext,
    #[error("this operation requires literal-v1 template randomness")]
    ExpectedLiteralRandomness,
    #[error("this operation requires challenge-derived-v1 randomness")]
    ExpectedChallengeDerivedRandomness,
    #[error("challenge context exceeds the {MAX_CHALLENGE_CONTEXT_BYTES}-byte limit")]
    ChallengeContextTooLarge,
    #[error("recorded template digest {recorded} does not match recomputed digest {recomputed}")]
    TemplateDigestMismatch {
        recorded: ProblemTemplateDigest,
        recomputed: ProblemTemplateDigest,
    },
    #[error("recorded challenge-context digest does not match the embedded canonical bytes")]
    ChallengeContextDigestMismatch,
    #[error("recorded challenge-derived seed does not match the recomputed seed")]
    DerivedSeedMismatch,
    #[error("the finalized challenge context does not match the expected challenge bytes")]
    UnexpectedFinalizedChallengeContext,
    #[error("could not allocate the bounded periodic generator table")]
    AllocationFailed,
}

impl ProblemTemplate {
    #[must_use]
    pub const fn dimension(&self) -> u64 {
        self.matrix.dimension()
    }

    pub fn from_json_slice(json: &[u8]) -> Result<Self, ProblemError> {
        let template: Self = serde_json::from_slice(json)?;
        template.validate()?;
        Ok(template)
    }

    pub fn to_pretty_json(&self) -> Result<String, ProblemError> {
        self.validate()?;
        Ok(format!("{}\n", serde_json::to_string_pretty(self)?))
    }

    pub fn validate(&self) -> Result<(), ProblemError> {
        validate_common(self.matrix, self.rhs, &self.requested_outputs)
    }

    pub fn digest(&self) -> Result<ProblemTemplateDigest, ProblemError> {
        ProblemTemplateDigest::for_template(self)
    }

    /// Finalizes according to the template policy. Literal templates require an
    /// empty context; challenge-derived templates embed and bind the supplied bytes.
    pub fn finalize(&self, challenge_context: &[u8]) -> Result<FinalizedProblem, ProblemError> {
        self.validate()?;
        let randomness = match self.randomness {
            TemplateRandomness::LiteralV1 { seed } => {
                if !challenge_context.is_empty() {
                    return Err(ProblemError::UnexpectedChallengeContext);
                }
                FinalizedRandomness::LiteralV1 { seed }
            }
            TemplateRandomness::ChallengeDerivedV1 { derivation } => {
                if challenge_context.len() > MAX_CHALLENGE_CONTEXT_BYTES {
                    return Err(ProblemError::ChallengeContextTooLarge);
                }
                let template_digest = self.digest()?;
                let seed = derive_instance_seed(template_digest, challenge_context);
                let canonical_bytes = CanonicalContextBytes::new(challenge_context.to_vec())
                    .map_err(|_| ProblemError::ChallengeContextTooLarge)?;
                FinalizedRandomness::ChallengeDerivedV1 {
                    derivation,
                    template_digest,
                    challenge_context: ChallengeContext::EmbeddedV1 { canonical_bytes },
                    challenge_context_digest: challenge_context_digest(challenge_context),
                    seed,
                }
            }
        };
        let problem = FinalizedProblem {
            schema: ProblemSchema::V1,
            randomness,
            matrix: self.matrix,
            rhs: self.rhs,
            requested_outputs: self.requested_outputs.clone(),
        };
        problem.validate()?;
        Ok(problem)
    }

    pub fn finalize_literal(&self) -> Result<FinalizedProblem, ProblemError> {
        if !matches!(self.randomness, TemplateRandomness::LiteralV1 { .. }) {
            return Err(ProblemError::ExpectedLiteralRandomness);
        }
        self.finalize(&[])
    }

    pub fn finalize_with_challenge_context(
        &self,
        challenge_context: &[u8],
    ) -> Result<FinalizedProblem, ProblemError> {
        if !matches!(
            self.randomness,
            TemplateRandomness::ChallengeDerivedV1 { .. }
        ) {
            return Err(ProblemError::ExpectedChallengeDerivedRandomness);
        }
        self.finalize(challenge_context)
    }
}

impl FinalizedProblem {
    #[must_use]
    pub const fn dimension(&self) -> u64 {
        self.matrix.dimension()
    }

    #[must_use]
    pub const fn randomness(&self) -> &FinalizedRandomness {
        &self.randomness
    }

    #[must_use]
    pub const fn instance_seed(&self) -> crate::InstanceSeed {
        self.randomness.instance_seed()
    }

    pub fn from_json_slice(json: &[u8]) -> Result<Self, ProblemError> {
        let problem: Self = serde_json::from_slice(json)?;
        problem.validate()?;
        Ok(problem)
    }

    pub fn to_pretty_json(&self) -> Result<String, ProblemError> {
        self.validate()?;
        Ok(format!("{}\n", serde_json::to_string_pretty(self)?))
    }

    /// Reconstructs the exact pre-finalization template whose digest is bound
    /// into a challenge-derived record.
    #[must_use]
    pub fn template(&self) -> ProblemTemplate {
        let randomness = match self.randomness {
            FinalizedRandomness::LiteralV1 { seed } => TemplateRandomness::LiteralV1 { seed },
            FinalizedRandomness::ChallengeDerivedV1 { derivation, .. } => {
                TemplateRandomness::ChallengeDerivedV1 { derivation }
            }
        };
        ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness,
            matrix: self.matrix,
            rhs: self.rhs,
            requested_outputs: self.requested_outputs.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), ProblemError> {
        validate_common(self.matrix, self.rhs, &self.requested_outputs)?;
        if let FinalizedRandomness::ChallengeDerivedV1 {
            template_digest,
            challenge_context,
            challenge_context_digest: recorded_context_digest,
            seed,
            ..
        } = &self.randomness
        {
            let recomputed_template_digest = self.template().digest()?;
            if *template_digest != recomputed_template_digest {
                return Err(ProblemError::TemplateDigestMismatch {
                    recorded: *template_digest,
                    recomputed: recomputed_template_digest,
                });
            }
            let context = challenge_context.canonical_bytes();
            if context.len() > MAX_CHALLENGE_CONTEXT_BYTES {
                return Err(ProblemError::ChallengeContextTooLarge);
            }
            if *recorded_context_digest != challenge_context_digest(context) {
                return Err(ProblemError::ChallengeContextDigestMismatch);
            }
            if *seed != derive_instance_seed(*template_digest, context) {
                return Err(ProblemError::DerivedSeedMismatch);
            }
        }
        Ok(())
    }

    /// Application-layer check used before accepting a service-issued context.
    pub fn verify_challenge_context(&self, expected: &[u8]) -> Result<(), ProblemError> {
        let Some(recorded) = self.randomness.challenge_context() else {
            return Err(ProblemError::ExpectedChallengeDerivedRandomness);
        };
        if recorded.canonical_bytes() != expected {
            return Err(ProblemError::UnexpectedFinalizedChallengeContext);
        }
        self.validate()
    }

    pub fn digest(&self) -> Result<ProblemDigest, ProblemError> {
        ProblemDigest::for_problem(self)
    }

    /// Compiles bounded periodic lookup tables without materializing dimension-sized data.
    pub fn compile(&self) -> Result<GeneratedProblem, ProblemError> {
        GeneratedProblem::compile(self)
    }
}

impl CanonicalEncode for TemplateSchema {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u16(1);
    }
}

impl CanonicalEncode for ProblemSchema {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u16(1);
    }
}

impl CanonicalEncode for BoundaryRule {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u16(1);
    }
}

impl CanonicalEncode for OffDiagonalValues {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::SeededPeriodicNegativeDyadicV1 {
                period_bits,
                fractional_bits,
                minimum_magnitude_mantissa,
                maximum_magnitude_mantissa,
            } => {
                encoder.write_u16(1);
                encoder.write_u8(*period_bits);
                encoder.write_u8(*fractional_bits);
                encoder.write_u64(*minimum_magnitude_mantissa);
                encoder.write_u64(*maximum_magnitude_mantissa);
            }
        }
    }
}

impl CanonicalEncode for DiagonalConstruction {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::AbsoluteRowSumPlusMarginV1 { margin_mantissa } => {
                encoder.write_u16(1);
                encoder.write_u64(*margin_mantissa);
            }
        }
    }
}

impl CanonicalEncode for MatrixSpec {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::SeededSymmetricTridiagonalV1 {
                dimension,
                boundary,
                off_diagonal,
                diagonal,
            } => {
                encoder.write_u16(1);
                encoder.write_u64(*dimension);
                boundary.encode(encoder);
                off_diagonal.encode(encoder);
                diagonal.encode(encoder);
            }
        }
    }
}

impl CanonicalEncode for RhsSpec {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::ManufacturedOnesV1 => encoder.write_u16(1),
            Self::SeededPeriodicDyadicV1 {
                period_bits,
                fractional_bits,
                minimum_mantissa,
                maximum_mantissa,
            } => {
                encoder.write_u16(2);
                encoder.write_u8(*period_bits);
                encoder.write_u8(*fractional_bits);
                encoder.write_i64(*minimum_mantissa);
                encoder.write_i64(*maximum_mantissa);
            }
        }
    }
}

impl CanonicalEncode for RequestedOutput {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u16(1);
    }
}

impl CanonicalEncode for ProblemTemplate {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema.encode(encoder);
        self.randomness.encode(encoder);
        self.matrix.encode(encoder);
        self.rhs.encode(encoder);
        encoder.write_u32(self.requested_outputs.len() as u32);
        for output in &self.requested_outputs {
            output.encode(encoder);
        }
    }
}

impl CanonicalEncode for FinalizedProblem {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema.encode(encoder);
        self.randomness.encode(encoder);
        self.matrix.encode(encoder);
        self.rhs.encode(encoder);
        encoder.write_u32(self.requested_outputs.len() as u32);
        for output in &self.requested_outputs {
            output.encode(encoder);
        }
    }
}

fn validate_common(
    matrix: MatrixSpec,
    rhs: RhsSpec,
    requested_outputs: &[RequestedOutput],
) -> Result<(), ProblemError> {
    if requested_outputs.len() > MAX_REQUESTED_OUTPUTS {
        return Err(ProblemError::TooManyRequestedOutputs {
            actual: requested_outputs.len(),
        });
    }
    if requested_outputs != [RequestedOutput::SquaredL2ResidualV1] {
        return Err(ProblemError::InvalidRequestedOutputs);
    }

    let (dimension, _boundary, off_diagonal, diagonal) = matrix.components();
    if !(MIN_DIMENSION..=MAX_DIMENSION).contains(&dimension) {
        return Err(ProblemError::InvalidDimension { actual: dimension });
    }
    let dimension = usize::try_from(dimension)
        .map_err(|_| ProblemError::IntegerOverflow("matrix dimension"))?;
    dimension
        .checked_mul(3)
        .and_then(|value| value.checked_sub(2))
        .ok_or(ProblemError::IntegerOverflow("structural nonzero count"))?;

    let (period_bits, fractional_bits, minimum_magnitude, maximum_magnitude) =
        off_diagonal.parameters();
    validate_period_and_scale(period_bits, fractional_bits)?;
    if minimum_magnitude == 0 || minimum_magnitude > maximum_magnitude {
        return Err(ProblemError::InvalidOffDiagonalRange);
    }
    let margin = diagonal.margin_mantissa();
    if margin == 0 {
        return Err(ProblemError::ZeroDominanceMargin);
    }
    let maximum_diagonal = maximum_magnitude
        .checked_mul(2)
        .and_then(|value| value.checked_add(margin))
        .ok_or(ProblemError::IntegerOverflow("maximum diagonal mantissa"))?;
    maximum_magnitude
        .checked_mul(4)
        .and_then(|value| value.checked_add(margin))
        .ok_or(ProblemError::IntegerOverflow(
            "maximum absolute row-sum mantissa",
        ))?;
    if maximum_diagonal > MAX_EXACT_BINARY64_MANTISSA {
        return Err(ProblemError::CoefficientTooLarge);
    }

    if let RhsSpec::SeededPeriodicDyadicV1 {
        period_bits,
        fractional_bits,
        minimum_mantissa,
        maximum_mantissa,
    } = rhs
    {
        validate_period_and_scale(period_bits, fractional_bits)?;
        if minimum_mantissa > maximum_mantissa {
            return Err(ProblemError::InvalidRhsRange);
        }
        let width = i128::from(maximum_mantissa) - i128::from(minimum_mantissa) + 1;
        if width > i128::from(u64::MAX) {
            return Err(ProblemError::RhsRangeTooWide);
        }
        if minimum_mantissa.unsigned_abs() > MAX_EXACT_BINARY64_MANTISSA
            || maximum_mantissa.unsigned_abs() > MAX_EXACT_BINARY64_MANTISSA
        {
            return Err(ProblemError::RhsMagnitudeTooLarge);
        }
    }
    Ok(())
}

fn validate_period_and_scale(period_bits: u8, fractional_bits: u8) -> Result<(), ProblemError> {
    if period_bits > MAX_PERIOD_BITS {
        return Err(ProblemError::PeriodTooLarge {
            actual: period_bits,
        });
    }
    if fractional_bits > MAX_FRACTIONAL_BITS {
        return Err(ProblemError::FractionalBitsTooLarge {
            actual: fractional_bits,
        });
    }
    1_usize
        .checked_shl(u32::from(period_bits))
        .ok_or(ProblemError::IntegerOverflow("period length"))?;
    Ok(())
}

mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if !is_canonical(&value) {
            return Err(de::Error::custom(
                "expected a canonical unsigned decimal string",
            ));
        }
        value.parse().map_err(de::Error::custom)
    }

    fn is_canonical(value: &str) -> bool {
        value == "0"
            || (value.as_bytes().first().is_some_and(u8::is_ascii_digit)
                && value.as_bytes()[0] != b'0'
                && value.bytes().all(|byte| byte.is_ascii_digit()))
    }
}

mod decimal_i64 {
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S>(value: &i64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<i64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if !is_canonical(&value) {
            return Err(de::Error::custom(
                "expected a canonical signed decimal string",
            ));
        }
        value.parse().map_err(de::Error::custom)
    }

    fn is_canonical(value: &str) -> bool {
        if value == "0" {
            return true;
        }
        let digits = value.strip_prefix('-').unwrap_or(value);
        !digits.is_empty()
            && digits.as_bytes()[0] != b'0'
            && digits.bytes().all(|byte| byte.is_ascii_digit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InstanceSeed, SeedDerivation};

    #[test]
    fn dyadic_scale_conversion_has_frozen_exact_bits() {
        assert_eq!(Dyadic::new(1, 0).to_f64().to_bits(), 0x3ff0_0000_0000_0000);
        assert_eq!(Dyadic::new(1, 52).to_f64().to_bits(), 0x3cb0_0000_0000_0000);
        assert_eq!(
            Dyadic::new(1, 255).to_f64().to_bits(),
            0x3000_0000_0000_0000
        );
        assert_eq!(Dyadic::new(-3, 1).to_f64(), -1.5);
    }

    fn matrix(dimension: u64) -> MatrixSpec {
        MatrixSpec::SeededSymmetricTridiagonalV1 {
            dimension,
            boundary: BoundaryRule::TruncateV1,
            off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                period_bits: 4,
                fractional_bits: 20,
                minimum_magnitude_mantissa: 3,
                maximum_magnitude_mantissa: 100,
            },
            diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 {
                margin_mantissa: 17,
            },
        }
    }

    fn template() -> ProblemTemplate {
        ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness: TemplateRandomness::LiteralV1 {
                seed: InstanceSeed::from_bytes([0x5a; 32]),
            },
            matrix: matrix(1_000),
            rhs: RhsSpec::ManufacturedOnesV1,
            requested_outputs: vec![RequestedOutput::SquaredL2ResidualV1],
        }
    }

    #[test]
    fn strict_json_round_trips_both_document_kinds() {
        let template = template();
        let json = template.to_pretty_json().unwrap();
        assert!(json.ends_with('\n'));
        assert_eq!(
            ProblemTemplate::from_json_slice(json.as_bytes()).unwrap(),
            template
        );
        assert!(json.contains("\"minimum_magnitude_mantissa\": \"3\""));

        let finalized = template.finalize_literal().unwrap();
        let json = finalized.to_pretty_json().unwrap();
        assert_eq!(
            FinalizedProblem::from_json_slice(json.as_bytes()).unwrap(),
            finalized
        );
    }

    #[test]
    fn json_rejects_unknown_fields_non_string_mantissas_and_noncanonical_seed() {
        let canonical = template().to_pretty_json().unwrap();
        let unknown = canonical.replacen(
            "\"schema\": \"sparse-solve/problem-template/v1\",",
            "\"schema\": \"sparse-solve/problem-template/v1\",\n  \"extra\": 1,",
            1,
        );
        assert!(ProblemTemplate::from_json_slice(unknown.as_bytes()).is_err());

        let numeric = canonical.replacen(
            "\"minimum_magnitude_mantissa\": \"3\"",
            "\"minimum_magnitude_mantissa\": 3",
            1,
        );
        assert!(ProblemTemplate::from_json_slice(numeric.as_bytes()).is_err());

        let uppercase = canonical.replace(&"5a".repeat(32), &"5A".repeat(32));
        assert!(ProblemTemplate::from_json_slice(uppercase.as_bytes()).is_err());
    }

    #[test]
    fn canonical_digests_bind_parameters_seed_and_context() {
        let original = template();
        let mut changed_dimension = original.clone();
        changed_dimension.matrix = matrix(1_001);
        assert_ne!(
            original.digest().unwrap(),
            changed_dimension.digest().unwrap()
        );

        let mut changed_rhs = original.clone();
        changed_rhs.rhs = RhsSpec::SeededPeriodicDyadicV1 {
            period_bits: 2,
            fractional_bits: 8,
            minimum_mantissa: -4,
            maximum_mantissa: 7,
        };
        assert_ne!(original.digest().unwrap(), changed_rhs.digest().unwrap());

        let mut derived = original;
        derived.randomness = TemplateRandomness::ChallengeDerivedV1 {
            derivation: SeedDerivation::Blake3XofV1,
        };
        let first = derived.finalize_with_challenge_context(b"first").unwrap();
        let second = derived.finalize_with_challenge_context(b"second").unwrap();
        assert_ne!(first.instance_seed(), second.instance_seed());
        assert_ne!(first.digest().unwrap(), second.digest().unwrap());
    }

    #[test]
    fn validation_enforces_resource_and_arithmetic_caps() {
        let mut value = template();
        value.matrix = matrix(1);
        assert!(matches!(
            value.validate(),
            Err(ProblemError::InvalidDimension { actual: 1 })
        ));

        value.matrix = MatrixSpec::SeededSymmetricTridiagonalV1 {
            dimension: 10,
            boundary: BoundaryRule::TruncateV1,
            off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                period_bits: MAX_PERIOD_BITS + 1,
                fractional_bits: 8,
                minimum_magnitude_mantissa: 1,
                maximum_magnitude_mantissa: 2,
            },
            diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 { margin_mantissa: 1 },
        };
        assert!(matches!(
            value.validate(),
            Err(ProblemError::PeriodTooLarge { .. })
        ));

        value.matrix = MatrixSpec::SeededSymmetricTridiagonalV1 {
            dimension: 10,
            boundary: BoundaryRule::TruncateV1,
            off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                period_bits: 1,
                fractional_bits: 8,
                minimum_magnitude_mantissa: 1,
                maximum_magnitude_mantissa: MAX_EXACT_BINARY64_MANTISSA,
            },
            diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 { margin_mantissa: 1 },
        };
        assert!(matches!(
            value.validate(),
            Err(ProblemError::CoefficientTooLarge)
        ));
    }
}
