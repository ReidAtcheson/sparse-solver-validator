//! Coefficient-aligned rate-one-half unit-circle code.
//!
//! The input is a Boolean-hypercube evaluation table. For `N = 2^m`, source
//! entry `i` becomes coefficient `bit_reverse(i, m)`. That bit reversal makes
//! the sumcheck's MSB-coordinate-first table fold coincide with an even/odd
//! coefficient fold. This module is not a soundness theorem by itself; it is a
//! reusable oracle/fold primitive for an enclosing sampled metric protocol.
//!
//! Provenance: refactored from `fast-validation/src/unit_circle.rs` at research
//! revision `be8b67b74da54d162df2e6e0a9d813779959bb60`, preserving FFT signs,
//! arithmetic order, padding, and fold equations.

use std::f64::consts::PI;

use thiserror::Error;

use crate::float_contract::{
    FloatContractError, canonicalize_arithmetic, canonicalize_source, decode_canonical_bits,
};

const NEGATIVE_ZERO_BITS: u64 = 1_u64 << 63;

/// A canonical pair of binary64 components.
///
/// Fields are private so callers cannot bypass source and transcript checks.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ComplexValue {
    real: f64,
    imaginary: f64,
}

impl ComplexValue {
    /// Constructs a source value, normalizing either zero sign to positive zero.
    pub fn new(real: f64, imaginary: f64) -> Result<Self, UnitCircleError> {
        Ok(Self {
            real: canonical_input_component(real)?,
            imaginary: canonical_input_component(imaginary)?,
        })
    }

    pub fn from_real(value: f64) -> Result<Self, UnitCircleError> {
        Self::new(value, 0.0)
    }

    /// Decodes transcript components, rejecting noncanonical negative zero.
    pub fn from_canonical_bits(
        real_bits: u64,
        imaginary_bits: u64,
    ) -> Result<Self, UnitCircleError> {
        // Preserve malformed-input error precedence from the frozen v2
        // decoder: either negative-zero component rejects the pair before
        // interpreting the other component.
        if real_bits == NEGATIVE_ZERO_BITS || imaginary_bits == NEGATIVE_ZERO_BITS {
            return Err(UnitCircleError::NegativeZeroEncoding);
        }
        Ok(Self {
            real: decode_component(real_bits)?,
            imaginary: decode_component(imaginary_bits)?,
        })
    }

    pub const fn real(self) -> f64 {
        self.real
    }

    pub const fn imaginary(self) -> f64 {
        self.imaginary
    }

    pub const fn canonical_bits(self) -> [u64; 2] {
        [self.real.to_bits(), self.imaginary.to_bits()]
    }

    pub fn magnitude(self) -> f64 {
        self.real.hypot(self.imaginary)
    }

    fn from_arithmetic(real: f64, imaginary: f64) -> Result<Self, UnitCircleError> {
        Ok(Self {
            real: canonical_arithmetic_component(real)?,
            imaginary: canonical_arithmetic_component(imaginary)?,
        })
    }

    fn add(self, rhs: Self) -> Result<Self, UnitCircleError> {
        Self::from_arithmetic(self.real + rhs.real, self.imaginary + rhs.imaginary)
    }

    fn subtract(self, rhs: Self) -> Result<Self, UnitCircleError> {
        Self::from_arithmetic(self.real - rhs.real, self.imaginary - rhs.imaginary)
    }

    fn multiply(self, rhs: Self) -> Result<Self, UnitCircleError> {
        Self::from_arithmetic(
            self.real * rhs.real - self.imaginary * rhs.imaginary,
            self.real * rhs.imaginary + self.imaginary * rhs.real,
        )
    }

    fn scale(self, scalar: f64) -> Result<Self, UnitCircleError> {
        let scalar = canonical_input_component(scalar)?;
        Self::from_arithmetic(self.real * scalar, self.imaginary * scalar)
    }

    const fn conjugate(self) -> Self {
        Self {
            real: self.real,
            imaginary: if self.imaginary == 0.0 {
                0.0
            } else {
                -self.imaginary
            },
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum UnitCircleError {
    #[error("unit-circle source must not be empty")]
    EmptySource,
    #[error("unit-circle binary64 component is NaN or infinite")]
    NonFiniteComponent,
    #[error("unit-circle binary64 source component is subnormal")]
    SubnormalComponent,
    #[error("unit-circle transcript component encodes negative zero")]
    NegativeZeroEncoding,
    #[error("unit-circle code dimensions overflow usize")]
    SizeOverflow,
    #[error("unit-circle codeword shape is invalid")]
    InvalidCodewordShape,
    #[error("a one-coefficient unit-circle codeword cannot be folded further")]
    AlreadyConstant,
    #[error("unit-circle arithmetic produced a non-finite value")]
    NonFiniteArithmetic,
}

/// One rate-one-half evaluation codeword.
///
/// `evaluations[k]` is the polynomial value at
/// `exp(-2 pi i k / evaluation_len)`. Entries `k` and
/// `k + evaluation_len/2` are therefore evaluations at `z` and `-z`.
#[derive(Clone, Debug, PartialEq)]
pub struct UnitCircleCodeword {
    logical_len: usize,
    message_len: usize,
    evaluations: Vec<ComplexValue>,
}

impl UnitCircleCodeword {
    /// Encodes real source values after zero-padding to a power of two.
    pub fn encode(source: &[f64]) -> Result<Self, UnitCircleError> {
        if source.is_empty() {
            return Err(UnitCircleError::EmptySource);
        }
        let message_len = source
            .len()
            .checked_next_power_of_two()
            .ok_or(UnitCircleError::SizeOverflow)?;
        let evaluation_len = message_len
            .checked_mul(2)
            .ok_or(UnitCircleError::SizeOverflow)?;
        let variables = message_len.trailing_zeros();
        let mut evaluations = vec![ComplexValue::default(); evaluation_len];
        for (source_index, &value) in source.iter().enumerate() {
            evaluations[bit_reverse(source_index, variables)] = ComplexValue::from_real(value)?;
        }
        fft_in_place(&mut evaluations)?;
        let result = Self {
            logical_len: source.len(),
            message_len,
            evaluations,
        };
        result.validate_shape()?;
        Ok(result)
    }

    pub const fn logical_len(&self) -> usize {
        self.logical_len
    }

    /// Power-of-two coefficient count after padding.
    pub const fn message_len(&self) -> usize {
        self.message_len
    }

    pub fn evaluations(&self) -> &[ComplexValue] {
        &self.evaluations
    }

    pub fn evaluation(&self, index: usize) -> Option<ComplexValue> {
        self.evaluations.get(index).copied()
    }

    /// Folds one MSB-first MLE coordinate using paired oracle values.
    ///
    /// The returned codeword remains rate one half and does not materialize a
    /// folded source vector. It allocates exactly the child evaluation vector.
    pub fn fold(&self, challenge: f64) -> Result<Self, UnitCircleError> {
        self.validate_shape()?;
        let challenge = canonical_input_component(challenge)?;
        if self.message_len == 1 {
            return Err(UnitCircleError::AlreadyConstant);
        }

        let next_message_len = self.message_len / 2;
        let next_evaluation_len = self.message_len;
        let complement = canonical_arithmetic_component(1.0 - challenge)?;
        let mut evaluations = Vec::with_capacity(next_evaluation_len);

        for index in 0..next_evaluation_len {
            let at_z = self.evaluations[index];
            let at_negative_z = self.evaluations[index + next_evaluation_len];
            evaluations.push(fold_pair_with_complement(
                at_z,
                at_negative_z,
                index,
                self.evaluations.len(),
                challenge,
                complement,
            )?);
        }

        let result = Self {
            logical_len: next_message_len,
            message_len: next_message_len,
            evaluations,
        };
        result.validate_shape()?;
        Ok(result)
    }

    fn validate_shape(&self) -> Result<(), UnitCircleError> {
        let expected = self
            .message_len
            .checked_mul(2)
            .ok_or(UnitCircleError::SizeOverflow)?;
        if self.logical_len == 0
            || self.logical_len > self.message_len
            || !self.message_len.is_power_of_two()
            || self.evaluations.len() != expected
        {
            return Err(UnitCircleError::InvalidCodewordShape);
        }
        Ok(())
    }
}

/// Computes one allocation-free verifier-side even/odd fold relation.
pub fn fold_pair_at_index(
    at_z: ComplexValue,
    at_negative_z: ComplexValue,
    index: usize,
    domain_len: usize,
    challenge: f64,
) -> Result<ComplexValue, UnitCircleError> {
    if domain_len < 4 || !domain_len.is_power_of_two() || index >= domain_len / 2 {
        return Err(UnitCircleError::InvalidCodewordShape);
    }
    let challenge = canonical_input_component(challenge)?;
    let complement = canonical_arithmetic_component(1.0 - challenge)?;
    fold_pair_with_complement(
        at_z,
        at_negative_z,
        index,
        domain_len,
        challenge,
        complement,
    )
}

fn fold_pair_with_complement(
    at_z: ComplexValue,
    at_negative_z: ComplexValue,
    index: usize,
    domain_len: usize,
    challenge: f64,
    complement: f64,
) -> Result<ComplexValue, UnitCircleError> {
    let even = at_z.add(at_negative_z)?.scale(0.5)?;

    // O(z^2) = (p(z) - p(-z)) * conjugate(z) / 2 because |z|=1.
    let z_inverse = evaluation_point(index, domain_len)?.conjugate();
    let odd = at_z
        .subtract(at_negative_z)?
        .multiply(z_inverse)?
        .scale(0.5)?;

    even.scale(complement)?.add(odd.scale(challenge)?)
}

/// Returns the padded source in the code's univariate coefficient order.
///
/// This audit helper allocates the padded coefficient vector. Recursive
/// validators should query committed evaluations rather than call it.
pub fn bit_reversed_source_coefficients(
    source: &[f64],
) -> Result<Vec<ComplexValue>, UnitCircleError> {
    if source.is_empty() {
        return Err(UnitCircleError::EmptySource);
    }
    let source = source
        .iter()
        .copied()
        .map(ComplexValue::from_real)
        .collect::<Result<Vec<_>, _>>()?;
    padded_bit_reversal(&source)
}

#[cfg(test)]
fn encode_complex(
    source: &[ComplexValue],
    logical_len: usize,
) -> Result<UnitCircleCodeword, UnitCircleError> {
    if source.is_empty() || logical_len == 0 || logical_len > source.len() {
        return Err(UnitCircleError::EmptySource);
    }
    let message_len = source
        .len()
        .checked_next_power_of_two()
        .ok_or(UnitCircleError::SizeOverflow)?;
    let evaluation_len = message_len
        .checked_mul(2)
        .ok_or(UnitCircleError::SizeOverflow)?;
    let variables = message_len.trailing_zeros();
    let mut evaluations = vec![ComplexValue::default(); evaluation_len];
    for (source_index, &value) in source.iter().enumerate() {
        evaluations[bit_reverse(source_index, variables)] = value;
    }
    fft_in_place(&mut evaluations)?;

    let codeword = UnitCircleCodeword {
        logical_len,
        message_len,
        evaluations,
    };
    codeword.validate_shape()?;
    Ok(codeword)
}

fn padded_bit_reversal(source: &[ComplexValue]) -> Result<Vec<ComplexValue>, UnitCircleError> {
    let message_len = source
        .len()
        .checked_next_power_of_two()
        .ok_or(UnitCircleError::SizeOverflow)?;
    let variables = message_len.trailing_zeros();
    let mut coefficients = vec![ComplexValue::default(); message_len];
    for (source_index, &value) in source.iter().enumerate() {
        coefficients[bit_reverse(source_index, variables)] = value;
    }
    Ok(coefficients)
}

fn bit_reverse(index: usize, variables: u32) -> usize {
    if variables == 0 {
        0
    } else {
        index.reverse_bits() >> (usize::BITS - variables)
    }
}

fn evaluation_point(index: usize, domain_len: usize) -> Result<ComplexValue, UnitCircleError> {
    if domain_len == 0 || !domain_len.is_power_of_two() || index >= domain_len {
        return Err(UnitCircleError::InvalidCodewordShape);
    }
    let angle = -2.0 * PI * index as f64 / domain_len as f64;
    let (sin, cos) = angle.sin_cos();
    ComplexValue::from_arithmetic(cos, sin)
}

/// Forward radix-two FFT with roots `exp(-2 pi i k / n)` in natural order.
fn fft_in_place(values: &mut [ComplexValue]) -> Result<(), UnitCircleError> {
    let len = values.len();
    if len == 0 || !len.is_power_of_two() {
        return Err(UnitCircleError::InvalidCodewordShape);
    }

    let variables = len.trailing_zeros();
    for index in 0..len {
        let reversed = bit_reverse(index, variables);
        if index < reversed {
            values.swap(index, reversed);
        }
    }

    for stage in 1..=variables {
        let block_len = 1_usize << stage;
        let half = block_len / 2;
        for block_start in (0..len).step_by(block_len) {
            for offset in 0..half {
                let twiddle = evaluation_point(offset, block_len)?;
                let even = values[block_start + offset];
                let odd = values[block_start + offset + half].multiply(twiddle)?;
                values[block_start + offset] = even.add(odd)?;
                values[block_start + offset + half] = even.subtract(odd)?;
            }
        }
    }
    Ok(())
}

fn canonical_input_component(value: f64) -> Result<f64, UnitCircleError> {
    canonicalize_source(value).map_err(map_source_error)
}

fn decode_component(bits: u64) -> Result<f64, UnitCircleError> {
    decode_canonical_bits(bits).map_err(map_source_error)
}

fn canonical_arithmetic_component(value: f64) -> Result<f64, UnitCircleError> {
    canonicalize_arithmetic(value).map_err(|_| UnitCircleError::NonFiniteArithmetic)
}

fn map_source_error(error: FloatContractError) -> UnitCircleError {
    match error {
        FloatContractError::NonFinite => UnitCircleError::NonFiniteComponent,
        FloatContractError::NegativeZero => UnitCircleError::NegativeZeroEncoding,
        FloatContractError::Subnormal => UnitCircleError::SubnormalComponent,
        FloatContractError::NonFiniteArithmetic => UnitCircleError::NonFiniteArithmetic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_close(actual: ComplexValue, expected: ComplexValue, scale: f64) {
        let tolerance = 4096.0 * f64::EPSILON * scale.max(1.0);
        let difference = actual.subtract(expected).unwrap().magnitude();
        assert!(
            difference <= tolerance,
            "actual=({:.17e},{:.17e}) expected=({:.17e},{:.17e}) difference={difference:.3e} tolerance={tolerance:.3e}",
            actual.real(),
            actual.imaginary(),
            expected.real(),
            expected.imaginary(),
        );
    }

    fn direct_mle_fold(source: &[ComplexValue], challenge: f64) -> Vec<ComplexValue> {
        assert!(source.len() >= 2 && source.len().is_power_of_two());
        let half = source.len() / 2;
        (0..half)
            .map(|index| {
                source[index]
                    .scale(1.0 - challenge)
                    .unwrap()
                    .add(source[index + half].scale(challenge).unwrap())
                    .unwrap()
            })
            .collect()
    }

    fn pad_real(source: &[f64]) -> Vec<ComplexValue> {
        let len = source.len().next_power_of_two();
        let mut padded = vec![ComplexValue::default(); len];
        for (slot, &value) in padded.iter_mut().zip(source) {
            *slot = ComplexValue::from_real(value).unwrap();
        }
        padded
    }

    fn direct_polynomial_evaluation(
        coefficients: &[ComplexValue],
        point: ComplexValue,
    ) -> ComplexValue {
        coefficients
            .iter()
            .rev()
            .fold(ComplexValue::default(), |accumulator, &coefficient| {
                accumulator
                    .multiply(point)
                    .unwrap()
                    .add(coefficient)
                    .unwrap()
            })
    }

    #[test]
    fn complex_values_have_one_canonical_encoding() {
        let value = ComplexValue::new(-0.0, 2.0).unwrap();
        assert_eq!(value.canonical_bits(), [0, 2.0_f64.to_bits()]);
        assert_eq!(
            ComplexValue::from_canonical_bits((-0.0_f64).to_bits(), 0),
            Err(UnitCircleError::NegativeZeroEncoding)
        );
        assert_eq!(
            ComplexValue::new(f64::INFINITY, 0.0),
            Err(UnitCircleError::NonFiniteComponent)
        );
        assert_eq!(
            ComplexValue::new(f64::from_bits(1), 0.0),
            Err(UnitCircleError::SubnormalComponent)
        );
    }

    #[test]
    fn source_coefficients_are_bit_reversed_after_padding() {
        let source = (0..8).map(f64::from).collect::<Vec<_>>();
        let coefficients = bit_reversed_source_coefficients(&source).unwrap();
        let actual = coefficients
            .iter()
            .map(|value| value.real() as u64)
            .collect::<Vec<_>>();
        assert_eq!(actual, [0, 4, 2, 6, 1, 5, 3, 7]);

        let padded = bit_reversed_source_coefficients(&[1.0, 2.0, 3.0]).unwrap();
        assert_eq!(
            padded.iter().map(|value| value.real()).collect::<Vec<_>>(),
            [1.0, 3.0, 2.0, 0.0]
        );
    }

    #[test]
    fn rate_half_fft_matches_direct_polynomial_evaluation() {
        let source = [1.0, -2.0, 0.5, 4.0];
        let coefficients = bit_reversed_source_coefficients(&source).unwrap();
        let codeword = UnitCircleCodeword::encode(&source).unwrap();
        assert_eq!(codeword.message_len(), 4);
        assert_eq!(codeword.evaluations().len(), 8);

        let scale = source.iter().map(|value| value.abs()).sum::<f64>();
        for (index, &actual) in codeword.evaluations().iter().enumerate() {
            let point = evaluation_point(index, codeword.evaluations().len()).unwrap();
            let expected = direct_polynomial_evaluation(&coefficients, point);
            assert_close(actual, expected, scale);
        }
    }

    #[test]
    fn paired_fold_matches_one_direct_mle_fold() {
        let source = [0.5, -1.25, 2.0, 0.75, -0.5, 3.0, 1.5, -2.0];
        let challenge = 0.375;
        let codeword = UnitCircleCodeword::encode(&source).unwrap();
        let folded_codeword = codeword.fold(challenge).unwrap();

        let expected_source = direct_mle_fold(&pad_real(&source), challenge);
        let expected_codeword = encode_complex(&expected_source, expected_source.len()).unwrap();
        let scale = source.iter().map(|value| value.abs()).sum::<f64>();
        assert_eq!(folded_codeword.message_len(), expected_source.len());
        for (&actual, &expected) in folded_codeword
            .evaluations()
            .iter()
            .zip(expected_codeword.evaluations())
        {
            assert_close(actual, expected, scale);
        }

        for (index, &actual) in folded_codeword.evaluations().iter().enumerate() {
            let expected = fold_pair_at_index(
                codeword.evaluations()[index],
                codeword.evaluations()[index + codeword.message_len()],
                index,
                codeword.evaluations().len(),
                challenge,
            )
            .unwrap();
            assert_eq!(actual.canonical_bits(), expected.canonical_bits());
        }
    }

    #[test]
    fn repeated_folds_match_direct_mle_for_padded_source() {
        let source = [1.0, -0.25, 3.5, 2.0, -4.0, 0.75];
        let challenges = [0.3125, 0.625, 0.4375];
        let mut direct = pad_real(&source);
        let mut codeword = UnitCircleCodeword::encode(&source).unwrap();
        let scale = source.iter().map(|value| value.abs()).sum::<f64>();

        for challenge in challenges {
            direct = direct_mle_fold(&direct, challenge);
            codeword = codeword.fold(challenge).unwrap();
            let expected = encode_complex(&direct, direct.len()).unwrap();
            assert_eq!(codeword.message_len(), direct.len());
            for (&actual, &expected) in codeword.evaluations().iter().zip(expected.evaluations()) {
                assert_close(actual, expected, scale);
            }
        }

        assert_eq!(direct.len(), 1);
        assert_eq!(codeword.message_len(), 1);
        assert_close(codeword.evaluations()[0], direct[0], scale);
        assert_close(codeword.evaluations()[1], direct[0], scale);
        assert_eq!(codeword.fold(0.5), Err(UnitCircleError::AlreadyConstant));
    }
}
