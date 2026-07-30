//! Frozen binary64 source, transcript, and arithmetic canonicalization rules.
//!
//! Provenance: refactored from `fast-validation/src/float.rs` at research
//! revision `be8b67b74da54d162df2e6e0a9d813779959bb60`. Sumcheck and the
//! unit-circle code use this module as the single owner of the policy instead
//! of maintaining subtly different local predicates.

use thiserror::Error;

const NEGATIVE_ZERO_BITS: u64 = 1_u64 << 63;

/// A violation of the fast path's canonical binary64 contract.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FloatContractError {
    /// NaNs and infinities have no valid source or transcript representation.
    #[error("binary64 value is NaN or infinite")]
    NonFinite,
    /// A serialized zero must use the all-zero positive-zero representation.
    #[error("binary64 value is negative zero")]
    NegativeZero,
    /// Source and transcript values may not be subnormal.
    #[error("binary64 subnormals are outside the fast-policy floating-point contract")]
    Subnormal,
    /// An internal operation overflowed or otherwise produced a non-finite value.
    #[error("binary64 arithmetic produced a non-finite value")]
    NonFiniteArithmetic,
}

/// Canonicalizes a source value before numerical processing.
///
/// Both arithmetic zero signs map to positive zero. Non-finite and subnormal
/// inputs are rejected. This is the source boundary; use
/// [`decode_canonical_bits`] for transcript bytes, where negative zero must be
/// rejected rather than normalized.
pub fn canonicalize_source(value: f64) -> Result<f64, FloatContractError> {
    if !value.is_finite() {
        return Err(FloatContractError::NonFinite);
    }
    if value == 0.0 {
        return Ok(0.0);
    }
    if value.is_subnormal() {
        return Err(FloatContractError::Subnormal);
    }
    Ok(value)
}

/// Returns the one accepted bit representation of a source value.
pub fn canonical_bits(value: f64) -> Result<u64, FloatContractError> {
    Ok(canonicalize_source(value)?.to_bits())
}

/// Decodes a transcript value and enforces its unique representation.
pub fn decode_canonical_bits(bits: u64) -> Result<f64, FloatContractError> {
    if bits == NEGATIVE_ZERO_BITS {
        return Err(FloatContractError::NegativeZero);
    }
    canonicalize_source(f64::from_bits(bits))
}

/// Checks that an already-decoded transcript value is canonical.
///
/// Unlike [`canonicalize_source`], this rejects negative zero. It is useful at
/// typed proof boundaries that have already decoded a binary64 value.
pub fn validate_canonical(value: f64) -> Result<(), FloatContractError> {
    if value.to_bits() == NEGATIVE_ZERO_BITS {
        return Err(FloatContractError::NegativeZero);
    }
    canonicalize_source(value).map(|_| ())
}

/// Canonicalizes a floating-point result produced by protocol arithmetic.
///
/// Arithmetic underflow is flushed to positive zero. This explicit policy
/// prevents transcript bytes from depending on host FTZ/DAZ configuration.
/// Inputs are expected to have been validated before entering hot loops.
pub fn canonicalize_arithmetic(value: f64) -> Result<f64, FloatContractError> {
    if !value.is_finite() {
        return Err(FloatContractError::NonFiniteArithmetic);
    }
    if value == 0.0 || value.is_subnormal() {
        Ok(0.0)
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_normalizes_both_arithmetic_zero_signs() {
        assert_eq!(canonicalize_source(-0.0).unwrap().to_bits(), 0);
        assert_eq!(canonical_bits(-0.0).unwrap(), 0);
    }

    #[test]
    fn transcript_rejects_noncanonical_encodings() {
        assert_eq!(
            decode_canonical_bits(NEGATIVE_ZERO_BITS),
            Err(FloatContractError::NegativeZero)
        );
        assert_eq!(
            decode_canonical_bits(f64::NAN.to_bits()),
            Err(FloatContractError::NonFinite)
        );
        assert_eq!(
            decode_canonical_bits(f64::INFINITY.to_bits()),
            Err(FloatContractError::NonFinite)
        );
        assert_eq!(decode_canonical_bits(1), Err(FloatContractError::Subnormal));
    }

    #[test]
    fn arithmetic_flushes_underflow_but_rejects_overflow() {
        assert_eq!(canonicalize_arithmetic(f64::from_bits(1)), Ok(0.0));
        assert_eq!(canonicalize_arithmetic(-0.0).unwrap().to_bits(), 0);
        assert_eq!(
            canonicalize_arithmetic(f64::INFINITY),
            Err(FloatContractError::NonFiniteArithmetic)
        );
    }
}
