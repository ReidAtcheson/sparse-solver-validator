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

/// Hashes a canonical binary64 vector with its semantic label and length.
pub fn vector_digest(label: &[u8], values: &[f64]) -> Result<[u8; 32], FloatContractError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sparse-solution/fast-validation/source-vector/v1\0");
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(values.len() as u64).to_le_bytes());
    for &value in values {
        hasher.update(&canonical_bits(value)?.to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Hashes an exact signed-integer source vector without dropping low bits.
pub fn i128_vector_digest(label: &[u8], values: &[i128]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sparse-solution/fast-validation/i128-source-vector/v1\0");
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(values.len() as u64).to_le_bytes());
    for &value in values {
        hasher.update(&value.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
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

    #[test]
    fn vector_digest_binds_label_length_order_and_bits() {
        let baseline = vector_digest(b"x", &[1.0, 2.0]).unwrap();
        assert_ne!(baseline, vector_digest(b"r", &[1.0, 2.0]).unwrap());
        assert_ne!(baseline, vector_digest(b"x", &[2.0, 1.0]).unwrap());
        assert_ne!(baseline, vector_digest(b"x", &[1.0]).unwrap());
        assert_eq!(
            vector_digest(b"x", &[0.0]).unwrap(),
            vector_digest(b"x", &[-0.0]).unwrap()
        );
    }

    #[test]
    fn integer_vector_digest_preserves_low_witness_bits() {
        let baseline = i128_vector_digest(b"x", &[1_i128 << 64]);
        assert_ne!(baseline, i128_vector_digest(b"x", &[(1_i128 << 64) + 1]));
    }
}
