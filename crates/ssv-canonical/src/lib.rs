//! Canonical byte encoding and digest primitives for sparse-solution artifacts.
//!
//! The wire format deliberately has a small vocabulary. Integers are fixed-width
//! and big-endian, digests are fixed-width, and variable-width byte strings carry
//! a `u64` byte length. Decoding always requires explicit resource limits.

#![forbid(unsafe_code)]

mod digest;
mod encoding;

pub use digest::{Digest, ParseDigestError, canonical_digest, domain_separated_digest};
pub use encoding::{CanonicalEncode, DecodeError, DecodeLimits, Encoder, Reader, encode_to_vec};
