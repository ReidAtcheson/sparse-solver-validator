use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{CanonicalEncode, encode_to_vec};

const DIGEST_LENGTH: usize = 32;
const HEX_LENGTH: usize = DIGEST_LENGTH * 2;
const HASH_FORMAT_DOMAIN: &[u8] = b"ssv.domain-separated-digest.v1";

/// A 256-bit digest.
///
/// Human-readable representations are exactly 64 lowercase hexadecimal
/// characters. The byte representation is kept private so callers cannot
/// accidentally confuse it with a variable-length byte string on the wire.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; DIGEST_LENGTH]);

impl Digest {
    /// The digest width in bytes.
    pub const LENGTH: usize = DIGEST_LENGTH;

    /// Constructs a digest from its exact byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DIGEST_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the digest's exact byte representation by reference.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LENGTH] {
        &self.0
    }

    /// Returns the digest's exact byte representation.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; DIGEST_LENGTH] {
        self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        for byte in self.0 {
            formatter.write_str(
                std::str::from_utf8(&[HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
                    .map_err(|_| fmt::Error)?,
            )?;
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Digest({self})")
    }
}

/// An error returned when parsing a canonical hexadecimal [`Digest`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParseDigestError {
    /// The text did not contain exactly 64 bytes.
    #[error(
        "digest must contain exactly {expected} lowercase hexadecimal characters, got {actual}"
    )]
    InvalidLength {
        /// The required number of hexadecimal characters.
        expected: usize,
        /// The observed string length in bytes.
        actual: usize,
    },

    /// A byte was not a lowercase hexadecimal digit.
    #[error("digest contains a non-canonical hexadecimal byte 0x{byte:02x} at offset {offset}")]
    InvalidHexByte {
        /// The byte offset within the input string.
        offset: usize,
        /// The rejected byte.
        byte: u8,
    },
}

impl FromStr for Digest {
    type Err = ParseDigestError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.len() != HEX_LENGTH {
            return Err(ParseDigestError::InvalidLength {
                expected: HEX_LENGTH,
                actual: text.len(),
            });
        }

        let mut bytes = [0_u8; DIGEST_LENGTH];
        for (output, (pair_index, pair)) in bytes
            .iter_mut()
            .zip(text.as_bytes().chunks_exact(2).enumerate())
        {
            let high_offset = pair_index * 2;
            let high = decode_nibble(pair[0]).ok_or(ParseDigestError::InvalidHexByte {
                offset: high_offset,
                byte: pair[0],
            })?;
            let low = decode_nibble(pair[1]).ok_or(ParseDigestError::InvalidHexByte {
                offset: high_offset + 1,
                byte: pair[1],
            })?;
            *output = (high << 4) | low;
        }

        Ok(Self(bytes))
    }
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

struct DigestVisitor;

impl Visitor<'_> for DigestVisitor {
    type Value = Digest;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("exactly 64 lowercase hexadecimal characters")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        value.parse().map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DigestVisitor)
    }
}

impl From<[u8; DIGEST_LENGTH]> for Digest {
    fn from(bytes: [u8; DIGEST_LENGTH]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<Digest> for [u8; DIGEST_LENGTH] {
    fn from(digest: Digest) -> Self {
        digest.into_bytes()
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Hashes a payload under an explicitly framed domain.
///
/// The format is `format-domain || u64(domain length) || domain ||
/// u64(payload length) || payload`, with both lengths encoded big-endian. This
/// framing makes domain and payload boundaries unambiguous. Callers should use
/// stable, protocol-specific domain labels.
#[must_use]
pub fn domain_separated_digest(domain: &[u8], payload: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HASH_FORMAT_DOMAIN);
    hasher.update(&wire_length(domain.len()).to_be_bytes());
    hasher.update(domain);
    hasher.update(&wire_length(payload.len()).to_be_bytes());
    hasher.update(payload);
    Digest::from_bytes(*hasher.finalize().as_bytes())
}

/// Canonically encodes and hashes a value under an explicitly framed domain.
#[must_use]
pub fn canonical_digest<T>(domain: &[u8], value: &T) -> Digest
where
    T: CanonicalEncode + ?Sized,
{
    domain_separated_digest(domain, &encode_to_vec(value))
}

fn wire_length(length: usize) -> u64 {
    u64::try_from(length).expect("Rust targets have pointers no wider than the u64 wire length")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_hex_round_trip_is_canonical() {
        let mut bytes = [0_u8; Digest::LENGTH];
        for (value, index) in bytes.iter_mut().zip(0_u8..) {
            *value = index;
        }
        let digest = Digest::from_bytes(bytes);
        let text = digest.to_string();

        assert_eq!(
            text,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        assert_eq!(text.parse::<Digest>(), Ok(digest));
        assert_eq!(digest.as_bytes(), &bytes);
        assert_eq!(digest.into_bytes(), bytes);
    }

    #[test]
    fn digest_parser_rejects_noncanonical_text() {
        assert!(matches!(
            "00".parse::<Digest>(),
            Err(ParseDigestError::InvalidLength { .. })
        ));

        let uppercase = "A000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            uppercase.parse::<Digest>(),
            Err(ParseDigestError::InvalidHexByte {
                offset: 0,
                byte: b'A'
            })
        );

        let invalid = "g000000000000000000000000000000000000000000000000000000000000000";
        assert!(matches!(
            invalid.parse::<Digest>(),
            Err(ParseDigestError::InvalidHexByte {
                offset: 0,
                byte: b'g'
            })
        ));
    }

    #[test]
    fn digest_serde_uses_strict_lowercase_hex() {
        let digest = Digest::from_bytes([0xab; Digest::LENGTH]);
        let json = serde_json::to_string(&digest).expect("digest serialization should succeed");
        assert_eq!(json, format!("\"{}\"", "ab".repeat(Digest::LENGTH)));
        assert_eq!(
            serde_json::from_str::<Digest>(&json).expect("canonical digest should deserialize"),
            digest
        );

        let uppercase = format!("\"{}\"", "AB".repeat(Digest::LENGTH));
        assert!(serde_json::from_str::<Digest>(&uppercase).is_err());
        assert!(serde_json::from_str::<Digest>("[0, 1]").is_err());
    }

    #[test]
    fn digest_domains_and_boundaries_are_separated() {
        let first = domain_separated_digest(b"problem", b"ab");
        assert_eq!(first, domain_separated_digest(b"problem", b"ab"));
        assert_ne!(first, domain_separated_digest(b"solution", b"ab"));
        assert_ne!(first, domain_separated_digest(b"problem", b"a"));
        assert_ne!(
            domain_separated_digest(b"a", b"bc"),
            domain_separated_digest(b"ab", b"c")
        );
    }
}
