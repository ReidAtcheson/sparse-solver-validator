use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssv_canonical::{CanonicalEncode, Digest, Encoder, domain_separated_digest};

use crate::{MAX_CHALLENGE_CONTEXT_BYTES, ProblemTemplateDigest};

const INSTANCE_SEED_DERIVATION_CONTEXT: &str = "sparse-solve/problem-instance-seed/v1";
const SUBSEED_DERIVATION_CONTEXT: &str = "sparse-solve/problem-subseed/v1";
const CHALLENGE_CONTEXT_DIGEST_DOMAIN: &[u8] = b"sparse-solve/challenge-context/v1";

/// Exactly 256 bits of generator input, rendered as lowercase hexadecimal in JSON.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InstanceSeed([u8; 32]);

impl InstanceSeed {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Display for InstanceSeed {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        hex::encode(self.0).fmt(formatter)
    }
}

impl FromStr for InstanceSeed {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !is_lower_hex(value) || value.len() != 64 {
            return Err("an instance seed must be exactly 64 lowercase hexadecimal characters");
        }
        let bytes = hex::decode(value).map_err(|_| "invalid hexadecimal instance seed")?;
        let bytes = bytes
            .try_into()
            .map_err(|_| "an instance seed must contain exactly 32 bytes")?;
        Ok(Self(bytes))
    }
}

impl Serialize for InstanceSeed {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for InstanceSeed {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(InstanceSeedVisitor)
    }
}

struct InstanceSeedVisitor;

impl Visitor<'_> for InstanceSeedVisitor {
    type Value = InstanceSeed;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("exactly 64 lowercase hexadecimal characters")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        value.parse().map_err(E::custom)
    }
}

/// Opaque canonical challenge bytes embedded in a finalized problem.
///
/// JSON uses lowercase hexadecimal so there is exactly one textual spelling.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalContextBytes(Vec<u8>);

impl CanonicalContextBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.len() > MAX_CHALLENGE_CONTEXT_BYTES {
            return Err("challenge context exceeds the configured byte limit");
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for CanonicalContextBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for CanonicalContextBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ContextBytesVisitor)
    }
}

struct ContextBytesVisitor;

impl Visitor<'_> for ContextBytesVisitor {
    type Value = CanonicalContextBytes;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("an even-length lowercase hexadecimal byte string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > 2 * MAX_CHALLENGE_CONTEXT_BYTES {
            return Err(E::custom(
                "challenge context exceeds the configured byte limit",
            ));
        }
        if !value.len().is_multiple_of(2) || !is_lower_hex(value) {
            return Err(E::custom(
                "challenge context must be even-length lowercase hexadecimal",
            ));
        }
        let bytes = hex::decode(value).map_err(E::custom)?;
        Ok(CanonicalContextBytes(bytes))
    }
}

/// Frozen rule used to turn a template and prior challenge context into a seed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum SeedDerivation {
    #[serde(rename = "blake3-xof-v1")]
    Blake3XofV1,
}

/// Randomness policy committed by the problem template.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum TemplateRandomness {
    #[serde(rename = "literal-v1")]
    LiteralV1 { seed: InstanceSeed },
    #[serde(rename = "challenge-derived-v1")]
    ChallengeDerivedV1 { derivation: SeedDerivation },
}

/// Challenge bytes carried by a self-contained finalized problem.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ChallengeContext {
    #[serde(rename = "embedded-v1")]
    EmbeddedV1 {
        canonical_bytes: CanonicalContextBytes,
    },
}

impl ChallengeContext {
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        match self {
            Self::EmbeddedV1 { canonical_bytes } => canonical_bytes.as_slice(),
        }
    }
}

/// Auditable randomness record carried by a finalized problem.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum FinalizedRandomness {
    #[serde(rename = "literal-v1")]
    LiteralV1 { seed: InstanceSeed },
    #[serde(rename = "challenge-derived-v1")]
    ChallengeDerivedV1 {
        derivation: SeedDerivation,
        template_digest: ProblemTemplateDigest,
        challenge_context: ChallengeContext,
        challenge_context_digest: Digest,
        /// Redundant by design. Validation recomputes and compares this seed.
        seed: InstanceSeed,
    },
}

impl FinalizedRandomness {
    #[must_use]
    pub const fn instance_seed(&self) -> InstanceSeed {
        match self {
            Self::LiteralV1 { seed } | Self::ChallengeDerivedV1 { seed, .. } => *seed,
        }
    }

    #[must_use]
    pub const fn is_challenge_derived(&self) -> bool {
        matches!(self, Self::ChallengeDerivedV1 { .. })
    }

    #[must_use]
    pub fn challenge_context(&self) -> Option<&ChallengeContext> {
        match self {
            Self::LiteralV1 { .. } => None,
            Self::ChallengeDerivedV1 {
                challenge_context, ..
            } => Some(challenge_context),
        }
    }
}

/// Deterministically derives an instance seed from a typed template digest and
/// the exact prior challenge-context bytes.
#[must_use]
pub fn derive_instance_seed(
    template_digest: ProblemTemplateDigest,
    challenge_context: &[u8],
) -> InstanceSeed {
    let mut hasher = blake3::Hasher::new_derive_key(INSTANCE_SEED_DERIVATION_CONTEXT);
    hasher.update(template_digest.as_bytes());
    hasher.update(&(challenge_context.len() as u64).to_le_bytes());
    hasher.update(challenge_context);
    let mut seed = [0_u8; 32];
    hasher.finalize_xof().fill(&mut seed);
    InstanceSeed(seed)
}

/// Derives an independent generator stream from the common instance seed.
/// Labels are length-delimited, making domain separation unambiguous.
#[must_use]
pub fn derive_subseed(instance_seed: InstanceSeed, label: &str) -> InstanceSeed {
    let mut hasher = blake3::Hasher::new_derive_key(SUBSEED_DERIVATION_CONTEXT);
    hasher.update(instance_seed.as_bytes());
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label.as_bytes());
    let mut seed = [0_u8; 32];
    hasher.finalize_xof().fill(&mut seed);
    InstanceSeed(seed)
}

#[must_use]
pub(crate) fn challenge_context_digest(context: &[u8]) -> Digest {
    domain_separated_digest(CHALLENGE_CONTEXT_DIGEST_DOMAIN, context)
}

impl CanonicalEncode for InstanceSeed {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_fixed_bytes(&self.0);
    }
}

impl CanonicalEncode for SeedDerivation {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Blake3XofV1 => encoder.write_u16(1),
        }
    }
}

impl CanonicalEncode for TemplateRandomness {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::LiteralV1 { seed } => {
                encoder.write_u16(1);
                seed.encode(encoder);
            }
            Self::ChallengeDerivedV1 { derivation } => {
                encoder.write_u16(2);
                derivation.encode(encoder);
            }
        }
    }
}

impl CanonicalEncode for ChallengeContext {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::EmbeddedV1 { canonical_bytes } => {
                encoder.write_u16(1);
                encoder.write_bytes(canonical_bytes.as_slice());
            }
        }
    }
}

impl CanonicalEncode for FinalizedRandomness {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::LiteralV1 { seed } => {
                encoder.write_u16(1);
                seed.encode(encoder);
            }
            Self::ChallengeDerivedV1 {
                derivation,
                template_digest,
                challenge_context,
                challenge_context_digest,
                seed,
            } => {
                encoder.write_u16(2);
                derivation.encode(encoder);
                encoder.write_digest(template_digest.inner());
                challenge_context.encode(encoder);
                encoder.write_digest(challenge_context_digest);
                seed.encode(encoder);
            }
        }
    }
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_json_is_strict_lowercase_hex() {
        let seed = InstanceSeed::from_bytes([0xab; 32]);
        let json = serde_json::to_string(&seed).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(serde_json::from_str::<InstanceSeed>(&json).unwrap(), seed);
        assert!(serde_json::from_str::<InstanceSeed>(&format!("\"{}\"", "AB".repeat(32))).is_err());
        assert!(serde_json::from_str::<InstanceSeed>("\"00\"").is_err());
    }

    #[test]
    fn subseed_labels_are_domain_separated() {
        let seed = InstanceSeed::from_bytes([7; 32]);
        assert_eq!(
            derive_subseed(seed, "matrix/values"),
            derive_subseed(seed, "matrix/values")
        );
        assert_ne!(
            derive_subseed(seed, "matrix/values"),
            derive_subseed(seed, "rhs/values")
        );
    }
}
