//! Transport-independent signed challenge and validation-certificate types.
//!
//! Signatures authenticate canonical typed payloads, never raw JSON. The same
//! types can therefore be carried over files, HTTP, or another transport.

#![forbid(unsafe_code)]

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssv_canonical::{
    CanonicalEncode, DecodeLimits, Digest, Encoder, Reader, domain_separated_digest, encode_to_vec,
};
use thiserror::Error;

const CHALLENGE_SIGNATURE_DOMAIN: &[u8] = b"sparse-solve/challenge-signature/ed25519/v1";
const CERTIFICATE_SIGNATURE_DOMAIN: &[u8] = b"sparse-solve/certificate-signature/ed25519/v3";
const CHALLENGE_DIGEST_DOMAIN: &[u8] = b"sparse-solve/challenge/v1";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"sparse-solve/validation-manifest/v1";
const CERTIFICATE_DIGEST_DOMAIN: &[u8] = b"sparse-solve/certificate/v3";

pub const MAX_ID_BYTES: usize = 256;
pub const MAX_CHALLENGE_BYTES: usize = 2 * 1024;
pub const MAX_SOLUTION_ELEMENTS_LIMIT: u64 = 1 << 30;
pub const MAX_PUBLIC_EVALUATION_TERMS_LIMIT: u64 = 1 << 20;
const DEFAULT_PUBLIC_EVALUATION_TERMS: u64 = 4_096;

const fn default_public_evaluation_terms() -> u64 {
    DEFAULT_PUBLIC_EVALUATION_TERMS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ChallengeSchema {
    #[serde(rename = "sparse-solve/challenge/v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum RetryPolicy {
    /// The service is stateless: a valid unexpired challenge may be reused.
    #[serde(rename = "replay-allowed-v1")]
    ReplayAllowedV1,
}

/// The bytes fixed and signed by the challenge issuer.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengePayload {
    pub schema: ChallengeSchema,
    pub issuer: String,
    pub key_id: String,
    pub issued_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
    pub entropy: Digest,
    pub problem_template_digest: Digest,
    pub retry_policy: RetryPolicy,
}

/// An Ed25519 signature represented as strict lowercase hex in JSON.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SignatureBytes([u8; 64]);

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SignatureBytes")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl SignatureBytes {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Serialize for SignatureBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 128
            || encoded
                .as_bytes()
                .iter()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
        {
            return Err(serde::de::Error::custom(
                "signature must be exactly 128 lowercase hexadecimal characters",
            ));
        }
        let decoded = hex::decode(encoded).map_err(serde::de::Error::custom)?;
        let bytes = decoded
            .try_into()
            .map_err(|_| serde::de::Error::custom("signature must decode to 64 bytes"))?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedChallenge {
    pub payload: ChallengePayload,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ValidationSchema {
    #[serde(rename = "sparse-solve/validation/v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProofProtocol {
    /// Integration/reference backend. The artifact carries the complete x.
    #[serde(rename = "direct-reference-v1")]
    DirectReferenceV1,
    /// Exact Q63.64 relation with Field192 sumchecks and a pinned WHIR PCS.
    #[serde(rename = "whir-field192-l2-v4")]
    WhirField192L2V4,
    /// Experimental binary64 metric certificate with unit-circle openings.
    #[serde(rename = "fast-binary64-unit-circle-v3")]
    FastBinary64UnitCircleV3,
}

impl ProofProtocol {
    /// Stable discriminator used by common proof containers and signatures.
    #[must_use]
    pub const fn wire_id(self) -> u16 {
        match self {
            Self::DirectReferenceV1 => 1,
            Self::WhirField192L2V4 => 2,
            Self::FastBinary64UnitCircleV3 => 4,
        }
    }

    /// Decodes a stable wire discriminator without accepting unknown backends.
    #[must_use]
    pub const fn from_wire_id(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::DirectReferenceV1),
            2 => Some(Self::WhirField192L2V4),
            4 => Some(Self::FastBinary64UnitCircleV3),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationManifest {
    pub schema: ValidationSchema,
    pub protocol: ProofProtocol,
    pub max_solution_elements: u64,
    #[serde(default = "default_public_evaluation_terms")]
    pub max_public_matrix_terms: u64,
    #[serde(default = "default_public_evaluation_terms")]
    pub max_public_rhs_terms: u64,
}

impl Default for ValidationManifest {
    fn default() -> Self {
        Self {
            schema: ValidationSchema::V1,
            protocol: ProofProtocol::DirectReferenceV1,
            max_solution_elements: 16 * 1024 * 1024,
            max_public_matrix_terms: DEFAULT_PUBLIC_EVALUATION_TERMS,
            max_public_rhs_terms: DEFAULT_PUBLIC_EVALUATION_TERMS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualMetrics {
    pub squared_l2: f64,
    pub l2: f64,
    pub rms: f64,
    pub max_abs: f64,
}

/// Canonical unsigned 192-bit integer, encoded as 48 lowercase hex digits.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Unsigned192([u8; 24]);

impl Unsigned192 {
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_be_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

impl fmt::Debug for Unsigned192 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Unsigned192")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for Unsigned192 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl Serialize for Unsigned192 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Unsigned192 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 48
            || encoded
                .as_bytes()
                .iter()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
        {
            return Err(serde::de::Error::custom(
                "unsigned 192-bit value must be exactly 48 lowercase hexadecimal characters",
            ));
        }
        let decoded = hex::decode(encoded).map_err(serde::de::Error::custom)?;
        Ok(Self(decoded.try_into().map_err(|_| {
            serde::de::Error::custom("unsigned 192-bit value must decode to 24 bytes")
        })?))
    }
}

/// One category of normalized binary64 consistency observations.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DefectMetrics {
    pub maximum_absolute_defect: f64,
    pub maximum_normalized_defect: f64,
    pub rms_normalized_defect: f64,
    pub threshold_exceedances: u64,
}

/// Auditable summary of the provisional fast validator's four checks.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FastConsistencyMetrics {
    pub norm_sumcheck: DefectMetrics,
    pub matvec_sumcheck: DefectMetrics,
    pub linear_opening: DefectMetrics,
    pub unit_circle_folds: DefectMetrics,
    pub recursive_query_trajectories: u32,
}

/// Protocol-specific score semantics carried by a signed certificate.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum CertifiedScore {
    #[serde(rename = "direct-binary64-residual-v1")]
    DirectBinary64ResidualV1 { residual: ResidualMetrics },
    #[serde(rename = "exact-dyadic-squared-l2-v1")]
    ExactDyadicSquaredL2V1 {
        numerator: Unsigned192,
        denominator_power: u32,
    },
    #[serde(rename = "fast-binary64-squared-l2-v1")]
    FastBinary64SquaredL2V1 {
        squared_l2: f64,
        consistency: FastConsistencyMetrics,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum CertificateSchema {
    #[serde(rename = "sparse-solve/validation-certificate/v3")]
    V3,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificatePayload {
    pub schema: CertificateSchema,
    pub issuer: String,
    pub key_id: String,
    pub issued_at_unix_seconds: i64,
    pub challenge_digest: Digest,
    pub problem_digest: Digest,
    pub validation_manifest_digest: Digest,
    pub proof_digest: Digest,
    pub protocol: ProofProtocol,
    pub score: CertifiedScore,
    pub validator_build: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCertificate {
    pub payload: CertificatePayload,
    pub signature: SignatureBytes,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("identifier {field} must be 1..={MAX_ID_BYTES} visible ASCII bytes without spaces")]
    InvalidIdentifier { field: &'static str },
    #[error("challenge expiry must be later than its issue time")]
    InvalidChallengeWindow,
    #[error("protocol timestamps must be nonnegative Unix seconds")]
    NegativeTimestamp,
    #[error("maximum future clock skew must be nonnegative")]
    InvalidClockSkew,
    #[error("challenge was issued too far in the future")]
    ChallengeFromFuture,
    #[error("challenge expired at Unix timestamp {0}")]
    ChallengeExpired(i64),
    #[error("challenge issuer mismatch")]
    IssuerMismatch,
    #[error("challenge key identifier mismatch")]
    KeyIdMismatch,
    #[error("Ed25519 signature verification failed")]
    InvalidSignature,
    #[error("validation manifest allows an invalid number of solution elements")]
    InvalidSolutionLimit,
    #[error("validation manifest allows an invalid public-evaluation term limit")]
    InvalidPublicEvaluationLimit,
    #[error("certificate contains a non-finite or negative residual metric")]
    InvalidResidual,
    #[error("certificate score semantics do not match its proof protocol")]
    ScoreProtocolMismatch,
    #[error("certificate contains invalid or policy-failing fast consistency metrics")]
    InvalidFastConsistency,
    #[error("certificate contains an invalid exact residual denominator")]
    InvalidExactDenominator,
    #[error("invalid canonical challenge: {0}")]
    Canonical(String),
}

impl ChallengePayload {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_id("issuer", &self.issuer)?;
        validate_id("key_id", &self.key_id)?;
        if self.issued_at_unix_seconds < 0 || self.expires_at_unix_seconds < 0 {
            return Err(ProtocolError::NegativeTimestamp);
        }
        if self.expires_at_unix_seconds <= self.issued_at_unix_seconds {
            return Err(ProtocolError::InvalidChallengeWindow);
        }
        Ok(())
    }
}

impl CanonicalEncode for ChallengePayload {
    fn encode(&self, output: &mut Encoder) {
        output.write_u16(1);
        output.write_str(&self.issuer);
        output.write_str(&self.key_id);
        output.write_i64(self.issued_at_unix_seconds);
        output.write_i64(self.expires_at_unix_seconds);
        output.write_digest(&self.entropy);
        output.write_digest(&self.problem_template_digest);
        output.write_u16(1);
    }
}

impl SignedChallenge {
    pub fn sign(
        payload: ChallengePayload,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        payload.validate()?;
        let message = signature_message(CHALLENGE_SIGNATURE_DOMAIN, &encode_to_vec(&payload));
        let signature = signing_key.sign(&message);
        Ok(Self {
            payload,
            signature: SignatureBytes(signature.to_bytes()),
        })
    }

    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        expected_issuer: &str,
        expected_key_id: &str,
        now_unix_seconds: i64,
        maximum_future_skew_seconds: i64,
    ) -> Result<(), ProtocolError> {
        self.payload.validate()?;
        if now_unix_seconds < 0 {
            return Err(ProtocolError::NegativeTimestamp);
        }
        if maximum_future_skew_seconds < 0 {
            return Err(ProtocolError::InvalidClockSkew);
        }
        if self.payload.issuer != expected_issuer {
            return Err(ProtocolError::IssuerMismatch);
        }
        if self.payload.key_id != expected_key_id {
            return Err(ProtocolError::KeyIdMismatch);
        }
        if self.payload.issued_at_unix_seconds
            > now_unix_seconds.saturating_add(maximum_future_skew_seconds)
        {
            return Err(ProtocolError::ChallengeFromFuture);
        }
        if now_unix_seconds > self.payload.expires_at_unix_seconds {
            return Err(ProtocolError::ChallengeExpired(
                self.payload.expires_at_unix_seconds,
            ));
        }
        let message = signature_message(CHALLENGE_SIGNATURE_DOMAIN, &encode_to_vec(&self.payload));
        let signature = Signature::from_bytes(self.signature.as_bytes());
        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| ProtocolError::InvalidSignature)
    }

    /// Returns the canonical payload bytes used as the problem challenge context.
    ///
    /// The problem layer derives its instance seed from these bytes and the
    /// typed template digest. Signature bytes deliberately do not participate.
    #[must_use]
    pub fn payload_canonical_bytes(&self) -> Vec<u8> {
        encode_to_vec(&self.payload)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        domain_separated_digest(CHALLENGE_DIGEST_DOMAIN, &self.to_canonical_bytes())
    }

    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut output = Encoder::with_capacity(256);
        self.payload.encode(&mut output);
        output.write_fixed_bytes(self.signature.as_bytes());
        output.into_bytes()
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let limits = DecodeLimits {
            max_input_bytes: MAX_CHALLENGE_BYTES,
            max_field_bytes: MAX_ID_BYTES,
        };
        let mut input = Reader::new(bytes, limits)
            .map_err(|error| ProtocolError::Canonical(error.to_string()))?;
        let schema = input
            .read_u16()
            .map_err(|error| ProtocolError::Canonical(error.to_string()))?;
        if schema != 1 {
            return Err(ProtocolError::Canonical(format!(
                "unsupported challenge schema tag {schema}"
            )));
        }
        let issuer = input
            .read_str()
            .map_err(|error| ProtocolError::Canonical(error.to_string()))?
            .to_owned();
        let key_id = input
            .read_str()
            .map_err(|error| ProtocolError::Canonical(error.to_string()))?
            .to_owned();
        let issued_at_unix_seconds = input
            .read_i64()
            .map_err(|error| ProtocolError::Canonical(error.to_string()))?;
        let expires_at_unix_seconds = input
            .read_i64()
            .map_err(|error| ProtocolError::Canonical(error.to_string()))?;
        let entropy = input
            .read_digest()
            .map_err(|error| ProtocolError::Canonical(error.to_string()))?;
        let problem_template_digest = input
            .read_digest()
            .map_err(|error| ProtocolError::Canonical(error.to_string()))?;
        let retry = input
            .read_u16()
            .map_err(|error| ProtocolError::Canonical(error.to_string()))?;
        if retry != 1 {
            return Err(ProtocolError::Canonical(format!(
                "unsupported retry-policy tag {retry}"
            )));
        }
        let signature = input
            .read_array::<64>()
            .map_err(|error| ProtocolError::Canonical(error.to_string()))?;
        input
            .finish()
            .map_err(|error| ProtocolError::Canonical(error.to_string()))?;
        let challenge = Self {
            payload: ChallengePayload {
                schema: ChallengeSchema::V1,
                issuer,
                key_id,
                issued_at_unix_seconds,
                expires_at_unix_seconds,
                entropy,
                problem_template_digest,
                retry_policy: RetryPolicy::ReplayAllowedV1,
            },
            signature: SignatureBytes(signature),
        };
        challenge.payload.validate()?;
        Ok(challenge)
    }
}

impl ValidationManifest {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.max_solution_elements == 0
            || self.max_solution_elements > MAX_SOLUTION_ELEMENTS_LIMIT
        {
            return Err(ProtocolError::InvalidSolutionLimit);
        }
        if self.max_public_matrix_terms == 0
            || self.max_public_matrix_terms > MAX_PUBLIC_EVALUATION_TERMS_LIMIT
            || self.max_public_rhs_terms == 0
            || self.max_public_rhs_terms > MAX_PUBLIC_EVALUATION_TERMS_LIMIT
        {
            return Err(ProtocolError::InvalidPublicEvaluationLimit);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest, ProtocolError> {
        self.validate()?;
        Ok(domain_separated_digest(
            MANIFEST_DIGEST_DOMAIN,
            &encode_to_vec(self),
        ))
    }
}

impl CanonicalEncode for ValidationManifest {
    fn encode(&self, output: &mut Encoder) {
        output.write_u16(1);
        output.write_u16(self.protocol.wire_id());
        output.write_u64(self.max_solution_elements);
        output.write_u64(self.max_public_matrix_terms);
        output.write_u64(self.max_public_rhs_terms);
    }
}

impl ResidualMetrics {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let values = [self.squared_l2, self.l2, self.rms, self.max_abs];
        if values
            .iter()
            .any(|value| !value.is_finite() || value.is_sign_negative())
        {
            return Err(ProtocolError::InvalidResidual);
        }
        Ok(())
    }
}

impl CanonicalEncode for ResidualMetrics {
    fn encode(&self, output: &mut Encoder) {
        output.write_u64(self.squared_l2.to_bits());
        output.write_u64(self.l2.to_bits());
        output.write_u64(self.rms.to_bits());
        output.write_u64(self.max_abs.to_bits());
    }
}

impl CanonicalEncode for Unsigned192 {
    fn encode(&self, output: &mut Encoder) {
        output.write_fixed_bytes(&self.0);
    }
}

impl DefectMetrics {
    fn validate(&self) -> Result<(), ProtocolError> {
        let values = [
            self.maximum_absolute_defect,
            self.maximum_normalized_defect,
            self.rms_normalized_defect,
        ];
        if values
            .iter()
            .any(|value| !value.is_finite() || value.is_sign_negative())
            || self.maximum_normalized_defect > 1.0
            || self.threshold_exceedances != 0
        {
            return Err(ProtocolError::InvalidFastConsistency);
        }
        Ok(())
    }
}

impl CanonicalEncode for DefectMetrics {
    fn encode(&self, output: &mut Encoder) {
        output.write_u64(self.maximum_absolute_defect.to_bits());
        output.write_u64(self.maximum_normalized_defect.to_bits());
        output.write_u64(self.rms_normalized_defect.to_bits());
        output.write_u64(self.threshold_exceedances);
    }
}

impl FastConsistencyMetrics {
    fn validate(&self) -> Result<(), ProtocolError> {
        self.norm_sumcheck.validate()?;
        self.matvec_sumcheck.validate()?;
        self.linear_opening.validate()?;
        self.unit_circle_folds.validate()?;
        // Query indices are distinct and transcript-derived. Small domains can
        // contain fewer than the policy target of 64 unique trajectories.
        if self.recursive_query_trajectories == 0 || self.recursive_query_trajectories > 64 {
            return Err(ProtocolError::InvalidFastConsistency);
        }
        Ok(())
    }
}

impl CanonicalEncode for FastConsistencyMetrics {
    fn encode(&self, output: &mut Encoder) {
        self.norm_sumcheck.encode(output);
        self.matvec_sumcheck.encode(output);
        self.linear_opening.encode(output);
        self.unit_circle_folds.encode(output);
        output.write_u32(self.recursive_query_trajectories);
    }
}

impl CertifiedScore {
    fn validate_for(&self, protocol: ProofProtocol) -> Result<(), ProtocolError> {
        match (protocol, self) {
            (ProofProtocol::DirectReferenceV1, Self::DirectBinary64ResidualV1 { residual }) => {
                residual.validate()
            }
            (
                ProofProtocol::WhirField192L2V4,
                Self::ExactDyadicSquaredL2V1 {
                    denominator_power, ..
                },
            ) => {
                if *denominator_power == 0 || *denominator_power > 512 {
                    Err(ProtocolError::InvalidExactDenominator)
                } else {
                    Ok(())
                }
            }
            (
                ProofProtocol::FastBinary64UnitCircleV3,
                Self::FastBinary64SquaredL2V1 {
                    squared_l2,
                    consistency,
                },
            ) => {
                if !squared_l2.is_finite() || squared_l2.is_sign_negative() {
                    return Err(ProtocolError::InvalidResidual);
                }
                consistency.validate()
            }
            _ => Err(ProtocolError::ScoreProtocolMismatch),
        }
    }
}

impl CanonicalEncode for CertifiedScore {
    fn encode(&self, output: &mut Encoder) {
        match self {
            Self::DirectBinary64ResidualV1 { residual } => {
                output.write_u16(1);
                residual.encode(output);
            }
            Self::ExactDyadicSquaredL2V1 {
                numerator,
                denominator_power,
            } => {
                output.write_u16(2);
                numerator.encode(output);
                output.write_u32(*denominator_power);
            }
            Self::FastBinary64SquaredL2V1 {
                squared_l2,
                consistency,
            } => {
                output.write_u16(3);
                output.write_u64(squared_l2.to_bits());
                consistency.encode(output);
            }
        }
    }
}

impl CanonicalEncode for CertificatePayload {
    fn encode(&self, output: &mut Encoder) {
        output.write_u16(3);
        output.write_str(&self.issuer);
        output.write_str(&self.key_id);
        output.write_i64(self.issued_at_unix_seconds);
        output.write_digest(&self.challenge_digest);
        output.write_digest(&self.problem_digest);
        output.write_digest(&self.validation_manifest_digest);
        output.write_digest(&self.proof_digest);
        output.write_u16(self.protocol.wire_id());
        self.score.encode(output);
        output.write_str(&self.validator_build);
    }
}

impl SignedCertificate {
    pub fn sign(
        payload: CertificatePayload,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        payload.validate()?;
        let message = signature_message(CERTIFICATE_SIGNATURE_DOMAIN, &encode_to_vec(&payload));
        let signature = signing_key.sign(&message);
        Ok(Self {
            payload,
            signature: SignatureBytes(signature.to_bytes()),
        })
    }

    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        expected_issuer: &str,
        expected_key_id: &str,
    ) -> Result<(), ProtocolError> {
        self.payload.validate()?;
        if self.payload.issuer != expected_issuer {
            return Err(ProtocolError::IssuerMismatch);
        }
        if self.payload.key_id != expected_key_id {
            return Err(ProtocolError::KeyIdMismatch);
        }
        let message =
            signature_message(CERTIFICATE_SIGNATURE_DOMAIN, &encode_to_vec(&self.payload));
        let signature = Signature::from_bytes(self.signature.as_bytes());
        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| ProtocolError::InvalidSignature)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut encoded = encode_to_vec(&self.payload);
        encoded.extend_from_slice(self.signature.as_bytes());
        domain_separated_digest(CERTIFICATE_DIGEST_DOMAIN, &encoded)
    }
}

impl CertificatePayload {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_id("issuer", &self.issuer)?;
        validate_id("key_id", &self.key_id)?;
        validate_id("validator_build", &self.validator_build)?;
        if self.issued_at_unix_seconds < 0 {
            return Err(ProtocolError::NegativeTimestamp);
        }
        self.score.validate_for(self.protocol)
    }
}

fn signature_message(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut output = Encoder::with_capacity(domain.len() + payload.len() + 16);
    output.write_bytes(domain);
    output.write_bytes(payload);
    output.into_bytes()
}

fn validate_id(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
    {
        return Err(ProtocolError::InvalidIdentifier { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn payload() -> ChallengePayload {
        ChallengePayload {
            schema: ChallengeSchema::V1,
            issuer: "test-issuer".to_owned(),
            key_id: "test-key".to_owned(),
            issued_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 2_000,
            entropy: Digest::from_bytes([3; 32]),
            problem_template_digest: Digest::from_bytes([4; 32]),
            retry_policy: RetryPolicy::ReplayAllowedV1,
        }
    }

    #[test]
    fn challenge_sign_verify_and_canonical_round_trip() {
        let key = signing_key();
        let challenge = SignedChallenge::sign(payload(), &key).unwrap();
        challenge
            .verify(&key.verifying_key(), "test-issuer", "test-key", 1_500, 5)
            .unwrap();
        let bytes = challenge.to_canonical_bytes();
        assert_eq!(
            SignedChallenge::from_canonical_bytes(&bytes).unwrap(),
            challenge
        );
    }

    #[test]
    fn fast_v3_has_a_fresh_wire_id() {
        assert_eq!(ProofProtocol::FastBinary64UnitCircleV3.wire_id(), 4);
        assert_eq!(
            ProofProtocol::from_wire_id(4),
            Some(ProofProtocol::FastBinary64UnitCircleV3)
        );
        assert_eq!(ProofProtocol::from_wire_id(3), None);
    }

    #[test]
    fn mutation_and_wrong_context_fail() {
        let key = signing_key();
        let challenge = SignedChallenge::sign(payload(), &key).unwrap();
        assert!(
            challenge
                .verify(&key.verifying_key(), "other", "test-key", 1_500, 5)
                .is_err()
        );
        let mut changed = challenge.clone();
        changed.payload.entropy = Digest::from_bytes([9; 32]);
        assert!(
            changed
                .verify(&key.verifying_key(), "test-issuer", "test-key", 1_500, 5)
                .is_err()
        );
        let mut unsafe_identifier = payload();
        unsafe_identifier.issuer = "terminal\ncontrol".to_owned();
        assert!(SignedChallenge::sign(unsafe_identifier, &key).is_err());
    }

    #[test]
    fn problem_context_ignores_signature_but_binds_payload() {
        let key = signing_key();
        let challenge = SignedChallenge::sign(payload(), &key).unwrap();
        let mut changed_signature = challenge.clone();
        changed_signature.signature.0[0] ^= 1;
        assert_eq!(
            challenge.payload_canonical_bytes(),
            changed_signature.payload_canonical_bytes()
        );

        let mut changed_payload = challenge.clone();
        changed_payload.payload.entropy = Digest::from_bytes([8; 32]);
        assert_ne!(
            challenge.payload_canonical_bytes(),
            changed_payload.payload_canonical_bytes()
        );
    }

    #[test]
    fn certificate_signatures_bind_metrics_and_provenance() {
        let key = signing_key();
        let payload = CertificatePayload {
            schema: CertificateSchema::V3,
            issuer: "test-issuer".to_owned(),
            key_id: "test-key".to_owned(),
            issued_at_unix_seconds: 1_500,
            challenge_digest: Digest::from_bytes([1; 32]),
            problem_digest: Digest::from_bytes([2; 32]),
            validation_manifest_digest: Digest::from_bytes([3; 32]),
            proof_digest: Digest::from_bytes([4; 32]),
            protocol: ProofProtocol::DirectReferenceV1,
            score: CertifiedScore::DirectBinary64ResidualV1 {
                residual: ResidualMetrics {
                    squared_l2: 0.25,
                    l2: 0.5,
                    rms: 0.125,
                    max_abs: 0.5,
                },
            },
            validator_build: "test-build".to_owned(),
        };
        let certificate = SignedCertificate::sign(payload, &key).unwrap();
        certificate
            .verify(&key.verifying_key(), "test-issuer", "test-key")
            .unwrap();
        assert_eq!(
            &encode_to_vec(&certificate.payload)[..2],
            &3_u16.to_be_bytes()
        );

        let mut changed = certificate.clone();
        changed.payload.score = CertifiedScore::DirectBinary64ResidualV1 {
            residual: ResidualMetrics {
                squared_l2: 0.5,
                l2: 0.5,
                rms: 0.125,
                max_abs: 0.5,
            },
        };
        assert!(
            changed
                .verify(&key.verifying_key(), "test-issuer", "test-key")
                .is_err()
        );

        let mut wrong_semantics = certificate.clone();
        wrong_semantics.payload.score = CertifiedScore::ExactDyadicSquaredL2V1 {
            numerator: Unsigned192::from_be_bytes([0; 24]),
            denominator_power: 136,
        };
        assert!(matches!(
            wrong_semantics.payload.validate(),
            Err(ProtocolError::ScoreProtocolMismatch)
        ));
    }

    #[test]
    fn signed_fast_certificate_survives_json_round_trip() {
        let key = signing_key();
        let zero = DefectMetrics {
            maximum_absolute_defect: 0.0,
            maximum_normalized_defect: 0.0,
            rms_normalized_defect: 0.0,
            threshold_exceedances: 0,
        };
        let certificate = SignedCertificate::sign(
            CertificatePayload {
                schema: CertificateSchema::V3,
                issuer: "test-issuer".to_owned(),
                key_id: "test-key".to_owned(),
                issued_at_unix_seconds: 1_500,
                challenge_digest: Digest::from_bytes([1; 32]),
                problem_digest: Digest::from_bytes([2; 32]),
                validation_manifest_digest: Digest::from_bytes([3; 32]),
                proof_digest: Digest::from_bytes([4; 32]),
                protocol: ProofProtocol::FastBinary64UnitCircleV3,
                score: CertifiedScore::FastBinary64SquaredL2V1 {
                    squared_l2: 0.0,
                    consistency: FastConsistencyMetrics {
                        norm_sumcheck: zero,
                        matvec_sumcheck: DefectMetrics {
                            maximum_absolute_defect: 6.938_893_903_907_228e-18,
                            maximum_normalized_defect: 2.104_791_105_834_217_8e-5,
                            rms_normalized_defect: 9.914_397_065_476_954e-6,
                            threshold_exceedances: 0,
                        },
                        linear_opening: zero,
                        unit_circle_folds: zero,
                        recursive_query_trajectories: 32,
                    },
                },
                validator_build: "test-build".to_owned(),
            },
            &key,
        )
        .unwrap();

        let encoded = serde_json::to_vec(&certificate).unwrap();
        let decoded: SignedCertificate = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            encode_to_vec(&decoded.payload),
            encode_to_vec(&certificate.payload)
        );
        decoded
            .verify(&key.verifying_key(), "test-issuer", "test-key")
            .unwrap();
    }

    #[test]
    fn fast_certificate_accepts_up_to_64_distinct_small_domain_queries() {
        let zero = DefectMetrics {
            maximum_absolute_defect: 0.0,
            maximum_normalized_defect: 0.0,
            rms_normalized_defect: 0.0,
            threshold_exceedances: 0,
        };
        let mut consistency = FastConsistencyMetrics {
            norm_sumcheck: zero,
            matvec_sumcheck: zero,
            linear_opening: zero,
            unit_circle_folds: zero,
            recursive_query_trajectories: 1,
        };
        assert!(consistency.validate().is_ok());
        consistency.recursive_query_trajectories = 64;
        assert!(consistency.validate().is_ok());
        consistency.recursive_query_trajectories = 0;
        assert!(matches!(
            consistency.validate(),
            Err(ProtocolError::InvalidFastConsistency)
        ));
        consistency.recursive_query_trajectories = 65;
        assert!(matches!(
            consistency.validate(),
            Err(ProtocolError::InvalidFastConsistency)
        ));
    }
}
