//! Stateless challenge issuance and certificate construction.
//!
//! This crate has no HTTP, clock, random-number-generator, or filesystem
//! dependency. Adapters supply explicit time and entropy, which keeps protocol
//! behavior deterministic in tests and portable across serverless runtimes.

#![forbid(unsafe_code)]

use ed25519_dalek::{SigningKey, VerifyingKey};
use ssv_canonical::Digest;
use ssv_direct::{DirectArtifact, DirectError, ValidatedDirectOutput, maximum_artifact_bytes};
use ssv_problem::{FinalizedRandomness, ProblemError, ProblemTemplate, TemplateRandomness};
use ssv_service_protocol::{
    CertificatePayload, CertificateSchema, ChallengePayload, ChallengeSchema, MAX_ID_BYTES,
    MAX_SOLUTION_ELEMENTS_LIMIT, ProtocolError, RetryPolicy, SignedCertificate, SignedChallenge,
};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub issuer: String,
    pub key_id: String,
    pub challenge_lifetime_seconds: i64,
    pub maximum_future_skew_seconds: i64,
    pub maximum_solution_elements: u64,
    pub validator_build: String,
}

#[derive(Clone)]
pub struct StatelessValidatorService {
    config: ServiceConfig,
    signing_key: SigningKey,
}

#[derive(Clone, Debug)]
pub struct CertifiedValidation {
    pub certificate: SignedCertificate,
    pub output: ValidatedDirectOutput,
}

/// Successfully validated work awaiting a post-validation service timestamp.
#[derive(Clone, Debug)]
pub struct ValidatedSubmission {
    output: ValidatedDirectOutput,
    challenge_digest: Digest,
    protocol: ssv_service_protocol::ProofProtocol,
    validation_started_at_unix_seconds: i64,
    challenge_issued_at_unix_seconds: i64,
    challenge_expires_at_unix_seconds: i64,
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("service configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("challenge issuance requires challenge-derived-v1 template randomness")]
    ChallengeRequiresDerivedTemplate,
    #[error("problem or manifest exceeds this service's solution-element policy")]
    SolutionElementLimit,
    #[error("hosted validation requires a signed challenge; literal local mode is rejected")]
    SignedChallengeRequired,
    #[error("challenge lifetime exceeds this service's configured policy")]
    ChallengeLifetimeMismatch,
    #[error("signed challenge is bound to a different problem template")]
    TemplateDigestMismatch,
    #[error("problem challenge provenance is inconsistent")]
    ProblemProvenanceMismatch,
    #[error("certificate timestamp precedes validation start")]
    CertificateBeforeValidation,
    #[error("certificate timestamp precedes the signed challenge")]
    CertificateBeforeChallenge,
    #[error("challenge expired before validation completed")]
    ChallengeExpiredDuringValidation,
    #[error("problem is invalid: {0}")]
    Problem(#[from] ProblemError),
    #[error("signed protocol object is invalid: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("validation artifact is invalid: {0}")]
    Direct(#[from] DirectError),
}

impl StatelessValidatorService {
    pub fn new(config: ServiceConfig, signing_key: SigningKey) -> Result<Self, ServiceError> {
        if config.challenge_lifetime_seconds <= 0 {
            return Err(ServiceError::InvalidConfiguration(
                "challenge lifetime must be positive",
            ));
        }
        if config.maximum_future_skew_seconds < 0 {
            return Err(ServiceError::InvalidConfiguration(
                "maximum future skew must not be negative",
            ));
        }
        if config.maximum_solution_elements == 0
            || config.maximum_solution_elements > MAX_SOLUTION_ELEMENTS_LIMIT
            || maximum_artifact_bytes(config.maximum_solution_elements).is_none()
        {
            return Err(ServiceError::InvalidConfiguration(
                "maximum solution elements is outside the direct-backend bounds",
            ));
        }
        // Exercise the signed payload validation for issuer/key/build bounds.
        let probe = ChallengePayload {
            schema: ChallengeSchema::V1,
            issuer: config.issuer.clone(),
            key_id: config.key_id.clone(),
            issued_at_unix_seconds: 0,
            expires_at_unix_seconds: 1,
            entropy: Digest::from_bytes([0; 32]),
            problem_template_digest: Digest::from_bytes([0; 32]),
            retry_policy: RetryPolicy::ReplayAllowedV1,
        };
        probe.validate()?;
        if config.validator_build.is_empty() || config.validator_build.len() > MAX_ID_BYTES {
            return Err(ServiceError::InvalidConfiguration(
                "validator build identifier must not be empty",
            ));
        }
        Ok(Self {
            config,
            signing_key,
        })
    }

    #[must_use]
    pub fn config(&self) -> &ServiceConfig {
        &self.config
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn issue_challenge(
        &self,
        template: &ProblemTemplate,
        entropy: Digest,
        now_unix_seconds: i64,
    ) -> Result<SignedChallenge, ServiceError> {
        template.validate()?;
        if !matches!(
            template.randomness,
            TemplateRandomness::ChallengeDerivedV1 { .. }
        ) {
            return Err(ServiceError::ChallengeRequiresDerivedTemplate);
        }
        if template.dimension() > self.config.maximum_solution_elements {
            return Err(ServiceError::SolutionElementLimit);
        }
        let expires_at_unix_seconds = now_unix_seconds
            .checked_add(self.config.challenge_lifetime_seconds)
            .ok_or(ServiceError::InvalidConfiguration(
                "challenge timestamp overflow",
            ))?;
        let template_digest = template.digest()?;
        let payload = ChallengePayload {
            schema: ChallengeSchema::V1,
            issuer: self.config.issuer.clone(),
            key_id: self.config.key_id.clone(),
            issued_at_unix_seconds: now_unix_seconds,
            expires_at_unix_seconds,
            entropy,
            problem_template_digest: Digest::from_bytes(template_digest.into_bytes()),
            retry_policy: RetryPolicy::ReplayAllowedV1,
        };
        Ok(SignedChallenge::sign(payload, &self.signing_key)?)
    }

    /// Validates one self-contained submission without yet signing a result.
    ///
    /// The caller supplies the time captured before validation begins. Call
    /// [`Self::certify`] with a fresh post-validation time if this succeeds.
    pub fn validate_submission(
        &self,
        proof_bytes: &[u8],
        validation_started_at_unix_seconds: i64,
    ) -> Result<ValidatedSubmission, ServiceError> {
        self.validate_owned_submission(proof_bytes, validation_started_at_unix_seconds)
    }

    /// Validates a submission while taking ownership of its backing buffer.
    ///
    /// The buffer is dropped after authenticated decoding and before the sparse
    /// numerical pass, reducing peak memory in HTTP adapters that pass an owned
    /// body such as `bytes::Bytes`.
    pub fn validate_owned_submission<B>(
        &self,
        proof_bytes: B,
        validation_started_at_unix_seconds: i64,
    ) -> Result<ValidatedSubmission, ServiceError>
    where
        B: AsRef<[u8]>,
    {
        let prelude = DirectArtifact::preparse_with_solution_limit(
            proof_bytes.as_ref(),
            self.config.maximum_solution_elements,
        )?;
        let (
            challenge_digest,
            protocol,
            challenge_issued_at_unix_seconds,
            challenge_expires_at_unix_seconds,
        ) = {
            let challenge = prelude
                .challenge()
                .ok_or(ServiceError::SignedChallengeRequired)?;
            challenge.verify(
                &self.verifying_key(),
                &self.config.issuer,
                &self.config.key_id,
                validation_started_at_unix_seconds,
                self.config.maximum_future_skew_seconds,
            )?;
            let lifetime = challenge
                .payload
                .expires_at_unix_seconds
                .checked_sub(challenge.payload.issued_at_unix_seconds)
                .ok_or(ServiceError::ChallengeLifetimeMismatch)?;
            if lifetime != self.config.challenge_lifetime_seconds {
                return Err(ServiceError::ChallengeLifetimeMismatch);
            }

            let problem = prelude.problem();
            if !matches!(
                problem.randomness(),
                FinalizedRandomness::ChallengeDerivedV1 { .. }
            ) {
                return Err(ServiceError::SignedChallengeRequired);
            }
            let template_digest = problem.template().digest()?;
            if challenge.payload.problem_template_digest
                != Digest::from_bytes(template_digest.into_bytes())
            {
                return Err(ServiceError::TemplateDigestMismatch);
            }
            problem
                .verify_challenge_context(&challenge.payload_canonical_bytes())
                .map_err(|_| ServiceError::ProblemProvenanceMismatch)?;
            (
                challenge.digest(),
                prelude.manifest().protocol,
                challenge.payload.issued_at_unix_seconds,
                challenge.payload.expires_at_unix_seconds,
            )
        };

        // Dimension-sized allocation, proof hashing, generator compilation,
        // and numerical work all occur only after authentication and freshness.
        let artifact = prelude.decode()?;
        drop(proof_bytes);
        let output = artifact.verify_relation()?;
        Ok(ValidatedSubmission {
            output,
            challenge_digest,
            protocol,
            validation_started_at_unix_seconds,
            challenge_issued_at_unix_seconds,
            challenge_expires_at_unix_seconds,
        })
    }

    /// Signs an already validated result using a timestamp captured after work.
    pub fn certify(
        &self,
        validated: ValidatedSubmission,
        issued_at_unix_seconds: i64,
    ) -> Result<CertifiedValidation, ServiceError> {
        if issued_at_unix_seconds < validated.validation_started_at_unix_seconds {
            return Err(ServiceError::CertificateBeforeValidation);
        }
        if issued_at_unix_seconds < validated.challenge_issued_at_unix_seconds {
            return Err(ServiceError::CertificateBeforeChallenge);
        }
        if issued_at_unix_seconds > validated.challenge_expires_at_unix_seconds {
            return Err(ServiceError::ChallengeExpiredDuringValidation);
        }
        let payload = CertificatePayload {
            schema: CertificateSchema::V1,
            issuer: self.config.issuer.clone(),
            key_id: self.config.key_id.clone(),
            issued_at_unix_seconds,
            challenge_digest: Some(validated.challenge_digest),
            problem_digest: validated.output.problem_digest,
            validation_manifest_digest: validated.output.validation_manifest_digest,
            proof_digest: validated.output.proof_digest,
            protocol: validated.protocol,
            residual: validated.output.residual,
            validator_build: self.config.validator_build.clone(),
        };
        let certificate = SignedCertificate::sign(payload, &self.signing_key)?;
        Ok(CertifiedValidation {
            certificate,
            output: validated.output,
        })
    }

    /// Convenience for adapters that already captured distinct start and finish times.
    pub fn validate_and_certify(
        &self,
        proof_bytes: &[u8],
        validation_started_at_unix_seconds: i64,
        validation_completed_at_unix_seconds: i64,
    ) -> Result<CertifiedValidation, ServiceError> {
        let validated =
            self.validate_submission(proof_bytes, validation_started_at_unix_seconds)?;
        self.certify(validated, validation_completed_at_unix_seconds)
    }
}
