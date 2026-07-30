//! Stateless challenge issuance, backend dispatch, and certificate construction.
//!
//! This crate has no HTTP, clock, random-number-generator, or filesystem
//! dependency. Adapters supply explicit time and entropy. Proof implementations
//! are selected through `ssv-backends`; service code never reproduces their
//! algebra.

#![forbid(unsafe_code)]

use ed25519_dalek::{SigningKey, VerifyingKey};
use ssv_backends::{
    BackendError, BackendVerifierReport, verify_with_cancellation as verify_backend,
};
use ssv_canonical::Digest;
use ssv_direct::maximum_backend_payload_bytes;
use ssv_problem::{
    FinalizedRandomness, ProblemError, ProblemTemplate, PublicEvaluationTerms, TemplateRandomness,
};
use ssv_service_protocol::{
    CertificatePayload, CertificateSchema, ChallengePayload, ChallengeSchema, MAX_CHALLENGE_BYTES,
    MAX_PUBLIC_EVALUATION_TERMS_LIMIT, MAX_SOLUTION_ELEMENTS_LIMIT, ProofProtocol, ProtocolError,
    RetryPolicy, SignedCertificate, SignedChallenge, validate_identifier,
};
use ssv_validation::{
    ArtifactPrelude, ArtifactResourceLimits, ArtifactSummary, MAX_PUBLIC_STATEMENT_BYTES,
    MAX_SUCCINCT_ARTIFACT_BYTES, MAX_SUCCINCT_PAYLOAD_BYTES, ValidationError,
};
use thiserror::Error;

pub use ssv_validation::ValidationCancellation;

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub issuer: String,
    pub key_id: String,
    pub challenge_lifetime_seconds: i64,
    pub maximum_future_skew_seconds: i64,
    pub maximum_solution_elements: u64,
    pub maximum_public_matrix_terms: u64,
    pub maximum_public_rhs_terms: u64,
    /// Immutable protocol allowlist for this service process.
    pub allowed_protocols: Vec<ProofProtocol>,
    pub validator_build: String,
}

#[derive(Clone)]
pub struct StatelessValidatorService {
    config: ServiceConfig,
    signing_key: SigningKey,
}

#[derive(Clone, Debug)]
pub struct ValidatedOutput {
    pub summary: ArtifactSummary,
    /// Structurally and cryptographically verified backend output. Fast
    /// binary64 discrepancies remain diagnostics rather than a service-level
    /// quality decision.
    pub report: BackendVerifierReport,
}

#[derive(Clone, Debug)]
pub struct CertifiedValidation {
    pub certificate: SignedCertificate,
    pub output: ValidatedOutput,
}

/// Successfully validated work awaiting a post-validation service timestamp.
#[derive(Clone, Debug)]
pub struct ValidatedSubmission {
    output: ValidatedOutput,
    challenge_digest: Digest,
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
    #[error("problem or manifest exceeds this service's public-evaluator term policy")]
    PublicEvaluationLimit,
    #[error("proof protocol {protocol:?} is not enabled by this service")]
    ProtocolNotAllowed { protocol: ProofProtocol },
    #[error("validation was cancelled")]
    ValidationCancelled,
    #[error("hosted validation requires a signed challenge; literal local mode is rejected")]
    SignedChallengeRequired,
    #[error("challenge lifetime differs from this service's configured policy")]
    ChallengeLifetimeMismatch,
    #[error("signed challenge is bound to a different problem template")]
    TemplateDigestMismatch,
    #[error("problem challenge provenance is inconsistent")]
    ProblemProvenanceMismatch,
    #[error("certificate timestamp precedes validation start")]
    CertificateBeforeValidation,
    #[error("certificate timestamp precedes a signed challenge")]
    CertificateBeforeChallenge,
    #[error("a challenge expired before validation completed")]
    ChallengeExpiredDuringValidation,
    #[error("problem is invalid: {0}")]
    Problem(#[from] ProblemError),
    #[error("signed protocol object is invalid: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("common validation artifact is invalid: {0}")]
    Artifact(#[from] ValidationError),
    #[error("validation backend rejected the artifact: {0}")]
    Backend(#[from] BackendError),
}

/// Computes the HTTP body cap for the common container under a service's
/// element policy. Succinct proofs retain their 64 MiB cap even for tiny n;
/// the direct oracle scales with its explicit full-vector payload.
#[must_use]
pub fn maximum_submission_bytes(maximum_solution_elements: u64) -> Option<usize> {
    if maximum_solution_elements == 0 || maximum_solution_elements > MAX_SOLUTION_ELEMENTS_LIMIT {
        return None;
    }
    let elements = usize::try_from(maximum_solution_elements).ok()?;
    let direct_payload = maximum_backend_payload_bytes(elements)?;
    let direct_artifact = MAX_CHALLENGE_BYTES
        .checked_add(MAX_PUBLIC_STATEMENT_BYTES)?
        .checked_add(direct_payload)?
        .checked_add(128)?;
    Some(direct_artifact.max(MAX_SUCCINCT_ARTIFACT_BYTES))
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
        if maximum_submission_bytes(config.maximum_solution_elements).is_none() {
            return Err(ServiceError::InvalidConfiguration(
                "maximum solution elements is outside backend bounds",
            ));
        }
        if config.maximum_public_matrix_terms == 0
            || config.maximum_public_matrix_terms > MAX_PUBLIC_EVALUATION_TERMS_LIMIT
            || config.maximum_public_rhs_terms == 0
            || config.maximum_public_rhs_terms > MAX_PUBLIC_EVALUATION_TERMS_LIMIT
        {
            return Err(ServiceError::InvalidConfiguration(
                "public-evaluator term limits are outside protocol bounds",
            ));
        }
        if config.allowed_protocols.is_empty() {
            return Err(ServiceError::InvalidConfiguration(
                "at least one proof protocol must be enabled",
            ));
        }
        validate_identifier("issuer", &config.issuer)?;
        validate_identifier("key_id", &config.key_id)?;
        validate_identifier("validator_build", &config.validator_build)?;
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
        let public_evaluation_terms = template.public_evaluation_terms()?;
        if !matches!(
            template.randomness,
            TemplateRandomness::ChallengeDerivedV1 { .. }
        ) {
            return Err(ServiceError::ChallengeRequiresDerivedTemplate);
        }
        if template.dimension() > self.config.maximum_solution_elements {
            return Err(ServiceError::SolutionElementLimit);
        }
        self.require_public_evaluation_terms(public_evaluation_terms)?;
        let expires_at_unix_seconds = now_unix_seconds
            .checked_add(self.config.challenge_lifetime_seconds)
            .ok_or(ServiceError::InvalidConfiguration(
                "challenge timestamp overflow",
            ))?;
        let payload = ChallengePayload {
            schema: ChallengeSchema::V1,
            issuer: self.config.issuer.clone(),
            key_id: self.config.key_id.clone(),
            issued_at_unix_seconds: now_unix_seconds,
            expires_at_unix_seconds,
            entropy,
            problem_template_digest: Digest::from_bytes(template.digest()?.into_bytes()),
            retry_policy: RetryPolicy::ReplayAllowedV1,
        };
        Ok(SignedChallenge::sign(payload, &self.signing_key)?)
    }

    pub fn validate_submission(
        &self,
        proof_bytes: &[u8],
        validation_started_at_unix_seconds: i64,
    ) -> Result<ValidatedSubmission, ServiceError> {
        self.validate_owned_submission(proof_bytes, validation_started_at_unix_seconds)
    }

    /// Validates a borrowed artifact while polling a shared cancellation
    /// signal throughout common admission and backend verification.
    pub fn validate_submission_with_cancellation(
        &self,
        proof_bytes: &[u8],
        validation_started_at_unix_seconds: i64,
        cancellation: &ValidationCancellation,
    ) -> Result<ValidatedSubmission, ServiceError> {
        self.validate_owned_submission_with_cancellation(
            proof_bytes,
            validation_started_at_unix_seconds,
            cancellation,
        )
    }

    /// Validates an owned artifact without a cancellation source.
    ///
    /// Ownership lets an HTTP adapter move its body directly onto a blocking
    /// worker without first cloning it.
    pub fn validate_owned_submission<B>(
        &self,
        proof_bytes: B,
        validation_started_at_unix_seconds: i64,
    ) -> Result<ValidatedSubmission, ServiceError>
    where
        B: AsRef<[u8]>,
    {
        self.validate_owned_submission_with_cancellation(
            proof_bytes,
            validation_started_at_unix_seconds,
            &ValidationCancellation::never(),
        )
    }

    /// Validates an owned artifact with cooperative cancellation.
    ///
    /// Registered backends check the signal at bounded phase or loop
    /// checkpoints. Cancellation is cooperative rather than a hard thread
    /// interruption.
    pub fn validate_owned_submission_with_cancellation<B>(
        &self,
        proof_bytes: B,
        validation_started_at_unix_seconds: i64,
        cancellation: &ValidationCancellation,
    ) -> Result<ValidatedSubmission, ServiceError>
    where
        B: AsRef<[u8]>,
    {
        require_not_cancelled(cancellation)?;
        let element_limit = self.config.maximum_solution_elements;
        let direct_limit = maximum_backend_payload_bytes(
            usize::try_from(element_limit).map_err(|_| ServiceError::SolutionElementLimit)?,
        )
        .ok_or(ServiceError::SolutionElementLimit)?;
        let payload_limit = direct_limit.max(MAX_SUCCINCT_PAYLOAD_BYTES);
        let prelude = ArtifactPrelude::parse_with_admission_policy(
            proof_bytes.as_ref(),
            ArtifactResourceLimits::new(
                element_limit,
                payload_limit,
                self.config.maximum_public_matrix_terms,
                self.config.maximum_public_rhs_terms,
            ),
            &self.config.allowed_protocols,
        )
        .map_err(|error| match error {
            ValidationError::ProtocolNotAllowed { protocol } => {
                ServiceError::ProtocolNotAllowed { protocol }
            }
            other => ServiceError::Artifact(other),
        })?;
        require_not_cancelled(cancellation)?;

        let challenge = prelude
            .statement()
            .challenge()
            .ok_or(ServiceError::SignedChallengeRequired)?;
        challenge.verify(
            &self.verifying_key(),
            &self.config.issuer,
            &self.config.key_id,
            validation_started_at_unix_seconds,
            self.config.maximum_future_skew_seconds,
        )?;
        require_configured_lifetime(
            challenge.payload.issued_at_unix_seconds,
            challenge.payload.expires_at_unix_seconds,
            self.config.challenge_lifetime_seconds,
        )?;
        if !matches!(
            prelude.statement().problem().randomness(),
            FinalizedRandomness::ChallengeDerivedV1 { .. }
        ) {
            return Err(ServiceError::SignedChallengeRequired);
        }
        if challenge.payload.problem_template_digest
            != Digest::from_bytes(
                prelude
                    .statement()
                    .problem()
                    .template()
                    .digest()?
                    .into_bytes(),
            )
        {
            return Err(ServiceError::TemplateDigestMismatch);
        }
        prelude
            .statement()
            .problem()
            .verify_challenge_context(&challenge.payload_canonical_bytes())
            .map_err(|_| ServiceError::ProblemProvenanceMismatch)?;
        require_not_cancelled(cancellation)?;

        let report = verify_backend(&prelude, cancellation);
        require_not_cancelled(cancellation)?;
        let report = report?;
        let output = ValidatedOutput {
            summary: prelude.summary(),
            report,
        };
        Ok(ValidatedSubmission {
            output,
            challenge_digest: challenge.digest(),
            validation_started_at_unix_seconds,
            challenge_issued_at_unix_seconds: challenge.payload.issued_at_unix_seconds,
            challenge_expires_at_unix_seconds: challenge.payload.expires_at_unix_seconds,
        })
    }

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
            schema: CertificateSchema::V4,
            issuer: self.config.issuer.clone(),
            key_id: self.config.key_id.clone(),
            issued_at_unix_seconds,
            challenge_digest: validated.challenge_digest,
            problem_digest: validated.output.summary.problem_digest,
            validation_manifest_digest: validated.output.summary.validation_manifest_digest,
            proof_digest: validated.output.summary.proof_digest,
            protocol: validated.output.report.protocol(),
            score: validated.output.report.certified_score()?,
            validator_build: self.config.validator_build.clone(),
        };
        let certificate = SignedCertificate::sign(payload, &self.signing_key)?;
        Ok(CertifiedValidation {
            certificate,
            output: validated.output,
        })
    }

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

    fn require_public_evaluation_terms(
        &self,
        terms: PublicEvaluationTerms,
    ) -> Result<(), ServiceError> {
        if terms.matrix_period_terms > self.config.maximum_public_matrix_terms
            || terms.rhs_period_terms > self.config.maximum_public_rhs_terms
        {
            return Err(ServiceError::PublicEvaluationLimit);
        }
        Ok(())
    }
}

fn require_not_cancelled(cancellation: &ValidationCancellation) -> Result<(), ServiceError> {
    if cancellation.is_cancelled() {
        return Err(ServiceError::ValidationCancelled);
    }
    Ok(())
}

fn require_configured_lifetime(
    issued_at: i64,
    expires_at: i64,
    configured_lifetime: i64,
) -> Result<(), ServiceError> {
    let lifetime = expires_at
        .checked_sub(issued_at)
        .ok_or(ServiceError::ChallengeLifetimeMismatch)?;
    if lifetime != configured_lifetime {
        return Err(ServiceError::ChallengeLifetimeMismatch);
    }
    Ok(())
}

impl ValidatedOutput {
    #[must_use]
    pub const fn backend_report(&self) -> &BackendVerifierReport {
        &self.report
    }
}
