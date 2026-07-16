//! Stateless challenge issuance, backend dispatch, and certificate construction.
//!
//! This crate has no HTTP, clock, random-number-generator, or filesystem
//! dependency. Adapters supply explicit time and entropy. Proof implementations
//! are selected through `ssv-backends`; service code never reproduces their
//! algebra.

#![forbid(unsafe_code)]

use ed25519_dalek::{SigningKey, VerifyingKey};
use ssv_backends::{
    AcceptedBackendReport, BackendError, BackendVerifierReport, verify as verify_backend,
};
use ssv_canonical::Digest;
use ssv_direct::maximum_backend_payload_bytes;
use ssv_fast::{FastBackend, FastError, FastNonceMode};
use ssv_problem::{FinalizedRandomness, ProblemError, ProblemTemplate, TemplateRandomness};
use ssv_service_protocol::{
    CertificatePayload, CertificateSchema, ChallengePayload, ChallengeSchema,
    CommitmentChallengePayload, CommitmentChallengeRequest, CommitmentChallengeSchema,
    MAX_CHALLENGE_BYTES, MAX_ID_BYTES, MAX_SOLUTION_ELEMENTS_LIMIT, ProofProtocol, ProtocolError,
    RetryPolicy, SignedCertificate, SignedChallenge, SignedCommitmentChallenge,
};
use ssv_validation::{
    ArtifactPrelude, ArtifactSummary, MAX_PUBLIC_STATEMENT_BYTES, MAX_SUCCINCT_ARTIFACT_BYTES,
    MAX_SUCCINCT_PAYLOAD_BYTES, ValidationError,
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
pub struct ValidatedOutput {
    pub summary: ArtifactSummary,
    pub report: AcceptedBackendReport,
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
    commitment_challenge_digest: Option<Digest>,
    validation_started_at_unix_seconds: i64,
    latest_challenge_issue_unix_seconds: i64,
    earliest_challenge_expiry_unix_seconds: i64,
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("service configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("challenge issuance requires challenge-derived-v1 template randomness")]
    ChallengeRequiresDerivedTemplate,
    #[error("the selected proof protocol has no registered post-commit challenge stage")]
    CommitmentChallengeUnsupported,
    #[error("problem or manifest exceeds this service's solution-element policy")]
    SolutionElementLimit,
    #[error("hosted validation requires a signed challenge; literal local mode is rejected")]
    SignedChallengeRequired,
    #[error("hosted fast validation requires an externally signed post-commit challenge")]
    SignedCommitmentChallengeRequired,
    #[error("challenge lifetime differs from this service's configured policy")]
    ChallengeLifetimeMismatch,
    #[error("signed challenge is bound to a different problem template")]
    TemplateDigestMismatch,
    #[error("problem challenge provenance is inconsistent")]
    ProblemProvenanceMismatch,
    #[error("fast commitment challenge predates the problem challenge")]
    CommitmentBeforeProblemChallenge,
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
    #[error("fast preflight rejected the artifact: {0}")]
    Fast(#[from] FastError),
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
        // Exercise signed-payload validation for issuer/key bounds.
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

    /// Issues a fresh commitment-bound challenge without retaining server state.
    /// Replay remains possible under v1; the token proves ordering/timestamping.
    pub fn issue_commitment_challenge(
        &self,
        request: &CommitmentChallengeRequest,
        entropy: Digest,
        now_unix_seconds: i64,
    ) -> Result<SignedCommitmentChallenge, ServiceError> {
        if request.protocol != ProofProtocol::FastBinary64UnitCircleV2 {
            return Err(ServiceError::CommitmentChallengeUnsupported);
        }
        let expires_at_unix_seconds = now_unix_seconds
            .checked_add(self.config.challenge_lifetime_seconds)
            .ok_or(ServiceError::InvalidConfiguration(
                "challenge timestamp overflow",
            ))?;
        let payload = CommitmentChallengePayload {
            schema: CommitmentChallengeSchema::V1,
            issuer: self.config.issuer.clone(),
            key_id: self.config.key_id.clone(),
            issued_at_unix_seconds: now_unix_seconds,
            expires_at_unix_seconds,
            entropy,
            problem_digest: request.problem_digest,
            validation_manifest_digest: request.validation_manifest_digest,
            protocol: request.protocol,
            commitment_digest: request.commitment_digest,
            retry_policy: RetryPolicy::ReplayAllowedV1,
        };
        Ok(SignedCommitmentChallenge::sign(payload, &self.signing_key)?)
    }

    pub fn validate_submission(
        &self,
        proof_bytes: &[u8],
        validation_started_at_unix_seconds: i64,
    ) -> Result<ValidatedSubmission, ServiceError> {
        self.validate_owned_submission(proof_bytes, validation_started_at_unix_seconds)
    }

    pub fn validate_owned_submission<B>(
        &self,
        proof_bytes: B,
        validation_started_at_unix_seconds: i64,
    ) -> Result<ValidatedSubmission, ServiceError>
    where
        B: AsRef<[u8]>,
    {
        let element_limit = self.config.maximum_solution_elements;
        let direct_limit = maximum_backend_payload_bytes(
            usize::try_from(element_limit).map_err(|_| ServiceError::SolutionElementLimit)?,
        )
        .ok_or(ServiceError::SolutionElementLimit)?;
        let payload_limit = direct_limit.max(MAX_SUCCINCT_PAYLOAD_BYTES);
        let prelude =
            ArtifactPrelude::parse_with_limits(proof_bytes.as_ref(), element_limit, payload_limit)?;

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

        let mut latest_issue = challenge.payload.issued_at_unix_seconds;
        let mut earliest_expiry = challenge.payload.expires_at_unix_seconds;
        let mut commitment_challenge_digest = None;

        if prelude.statement().manifest().protocol == ProofProtocol::FastBinary64UnitCircleV2 {
            let preflight = FastBackend::preflight(
                &prelude.statement().verifier_statement(),
                prelude.payload(),
            )?;
            if preflight.nonce_mode != FastNonceMode::ExternalSigned {
                return Err(ServiceError::SignedCommitmentChallengeRequired);
            }
            let commitment_challenge = preflight
                .external_challenge
                .as_ref()
                .ok_or(ServiceError::SignedCommitmentChallengeRequired)?;
            commitment_challenge.verify(
                &self.verifying_key(),
                &self.config.issuer,
                &self.config.key_id,
                validation_started_at_unix_seconds,
                self.config.maximum_future_skew_seconds,
            )?;
            require_configured_lifetime(
                commitment_challenge.payload.issued_at_unix_seconds,
                commitment_challenge.payload.expires_at_unix_seconds,
                self.config.challenge_lifetime_seconds,
            )?;
            if commitment_challenge.payload.issued_at_unix_seconds
                < challenge.payload.issued_at_unix_seconds
            {
                return Err(ServiceError::CommitmentBeforeProblemChallenge);
            }
            latest_issue = latest_issue.max(commitment_challenge.payload.issued_at_unix_seconds);
            earliest_expiry =
                earliest_expiry.min(commitment_challenge.payload.expires_at_unix_seconds);
            commitment_challenge_digest = Some(commitment_challenge.digest());
        }

        let report = verify_backend(&prelude)?.accept()?;
        let output = ValidatedOutput {
            summary: prelude.summary(),
            report,
        };
        Ok(ValidatedSubmission {
            output,
            challenge_digest: challenge.digest(),
            commitment_challenge_digest,
            validation_started_at_unix_seconds,
            latest_challenge_issue_unix_seconds: latest_issue,
            earliest_challenge_expiry_unix_seconds: earliest_expiry,
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
        if issued_at_unix_seconds < validated.latest_challenge_issue_unix_seconds {
            return Err(ServiceError::CertificateBeforeChallenge);
        }
        if issued_at_unix_seconds > validated.earliest_challenge_expiry_unix_seconds {
            return Err(ServiceError::ChallengeExpiredDuringValidation);
        }
        let payload = CertificatePayload {
            schema: CertificateSchema::V2,
            issuer: self.config.issuer.clone(),
            key_id: self.config.key_id.clone(),
            issued_at_unix_seconds,
            challenge_digest: Some(validated.challenge_digest),
            commitment_challenge_digest: validated.commitment_challenge_digest,
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
        self.report.report()
    }
}
