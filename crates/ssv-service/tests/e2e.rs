use ed25519_dalek::SigningKey;
use ssv_backends::{BackendVerifierReport, prove_single_stage};
use ssv_canonical::Digest;
use ssv_fast::{FastBackend, FastProverContext};
use ssv_problem::ProblemTemplate;
use ssv_service::{ServiceConfig, ServiceError, StatelessValidatorService};
use ssv_service_protocol::{
    CertifiedScore, CommitmentChallengeRequest, CommitmentChallengeRequestSchema, ProofProtocol,
    SignedChallenge, ValidationManifest,
};
use ssv_solution::Solution;
use ssv_validation::{
    ArtifactPrelude, PrecommitBackend, PublicStatement, ValidationBackend, encode_artifact,
};

fn service() -> StatelessValidatorService {
    StatelessValidatorService::new(
        ServiceConfig {
            issuer: "integration-test".to_owned(),
            key_id: "integration-key-v1".to_owned(),
            challenge_lifetime_seconds: 900,
            maximum_future_skew_seconds: 5,
            maximum_solution_elements: 1024,
            validator_build: "integration-test-build".to_owned(),
        },
        SigningKey::from_bytes(&[7; 32]),
    )
    .unwrap()
}

fn challenge_template() -> ProblemTemplate {
    ProblemTemplate::from_json_slice(include_bytes!("../../../examples/challenge-template.json"))
        .unwrap()
}

fn local_template() -> ProblemTemplate {
    ProblemTemplate::from_json_slice(include_bytes!("../../../examples/local-template.json"))
        .unwrap()
}

fn manifest() -> ValidationManifest {
    ValidationManifest {
        max_solution_elements: 1_024,
        ..ValidationManifest::default()
    }
}

fn statement(
    problem: ssv_problem::FinalizedProblem,
    manifest: ValidationManifest,
    challenge: Option<SignedChallenge>,
) -> PublicStatement {
    PublicStatement::new(problem, manifest, challenge).unwrap()
}

fn single_stage_proof(statement: &PublicStatement, solution: &Solution) -> Vec<u8> {
    let (payload, _) = prove_single_stage(statement, solution).unwrap();
    encode_artifact(statement, &payload).unwrap()
}

#[test]
fn stateless_post_commit_challenge_binds_the_requested_root_digest() {
    let service = service();
    let request = CommitmentChallengeRequest {
        schema: CommitmentChallengeRequestSchema::V1,
        problem_digest: Digest::from_bytes([1; 32]),
        validation_manifest_digest: Digest::from_bytes([2; 32]),
        protocol: ProofProtocol::FastBinary64UnitCircleV2,
        commitment_digest: Digest::from_bytes([3; 32]),
    };
    let challenge = service
        .issue_commitment_challenge(&request, Digest::from_bytes([4; 32]), 1_000)
        .unwrap();
    challenge
        .verify(
            &service.verifying_key(),
            "integration-test",
            "integration-key-v1",
            1_001,
            5,
        )
        .unwrap();
    assert_eq!(
        challenge.payload.commitment_digest,
        request.commitment_digest
    );
    assert_eq!(challenge.payload.problem_digest, request.problem_digest);

    let mut unsupported = request;
    unsupported.protocol = ProofProtocol::WhirField192L2V4;
    assert!(matches!(
        service.issue_commitment_challenge(&unsupported, Digest::from_bytes([5; 32]), 1_000),
        Err(ServiceError::CommitmentChallengeUnsupported)
    ));
}

#[test]
fn hosted_single_problem_flow_signs_the_recomputed_residual() {
    let service = service();
    let template = challenge_template();
    let challenge = service
        .issue_challenge(&template, Digest::from_bytes([9; 32]), 1_000)
        .unwrap();
    let problem = template
        .finalize_with_challenge_context(&challenge.payload_canonical_bytes())
        .unwrap();
    let solution = Solution::new(vec![1.0; problem.dimension() as usize], 16).unwrap();
    assert!(PublicStatement::new(problem.clone(), manifest(), None).is_err());
    let statement = statement(problem, manifest(), Some(challenge.clone()));
    let proof = single_stage_proof(&statement, &solution);
    for length in 0..proof.len() {
        assert!(ArtifactPrelude::parse(&proof[..length]).is_err());
    }

    let certified = service.validate_and_certify(&proof, 1_001, 1_002).unwrap();
    let BackendVerifierReport::Direct(report) = certified.output.backend_report() else {
        panic!("expected direct report");
    };
    assert_eq!(report.residual.squared_l2, 0.0);
    assert_eq!(report.residual.max_abs, 0.0);
    certified
        .certificate
        .verify(
            &service.verifying_key(),
            "integration-test",
            "integration-key-v1",
        )
        .unwrap();
    assert_eq!(
        certified.certificate.payload.proof_digest,
        certified.output.summary.proof_digest
    );

    let mut invalid_challenge = challenge.clone();
    invalid_challenge.payload.issued_at_unix_seconds = -1;
    let invalid_problem = template
        .finalize_with_challenge_context(&invalid_challenge.payload_canonical_bytes())
        .unwrap();
    assert!(PublicStatement::new(invalid_problem, manifest(), Some(invalid_challenge)).is_err());

    let validated = service.validate_submission(&proof, 1_001).unwrap();
    assert!(matches!(
        service.certify(validated.clone(), 1_000),
        Err(ServiceError::CertificateBeforeValidation)
    ));
    assert!(matches!(
        service.certify(validated, 1_901),
        Err(ServiceError::ChallengeExpiredDuringValidation)
    ));
}

#[test]
fn service_rejects_expired_malformed_and_literal_submissions() {
    let service = service();
    let template = challenge_template();
    let challenge = service
        .issue_challenge(&template, Digest::from_bytes([9; 32]), 1_000)
        .unwrap();
    let problem = template
        .finalize_with_challenge_context(&challenge.payload_canonical_bytes())
        .unwrap();
    let solution = Solution::new(vec![1.0; 16], 16).unwrap();
    let hosted_statement = statement(problem.clone(), manifest(), Some(challenge.clone()));
    let proof = single_stage_proof(&hosted_statement, &solution);
    assert!(service.validate_and_certify(&proof, 1_901, 1_902).is_err());

    let mut trailing = proof.clone();
    trailing.push(0);
    assert!(
        service
            .validate_and_certify(&trailing, 1_001, 1_002)
            .is_err()
    );

    let local_problem = local_template().finalize_literal().unwrap();
    let local_statement = statement(local_problem, manifest(), None);
    let local_proof = single_stage_proof(&local_statement, &solution);
    assert!(matches!(
        service.validate_and_certify(&local_proof, 1_001, 1_002),
        Err(ServiceError::SignedChallengeRequired)
    ));
    let local_prelude = ArtifactPrelude::parse(&local_proof).unwrap();
    let BackendVerifierReport::Direct(local_report) = ssv_backends::verify(&local_prelude).unwrap()
    else {
        panic!("expected direct report");
    };
    assert_eq!(local_report.residual.squared_l2, 0.0);

    let relaxed_manifest = ValidationManifest {
        max_solution_elements: 2_048,
        ..ValidationManifest::default()
    };
    let over_policy_statement = statement(problem, relaxed_manifest, Some(challenge));
    let over_policy = single_stage_proof(&over_policy_statement, &solution);
    assert!(service.validate_submission(&over_policy, 1_001).is_err());
}

#[test]
fn challenge_cannot_be_rebound_to_another_template() {
    let service = service();
    let template = challenge_template();
    let challenge = service
        .issue_challenge(&template, Digest::from_bytes([9; 32]), 1_000)
        .unwrap();
    let mut other_json = include_bytes!("../../../examples/challenge-template.json").to_vec();
    let position = other_json
        .windows(b"\"dimension\": 16".len())
        .position(|window| window == b"\"dimension\": 16")
        .unwrap();
    other_json[position..position + b"\"dimension\": 16".len()]
        .copy_from_slice(b"\"dimension\": 17");
    let other = ProblemTemplate::from_json_slice(&other_json).unwrap();
    assert_ne!(template.digest().unwrap(), other.digest().unwrap());
    assert_ne!(
        challenge.payload.problem_template_digest,
        Digest::from_bytes(other.digest().unwrap().into_bytes())
    );
}

#[test]
fn certificate_cannot_predate_a_skew_tolerated_challenge() {
    let service = service();
    let template = challenge_template();
    let challenge = service
        .issue_challenge(&template, Digest::from_bytes([4; 32]), 1_004)
        .unwrap();
    let problem = template
        .finalize_with_challenge_context(&challenge.payload_canonical_bytes())
        .unwrap();
    let solution = Solution::new(vec![1.0; 16], 16).unwrap();
    let statement = statement(problem, manifest(), Some(challenge));
    let proof = single_stage_proof(&statement, &solution);
    let validated = service.validate_submission(&proof, 1_000).unwrap();
    assert!(matches!(
        service.certify(validated, 1_000),
        Err(ServiceError::CertificateBeforeChallenge)
    ));
}

#[test]
fn hosted_exact_backend_returns_an_exact_dyadic_certificate() {
    let service = service();
    let template = challenge_template();
    let challenge = service
        .issue_challenge(&template, Digest::from_bytes([21; 32]), 1_000)
        .unwrap();
    let problem = template
        .finalize_with_challenge_context(&challenge.payload_canonical_bytes())
        .unwrap();
    let exact_manifest = ValidationManifest {
        protocol: ProofProtocol::WhirField192L2V4,
        max_solution_elements: 1_024,
        ..ValidationManifest::default()
    };
    let statement = statement(problem, exact_manifest, Some(challenge));
    let solution = Solution::new(vec![1.0; 16], 16).unwrap();
    let proof = single_stage_proof(&statement, &solution);
    let certified = service.validate_and_certify(&proof, 1_001, 1_002).unwrap();
    assert!(matches!(
        certified.output.backend_report(),
        BackendVerifierReport::Exact(_)
    ));
    assert!(matches!(
        certified.certificate.payload.score,
        CertifiedScore::ExactDyadicSquaredL2V1 {
            denominator_power: 144,
            ..
        }
    ));
}

#[test]
fn hosted_fast_backend_requires_and_certifies_the_post_commit_challenge() {
    let service = service();
    let template = challenge_template();
    let problem_challenge = service
        .issue_challenge(&template, Digest::from_bytes([31; 32]), 1_000)
        .unwrap();
    let problem = template
        .finalize_with_challenge_context(&problem_challenge.payload_canonical_bytes())
        .unwrap();
    let fast_manifest = ValidationManifest {
        protocol: ProofProtocol::FastBinary64UnitCircleV2,
        max_solution_elements: 1_024,
        ..ValidationManifest::default()
    };
    let statement = statement(problem, fast_manifest, Some(problem_challenge));
    let solution = Solution::new(vec![1.0; 16], 16).unwrap();
    let (commitment, _) = <FastBackend as PrecommitBackend>::commit(&statement, &solution).unwrap();
    let request = CommitmentChallengeRequest {
        schema: CommitmentChallengeRequestSchema::V1,
        problem_digest: statement.problem_digest(),
        validation_manifest_digest: statement.manifest_digest(),
        protocol: ProofProtocol::FastBinary64UnitCircleV2,
        commitment_digest: commitment.digest(),
    };
    let commitment_challenge = service
        .issue_commitment_challenge(&request, Digest::from_bytes([32; 32]), 1_001)
        .unwrap();
    let context = FastProverContext::external_signed(commitment, commitment_challenge.clone());
    let (payload, _) =
        <FastBackend as ValidationBackend>::prove(&statement, &solution, &context).unwrap();
    let proof = encode_artifact(&statement, &payload).unwrap();
    let certified = service.validate_and_certify(&proof, 1_002, 1_003).unwrap();
    assert_eq!(
        certified.certificate.payload.commitment_challenge_digest,
        Some(commitment_challenge.digest())
    );
    assert!(matches!(
        certified.certificate.payload.score,
        CertifiedScore::FastBinary64SquaredL2V1 { .. }
    ));

    let (offline_commitment, _) = FastBackend::commit_offline(&statement, &solution).unwrap();
    let offline_context = FastProverContext::offline_fiat_shamir(offline_commitment);
    let (offline_payload, _) =
        <FastBackend as ValidationBackend>::prove(&statement, &solution, &offline_context).unwrap();
    let offline_proof = encode_artifact(&statement, &offline_payload).unwrap();
    assert!(matches!(
        service.validate_submission(&offline_proof, 1_002),
        Err(ServiceError::SignedCommitmentChallengeRequired)
    ));
}
