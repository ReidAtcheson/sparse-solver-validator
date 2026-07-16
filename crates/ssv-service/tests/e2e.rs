use ed25519_dalek::SigningKey;
use ssv_canonical::Digest;
use ssv_direct::DirectArtifact;
use ssv_problem::ProblemTemplate;
use ssv_service::{ServiceConfig, ServiceError, StatelessValidatorService};
use ssv_service_protocol::ValidationManifest;
use ssv_solution::Solution;

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
    assert!(DirectArtifact::create(&problem, &manifest(), None, &solution).is_err());
    let proof = DirectArtifact::create(&problem, &manifest(), Some(&challenge), &solution).unwrap();
    for length in 0..proof.len() {
        assert!(DirectArtifact::from_bytes(&proof[..length]).is_err());
    }

    let certified = service.validate_and_certify(&proof, 1_001, 1_002).unwrap();
    assert_eq!(certified.output.residual.squared_l2, 0.0);
    assert_eq!(certified.output.residual.max_abs, 0.0);
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
        certified.output.proof_digest
    );

    let mut invalid_challenge = challenge.clone();
    invalid_challenge.payload.issued_at_unix_seconds = -1;
    let invalid_problem = template
        .finalize_with_challenge_context(&invalid_challenge.payload_canonical_bytes())
        .unwrap();
    assert!(
        DirectArtifact::create(
            &invalid_problem,
            &manifest(),
            Some(&invalid_challenge),
            &solution,
        )
        .is_err()
    );

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
    let proof = DirectArtifact::create(&problem, &manifest(), Some(&challenge), &solution).unwrap();
    assert!(service.validate_and_certify(&proof, 1_901, 1_902).is_err());

    let mut trailing = proof.clone();
    trailing.push(0);
    assert!(
        service
            .validate_and_certify(&trailing, 1_001, 1_002)
            .is_err()
    );

    let local_problem = local_template().finalize_literal().unwrap();
    let local_proof = DirectArtifact::create(&local_problem, &manifest(), None, &solution).unwrap();
    assert!(matches!(
        service.validate_and_certify(&local_proof, 1_001, 1_002),
        Err(ServiceError::SignedChallengeRequired)
    ));
    assert_eq!(
        DirectArtifact::from_bytes(&local_proof)
            .unwrap()
            .verify_relation()
            .unwrap()
            .residual
            .squared_l2,
        0.0
    );

    let relaxed_manifest = ValidationManifest {
        max_solution_elements: 2_048,
        ..ValidationManifest::default()
    };
    let over_policy =
        DirectArtifact::create(&problem, &relaxed_manifest, Some(&challenge), &solution).unwrap();
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
    let proof = DirectArtifact::create(&problem, &manifest(), Some(&challenge), &solution).unwrap();
    let validated = service.validate_submission(&proof, 1_000).unwrap();
    assert!(matches!(
        service.certify(validated, 1_000),
        Err(ServiceError::CertificateBeforeChallenge)
    ));
}
