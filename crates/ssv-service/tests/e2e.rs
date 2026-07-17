use ed25519_dalek::SigningKey;
use ssv_backends::{BackendProverReport, BackendVerifierReport, prove_single_stage};
use ssv_canonical::Digest;
use ssv_problem::ProblemTemplate;
use ssv_service::{ServiceConfig, ServiceError, StatelessValidatorService};
use ssv_service_protocol::{CertifiedScore, ProofProtocol, SignedChallenge, ValidationManifest};
use ssv_solution::Solution;
use ssv_validation::{ArtifactPrelude, PublicStatement, encode_artifact};

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
fn hosted_fast_and_exact_followup_share_the_signed_problem_header() {
    let service = service();
    let template = challenge_template();
    let problem_challenge = service
        .issue_challenge(&template, Digest::from_bytes([31; 32]), 1_000)
        .unwrap();
    let expected_challenge_digest = problem_challenge.digest();
    let problem = template
        .finalize_with_challenge_context(&problem_challenge.payload_canonical_bytes())
        .unwrap();
    let fast_manifest = ValidationManifest {
        protocol: ProofProtocol::FastBinary64UnitCircleV4,
        max_solution_elements: 1_024,
        ..ValidationManifest::default()
    };
    let fast_statement = statement(
        problem.clone(),
        fast_manifest,
        Some(problem_challenge.clone()),
    );
    let solution = Solution::new(vec![1.0; 16], 16).unwrap();
    let (fast_payload, fast_prover_report) =
        prove_single_stage(&fast_statement, &solution).unwrap();
    let BackendProverReport::Fast(fast_prover_report) = fast_prover_report else {
        panic!("expected fast prover report");
    };
    let fast_proof = encode_artifact(&fast_statement, &fast_payload).unwrap();
    let fast_certificate = service
        .validate_and_certify(&fast_proof, 1_001, 1_002)
        .unwrap();
    assert_eq!(
        fast_certificate.certificate.payload.challenge_digest,
        expected_challenge_digest
    );
    let CertifiedScore::FastBinary64DiagnosticsV1 {
        squared_l2_claim,
        consistency,
    } = &fast_certificate.certificate.payload.score
    else {
        panic!("expected fast diagnostic score");
    };
    assert_eq!(*squared_l2_claim, 0.0);
    assert_eq!(consistency.norm_sumcheck.zero_scale, 2.0_f64.powi(-84));
    assert_eq!(consistency.matvec_sumcheck.zero_scale, 2.0_f64.powi(-42));
    assert_eq!(consistency.linear_opening.zero_scale, 2.0_f64.powi(-42));
    assert_eq!(consistency.unit_circle_folds.zero_scale, 2.0_f64.powi(-38));
    for metrics in [
        consistency.norm_sumcheck,
        consistency.matvec_sumcheck,
        consistency.linear_opening,
        consistency.unit_circle_folds,
    ] {
        assert!(metrics.checks > 0);
        assert!(metrics.maximum_relative_error.is_finite());
        assert!(metrics.rms_relative_error.is_finite());
    }
    let BackendVerifierReport::Fast(fast_report) = fast_certificate.output.backend_report() else {
        panic!("expected fast verifier report");
    };
    for (certified, verified) in [
        (
            consistency.public_rhs_roundoff,
            fast_report.public_evaluations.rhs,
        ),
        (
            consistency.public_matrix_roundoff,
            fast_report.public_evaluations.matrix,
        ),
    ] {
        assert_eq!(
            certified.forward_absolute_error_bound,
            verified.forward_absolute_error_bound
        );
        assert_eq!(
            certified.maximum_absolute_source,
            verified.maximum_absolute_source
        );
        assert_eq!(
            certified.maximum_absolute_intermediate,
            verified.maximum_absolute_intermediate
        );
    }
    let certificate_json = serde_json::to_value(&fast_certificate.certificate).unwrap();
    let certificate_payload = certificate_json.get("payload").unwrap();
    assert_eq!(
        certificate_payload.get("schema").unwrap(),
        "sparse-solve/validation-certificate/v4"
    );

    let root_offset = fast_proof
        .windows(fast_prover_report.packed_codeword_root.len())
        .position(|window| window == fast_prover_report.packed_codeword_root)
        .expect("artifact contains its transcript-bound packed root");
    let mut invalid_root = fast_proof.clone();
    invalid_root[root_offset] ^= 1;
    assert!(service.validate_submission(&invalid_root, 1_001).is_err());

    let exact_manifest = ValidationManifest {
        protocol: ProofProtocol::WhirField192L2V4,
        max_solution_elements: 1_024,
        ..ValidationManifest::default()
    };
    let exact_statement = statement(problem, exact_manifest, Some(problem_challenge));
    let exact_proof = single_stage_proof(&exact_statement, &solution);
    let exact_certificate = service
        .validate_and_certify(&exact_proof, 1_001, 1_002)
        .unwrap();
    assert_eq!(
        exact_certificate.certificate.payload.challenge_digest,
        expected_challenge_digest
    );
    assert!(matches!(
        exact_certificate.certificate.payload.score,
        CertifiedScore::ExactDyadicSquaredL2V1 { .. }
    ));
}
