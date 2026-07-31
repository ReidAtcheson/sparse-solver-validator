use ed25519_dalek::SigningKey;
use ssv_backends::{BackendProverReport, BackendVerifierReport, prove_single_stage, verify};
use ssv_canonical::Digest;
use ssv_problem::{
    BoundaryRule, GeneratedProblem, MatrixSpec, ProblemTemplate, RhsSpec, SymmetricDiaEdge,
};
use ssv_service::{ServiceConfig, ServiceError, StatelessValidatorService, ValidationCancellation};
use ssv_service_protocol::{
    CertifiedScore, MAX_ID_BYTES, MAX_PUBLIC_EVALUATION_TERMS_LIMIT, ProofProtocol, ProtocolError,
    SignedChallenge, ValidationManifest,
};
use ssv_solution::Solution;
use ssv_validation::{ArtifactPrelude, PublicStatement, ValidationError, encode_artifact};

fn service_config() -> ServiceConfig {
    ServiceConfig {
        issuer: "integration-test".to_owned(),
        key_id: "integration-key-v1".to_owned(),
        challenge_lifetime_seconds: 900,
        maximum_future_skew_seconds: 5,
        maximum_solution_elements: 1024,
        maximum_public_matrix_terms: 4096,
        maximum_public_rhs_terms: 4096,
        allowed_protocols: vec![
            ProofProtocol::DirectReferenceV1,
            ProofProtocol::WhirField192L2V4,
            ProofProtocol::FastBinary64UnitCircleV5,
        ],
        validator_build: "integration-test-build".to_owned(),
    }
}

fn service() -> StatelessValidatorService {
    StatelessValidatorService::new(service_config(), SigningKey::from_bytes(&[7; 32])).unwrap()
}

fn challenge_template() -> ProblemTemplate {
    ProblemTemplate::from_json_slice(include_bytes!("../../../examples/challenge-template.json"))
        .unwrap()
}

fn local_template() -> ProblemTemplate {
    ProblemTemplate::from_json_slice(include_bytes!("../../../examples/local-template.json"))
        .unwrap()
}

fn seeded_rhs_challenge_template() -> ProblemTemplate {
    let mut template = challenge_template();
    template.rhs = RhsSpec::SeededPeriodicDyadicV1 {
        period_bits: 3,
        fractional_bits: 8,
        minimum_mantissa: -4,
        maximum_mantissa: 7,
    };
    template
}

fn dia_seeded_rhs_local_template() -> ProblemTemplate {
    let mut template = local_template();
    template.matrix = MatrixSpec::SeededSymmetricDiaLaplacianV1 {
        dimension: 8,
        boundary: BoundaryRule::TruncateV1,
        fractional_bits: 8,
        diagonal_shift_mantissa: 64,
        edge_diagonals: vec![
            SymmetricDiaEdge {
                positive_offset: 1,
                period_bits: 2,
                minimum_weight_mantissa: 2,
                maximum_weight_mantissa: 7,
            },
            SymmetricDiaEdge {
                positive_offset: 3,
                period_bits: 1,
                minimum_weight_mantissa: 1,
                maximum_weight_mantissa: 5,
            },
        ],
    };
    template.rhs = RhsSpec::SeededPeriodicDyadicV1 {
        period_bits: 3,
        fractional_bits: 8,
        minimum_mantissa: -16,
        maximum_mantissa: 19,
    };
    template
}

fn nonsymmetric_seeded_rhs_local_template() -> ProblemTemplate {
    let mut template = local_template();
    template.matrix = MatrixSpec::SeededNonsymmetricRowSparseV1 {
        dimension: 12,
        boundary: BoundaryRule::TruncateV1,
        row_pattern_bits: 3,
        maximum_half_bandwidth: 5,
        maximum_nonzeros_per_row: 7,
        fractional_bits: 12,
        minimum_mantissa: -4096,
        maximum_mantissa: 4096,
    };
    template.rhs = RhsSpec::SeededPeriodicDyadicV1 {
        period_bits: 3,
        fractional_bits: 12,
        minimum_mantissa: -2048,
        maximum_mantissa: 2047,
    };
    template
}

fn conjugate_gradient_solution(problem: &GeneratedProblem) -> Solution {
    fn dot(left: &[f64], right: &[f64]) -> f64 {
        left.iter()
            .zip(right)
            .map(|(&left, &right)| left * right)
            .sum()
    }

    fn apply(problem: &GeneratedProblem, input: &[f64]) -> Vec<f64> {
        problem
            .rows()
            .map(|row| {
                row.map(|entry| entry.value.to_f64() * input[entry.column])
                    .sum()
            })
            .collect()
    }

    let dimension = problem.dimension();
    let mut solution = vec![0.0; dimension];
    let mut residual = (0..dimension)
        .map(|row| problem.rhs_f64(row).unwrap())
        .collect::<Vec<_>>();
    let mut direction = residual.clone();
    let initial_squared_norm = dot(&residual, &residual);
    let target_squared_norm = initial_squared_norm.max(1.0) * 1.0e-28;
    let mut squared_norm = initial_squared_norm;
    if squared_norm <= target_squared_norm {
        return Solution::new(solution, dimension).unwrap();
    }
    for _ in 0..4 * dimension {
        let image = apply(problem, &direction);
        let denominator = dot(&direction, &image);
        assert!(denominator > 0.0, "the generated DIA matrix must be SPD");
        let step = squared_norm / denominator;
        for ((solution, residual), (&direction, &image)) in solution
            .iter_mut()
            .zip(&mut residual)
            .zip(direction.iter().zip(&image))
        {
            *solution += step * direction;
            *residual -= step * image;
        }
        let next_squared_norm = dot(&residual, &residual);
        if next_squared_norm <= target_squared_norm {
            return Solution::new(solution, dimension).unwrap();
        }
        let beta = next_squared_norm / squared_norm;
        for (direction, &residual) in direction.iter_mut().zip(&residual) {
            *direction = residual + beta * *direction;
        }
        squared_norm = next_squared_norm;
    }
    panic!("conjugate gradient did not converge on the shifted DIA system");
}

fn pivoted_dense_solution(problem: &GeneratedProblem) -> Solution {
    let dimension = problem.dimension();
    let mut matrix = vec![0.0; dimension * dimension];
    for (row_index, row) in problem.rows().enumerate() {
        for entry in row {
            matrix[row_index * dimension + entry.column] = entry.value.to_f64();
        }
    }
    let mut rhs = (0..dimension)
        .map(|row| problem.rhs_f64(row).unwrap())
        .collect::<Vec<_>>();

    for column in 0..dimension {
        let pivot = (column..dimension)
            .max_by(|&left, &right| {
                matrix[left * dimension + column]
                    .abs()
                    .total_cmp(&matrix[right * dimension + column].abs())
            })
            .unwrap();
        let pivot_magnitude = matrix[pivot * dimension + column].abs();
        assert!(
            pivot_magnitude > 1.0e-12,
            "fixed generated test matrix is singular"
        );
        if pivot != column {
            for entry_column in 0..dimension {
                matrix.swap(
                    column * dimension + entry_column,
                    pivot * dimension + entry_column,
                );
            }
            rhs.swap(column, pivot);
        }
        let diagonal = matrix[column * dimension + column];
        for row in column + 1..dimension {
            let factor = matrix[row * dimension + column] / diagonal;
            matrix[row * dimension + column] = 0.0;
            for entry_column in column + 1..dimension {
                matrix[row * dimension + entry_column] -=
                    factor * matrix[column * dimension + entry_column];
            }
            rhs[row] -= factor * rhs[column];
        }
    }

    let mut solution = vec![0.0; dimension];
    for row in (0..dimension).rev() {
        let known = (row + 1..dimension)
            .map(|column| matrix[row * dimension + column] * solution[column])
            .sum::<f64>();
        solution[row] = (rhs[row] - known) / matrix[row * dimension + row];
    }
    Solution::new(solution, dimension).unwrap()
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

fn empty_challenged_artifact(
    issuer: &StatelessValidatorService,
    template: &ProblemTemplate,
    manifest: ValidationManifest,
) -> Vec<u8> {
    let challenge = issuer
        .issue_challenge(template, Digest::from_bytes([39; 32]), 1_000)
        .unwrap();
    let problem = template
        .finalize_with_challenge_context(&challenge.payload_canonical_bytes())
        .unwrap();
    let statement = statement(problem, manifest, Some(challenge));
    encode_artifact(&statement, &[]).unwrap()
}

fn replace_once(encoded: &mut [u8], original: &[u8], replacement: &[u8]) {
    assert_eq!(original.len(), replacement.len());
    let position = encoded
        .windows(original.len())
        .position(|window| window == original)
        .unwrap();
    encoded[position..position + original.len()].copy_from_slice(replacement);
}

#[test]
fn service_rejects_validator_builds_that_are_invalid_in_certificates() {
    for invalid in [
        "",
        "contains space",
        "line\nbreak",
        "\u{7f}",
        "non-ascii-\u{e9}",
    ] {
        let mut config = service_config();
        config.validator_build = invalid.to_owned();
        assert!(matches!(
            StatelessValidatorService::new(config, SigningKey::from_bytes(&[7; 32])),
            Err(ServiceError::Protocol(ProtocolError::InvalidIdentifier {
                field: "validator_build"
            }))
        ));
    }

    let mut oversized = service_config();
    oversized.validator_build = "x".repeat(MAX_ID_BYTES + 1);
    assert!(matches!(
        StatelessValidatorService::new(oversized, SigningKey::from_bytes(&[7; 32])),
        Err(ServiceError::Protocol(ProtocolError::InvalidIdentifier {
            field: "validator_build"
        }))
    ));

    let mut maximum = service_config();
    maximum.validator_build = "x".repeat(MAX_ID_BYTES);
    assert!(StatelessValidatorService::new(maximum, SigningKey::from_bytes(&[7; 32])).is_ok());
}

#[test]
fn service_rejects_invalid_deployment_policy() {
    for (matrix_terms, rhs_terms) in [
        (0, 1),
        (1, 0),
        (MAX_PUBLIC_EVALUATION_TERMS_LIMIT + 1, 1),
        (1, MAX_PUBLIC_EVALUATION_TERMS_LIMIT + 1),
    ] {
        let mut config = service_config();
        config.maximum_public_matrix_terms = matrix_terms;
        config.maximum_public_rhs_terms = rhs_terms;
        assert!(matches!(
            StatelessValidatorService::new(config, SigningKey::from_bytes(&[7; 32])),
            Err(ServiceError::InvalidConfiguration(_))
        ));
    }

    let mut config = service_config();
    config.allowed_protocols.clear();
    assert!(matches!(
        StatelessValidatorService::new(config, SigningKey::from_bytes(&[7; 32])),
        Err(ServiceError::InvalidConfiguration(_))
    ));
}

#[test]
fn cancelled_validation_stops_before_artifact_parsing() {
    let cancellation = ValidationCancellation::new();
    cancellation.cancel();
    assert!(matches!(
        service().validate_submission_with_cancellation(
            b"not a validation artifact",
            1_001,
            &cancellation
        ),
        Err(ServiceError::ValidationCancelled)
    ));
}

#[test]
fn challenge_issuance_enforces_deployment_evaluator_limits() {
    let mut matrix_config = service_config();
    matrix_config.maximum_public_matrix_terms = 7;
    let matrix_limited =
        StatelessValidatorService::new(matrix_config, SigningKey::from_bytes(&[7; 32])).unwrap();
    assert!(matches!(
        matrix_limited.issue_challenge(&challenge_template(), Digest::from_bytes([40; 32]), 1_000),
        Err(ServiceError::PublicEvaluationLimit)
    ));

    let mut rhs_config = service_config();
    rhs_config.maximum_public_rhs_terms = 7;
    let rhs_limited =
        StatelessValidatorService::new(rhs_config, SigningKey::from_bytes(&[7; 32])).unwrap();
    assert!(matches!(
        rhs_limited.issue_challenge(
            &seeded_rhs_challenge_template(),
            Digest::from_bytes([41; 32]),
            1_000
        ),
        Err(ServiceError::PublicEvaluationLimit)
    ));
}

#[test]
fn artifact_admission_rechecks_deployment_evaluator_limits() {
    let issuer = service();
    let mut matrix_artifact = empty_challenged_artifact(
        &issuer,
        &challenge_template(),
        ValidationManifest {
            max_solution_elements: 1_024,
            max_public_matrix_terms: 8,
            max_public_rhs_terms: 1,
            ..ValidationManifest::default()
        },
    );
    replace_once(
        &mut matrix_artifact,
        b"\"max_public_matrix_terms\":8",
        b"\"max_public_matrix_terms\":7",
    );
    let mut matrix_config = service_config();
    matrix_config.maximum_public_matrix_terms = 7;
    let matrix_limited =
        StatelessValidatorService::new(matrix_config, SigningKey::from_bytes(&[7; 32])).unwrap();
    assert!(matches!(
        matrix_limited.validate_submission(&matrix_artifact, 1_001),
        Err(ServiceError::Artifact(
            ValidationError::PublicEvaluationLimit
        ))
    ));

    let mut rhs_artifact = empty_challenged_artifact(
        &issuer,
        &seeded_rhs_challenge_template(),
        ValidationManifest {
            max_solution_elements: 1_024,
            max_public_matrix_terms: 8,
            max_public_rhs_terms: 8,
            ..ValidationManifest::default()
        },
    );
    replace_once(
        &mut rhs_artifact,
        b"\"max_public_rhs_terms\":8",
        b"\"max_public_rhs_terms\":7",
    );
    let mut rhs_config = service_config();
    rhs_config.maximum_public_rhs_terms = 7;
    let rhs_limited =
        StatelessValidatorService::new(rhs_config, SigningKey::from_bytes(&[7; 32])).unwrap();
    assert!(matches!(
        rhs_limited.validate_submission(&rhs_artifact, 1_001),
        Err(ServiceError::Artifact(
            ValidationError::PublicEvaluationLimit
        ))
    ));
}

#[test]
fn manifest_cannot_raise_deployment_evaluator_limits() {
    let issuer = service();
    let template = challenge_template();
    let challenge = issuer
        .issue_challenge(&template, Digest::from_bytes([42; 32]), 1_000)
        .unwrap();
    let problem = template
        .finalize_with_challenge_context(&challenge.payload_canonical_bytes())
        .unwrap();
    let mut config = service_config();
    config.maximum_public_matrix_terms = 8;
    config.maximum_public_rhs_terms = 1;
    let restricted =
        StatelessValidatorService::new(config, SigningKey::from_bytes(&[7; 32])).unwrap();

    for manifest in [
        ValidationManifest {
            max_solution_elements: 1_024,
            max_public_matrix_terms: 9,
            max_public_rhs_terms: 1,
            ..ValidationManifest::default()
        },
        ValidationManifest {
            max_solution_elements: 1_024,
            max_public_matrix_terms: 8,
            max_public_rhs_terms: 2,
            ..ValidationManifest::default()
        },
    ] {
        let statement = statement(problem.clone(), manifest, Some(challenge.clone()));
        let artifact = encode_artifact(&statement, &[]).unwrap();
        assert!(matches!(
            restricted.validate_submission(&artifact, 1_001),
            Err(ServiceError::Artifact(
                ValidationError::PublicEvaluationLimit
            ))
        ));
    }
}

#[test]
fn every_disallowed_protocol_is_rejected_before_backend_verification() {
    let issuer = service();
    let template = challenge_template();
    let challenge = issuer
        .issue_challenge(&template, Digest::from_bytes([43; 32]), 1_000)
        .unwrap();
    let problem = template
        .finalize_with_challenge_context(&challenge.payload_canonical_bytes())
        .unwrap();

    for (protocol, allowed_protocols) in [
        (
            ProofProtocol::DirectReferenceV1,
            vec![ProofProtocol::WhirField192L2V4],
        ),
        (
            ProofProtocol::WhirField192L2V4,
            vec![ProofProtocol::FastBinary64UnitCircleV5],
        ),
        (
            ProofProtocol::FastBinary64UnitCircleV5,
            vec![ProofProtocol::DirectReferenceV1],
        ),
    ] {
        let artifact = encode_artifact(
            &statement(
                problem.clone(),
                ValidationManifest {
                    protocol,
                    max_solution_elements: 1_024,
                    max_public_matrix_terms: 8,
                    max_public_rhs_terms: 1,
                    ..ValidationManifest::default()
                },
                Some(challenge.clone()),
            ),
            &[],
        )
        .unwrap();
        let mut config = service_config();
        config.maximum_public_matrix_terms = 8;
        config.maximum_public_rhs_terms = 1;
        config.allowed_protocols = allowed_protocols;
        let restricted =
            StatelessValidatorService::new(config, SigningKey::from_bytes(&[7; 32])).unwrap();

        assert!(matches!(
            restricted.validate_submission(&artifact, 1_001),
            Err(ServiceError::ProtocolNotAllowed {
                protocol: rejected
            }) if rejected == protocol
        ));
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
        protocol: ProofProtocol::FastBinary64UnitCircleV5,
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

#[test]
fn dia_family_with_seeded_rhs_round_trips_every_backend_without_a_manufactured_solution() {
    let problem = dia_seeded_rhs_local_template().finalize_literal().unwrap();
    assert!(matches!(
        problem.rhs,
        RhsSpec::SeededPeriodicDyadicV1 { .. }
    ));
    let generated = problem.compile().unwrap();
    let solution = conjugate_gradient_solution(&generated);

    for protocol in [
        ProofProtocol::DirectReferenceV1,
        ProofProtocol::WhirField192L2V4,
        ProofProtocol::FastBinary64UnitCircleV5,
    ] {
        let statement = statement(
            problem.clone(),
            ValidationManifest {
                protocol,
                max_solution_elements: 8,
                max_public_matrix_terms: 64,
                max_public_rhs_terms: 64,
                ..ValidationManifest::default()
            },
            None,
        );
        let artifact = single_stage_proof(&statement, &solution);
        let prelude = ArtifactPrelude::parse(&artifact).unwrap();
        match verify(&prelude).unwrap() {
            BackendVerifierReport::Direct(report) => {
                assert_eq!(protocol, ProofProtocol::DirectReferenceV1);
                assert!(report.residual.l2 < 1.0e-12);
                assert_eq!(report.rows_visited, 8);
                assert_eq!(report.nonzeros_visited, 32);
            }
            BackendVerifierReport::Exact(report) => {
                assert_eq!(protocol, ProofProtocol::WhirField192L2V4);
                assert!(report.residual.l2_approx().unwrap() < 1.0e-12);
                assert_eq!(report.algebra.generator_row_queries, 0);
            }
            BackendVerifierReport::Fast(report) => {
                assert_eq!(protocol, ProofProtocol::FastBinary64UnitCircleV5);
                assert!(report.score.squared_l2_claim < 1.0e-20);
                assert_eq!(report.work.public_matrix_period_terms, 6);
                assert_eq!(report.work.generator_row_queries, 0);
            }
        }
    }
}

#[test]
fn nonsymmetric_generated_pattern_family_round_trips_every_backend() {
    let problem = nonsymmetric_seeded_rhs_local_template()
        .finalize_literal()
        .unwrap();
    assert!(matches!(
        problem.rhs,
        RhsSpec::SeededPeriodicDyadicV1 { .. }
    ));
    let generated = problem.compile().unwrap();
    assert!(!generated.certificate().symmetric);
    assert!(!generated.certificate().strictly_row_diagonally_dominant);
    assert_eq!(generated.certificate().maximum_half_bandwidth, 5);
    assert_eq!(generated.certificate().maximum_nonzeros_per_row, 7);
    let solution = pivoted_dense_solution(&generated);

    for protocol in [
        ProofProtocol::DirectReferenceV1,
        ProofProtocol::WhirField192L2V4,
        ProofProtocol::FastBinary64UnitCircleV5,
    ] {
        let statement = statement(
            problem.clone(),
            ValidationManifest {
                protocol,
                max_solution_elements: 12,
                max_public_matrix_terms: 64,
                max_public_rhs_terms: 64,
                ..ValidationManifest::default()
            },
            None,
        );
        let artifact = single_stage_proof(&statement, &solution);
        let prelude = ArtifactPrelude::parse(&artifact).unwrap();
        match verify(&prelude).unwrap() {
            BackendVerifierReport::Direct(report) => {
                assert_eq!(protocol, ProofProtocol::DirectReferenceV1);
                assert!(report.residual.l2 < 1.0e-10);
                assert_eq!(report.rows_visited, 12);
                assert_eq!(
                    report.nonzeros_visited,
                    u64::try_from(generated.structural_nonzeros())
                        .expect("test nonzero count fits u64")
                );
            }
            BackendVerifierReport::Exact(report) => {
                assert_eq!(protocol, ProofProtocol::WhirField192L2V4);
                assert!(report.residual.l2_approx().unwrap() < 1.0e-10);
                assert_eq!(report.algebra.generator_row_queries, 0);
            }
            BackendVerifierReport::Fast(report) => {
                assert_eq!(protocol, ProofProtocol::FastBinary64UnitCircleV5);
                assert!(report.score.squared_l2_claim < 1.0e-18);
                assert_eq!(report.work.public_matrix_period_terms, 56);
                assert_eq!(report.work.generator_row_queries, 0);
            }
        }
    }
}
