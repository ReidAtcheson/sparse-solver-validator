use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use ssv_backends::{BackendVerifierReport, prove_single_stage, verify as verify_backend};
use ssv_canonical::{Digest, domain_separated_digest};
use ssv_problem::FinalizedProblem;
use ssv_service_protocol::{SignedCertificate, SignedChallenge};
use ssv_solution::Solution;
use ssv_validation::{ArtifactPrelude, MAX_ARTIFACT_BYTES, PublicStatement, encode_artifact};

use crate::files::{
    MAX_RUN_JSON_BYTES, RunLock, RunPaths, create_run_directory, read_bounded, read_json,
    write_bytes_atomic, write_json_atomic, write_matrix_market_matrix, write_matrix_market_rhs,
};
use crate::model::{
    AuthorityConfig, BenchmarkConfig, CardAuthorityEvidence, Materialization, ProblemSummary,
    RemoteAuthorityRef, ResultCard, ResultCardSchema, RunStage, RunState,
};
use crate::remote::{HttpRemoteApi, RemoteApi};

const SOLUTION_FILE_DIGEST_DOMAIN: &[u8] = b"sparse-solve/benchmark-solution-file/v1";
const MAX_CERTIFICATE_JSON_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn start(
    config_path: &Path,
    runs_dir: &Path,
    materialization: Materialization,
) -> Result<PathBuf> {
    let api = HttpRemoteApi::new()?;
    start_with_api(config_path, runs_dir, materialization, &api)
}

fn start_with_api(
    config_path: &Path,
    runs_dir: &Path,
    materialization: Materialization,
    api: &impl RemoteApi,
) -> Result<PathBuf> {
    let config: BenchmarkConfig = read_json(config_path, MAX_RUN_JSON_BYTES)?;
    config.validate()?;
    let now = now_unix_seconds()?;
    let paths = create_run_directory(runs_dir, now)?;
    println!("created_run_directory={}", paths.root.display());
    let _lock = RunLock::acquire(&paths)?;
    write_json_atomic(&paths.benchmark(), &config)?;
    let mut state = RunState::new(config.digest()?, materialization, now);
    write_json_atomic(&paths.state(), &state)?;
    prepare_run(&paths, &config, &mut state, api)?;
    print_awaiting_solution(&paths, &config, &state)?;
    Ok(paths.root)
}

pub(crate) fn resume(run_dir: &Path) -> Result<()> {
    let api = HttpRemoteApi::new()?;
    resume_with_api(run_dir, &api)
}

fn resume_with_api(run_dir: &Path, api: &impl RemoteApi) -> Result<()> {
    let paths = RunPaths::new(run_dir);
    let _lock = RunLock::acquire(&paths)?;
    let config = load_config(&paths)?;
    let mut state = load_state(&paths, &config)?;

    loop {
        match state.stage {
            RunStage::Created | RunStage::ChallengeIssued | RunStage::ProblemReady => {
                prepare_run(&paths, &config, &mut state, api)?;
            }
            RunStage::AwaitingSolution => {
                if !paths.solution().is_file() {
                    print_awaiting_solution(&paths, &config, &state)?;
                    return Ok(());
                }
                construct_proof(&paths, &config, &mut state)?;
            }
            RunStage::ProofReady => match config.authority {
                AuthorityConfig::RemoteV1 { .. } => {
                    obtain_certificate(&paths, &config, &mut state, api)?;
                }
                AuthorityConfig::LocalV1 => {
                    build_card(&paths, &config, &mut state)?;
                }
            },
            RunStage::CertificateReceived => {
                build_card(&paths, &config, &mut state)?;
            }
            RunStage::Complete => {
                if !paths.card().is_file() {
                    build_card(&paths, &config, &mut state)?;
                    continue;
                }
                let card: ResultCard = read_json(&paths.card(), MAX_RUN_JSON_BYTES)?;
                let verified = verify_card_value(&card)?;
                print_complete(&paths, &card, &verified)?;
                return Ok(());
            }
        }
    }
}

pub(crate) fn status(run_dir: &Path) -> Result<()> {
    let paths = RunPaths::new(run_dir);
    let config = load_config(&paths)?;
    let state = load_state(&paths, &config)?;
    println!("run_directory={}", paths.root.display());
    println!("benchmark_id={}", config.benchmark_id);
    println!("benchmark_digest={}", state.benchmark_digest);
    println!("stage={}", state.stage.label());
    println!("materialization={}", state.materialization.label());
    if let Some(digest) = state.problem_digest {
        println!("problem_digest={digest}");
    }
    if let Some(digest) = state.proof_digest {
        println!("proof_digest={digest}");
    }
    if let Some(digest) = state.certificate_digest {
        println!("certificate_digest={digest}");
    }
    if let Some(remote) = config.remote()
        && paths.challenge().is_file()
    {
        let challenge: SignedChallenge = read_json(&paths.challenge(), MAX_RUN_JSON_BYTES)?;
        validate_challenge_structure(&config, remote, &challenge)?;
        println!(
            "challenge_issued_at_unix_seconds={}",
            challenge.payload.issued_at_unix_seconds
        );
        println!(
            "challenge_expires_at_unix_seconds={}",
            challenge.payload.expires_at_unix_seconds
        );
    }
    println!("solution_file={}", paths.solution().display());
    println!("result_card={}", paths.card().display());
    Ok(())
}

pub(crate) fn card(run_dir: &Path) -> Result<()> {
    let paths = RunPaths::new(run_dir);
    let _lock = RunLock::acquire(&paths)?;
    let config = load_config(&paths)?;
    let mut state = load_state(&paths, &config)?;
    if paths.card().is_file() {
        let card: ResultCard = read_json(&paths.card(), MAX_RUN_JSON_BYTES)?;
        let verified = verify_card_value(&card)?;
        print_complete(&paths, &card, &verified)?;
        return Ok(());
    }
    if !matches!(
        state.stage,
        RunStage::ProofReady | RunStage::CertificateReceived | RunStage::Complete
    ) {
        bail!("the run has not produced a verified proof yet");
    }
    build_card(&paths, &config, &mut state)?;
    let card: ResultCard = read_json(&paths.card(), MAX_RUN_JSON_BYTES)?;
    let verified = verify_card_value(&card)?;
    print_complete(&paths, &card, &verified)
}

pub(crate) fn verify_card(path: &Path, benchmark_path: &Path) -> Result<()> {
    let card: ResultCard = read_json(path, MAX_RUN_JSON_BYTES)?;
    let benchmark: BenchmarkConfig = read_json(benchmark_path, MAX_RUN_JSON_BYTES)?;
    let verified = verify_card_against_benchmark(&card, &benchmark)?;
    println!("card_valid=true");
    println!("server_attested={}", verified.server_attested);
    println!("benchmark_id={}", card.benchmark.benchmark_id);
    println!("benchmark_digest={}", card.benchmark_digest);
    println!("problem_digest={}", card.problem.problem_digest);
    println!("proof_digest={}", card.proof_digest);
    if let Some(digest) = verified.certificate_digest {
        println!("certificate_digest={digest}");
    }
    println!("card_digest={}", card.digest()?);
    Ok(())
}

fn prepare_run(
    paths: &RunPaths,
    config: &BenchmarkConfig,
    state: &mut RunState,
    api: &impl RemoteApi,
) -> Result<()> {
    let problem = match config.remote() {
        None => config.problem_template.finalize_literal()?,
        Some(remote) => {
            let challenge = if paths.challenge().is_file() {
                read_json(&paths.challenge(), MAX_RUN_JSON_BYTES)?
            } else {
                println!("requesting_signed_challenge=true");
                let challenge = api.issue_challenge(remote, &config.problem_template)?;
                validate_live_challenge(config, remote, &challenge, now_unix_seconds()?)?;
                write_json_atomic(&paths.challenge(), &challenge)?;
                state.challenge_digest = Some(challenge.digest());
                update_stage(paths, state, RunStage::ChallengeIssued)?;
                challenge
            };
            validate_live_challenge(config, remote, &challenge, now_unix_seconds()?)?;
            require_recorded_digest("challenge", state.challenge_digest, challenge.digest())?;
            state.challenge_digest = Some(challenge.digest());
            config
                .problem_template
                .finalize_with_challenge_context(&challenge.payload_canonical_bytes())?
        }
    };

    let expected_digest = Digest::from_bytes(problem.digest()?.into_bytes());
    if paths.problem().is_file() {
        let recorded = FinalizedProblem::from_json_slice(&read_bounded(
            &paths.problem(),
            MAX_RUN_JSON_BYTES,
        )?)?;
        if recorded != problem {
            bail!("recorded problem does not match the benchmark and challenge");
        }
    } else {
        write_bytes_atomic(&paths.problem(), problem.to_pretty_json()?.as_bytes())?;
    }
    require_recorded_digest("problem", state.problem_digest, expected_digest)?;
    state.problem_digest = Some(expected_digest);
    state.validation_manifest_digest = Some(config.validation.digest()?);
    update_stage(paths, state, RunStage::ProblemReady)?;

    let generated = problem.compile()?;
    if state.materialization.writes_matrix() {
        println!("materializing_matrix={}", paths.matrix().display());
        write_matrix_market_matrix(&paths.matrix(), &generated)?;
    }
    if state.materialization.writes_rhs() {
        println!("materializing_rhs={}", paths.rhs().display());
        write_matrix_market_rhs(&paths.rhs(), &generated)?;
    }
    update_stage(paths, state, RunStage::AwaitingSolution)
}

fn construct_proof(paths: &RunPaths, config: &BenchmarkConfig, state: &mut RunState) -> Result<()> {
    let (problem, challenge) = load_problem_and_challenge(paths, config)?;
    if let (Some(remote), Some(challenge)) = (config.remote(), challenge.as_ref()) {
        validate_live_challenge(config, remote, challenge, now_unix_seconds()?)?;
        let remaining = challenge
            .payload
            .expires_at_unix_seconds
            .saturating_sub(now_unix_seconds()?);
        println!("challenge_seconds_remaining_before_proving={remaining}");
    }

    let dimension = problem_dimension(&problem)?;
    let solution_limit = Solution::maximum_json_bytes(dimension).min(MAX_ARTIFACT_BYTES);
    let solution_bytes = read_bounded(&paths.solution(), solution_limit)?;
    let solution = Solution::from_json(&solution_bytes, dimension)
        .with_context(|| format!("invalid solution {}", paths.solution().display()))?;
    let solution_digest = domain_separated_digest(SOLUTION_FILE_DIGEST_DOMAIN, &solution_bytes);

    let statement = PublicStatement::new(problem, config.validation.clone(), challenge)?;
    println!("constructing_proof=true");
    let (payload, _) = prove_single_stage(&statement, &solution)?;
    let proof = encode_artifact(&statement, &payload)?;
    let prelude = ArtifactPrelude::parse(&proof)?;
    verify_backend(&prelude).context("locally constructed proof did not verify")?;
    let summary = prelude.summary();
    write_bytes_atomic(&paths.proof(), &proof)?;

    state.solution_file_digest = Some(solution_digest);
    state.problem_digest = Some(summary.problem_digest);
    state.validation_manifest_digest = Some(summary.validation_manifest_digest);
    state.proof_digest = Some(summary.proof_digest);
    update_stage(paths, state, RunStage::ProofReady)?;
    println!("proof_digest={}", summary.proof_digest);
    println!("proof_file={}", paths.proof().display());
    Ok(())
}

fn obtain_certificate(
    paths: &RunPaths,
    config: &BenchmarkConfig,
    state: &mut RunState,
    api: &impl RemoteApi,
) -> Result<()> {
    let remote = config
        .remote()
        .context("remote certificate requested for a local benchmark")?;
    let (problem, challenge) = load_problem_and_challenge(paths, config)?;
    let challenge = challenge.context("remote run is missing its signed challenge")?;
    let proof = load_and_verify_proof(paths, config, &problem, Some(&challenge), state)?.0;
    require_solution_unchanged(paths, &problem, state)?;

    let certificate = if paths.certificate().is_file() {
        read_json(&paths.certificate(), MAX_CERTIFICATE_JSON_BYTES)?
    } else {
        validate_live_challenge(config, remote, &challenge, now_unix_seconds()?)?;
        println!("submitting_proof=true");
        let certificate = api.submit_proof(remote, proof)?;
        validate_certificate(config, &challenge, &certificate, state)?;
        write_json_atomic(&paths.certificate(), &certificate)?;
        certificate
    };
    validate_certificate(config, &challenge, &certificate, state)?;
    state.certificate_digest = Some(certificate.digest());
    update_stage(paths, state, RunStage::CertificateReceived)?;
    println!("certificate_digest={}", certificate.digest());
    println!("certificate_file={}", paths.certificate().display());
    Ok(())
}

fn build_card(paths: &RunPaths, config: &BenchmarkConfig, state: &mut RunState) -> Result<()> {
    let (problem, challenge) = load_problem_and_challenge(paths, config)?;
    require_solution_unchanged(paths, &problem, state)?;
    let (_, summary, report) =
        load_and_verify_proof(paths, config, &problem, challenge.as_ref(), state)?;
    let authority = match (&config.authority, challenge) {
        (AuthorityConfig::LocalV1, None) => CardAuthorityEvidence::LocalV1 {
            validated_at_unix_seconds: now_unix_seconds()?,
            protocol: report.protocol(),
            score: report.certified_score()?,
            validator_build: format!("sparse-benchmark/{}", env!("CARGO_PKG_VERSION")),
        },
        (AuthorityConfig::RemoteV1 { .. }, Some(challenge)) => {
            let certificate: SignedCertificate =
                read_json(&paths.certificate(), MAX_CERTIFICATE_JSON_BYTES)?;
            validate_certificate(config, &challenge, &certificate, state)?;
            state.certificate_digest = Some(certificate.digest());
            CardAuthorityEvidence::RemoteV1 {
                challenge: Box::new(challenge),
                certificate: Box::new(certificate),
            }
        }
        _ => bail!("benchmark authority and challenge provenance disagree"),
    };

    let card = ResultCard {
        schema: ResultCardSchema::V1,
        benchmark: config.clone(),
        benchmark_digest: config.digest()?,
        problem: ProblemSummary::from_problem(&problem)?,
        proof_digest: summary.proof_digest,
        authority,
    };
    verify_card_value(&card)?;
    write_json_atomic(&paths.card(), &card)?;
    update_stage(paths, state, RunStage::Complete)?;
    println!("result_card={}", paths.card().display());
    Ok(())
}

fn load_and_verify_proof(
    paths: &RunPaths,
    config: &BenchmarkConfig,
    problem: &FinalizedProblem,
    challenge: Option<&SignedChallenge>,
    state: &RunState,
) -> Result<(
    Vec<u8>,
    ssv_validation::ArtifactSummary,
    BackendVerifierReport,
)> {
    let proof = read_bounded(&paths.proof(), MAX_ARTIFACT_BYTES)?;
    let prelude = ArtifactPrelude::parse(&proof)?;
    let summary = prelude.summary();
    let expected_problem = Digest::from_bytes(problem.digest()?.into_bytes());
    if summary.problem_digest != expected_problem
        || summary.validation_manifest_digest != config.validation.digest()?
        || summary.protocol != config.validation.protocol
        || summary.has_signed_problem_challenge != challenge.is_some()
    {
        bail!("proof public statement does not match this benchmark run");
    }
    require_recorded_digest("proof", state.proof_digest, summary.proof_digest)?;
    let report = verify_backend(&prelude).context("stored proof did not verify")?;
    drop(prelude);
    Ok((proof, summary, report))
}

fn load_problem_and_challenge(
    paths: &RunPaths,
    config: &BenchmarkConfig,
) -> Result<(FinalizedProblem, Option<SignedChallenge>)> {
    let challenge = match config.remote() {
        None => None,
        Some(remote) => {
            let challenge: SignedChallenge = read_json(&paths.challenge(), MAX_RUN_JSON_BYTES)?;
            validate_challenge_structure(config, remote, &challenge)?;
            Some(challenge)
        }
    };
    let expected = match challenge.as_ref() {
        None => config.problem_template.finalize_literal()?,
        Some(challenge) => config
            .problem_template
            .finalize_with_challenge_context(&challenge.payload_canonical_bytes())?,
    };
    let recorded =
        FinalizedProblem::from_json_slice(&read_bounded(&paths.problem(), MAX_RUN_JSON_BYTES)?)?;
    if recorded != expected {
        bail!("recorded problem does not match the benchmark authority evidence");
    }
    Ok((recorded, challenge))
}

fn require_solution_unchanged(
    paths: &RunPaths,
    problem: &FinalizedProblem,
    state: &RunState,
) -> Result<()> {
    let expected = state
        .solution_file_digest
        .context("run state is missing the solution-file digest")?;
    let dimension = problem_dimension(problem)?;
    let maximum = Solution::maximum_json_bytes(dimension).min(MAX_ARTIFACT_BYTES);
    let bytes = read_bounded(&paths.solution(), maximum)?;
    Solution::from_json(&bytes, dimension)
        .with_context(|| format!("invalid solution {}", paths.solution().display()))?;
    let actual = domain_separated_digest(SOLUTION_FILE_DIGEST_DOMAIN, &bytes);
    if actual != expected {
        bail!("solution file changed after proof construction; start an explicit new run");
    }
    Ok(())
}

fn validate_live_challenge(
    config: &BenchmarkConfig,
    remote: RemoteAuthorityRef<'_>,
    challenge: &SignedChallenge,
    now: i64,
) -> Result<()> {
    validate_challenge_structure(config, remote, challenge)?;
    challenge
        .verify(
            &remote.verifying_key()?,
            remote.issuer,
            remote.key_id,
            now,
            remote.maximum_future_skew_seconds,
        )
        .context("signed challenge is not currently valid")
}

fn validate_challenge_structure(
    config: &BenchmarkConfig,
    remote: RemoteAuthorityRef<'_>,
    challenge: &SignedChallenge,
) -> Result<()> {
    challenge.payload.validate()?;
    let lifetime = challenge
        .payload
        .expires_at_unix_seconds
        .checked_sub(challenge.payload.issued_at_unix_seconds)
        .context("challenge timestamp interval underflow")?;
    if lifetime <= 0 || lifetime > remote.maximum_challenge_lifetime_seconds {
        bail!("challenge lifetime exceeds benchmark policy");
    }
    let expected_template = Digest::from_bytes(config.problem_template.digest()?.into_bytes());
    if challenge.payload.problem_template_digest != expected_template {
        bail!("challenge is bound to a different problem template");
    }
    Ok(())
}

fn validate_certificate(
    config: &BenchmarkConfig,
    challenge: &SignedChallenge,
    certificate: &SignedCertificate,
    state: &RunState,
) -> Result<()> {
    let remote = config
        .remote()
        .context("signed certificate used with local authority")?;
    certificate
        .verify(&remote.verifying_key()?, remote.issuer, remote.key_id)
        .context("certificate signature is invalid")?;
    validate_challenge_structure(config, remote, challenge)?;
    challenge
        .verify(
            &remote.verifying_key()?,
            remote.issuer,
            remote.key_id,
            certificate.payload.issued_at_unix_seconds,
            0,
        )
        .context("certificate was not issued inside the signed challenge window")?;
    if certificate.payload.challenge_digest != challenge.digest() {
        bail!("certificate is bound to a different challenge");
    }
    require_recorded_digest(
        "problem",
        state.problem_digest,
        certificate.payload.problem_digest,
    )?;
    require_recorded_digest(
        "validation manifest",
        state.validation_manifest_digest,
        certificate.payload.validation_manifest_digest,
    )?;
    require_recorded_digest(
        "proof",
        state.proof_digest,
        certificate.payload.proof_digest,
    )?;
    if certificate.payload.protocol != config.validation.protocol {
        bail!("certificate protocol does not match the benchmark manifest");
    }
    require_recorded_digest(
        "certificate",
        state.certificate_digest,
        certificate.digest(),
    )?;
    Ok(())
}

pub(crate) struct CardVerification {
    server_attested: bool,
    certificate_digest: Option<Digest>,
}

fn verify_card_value(card: &ResultCard) -> Result<CardVerification> {
    card.benchmark.validate()?;
    if card.benchmark.digest()? != card.benchmark_digest {
        bail!("result card benchmark digest does not match its embedded configuration");
    }
    let (problem, server_attested, certificate_digest) =
        match (&card.benchmark.authority, &card.authority) {
            (
                AuthorityConfig::RemoteV1 { .. },
                CardAuthorityEvidence::RemoteV1 {
                    challenge,
                    certificate,
                },
            ) => {
                let remote = card.benchmark.remote().expect("matched remote authority");
                validate_challenge_structure(&card.benchmark, remote, challenge)?;
                certificate
                    .verify(&remote.verifying_key()?, remote.issuer, remote.key_id)
                    .context("result-card certificate signature is invalid")?;
                challenge
                    .verify(
                        &remote.verifying_key()?,
                        remote.issuer,
                        remote.key_id,
                        certificate.payload.issued_at_unix_seconds,
                        0,
                    )
                    .context("result-card challenge was not valid at certification time")?;
                if certificate.payload.challenge_digest != challenge.digest() {
                    bail!("result-card certificate and challenge digests disagree");
                }
                if certificate.payload.problem_digest != card.problem.problem_digest
                    || certificate.payload.validation_manifest_digest
                        != card.benchmark.validation.digest()?
                    || certificate.payload.proof_digest != card.proof_digest
                    || certificate.payload.protocol != card.benchmark.validation.protocol
                {
                    bail!("result-card certificate bindings disagree with the displayed result");
                }
                let problem = card
                    .benchmark
                    .problem_template
                    .finalize_with_challenge_context(&challenge.payload_canonical_bytes())?;
                (problem, true, Some(certificate.digest()))
            }
            (
                AuthorityConfig::LocalV1,
                CardAuthorityEvidence::LocalV1 {
                    validated_at_unix_seconds,
                    protocol,
                    score,
                    validator_build,
                },
            ) => {
                if *validated_at_unix_seconds < 0 {
                    bail!("local result has a negative validation timestamp");
                }
                ssv_service_protocol::validate_identifier("validator_build", validator_build)
                    .context("local validator build identifier is invalid")?;
                if *protocol != card.benchmark.validation.protocol {
                    bail!("local result protocol does not match the benchmark manifest");
                }
                score.validate_for_protocol(*protocol)?;
                (
                    card.benchmark.problem_template.finalize_literal()?,
                    false,
                    None,
                )
            }
            _ => bail!("result-card authority configuration and evidence disagree"),
        };
    let expected_summary = ProblemSummary::from_problem(&problem)?;
    if expected_summary != card.problem {
        bail!("result-card problem summary is not derivable from its authority evidence");
    }
    Ok(CardVerification {
        server_attested,
        certificate_digest,
    })
}

fn verify_card_against_benchmark(
    card: &ResultCard,
    benchmark: &BenchmarkConfig,
) -> Result<CardVerification> {
    benchmark.validate()?;
    if benchmark.digest()? != card.benchmark_digest {
        bail!("result card does not match the externally supplied benchmark configuration");
    }
    verify_card_value(card)
}

fn load_config(paths: &RunPaths) -> Result<BenchmarkConfig> {
    let config: BenchmarkConfig = read_json(&paths.benchmark(), MAX_RUN_JSON_BYTES)?;
    config.validate()?;
    Ok(config)
}

fn load_state(paths: &RunPaths, config: &BenchmarkConfig) -> Result<RunState> {
    let state: RunState = read_json(&paths.state(), MAX_RUN_JSON_BYTES)?;
    if state.benchmark_digest != config.digest()? {
        bail!("run benchmark configuration changed after the run was created");
    }
    if state.created_at_unix_seconds < 0
        || state.updated_at_unix_seconds < state.created_at_unix_seconds
    {
        bail!("run state timestamps are invalid");
    }
    Ok(state)
}

fn update_stage(paths: &RunPaths, state: &mut RunState, stage: RunStage) -> Result<()> {
    state.stage = stage;
    state.updated_at_unix_seconds = now_unix_seconds()?;
    write_json_atomic(&paths.state(), state)
}

fn require_recorded_digest(object: &str, recorded: Option<Digest>, actual: Digest) -> Result<()> {
    if let Some(recorded) = recorded
        && recorded != actual
    {
        bail!("recorded {object} digest does not match the artifact");
    }
    Ok(())
}

fn print_awaiting_solution(
    paths: &RunPaths,
    config: &BenchmarkConfig,
    state: &RunState,
) -> Result<()> {
    println!("run_directory={}", paths.root.display());
    println!("stage={}", state.stage.label());
    if let Some(remote) = config.remote() {
        let challenge: SignedChallenge = read_json(&paths.challenge(), MAX_RUN_JSON_BYTES)?;
        validate_challenge_structure(config, remote, &challenge)?;
        println!("authority=remote-v1");
        println!(
            "challenge_issued_at_unix_seconds={}",
            challenge.payload.issued_at_unix_seconds
        );
        println!(
            "challenge_expires_at_unix_seconds={}",
            challenge.payload.expires_at_unix_seconds
        );
        println!(
            "challenge_seconds_remaining={}",
            challenge
                .payload
                .expires_at_unix_seconds
                .saturating_sub(now_unix_seconds()?)
        );
    } else {
        println!("authority=local-v1");
    }
    if state.materialization.writes_matrix() {
        println!("matrix_file={}", paths.matrix().display());
    }
    if state.materialization.writes_rhs() {
        println!("rhs_file={}", paths.rhs().display());
    }
    println!("problem_file={}", paths.problem().display());
    println!("solution_file={}", paths.solution().display());
    println!(
        "instruction=solve the finalized system, write x.json, then run sparse-benchmark resume {}",
        paths.root.display()
    );
    Ok(())
}

fn print_complete(
    paths: &RunPaths,
    card: &ResultCard,
    verification: &CardVerification,
) -> Result<()> {
    println!("run_directory={}", paths.root.display());
    println!("stage=complete");
    println!("card_valid=true");
    println!("server_attested={}", verification.server_attested);
    println!("problem_digest={}", card.problem.problem_digest);
    println!("proof_digest={}", card.proof_digest);
    if let Some(digest) = verification.certificate_digest {
        println!("certificate_digest={digest}");
    }
    println!("card_digest={}", card.digest()?);
    println!("result_card={}", paths.card().display());
    Ok(())
}

fn now_unix_seconds() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    i64::try_from(duration.as_secs()).context("Unix timestamp does not fit i64")
}

fn problem_dimension(problem: &FinalizedProblem) -> Result<usize> {
    usize::try_from(problem.dimension()).context("problem dimension does not fit usize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::sync::Mutex;

    use ed25519_dalek::SigningKey;
    use ssv_canonical::Digest;
    use ssv_service::{ServiceConfig, StatelessValidatorService};
    use ssv_service_protocol::ProofProtocol;

    struct FakeRemoteApi {
        service: StatelessValidatorService,
        now: Mutex<i64>,
        fail_first_submission: Mutex<bool>,
    }

    impl RemoteApi for FakeRemoteApi {
        fn issue_challenge(
            &self,
            _authority: RemoteAuthorityRef<'_>,
            template: &ssv_problem::ProblemTemplate,
        ) -> Result<SignedChallenge> {
            let now = *self.now.lock().expect("time mutex");
            self.service
                .issue_challenge(template, Digest::from_bytes([9; 32]), now)
                .map_err(Into::into)
        }

        fn submit_proof(
            &self,
            _authority: RemoteAuthorityRef<'_>,
            proof: Vec<u8>,
        ) -> Result<SignedCertificate> {
            let mut fail = self.fail_first_submission.lock().expect("failure mutex");
            if *fail {
                *fail = false;
                bail!("simulated transport interruption");
            }
            drop(fail);
            let mut now = self.now.lock().expect("time mutex");
            *now += 1;
            let validated = self.service.validate_submission(&proof, *now)?;
            *now += 1;
            Ok(self.service.certify(validated, *now)?.certificate)
        }
    }

    #[test]
    fn remote_run_resumes_and_produces_a_portable_card() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let service = StatelessValidatorService::new(
            ServiceConfig {
                issuer: "test-validator".to_owned(),
                key_id: "test-key-v1".to_owned(),
                challenge_lifetime_seconds: 3_600,
                maximum_future_skew_seconds: 30,
                maximum_solution_elements: 1_024,
                maximum_public_matrix_terms: 4_096,
                maximum_public_rhs_terms: 4_096,
                allowed_protocols: vec![ProofProtocol::DirectReferenceV1],
                validator_build: "test-build".to_owned(),
            },
            signing_key,
        )
        .expect("service");
        let api = FakeRemoteApi {
            service,
            now: Mutex::new(now_unix_seconds().expect("time")),
            fail_first_submission: Mutex::new(true),
        };
        let temporary = temporary_directory("remote-card");
        let config_path = temporary.join("benchmark-input.json");
        let config = remote_config(public_key);
        write_json_atomic(&config_path, &config).expect("config");

        let run = start_with_api(
            &config_path,
            &temporary.join("runs"),
            Materialization::None,
            &api,
        )
        .expect("start");
        let paths = RunPaths::new(&run);
        Solution::write_repeated_json(
            File::create(paths.solution()).expect("solution file"),
            0.0,
            4,
        )
        .expect("solution");
        let interrupted = resume_with_api(&run, &api).expect_err("first submission fails");
        assert!(interrupted.to_string().contains("simulated transport"));
        let interrupted_state: RunState =
            read_json(&paths.state(), MAX_RUN_JSON_BYTES).expect("interrupted state");
        assert_eq!(interrupted_state.stage, RunStage::ProofReady);
        assert!(paths.proof().is_file());

        resume_with_api(&run, &api).expect("resumed submission");

        let state: RunState = read_json(&paths.state(), MAX_RUN_JSON_BYTES).expect("state");
        assert_eq!(state.stage, RunStage::Complete);
        let card: ResultCard = read_json(&paths.card(), MAX_RUN_JSON_BYTES).expect("card");
        assert!(
            verify_card_value(&card)
                .expect("valid card")
                .server_attested
        );
        let mut rebranded = card.clone();
        rebranded.benchmark.benchmark_id = "different-benchmark-v1".to_owned();
        rebranded.benchmark_digest = rebranded.benchmark.digest().expect("rebranded digest");
        assert!(verify_card_value(&rebranded).is_ok());
        assert!(verify_card_against_benchmark(&rebranded, &config).is_err());
        fs::remove_dir_all(temporary).expect("cleanup");
    }

    #[test]
    fn local_card_is_consistent_but_not_server_attested() {
        let temporary = temporary_directory("local-card");
        let config_path = temporary.join("benchmark-input.json");
        let config = local_config();
        write_json_atomic(&config_path, &config).expect("config");
        let api = HttpRemoteApi::new().expect("client");
        let run = start_with_api(
            &config_path,
            &temporary.join("runs"),
            Materialization::MatrixAndRhs,
            &api,
        )
        .expect("start");
        let paths = RunPaths::new(&run);
        assert!(paths.matrix().is_file());
        assert!(paths.rhs().is_file());
        Solution::write_repeated_json(
            File::create(paths.solution()).expect("solution file"),
            0.0,
            4,
        )
        .expect("solution");
        resume_with_api(&run, &api).expect("resume");
        let card: ResultCard = read_json(&paths.card(), MAX_RUN_JSON_BYTES).expect("card");
        assert!(
            !verify_card_value(&card)
                .expect("valid card")
                .server_attested
        );
        fs::remove_dir_all(temporary).expect("cleanup");
    }

    fn remote_config(public_key: String) -> BenchmarkConfig {
        let mut config = local_config();
        config.problem_template.randomness = ssv_problem::TemplateRandomness::ChallengeDerivedV1 {
            derivation: ssv_problem::SeedDerivation::Blake3XofV1,
        };
        config.authority = AuthorityConfig::RemoteV1 {
            service_url: "https://validator.example".to_owned(),
            issuer: "test-validator".to_owned(),
            key_id: "test-key-v1".to_owned(),
            public_key,
            authentication: crate::model::RemoteAuthentication::NoneV1,
            maximum_future_skew_seconds: 30,
            maximum_challenge_lifetime_seconds: 3_600,
        };
        config
    }

    fn local_config() -> BenchmarkConfig {
        serde_json::from_value(serde_json::json!({
            "schema": "sparse-solve/benchmark/v1",
            "benchmark_id": "runner-test-v1",
            "authority": { "kind": "local-v1" },
            "problem_template": {
                "schema": "sparse-solve/problem-template/v1",
                "randomness": {
                    "kind": "literal-v1",
                    "seed": "0101010101010101010101010101010101010101010101010101010101010101"
                },
                "matrix": {
                    "kind": "seeded-symmetric-tridiagonal-v1",
                    "dimension": 4,
                    "boundary": "truncate-v1",
                    "off_diagonal": {
                        "kind": "seeded-periodic-negative-dyadic-v1",
                        "period_bits": 1,
                        "fractional_bits": 8,
                        "minimum_magnitude_mantissa": "8",
                        "maximum_magnitude_mantissa": "24"
                    },
                    "diagonal": {
                        "kind": "absolute-row-sum-plus-margin-v1",
                        "margin_mantissa": "32"
                    }
                },
                "rhs": {
                    "kind": "seeded-periodic-dyadic-v1",
                    "period_bits": 2,
                    "fractional_bits": 8,
                    "minimum_mantissa": "-16",
                    "maximum_mantissa": "19"
                },
                "requested_outputs": [{ "kind": "squared-l2-residual-v1" }]
            },
            "validation": {
                "schema": "sparse-solve/validation/v1",
                "protocol": "direct-reference-v1",
                "max_solution_elements": 1024,
                "max_public_matrix_terms": 4096,
                "max_public_rhs_terms": 4096
            }
        }))
        .expect("test benchmark config")
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sparse-benchmark-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir(&path).expect("temporary directory");
        path
    }
}
