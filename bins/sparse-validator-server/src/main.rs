use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use ssv_canonical::Digest;
use ssv_problem::ProblemTemplate;
use ssv_service::{
    ServiceConfig, ServiceError, StatelessValidatorService, ValidationCancellation,
    maximum_submission_bytes,
};
use ssv_service_protocol::{ProofProtocol, SignedCertificate, SignedChallenge};
use tokio::sync::Semaphore;
use tokio::task::JoinError;
use tokio::time::Instant;
use tower::limit::ConcurrencyLimitLayer;
use zeroize::Zeroizing;

const MAX_TEMPLATE_JSON_BYTES: usize = 1024 * 1024;
const DEFAULT_MAXIMUM_PUBLIC_EVALUATION_TERMS: u64 = 4096;
const DEFAULT_ALLOWED_PROTOCOLS: &str = "direct-reference-v1,whir-field192-l2-v4,fast-binary64-unit-circle-v5,fast-binary64-unit-circle-chunked-v6";
const PACKAGE_VALIDATOR_BUILD: &str =
    concat!("sparse-validator-server/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Parser)]
#[command(
    name = "sparse-validator-server",
    about = "Stateless challenge and sparse-solution validation service"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a development Ed25519 signing key and public trust anchor.
    Keygen {
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Serve localhost or Cloud Run-compatible HTTP endpoints.
    Serve {
        #[arg(long, default_value = "0.0.0.0")]
        host: IpAddr,
        #[arg(long, env = "PORT", default_value_t = 8080)]
        port: u16,
        #[arg(long, env = "SSV_SIGNING_KEY_FILE")]
        signing_key: PathBuf,
        #[arg(long, env = "SSV_ISSUER", default_value = "sparse-validator-local")]
        issuer: String,
        #[arg(long, env = "SSV_KEY_ID", default_value = "local-development-v1")]
        key_id: String,
        #[arg(long, env = "SSV_VALIDATOR_BUILD")]
        validator_build: Option<String>,
        #[arg(long, default_value_t = 900)]
        challenge_lifetime_seconds: i64,
        #[arg(long, default_value_t = 30)]
        maximum_future_skew_seconds: i64,
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        maximum_solution_elements: u64,
        #[arg(
            long,
            env = "SSV_MAXIMUM_PUBLIC_MATRIX_TERMS",
            default_value_t = DEFAULT_MAXIMUM_PUBLIC_EVALUATION_TERMS
        )]
        maximum_public_matrix_terms: u64,
        #[arg(
            long,
            env = "SSV_MAXIMUM_PUBLIC_RHS_TERMS",
            default_value_t = DEFAULT_MAXIMUM_PUBLIC_EVALUATION_TERMS
        )]
        maximum_public_rhs_terms: u64,
        #[arg(
            long = "allowed-protocol",
            env = "SSV_ALLOWED_PROTOCOLS",
            value_delimiter = ',',
            value_parser = parse_proof_protocol,
            default_value = DEFAULT_ALLOWED_PROTOCOLS
        )]
        allowed_protocols: Vec<ProofProtocol>,
        #[arg(long, default_value_t = 1)]
        max_concurrent_validations: usize,
        /// Request timeout. For validation, the deadline starts after body
        /// admission and includes capacity wait and cooperative cancellation.
        #[arg(long, default_value_t = 120)]
        request_timeout_seconds: u64,
    },
}

#[derive(Clone)]
struct AppState {
    service: Arc<StatelessValidatorService>,
    validation_slots: Arc<Semaphore>,
    validation_timeout: Duration,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: &'static str,
    message: String,
}

struct ApiError {
    status: StatusCode,
    kind: &'static str,
    message: String,
}

impl ApiError {
    fn invalid(kind: &'static str, error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            kind,
            message: error.to_string(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            kind: "internal-error",
            message: error.to_string(),
        }
    }

    fn timeout() -> Self {
        Self {
            status: StatusCode::REQUEST_TIMEOUT,
            kind: "request-timeout",
            message: "validation exceeded the configured deadline".to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                error: self.kind,
                message: self.message,
            }),
        )
            .into_response()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            signing_key,
            public_key,
        } => keygen(&signing_key, &public_key),
        Command::Serve {
            host,
            port,
            signing_key,
            issuer,
            key_id,
            validator_build,
            challenge_lifetime_seconds,
            maximum_future_skew_seconds,
            maximum_solution_elements,
            maximum_public_matrix_terms,
            maximum_public_rhs_terms,
            allowed_protocols,
            max_concurrent_validations,
            request_timeout_seconds,
        } => {
            if max_concurrent_validations == 0 {
                bail!("max-concurrent-validations must be positive");
            }
            if request_timeout_seconds == 0 {
                bail!("request-timeout-seconds must be positive");
            }
            let structural_proof_limit = maximum_submission_bytes(maximum_solution_elements)
                .context("maximum-solution-elements exceeds registered backend limits")?;
            let max_proof_bytes = structural_proof_limit;
            let signing_key = load_signing_key(&signing_key)?;
            let cloud_run_revision = std::env::var("K_REVISION").ok();
            let validator_build =
                select_validator_build(validator_build.as_deref(), cloud_run_revision.as_deref());
            let service = StatelessValidatorService::new(
                ServiceConfig {
                    issuer,
                    key_id,
                    challenge_lifetime_seconds,
                    maximum_future_skew_seconds,
                    maximum_solution_elements,
                    maximum_public_matrix_terms,
                    maximum_public_rhs_terms,
                    allowed_protocols,
                    validator_build,
                },
                signing_key,
            )?;
            serve(
                SocketAddr::new(host, port),
                service,
                max_concurrent_validations,
                max_proof_bytes,
                request_timeout_seconds,
            )
            .await
        }
    }
}

async fn serve(
    address: SocketAddr,
    service: StatelessValidatorService,
    max_concurrent_validations: usize,
    max_proof_bytes: usize,
    request_timeout_seconds: u64,
) -> Result<()> {
    let validation_timeout = Duration::from_secs(request_timeout_seconds);
    let challenge_timeout = validation_timeout;
    let challenge_timeout_layer =
        middleware::from_fn(move |request: Request, next: Next| async move {
            match tokio::time::timeout(challenge_timeout, next.run(request)).await {
                Ok(response) => response,
                Err(_) => (
                    StatusCode::REQUEST_TIMEOUT,
                    Json(ApiErrorBody {
                        error: "request-timeout",
                        message: "request exceeded the configured deadline".to_owned(),
                    }),
                )
                    .into_response(),
            }
        });
    let state = AppState {
        service: Arc::new(service),
        validation_slots: Arc::new(Semaphore::new(max_concurrent_validations)),
        validation_timeout,
    };
    let app = Router::new()
        // Cloud Run reserves some paths ending in `z`; keep this endpoint on
        // an ordinary application path so requests reach the container.
        .route("/health", get(health))
        .route(
            "/v1/challenges",
            post(issue_challenge)
                .layer(DefaultBodyLimit::max(MAX_TEMPLATE_JSON_BYTES))
                .layer(challenge_timeout_layer),
        )
        .route(
            "/v1/validate",
            post(validate)
                .layer::<_, std::convert::Infallible>(DefaultBodyLimit::max(max_proof_bytes))
                // Bound admitted bodies and handlers. The separate semaphore
                // remains owned by a blocking worker until that worker exits.
                .layer::<_, std::convert::Infallible>(ConcurrencyLimitLayer::new(
                    max_concurrent_validations,
                )),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("could not bind HTTP listener to {address}"))?;
    println!("listening=http://{address}");
    println!("health_path=/health");
    println!("challenge_path=/v1/challenges");
    println!("validation_path=/v1/validate");
    println!("max_proof_bytes={max_proof_bytes}");
    println!("request_timeout_seconds={request_timeout_seconds}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn issue_challenge(
    State(state): State<AppState>,
    Json(template): Json<ProblemTemplate>,
) -> Result<Json<SignedChallenge>, ApiError> {
    let mut entropy = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut entropy)
        .map_err(ApiError::internal)?;
    let now = now_unix_seconds().map_err(ApiError::internal)?;
    state
        .service
        .issue_challenge(&template, Digest::from_bytes(entropy), now)
        .map(Json)
        .map_err(|error| ApiError::invalid("invalid-problem-template", error))
}

enum ValidationTaskError {
    Clock(anyhow::Error),
    Submission(ServiceError),
    Certificate(ServiceError),
}

#[derive(Debug)]
enum ValidationRun<T, E> {
    Completed(Result<T, E>),
    TimedOut,
    CapacityClosed,
    WorkerFailed(JoinError),
}

struct CancelOnDrop {
    cancellation: Option<ValidationCancellation>,
}

impl CancelOnDrop {
    fn new(cancellation: ValidationCancellation) -> Self {
        Self {
            cancellation: Some(cancellation),
        }
    }

    fn disarm(&mut self) {
        self.cancellation = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(cancellation) = self.cancellation.as_ref() {
            cancellation.cancel();
        }
    }
}

async fn run_validation_until<T, E, F>(
    validation_slots: Arc<Semaphore>,
    deadline: Instant,
    operation: F,
) -> ValidationRun<T, E>
where
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce(ValidationCancellation) -> Result<T, E> + Send + 'static,
{
    let permit = match tokio::time::timeout_at(deadline, validation_slots.acquire_owned()).await {
        Err(_) => return ValidationRun::TimedOut,
        Ok(Err(_)) => return ValidationRun::CapacityClosed,
        Ok(Ok(permit)) => permit,
    };
    let cancellation = ValidationCancellation::new();
    let worker_cancellation = cancellation.clone();
    let mut cancel_on_drop = CancelOnDrop::new(cancellation.clone());
    let mut worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(worker_cancellation)
    });
    let outcome = match tokio::time::timeout_at(deadline, &mut worker).await {
        Ok(Ok(result)) => ValidationRun::Completed(result),
        Ok(Err(error)) => ValidationRun::WorkerFailed(error),
        Err(_) => {
            cancellation.cancel();
            let _ = worker.await;
            ValidationRun::TimedOut
        }
    };
    cancel_on_drop.disarm();
    outcome
}

async fn validate(
    State(state): State<AppState>,
    proof: Bytes,
) -> Result<Json<SignedCertificate>, ApiError> {
    let deadline = Instant::now()
        .checked_add(state.validation_timeout)
        .ok_or_else(|| ApiError::internal("validation deadline exceeds the platform clock"))?;
    let service = state.service.clone();
    let outcome = run_validation_until(
        state.validation_slots.clone(),
        deadline,
        move |cancellation| {
            let validation_started_at = now_unix_seconds().map_err(ValidationTaskError::Clock)?;
            let validated = service
                .validate_owned_submission_with_cancellation(
                    proof,
                    validation_started_at,
                    &cancellation,
                )
                .map_err(ValidationTaskError::Submission)?;
            if cancellation.is_cancelled() {
                return Err(ValidationTaskError::Submission(
                    ServiceError::ValidationCancelled,
                ));
            }
            let certificate_issued_at = now_unix_seconds().map_err(ValidationTaskError::Clock)?;
            service
                .certify(validated, certificate_issued_at)
                .map(|certified| certified.certificate)
                .map_err(ValidationTaskError::Certificate)
        },
    )
    .await;
    match outcome {
        ValidationRun::Completed(Ok(certificate)) => Ok(Json(certificate)),
        ValidationRun::Completed(Err(ValidationTaskError::Clock(error))) => {
            Err(ApiError::internal(error))
        }
        ValidationRun::Completed(Err(ValidationTaskError::Submission(error))) => {
            Err(ApiError::invalid("invalid-validation-submission", error))
        }
        ValidationRun::Completed(Err(ValidationTaskError::Certificate(error))) => {
            Err(ApiError::invalid("certificate-policy-rejected", error))
        }
        ValidationRun::TimedOut => Err(ApiError::timeout()),
        ValidationRun::CapacityClosed => Err(ApiError::internal("validation capacity is closed")),
        ValidationRun::WorkerFailed(error) => Err(ApiError::internal(error)),
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(terminate) => terminate,
            Err(error) => {
                eprintln!("could not install SIGTERM handler: {error}");
                return;
            }
        };
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    eprintln!("could not listen for Ctrl-C: {error}");
                }
            }
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("could not listen for Ctrl-C: {error}");
    }
}

fn select_validator_build(configured: Option<&str>, cloud_run_revision: Option<&str>) -> String {
    configured
        .or(cloud_run_revision)
        .unwrap_or(PACKAGE_VALIDATOR_BUILD)
        .to_owned()
}

fn parse_proof_protocol(value: &str) -> Result<ProofProtocol, String> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|error| error.to_string())
}

fn keygen(signing_key_path: &Path, public_key_path: &Path) -> Result<()> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let signing_key_bytes = Zeroizing::new(signing_key.to_bytes());
    let encoded_signing_key = Zeroizing::new(hex::encode(&signing_key_bytes[..]));
    write_new_secret(signing_key_path, encoded_signing_key.as_bytes())?;
    write_new_file(
        public_key_path,
        hex::encode(signing_key.verifying_key().to_bytes()).as_bytes(),
    )?;
    println!("signing_key_file={}", signing_key_path.display());
    println!("public_key_file={}", public_key_path.display());
    Ok(())
}

fn write_new_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("could not create new secret file {}", path.display()))?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("could not create new file {}", path.display()))?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let encoded_file = Zeroizing::new(read_bounded(path, 256)?);
    let encoded = std::str::from_utf8(&encoded_file)
        .context("signing-key file is not UTF-8")?
        .trim();
    if encoded.len() != 64 {
        bail!("signing key must contain exactly 64 hexadecimal characters");
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(encoded, bytes.as_mut())
        .context("signing key is not 32-byte hexadecimal data")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read {}", path.display()))?;
    if bytes.len() > maximum {
        bail!(
            "{} exceeds the {}-byte input limit",
            path.display(),
            maximum
        );
    }
    Ok(bytes)
}

fn now_unix_seconds() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    i64::try_from(duration.as_secs()).context("Unix timestamp does not fit i64")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        PACKAGE_VALIDATOR_BUILD, ProofProtocol, ValidationRun, keygen, load_signing_key,
        parse_proof_protocol, run_validation_until, select_validator_build,
    };
    use tokio::sync::Semaphore;
    use tokio::time::Instant;

    struct KeygenFiles {
        directory: PathBuf,
        signing_key: PathBuf,
        public_key: PathBuf,
    }

    impl KeygenFiles {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let stem = format!(
                "sparse-validator-keygen-test-{}-{nonce}",
                std::process::id()
            );
            let directory = std::env::temp_dir().join(stem);
            fs::create_dir(&directory).unwrap();
            Self {
                signing_key: directory.join("signing-key.hex"),
                public_key: directory.join("public-key.hex"),
                directory,
            }
        }
    }

    impl Drop for KeygenFiles {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.signing_key);
            let _ = fs::remove_file(&self.public_key);
            let _ = fs::remove_dir(&self.directory);
        }
    }

    #[test]
    fn validator_build_prefers_explicit_configuration() {
        assert_eq!(
            select_validator_build(Some("configured-build"), Some("cloud-run-revision")),
            "configured-build"
        );
    }

    #[test]
    fn validator_build_uses_cloud_run_revision_when_not_configured() {
        assert_eq!(
            select_validator_build(None, Some("cloud-run-revision")),
            "cloud-run-revision"
        );
    }

    #[test]
    fn validator_build_falls_back_to_package_version() {
        assert_eq!(select_validator_build(None, None), PACKAGE_VALIDATOR_BUILD);
    }

    #[test]
    fn empty_explicit_validator_build_is_not_silently_replaced() {
        assert_eq!(select_validator_build(Some(""), Some("revision")), "");
    }

    #[test]
    fn configured_protocols_use_the_signed_protocol_names() {
        assert_eq!(
            parse_proof_protocol("direct-reference-v1").unwrap(),
            ProofProtocol::DirectReferenceV1
        );
        assert_eq!(
            parse_proof_protocol("whir-field192-l2-v4").unwrap(),
            ProofProtocol::WhirField192L2V4
        );
        assert_eq!(
            parse_proof_protocol("fast-binary64-unit-circle-v5").unwrap(),
            ProofProtocol::FastBinary64UnitCircleV5
        );
        assert_eq!(
            parse_proof_protocol("fast-binary64-unit-circle-chunked-v6").unwrap(),
            ProofProtocol::FastBinary64UnitCircleChunkedV6
        );
        assert!(parse_proof_protocol("unknown").is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_validation_stops_before_capacity_is_reused() {
        let slots = Arc::new(Semaphore::new(1));
        let stopped = Arc::new(AtomicBool::new(false));
        let worker_stopped = stopped.clone();
        let first = run_validation_until(
            slots.clone(),
            Instant::now() + Duration::from_millis(20),
            move |cancellation| {
                while !cancellation.is_cancelled() {
                    std::thread::yield_now();
                }
                worker_stopped.store(true, Ordering::Release);
                Ok::<(), ()>(())
            },
        );
        let outcome = tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .unwrap();
        assert!(matches!(outcome, ValidationRun::TimedOut));
        assert!(stopped.load(Ordering::Acquire));
        assert_eq!(slots.available_permits(), 1);

        let second = run_validation_until(slots, Instant::now() + Duration::from_secs(1), |_| {
            Ok::<u8, ()>(17)
        })
        .await;
        assert!(matches!(second, ValidationRun::Completed(Ok(17))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_a_validation_waiter_cancels_its_worker() {
        let slots = Arc::new(Semaphore::new(1));
        let started = Arc::new(AtomicBool::new(false));
        let stopped = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let worker_stopped = stopped.clone();
        let task = tokio::spawn(run_validation_until(
            slots.clone(),
            Instant::now() + Duration::from_secs(10),
            move |cancellation| {
                worker_started.store(true, Ordering::Release);
                while !cancellation.is_cancelled() {
                    std::thread::yield_now();
                }
                worker_stopped.store(true, Ordering::Release);
                Ok::<(), ()>(())
            },
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !stopped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let permit = tokio::time::timeout(Duration::from_secs(1), slots.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
    }

    #[test]
    fn keygen_writes_a_loadable_secret_and_matching_public_key() {
        let files = KeygenFiles::new();
        keygen(&files.signing_key, &files.public_key).unwrap();

        let signing_key = load_signing_key(&files.signing_key).unwrap();
        let encoded_public_key = fs::read_to_string(&files.public_key).unwrap();
        assert_eq!(
            encoded_public_key.trim(),
            hex::encode(signing_key.verifying_key().to_bytes())
        );
        assert_eq!(fs::metadata(&files.signing_key).unwrap().len(), 65);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&files.signing_key)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
    }
}
