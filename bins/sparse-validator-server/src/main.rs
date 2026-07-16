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
use ssv_service::{ServiceConfig, StatelessValidatorService, maximum_submission_bytes};
use ssv_service_protocol::{SignedCertificate, SignedChallenge};
use tokio::sync::Semaphore;
use tower::limit::ConcurrencyLimitLayer;
use zeroize::Zeroizing;

const MAX_TEMPLATE_JSON_BYTES: usize = 1024 * 1024;

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
        #[arg(long, default_value_t = 900)]
        challenge_lifetime_seconds: i64,
        #[arg(long, default_value_t = 30)]
        maximum_future_skew_seconds: i64,
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        maximum_solution_elements: u64,
        #[arg(long, default_value_t = 1)]
        max_concurrent_validations: usize,
        #[arg(long, default_value_t = 120)]
        request_timeout_seconds: u64,
    },
}

#[derive(Clone)]
struct AppState {
    service: Arc<StatelessValidatorService>,
    validation_slots: Arc<Semaphore>,
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
            challenge_lifetime_seconds,
            maximum_future_skew_seconds,
            maximum_solution_elements,
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
            let service = StatelessValidatorService::new(
                ServiceConfig {
                    issuer,
                    key_id,
                    challenge_lifetime_seconds,
                    maximum_future_skew_seconds,
                    maximum_solution_elements,
                    validator_build: format!(
                        "sparse-validator-server/{}",
                        env!("CARGO_PKG_VERSION")
                    ),
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
    let state = AppState {
        service: Arc::new(service),
        validation_slots: Arc::new(Semaphore::new(max_concurrent_validations)),
    };
    let request_timeout = Duration::from_secs(request_timeout_seconds);
    let timeout_layer = middleware::from_fn(move |request: Request, next: Next| async move {
        match tokio::time::timeout(request_timeout, next.run(request)).await {
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
    let app = Router::new()
        .route("/healthz", get(health))
        .route(
            "/v1/challenges",
            post(issue_challenge).layer(DefaultBodyLimit::max(MAX_TEMPLATE_JSON_BYTES)),
        )
        .route(
            "/v1/validate",
            post(validate)
                .layer::<_, std::convert::Infallible>(DefaultBodyLimit::max(max_proof_bytes))
                .layer::<_, std::convert::Infallible>(ConcurrencyLimitLayer::new(
                    max_concurrent_validations,
                )),
        )
        .with_state(state)
        .layer(timeout_layer);
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("could not bind HTTP listener to {address}"))?;
    println!("listening=http://{address}");
    println!("health_path=/healthz");
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

async fn validate(
    State(state): State<AppState>,
    proof: Bytes,
) -> Result<Json<SignedCertificate>, ApiError> {
    let service = state.service.clone();
    let permit = state
        .validation_slots
        .clone()
        .acquire_owned()
        .await
        .map_err(ApiError::internal)?;
    let validation_started_at = now_unix_seconds().map_err(ApiError::internal)?;
    let validated = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        service.validate_owned_submission(proof, validation_started_at)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(|error| ApiError::invalid("invalid-validation-submission", error))?;
    let certificate_issued_at = now_unix_seconds().map_err(ApiError::internal)?;
    let certified = state
        .service
        .certify(validated, certificate_issued_at)
        .map_err(|error| ApiError::invalid("certificate-policy-rejected", error))?;
    Ok(Json(certified.certificate))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn keygen(signing_key_path: &Path, public_key_path: &Path) -> Result<()> {
    let signing_key = SigningKey::generate(&mut OsRng);
    write_new_secret(
        signing_key_path,
        hex::encode(signing_key.to_bytes()).as_bytes(),
    )?;
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
