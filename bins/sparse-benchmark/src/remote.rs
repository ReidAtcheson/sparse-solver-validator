use std::io::Read;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::CONTENT_TYPE;
use ssv_problem::ProblemTemplate;
use ssv_service_protocol::{SignedCertificate, SignedChallenge};

use crate::model::{RemoteAuthentication, RemoteAuthorityRef};

const MAX_CHALLENGE_JSON_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATE_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 64 * 1024;
const MAX_IDENTITY_TOKEN_BYTES: usize = 64 * 1024;

pub(crate) trait RemoteApi {
    fn issue_challenge(
        &self,
        authority: RemoteAuthorityRef<'_>,
        template: &ProblemTemplate,
    ) -> Result<SignedChallenge>;

    fn submit_proof(
        &self,
        authority: RemoteAuthorityRef<'_>,
        proof: Vec<u8>,
    ) -> Result<SignedCertificate>;
}

pub(crate) struct HttpRemoteApi {
    client: Client,
}

impl HttpRemoteApi {
    pub(crate) fn new() -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(300))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("sparse-benchmark/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("could not construct the benchmark HTTP client")?;
        Ok(Self { client })
    }

    fn endpoint(authority: RemoteAuthorityRef<'_>, path: &str) -> Result<reqwest::Url> {
        let base = reqwest::Url::parse(authority.service_url)?;
        base.join(path)
            .context("could not construct service endpoint")
    }

    fn authorize(
        &self,
        request: RequestBuilder,
        authentication: &RemoteAuthentication,
    ) -> Result<RequestBuilder> {
        match authentication {
            RemoteAuthentication::NoneV1 => Ok(request),
            RemoteAuthentication::GcloudIdentityTokenV1 { audience } => {
                Ok(request.bearer_auth(gcloud_identity_token(audience.as_deref())?))
            }
        }
    }
}

impl RemoteApi for HttpRemoteApi {
    fn issue_challenge(
        &self,
        authority: RemoteAuthorityRef<'_>,
        template: &ProblemTemplate,
    ) -> Result<SignedChallenge> {
        let endpoint = Self::endpoint(authority, "/v1/challenges")?;
        let request = self
            .client
            .post(endpoint)
            .header(CONTENT_TYPE, "application/json")
            .json(template);
        let response = self
            .authorize(request, authority.authentication)?
            .send()
            .context("challenge request failed")?;
        decode_json_response(response, MAX_CHALLENGE_JSON_BYTES, "challenge")
    }

    fn submit_proof(
        &self,
        authority: RemoteAuthorityRef<'_>,
        proof: Vec<u8>,
    ) -> Result<SignedCertificate> {
        let endpoint = Self::endpoint(authority, "/v1/validate")?;
        let request = self
            .client
            .post(endpoint)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(proof);
        let response = self
            .authorize(request, authority.authentication)?
            .send()
            .context("proof submission failed")?;
        decode_json_response(response, MAX_CERTIFICATE_JSON_BYTES, "certificate")
    }
}

fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: Response,
    maximum: usize,
    object: &str,
) -> Result<T> {
    let status = response.status();
    let limit = if status.is_success() {
        maximum
    } else {
        MAX_ERROR_BYTES
    };
    let bytes = read_response_bounded(response, limit)?;
    if !status.is_success() {
        let message = String::from_utf8_lossy(&bytes);
        bail!("service returned HTTP {status}: {message}");
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("service returned invalid {object} JSON"))
}

fn read_response_bounded(response: Response, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    response
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .context("could not read service response")?;
    if bytes.len() > maximum {
        bail!("service response exceeds the {maximum}-byte limit");
    }
    Ok(bytes)
}

fn gcloud_identity_token(audience: Option<&str>) -> Result<String> {
    let mut command = Command::new("gcloud");
    command.args(["auth", "print-identity-token"]);
    if let Some(audience) = audience {
        command.arg(format!("--audiences={audience}"));
    }
    let output = command
        .output()
        .context("could not run gcloud to obtain an identity token")?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        bail!("gcloud could not obtain an identity token: {error}");
    }
    if output.stdout.len() > MAX_IDENTITY_TOKEN_BYTES {
        bail!("gcloud identity token exceeds its input limit");
    }
    let token = std::str::from_utf8(&output.stdout)
        .context("gcloud identity token is not UTF-8")?
        .trim();
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        bail!("gcloud returned an invalid identity token");
    }
    Ok(token.to_owned())
}
