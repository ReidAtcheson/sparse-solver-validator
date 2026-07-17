# Deploying the validator to Google Cloud Run

This runbook deploys `sparse-validator-server` from the repository root with
`gcloud run deploy --source .`. It is private by default, uses a dedicated
runtime service account, and keeps the Ed25519 signing key in Secret Manager.
It does not cover production admission control, quotas, audit retention, or key
custody.

Cloud Run can execute a container written in any language, but Rust is not in
the list of languages supported by Google Cloud's source-deployment buildpacks.
This repository therefore needs a `Dockerfile` in the source directory. When a
Dockerfile is present, source deploy builds it with Cloud Build and stores the
image in Artifact Registry; without one, `gcloud` attempts buildpack language
detection. See Google's [source deployment
documentation](https://cloud.google.com/run/docs/deploying-source-code) and
[`gcloud run deploy` reference](https://cloud.google.com/sdk/gcloud/reference/run/deploy).

## 1. Choose names and a region

Keep project/account-specific values outside the commands and source tree. Copy
the versioned, non-secret template to the ignored local configuration file,
edit it for the target project, then source it in every deployment shell:

```sh
cp deploy/gcp.env.example deploy/gcp.env
${EDITOR:-vi} deploy/gcp.env
. ./deploy/gcp.env
```

`deploy/gcp.env` is ignored by Git and excluded from the Cloud Build context.
It contains resource names and policy choices, not the private signing seed or
Google credentials. Use a stable issuer string and change `KEY_ID` whenever the
Ed25519 key changes.

Select a Cloud Run region that also supports Cloud Build and Artifact Registry.
The project must have billing enabled, and the Google Cloud CLI must be installed,
initialized, and authenticated.

```sh
gcloud config set project "${PROJECT_ID}"
gcloud config set run/region "${REGION}"
```

## 2. Enable APIs and establish IAM

Source deployment with a stored signing key uses these APIs:

```sh
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  --project "${PROJECT_ID}"
```

Enabling APIs requires `roles/serviceusage.serviceUsageAdmin` or equivalent
permissions. The routine source deployer needs:

- `roles/run.sourceDeveloper` on the project;
- `roles/serviceusage.serviceUsageConsumer` on the project; and
- `roles/iam.serviceAccountUser` on the selected Cloud Run runtime identity.

Bootstrap administration additionally needs permission to create service
accounts and secrets and to change their IAM policies. Keep those permissions
out of the routine deployer and both service identities.

Cloud Build also needs a build identity with `roles/run.builder`. Do not rely on
a broadly privileged default Compute Engine account: create a dedicated build
identity. It is separate from the runtime identity created below. Google's [source-deploy IAM
documentation](https://cloud.google.com/run/docs/deploying-source-code#required-roles)
and [build service-account
guide](https://cloud.google.com/run/docs/configuring/services/build-service-account)
are authoritative for these grants.

Create dedicated build and runtime identities. Do not give the runtime identity
source-build or broad project roles.

```sh
gcloud iam service-accounts create "${BUILD_SA_NAME}" \
  --project "${PROJECT_ID}" \
  --display-name "Sparse validator Cloud Build"

gcloud iam service-accounts create "${RUNTIME_SA_NAME}" \
  --project "${PROJECT_ID}" \
  --display-name "Sparse validator Cloud Run runtime"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member "serviceAccount:${BUILD_SA_EMAIL}" \
  --role roles/run.builder \
  --condition None
```

An administrator must grant the deploying principal
`roles/iam.serviceAccountUser` on `${RUNTIME_SA_EMAIL}`. Later, the runtime
identity receives access only to its signing secret.

The explicit private/public IAM flags used below can also require
`run.services.setIamPolicy`; `roles/run.admin` includes that permission. Keep
that administrative grant separate from the runtime identity.

## 3. Generate and store the signing key

Generate the Ed25519 keypair locally. The private key is sensitive; never add it
to the repository, container image, build context, or ordinary environment
variables.

```sh
umask 077
cargo run --release -p sparse-validator-server -- keygen \
  --signing-key "${SIGNING_KEY_FILE}" \
  --public-key "${PUBLIC_KEY_FILE}"
```

The private file is exactly one 32-byte Ed25519 seed encoded as 64 lowercase
hexadecimal characters plus a newline. The public file is the 32-byte compressed
Ed25519 public key in the same textual form. PEM, base64, JSON, and expanded
64-byte private keys are not accepted. After uploading the seed, either retain
the local file under an explicit offline custody policy or remove the working
copy; `/tmp` is not durable key storage.

Create the secret once, then add the private key as a secret version:

```sh
gcloud secrets create "${SIGNING_SECRET}" \
  --project "${PROJECT_ID}" \
  --replication-policy automatic

gcloud secrets versions add "${SIGNING_SECRET}" \
  --project "${PROJECT_ID}" \
  --data-file "${SIGNING_KEY_FILE}"
```

List the enabled versions and record the numeric version printed by Google
Cloud. Do not use `latest` in the deployment command: a numeric version makes
the revision's signing identity reproducible.

```sh
gcloud secrets versions list "${SIGNING_SECRET}" \
  --project "${PROJECT_ID}" \
  --filter 'state=ENABLED' \
  --format 'table(name,state,createTime)'

export SIGNING_SECRET_VERSION="1"
```

Grant the runtime identity only the secret-access permission it needs:

```sh
gcloud secrets add-iam-policy-binding "${SIGNING_SECRET}" \
  --project "${PROJECT_ID}" \
  --member "serviceAccount:${RUNTIME_SA_EMAIL}" \
  --role roles/secretmanager.secretAccessor
```

Cloud Run's [secret configuration
guide](https://cloud.google.com/run/docs/configuring/services/secrets) documents
file mounts, version selection, and the required Secret Accessor role.

## 4. Deploy privately from the Dockerfile

Run this command from the repository root after its multi-stage `Dockerfile` is
present. The image command must start `sparse-validator-server serve`; the
server already defaults to `0.0.0.0` and reads Cloud Run's injected `PORT`
variable.

```sh
gcloud run deploy "${SERVICE}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --source . \
  --build-service-account "${BUILD_SA_RESOURCE}" \
  --service-account "${RUNTIME_SA_EMAIL}" \
  --set-env-vars "SSV_SIGNING_KEY_FILE=/var/run/secrets/ssv/signing.key,SSV_ISSUER=${ISSUER},SSV_KEY_ID=${KEY_ID},RAYON_NUM_THREADS=1" \
  --set-secrets "/var/run/secrets/ssv/signing.key=${SIGNING_SECRET}:${SIGNING_SECRET_VERSION}" \
  --timeout 300s \
  --cpu "${CPU}" \
  --memory "${MEMORY}" \
  --concurrency "${CONCURRENCY}" \
  --max "${MAX_INSTANCES}" \
  --max-instances "${MAX_INSTANCES}" \
  --args "serve,--challenge-lifetime-seconds=${CHALLENGE_LIFETIME_SECONDS},--max-concurrent-validations=1,--request-timeout-seconds=${REQUEST_TIMEOUT_SECONDS}" \
  --invoker-iam-check \
  --no-allow-unauthenticated
```

Both private-access flags are intentional. `--invoker-iam-check` ensures the IAM
invoker check is enabled, while `--no-allow-unauthenticated` avoids or removes an
`allUsers` invoker grant. The deployment remains reachable at its HTTPS URL, but
only callers with `run.routes.invoke` can pass the Cloud Run authentication
layer.

Cloud Run injects `PORT` and requires the ingress container to listen on that
port on `0.0.0.0`, not `127.0.0.1`. TLS terminates at Cloud Run. See the
[container runtime contract](https://cloud.google.com/run/docs/container-contract).

## 5. Redeploy after a code change

API enablement, service-account creation, IAM grants, and key generation are
one-time bootstrap operations. A normal code-change deployment reuses the same
numeric secret version and identities:

```sh
. ./deploy/gcp.env

cargo +stable fmt --all -- --check
cargo +stable test --workspace --all-targets --all-features --locked
cargo +stable clippy --workspace --all-targets --all-features --locked -- -D warnings

gcloud meta list-files-for-upload
```

Review the upload list: `--source .` deploys the current working tree, including
uncommitted files not excluded by `.gcloudignore`. Then rerun the **complete**
deploy command from section 4. Keeping the full command in the runbook makes the
runtime identity, build identity, secret version, resource caps, and protocol
timeouts explicit instead of relying on sticky service configuration.

Preserve the intended access mode when rerunning it:

- For `DEPLOYMENT_ACCESS="private"`, retain `--invoker-iam-check` and
  `--no-allow-unauthenticated`.
- For `DEPLOYMENT_ACCESS="public"`, replace those two flags with
  `--no-invoker-iam-check`. No identity token is then required.

Cloud Build constructs a new image from the Dockerfile, Cloud Run creates an
immutable revision, and traffic moves to it after the revision becomes ready.
Confirm which revision received traffic and smoke-test it:

```sh
gcloud run services describe "${SERVICE}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format 'value(status.latestReadyRevisionName,status.url)'

export SERVICE_URL="$(gcloud run services describe "${SERVICE}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format 'value(status.url)')"

curl --fail --silent --show-error "${SERVICE_URL}/health"
```

For a private service, add the identity-token header shown in the next section
to the smoke-test request. A health check alone is not a protocol test; also
issue a signed challenge and submit at least one small proof before declaring a
new revision good.

## 6. Grant a caller and run an authenticated smoke test

Grant `roles/run.invoker` to the developer or group that will test the private
service. This is an invocation role, not the service's runtime identity.

```sh
export CALLER_EMAIL="developer@example.com"

gcloud run services add-iam-policy-binding "${SERVICE}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --member "user:${CALLER_EMAIL}" \
  --role roles/run.invoker
```

Obtain the deployed URL and call the health endpoint with the active `gcloud`
user's identity token:

```sh
export SERVICE_URL="$(gcloud run services describe "${SERVICE}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format 'value(status.url)')"

curl --fail --silent --show-error \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "${SERVICE_URL}/health"
```

The application deliberately uses `/health`, not `/healthz`: Google reserves
some paths ending in `z` and can intercept them before they reach the container.

The same header authenticates a development challenge request:

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H 'content-type: application/json' \
  --data-binary @examples/challenge-template.json \
  "${SERVICE_URL}/v1/challenges" \
  -o /tmp/challenge.json
```

Google documents this development flow in [Authenticate
developers](https://cloud.google.com/run/docs/authenticating/developers). A
`gcloud` user token is appropriate for a smoke test. Production callers should
use an audience-bound ID token and a workload or service identity rather than a
downloaded service-account key.

## 7. Pin the public trust anchor

Distribute `${PUBLIC_KEY_FILE}` to relying parties through a channel independent
of the validator service. A client must pin all three of:

- the Ed25519 public key;
- the exact `ISSUER` string; and
- the exact `KEY_ID` string.

Do not treat a key returned by the same untrusted HTTP response as a trust
anchor. The repository CLIs require the pinned tuple when finalizing a signed
problem or checking a certificate:

```sh
cargo run -p sparse-problem -- finalize-challenge \
  --template examples/challenge-template.json \
  --challenge /tmp/challenge.json \
  --public-key "${PUBLIC_KEY_FILE}" \
  --issuer "${ISSUER}" \
  --key-id "${KEY_ID}" \
  --problem /tmp/hosted-problem.json

cargo run -p sparse-validator -- verify-certificate \
  --certificate /tmp/certificate.json \
  --public-key "${PUBLIC_KEY_FILE}" \
  --issuer "${ISSUER}" \
  --key-id "${KEY_ID}"
```

Signature verification alone does not establish certificate freshness, expected
problem or proof digests, or an application-specific residual threshold. The
relying party must pin and enforce those separately.

## 8. Public access is an explicit opt-in

Cloud Run services are private by default. If this API is intentionally public,
the current Google recommendation is to disable the Invoker IAM check:

```sh
gcloud run services update "${SERVICE}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --no-invoker-iam-check
```

The alternative `--allow-unauthenticated` flow grants `roles/run.invoker` to
`allUsers`; organization domain-restricted-sharing policy can reject that grant.
See [Allowing public
access](https://cloud.google.com/run/docs/authenticating/public). This server has
no additional caller-authentication layer, so making Cloud Run public exposes
challenge issuance and proof validation to every Internet caller. Configure
edge admission, quotas, rate limiting, and audit policy before doing so.

To restore the IAM check, use `--invoker-iam-check`. If public access was granted
through an `allUsers` IAM binding, remove that binding as a separate step.

## 9. Rotate keys by deploying a new revision

A numeric Secret Manager version stays pinned to the Cloud Run revision. Adding
a new secret version does not update the deployed revision, and this server
loads its signing key at process startup rather than polling the mounted file.

The current server has one active signing key and verifies submitted challenges
with that same key. Do **not** split traffic between revisions carrying different
keys: a challenge issued by one revision can be routed to the other revision at
submission time and be rejected.

Until the server supports a verification keyring, use a blue/green service
rotation:

1. Generate a new local keypair and add its seed as a new numeric secret version.
2. Choose a new `KEY_ID`; never reuse one key ID for a different public key.
3. Deploy a separately named service with the new secret version and key ID.
4. Publish and pin the new endpoint, issuer, key ID, and public key together.
5. Keep the old service available until its last challenge has expired and all
   in-flight submissions have drained.
6. Remove traffic from the old service and terminate its revisions before
   disabling the old private secret version.

Retain the old *public* trust anchor for as long as old certificates must remain
verifiable. The old private seed is needed only while an old revision must sign
certificates for still-valid challenges; disabling its Secret Manager version
does not revoke a copy already loaded into a running instance.

## 10. Request size and timeout constraints

Cloud Run currently limits an HTTP/1 request to **32 MiB**. It lists no request
size limit for an end-to-end HTTP/2 server, but enabling `--use-http2` requires
the container to support cleartext HTTP/2 (`h2c`) after Cloud Run terminates TLS.
This deployment deliberately stays on the ordinary HTTP/1 path until that mode
is implemented and tested. The effective upload limit is therefore the smaller
of 32 MiB and the server's own proof-body limit. An oversized request can be
rejected by Cloud Run before Axum sees it. Cloud Run also limits a non-streamed
HTTP/1 response to 32 MiB. See [Cloud Run quotas and
limits](https://cloud.google.com/run/quotas).

The Cloud Run request timeout defaults to 300 seconds and can be configured from
1 to 3600 seconds. On expiry, Cloud Run closes the connection and returns 504;
the container may continue processing the abandoned request. This server has a
separate default handler deadline of 120 seconds. The example retains Cloud
Run's 300-second timeout so the application deadline normally fires first. If
either value changes, keep the platform timeout longer than the application
deadline and test the largest supported proofs. See [Configure request
timeout](https://cloud.google.com/run/docs/configuring/request-timeout).

## 11. Migration notes for another GCP project or account

The repository contains no deployed project ID, account email, generated Cloud
Run URL, or private key. Those values live in the ignored `deploy/gcp.env`, GCP
IAM, and Secret Manager. Create a separate configuration file for each target
project rather than editing commands or source code.

The following resources are project-scoped and must be recreated or deliberately
transferred:

| Resource or setting | Migration action |
|---|---|
| Billing, APIs, quotas, budgets, and alerting | Enable and configure in the target project. |
| Build and runtime service accounts | Recreate from section 2 and reapply least-privilege IAM. |
| Signing secret | Create in the target Secret Manager; either transfer the existing seed securely or generate a new identity. |
| Artifact Registry image and source-upload bucket | Let the first source deployment recreate them; build history is not portable state. |
| Cloud Run service and revisions | Redeploy from source; do not try to copy revisions. |
| Invoker principals and public/private mode | Reapply explicitly; IAM bindings do not follow the source. |
| Service URL | Expect it to change because the generated hostname includes target-project identity. Update client endpoint configuration. |
| Load balancer, Cloud Armor, DNS, and TLS | Recreate separately when those resources are introduced. |
| Logs, metrics, audit retention, and certificates | Export or retain them according to the old project's retention policy. |

A migration has two signing-identity choices:

**Preserve the identity.** Put the same 32-byte seed into a new target-project
secret version and retain the same `ISSUER`, `KEY_ID`, and public-key pin. This
avoids a client trust-anchor change. Perform the seed transfer through a secure
operator channel without printing it to a terminal or placing it in source.
During overlap the private key exists in both projects, so restrict access and
retire the old runtime and secret promptly after its challenges drain.

**Rotate the identity.** Generate a new seed, use a new `KEY_ID`, and distribute
the new public-key pin before cutover. Keep the old endpoint available for its
unexpired challenges, following the blue/green procedure in section 9. Never
reuse a key ID for a different public key.

For either choice, a practical migration sequence is:

1. Copy `deploy/gcp.env.example` to a new ignored environment file and fill in
   the target project, region, resource names, access mode, and policy limits.
2. Authenticate `gcloud` to the target account and verify billing and project
   selection. Every command in this runbook still carries explicit `--project`
   and `--region` arguments to reduce cross-project mistakes.
3. Enable APIs; bootstrap the dedicated build/runtime identities and target
   secret; grant only the documented roles.
4. Deploy the target service privately first and complete the health,
   challenge, proof, and certificate smoke tests with the target public key.
5. Apply the intended public or private access mode, then update clients to the
   new URL and trust tuple.
6. Drain the old service, preserve public verification material and audit data,
   and retire old private-key access according to the chosen identity strategy.

Treat `ISSUER` as the validator service's durable logical identity, not as a GCP
project name. `validator_build` is expected to change because it records each
Cloud Run revision. The GCP URL is transport configuration and is not itself a
signature trust anchor.
