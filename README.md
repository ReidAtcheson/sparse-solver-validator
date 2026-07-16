# sparse-solver-validator

A modular Rust implementation of challenge-driven sparse linear-system
validation. Public `A,b` come from a versioned generator; the prover reads `x`
from a file; and direct, exact, and provisional fast backends share strict
statement and artifact infrastructure.

The mathematical protocols come from the `sparse-solution-stark` research
implementation and the accompanying validated-solution design. That repository
is the protocol/conformance oracle, not the crate graph copied here. This rewrite
factors reusable generators, public multilinear-extension evaluation, fixed
relations, sumcheck, commitments, metric primitives, service protocol, and
backend dispatch behind explicit boundaries.

This is development software and has not received an external security or
numerical audit.

> `direct-reference-v1` is not succinct and does not hide `x`.
> `whir-field192-l2-v4` proves an exact integer statement about once-quantized
> Q63.64 `x`. `fast-binary64-unit-circle-v2` is an experimental metric
> certificate with no completed global numerical soundness theorem. None of the
> profiles claims zero knowledge.

## Workspace

- `ssv-canonical`: canonical big-endian encoding, bounded decoding, typed digests
- `ssv-problem`: templates, seed finalization, generators, certificates, and the
  generator-owned succinct matrix/RHS MLE evaluator
- `ssv-solution`: strict binary64 solution-vector input
- `ssv-relation`: shared Q63.64 conversion and exact integer residual relation
- `ssv-service-protocol`: manifests, signed problem/post-commit challenges, and
  typed certificates
- `ssv-validation`: common statements, restricted succinct-verifier view,
  artifact framing, and backend lifecycle traits
- `ssv-direct`: non-succinct independent streaming `Ax-b` checker
- `ssv-field-sumcheck`: reusable finite-field sumcheck
- `ssv-whir-pcs`: pinned Field192/WHIR commitment profile
- `ssv-exact`: exact Q63.64/Field192 sparse-solve backend
- `ssv-fast`: binary64 metric sumcheck, unit-circle/Merkle primitives, and fast
  backend
- `ssv-backends`: exhaustive application dispatch and certificate-score mapping
- `ssv-service`: transport-independent stateless issuance and validation logic
- `sparse-problem`: finalize, inspect, export, and fixture helpers
- `sparse-prover`: read `x` from a file and build a proof artifact
- `sparse-validator`: inspect, verify, and authenticate certificates
- `sparse-validator-server`: localhost/Cloud Run-compatible HTTP adapter

See [architecture.md](docs/architecture.md), [protocol.md](docs/protocol.md), and
[benchmarking.md](docs/benchmarking.md) for component boundaries, exact/fast
semantics, security limits, and the measurement method required before making
performance claims about this rewrite.

## Local direct workflow

The checked-in local example uses an explicit literal seed and a manufactured
RHS for which `x=1` is the known solution.

```sh
cargo run -p sparse-problem -- finalize-local \
  --template examples/local-template.json \
  --problem /tmp/problem.json

cargo run -p sparse-problem -- manufactured-solution \
  --problem /tmp/problem.json \
  --solution /tmp/x.json

cargo run -p sparse-prover -- prove \
  --problem /tmp/problem.json \
  --validation examples/direct-validation.json \
  --solution /tmp/x.json \
  --proof /tmp/validation.proof

cargo run -p sparse-validator -- verify \
  --proof /tmp/validation.proof \
  --allow-literal
```

`manufactured-solution` is a development fixture helper. A real solver writes a
solution file with this shape (the illustrative array below is for a
three-dimensional problem):

```json
{
  "schema": "sparse-solve/solution/binary64-v1",
  "values": ["1.0", "-2.5", "0"]
}
```

The array length must equal the problem dimension. Values are decimal strings,
not JSON numbers; NaN, infinity, negative zero, and subnormal values are rejected.

Export the same public `A,b` without materializing a dense matrix:

```sh
cargo run -p sparse-problem -- export \
  --problem /tmp/problem.json \
  --matrix /tmp/A.mtx \
  --rhs /tmp/b.mtx
```

`sparse-validator inspect` labels its output unverified. Only `verify` evaluates
the relation and constructs a validated result.

## Local exact and fast workflows

Use release builds for the proof backends. The exact profile is a one-stage
Fiat--Shamir proof over the same finalized problem and solution:

```sh
cargo run --release -p sparse-prover -- prove \
  --problem /tmp/problem.json \
  --validation examples/exact-validation.json \
  --solution /tmp/x.json \
  --proof /tmp/exact.proof

cargo run --release -p sparse-validator -- verify \
  --proof /tmp/exact.proof \
  --allow-literal
```

For local fast testing, select the explicitly encoded offline Fiat--Shamir
mode. It is not an automatic fallback when a signed post-commit challenge is
missing:

```sh
cargo run --release -p sparse-prover -- fast-commit \
  --problem /tmp/problem.json \
  --validation examples/fast-validation.json \
  --solution /tmp/x.json \
  --nonce-mode offline \
  --precommitment /tmp/fast.precommitment

cargo run --release -p sparse-prover -- fast-prove \
  --problem /tmp/problem.json \
  --validation examples/fast-validation.json \
  --solution /tmp/x.json \
  --precommitment /tmp/fast.precommitment \
  --proof /tmp/fast.proof

cargo run --release -p sparse-validator -- verify \
  --proof /tmp/fast.proof \
  --allow-literal \
  --allow-offline-fast
```

The fast validator enforces the frozen consistency policy but does not apply a
caller-selected residual-quality threshold. Its reported residual is a
provisional binary64 metric, not the exact profile's dyadic result.

## Local signed service workflow

Generate a development key once:

```sh
cargo run -p sparse-validator-server -- keygen \
  --signing-key /tmp/validator.key \
  --public-key /tmp/validator.pub
```

Start the service. It defaults to `0.0.0.0:$PORT`; loopback is convenient for
local development. Its default maximum solution length is 16,777,216 elements,
which matches the checked-in validation manifest. The HTTP proof-body cap is
derived from that element limit, and the default request deadline is 120
seconds:

```sh
cargo run -p sparse-validator-server -- serve \
  --host 127.0.0.1 \
  --port 8080 \
  --signing-key /tmp/validator.key \
  --issuer local-validator \
  --key-id local-key-v1
```

Issue and verify a template-bound challenge:

```sh
curl --fail --silent --show-error \
  -H 'content-type: application/json' \
  --data-binary @examples/challenge-template.json \
  http://127.0.0.1:8080/v1/challenges \
  -o /tmp/challenge.json

cargo run -p sparse-problem -- finalize-challenge \
  --template examples/challenge-template.json \
  --challenge /tmp/challenge.json \
  --public-key /tmp/validator.pub \
  --issuer local-validator \
  --key-id local-key-v1 \
  --problem /tmp/hosted-problem.json
```

Produce a submission from a solver-owned `x` file:

```sh
cargo run -p sparse-problem -- manufactured-solution \
  --problem /tmp/hosted-problem.json \
  --solution /tmp/x.json

cargo run -p sparse-prover -- prove \
  --problem /tmp/hosted-problem.json \
  --validation examples/direct-validation.json \
  --solution /tmp/x.json \
  --challenge /tmp/challenge.json \
  --proof /tmp/hosted.proof
```

The hosted proof can also be checked offline while its challenge is valid:

```sh
cargo run -p sparse-validator -- verify \
  --proof /tmp/hosted.proof \
  --public-key /tmp/validator.pub \
  --issuer local-validator \
  --key-id local-key-v1
```

Submit the self-contained proof and authenticate the returned certificate:

```sh
curl --fail --silent --show-error \
  -H 'content-type: application/octet-stream' \
  --data-binary @/tmp/hosted.proof \
  http://127.0.0.1:8080/v1/validate \
  -o /tmp/certificate.json

cargo run -p sparse-validator -- verify-certificate \
  --certificate /tmp/certificate.json \
  --public-key /tmp/validator.pub \
  --issuer local-validator \
  --key-id local-key-v1
```

`verify-certificate` authenticates the signed payload and expected issuer/key.
It does not re-run the proof, check certificate freshness, or compare the
certificate's digests with local proof or challenge files.

The exact hosted flow is identical except that the prover uses
`examples/exact-validation.json`. Fast external mode adds a commitment-bound
challenge between its two prover stages:

```sh
cargo run --release -p sparse-prover -- fast-commit \
  --problem /tmp/hosted-problem.json \
  --validation examples/fast-validation.json \
  --solution /tmp/x.json \
  --challenge /tmp/challenge.json \
  --nonce-mode external \
  --precommitment /tmp/fast.precommitment \
  --challenge-request /tmp/commitment-request.json

curl --fail --silent --show-error \
  -H 'content-type: application/json' \
  --data-binary @/tmp/commitment-request.json \
  http://127.0.0.1:8080/v1/commitment-challenges \
  -o /tmp/commitment-challenge.json

cargo run --release -p sparse-prover -- fast-prove \
  --problem /tmp/hosted-problem.json \
  --validation examples/fast-validation.json \
  --solution /tmp/x.json \
  --challenge /tmp/challenge.json \
  --precommitment /tmp/fast.precommitment \
  --commitment-challenge /tmp/commitment-challenge.json \
  --proof /tmp/fast-hosted.proof

curl --fail --silent --show-error \
  -H 'content-type: application/octet-stream' \
  --data-binary @/tmp/fast-hosted.proof \
  http://127.0.0.1:8080/v1/validate \
  -o /tmp/fast-certificate.json
```

The signed post-commit challenge authenticates that the exact fast commitment
digest preceded fresh service entropy and its timestamp. Because the service is
stateless, it still cannot make the challenge one-shot or prevent replay.

For Cloud Run, leave the host as `0.0.0.0` and let the platform set `PORT`.
Clients connect to the service URL, never to `0.0.0.0`. This repository provides
the compatible listener, but not container or deployment manifests. The current
server reads a hexadecimal signing key from a file, which a deployment must
provide through an appropriately protected secret mount. Set
`--maximum-solution-elements` to fit the deployment's request-size and memory
budget; the service derives its proof-body cap from that value.

## Semantics and limitations

- `A` and `b` are public and regenerated from the finalized typed problem.
- A hosted matrix seed derives from the canonical unsigned challenge payload
  and template digest. The signature authenticates that payload but is excluded
  from the seed, as is JSON formatting.
- The service reports residual metrics for one submission. It applies no quality
  threshold and does not call the result “best.”
- The challenge endpoint signs fresh entropy for a caller-selected, digest-bound
  template. A relying party treating certificates as benchmark credentials must
  pin the expected template/problem; otherwise trivial families and seed
  grinding are intentionally possible.
- The service is stateless. Expiry is enforced, but replay prevention, one-shot
  challenges, and a global best residual require durable transactional state.
- External fast mode requires a second signed challenge after witness
  commitment. The initial matrix challenge cannot substitute for that nonce;
  local offline mode is separately tagged and must be explicitly allowed by the
  validator.
- The built-in timeout, body limit, and validation concurrency cap are local
  safety controls. Production authentication, quotas/rate limits, bounded edge
  admission, and protected key management remain deployment responsibilities.

## Development checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Use `--release` for performance measurements.
