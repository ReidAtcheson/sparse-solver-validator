# sparse-solver-validator

A clean Rust implementation of a challenge-driven sparse linear-system
validation service.

The current milestone establishes deterministic public problem generation,
canonical identities, file-based solution input, strict proof framing, Ed25519
challenge/certificate signing, offline verification, Matrix Market export, and
a stateless HTTP service. It intentionally starts with
`direct-reference-v1`, an independent relation checker that transmits the
complete solution vector.

This is development software and has not received an external security or
numerical audit.

> `direct-reference-v1` is not succinct and does not hide `x`. It is the
> integration and correctness oracle for the future exact Field192/WHIR and
> experimental fast binary64 backends.

## Workspace

- `ssv-canonical`: canonical big-endian encoding, bounded decoding, typed digests
- `ssv-problem`: typed templates, seed finalization, generators, certificates
- `ssv-solution`: strict binary64 solution-vector input
- `ssv-service-protocol`: signed challenges, manifests, and certificates
- `ssv-direct`: strict direct artifact and streaming `Ax-b` checker
- `ssv-service`: transport-independent stateless service logic
- `sparse-problem`: finalize, inspect, export, and fixture helpers
- `sparse-prover`: read `x` from a file and build a proof artifact
- `sparse-validator`: inspect, verify, and authenticate certificates
- `sparse-validator-server`: localhost/Cloud Run-compatible HTTP adapter

See [architecture.md](docs/architecture.md) and [protocol.md](docs/protocol.md)
for the boundaries, security model, and succinct-backend roadmap.

## Local workflow

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
- The future fast backend needs a second challenge after witness commitment.
  The initial matrix challenge cannot substitute for that nonce.
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
