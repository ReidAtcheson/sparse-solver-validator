# Architecture

**Status:** implemented direct-reference and stateless-service baseline, plus a
roadmap for later succinct backends

This repository is a clean implementation of a service that validates one
solution of one generated sparse linear system. The research repository remains
a mathematical reference and regression oracle; it is not the module layout for
this project and code should not be copied from it wholesale.

The first usable backend is intentionally simple. It receives the complete
solution vector, independently evaluates the public relation, and reports the
residual. This establishes file formats, generator determinism, command-line
workflows, and service signing before succinct proof machinery and independent
cross-implementation vectors are introduced.

`direct-reference-v1` is **not a succinct proof**. It carries `x`, takes linear
space on the wire, and performs at least `O(nnz(A))` validation work. It exists
only as an integration baseline and as an independent relation checker for the
later exact and fast proof backends.

## 1. Design principles

1. `A` and `b` are public, deterministic outputs of a registered, versioned
   generator. A proof never gets to redefine them.
2. A problem template describes the matrix family, RHS recipe, and randomness
   policy. A local template carries its explicit literal seed; a hosted template
   receives its seed only after a signed challenge finalizes one instance.
3. The mathematical problem is separate from the validation backend. The same
   finalized `A,b` can be checked by the direct, exact, or fast backend.
4. Proving and validation are separate processes. The prover reads `x` from a
   file and writes an artifact; it does not share memory or implementation state
   with the validator.
5. Network transport is outside proof semantics. The same strict submission can
   be verified by the offline validator or sent as an HTTP request.
6. Signed challenge and certificate payloads have canonical binary encodings.
   JSON is their strict transport spelling; signatures are reconstructed from
   typed canonical bytes rather than raw JSON formatting.
7. Each proof version has a fixed verifier. There is no prover-selected proof
   program or generic interpreter.
8. Hot numerical data is flat and contiguous. Parsers validate structure once at
   the boundary, and validated types carry those invariants into hot loops.

## 2. End-to-end flow

The hosted path is:

```text
problem template
      |
      v
challenge service --signs--> signed challenge
      |                              |
      |                    template digest + entropy
      |                              |
      +------------------------------+
                                     v
                           finalized public A,b
                                     |
solution file x --> sparse-prover --> validation submission
                                     |
                                     v
                           sparse-validator-server
                                     |
                        verify one submitted relation
                                     |
                                     v
                              signed certificate
```

The local path replaces the signed challenge with the explicitly tagged
`literal-v1` seed origin. Empty bytes, a zero signature, or a missing
challenge are never interpreted as local mode.

Repeated solves are repeated independent requests. The MVP neither batches
solutions nor maintains a leaderboard.

## 3. Core domain objects

### 3.1 Problem template

A `ProblemTemplate` fixes everything required to interpret public data except
the instance seed:

- matrix family and generator version;
- dimensions, sparsity and boundary rules;
- exact coefficient representation and generation parameters;
- RHS generator and version; and
- requested output, initially squared L2 residual.

The template is canonical and content-addressed. A hosted challenge signs its
template digest, so challenge entropy cannot later be applied to another family
or dimension.

### 3.2 Finalized problem

A `FinalizedProblem` combines a validated template with a 32-byte instance seed.
The seed comes from exactly one tagged origin:

- `challenge-derived-v1`, derived from a verified challenge payload; or
- `literal-v1`, supplied directly for tests, examples, and benchmarks.

The current family derives one sub-seed for matrix off-diagonal values and, for
the seeded RHS variant, one distinct RHS sub-seed. Its tridiagonal support and
diagonal rule are deterministic and need no random stream. Generator code
consumes an `InstanceSeed`; it does not need to know whether the seed was hosted
or local.

The problem digest identifies the complete finalized problem record, including
its seed provenance, not merely an equivalence class of numerically identical
`A,b`. Challenge provenance also has a separate digest bound into hosted
certificates. Signature bytes do not affect `A,b`: re-signing an identical
unsigned challenge payload leaves the instance seed unchanged.

### 3.3 Solution file

A solution file is a versioned, bounded vector input. The prover CLI takes it as
a file; passing millions of values through command-line arguments is not
supported. The implemented solver-facing format is JSON containing decimal
strings. It normalizes into a validated contiguous `Box<[f64]>`, and the proof
artifact contains canonical IEEE bits rather than the original JSON spelling.
The parser rejects NaNs, infinities, negative zero, and subnormals. A future
packed input format or fixed-point encoding would require its own explicit
version; neither is currently accepted by the CLI.

### 3.4 Validation manifest and backend artifact

A validation manifest selects a registered backend and all of its security or
numerical parameters. It is digested separately from the problem so a single
problem can be validated by more than one backend.

The backend artifact is backend-specific:

- `direct-reference-v1` contains the complete canonical `x` vector;
- an exact artifact will contain commitments, sumcheck messages, openings, and
  an exact residual claim, but not `x`; and
- a fast artifact will contain a committed numerical encoding and sampled
  openings, but not `x`.

Every artifact binds the problem digest, validation-manifest digest, backend ID,
and backend version.

### 3.5 Submission, result, and certificate

A validation submission packages the finalized problem provenance, validation
manifest, and backend artifact in one strict file. The core verifier returns a
typed backend validation result; it has no signing key and performs no network
I/O.

The service signs a `ValidationCertificate` only after core verification. A
certificate reports the residual established for **one submission**. It does not
claim that the residual is globally best, that the solution is optimal, or that
the challenge was used only once.

## 4. Initial Rust workspace

The initial workspace uses small crates with one-directional dependencies. Core
crates do not depend on CLI, HTTP, or a concrete key-storage mechanism.

| Crate | Responsibility | Explicitly does not own |
| --- | --- | --- |
| `ssv-canonical` | Canonical primitives, bounded readers/writers, typed digests, domain-separated BLAKE3 helpers, strict framing | Generators, signatures, numerical validation |
| `ssv-problem` | Template parsing, seed finalization, family registry, deterministic row/RHS generation, generator certificates | Service policy, proof messages, HTTP |
| `ssv-solution` | Strict solution-vector formats and validated flat storage | Matrix generation, proving, scoring |
| `ssv-service-protocol` | Challenge, manifest, result, and certificate types; Ed25519 signing and verification; timestamp policy | Numerical relation checks, private-key persistence, HTTP server state |
| `ssv-direct` | Independent `direct-reference-v1` prover/decoder and sparse relation checker | Succinctness or privacy claims, service signing |
| `ssv-service` | Stateless challenge issuance, provenance checks, and post-validation certificate construction | HTTP, clocks, entropy sources, key files |

Dependencies should flow approximately as follows:

```text
ssv-canonical
   |-- ssv-problem
   |-- ssv-solution
   `-- ssv-service-protocol

ssv-direct --> canonical + problem + solution + service-protocol types
ssv-service --> direct + problem + service-protocol
```

If `ssv-direct` only needs shared validation output types, those types should live
in a small neutral module rather than making protocol code depend back on a
backend.

Later exact and fast crates should be added around stable mathematical
components, for example `ssv-transcript`, `ssv-sumcheck`, `ssv-exact`,
`ssv-fast`, and backend-specific commitment crates. Sharing is earned by a clear
common contract; exact field arithmetic and provisional binary64 checks should
not be forced behind a misleading common arithmetic abstraction.

## 5. Executable targets

### `sparse-problem`

The problem helper owns generator-facing workflows:

- validate and inspect a problem template;
- finalize a template from a signed challenge or literal local seed;
- print the derived seed and canonical digests;
- materialize `A,b` for interoperability; and
- export generated data to Matrix Market matrix and vector files.

Exports are derived views, not new problem identities. The current Matrix Market
files include the source problem digest and standard format dimensions; Matrix
Market itself supplies the one-based index and scalar conventions. Dedicated
CSR, solver-specific vector, export-manifest, and file-checksum formats are
future work. The canonical generator specification remains the source of truth.

### `sparse-prover`

The prover reads a finalized problem, validation manifest, `x` file, and a signed
challenge for hosted problems. Literal local problems omit the challenge. It
writes one self-contained backend artifact:

```text
sparse-prover prove --problem problem.json \
                    --validation validation.json \
                    --solution x.json \
                    --challenge challenge.json \
                    --proof validation.proof
```

For `direct-reference-v1`, this packages canonical `x`; it does not make the
result succinct. Future exact and fast backends use the same file boundary while
producing different, versioned payloads.

### `sparse-validator`

The offline validator provides three distinct operations:

- `verify` runs the same core relation and challenge-provenance checks as the
  service and prints a stable human-readable result;
- `inspect` prints a human-readable, explicitly non-authoritative proof view; and
- `verify-certificate` authenticates a JSON certificate against an external key.

Inspection must never imply verification. Unknown versions and malformed trailing
bytes are errors even when the known prefix could be displayed. The implemented
inspection output is human-readable key/value text; there is currently no JSON
inspection mode.

Offline proof verification applies caller-selected key, clock-skew, and maximum
challenge-lifetime policy. The hosted service additionally applies its configured
exact challenge lifetime and maximum solution-element policy. Certificate
verification authenticates the signed payload and expected issuer/key; it does
not re-run the proof, impose certificate freshness, or compare the recorded
digests with caller-supplied files.

### `sparse-validator-server`

The server is a thin HTTP and signing layer around the same libraries:

- `GET /healthz` performs a shallow liveness check;
- `POST /v1/challenges` validates strict typed template JSON and returns a signed
  challenge as JSON; and
- `POST /v1/validate` accepts one canonical submission and returns a signed
  certificate or a bounded, unsigned error response.

A later fast backend may add a post-commit challenge endpoint. That challenge is
separate from the problem-instance challenge; see `protocol.md`.

## 6. Generator and relation-checker boundaries

A registered family should compile untrusted parameters into a validated plan.
The logical interface provides:

```text
identity and version
logical dimensions and structural nonzero count
deterministic sorted, duplicate-free row iteration
deterministic RHS entry generation
coefficient and work certificates
canonical compiled parameters
```

Succinct backends additionally require public multilinear-extension evaluation.
That capability belongs to a generator implementation or a reviewed evaluation
plan, not to the proof payload. The initial direct checker can stream every row;
an exact or fast manifest may later reject families without an appropriately
cheap public evaluator.

The direct relation checker keeps `x` contiguous and streams rows in increasing
index order. It need not materialize `A`. A future CSR export should use three
flat arrays (`row_offsets`, `column_indices`, and `values`) and establish sorted
columns, unique entries, valid offsets, dimensions, and allocation bounds at
construction time.

Residual evaluation has a named, frozen operation order. Parallel reductions,
FMA contraction, and platform-dependent extended precision are not enabled
silently because they can change binary64 certificate bits. There is currently
one deliberately simple implementation. Any later optimized kernel must be
tested against that path on the same generator rows.

## 7. Service deployment model

The service is horizontally scalable and keeps no request or result state in
process memory or local disk. The current service owns a concrete Ed25519 signing
key loaded from a hexadecimal file by the HTTP binary. A narrow signer interface
and direct managed-signing-service integration are future work; a deployment can
currently provide the key file through an appropriately protected secret mount.

For Cloud Run, the HTTP listener binds to:

```text
0.0.0.0:$PORT
```

where `PORT` comes from the environment. `0.0.0.0` is a listen address, not a
client destination. Local clients connect to `http://127.0.0.1:$PORT`; deployed
clients use the Cloud Run service URL. Local development may explicitly bind to
`127.0.0.1` when external access is undesirable.

The server applies request-size, decoded-element, dimension, nonzero, and
proof-size limits before expensive allocation or work. CPU-heavy validation runs
outside the asynchronous I/O executor behind a configured concurrency limit and
an owned work permit that survives client cancellation. The proof-body cap is
derived from the decoded-element cap, and the adapter enforces a request
deadline. Authentication, rate limits/quotas, edge admission, and any tighter
platform deadline remain deployment configuration.

Statelessness has important semantic limits:

- it cannot remember that a challenge has already been submitted;
- it cannot enforce a truly one-shot nonce or prevent replay;
- it cannot compare a residual with all prior residuals; and
- it cannot maintain a global or per-problem best result.

Expiry checks and unpredictable entropy reduce accidental or stale use but do not
provide those properties. One-shot use or a leaderboard requires durable,
transactional state keyed by challenge or problem digest. Per-instance memory in
a serverless container is not a substitute because instances restart, scale out,
and handle requests concurrently.

## 8. Trust and security boundaries

- Generator parameters, solution files, submissions, and HTTP bodies are
  untrusted and decoded with hard limits.
- A challenge public key comes from validator configuration. An embedded key is
  an identifier, not a trust anchor.
- Private service keys never enter problem, solution, or proof crates; only the
  transport-independent service/signing layers receive them.
- The validator recomputes the template digest, instance seed, problem digest,
  validation-manifest digest, public generator values, and relation endpoints.
- Service errors do not echo arbitrary input bytes or secret key material.
- A signed timestamp is an assertion by the configured issuer's clock, not an
  independent trusted timestamp authority.
- Validating a proof establishes its versioned relation and metric. A separate
  application policy decides whether the reported residual is useful.
- Challenge issuance accepts caller-selected templates and returns fresh signed
  entropy bound to their digest. Benchmark consumers must pin the intended
  template or problem; the signature alone does not assert difficulty.

## 9. Delivery roadmap

### Stage 0: deterministic foundations (partially implemented)

- Canonical framing, digest domains, and solution encoding are implemented;
  published golden vectors remain.
- Implement one well-tested sparse family and RHS generator with literal local
  seeds.
- Cross-check generator rows and materialized exports against a simple independent
  reference (remaining).
- Establish release benchmarks for generation, parsing, and residual evaluation
  (remaining).

### Stage 1: direct local MVP (implemented)

- Implement all four CLIs with offline problem finalization, file-based `x`,
  `direct-reference-v1`, strict inspection, and verification.
- Compute the residual independently rather than trusting a claimed value.
- Use this backend as the oracle for every later proof backend.

This stage proves integration correctness, not succinctness.

### Stage 2: signed stateless service MVP (implemented)

- Add Ed25519 challenge and certificate signing, template-digest binding,
  expiration checks, and the canonical submission envelope.
- Expose the challenge and validation HTTP endpoints through a Cloud Run-compatible
  listener. Container and deployment manifests remain deployment-specific and are
  not included in this repository.
- Document clearly that a certificate is for one submission and that no replay
  or global-best state exists.

### Stage 3: exact succinct backend

- Port the reviewed fixed-point relation, no-wrap bounds, range/padding checks,
  sparse matvec and residual-norm sumchecks, and polynomial openings into modular
  crates.
- Pin one immutable transcript and artifact version. Do not allow proof-supplied
  field, layout, security, or commitment parameters.
- Compare exact outputs with `direct-reference-v1` on deterministic fixtures,
  malformed proofs, scale-separated systems, and boundary values.
- Gate release on proof size, prover RSS, validator RSS, and validator-time
  benchmarks.

The exact backend is the first target that can make a cryptographic succinctness
claim.

### Stage 4: fast metric backend

- Freeze the binary64 numerical contract and tolerance provenance.
- Add commit-before-challenge framing, a distinct signed post-commit nonce,
  floating sumchecks, the unit-circle code, folds, and Merkle multiproofs.
- Keep external and local Fiat--Shamir challenge modes explicitly different and
  reject downgrades.
- Compare the metric certificate with both direct and exact results over a
  documented operating envelope.

The fast backend remains a provisional, probabilistic numerical consistency
certificate. It is not silently promoted to the semantics of the exact backend.

### Stage 5: families, optimization, and stateful products

- Add new generator families only with versioned row rules, public-evaluator
  capabilities, certificates, and reference tests.
- Profile before introducing parallel kernels, SIMD, memory mapping, or unsafe
  code; retain reference paths.
- Add durable replay protection or a best-residual leaderboard only as a separate
  stateful service with explicit transactional semantics.
- Consider batched or repeated-solve protocols after the single-submission path is
  stable and measured.

## 10. Initial non-goals

- zero knowledge;
- arbitrary prover-defined matrices or proof programs;
- accepting an arbitrary CSR file as a succinct public instance without an
  authenticated matrix-opening design;
- global-best, one-shot, or replay-prevention claims from a stateless service;
- copying the research repository's crate graph or application plumbing; and
- optimizing before deterministic reference behavior and benchmarks exist.
