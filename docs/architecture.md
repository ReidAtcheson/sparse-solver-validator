# Architecture

**Status:** implemented development system with direct, exact, and provisional
fast profiles wired through the library registry, command-line tools, and
stateless service. This is not a production-readiness or performance claim.

This repository turns the sparse-solve research prototype into a modular Rust
system with explicit statement, generator, proof, service, and transport
boundaries. It validates one solution of one public generated system at a time:

```text
A x = b,                     R = A x - b.
```

The proof establishes the residual score for the committed or transmitted
solution. It does not decide whether that residual is useful; a caller applies
its own quality policy.

## 1. Source of protocol truth

The `sparse-solution-stark` research repository, its design documents, and the
validated-solution blog post are the protocol and conformance oracle for the
exact and fast profiles. This means the rewrite should preserve reviewed
mathematical statements, coordinate order, transcript order, numerical policy,
commitment parameters, and test vectors.

It does **not** mean copying the research repository's application structure or
assuming that two similar implementations are independent evidence. Reusable
components are extracted behind narrow contracts, and the simple direct relation
checker remains an independent end-to-end oracle. Cross-repository fixtures
should compare generated rows, public MLE endpoints, transcript challenges,
residual values, proof acceptance, and malformed-proof rejection.

The pinned upstream WHIR revision is also part of the exact profile. Its status
as an academic prototype must remain visible; preserving a research configuration
is not a production security audit.

## 2. Architectural invariants

1. `A` and `b` are public outputs of a registered, versioned generator. A proof
   cannot redefine either object.
2. A problem template and an instance-seed origin determine the mathematical
   problem. A validation manifest independently selects direct, exact, or fast
   validation.
3. Provers may scan generated sparse rows. Succinct validators may not scan rows
   or enumerate RHS entries; they receive only the generator-owned public-MLE
   capability.
4. Exact and fast profiles share statements, generators, framing, Q63.64 witness
   conversion, and selected algebraic primitives. The exact profile constructs
   an integer residual; the fast profile recomputes its residual in binary64.
   They do not share a misleading lowest-common-denominator arithmetic or
   soundness claim.
5. Every backend is an immutable, versioned verifier schedule. There is no
   prover-selected proof program.
6. Network transport does not define proof semantics. Offline and hosted paths
   verify the same strict artifact bytes.
7. Local literal randomness and hosted problem challenges are explicitly tagged
   seed origins. Exact and fast proof challenges are noninteractive
   Fiat--Shamir derivations bound to the complete public statement and prior
   transcript.
8. Hot data uses flat contiguous storage and validated indices. Untrusted lengths
   and resource policy are checked before large allocation or expensive work.

## 3. End-to-end flows

### 3.1 Hosted problem and validation

```text
ProblemTemplate
      |
      | POST /v1/challenges
      v
SignedChallenge(template digest, entropy, time)
      |
      | canonical unsigned payload -> instance seed
      v
FinalizedProblem -> public generated A,b
      |
      +-------------------------+
                                |
solver writes x                 |
      |                         |
      v                         v
sparse-prover ------------> validation artifact
                                |
                                | POST /v1/validate
                                v
                     sparse-validator-server
                                |
                         verify one artifact
                                |
                                v
                        signed certificate
```

The certificate identifies one problem, manifest, protocol, and proof digest. A
stateless service does not claim that it is the first submission or the best
residual.

### 3.2 Local validation

A local template uses the explicit `literal-v1` seed form. The offline validator
accepts it only when local mode is explicitly enabled. Exact and fast proofs
derive every algebraic challenge from their pinned Fiat--Shamir transcript.
Hosted and local artifacts use the same proof schedule; only problem-seed
provenance differs.

### 3.3 Fast noninteractive precommitment

The fast profile commits to its encoded witness before deriving its algebraic
challenges:

```text
signed or literal problem -> fixes A,b -> solve -> commit to encoded [x || R]
                                                  |
                                                  | absorb root and statement
                                                  v
                                      Fiat--Shamir challenges -> finish proof
```

The commitment root, problem digest, manifest digest, protocol, and numerical
policy are bound before the first challenge is derived. The one-step prover owns
this sequencing internally; no issuer round trip is part of proof construction.

A signed problem header makes the instance unpredictable before issuance, but
it does not prevent a prover from retrying commitments after seeing that header.
Authentication, expiry, quotas, rate limits, and audit logs are deployment-level
abuse controls, not a cryptographic one-shot guarantee. The fast profile remains
provisional; exact validation under the same signed problem header is the
assurance follow-up.

## 4. Public problem and succinct evaluation

### 4.1 Template and finalized problem

`ProblemTemplate` fixes the matrix family, dimensions, boundary rules, exact
dyadic coefficient recipe, RHS recipe, requested metric, and seed policy. A
hosted template omits a literal seed and is finalized from a verified signed
challenge. A local template carries its literal 32-byte seed directly.

The current registered matrix family is a seeded symmetric tridiagonal matrix.
It uses a flat periodic table of negative dyadic off-diagonal mantissas and a
diagonal constructed as the absolute off-diagonal row sum plus a positive
margin. Rows are sorted, duplicate-free, truncated at boundaries, strictly row
diagonally dominant, and contain at most three entries. Registered RHS variants
include a manufactured-ones relation and a seeded periodic dyadic RHS.

Compilation validates parameters and derives structural, coefficient, scale,
dominance, work, and exact-arithmetic bounds from trusted code. Proof-supplied
certificate fields are never trusted.

### 4.2 Why random-access rows are insufficient

Random-access sparse rows let a prover build a sumcheck in `O(nnz(A))` work, but
they do not make verification succinct. Both application sumchecks end at public
values of the form

```text
A_tilde(u, v) = sum_(i,j) eq_i(u) eq_j(v) A_ij
b_tilde(u)    = sum_i     eq_i(u) b_i.
```

If a validator computes either endpoint by scanning rows or RHS entries, it has
lost the intended validation complexity even if the private witness is
committed.

### 4.3 Generator-owned MLE capability

`ssv-problem` compiles each registered family into a `PublicEvaluationPlan`. The
`SuccinctPublicEvaluator` capability supplies matrix and RHS MLE evaluations,
zero-padding semantics, exact arithmetic bounds, binary64 roundoff diagnostics,
and deterministic work counters.

The current plan has these invariants:

- Boolean coordinates are most-significant-bit first;
- logical indices occupy the low prefix of the next-power-of-two domain;
- the padded tail is exactly zero;
- exact and binary64 evaluators execute the same generator plan and operation
  order; and
- work depends on the registered period and `log2(n)`, not on `n` or `nnz(A)`.

For the current family, matrix work is `O(P_A log n)` and RHS work is
`O(P_b log n)`, where `P_A` and `P_b` are bounded periodic term counts recorded
in metadata and capped by the validation manifest. The evaluator does not
materialize dimension-sized public tables.

The generator owns this capability. Exact and fast backends must not match on a
matrix-family enum and duplicate its formulas. Adding a family therefore requires
both a row generator and a reviewed public evaluator before succinct manifests
can accept it. Arbitrary CSR input needs an authenticated public-data opening or
another succinct evaluator; a hidden linear scan is not an acceptable fallback.

### 4.4 Enforced verifier boundary

`ssv-validation` exposes two statement views:

```text
PublicStatement
    problem + generated rows + manifest + provenance
    used by provers

VerifierStatement
    protocol + digests + dimension + PublicEvaluationPlan
    used by succinct validators
```

`VerifierStatement` deliberately has no row iterator and no RHS-entry method.
The exact and fast verifier reports also count generator row queries and
dimension-sized private materialization; those counters must remain zero. This
turns the succinctness boundary into an API and regression-test property.

The direct reference backend is the intentional exception. Its job is to scan
the relation after receiving all of `x`.

## 5. Workspace boundaries

| Crate | Responsibility |
| --- | --- |
| `ssv-canonical` | Canonical big-endian encoding, bounded decoding, typed digests, and domain-separated BLAKE3 |
| `ssv-problem` | Templates, seed derivation, generator compilation, sparse rows, certificates, and the shared succinct public-MLE plan |
| `ssv-solution` | Strict solver-facing binary64 vector input and contiguous validated storage |
| `ssv-relation` | Proof-independent Q63.64 witness conversion, exact integer residual relation, and no-wrap bounds; fast reuses the witness conversion but computes its own binary64 residual |
| `ssv-service-protocol` | Backend IDs, manifests, signed problem challenges, typed certificate scores, and Ed25519 verification |
| `ssv-validation` | Backend-neutral public statements, restricted verifier statements, strict outer artifact framing, and backend lifecycle traits |
| `ssv-direct` | Non-succinct artifact carrying `x` and independent streaming relation checker |
| `ssv-field-sumcheck` | Reusable flat-table finite-field sumcheck with fixed coordinate and transcript conventions |
| `ssv-whir-pcs` | Pinned Field192/WHIR commitment profile, opening composition, strict inner certificate framing, and work metrics |
| `ssv-exact` | Q63.64/Field192 sparse-solve protocol composition and exact score report |
| `ssv-fast` | Frozen binary64 contract, metric sumcheck, transcript, unit-circle code, Merkle multiproofs, error-provenance diagnostics, and fast protocol composition |
| `ssv-backends` | Exhaustive application dispatch across registered backends and conversion of structurally verified reports into protocol-matched certificate scores |
| `ssv-service` | Transport-independent stateless issuance, provenance checks, backend dispatch, and certificate construction |

The dependency direction is intentional:

```text
canonical
  |-- problem -- relation
  |-- solution -----|
  |-- service-protocol
  `-- validation(statement + artifact lifecycle)
          |-- exact ---- field-sumcheck + whir-pcs
          |-- fast ----- metric primitives
          `-- direct --- independent full relation

ssv-backends -> exhaustive direct + exact + fast dispatch
service -> ssv-backends + validation + service-protocol
bins    -> library APIs
```

Shared framing does not imply shared backend payloads. Exact Field192 messages
and fast binary64/Merkle messages remain individualized formats and verifiers.

## 6. Validation profiles

### 6.1 `direct-reference-v1`

The direct profile stores the complete canonical binary64 solution in its
artifact. Validation regenerates `A,b`, streams every sparse row in order,
computes `Ax-b`, and reports squared L2, L2, RMS, and maximum absolute residual.

It is `O(n)` on the wire, reveals `x`, and performs `O(nnz(A))` verifier work. It
is not a succinct or zero-knowledge proof. Its role is integration, diagnosis,
and independent relation checking for exact and fast fixtures.

### 6.2 `whir-field192-l2-v4`

The exact profile rounds solver output once to signed Q63.64 and proves an exact
integer relation for that quantized witness. It digit-decomposes witness and
residual values, packs them into one 64-selector table, commits with a fixed
Field192/WHIR profile, and composes three finite-field sumchecks:

1. digit range and zero-padding constraints;
2. compressed sparse matrix-vector consistency; and
3. the exact squared residual norm.

WHIR authenticates every private endpoint used by those reductions. The
generator-owned exact MLE evaluator supplies public matrix and RHS endpoints and
no-wrap metadata without row scans. The result is an exact residual numerator and
dyadic denominator for Q63.64 `x`; it is not a proof about unrounded solver
arithmetic and it does not claim zero knowledge.

### 6.3 `fast-binary64-unit-circle-v4`

The fast profile converts the same Q63.64 witness back to a frozen binary64
representation and computes `R = Ax-b` under its binary64 contract. It packs
`W = [x || R]`, bit-reverses it into
monomial-coefficient order, evaluates a rate-one-half complex unit-circle code,
and commits its codeword with BLAKE3 Merkle trees.

It composes:

1. a binary64 residual-norm sumcheck;
2. a binary64 sparse matvec sumcheck;
3. a batched linear-opening sumcheck tying `x_tilde(v)` and `R_tilde(u)` to the
   packed commitment; and
4. recursively committed unit-circle folds with transcript-derived Merkle
   multiproofs.

The verifier derives query indices after all roots are committed and uses the
same generator-owned public evaluator for `A_tilde` and `b_tilde`. Exact
relations such as framing, transcript replay, and Merkle authentication remain
hard verification conditions. Approximate algebraic relations do not produce a
protocol-level quality verdict: the verifier reports absolute defects and
floor-relative errors under relation-specific, transcript-bound zero scales,
along with a conditional sampling curve.

This is a **provisional metric certificate**, not the exact profile with faster
arithmetic. Structural framing, signatures, transcript binding, Merkle
authentication, and canonical public endpoint evaluation have ordinary
discrete checks; the composition does not yet have one global theorem converting
its observed binary64 defects and sampled bad-fraction curves into a final
numerical soundness bound. The claimed residual and its diagnostics therefore
do not establish residual quality by themselves.

## 7. Executable targets

### `sparse-problem`

Validates and finalizes problem templates, inspects generator-derived metadata,
writes manufactured fixtures, and streams Matrix Market `A,b` exports. Exported
files are interoperability views; the canonical generator and problem digest
remain authoritative.

### `sparse-prover`

Reads a finalized problem, validation manifest, and solver-owned `x` file.
`prove` exhaustively dispatches direct, exact, and fast profiles and writes the
same strict outer artifact format. For fast proofs it performs commitment and
Fiat--Shamir completion inside one process. Local `fast-commit` and `fast-prove`
commands retain those implementation stages for diagnostics and separate
process-memory benchmarks; neither contacts an issuer.

### `sparse-validator`

Separates inspection from verification. Inspection is explicitly unverified.
Verification authenticates required challenge provenance, dispatches to the
manifest-selected backend, and prints the backend-specific exact or metric
result. Certificate verification authenticates the signed payload against an
external public key; applications must separately pin expected problem, proof,
manifest, time, and score policy as needed.

### `sparse-validator-server`

Provides health, problem-challenge, and validation HTTP endpoints around the
same library verification paths. It binds
`0.0.0.0:$PORT` for Cloud Run; local clients connect to
`127.0.0.1:$PORT`, not to `0.0.0.0`. Every hosted submission requires the
ordinary signed problem challenge embedded in its public statement; fast does
not add an issuer interaction.

## 8. Data layout and performance design

- Solutions, residuals, sumcheck tables, digit columns, codewords, and Merkle
  frontiers use flat contiguous vectors or boxed slices.
- Sparse rows are generated on demand in sorted order; the direct checker and
  provers do not materialize a dense matrix.
- The exact prover folds sumcheck tables in place. The shared sumcheck retains a
  serial path below a documented scheduling threshold and parallelizes large
  exact reductions without changing field results.
- The fast prover commits and opens flat complex codewords. Multiproofs carry one
  canonical joint frontier rather than repeated paths.
- Succinct validators retain transcript state, scalar claims, roots, public
  evaluator state, and query frontiers—not `x`, `R`, a codeword, or generated
  matrix rows.
- Bounded readers validate lengths before allocation. The HTTP adapter
  authenticates public context before backend proof work and limits concurrent
  blocking validation.

Performance reports in backend structs are diagnostic work accounting, not RSS
measurements or hard memory bounds. Current-repository performance claims require
fresh release measurements. The research repository's published numbers are
historical comparison targets only. See [benchmarking.md](benchmarking.md) for the
required baseline and measurement method.

## 9. Service and state model

Core service methods receive explicit entropy and time; HTTP, operating-system
RNG access, key files, and socket binding remain adapter concerns. Development
uses a file-backed Ed25519 key. Deployments must provide protected key material
and configure request, concurrency, and platform time limits for their resource
budget.

The service intentionally stores no challenge, proof, result, or
leaderboard state. Signed objects authenticate their bytes and timestamps, but
statelessness cannot enforce:

- one use of a problem challenge;
- replay rejection;
- one certificate per solver or problem; or
- a global or per-problem best residual.

Those properties require durable storage and atomic check-and-record or
compare-and-update operations. Cloud Run instance memory and logs are not
correctness mechanisms.

## 10. Test and review strategy

The repository should maintain four complementary layers:

1. **Primitive conformance:** canonical encodings, transcripts, field elements,
   float policy, Merkle frontiers, sumcheck rounds, and WHIR wrappers.
2. **Generator equivalence:** public MLE evaluators match complete materialized
   scans at Boolean and non-Boolean points in exact and binary64 arithmetic.
3. **Backend relations:** exact and fast honest proofs match the direct relation
   on deterministic solutions; statement, message, root, opening, and trailing
   byte mutations are rejected or, for allowed metric perturbations, scored.
4. **Succinctness regressions:** exact and fast verifier row-query and private
   materialization counters remain zero while public-evaluator work follows the
   registered period/logarithmic bound.

Published cross-repository golden vectors, decoder fuzzing, Miri/sanitizers where
applicable, deployment load tests, and independent review remain required before
production use.

## 11. Delivery status and release gates

The current development implementation includes:

- deterministic template finalization, signed problem challenges, literal local
  mode, and a generator-owned succinct public evaluator;
- a strict common artifact container and exhaustive direct/exact/fast dispatch;
- one-step noninteractive proving for all three profiles, optional local fast
  stage diagnostics, backend-specific human-readable verification, and typed
  certificate scores; and
- stateless HTTP problem issuance and hosted validation for all three profiles.

Production release still requires published cross-repository golden vectors,
coverage-guided decoder fuzzing, applicable Miri/sanitizer runs, fresh benchmark
results from this repository, deployment load tests, protected key management,
abuse controls, and independent cryptographic and numerical review. Stateful
one-shot or best-score products additionally require durable transactional
storage; they are not hidden inside the current service.

## 12. Non-goals and extensions

Current non-goals are:

- zero knowledge;
- arbitrary prover-defined proof programs or security parameters;
- a hidden dense or row-scanning fallback for succinct verification;
- global-best, one-shot, or replay-prevention claims from stateless operation;
- treating fast metric acceptance as an exact field statement; and
- presenting research-repository measurements as results of this rewrite.

Additional matrix families should be admitted only with versioned row semantics,
generator-derived bounds, a reviewed public MLE plan, reference equivalence
tests, and explicit work limits. Stateful competitions, batch/repeated solves,
and authenticated arbitrary sparse inputs are separate protocol extensions.
