# Challenge, proof, and certificate protocol

**Status:** development protocol. The Rust implementation and tests are
normative until this repository publishes a complete independent wire appendix
and cross-repository golden vectors. The exact backend follows the reviewed
`whir-field192-l2-v4` relation; the fast backend is an experimental metric
protocol, not a substitute for exact soundness.

Changing a canonical field, tag, byte order, digest domain, generator rule,
transcript checkpoint, numerical operation order, tolerance, commitment
parameter, or output meaning requires a new version.

## 1. Statements and proof kinds

All profiles validate the same public statement:

```text
FinalizedProblem          versioned generator for public A,b
ValidationManifest       backend and resource policy
optional SignedChallenge hosted problem provenance
```

The public statement produces a problem digest, manifest digest, protocol ID,
and transcript digest. Backend proof bytes cannot change any of them.

Three proof kinds are registered:

| Protocol | Meaning | Carries `x` | Validator row scan |
| --- | --- | ---: | ---: |
| `direct-reference-v1` | Independent binary64 relation computation | yes | yes |
| `whir-field192-l2-v4` | Exact integer statement for Q63.64 `x` | no | no |
| `fast-binary64-unit-circle-v4` | Provisional sampled metric diagnostics | no | no |

The direct profile is not succinct. The exact and fast profiles receive a
restricted verifier statement with the registered public-MLE evaluator but no
sparse row or RHS-entry interface.

None of the profiles claims zero knowledge.

## 2. Canonical encoding and strict parsing

Canonical fixed-width integers are big-endian unless an inner protocol
explicitly freezes a different legacy order. A length-delimited byte or UTF-8
string is:

```text
length     u64 big-endian
payload    exactly length bytes
```

Booleans are exactly one byte, `0` or `1`. Digests are exactly 32 bytes. JSON
digests, seeds, and signatures use one lowercase hexadecimal spelling. Typed JSON
parsers reject unknown fields.

Semantic hashes and signatures are reconstructed from typed canonical bytes,
never from JSON whitespace, object-key order, or decimal formatting. Proof
containers may embed the compact typed JSON representation as public context;
the parser first bounds it, parses it into closed Rust types, and recomputes
semantic identities.

Every untrusted decoder enforces limits before allocation and rejects:

- unknown versions, proof kinds, flags, enum tags, and required frame tags;
- length, count, offset, index, or allocation overflow;
- truncation, missing frames, duplicated or reordered material;
- noncanonical field or binary64 encodings; and
- any bytes after the mandatory final frame.

A valid prefix followed by trailing bytes is not a valid proof.

### 2.1 Domain-separated digests

The common digest helper computes:

```text
BLAKE3(
  "ssv.domain-separated-digest.v1"
  || u64_be(domain.len) || domain
  || u64_be(payload.len) || payload
)
```

Every object supplies a purpose-specific domain. BLAKE3 derive-key mode is used
separately for problem seed expansion. A 32-byte digest from one domain is not a
substitute for a digest from another.

## 3. Public problem and MLE semantics

The problem schema fixes:

- literal or challenge-derived instance randomness;
- the registered matrix family and parameters;
- the RHS generator and parameters;
- exact dyadic scalar formats;
- dimensions, boundaries, and zero padding; and
- the requested squared-L2 residual output.

The current family is `seeded-symmetric-tridiagonal-v1`. Off-diagonal mantissas
come from a seed-derived periodic table, symmetry reuses the same edge value, and
the diagonal is the absolute off-diagonal row sum plus a positive margin.
Boundary rows truncate instead of wrapping.

Both succinct backends interpret the same Boolean tables with
most-significant-bit-first coordinates and a zero tail to the next power of two:

```text
A_tilde(u,v) = sum_(i,j) eq_i(u) eq_j(v) A_ij
b_tilde(u)   = sum_i     eq_i(u) b_i.
```

The generator-owned `PublicEvaluationPlan` evaluates these endpoints without
enumerating rows or RHS entries. It exposes the same reviewed operation plan to
Field192 and binary64 interpreters, reports exact coefficient/no-wrap metadata,
and returns deterministic work and binary64 roundoff diagnostics. Validation
manifests cap matrix and RHS periodic terms before proving or verification.

For the current family, endpoint work depends on the registered periods and
`log2(n)`, not on `n` or `nnz(A)`. A family without such a capability is not
eligible for the succinct profiles merely because it has a sparse row iterator.

## 4. Problem-instance challenge

### 4.1 Signed payload

The canonical unsigned `ChallengePayload` contains:

```text
schema tag                     u16 = 1
issuer                         bounded visible-ASCII string
key_id                         bounded visible-ASCII string
issued_at_unix_seconds         i64
expires_at_unix_seconds        i64
entropy                        32 bytes
problem_template_digest        32 bytes
retry_policy                   u16 = replay-allowed-v1
```

The server chooses 32 bytes from the operating-system RNG, uses a nonnegative
Unix timestamp, and signs the digest of the complete validated template.
`expires_at` must be later than `issued_at` and the configured service accepts
only its expected challenge lifetime.

The Ed25519 signature message is:

```text
bytes("sparse-solve/challenge-signature/ed25519/v1")
|| bytes(canonical_unsigned_payload)
```

where `bytes` is the canonical length-delimited encoding. Verification uses
strict Ed25519 and an externally configured public key, issuer, and key ID. An
artifact-carried key would be an identifier, not a trust anchor.

### 4.2 Instance seed

The exact unsigned payload bytes are the challenge context. The signature and
JSON spelling are excluded from seed derivation:

```text
hasher = BLAKE3-DERIVE-KEY("sparse-solve/problem-instance-seed/v1")
hasher.update(template_digest)
hasher.update(u64_le(challenge_context.len))
hasher.update(challenge_context)
instance_seed = hasher.finalize_xof()[0..32]
```

The template digest is deliberately present both before the context and inside
the signed payload. The validator recomputes both occurrences. Re-signing an
identical payload leaves `A,b` unchanged; changing issuer, key ID, time, entropy,
template, or retry policy changes the seed.

Generator components derive separate streams with the fixed
`sparse-solve/problem-subseed/v1` derive-key context plus a length-delimited
component label. Matrix and RHS labels are distinct.

The finalized problem records the template digest, exact challenge-context
bytes, context digest, and redundant derived seed. Parsing recomputes them. A
self-contained hosted artifact also carries the full signed challenge, and its
unsigned payload must equal the finalized problem's recorded context.

### 4.3 Explicit local mode

Local templates use the distinct form:

```json
{
  "kind": "literal-v1",
  "seed": "<64 lowercase hexadecimal characters>"
}
```

An all-zero literal is valid when explicitly written. An absent header, empty
bytes, bad signature, expired challenge, or unknown version never falls back to
literal mode. The offline validator requires explicit permission; the hosted
service rejects literal submissions.

## 5. Validation manifest and common statement

`ValidationManifest` schema `sparse-solve/validation/v1` contains:

```text
protocol                    one registered ProofProtocol
max_solution_elements       positive bounded u64
max_public_matrix_terms     positive bounded u64
max_public_rhs_terms        positive bounded u64
```

It has its own canonical digest and is excluded from matrix-seed derivation. One
finalized problem can therefore be validated under several reviewed profiles.
The proof cannot weaken limits or switch protocols because the outer header,
manifest, statement digest, backend dispatch, and certificate all bind the same
protocol ID.

The common statement constructor validates problem/challenge consistency,
compiles the generator, checks dimension and public-evaluator term limits, and
derives:

```text
transcript_digest = H(
    protocol_id,
    problem_digest,
    validation_manifest_digest
)
```

before any backend message exists.

## 6. Proof framing

### 6.1 Shared artifact

All newly produced direct, exact, and fast payloads use the strict
backend-neutral `SSVART` container:

```text
magic                         "SSVART\0\0"
container_version             u16 = 1
protocol_id                   u16
flags                         u32
problem_challenge_length      u64
problem_challenge             canonical SignedChallenge or empty
problem_json_length           u64
problem_json                  canonical compact typed JSON
manifest_json_length          u64
manifest_json                 canonical compact typed JSON

payload tag                   u16 = 1
payload frame version         u16 = 1
payload length                u64
backend payload               exact payload length

final tag                     u16 = 65535
final frame version           u16 = 1
final payload length          u64 = 0
physical EOF
```

The one recognized flag states whether a signed problem challenge is present.
Flag and bytes must agree. The parser rejects a header/manifest protocol mismatch,
noncanonical compact public JSON, resource-policy excess, a missing final frame,
and trailing bytes. Succinct backend decoders apply a tighter payload limit than
the outer direct-reference ceiling.

The complete outer artifact has its own domain-separated proof digest. Each
backend also owns strict, versioned inner framing; a common envelope is not a
generic proof instruction language. Direct verification is dispatched through a
separate reference-backend trait that receives the full public statement, while
exact and fast receive the restricted no-row-access verifier statement.

### 6.2 Direct-reference payload and legacy container

Inside `SSVART`, `direct-reference-v1` uses a strict `SSVDIR` payload whose only
data frame contains an element count and packed canonical IEEE binary64 bits,
followed by a mandatory final frame and EOF.

The library retains the original strict `SSVPRF` direct container as a legacy
compatibility API and byte-format oracle. Current CLI output uses `SSVART`; a
transport migration must not silently reinterpret historical `SSVPRF` bytes.

The profile reveals all of `x`, is linear in `n`, and scans every sparse row. It
exists for integration and independent relation checks only.

## 7. Direct validation semantics

The direct validator compiles public `A,b`, visits rows and columns in fixed
increasing order, and evaluates:

```text
ax = 0
for (column, value) in row:
    product = binary64(value) * x[column]
    ax = ax + product
residual = ax - binary64(rhs[row])
```

It deliberately does not request fused multiply-add and performs sequential
norm reduction. It rejects non-finite arithmetic and underflow cases that could
turn a nonzero residual or mean into a reported zero. The proof carries no
trusted residual claim. Output includes squared L2, L2, RMS, maximum absolute
residual, rows visited, and nonzeros visited.

Direct binary64 semantics are a baseline; they are not identical to the exact
profile's once-quantized Q63.64 statement for every possible input.

## 8. Exact sparse-solve profile

### 8.1 Statement

`whir-field192-l2-v4` converts the solver's validated binary64 output once to a
signed Q63.64 integer vector `X`. For a matrix mantissa scale `2^-f`, RHS scale
`2^-g`, and the generator-derived alignment shift, it constructs an exact integer
residual `R`. In the common `f=4`, `g=64` case:

```text
R_i = sum_j m_ij X_j - 2^f B_i
(Ax-b)_i = R_i * 2^-(64+f)
rho = sum_i R_i^2
||Ax-b||_2^2 = rho * 2^(-2(64+f)).
```

`X` spans signed 128-bit Q63.64. The profile constrains each residual to the
signed 69-bit representation `[-2^68, 2^68-1]`. Generator-derived row, RHS, and
norm bounds are checked against the Field192 modulus before a field identity is
interpreted as an integer identity.

“Exact” means exact for this quantized witness and dyadic public problem. It does
not mean the original floating-point solver executed exact arithmetic.

### 8.2 Commitment layout

Each witness integer is decomposed into 31 nibbles, a top-three-bit value, and a
sign bit. Each residual uses 17 nibbles and a sign bit. These 51 logical columns
are packed into one `64 x L` table, where

```text
L = next_power_of_two(max(n, 64)).
```

Unused selector columns and the logical row tail are zero. Six leading Boolean
coordinates select one of 64 slots; remaining coordinates select a row. One
pinned Field192/WHIR commitment binds the packed table.

### 8.3 Transcript schedule

The exact proof uses one self-contained Fiat--Shamir transcript with this fixed
composition:

1. bind the fixed WHIR profile, public statement digest, exact protocol header,
   commitment, and claimed `rho`;
2. range/padding sumcheck over all digit columns and tail masks;
3. compressed sparse matvec sumcheck, ending at public
   `A_tilde(u,v)` and `b_tilde(u)` plus authenticated private endpoints;
4. residual-norm sumcheck binding `rho` to the committed residual; and
5. one WHIR opening proof authenticating all packed digit endpoints, followed by
   WHIR's deferred final check and strict inner EOF.

The range argument gives field values their bounded integer meaning. The matvec
argument binds residual to `AX-B`. The norm argument binds `rho` to `R`. WHIR
binds all private scalar endpoints to the original table. Omitting any one of
these connections changes the statement.

The WHIR profile pins Field192, unique decoding, inverse rate two, folding factor
four, BLAKE3 Merkle hashing, no proof-of-work bits, and a computed security target
of at least 128 bits. Neither a manifest nor proof supplies these parameters.

### 8.4 Exact output and verifier work

The accepted output is an unsigned exact numerator and dyadic denominator power.
An approximate decimal is a display convenience only. The verifier constructs
public endpoints through `PublicEvaluationPlan`; it performs zero generator-row
queries and materializes zero solution or residual elements.

## 9. Fast metric profile

### 9.1 Semantics and floating contract

`fast-binary64-unit-circle-v4` is a provisional metric certificate. It applies
the exact path's one-time Q63.64 witness conversion, converts that witness back
to binary64 deterministically, and computes `R = Ax-b` under a frozen binary64
policy. Solver input rejects negative zero; internal source normalization maps
either arithmetic zero sign to positive zero, while transcript decoders reject a
negative-zero encoding. NaN, infinity, and source/transcript subnormals are
rejected. Protocol arithmetic rejects non-finite results and flushes subnormal
results to positive zero. The operation order is fixed and does not silently
introduce FMA.

The profile pads `x` and `R` to `N = next_power_of_two(n)` and packs:

```text
W = [x_0, ..., x_(N-1), R_0, ..., R_(N-1)].
```

### 9.2 Precommitment and unit-circle code

`W` is bit-reversed into monomial-coefficient order and evaluated on twice as
many complex roots of unity as coefficients. The resulting rate-one-half
unit-circle codeword is committed with a BLAKE3 Merkle root.

The strict precommitment binds the statement, problem, manifest,
public-evaluator metadata, numerical policy, code basis, source digests, shapes,
and packed codeword root before the first algebraic challenge. Source digests
are linkage metadata; the root plus opening protocol supplies proof binding.

### 9.3 Noninteractive challenge derivation

The prover and validator initialize the fast transcript from the complete
canonical precommitment and public statement. Each challenge is then derived by
Fiat--Shamir only after absorbing every message on which it depends:

```text
precommitment = H(statement, policy, shapes, source digests, packed root)
challenge_0   = FS(precommitment, first claim)
challenge_k   = FS(all transcript messages through round k)
```

There is no proof-specific issuer interaction. The ordinary signed problem
header, when present, is already part of the public statement: it fixes `A,b`,
provides issuance time and fresh instance entropy, and is authenticated before
proof work. Local literal problems use the same proof transcript after their
different, explicitly tagged seed origin is bound.

Fiat--Shamir binds challenges to a chosen root; it does not stop a prover from
trying several roots after learning the signed problem header. Authentication,
short header lifetimes, issuance and submission quotas, per-principal rate
limits, and audit logs can constrain service abuse, but cannot prove that only
one local commitment was attempted. Fast remains a provisional metric result.
An exact proof for the same finalized problem and signed header is the assurance
follow-up when exact field soundness is required.

### 9.4 Proof schedule

After precommitment binding, the transcript is fixed as follows:

1. residual-norm binary64 product sumcheck, yielding `R_tilde(u)`;
2. sparse matvec binary64 product sumcheck, using generator-owned
   `b_tilde(u)` and `A_tilde(u,v)` and yielding `x_tilde(v)`;
3. a batching challenge and linear-opening sumcheck for
   `x_tilde(v) + alpha R_tilde(u)` against committed `W`;
4. one child Merkle root after each coefficient-aligned unit-circle fold, with
   the child committed before the next challenge;
5. transcript-derived unique recursive query trajectories only after every root
   is fixed; and
6. canonical joint Merkle multiproofs for each queried `z/-z` parent pair and
   child, ending in a verified two-leaf constant oracle.

The third sumcheck is required. A Merkle root and sampled code proximity do not
by themselves authenticate an arbitrary MLE endpoint supplied by the prover.

### 9.5 Zero scales and diagnostic semantics

Fast policy 3 classifies every verifier relation as exact or approximate. Exact
relations hard-fail verification. They include canonical framing and binary64
encoding, statement and transcript binding, message schedules and shapes,
Merkle authentication, and every other discrete structural condition.

For an approximate scalar relation comparing `actual` with `expected`, the
validator records:

```text
absolute_defect     = abs(actual - expected)
normalization_scale = min(abs(actual), abs(expected))
relative_error      = absolute_defect / max(normalization_scale, zero_scale)
```

If the mathematical absolute defect is larger than finite binary64 can
represent, the diagnostic magnitude saturates to `f64::MAX`. This preserves a
traceable large discrepancy without turning diagnostic-only arithmetic into a
verification failure. Conversely, finite subnormal defects are retained rather
than applying the flush-to-zero rule used by arithmetic that feeds subsequent
transcript challenges.

Each relation family has a separately transcript-bound zero scale with the
appropriate units:

| Relation family | Zero scale |
| --- | ---: |
| residual-norm sumcheck | `2^-84` |
| sparse matvec sumcheck | `2^-42` |
| linear-opening sumcheck | `2^-42` |
| unit-circle folds | `2^-38` |

These are normalization floors, not acceptance tolerances and not claimed
roundoff or soundness bounds. In particular, an approximate relation with
relative error greater than one remains a structurally verified observation;
applications may interpret the diagnostics but cannot convert them into a
proven residual interval without an additional theorem.

The score records check count, zero scale, maximum absolute defect, maximum and
RMS relative error, and the minimum and maximum observed normalization scale
for the four relation families below. RMS is accumulated with a scaled
sum-of-squares algorithm so very large and very small finite errors are not
lost to intermediate overflow or underflow.

- residual-norm sumcheck;
- sparse matvec sumcheck;
- linear-opening sumcheck; and
- unit-circle folds.

The in-process fast verifier additionally retains every observation with its
relation location: sumcheck round or endpoint, and unit-circle query trajectory
and fold round (plus each final-value check). It also retains the public RHS and
matrix evaluator's forward-error bound, maximum source magnitude, and maximum
intermediate magnitude. Signed certificates carry the corresponding family
summaries and public-evaluator roundoff provenance after validating their
policy-3 zero scales and finite nonnegative encoding.

No approximate diagnostic causes protocol verification to accept or reject.
The binary64 squared-L2 value is explicitly a claim, and residual-quality policy
remains an application concern.

As a calibration vector, consider a valid system whose RHS entries are
`2^-42`, together with an all-zero committed solution and residual transcript.
The first sparse-matvec relation compares zero with `2^-42`; it therefore has
absolute defect `2^-42`, normalization scale zero, and relative error one. This
is expected diagnostic output, not by itself a mandatory rejection. Invalid
Merkle openings or transcript messages in the same artifact still hard-fail.

For `q` distinct trajectories, the reported per-round conditional miss curve
for a fixed bad fraction `phi` is `(1-phi)^q`. The implementation reports
examples for 1%, 5%, and 10% bad fractions. These values are not multiplied
across rounds because the same trajectories are reused and the composition has
no theorem justifying such multiplication.

The fast verifier authenticates framing, commitments, openings, sampled folds,
and public endpoints and returns zero row queries and zero materialized solution,
residual, or codeword elements. A future a posteriori theorem could derive a
bound `B(observations, public_bounds)` and failure probability `delta` relating
the claimed metric to the committed oracle's true residual. Quantifying or
claiming that theorem is explicitly out of scope for policy 3. This unresolved
global statement is why the profile remains provisional and should be followed
by the exact profile when exact assurance is required.

## 10. Signed certificate

Certificate schema `sparse-solve/validation-certificate/v4` binds:

```text
issuer and key ID
certificate issue time
required problem-challenge digest
problem digest
validation-manifest digest
proof digest
proof protocol
one protocol-matched typed score
validator-build identifier
```

The Ed25519 signature message is:

```text
bytes("sparse-solve/certificate-signature/ed25519/v4")
|| bytes(canonical_certificate_payload)
```

The score variants are deliberately different:

- direct: binary64 squared L2, L2, RMS, and maximum absolute residual;
- exact: unsigned residual numerator plus dyadic denominator power; and
- fast: a binary64 squared-L2 claim, four diagnostic summaries, public RHS and
  matrix evaluator roundoff provenance, and the distinct recursive-query-
  trajectory count.

A v4 certificate always carries the signed problem-challenge digest. Fast needs
no additional signed challenge field. A score/protocol mismatch is invalid. A
relying party verifies the signature with an external trust anchor and pins
whatever problem, manifest, proof, challenge, time, and quality policy its
application requires.

A certificate reports one submitted proof's result. It does not claim that the
residual is good, globally best, attributable to a solver identity, or based on a
one-shot challenge.

## 11. Stateless service semantics

The HTTP adapter exposes:

```text
GET  /health
POST /v1/challenges
POST /v1/validate
```

Problem templates and challenge requests use bounded typed JSON; proof artifacts
use binary bodies; signed challenges and certificates are returned as typed JSON
whose signatures reconstruct canonical payload bytes.

Every hosted submission must carry a valid service-issued problem challenge.
Direct, exact, and fast artifacts use that same provenance rule; fast proof
construction adds no issuer round trip. The hosted service rejects literal
problems, which require the explicit local-validator flag.

The service captures validation start time before proof work and completion time
after it. It refuses certification when the challenge expires during validation
or the clock moves behind required events. CPU work runs on a blocking pool behind
body, concurrency, and deadline controls.

For Cloud Run, the listener binds `0.0.0.0:$PORT`. `0.0.0.0` is not a client URL;
local clients use `127.0.0.1:$PORT` and deployed clients use the service URL.

The service stores no challenge, proof, or certificate state. Its
explicit retry policy is therefore `replay-allowed-v1`. Expiry and fresh entropy
do not provide one-shot semantics. Without durable transactional state the
service cannot:

- reject reuse or replay;
- limit certificates per challenge;
- compare against prior submissions; or
- certify a global or per-problem best residual.

A signed problem challenge also does not attest that a caller-selected template
is difficult. Benchmark or reward systems must pin allowed templates/problems
and apply authentication, quotas, and durable state outside this stateless core.

## 12. Conformance and release requirements

The research implementation is the protocol/conformance oracle, not a source of
current-repository performance results. Before a production release, publish
byte-for-byte vectors for:

1. canonical template, problem, manifest, statement, challenge, precommitment,
   proof, and certificate encodings;
2. instance and component seed derivation;
3. matrix rows, RHS values, and generator certificates;
4. exact and binary64 public MLE endpoints at Boolean and non-Boolean points;
5. exact transcript challenges, digit openings, and WHIR acceptance;
6. fast transcript challenges, code roots, folds, query indices, multiproofs,
   and normalized scores;
7. one-step and locally staged fast proving producing the same transcript;
8. mutation, cross-kind, cross-version, cross-statement, truncation, resource,
   and trailing-byte rejection; and
9. exact and fast verifier work counters showing zero generator-row queries and
   zero private-vector materialization.

Coverage-guided fuzzing of every untrusted decoder, independent relation and
generator implementations, key-rotation tests, and deployment load tests remain
required. Performance measurement requirements are in
[benchmarking.md](benchmarking.md).
