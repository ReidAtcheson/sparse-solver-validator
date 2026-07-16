# Challenge, proof, and certificate protocol

**Status:** implemented development protocol v1. Numeric tags, domains, limits,
and encodings are frozen by the current code and tests, but this release has not
undergone an external cryptographic or numerical audit.

Until the repository publishes a complete wire-format appendix and independent
golden vectors, the Rust implementation and its tests are normative for v1. This
document records the major objects, bindings, and framing, but is not by itself a
sufficient clean-room implementation specification. In particular, consult the
current code for every canonical encoding, generator component label, generator
sampling detail, and validation limit. Changing any of those values still
requires a new protocol or generator version.

This document describes the protocol that exists in this repository. The only
implemented validation backend is `direct-reference-v1`; exact and fast
succinct backends are later immutable proof kinds.

## 1. Objects and trust boundaries

The protocol uses these typed objects:

```text
ProblemTemplate          seed policy plus public matrix/RHS recipe
SignedChallenge          issuer entropy, timestamps, template digest, signature
FinalizedProblem         template fields plus literal or derived seed provenance
Solution                 solver-produced x
ValidationManifest       proof backend and resource policy
DirectArtifact           self-contained validation submission
SignedCertificate        one verified submission's residual and provenance
```

JSON is the bounded presentation format for templates, finalized problems,
solutions, manifests, signed challenges, and signed certificates. Parsers use
closed typed structs and reject unknown fields. Semantic identities and
signatures never hash raw JSON: each type has a separately defined canonical
binary encoding.

The direct proof is a strict binary container. It embeds the finalized problem
and validation manifest as bounded typed JSON context, plus the canonical binary
signed challenge header. Reformatting embedded JSON changes the proof digest but
does not change the recomputed problem or manifest digest.

Public keys are externally configured trust anchors. A key carried by an
artifact would not become trusted merely by verifying its own signature.
Issuer, key, and validator-build identifiers are nonempty visible ASCII without
spaces and are capped at 256 bytes, preventing control characters in logs and
canonical payloads.

## 2. Canonical primitives

Canonical integers are fixed-width big-endian. Booleans are one byte, exactly
`0` or `1`. A byte string or UTF-8 string is:

```text
length     u64 big-endian
payload    exactly length bytes
```

A digest is exactly 32 bytes. Human-readable digests and seeds are exactly 64
lowercase hexadecimal characters. An Ed25519 signature is 64 bytes and appears
as exactly 128 lowercase hexadecimal characters in JSON.

Bounded readers check the total input and every declared field before slicing or
allocating. Unknown tags, overflow, truncation, noncanonical values, invalid
UTF-8, oversized fields, missing final frames, and trailing bytes are errors.

The common domain-separated digest helper computes:

```text
BLAKE3(
  "ssv.domain-separated-digest.v1"
  || u64_be(domain.len) || domain
  || u64_be(payload.len) || payload
)
```

Every use supplies a purpose-specific domain such as problem template, problem,
manifest, challenge, proof, or certificate. A field-order or domain change
requires a new version.

## 3. Problem template and generator

`ProblemTemplate` schema `sparse-solve/problem-template/v1` fixes:

- a literal or challenge-derived randomness policy;
- `seeded-symmetric-tridiagonal-v1` parameters;
- a registered RHS recipe;
- dyadic coefficient scales and exact mantissa ranges; and
- the requested `squared-l2-residual-v1` output.

The initial matrix generator uses a seed-derived flat periodic table of negative
off-diagonal dyadic mantissas. Edge `(i,i+1)` and its transpose use the same
table entry. Each diagonal is constructed as the absolute off-diagonal row sum
plus a positive margin. The result is symmetric, has positive diagonal,
nonpositive off-diagonals, and is strictly row diagonally dominant. Boundary
rows truncate rather than wrap.

Rows are produced in sorted order from a stack-backed iterator with at most
three entries. The compiler stores only periodic lookup tables; it does not
materialize dimension-sized `A` or `b`. The generator recomputes its structural,
coefficient, dominance, and work certificate from trusted code.

The current generator is the direct backend's conformance family. A succinct
backend must additionally provide a reviewed, cheap evaluator for the public
multilinear extensions of `A` and `b`.

## 4. Signed matrix-instance challenge

### 4.1 Payload

The canonical challenge payload contains, in order:

```text
schema tag                     u16 = 1
issuer                         bounded string
key_id                         bounded string
issued_at_unix_seconds         i64
expires_at_unix_seconds        i64
entropy                        32 bytes
problem_template_digest        32 bytes
retry_policy                   u16 = replay-allowed-v1
```

`expires_at` must be later than `issued_at`. The server issues timestamps from a
nonnegative Unix clock, chooses 32 bytes from the operating-system RNG, and
binds the digest of the complete validated template. Its configured challenge
lifetime is fixed for all challenges it later accepts.

The retry policy is explicit because the service is stateless. It does not imply
one-shot use.

### 4.2 Signature

The Ed25519 signature preimage is the canonical encoding:

```text
bytes("sparse-solve/challenge-signature/ed25519/v1")
bytes(canonical_challenge_payload)
```

where `bytes` is the `u64` big-endian length-delimited encoding above. The
signature is excluded from its own preimage.

Validators select a trusted key from externally expected issuer and key ID,
perform strict Ed25519 verification, reject a challenge issued too far in the
future, and reject validation after expiry. They recompute the template digest
instead of trusting the redundant payload field.

### 4.3 Instance seed

The challenge context is the canonical unsigned payload bytes, not its JSON and
not its signature. The problem layer derives:

```text
hasher = BLAKE3-DERIVE-KEY("sparse-solve/problem-instance-seed/v1")
hasher.update(template_digest)
hasher.update(u64_le(challenge_context.len))
hasher.update(challenge_context)
instance_seed = hasher.finalize_xof()[0..32]
```

The template digest appears both before the context and inside the payload. This
redundancy is intentional and checked. Re-signing an identical payload does not
change `A,b`; changing issuer, key ID, time, entropy, template, or retry policy
does.

Generator components derive independent streams with
`BLAKE3-DERIVE-KEY("sparse-solve/problem-subseed/v1")`, the instance seed, and a
length-delimited component label. Matrix and RHS labels are distinct.

`FinalizedProblem` records the template digest, exact challenge-context bytes,
context digest, and redundant derived seed. Parsing recomputes and compares all
of them. The direct artifact separately carries the complete signed challenge,
and validation requires its unsigned payload to equal the embedded context.

## 5. Explicit literal local mode

A local template may instead contain:

```json
{
  "kind": "literal-v1",
  "seed": "<32 lowercase-hex bytes>"
}
```

This is an explicit variant; an all-zero seed is valid if deliberately written.
An absent header, empty bytes, invalid signature, or expired challenge never
falls back to local mode.

The offline validator requires `--allow-literal`. The hosted service rejects
literal artifacts unconditionally. Local and hosted problems share generator
code only after obtaining their instance seed.

## 6. Validation manifest and solution input

The implemented manifest is:

```text
schema                  sparse-solve/validation/v1
protocol                direct-reference-v1
max_solution_elements   positive bounded u64
```

It has its own canonical digest and is not part of matrix-seed derivation. A
future exact or fast manifest can therefore validate the same public instance.
The hosted service has an independent maximum solution-element policy. It does
not issue challenges above that dimension and rejects manifests whose declared
cap is larger, before allocating the packed solution.

The solver-facing solution JSON uses schema
`sparse-solve/solution/binary64-v1` and a flat array of decimal strings. Parsing
produces contiguous binary64 values and rejects wrong length, NaN, infinity,
negative zero, and subnormals. Proof artifacts store the already validated IEEE
bits, not decimal text.

## 7. Direct proof container

`direct-reference-v1` uses this big-endian prelude:

```text
magic                         "SSVPRF\0\0"
container_version             u16 = 1
proof_kind                    u16 = 1
proof_version                 u16 = 1
transcript_suite              u16 = 0
flags                         u32
application_header_length     u64
application_header            bytes
public_context_length         u64
public_context                bytes
```

Flag bit zero says that the application header contains a canonical
`SignedChallenge`. No other flag is recognized. Literal mode has zero flags and
an empty header; presence and flag must agree.

The public context contains two length-delimited strict JSON documents:

```text
finalized_problem_json
validation_manifest_json
```

The only payload frame is:

```text
tag                           u16 = 1
frame_version                 u16 = 1
payload_length                u64
solution_element_count        u64
solution_bits                 count packed u64 IEEE encodings
```

A mandatory final frame follows:

```text
tag                           u16 = 65535
frame_version                 u16 = 1
payload_length                u64 = 0
physical EOF
```

The parser checks context, proof, field, manifest, dimension, element, and
allocation limits before numerical work. The proof digest covers the complete
container under the `sparse-solve/direct-proof-artifact/v1` digest domain.

The artifact reveals all of `x`, is linear in `n`, and takes `O(nnz(A))`
validation work. It is not a succinct or zero-knowledge proof.

## 8. Direct validation semantics

The validator compiles `A,b` from the finalized problem, streams rows in
increasing order, and iterates each row in increasing column order. For every
row it computes:

```text
ax = 0
for (column, value) in row:
    product = binary64(value) * x[column]
    ax = ax + product
residual = ax - binary64(rhs[row])
```

The row and squared-norm reductions are sequential and do not deliberately use
fused multiply-add. Validation rejects non-finite arithmetic, a nonzero
residual whose binary64 square underflows to zero, overflow of the accumulated
squared norm, and a nonzero squared norm whose mean underflows to zero. Thus a
reported zero norm means every computed binary64 residual was zero. The output
reports:

```text
squared_l2, l2, rms, max_abs, rows_visited, nonzeros_visited
```

The proof supplies no trusted residual claim. The validator recomputes all
metrics. No quality threshold is applied: a correctly bound poor solution is a
valid direct artifact with a large residual.

## 9. Signed certificate

After successful hosted validation, the canonical certificate payload contains:

```text
schema
issuer
key_id
issued_at_unix_seconds
optional challenge_digest
problem_digest
validation_manifest_digest
proof_digest
proof protocol
squared_l2, l2, rms, max_abs as canonical IEEE bits
validator_build identifier
```

The signature preimage uses the certificate-specific domain:

```text
bytes("sparse-solve/certificate-signature/ed25519/v1")
bytes(canonical_certificate_payload)
```

The JSON certificate is only a transport spelling of the typed payload and
lowercase-hex signature. Verification reconstructs canonical bytes and uses an
external issuer, key ID, and public key.

The implemented `verify-certificate` command authenticates that signed payload.
It does not re-run the proof, check certificate freshness or expiry, or compare
the recorded challenge/problem/proof digests with caller-supplied files. Those
are separate application-policy checks.

A certificate reports the residual for one specific proof digest. It does not
say that the residual is globally best, acceptable under some unrecorded
threshold, or attributable to a particular solver identity.

## 10. Stateless service and HTTP

The HTTP adapter exposes:

```text
GET  /healthz
POST /v1/challenges   JSON ProblemTemplate -> JSON SignedChallenge
POST /v1/validate     binary DirectArtifact -> JSON SignedCertificate
```

Template and proof bodies have separate size limits; the proof-body limit is
derived from the configured solution-element cap. CPU-heavy validation runs on
the blocking pool behind both an early per-route concurrency limit and an owned
work permit, while a request deadline bounds slow bodies. Core service logic
receives explicit time and entropy and contains no HTTP, filesystem, or RNG
dependency.

The HTTP adapter captures one time before relation checking and a fresh time
after it finishes. Certificate issuance uses the latter and is refused if the
challenge expired during validation or if the clock moved behind the start time.

Cloud Run listens on `0.0.0.0:$PORT`. Local clients connect to
`127.0.0.1:$PORT`; `0.0.0.0` is a bind address, not a destination URL.

The service checks expiry but stores no challenge, proof, or certificate state.
It therefore cannot enforce one-time use, reject replay, limit certificates per
challenge, or remember a global/per-problem best residual. Those properties
require durable storage and atomic updates.

Challenge issuance accepts a caller-selected template and signs fresh entropy
bound to its digest. This supports arbitrary registered families, but it does
not certify that a family is difficult or prevent repeated issuance for seed
grinding. Any benchmark or reward policy must pin its accepted template/problem
and apply authentication, quotas, and rate limits outside this stateless core.

## 11. Separate fast post-commit challenge

The signed challenge above exists before solving and determines public `A,b`.
A future external-challenge fast proof must first commit to its solution/residual
encoding and then obtain a second nonce bound to that commitment digest. The
matrix challenge cannot substitute for this later event.

A stateless service can return a signed token containing the commitment digest,
nonce, and timestamp, which attests to ordering. It still cannot stop repeated
nonce requests or replay without durable state. Offline Fiat--Shamir mode must be
an explicitly different manifest and never an automatic fallback.

The exact Field192/WHIR path can remain fully Fiat--Shamir and does not need the
fast path's external post-commit nonce.

## 12. Versioning and required tests

Changing a canonical field, tag, field order, byte order, domain, generator
rule, numerical operation order, signature preimage, proof schedule, or output
meaning requires a new version.

The current suite covers canonical boundary/mutation parsing, strict JSON,
digest and seed binding, row structure and generator certificates, unbiased
sampling, signed challenge mutation, expiry, template rebinding, explicit local
mode, final-frame/EOF enforcement, exact manufactured-solution residuals, and
certificate signature verification.

Before a production release, add published byte-for-byte golden vectors,
coverage-guided fuzzing of every untrusted decoder, independent generator and
residual implementations, signature key-rotation tests, deployment load tests,
and release benchmarks for artifact size, time, and peak memory.
