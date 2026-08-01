# One-pass residual-witness certificates for binary64 sparse solves

Status: research proposal; non-normative.

Scope: a possible successor to `fast-binary64-unit-circle-v5`. Nothing in this
document changes the guarantees, accepted inputs, transcript, proof bytes,
diagnostic policy, or certificate schema of the current fast profile.

This document narrows the performance architecture discussed in
[`fast-path-a-posteriori-statistical-guarantees.md`](fast-path-a-posteriori-statistical-guarantees.md).
That proposal remains the broader source for a-posteriori sumcheck,
proximity, numerical-error, and confidence-composition questions. The focus
here is whether an untrusted residual supplied by the solver can reduce the
matrix-dependent prover work to one sparse pass while preserving a succinct
proof.

The division of responsibility is:

| Topic | Broader a-posteriori proposal | This proposal |
| --- | --- | --- |
| Exact-real interval decomposition | Imported | Applies it to a supplied residual |
| Rademacher moment and small-ball lemma | Imported | Batches repetitions into one matrix scan |
| Approximate sumcheck and robust proximity | Owns the general research questions | Treats both as release gates |
| Solver/prover interface | Not the focus | Adds `[x || r]` as the committed input |
| Performance model | General evaluation plan | Separates matrix, sign, transpose-scatter, code, hash, and memory costs |
| Deployment | General retry alternatives | Prefers registered interactive attempts for the first experiment |

## 1. Decision summary

Investigate a new residual-witness protocol with the following shape:

1. The solver supplies a candidate solution `x` and a residual witness `r`.
2. The prover commits to the packed message `[x || r]` before any audit
   challenges are known.
3. The verifier uses post-commitment randomized residual sketches and a fresh
   batching challenge.
4. The prover performs one challenged sparse contraction to audit
   `b - A x - r`.
5. A norm proof for `r` and a proved upper bound on the relation defect compose
   into a confidence-indexed interval for the exact-real residual.

The design is promising because the current fast prover performs two complete
matrix scans: one to construct `R = A x - b` and one to construct the
challenge-weighted matvec table. Accepting an already available solver residual
can remove the first scan without trusting that residual.

This is not yet a complete protocol. In particular, no current theorem or
implementation supplies all of:

- a useful global defect bound from the batched binary64 transcript;
- verifier-succinct contractions for a distribution-free sketch family;
- robust proximity from the committed complex oracle to a unique real packed
  message;
- useful instantiated approximate-sumcheck constants at target dimensions;
- an enforced retry model under which a solve-relative soundness budget is
  meaningful; or
- a full prover whose total constant is already comparable to one optimized
  CSR SpMV.

These are release gates, not details to fill in after assigning a confidence
level.

## 2. Motivation and current baseline

Direct validation evaluates `A x - b` and therefore needs access to the whole
candidate vector `x`. A succinct proof can be substantially smaller than `x`
and can avoid linear online-verifier dependence on `n` and `nnz(A)` after the
public problem has been registered. This transfer advantage remains valuable
even if proof construction does more arithmetic than direct validation.

The current fast path already provides most of the structural machinery:

- a canonical packed `[x || R]` message;
- a degree-two product sumcheck for the residual norm;
- a degree-two product sumcheck for a challenged sparse matvec;
- a batched linear-opening sumcheck tying solution and residual endpoints to
  the packed message;
- a coefficient-aligned rate-one-half unit-circle code;
- recursive committed folds and Merkle multiproofs;
- strict transcript framing and commit-before-derived-challenge ordering; and
- succinct public matrix and right-hand-side evaluation for registered
  generator families.

The current one-step prover deliberately records two row and nonzero scans. It
also constructs a rate-one-half complex codeword, hashes full fold layers, and
performs several `O(n)` sumcheck and opening passes. Consequently, reducing the
matrix scans from two to one is material, but it is not by itself evidence that
the complete prover costs one SpMV.

The current fast verifier reports authenticated numerical diagnostics. Those
diagnostics do not reject an approximate algebraic inconsistency and do not
constitute a confidence interval for the exact-real residual. This proposal
must not be described as an incremental strengthening of that existing claim;
it requires a new protocol and certificate statement.

## 3. Goals and non-goals

### 3.1 Goals

- Keep the independently verifiable proof substantially smaller than a raw
  binary64 solution vector.
- Reduce matrix-dependent honest-prover work to one sequential traversal of
  the registered sparse matrix when the solver supplies `r`.
- Require no online row scan. Bound verification by the registered public
  evaluator plan, with a polylogarithmic target for families whose registered
  period terms also scale polylogarithmically.
- Report an absolute and, when defined, relative residual interval with an
  explicit frequentist failure budget.
- Define residual truth independently of SpMV reduction order, thread
  schedule, FMA contraction, and the solver's floating-point implementation.
- Reuse the current Rust sumcheck, transcript, evaluator, framing, and
  commitment abstractions when their proved contracts remain applicable.
- Measure total prover work, memory, proof bytes, and attempt cost rather than
  counting only sparse multiplications.

### 3.2 Non-goals

- Do not modify or reinterpret `fast-binary64-unit-circle-v5`.
- Do not trust a solver-supplied residual because it is small or because it was
  produced by a known solver.
- Do not infer a vector norm from the expectation of one random polynomial
  evaluation.
- Do not claim that a finite-field proximity theorem automatically applies to
  approximate complex or binary64 codewords.
- Do not claim generic succinct verification for arbitrary uploaded CSR
  matrices without an authenticated public-evaluation or preprocessing layer.
- Do not label a solve-relative work target as cryptographic soundness or as a
  lower bound against all adversaries.
- Do not equate one sparse matrix traversal with one-SpMV total runtime.

## 4. Proposed numerical statement

The first prototype remains scoped to the square systems supported by the
current generated-problem API. The registered problem digest fixes exact dyadic
matrix and right-hand-side values; current generator caps make those values
exactly representable in binary64. The candidate solution and residual witness
are accepted finite binary64 bit patterns:

```text
A in D_registered^(n x n)
b in D_registered^n
x in F64^n
r in F64^n.
```

A rectangular successor would need separately padded row and column domains
and a new packed-opening layout; it must not assume that the current equal-half
layout generalizes unchanged.

Interpret the registered dyadics and every accepted binary64 bit pattern as
exact real values and define

```text
r_star = b - A x
```

over the exact reals. The proposed statement is independent of the order in
which a solver or prover evaluates a row.

The successor profile should reject NaNs and infinities, choose one signed-zero
rule, preserve subnormals, and prohibit unrecorded FTZ or DAZ behavior. It must
bind dimensions, index base, sparse ordering, duplicate policy, padding,
binary64 encodings, generator version, and protocol version. These semantics
are intentionally different from the current fast profile, which rejects
source subnormals and flushes arithmetic subnormals. They therefore require a
new wire identifier and input boundary.

A later arbitrary-matrix profile may instead register canonical binary64
entries. It must define and authenticate those bytes separately rather than
pretending that the current generator digest commits a materialized CSR array.

The prover commits to binary64 vectors `x` and `r`, where `r` is an untrusted
residual witness. Define

```text
e = b - A x - r
C = ||r||_2
D = ||e||_2.
```

The triangle inequality gives

```text
max(0, C - D) <= ||b - A x||_2 <= C + D.
```

Suppose authenticated proof components establish, simultaneously,

```text
C in [C_minus, C_plus]
D <= D_plus
```

except with total probability at most `p_total`. Then the reported absolute
residual interval is

```text
L_abs = max(0, C_minus - D_plus)
U_abs = C_plus + D_plus.
```

Here `p_total` is a statistical failure probability over registered verifier
randomness, conditional on the stated hash, commitment, signature, and
content-addressing assumptions. Computational binding parameters are reported
separately; they are not silently added to a frequentist union bound.

If an independently authenticated bound gives

```text
||b||_2 in [B_minus, B_plus],  B_minus > 0,
```

then the relative residual interval is

```text
[L_abs / B_plus, U_abs / B_minus].
```

For `b = 0`, report only the absolute metric or a separately defined scaling;
do not divide by a normalization floor and call the result a relative
residual.

The central obligation is a valid and useful construction of `D_plus`. Until
that exists, certificate fields for a theorem-derived interval and failure
probability must remain absent or `null`.

## 5. Candidate one-pass audit

### 5.1 Commit the residual before its audit

The initial commitment covers the complete canonical packed message

```text
W = [x || r].
```

This reuses only the current equal-half concatenated shape. The existing second
half has semantics `R = A x - b`, while the successor witness has semantics
`r ~= b - A x`. The sign, arithmetic meaning, and accepted binary64 domain are
new and must be bound by the successor protocol identifier.

It is fixed before residual-sketch, sumcheck, batching, fold, or query
challenges are revealed. Supplying `r` changes who constructs the residual; it
does not remove the requirement to bind and audit it.

Both full vectors remain prover-local committed data. The independently
verifiable artifact is intended to carry roots, sumchecks, openings, and
multiproofs, not `x` or `r` themselves. Transferring `r` from a separate solver
process to the prover is an end-to-end implementation cost, not a proof-byte
requirement.

This interface is most useful when the solver already materializes a final
residual for convergence testing. If it does not, constructing and transferring
`r` may cost another SpMV and `O(n)` memory traffic. Benchmarks must report that
cost rather than treating every supplied residual as free.

### 5.2 Distribution-free reference sketches

Pad the row defect with exact zeros to `N = next_power_of_two(n)`. Let
`epsilon_t(i)` be four-wise-independent Rademacher signs over this padded
domain within repetition `t`, independent between repetitions and sampled
after `W` is fixed. For the conditionally fixed padded real defect `e`, define

```text
z_t = sum_i epsilon_t(i) e_i.
```

Here "fixed" is conditional on a successful robust-proximity event under which
the pre-sketch root determines one canonical binary64 message. The moment
argument cannot be applied to a decoded message selected after the sketch
seeds.

Four-wise independence is sufficient for

```text
E[z_t^2] = ||e||_2^2
E[z_t^4] <= 3 ||e||_2^4.
```

For `0 < theta < 1`, Paley--Zygmund therefore gives

```text
Pr[abs(z_t) >= sqrt(theta) ||e||_2]
    >= (1 - theta)^2 / 3.
```

This application assumes `e != 0`; the zero vector is handled directly with
`D = 0`.

For `k` independent repetitions, the probability that all sketches miss this
threshold is at most

```text
p_sketch(theta, k)
    = (1 - (1 - theta)^2 / 3)^k.
```

For example, `theta = 1/4` and `k = 15` give approximately `0.0444` before
allocating failure probability to batching, sumcheck, openings, proximity, or
retry. The resulting factor of two is an upper-bound conversion, not a claim
that the interval is within a factor of two of the true norm.

This is a reference theorem, not yet a protocol construction. A short seed can
make four-wise-independent signs reproducible without making their global
contractions succinct.

### 5.3 Batch the sketches into one sparse relation

After any sketch centers `z_hat_t` have been fixed, sample fresh batching
coefficients `lambda_t` and define

```text
s_i = sum_t lambda_t epsilon_t(i)
Z   = sum_t lambda_t z_hat_t.
```

The intended scalar relation is

```text
Z + (A^T s)^T x + s^T r = s^T b,
```

because `s^T e = s^T b - (A^T s)^T x - s^T r`.

The prover can construct `c = A^T s` with one canonical generated-row
traversal, or one CSR traversal for a materialized matrix. Each nonzero uses one
already-combined row scalar `s_i`, rather than performing one matrix scan per
sketch. The matrix-dependent arithmetic is therefore

```text
O(nnz(A)),
```

while forming the signs and combined row weights costs `O(k n)` and the
remaining norm, sumcheck, commitment, hashing, and opening work depends on `n`
and on the selected code.

The first near-one-pass experiment should fix `z_hat_t = 0` by protocol. This
avoids computing `k` exact residual projections and removes cheap prover-chosen
claim bytes as a grinding surface. It asks whether the supplied residual is
consistent enough that every true defect sketch is close to zero. Allowing
nonzero centers may tighten intervals when a solver can produce them cheaply.
Computing every center directly takes one residual matrix traversal plus
`O(k n)` row-sketch work, after which the fresh batching challenge normally
requires a second traversal for `A^T s`. Avoiding that second traversal by
precomputing every `A^T epsilon_t` costs `O(k nnz(A))` work and potentially
`O(k n)` storage. Both variants defeat a different part of the one-pass target
and must be reported honestly.

One accepted batched scalar relation does not deterministically establish all
individual sketch relations. Conditional on every transcript-prefix value that
fixes `d = z - z_hat` before `lambda` is sampled, a required robust batching
lemma has the uniform form

```text
sup over d with ||d||_infinity > E of
    Pr_lambda[abs(lambda^T d) <= tau | fixed prefix]
<= p_batch.
```

Its constants depend on the actual finite coefficient grid, `tau / E`,
coefficient scaling, and binary64 error envelope. Rademacher batching
coefficients are insufficient in general because equal components can cancel
with constant probability. A larger signed dyadic grid may work, but larger
coefficients increase dynamic range and roundoff. Complex phases improve some
anti-concentration geometry at the cost of complex sparse arithmetic. No one
of these choices is accepted by this proposal without an instantiated lemma.

The accepted binary64 transcript must imply the exact-real inequality used by
this lemma through a deterministic outward enclosure. Parameters `theta`, `k`,
`E`, `tau`, the coefficient grid, and their confidence allocations must be
bound before the sketch seeds. If `E` or `tau` is instead derived after seeing
the scalar defect, the protocol needs a simultaneous or explicitly
a-posteriori inversion theorem; selecting a favorable fixed-radius test after
acceptance is invalid.

If an accepted batched proof implies `|lambda^T (z - z_hat)| <= tau`, the
batching lemma establishes

```text
max_t |z_t - z_hat_t| <= E
```

except with probability `p_batch`. Combining this event with the independent
small-ball repetitions gives

```text
D_plus = max_t (|z_hat_t| + E) / sqrt(theta)
```

and a preliminary failure allocation

```text
p_D <= p_sketch + p_batch + p_sumcheck + p_opening + p_proximity.
```

For the zero-centered experiment, `D_plus = E / sqrt(theta)`. This is the
missing bridge from the batched relation to the final interval, but it is only
a theorem shape: `E` must be a proved simultaneous bound derived from
verifier-owned data, and every displayed probability must be instantiated for
the implemented finite distributions. This is a per-registered-attempt
statistical allocation conditional on computational binding; Section 7 must
lift it to the permitted adaptive retry process.

### 5.4 Reuse the packed opening

The existing packed linear-opening sumcheck can in principle batch:

- the final solution evaluation from the matvec sumcheck;
- the final residual evaluation from the norm sumcheck; and
- the claimed contraction `s^T r`.

This avoids `k` independent matvec and opening sumchecks. At the authenticated
endpoint, however, the verifier must evaluate the multilinear extension of
`s`. The complete verifier additionally needs succinct values for

```text
s^T b
s^T A eq_v
s_tilde(w).
```

The current `PublicEvaluationPlan` supports bit-separable equality weights. It
does not support arbitrary four-wise-independent signs. A seed makes `s_i`
cheap to reproduce at one index but does not make any of these three global
contractions polylogarithmic.

This succinct-contraction problem is the primary algebraic go/no-go gate. A
candidate sign family must simultaneously provide:

1. a proved lower-tail or small-ball property for every fixed defect vector;
2. succinct public RHS and matrix contractions for each supported generator;
3. a succinct packed-opening endpoint; and
4. an implementation whose sign-generation cost does not dominate low-degree
   sparse matrices.

If no such family is found, the Rademacher theorem still supports an `O(n)`
verifier or an additional proof, but not the intended online-verifier target.
Plain bit-separable Hadamard characters are succinct but do not provide the
same distribution-free four-wise guarantee; oversampling them requires an
explicit spectral-spread assumption.

## 6. Proof composition still required

The one-pass sparse contraction addresses only matrix traversal count. A
confidence-bearing certificate additionally requires all of the following.

### 6.1 Residual-witness norm

The norm proof must provide `[C_minus, C_plus]` for the exact-real L2 norm of the
decoded binary64 witness `r`. Replaying approximate degree-two identities and
recording their defects is not by itself such an interval. The proof needs a
robust a-posteriori sumcheck analysis, deterministic numerical enclosures, or
an exact alternative whose cost is measured.

### 6.2 Approximate sumcheck

The applicable theorem must be instantiated for:

- degree two;
- the actual number of rounds at target dimensions;
- the exact finite real or complex challenge grid;
- heterogeneous, transcript-observed numerical errors;
- the chosen acceptance gap; and
- the allowed challenge-retry model.

The currently studied general approximate-sumcheck bound has a contraction
exponent proportional to the reciprocal of the round count. Straightforward
binary64-scale substitutions appear vacuous around `2^20` entries even before
proximity and retry costs are added. This observation must be reproduced in a
checked parameter notebook or test. It motivates a sharper degree-two,
a-posteriori theorem; it does not prove that no useful theorem exists.

There is also a domain mismatch before constants are considered: the
real-domain theorem assumes that the Boolean evaluation set lies in the convex
hull of the challenge set, while current challenges lie in `[1/4, 3/4)` and
the Boolean endpoints are `{0, 1}`. A successor needs either a bespoke
extrapolation theorem or a versioned challenge-distribution change.

Complex unit-circle or affine-diameter challenges may improve local numerical
conditioning. They do not, on their own, turn a scalar accepted identity into
a bound on `||e||_2`, and they do not transfer a theorem from ideal Haar phases
to a discrete binary64 phase table.

### 6.3 Robust committed-oracle proximity

Merkle authentication proves that queried values belong to one committed
oracle. A small number of successful recursive fold queries proves, at most, a
conditional statement about the sampled trajectories and a hypothesized bad
fraction. It does not prove that the full approximate complex oracle is close
to a unique codeword encoding a real `[x || r]` message.

An arbitrary nearby real message is also insufficient for the exact-bit
statement. The proximity target must be the image of the canonical
binary64-message encoder, or a separate source-byte commitment must be linked
to the encoded oracle. The pre-sketch root must determine the decoded `W`
uniquely and independently of later sketches; selecting a compatible decoded
message after seeing sketch seeds would invalidate the fixed-defect moment
argument.

A successor protocol needs an explicit robust proximity statement covering:

- distance to the real-message code;
- canonical binary64 coordinates and linkage to their committed source bits;
- approximate complex fold errors;
- magnitude or energy control;
- outlier locations and sampled-query probabilities;
- uniqueness or stability of the decoded message; and
- composition across dependent fold rounds.

Until this statement is proved and instantiated, lowering the current query
count changes an empirical audit rate, not a theorem-derived soundness level.

### 6.4 Public problem authentication

For current registered generator families, the existing evaluator is a useful
starting point. It already avoids scanning rows and is scalar-generic through
`MleInterpreter`. A reviewed complex or interval interpreter and its error
semantics are new work, as are the selected sign contractions. A safe evaluator
bound is `O((registered period terms + 1) log n)`, and manifests permit a
bounded term count as large as `2^20`; it is not unconditionally polylogarithmic
merely because it performs zero row queries.

For an arbitrary CSR input, public knowledge of `A` does not make
`s^T A eq_v` succinct. Such inputs require authenticated preprocessing, a
separate sparse lookup/sumcheck argument, or an explicit `O(nnz(A))` verifier.
The preprocessing bytes, time, mutability, and trust model must be part of the
statement.

## 7. Challenge and retry model

The clean statistical chronology is:

1. register the public statement, attempt policy, `theta`, `k`, batching grid,
   threshold/enclosure selection rule, and confidence allocations;
2. commit to `[x || r]`;
3. reveal independently generated sketch seeds;
4. fix any prover-supplied sketch centers;
5. reveal fresh batching coefficients;
6. for each sumcheck round, fix the round message before revealing its
   challenge;
7. fix each child fold root before any challenge that depends on it; and
8. sample audit queries only after all audited roots are fixed.

The current noninteractive Fiat--Shamir construction derives challenges in the
right local order, but a prover can retry roots or cheap round messages. A
solve-relative design is especially sensitive to this distinction: if an
attempt can be varied without rebuilding the expensive commitment or sparse
contraction, the relevant attack cost is the cheap variation, not the cost of
an honest full proof.

The preferred initial deployment model is a stateful interactive service with
fresh post-commitment challenges and an enforced attempt identity. A fully
sequential sumcheck requires `O(log n)` challenge round trips, which can make
network latency dominate verifier arithmetic. Moreover, an independently
replayed artifact must authenticate and trust the external challenge source;
interaction does not preserve the same permissionless verification model as a
plain Fiat--Shamir artifact.

The service must also retain bounded session state, expire abandoned sessions,
make replay behavior explicit, and defend the commitment endpoint against
resource-exhaustion attacks. These operational costs must be benchmarked with
the cryptographic work rather than treated as free challenge freshness.

If a noninteractive artifact is retained, its theorem must include a
random-oracle query and branching budget rather than treating one
Fiat--Shamir transcript as one attempt. An account or request identifier alone
does not stop a distributed prover from creating more identities; rate limits,
fees, or another enforceable resource policy belong to the deployment model.

For a fixed attack strategy with per-attempt escape probability `p_escape`,
attempt cost `C_attempt`, and solve cost `C_solve`, the heuristic

```text
C_attempt / p_escape >= kappa C_solve
```

can guide parameter selection. It is not a lower bound on the cheapest false
certificate strategy, and it applies only when attempts have approximately the
assumed cost and conditional escape bound.

A realistic attacker may reuse an `A x` computation, inspect fresh sketch
challenges, abandon unfavorable branches cheaply, and construct the expensive
remainder only after a favorable prefix. A more useful selective-abort model
separates

```text
C_setup
    + ((1 - p_escape) / p_escape) C_failed_branch
    + C_successful_branch.
```

An operational policy must also bound the number of registered attempts `T`.
The bound `min(1, T p_escape)` is valid for adaptive attempts only when every
attempt has conditional escape probability at most `p_escape`, not merely when
one fixed attack has that measured rate. Query counts may be reduced only after
the proximity, batching, selective-abort, amortization, and retry experiments
defining these quantities are fixed.

## 8. Performance model

With a supplied residual and successful batching, the candidate prover has the
following leading work:

```text
one sparse transpose scatter: O(nnz(A))
sketch/sign construction:     O(k n)
norm and sumcheck tables:      O(n) per composed pass
code construction:            currently O(N log N) for the initial FFT
folds and Merkle hashing:      O(N) aggregate data, with large constants
proof serialization:          depends on queries and fold depth
```

Here `N` is the padded solution dimension used by the current memory model;
the packed message has `2 N` entries. Every currently registered family is in
the low-degree regime: DIA rows contain at most 33 structural entries and the
nonsymmetric families at most 32. On these workloads, `k n`, FFT, hashing, and
memory traffic may dominate. Testing hundreds of nonzeros per row requires a
new registered generator and matching public evaluator; only in such a regime
is the sparse scan likely to dominate automatically.

Constructing `A^T s` from row-oriented CSR is a transpose scatter, not the same
memory-access pattern as an optimized `A x`. Column updates can be irregular;
parallel implementations may need per-thread scratch, atomics, or a separate
CSC representation and must address false sharing, determinism, and reduction
order. Benchmark this contraction separately against both CSR SpMV and the
current fast-path contraction instead of assigning it the SpMV constant.

Reducing proximity queries primarily reduces proof bytes and verifier work.
The current prover still constructs the full codeword and fold hierarchy.
Changing the code rate from one-half to a higher rate can reduce code-side work
by at most a modest constant unless the FFT-based commitment is replaced.
Reaching a total cost close to one SpMV likely requires a genuinely linear,
high-rate commitment with a robust approximate-real proximity theorem.
Linear-time finite-field commitments are evidence that useful layouts exist;
their theorems do not automatically transfer to this domain.

Memory is a separate blocker. The current fast backend estimates `176 N` bytes
of size-dependent live storage and enforces a one-GiB preflight limit. A
protocol aimed at tens or hundreds of millions of unknowns needs streamed or
reused buffers, a lower-rate footprint, external-memory construction, or some
combination. Linear arithmetic scaling alone is insufficient if the proof
cannot be constructed within the target memory envelope.

The current `176 N` estimate also excludes caller-owned problem and solution
storage. A supplied residual adds another caller-side binary64 vector unless
the successor API transfers or reuses solver-owned storage. Both backend and
end-to-end process memory must be reported.

### 8.1 Oversampling parameters are not interchangeable

Several independent parameters can look like "oversampling," but reducing one
does not substitute for analyzing the others:

- proximity query count controls proof bytes, verifier work, and a conditional
  sampled bad-fraction miss probability;
- code rate controls encoded length, distance, hashing, and proximity
  assumptions;
- residual-sketch count `k` controls the Rademacher small-ball miss probability
  and adds `O(k n)` sign work;
- batching-grid cardinality controls one anti-cancellation term and affects
  coefficient magnitude and numerical error; and
- a sumcheck challenge-set size controls an algebraic root event but does not
  remove the tolerance-contraction term in an approximate theorem.

Solve-relative calibration may eventually justify smaller values than a
conventional cryptographic profile. Each reduction still needs to be charged
to its own theorem term and to the allowed retry budget.

The honest benchmark target should therefore be reported as

```text
one matrix pass + measured contiguous-vector/commitment passes,
```

with total wall time also expressed in equivalent optimized CSR SpMV times.
The phrase "one-pass prover" refers only to matrix traversal until the complete
measured ratio justifies a stronger claim.

## 9. Proposed repository architecture

All work should remain in Rust and reuse existing crates. A standalone rewrite
would duplicate mature framing, sumcheck, Merkle, evaluator, and mutation-test
coverage without resolving the missing theorems.

The likely boundaries are:

- add a successor protocol identifier rather than changing the current enum
  meaning;
- introduce a versioned candidate input containing both `x` and `r`, whose
  dimensions and binary64 semantics are explicit; the shared `Solution` type
  rejects subnormals and negative zero, and the existing `ValidationBackend`
  accepts only that type, so adding only a `ResidualWitness` is insufficient;
- allow material preparation to consume supplied `[x || r]` without calling
  the current residual constructor;
- retain a full-scan mode behind a successor boundary analogous to
  `ReferenceValidationBackend` that computes `b - A x - r` independently; the
  current trait also accepts only `Solution`, so it needs a versioned extension,
  while the succinct verifier must continue to have no row access;
- add an exact-dyadic or outward-rounded high-precision reference oracle for
  small and medium tests;
- reuse the scalar-generic `MleInterpreter` plan with reviewed complex or
  interval interpreters and explicit error semantics, while adding new public
  operations only after a candidate sign family specifies its contractions;
- put interactive challenge state in a new service path rather than pretending
  that a stateless request supplies fresh post-commitment randomness; and
- define a new interval-bearing score and signed-certificate variant only
after the theorem inputs are verifier-owned and complete.

The current product-sumcheck and unit-circle implementations hardwire v5's
concrete binary64 validation and FTZ behavior. Their algorithms, layouts, and
tests are reusable, but their arithmetic implementations are not a semantic
drop-in for preserved-subnormal or complex/interval successor arithmetic.

The current staged `commit` followed by `prove` path also recomputes prepared
material: together it performs three matrix scans and repeats encoding/root
work, while the one-step path performs two scans. An interactive successor must
retain large prepared state across challenges or define a checkpoint that can
be reloaded without recomputation. Retained memory, checkpoint I/O, expiry,
authentication, and cleanup are part of the performance and service design.

The full-scan mode is a research oracle and regression baseline, not the final
succinct verifier. It should share serialization and numerical semantics with
the sampled mode so comparisons detect proof-system errors rather than format
differences.

## 10. Research phases and gates

### Phase 0: freeze claims and reproduce baselines

- Record current two-scan fast-prover time, proof bytes, peak RSS, and work
  counters in release mode.
- Record optimized CSR SpMV and representative solve times on the same inputs.
- Separate matrix scans, vector passes, FFT, hashing, fold construction,
  multiproof construction, and serialization.
- Freeze exact-real source semantics and a versioned full-scan oracle.
- Freeze representative dimensions and sparsities plus numeric targets for the
  proof/vector byte ratio, total-prover SpMV multiple, verifier work and
  latency, peak process memory, and useful interval width.

Gate: no performance conclusion without reproducible inputs, thread counts,
hardware context, repeated timings, and memory measurements.

### Phase 1: supplied residual witness

- Add an experimental API accepting `x` and `r`.
- Commit the successor's equal-half packed shape while skipping internal
  residual formation; do not reuse the current second-half semantics.
- Verify the one-matrix-scan work counter.
- Compare solver-produced, prover-recomputed, zero, understated, and adversarial
  residual witnesses.
- Include the cost of obtaining and transferring `r` in end-to-end results.

Gate: for fixed challenges, its norm inputs, sparse contraction, endpoint
values, and deterministic interval composition must agree with the independent
full-scan oracle within the successor's stated enclosures on exhaustive tiny
examples and deterministic randomized tests.

### Phase 2: batching theorem and one-pass prototype

- Implement four-wise-independent Rademacher signs with a frozen field basis,
  index map, trace convention, and reproducible seeds.
- Verify second- and fourth-moment identities exhaustively at small sizes.
- Prototype zero-centered and claimed-center batching.
- Enumerate the actual finite batching grid and derive an anti-cancellation
  bound including binary64 intervals.
- Measure `O(k n)` sign generation separately from the sparse scan.

Gate: no individual-sketch interval may be inferred from one batch without a
proved robust batching lemma for the implemented distribution.

### Phase 3: succinct contraction search

- Search for a sketch family satisfying both the small-ball theorem and the
  three public/packed contractions.
- Implement `O(n)` reference contractions and compare every succinct candidate
  against them.
- Test supported generator families separately; do not generalize from one
  stencil or banded family.
- Measure low-degree matrices where sign expansion can dominate `nnz(A)` work.

Gate: record an `O(n)` verifier as a failed succinctness result. Do not hide it
inside preprocessing or an unmeasured helper.

### Phase 4: approximate sumcheck and proximity

- Instantiate the existing general theorem before relying on it.
- Develop and test a sharper degree-two a-posteriori alternative if the bound
  is vacuous.
- Prove robust proximity for the exact real-message code and implemented
  approximate fold arithmetic.
- Compare the current real challenge grid, canonical dyadic grids, and complex
  circle variants without conflating local conditioning with global norm
  inference.

Gate: theorem-derived interval fields remain `null` until both the global
relation-defect and committed-oracle proximity statements compose.

### Phase 5: interaction and end-to-end composition

- Implement registered post-commitment challenges and attempt accounting.
- Allocate failure probability across sketches, batching, sumchecks, openings,
  proximity, and retries.
- Add a new strict certificate schema exposing every allocation and numerical
  enclosure.
- Run malicious-prover and transcript-mutation campaigns before enabling the
  profile outside research mode.

Gate: an empirical escape rate is not serialized as a theorem-derived failure
probability.

### Phase 6: commitment and memory optimization

- Profile before changing the current code.
- Evaluate higher-rate and linear-time commitment candidates only against a
  written approximate-real proximity statement.
- Reuse or stream flat buffers and measure peak resident memory.
- Re-run proof-size, verifier, and false-certificate experiments after every
  query or rate change.

Gate: retain the simpler implementation unless a release benchmark shows a
material end-to-end improvement without weakening the documented claim.

## 11. Required tests and adversarial cases

Correctness and numerical tests must include:

- empty and singleton dimensions where supported;
- non-power-of-two padding;
- duplicate sparse entries under the registered policy;
- smallest and largest subnormals and values around the normal boundary;
- signed zero according to the chosen canonicalization rule;
- overflow, underflow, cancellation, scale separation, and non-finite
  intermediates;
- exact zero residual, one-coordinate defects, dense equal defects,
  checkerboard/parity defects, and tensor-product defects;
- well-conditioned, ill-conditioned, singular, and inconsistent systems; and
- deterministic comparison with an independent exact-dyadic reference.

Adversarial protocol tests must include:

- zero, understated, unrelated, and challenge-dependent residual witnesses;
- sketch vectors chosen to maximize lower-tail probability;
- batch components engineered to cancel for weak coefficient grids;
- round messages or roots chosen after their challenge;
- malformed, aliased, duplicate, and out-of-range multiproof paths;
- complex codewords far from every real packed message but locally consistent
  on sampled trajectories;
- grinding over roots, sketch centers, batching messages, and fold messages;
- replay across statements, attempts, generator versions, and protocol
  versions; and
- verifier public-endpoint implementations that silently fall back to a full
  row scan.

All randomized failures must report their seed. Optimized implementations must
be checked against simple reference implementations.

## 12. Certificate and reporting requirements

Every research result must distinguish:

- a signed service certificate from the complete independently verifiable
  proof artifact;
- exact-real reference truth from frozen binary64 prover computations;
- deterministic numerical enclosures from stochastic failure probabilities;
- a conditional query miss curve from global codeword proximity;
- per-registered-attempt probability from a multi-attempt operational budget;
- matrix-dependent work from total prover work; and
- theorem-derived intervals from empirical coverage or attack rates.

Before the missing composition is complete, a research result may report:

```text
full_reference_interval
local_consistency_diagnostics
conditional_query_miss_curves
empirical_attack_rate
```

but must set

```text
theorem_residual_interval = null
theorem_failure_probability = null.
```

A future interval-bearing certificate should include at least:

- protocol, arithmetic, matrix-layout, sketch, batching, sumcheck, proximity,
  and retry-policy identifiers;
- commitments to the statement and packed message;
- `C_minus`, `C_plus`, `D_plus`, and the final absolute interval;
- the right-hand-side norm interval and relative interval when defined;
- separate failure allocations for every stochastic component;
- deterministic numerical-error provenance;
- proof digest and complete transcript digest; and
- proof bytes or an unambiguous content-addressed reference to them.

## 13. Alternatives deliberately rejected for the first prototype

### Recompute the residual inside the prover

This preserves the current two-scan architecture and misses the main
performance opportunity. It remains the required full-scan reference path.

### Trust the supplied residual

This makes a dishonest residual an unchecked assertion and does not validate
the candidate solution.

### Use one torus MLE observation as the defect norm

The second-moment identity is correct, but structured vectors can have a poor
lower tail. Unbiasedness is not an upper-confidence theorem.

### Reduce the 64 proximity queries immediately

This shrinks proof and verifier work but has little effect on code construction
and can make cheap grinding decisive. Query tuning follows, rather than
precedes, a proximity and retry theorem.

### Port a finite-field linear commitment unchanged

Finite-field results motivate data layouts and asymptotic targets. They do not
establish distance, approximate folding, or numerical soundness over binary64
or complex values.

### Rewrite the prototype in another language

The unresolved work is mathematical and architectural rather than a lack of
low-level implementation machinery. Reusing the current Rust components keeps
wire parsing, work limits, sparse generators, and adversarial tests in scope.

## 14. Success criteria

This proposal succeeds only if the implementation eventually demonstrates all
of the following:

1. The exact-real residual semantics and binary64 boundary are frozen and
   independently testable.
2. A solver-supplied residual removes one complete matrix scan without being
   trusted.
3. The selected sketch family gives a distribution-free global defect bound
   and all required verifier contractions remain succinct.
4. Batching, approximate sumcheck, openings, and robust proximity compose into
   a useful `D_plus` at target dimensions.
5. The challenge service enforces, or the theorem explicitly accounts for,
   retries and Fiat--Shamir branching.
6. The complete proof and verifier meet the proof/vector ratio and verifier
   targets frozen in Phase 0 for supported registered problems.
7. Release benchmarks meet the Phase 0 total-prover SpMV multiple and process
   memory ceiling, including residual transfer and interaction costs.
8. The adversarial campaign documents the cheapest implemented
   false-certificate strategy and the parameter model charges that strategy;
   passing the campaign is not presented as a lower bound against unknown
   attacks.

Failure of an intermediate candidate is still useful if it identifies the
smallest missing lemma, contraction, or cost center without upgrading an
empirical result into a certificate claim.
