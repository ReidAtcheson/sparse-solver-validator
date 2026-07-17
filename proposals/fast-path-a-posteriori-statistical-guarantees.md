# A posteriori statistical guarantees for the fast path

Status: research proposal; non-normative.

Scope: a possible successor to `fast-binary64-unit-circle-v4` and diagnostic
policy 3. Nothing in this document upgrades the guarantees of the current
profile, `fast-binary64-diagnostics-v1` score, or
`sparse-solve/validation-certificate/v4` certificate.

## 1. Summary

The fast validator already records much of the numerical provenance needed for
an a posteriori statement of the form

```text
Pr[abs(squared_l2_claim - true_squared_l2) > B(transcript, public_bounds)]
    <= alpha.
```

Here `B` must be a prespecified, proved function of the random transcript, or
part of a simultaneous/anytime-valid family. Data dependence is allowed;
selecting a favorable bound or confidence allocation after inspection is not.

The intended result is a confidence interval around the reported residual, not
a new approximate protocol-level accept/reject rule. Exact failures such as
invalid framing, noncanonical values, transcript mismatches, shape errors, and
invalid Merkle openings remain hard verification failures. Approximate
relations remain measurements whose error contributions are exposed to the
caller.

A recent approximate-sumcheck result makes this direction plausible: for a
fixed local tolerance, it proves that the probability of hiding a large
initial-claim error degrades gracefully with the ratio between that tolerance
and the false initial claim. Converting located, observed defects into a
post-hoc heterogeneous bound is new work. That analysis must then be composed
with a robust numerical unit-circle proximity argument.

The central engineering conclusion is:

> The current provenance is close to the input of a global theorem, but the
> current single MLE consistency point and signed aggregate fold summaries are
> not yet sufficient for a useful distribution-free residual interval.

## 2. Current fast-path statement and evidence

The current fast profile constructs a once-quantized Q63.64 witness, converts
it to the frozen binary64 representation, computes a candidate residual, and
packs

```text
W = [x || R].
```

It then composes:

1. a residual-norm product sumcheck;
2. a sparse matvec product sumcheck;
3. a batched linear-opening sumcheck tying `x_tilde(v)` and `R_tilde(u)` to
   `W`; and
4. recursively committed unit-circle folds with transcript-derived Merkle
   multiproofs.

For every approximate scalar relation, policy 3 records

```text
absolute_defect     = abs(actual - expected)
normalization_scale = min(abs(actual), abs(expected))
relative_error      = absolute_defect
                    / max(normalization_scale, zero_scale).
```

The zero scales are normalization floors, not tolerances or error bounds. The
in-process verifier retains located observations for each sumcheck round and
endpoint and for each sampled fold trajectory. Certificates retain stable
family summaries and deterministic public RHS/matrix evaluation roundoff
provenance.

The existing report deliberately states that it supplies no residual-quality
verdict and no global a posteriori error bound.

## 3. Quantity to be bounded

The first theorem should choose one target semantics and name it explicitly.
The recommended initial target is

```text
X      = the real binary64 solution identified by a future robust decoder
R      = the real binary64 residual identified by that robust decoder
r_real = A X - b, with all canonical values interpreted as exact reals
Q      = squared_l2_claim
```

The candidate theorem is conditional on the proximity lemma establishing the
existence and required uniqueness/stability of that real packed message
`W = [X || R]`. The present Merkle root directly commits a complex evaluation
oracle, not an already decoded real message.

The honest current prover constructs `X` from the once-quantized Q63.64
witness. A global theorem must not infer that fact merely from the source
digest: the digest is linkage metadata, while the root and opening bind the
proof to the packed oracle. A theorem specifically about the Q63.64 witness
therefore needs an additional quantization/range binding, or it must state that
the committed binary64 `X` is its target.

This target separates three effects that should not be conflated:

- transcript consistency between `Q`, `R`, `X`, `A`, and `b`;
- binary64 roundoff in the prover and verifier; and
- quantization distance between the original solver output and the
  once-quantized witness used by the honest prover.

An alternative theorem may target the frozen rowwise binary64 computation
`r_fl = fl(A X - b)`. That version needs a deterministic row-computation
roundoff term connecting `r_fl` to `r_real`. A theorem about the original,
pre-quantization solver vector additionally needs an explicit quantization
term. Neither extension should be implicit.

## 4. Candidate end-to-end theorem

Assume two component results hold simultaneously:

```text
abs(Q - norm(R)^2) <= B_N
norm(R - r_real)   <= D.
```

The first is the residual-norm claim bound. The second is the global
matvec/opening/commitment consistency bound. Then

```text
abs(Q - norm(r_real)^2)
    <= B_N + 2 * sqrt(Q + B_N) * D + D^2
    =: B_squared.
```

This follows from

```text
abs(norm(R)^2 - norm(r_real)^2)
    <= 2 * norm(R) * D + D^2
```

and `norm(R) <= sqrt(Q + B_N)`.

The tighter interval implied directly by the two component events is

```text
L_R = sqrt(max(0, Q - B_N))
U_R = sqrt(Q + B_N)

norm(r_real) in [max(0, L_R - D), U_R + D].
```

Squaring these endpoints gives the corresponding asymmetric squared-L2
interval. `B_squared` remains useful when an API specifically needs one
symmetric absolute-error radius.

If the component events fail with probabilities at most `alpha_N` and
`alpha_D`, respectively, a first composition may use the union bound

```text
alpha_total <= alpha_N + alpha_D.
```

Sharper accounting is welcome, but dependencies must be proved rather than
assuming that transcript rounds or reused query trajectories are independent.

## 5. Mapping current provenance to theorem terms

| Current evidence | Proposed theorem role |
| --- | --- |
| Located residual-norm sumcheck defects | Construct `B_N` through a robust backward sumcheck calculation |
| Located sparse matvec sumcheck defects | Bound the sampled consistency error between `R + b` and `A X` |
| Located linear-opening defects and batching challenge | Bind the sampled `X` and `R` evaluations to the packed oracle |
| Sampled unit-circle fold defects | Inputs to a future robust proximity bound, together with magnitude or energy control |
| Public RHS/matrix forward-roundoff provenance | Add deterministic corrections to verifier endpoint evaluations |
| Conditional query miss curves | Bound an unsampled bad fraction, conditional on a defined threshold |
| Exact structural and Merkle checks | Preconditions for the statistical argument; never numerical error terms |

The theorem should consume absolute defects and explicit deterministic
roundoff bounds. The current floor-relative statistic remains important
human-readable provenance, but it is not the primary proof metric: its
denominator depends on the compared values and it is not known to satisfy the
metric and triangle properties required by robust-sumcheck composition.

Policy 3 saturates a diagnostic-only subtraction overflow to `f64::MAX`. That
sentinel preserves traceability but is not an upper bound on the mathematical
real-number defect. A formal calculator must recompute such a relation in a
wider or exact interval representation; otherwise it must report the global
bound as unavailable or unbounded.

## 6. Required theoretical work

### 6.1 Heterogeneous robust product sumcheck

For one `m`-round product sumcheck, let `d_i` be the absolute defect in round
`i` and `d_endpoint` the authenticated endpoint defect. A candidate analysis
works backward from the endpoint:

```text
B_m     = d_endpoint + endpoint_product_roundoff
B_{i-1} = (d_i + endpoint_sum_roundoff_i)
          + A_2(alpha_i) * (B_i + evaluation_roundoff_i).
```

Here `endpoint_sum_roundoff_i` bounds computing `g_i(0) + g_i(1)`, while
`evaluation_roundoff_i` bounds de Casteljau evaluation at the challenge.
`A_2(alpha_i)` is a degree-two anti-concentration factor for the actual
challenge distribution satisfying, for every real degree-two polynomial `p`
fixed before `U` is sampled,

```text
Pr_U[abs(p(0) + p(1)) > A_2(alpha_i) * abs(p(U))] <= alpha_i.
```

In an adaptive sumcheck this statement is applied conditionally on the
transcript prefix and prover round message fixed before that round's challenge.

This is the located, heterogeneous-defect analogue of applying one fixed
tolerance to every approximate sumcheck check. A tight degree-two derivation is
preferable to importing a loose general-degree result. The analysis must also
cover:

- Bernstein-basis round messages;
- the exact 52-bit discrete challenge distribution;
- binary64 de Casteljau evaluation and endpoint arithmetic;
- the fast arithmetic rule that flushes transcript-feeding subnormals; and
- the fact that finite subnormal diagnostic defects themselves are retained.

The 2026 approximate-sumcheck theorem does not apply verbatim. Its real-domain
instantiation assumes that the Boolean evaluation set is inside the convex
hull of the challenge set. The current challenges lie in `[1/4, 3/4)`, while
the Boolean endpoints are `{0, 1}`. A protocol successor may either prove a
bespoke extrapolation bound or change the challenge distribution. Any challenge
change is protocol-versioned.

Because the desired result is computed after observing the transcript, the
proof must establish a simultaneous or directly a posteriori inequality for
the random defect budget. It is not valid merely to take a theorem proved for
one fixed tolerance and select that tolerance after seeing the challenges and
errors. Confidence allocations, thresholds, and any choice among advertised
confidence levels must be fixed in advance or covered simultaneously by the
theorem.

The batched linear opening additionally needs a degree-one anti-concentration
step. The opening initially binds only the random combination

```text
Delta_X + alpha * Delta_R.
```

One fixed `alpha` cannot deterministically bound both terms because they may
cancel. The theorem must use that `alpha` is sampled after the two claims are
fixed, allocate a batching failure probability, and account for the actual
discrete challenge distribution.

### 6.2 From one row MLE observation to a global residual bound

The current row consistency measurement can be badly conditioned as an
estimator of `norm(R - r_real)`. For `n = 2^m`, consider the structured error

```text
D_s = M * (-1)^popcount(s).
```

Its multilinear extension is

```text
D_tilde(u) = M * product_j(1 - 2*u_j).
```

Every current challenge coordinate is in `[1/4, 3/4)`, so

```text
abs(D_tilde(u)) <= M / n,
norm(D)          = M * sqrt(n).
```

Equivalently,

```text
abs(D_tilde(u)) / norm(D) <= n^(-3/2).
```

Thus a global inconsistency can appear smaller by a factor of at least
`n^(3/2)` at every permitted row point. This is a conditioning example, not a
cryptographic attack requirement. It shows that a dimension-independent,
useful `L2` bound cannot be derived from this single observation for arbitrary
signed errors.

The leading replacement candidate is a challenge-driven, oversampled Hadamard
sketch. Complex unit-circle sketches, direct random row checks, and an explicit
incoherence or spectral-shape condition remain alternatives to evaluate.
Repeating the current central MLE sample reduces a tail probability but does
not remove its dimension-dependent conditioning.

#### 6.2.1 Challenge-driven oversampled Hadamard sketches

Let `N = 2^m` be the padded dimension and, for a challenged column index
`a in {0,1}^m`, define the unnormalized Hadamard column

```text
h_a(i) = (-1)^<a,i>.
```

For the global consistency error

```text
D = A X - b - R,
```

one supervised observation is the ordinary linear sketch

```text
z_a = h_a^T D.
```

Uniform Hadamard columns satisfy

```text
E_a[h_a h_a^T] = I,
E_a[abs(h_a^T D)^2] = norm(D)^2.
```

This is the useful linear-algebra interpretation missing from the current row
MLE observation. The current equality-polynomial vector is a positive
Kronecker-product averaging vector; `h_a` is a signed Kronecker-product vector
from an orthogonal basis.

The least disruptive protocol design changes only the row sketch. It retains
the existing column MLE point `v`, committed-vector opening, and product
sumcheck. The prover forms

```text
c = A^T h_a
```

and proves

```text
c^T X = h_a^T A X.
```

The terminal public/committed factors are then

```text
(h_a^T A w(v)) * (w(v)^T X),
```

where `w(v)_j = eq_j(v)`. The generator-owned public evaluator would need
succinct, supervised operations for

```text
h_a^T b
h_a^T A w(v).
```

For the registered periodic tridiagonal family, this appears compatible with
work proportional to the generator period and `log N`: both `h_a` and `w(v)`
are separable over index bits, while the existing public evaluator already
handles the carry structure introduced by neighboring indices. This complexity
claim must be demonstrated by a reference-equivalent implementation and
measured; the protocol must not hide an `O(N)` public scan.

A fully transformed alternative would use

```text
A_hat(a,b) = h_a^T A h_b
X_hat(b)   = h_b^T X
h_a^T A X  = (1 / N) * sum_b A_hat(a,b) X_hat(b).
```

That formulation exposes individual entries of `H^T A H`, but it also requires
authenticated Hadamard-domain openings of `X` and a transformed-coordinate
sumcheck. The hybrid `h_a^T A w(v)` endpoint is therefore the preferred first
prototype.

In the binary64 profile, one observation is not intended to carry the final
confidence statement. After the packed oracle root and all data determining
`D` are fixed, the supervisor repeatedly performs

```text
challenge a_1 -> verify sketch 1
challenge a_2 -> verify sketch 2
...
challenge a_k -> verify sketch k.
```

Each sketch proof must receive its own fresh challenges in the sequential
model of Section 6.5. The repetition count and confidence allocation must be
fixed before observing the sketches, or be covered by an anytime-valid rule.
Stopping after favorable observations and reporting a fixed-sample confidence
level is invalid. Individual sketch observations and their deterministic
binary64 error intervals must remain available to the bound calculator;
oversampling reduces statistical uncertainty, not roundoff.

Sampling columns from one fixed Hadamard basis has a serious worst-case
limitation. Although the squared observation is unbiased, a nonzero `D` may be
concentrated in one Hadamard mode. Sampling `k` distinct columns then misses it
with probability `1 - k / N`. Consequently, a small number of plain Hadamard
columns cannot give a useful distribution-free upper confidence bound.

The primary design to analyze should therefore randomize the basis as well as
the column. For example, let `S_t` be a fresh challenge-derived Rademacher
diagonal and observe

```text
z_t = h_(a_t)^T S_t D.
```

For fixed `a_t`, the vector `S_t h_(a_t)` is a Rademacher sketch. An arbitrary
independent sign diagonal, however, destroys the simple bit-separable public
contraction: a short seed makes the signs reproducible but does not by itself
make `h_(a_t)^T S_t A w(v)` succinctly evaluable. The design therefore needs a
challenge-derived sign family with both a proved small-ball property and a
generator-owned succinct contraction algorithm. The theorem must specify how
the signs are generated, how much independence is required, and whether a
short challenge seed is interpreted through a cryptographic random oracle or
an explicit bounded-independence family. Independently randomized Hadamard
bases with supervised contractions are another candidate. If no such family
exists at useful cost, plain Hadamard oversampling can support only a theorem
with an explicit spectral-spread assumption, not the desired
distribution-free result.

The residual-consistency theorem must derive a simultaneous upper bound on
`norm(D)` from the interval-valued observations `{z_t}`. It must cover the
chosen sketch's lower-tail or small-ball probability, the number of sequential
samples, sampling with or without replacement, adaptive transcript messages,
and deterministic errors in both public bilinear evaluation and authenticated
linear openings. Merely citing the unbiased second moment is insufficient.

### 6.3 Robust numerical unit-circle proximity

The existing `q` unique initial fold trajectories are sampled without
replacement, where `q = min(64, message_len)`. For a fixed fold round and a
fixed bad set containing fraction `phi` of base trajectories, their miss
probability is bounded by

```text
(1 - phi)^q.
```

The same trajectories are reused and projected across rounds, so these
probabilities must not be multiplied across rounds. When `message_len >= 64`,
`q = 64`, and the population was fixed before sampling, missing a fixed 1% bad
set in one round has probability about `0.99^64 = 0.526`. If no sampled
trajectory exceeds a selected threshold (or the sample maximum is used as that
threshold), the same one-round calculation only establishes at 95% confidence
that approximately 4.6% of base trajectories may be worse. Projected
trajectories can collide in later, smaller domains; exact per-round
finite-population bounds must account for their preimage multiplicities. A
simultaneous all-round statement needs an explicit confidence allocation, such
as a union bound.

This is a quantile or bad-fraction statement, not yet an `L2` magnitude bound.
If unsampled fold errors are unbounded, a small unseen fraction can contain
nearly all of the numerical error. A complete lemma therefore needs at least
one of:

- an authenticated maximum-magnitude bound;
- an authenticated energy bound;
- a justified tail model; or
- a robust decoding theorem that tolerates a bounded outlier fraction and
  controls numerical distance to a valid codeword.

The resulting proximity statement must also identify a valid *real* packed
message `W = [X || R]`, or separately bound deviation from real coefficients;
ordinary low-degree proximity of a complex evaluation oracle is not by itself
that statement.

The proof should retain fold observations by round. One aggregate maximum and
RMS across all rounds loses the local domain size and operator conditioning
needed for a tight calculation.

In ideal real arithmetic, the parent-to-child fold map is contractive in the
unnormalized complex Euclidean norm. For challenge `r`, its operator norm is

```text
sqrt(((1 - r)^2 + r^2) / 2) <= sqrt(5) / 4.
```

This is promising for backward error propagation. The replayed binary64 map is
not exactly linear because of rounding and subnormal handling, so a rigorous
result must use that actual map or add deterministic bounds for trigonometric
evaluation, complex arithmetic, and deviation from the ideal unit circle.

### 6.4 Deterministic floating-point envelopes

Probability should come from random transcript challenges and sampled query
locations, not from an unspoken independent-roundoff model. Binary64 effects
should enter the base theorem as deterministic intervals.

Any relation whose policy-3 defect saturated at `f64::MAX` must be recomputed
with a wider interval or make the theorem result unavailable. Treating the
saturated diagnostic itself as a mathematical upper bound would be unsound.

The current public RHS and matrix evaluator diagnostics are a useful start, but
a full calculation also needs bounds for:

- sumcheck endpoint sums and Bernstein evaluation;
- endpoint products;
- the initial matvec and batched-opening additions;
- equality-kernel evaluation;
- unit-circle fold arithmetic; and
- rowwise residual formation if the target includes frozen binary64
  semantics.

An offline reference calculator may replay binary64 inputs as exact dyadic
rationals to validate simpler runtime interval formulas.

### 6.5 Randomness and retry model

The clean sequential statistical model is:

1. the public statement and initial oracle root are fixed;
2. each prover round message is fixed before its corresponding fresh,
   unpredictable challenge;
3. each child fold root is fixed in the specified order, and all roots are
   fixed before query locations are sampled; and
4. the confidence statement charges exactly the attempts and branches allowed
   by the experiment.

The current noninteractive Fiat--Shamir flow lets a prover search over roots
and round messages after seeing the problem header. If one complete independent
attempt succeeds with probability `p`, then `T` such attempts succeed with
probability `1 - (1 - p)^T`; without independence, the general upper bound is
`min(1, T * p)`. A whole-transcript attempt budget alone does not account for
branching or grinding over candidate messages within each transcript.

This proposal does not seek an unrestricted cryptographic theorem, but it must
still state the statistical experiment. Practical choices are:

- issue fresh service challenges after each required commitment/message;
- invoke an explicit round-by-round Fiat--Shamir analysis with a random-oracle
  query and branching budget;
- bind and enforce both transcript-attempt and in-transcript work budgets; or
- present a sequential one-attempt guarantee explicitly without attributing it
  to the current noninteractive artifact.

## 7. Candidate protocol and report additions

The following are research candidates, not changes to policy 3:

1. Preserve ordered absolute-defect inputs to the bound calculator, either by
   retaining the certificate-bound proof for deterministic replay or by
   signing a theorem-specific per-round accumulator.
2. Report deterministic roundoff envelopes for every verifier operation used
   by the theorem.
3. Add sequential, independently challenged randomized-Hadamard
   residual-consistency sketches, retaining each interval-valued observation.
4. Split fold summaries by round and bind a useful oracle magnitude or energy
   cap.
5. Make the randomness/attempt model machine-readable.
6. Publish several confidence levels rather than one policy threshold.

A future optional result could have a shape such as:

```text
bound_status=available
bound_theorem=fast-a-posteriori-v1
target_semantics=exact-real-residual-of-committed-binary64-solution
confidence_level=9.50000000000000000e-1
squared_l2_claim=...
squared_l2_absolute_error_bound=...
squared_l2_interval_lower=...
squared_l2_interval_upper=...
residual_l2_interval_lower=...
residual_l2_interval_upper=...
randomness_model=sequential-fresh-challenges-one-attempt
```

This output remains neutral. An application may compare the interval with its
own quality requirement, but the proof protocol does not collapse it into a
generic `passes=true` field.

## 8. Research plan

### Phase 1: reference semantics and decomposition

- Freeze the target residual semantics.
- Implement a proof-independent, exhaustive reference calculation for small
  instances.
- Implement the deterministic final composition from `B_N` and `D`.
- Validate interval conversion for squared L2, L2, and RMS.

### Phase 2: one-sumcheck a posteriori lemma

- Prove a degree-two anti-concentration lemma for the exact challenge grid.
- Generalize it to ordered, heterogeneous absolute defects.
- Add deterministic binary64 evaluation envelopes.
- Compare the rigorous bound with exhaustive small-dimensional challenge
  enumeration.

### Phase 3: residual-consistency sketch design

- Quantify the conditioning of the current MLE point on representative sizes.
- Implement a reference hybrid Hadamard/MLE check with public endpoint
  `h_a^T A w(v)` and compare it with direct computation.
- Measure plain-Hadamard oversampling, including errors concentrated in one or
  a few Hadamard modes.
- Prototype challenge-derived randomized-Hadamard sign families that offer
  both a small-ball theorem and a succinct generator-owned public contraction.
- Compare predetermined sequential sample counts and anytime-valid stopping
  rules, retaining deterministic binary64 intervals for every observation.
- Retain complex-unit-circle and direct-row sketches as comparative designs.
- Compare verifier work, proof bytes, memory, and interval tightness.
- Select a sketch only after the benchmark and theorem constants are known.

### Phase 4: robust proximity lemma

- Derive exact without-replacement sampling bounds by fold round.
- Add and authenticate the selected magnitude/energy control.
- Prove distance to a valid packed oracle under bounded local perturbations and
  an allowed outlier fraction.
- Compose fold round errors without assuming independence.

### Phase 5: full composition and certificate design

- Allocate the confidence budget across sumchecks, batching, sketches, and
  folds.
- Construct `B_N`, `D`, and `B_squared` from verifier-owned data.
- Specify replay requirements and signed summaries.
- Decide whether the resulting wire changes justify a new profile, diagnostic
  policy, score, and certificate schema.

### Phase 6: empirical calibration

- Compare intervals with the exact backend and exhaustive direct computation.
- For each fixed instance, repeat fresh protocol randomness and measure
  empirical coverage at several predeclared confidence levels.
- Report variation across workload instances separately from coverage over
  protocol randomness.
- Record interval width as a function of dimension, scale separation, sparsity,
  and conditioning.
- Preserve reproducible seeds and report the seed on failures.

Calibration can find implementation mistakes and diagnose loose constants; it
cannot replace the coverage proof.

## 9. Evaluation workloads

The evaluation should emphasize numerical coverage rather than adversarial
cryptographic testing. Include:

- manufactured exact solutions;
- ordinary random sparse systems with reproducible seeds;
- zero and near-zero residuals;
- scale-separated matrix and RHS values;
- ill-conditioned and nearly singular systems;
- the all-zero calibration transcript from policy 3;
- the parity/checkerboard mode above as a conditioning calibration; and
- controlled injected local defects whose true contribution is known.

For every workload, record:

- claimed and directly computed squared L2;
- interval endpoints and width;
- whether the reference value is covered;
- confidence allocation by protocol component;
- maximum and RMS relative diagnostics;
- deterministic roundoff contribution;
- statistical/proximity contribution;
- proof size, verifier time, and verifier memory; and
- the number of permitted transcript attempts.

Performance measurements must use release builds and must compare identical
inputs with the current fast profile.

## 10. Success criteria

The research direction is ready for a protocol proposal only when:

1. the target residual semantics are unambiguous;
2. each probability is tied to an explicit randomness and retry model;
3. every binary64 contribution is bounded or explicitly excluded;
4. the full theorem consumes verifier-owned or signed/replayable provenance;
5. a proved coverage theorem establishes the declared rate, and independent
   empirical validation agrees with exhaustive/reference results;
6. interval width remains useful on representative dimensions and scales;
7. exact structural failures remain unchanged;
8. no approximate observation silently becomes a protocol acceptance gate;
9. changed transcript and certificate fields are versioned; and
10. the additional proof, time, and memory costs are measured.

A mathematically valid but consistently vacuous interval is a useful research
result, but not a reason to claim residual-quality assurance in production.

## 11. Non-goals

This proposal does not attempt to:

- turn the fast profile into the exact backend;
- claim zero knowledge;
- provide an unrestricted cryptographic soundness theorem for Fiat--Shamir;
- infer solution forward error without matrix conditioning information;
- hide the committed witness or residual;
- define one universal application quality threshold; or
- replace exact framing, transcript, and Merkle verification with statistics.

## 12. Open questions

1. Should the first target be exact-real `A X - b` or the frozen rowwise
   binary64 residual?
2. Which consistency sketch gives the best theorem/throughput tradeoff for the
   generator's sparse workloads?
3. Can the current unit-circle folding construction obtain a robust numerical
   proximity theorem, or should it be replaced?
4. What magnitude or energy bound is both useful and inexpensive to
   authenticate?
5. How many independent repetitions are needed before worst-case bounds become
   practically informative?
6. Which randomized-Hadamard sign family simultaneously gives useful
   distribution-free small-ball bounds and succinct public evaluation for the
   registered matrix generators?
7. Should services provide post-precommitment randomness, or is an explicit
   attempt budget sufficient for the intended deployment?
8. Should certificates carry per-round bound inputs, or rely on availability of
   the certificate-bound proof digest and deterministic replay?
9. Which confidence levels should be standardized for presentation without
   implying an application policy?

## 13. Suggested research narrative

A concise paper or blog-post progression is:

1. Local approximate relations are measurements, not Boolean verdicts.
2. Ordered transcript defects support backward robust-sumcheck analysis.
3. A deterministic decomposition converts committed-residual bounds into a
   final residual interval.
4. The current central MLE challenge exposes a concrete conditioning barrier.
5. Sequential randomized-Hadamard sketches separate statistically meaningful
   residual sampling from the MLE machinery used for succinct openings.
6. Sampled fold checks need magnitude control in addition to bad-fraction
   estimates.
7. Better sketches, deterministic roundoff envelopes, and a fixed randomness
   model turn provenance into an a posteriori certificate.

The honest conclusion should distinguish feasibility from present readiness:
the theorem has a clear shape, the sumcheck literature supports the core idea,
and the remaining obstacles are identifiable, but a useful bound for the
current complete fast path has not yet been established.

## 14. References

- Dor Bitan, Zachary DeStefano, Shafi Goldwasser, Yuval Ishai, Yael Tauman
  Kalai, and Justin Thaler, [Sum-Check Protocol for Approximate
  Computations](https://cs.nyu.edu/~zd2131/papers/25-2152.pdf), EUROCRYPT 2026,
  [DOI](https://doi.org/10.1007/978-3-032-25336-1_8).
- Carsten Lund, Lance Fortnow, Howard Karloff, and Noam Nisan,
  [Algebraic Methods for Interactive Proof
  Systems](https://doi.org/10.1145/146585.146605), JACM 1992.
- Anthony Carbery and James Wright,
  [Distributional and L-q Norm Inequalities for Polynomials over Convex
  Bodies](https://doi.org/10.4310/MRL.2001.v8.n3.a1), 2001.
- Eli Ben-Sasson, Iddo Bentov, Yinon Horesh, and Michael Riabzev,
  [Fast Reed-Solomon Interactive Oracle Proofs of
  Proximity](https://doi.org/10.4230/LIPIcs.ICALP.2018.14), ICALP 2018.
- Stephen M. Rump,
  [Verification Methods: Rigorous Results Using Floating-Point
  Arithmetic](https://doi.org/10.1017/S096249291000005X), Acta Numerica 2010.
- Ian Waudby-Smith and Aaditya Ramdas,
  [Confidence Sequences for Sampling Without
  Replacement](https://papers.nips.cc/paper/2020/hash/e96c7de8f6390b1e6c71556e4e0a4959-Abstract.html),
  NeurIPS 2020.

The normative current behavior remains in [the protocol
specification](../docs/protocol.md) and [architecture
documentation](../docs/architecture.md).
