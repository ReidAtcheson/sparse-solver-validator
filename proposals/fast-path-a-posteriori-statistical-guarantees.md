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
For the current real profile, `A_2(alpha_i)` is a degree-two
anti-concentration factor for the actual challenge distribution satisfying,
for every real degree-two polynomial `p` fixed before `U` is sampled,

```text
Pr_U[abs(p(0) + p(1)) > A_2(alpha_i) * abs(p(U))] <= alpha_i.
```

In an adaptive sumcheck this statement is applied conditionally on the
transcript prefix and prover round message fixed before that round's challenge.

A complex-circle successor needs the analogous statement for a complex error
polynomial, complex modulus, and its exact full-circle, half-arc, or finite-grid
distribution. It receives a separately derived factor `A_2_complex`; it cannot
inherit the current real-grid factor merely from the shared polynomial degree.
The backward recurrence has the same shape once complex interval arithmetic
supplies the defect and roundoff radii.

This is the located, heterogeneous-defect analogue of applying one fixed
tolerance to every approximate sumcheck check. A tight degree-two derivation is
preferable to importing a loose general-degree result. The analysis must also
cover:

- Bernstein-basis round messages;
- for the current profile, the exact 52-bit discrete real challenge
  distribution;
- for a successor, the exact canonical complex phase grid and component
  representation;
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
Delta_s = M * (-1)^popcount(s).
```

Its multilinear extension is

```text
Delta_tilde(u) = M * product_j(1 - 2*u_j).
```

Every current challenge coordinate is in `[1/4, 3/4)`, so

```text
abs(Delta_tilde(u)) <= M / n,
norm(Delta)          = M * sqrt(n).
```

Equivalently,

```text
abs(Delta_tilde(u)) / norm(Delta) <= n^(-3/2).
```

Thus a global inconsistency can appear smaller by a factor of at least
`n^(3/2)` at every permitted row point. This is a conditioning example, not a
cryptographic attack requirement. It shows that a dimension-independent,
useful `L2` bound cannot be derived from this single observation for arbitrary
signed errors.

The leading candidate for a distribution-free global residual bound is a
challenge-driven randomized-Hadamard or Rademacher sketch. Complex circle
geometry is a separate leading candidate for the fixed-degree sumcheck
challenges and perhaps the recursive commitment folds. The two directions are
algebraically related, but they solve different statistical problems. Direct
random row checks and an explicit incoherence or spectral-shape condition
remain alternatives to evaluate. Repeating the current central MLE sample
reduces a tail probability but does not remove its dimension-dependent
conditioning.

#### 6.2.1 Randomized Hadamard and Rademacher residual sketches

Let `N = 2^m` be the padded dimension and, for a challenged column index
`a in {0,1}^m`, define the unnormalized Hadamard column

```text
h_a(i) = (-1)^<a,i>.
```

For the global consistency error

```text
Delta = A X - b - R,
```

one supervised observation is the ordinary linear sketch

```text
z_a = h_a^T Delta.
```

Uniform Hadamard columns satisfy

```text
E_a[h_a h_a^T] = I,
E_a[abs(h_a^T Delta)^2] = norm(Delta)^2.
```

This is the useful linear-algebra interpretation missing from the current row
MLE observation. The current equality-polynomial vector is a positive
Kronecker-product averaging vector; `h_a` is a signed Kronecker-product vector
from an orthogonal basis.

Hadamard and Kronecker structure are not alternatives. With the normalized
one-bit matrix

```text
H_2 = (1 / sqrt(2)) * [[1, 1], [1, -1]],
```

the normalized Walsh--Hadamard transform is `H_N = H_2^(tensor m)`. An MLE
row is `tensor_j [1 - u_j, u_j]`, while
`h_a / sqrt(N) = tensor_j ([1, (-1)^a_j] / sqrt(2))`, and the complex-torus row
below is `tensor_j ([1, z_j] / sqrt(2))`. The relevant improvement is therefore
orthogonal or isotropic local factors, not removal of a tensor product.

The algebraically least disruptive plain-Hadamard design changes the row
linear form of the consistency check while retaining the product and
linear-opening sumcheck machinery. It is not merely a substitution in the
current transcript schedule: the residual-norm sumcheck still ends at
`R_tilde(u)` and must keep that packed-oracle opening. Each new consistency
sketch additionally needs an authenticated `h_a^T R`, its own matvec
transcript and column point `v_a`, and an authenticated `X_tilde(v_a)`. If
several claims are batched, the batching challenges must be fresh after the
claims are fixed and their anti-cancellation failure must receive an explicit
confidence allocation. For one sketch, the prover forms

```text
c = A^T h_a
```

and proves

```text
c^T X = h_a^T A X.
```

The terminal public/committed factors are then

```text
(h_a^T A w(v_a)) * (w(v_a)^T X),
```

where `w(v_a)_j = eq_j(v_a)`. The generator-owned public evaluator would need
succinct, supervised operations for

```text
h_a^T b
h_a^T A w(v_a).
```

The packed-oracle opening must also bind `h_a^T R`. For a plain Hadamard row,
the opening-weight endpoint remains bit-separable. For a randomized sign row,
succinct evaluation of that opening weight is an additional instance of the
same contraction problem discussed below; merely retaining the existing
opening transcript does not authenticate a new arbitrary linear form.

For the registered periodic tridiagonal family, this appears compatible with
work proportional to the generator period and `log N`: both `h_a` and `w(v_a)`
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
sumcheck. The hybrid `h_a^T A w(v_a)` endpoint is therefore the preferred first
prototype.

Sampling columns from one fixed Hadamard basis has a serious worst-case
limitation. Although the squared observation is unbiased, a nonzero `Delta` may be
concentrated in one Hadamard mode. Sampling `k` distinct columns then misses it
with probability `1 - k / N`. Consequently, a small number of plain Hadamard
columns cannot give a useful distribution-free upper confidence bound.

The primary design to analyze should therefore randomize the basis before
sampling it. There are two statistically and operationally distinct versions.
With a fresh challenge-derived sign diagonal `S_t` for every observation,

```text
Z_t = h_(a_t)^T S_t Delta.
```

For fixed `a_t`, multiplication by `h_(a_t)` only flips deterministic signs.
If the diagonal entries of `S_t` are independent Rademacher signs, this is just
a Rademacher projection and `a_t` is distributionally redundant. The proof
must fix `a_t` independently of the sign seed; the simplest independent-sketch
design sets `a_t = 0`. A genuine subsampled randomized Hadamard transform
instead draws one sign diagonal `S`,
forms `H_N S Delta`, and samples several of its coordinates. Because `H_N` is
normalized, the observation on the same scale as `Z_t` is

```text
Z_a = sqrt(N) * (H_N S Delta)_a = h_a^T S Delta.
```

Equivalently, a calculator using the raw normalized coordinate must retain the
factor `N` in its squared-magnitude normalization. This shared-diagonal
version can amortize one fast transform across observations, but the
observations share
`S` and are dependent; its theorem must use an SRHT row-sampling analysis
rather than treating the coordinates as independent sketches.

Full independence within one Rademacher sketch is more than the first
small-ball calculation needs. Let the signs `epsilon_t(i)` be four-wise
independent within sketch `t`, independent between sketches, and sampled after
`Delta` is fixed. For real `Delta`,

```text
Z_t = sum_i epsilon_t(i) * Delta_i,
E[Z_t^2] = norm(Delta)^2,
E[Z_t^4] = 3 * norm(Delta)^4 - 2 * sum_i Delta_i^4
         <= 3 * norm(Delta)^4.
```

Paley--Zygmund applied to `Z_t^2` gives, for `0 < theta < 1`,

```text
Pr[abs(Z_t) >= sqrt(theta) * norm(Delta)]
    >= (1 - theta)^2 / 3.
```

One explicit reference family exists at the required independence level for
`m >= 1`; the scalar case `N = 1` is handled directly. Identify the
`N = 2^m` indices with `GF(2^m)`, sample a uniform cubic
`P_t(x) = c_0 + c_1*x + c_2*x^2 + c_3*x^3`, and set

```text
epsilon_t(i) = (-1)^Trace(P_t(i)).
```

Four distinct evaluations of a uniform cubic are independent uniform field
elements, so their trace bits are four-wise independent; its four field
coefficients require a `4*m`-bit seed. Any protocol use must freeze the field
basis, index map, and trace convention. This supplies a proof-friendly randomness
baseline, not a succinct contraction algorithm. Replacing it with signs
expanded by a cryptographic hash changes the theorem to a stated
random-oracle or computational assumption.

The fourth-moment calculation, Paley--Zygmund step, and
polynomial-interpolation proof of four-wise independence are intended as
self-contained lemmas in a successor proof. A citation or empirical test is
not a substitute for writing those short arguments against the exact
protocol-defined family.

Let `E_interval` be the simultaneous event that the future robust
matvec/opening/proximity analyses produce centers `Z_hat_t` and deterministic
radii `e_t` satisfying `abs(Z_t - Z_hat_t) <= e_t` for every repetition. For a
prespecified count `k`, the union bound gives

```text
Pr[norm(Delta) > max_t(abs(Z_hat_t) + e_t) / sqrt(theta)]
    <= (1 - (1 - theta)^2 / 3)^k + Pr[not E_interval].
```

The interval event is not supplied by current verifier replay alone. Its
failure probability must compose the robust sumcheck, batching,
packed-opening, and decoder/proximity allocations. The displayed union bound
does not assume those events are independent of the sketch values.

This is deliberately a loose first target, but it is already concrete. With
`theta = 1/4` and `k = 15`, the displayed upper bound is `(13/16)^15`, about
`0.0444`, before the interval-event allocation. Equivalently, multiplying the
maximum interval magnitude by two gives a valid upper confidence bound at
greater than 95% confidence for the sketch event; it does not claim that the
reported upper endpoint is within a factor two of `norm(Delta)`. Tighter constants
or estimators are welcome, but this calculation is a useful reference test
that uses only four moments and does not mistake unbiasedness for an
upper-confidence theorem.

In the binary64 profile, all data determining `Delta` must be fixed before these
sketch challenges. The independent-Rademacher branch needs a fresh,
conditionally independent seed for every repetition in the sequential model
of Section 6.5. The SRHT branch instead needs one post-commitment sign diagonal
and the specified dependent row-sampling challenges. In either branch, the
repetition count and confidence allocation must be fixed before observing the
sketches, or be covered by an anytime-valid rule. Stopping after favorable
observations and reporting a fixed-sample confidence level is invalid.
Individual sketch observations and their deterministic binary64 intervals
must remain available to the bound calculator; oversampling reduces
statistical uncertainty, not roundoff.

An arbitrary independent or four-wise-independent sign diagonal destroys the
simple bit-separable public contraction. A short seed makes the signs
reproducible but does not by itself make `epsilon_t^T A w(v_t)` or
`epsilon_t^T b` succinctly evaluable. The packed-oracle bridge must likewise
authenticate `epsilon_t^T R`. The design therefore needs a
challenge-derived sign family with both the required moment or small-ball
property and a generator-owned succinct contraction algorithm. The theorem
must specify how the signs are generated, their exact independence, and
whether a short seed is interpreted through a cryptographic random oracle or
an explicit bounded-independence family. If no such family has a succinct
contraction, the distribution-free Rademacher theorem still exists with an
`O(N)` verifier or an additional authenticated auxiliary proof. If the design
instead insists on the current succinct bit-separable contraction, plain
Hadamard oversampling can support only a theorem with an explicit
spectral-spread assumption, not the desired distribution-free result.

The residual-consistency theorem must derive a simultaneous upper bound on
`norm(Delta)` from the interval-valued observations `{Z_t}`. It must cover the
chosen sketch's lower-tail or small-ball probability, the number of sequential
samples, sampling with or without replacement, adaptive transcript messages,
and deterministic errors in both public bilinear evaluation and authenticated
linear openings. Merely citing the unbiased second moment is insufficient.

#### 6.2.2 Affine MLE sampling on the Boolean-diameter circle

A complex challenge does not require abandoning the current affine MLE.
Naively putting the affine coordinate itself on the origin-centered unit
circle is poorly conditioned. For

```text
f_tilde(u) = sum_s f_s product_j (1 - u_j)^(1 - s_j) u_j^s_j,
```

setting `abs(u_j) = 1` leaves the one-coordinate weight vector
`[1 - u_j, u_j]`, whose squared norm is

```text
abs(1 - u_j)^2 + abs(u_j)^2 = 3 - 2*cos(theta_j).
```

This ranges from `1` to `5`, so its tensor-product norm can vary
exponentially with the number of variables. This rules out the wrong circle,
not complex affine coordinates themselves.

Instead let `z_j` be a unit phase and set

```text
u_j = (1 - z_j) / 2,
abs(z_j) = 1.
```

Then `u_j` lies on the circle `abs(u_j - 1/2) = 1/2`, whose diameter has the
Boolean points `0` and `1` as endpoints, and

```text
[1 - u_j, u_j] = [1 + z_j, 1 - z_j] / 2,
abs(1 - u_j)^2 + abs(u_j)^2 = 1.
```

Thus every tensor-product affine row has unit Euclidean norm. More strongly,
let

```text
H_2 = (1 / sqrt(2)) * [[1, 1], [1, -1]],
H_N = H_2^(tensor m),
q_z(s) = (1 / sqrt(N)) * product_j z_j^s_j,
w_u(s) = product_j (1 - u_j)^(1 - s_j) u_j^s_j.
```

Here `*` in covariance expressions denotes conjugate transpose. Polynomial
and application-sumcheck evaluations below use the bilinear transpose `T`.
Conjugating every phase makes `q_z^T` and `q_z^*` identically distributed on
the full circle or a conjugation-symmetric grid, but not on one oriented
half-arc.

With matching bit order,

```text
w_u = H_N q_z.
```

The affine diameter-circle sketch is therefore a normalized Hadamard rotation
of the homogeneous torus sketch below. It is not a non-Kronecker alternative:
both sides are tensor products, related by a fixed orthogonal basis change. If
the phases are independent across coordinates and uniform on the full circle,
or are sampled independently from a finite grid with the same first character
moment, then

```text
E_z[w_u w_u^*] = I / N,
E_z[abs(sum_s f_s w_u(s))^2] = norm(f)^2 / N.
```

These are ideal linear-algebra identities, not binary64 bit-equivalence claims
between a fast Hadamard transform and recursive MLE folds. Their operation
orders differ and require separate deterministic roundoff envelopes.

Any bound calculator must retain this normalization. It should work with
`N * abs(f_tilde(u))^2`, where `N` is an exact power-of-two scale, rather than
silently comparing one normalized observation directly with `norm(f)^2`.

This affine realization may be the least disruptive complex prototype. A
hybrid application sumcheck can retain the real column point `v` and terminate
at

```text
A_tilde(u(z), v) * X_tilde(v),
```

with public `b_tilde(u(z))` and `A_tilde(u(z), v)` evaluations and a complex
affine opening of `R_tilde(u(z))`. The generator-owned evaluator is already
expressed through scalar addition, subtraction, multiplication, and the local
weights `[1 - u_j, u_j]`. A tracked-complex interpreter can therefore reuse
the generator operation plan in principle. The current binary64 facade still
accepts only real coordinates in `[0,1]`, and the transcript, sumcheck, and
roundoff types are real-valued, so this remains a versioned protocol and API
change. Reference equivalence must confirm both the complex operation order
and the absence of a hidden `O(N)` scan.

The phrase *half-circle* needs an explicit measure. If `z = exp(i*theta)` is
sampled only for `theta in [0, pi]`, then `E[z] = 2*i/pi`, not zero. Tensoring
the resulting affine rows can therefore reintroduce exponentially worsening
conditioning, and the literal half-arc must not be advertised as an isotropic
global `L2` sketch. A projective half-circle can preserve the desired
distribution: sample `theta in [0, pi)` but use relative phase
`z = exp(2*i*theta)`, which covers the full circle. Equivalently, symmetrize
the phase distribution explicitly.

The literal diameter half-arc remains interesting for one fixed degree-two
sumcheck round. For the current Bernstein message

```text
g(t) = b_0*(1 - t)^2 + 2*b_1*t*(1 - t) + b_2*t^2,
```

substitution of `t = (1 - z) / 2` gives

```text
g(t(z)) = c_0 + c_1*z + c_2*z^2,
c_0 = (b_0 + 2*b_1 + b_2) / 4,
c_1 = (b_0 - b_2) / 2,
c_2 = (b_0 - 2*b_1 + b_2) / 4.
```

The Boolean endpoint sum `L = b_0 + b_2` obeys `L = 2*(c_0 + c_2)`. On the
full circle, orthogonality of degrees zero through two gives

```text
E_z[abs(g(t(z)))^2]
    = abs(c_0)^2 + abs(c_1)^2 + abs(c_2)^2
    >= abs(L)^2 / 8.
```

In the robust-sumcheck proof, this calculation applies to the relevant error
polynomial fixed by the transcript prefix before `z` is sampled, not to a
legitimate received round polynomial merely because its endpoint sum is
large. The observed round defect and deterministic endpoint roundoff must be
subtracted or enclosed when identifying that error polynomial's `L`.

The same sharp energy lower bound holds on the uniform oriented half-arc from
`z = +1` to `z = -1`, even though that arc is not an isotropic tensor sketch.
This is promising for a degree-two anti-concentration lemma that avoids
extrapolating from `[1/4,3/4)` to the Boolean endpoints. Equal energy lower
bounds do not imply equal small-ball constants: the half-arc can be
quantitatively worse and needs its own proof.

For a finite phase grid, roots of unity of order at least three reproduce the
full-circle second moment of a degree-two polynomial, while order at least five
also avoids aliasing in its degree-four moment. An eight-root grid is a natural
radix-two prototype for exhaustive analysis, not a settled protocol choice.
The four-root grid `{1, i, -1, -i}` and its diameter-circle affine points are
exact dyadic binary64 values, but two challenge bits per round and the ability
of a quadratic to vanish at two grid points make it a calibration grid rather
than an adequate adversarial design. The non-axis roots of an eight-root grid
are not exact binary64 unit points, so the transcript should select a canonical
phase index under a frozen component-generation rule. The theorem must enclose
the actual stored components or their deviation from the ideal roots; it must
not rely on platform `sin` and `cos` behavior. A finite-grid small-ball theorem,
not just moment matching, remains required.

#### 6.2.3 Homogeneous multilinear sampling on the complex unit torus

The same unitary geometry can be expressed without the affine constraint
`alpha_j + beta_j = 1` through the homogeneous multilinear extension

```text
F_f((alpha_1,beta_1),...,(alpha_m,beta_m))
  = sum_s f_s
      product_(j:s_j=0) alpha_j
      product_(j:s_j=1) beta_j.
```

The ordinary MLE is the affine slice

```text
(alpha_j, beta_j) = (1 - u_j, u_j),
```

and the Boolean values remain the coordinate-axis points

```text
0 -> (1,0)
1 -> (0,1).
```

The balanced complex unit equator is

```text
(alpha_j, beta_j) = (1, z_j) / sqrt(2),
abs(z_j) = 1.
```

For `N = 2^m`, this gives

```text
F_f(z) = (1 / sqrt(N)) * sum_s f_s product_j z_j^s_j.
```

For independent uniform phases, the characters are orthogonal and

```text
E_z[abs(F_f(z))^2] = norm(f)^2 / N.
```

This is a continuous unit-modulus Kronecker sketch and a multivariate Fourier
polynomial on the torus. The Hadamard sketch is its discrete
`z_j in {-1,+1}` relative. The affine diameter-circle evaluation and this
homogeneous evaluation are related by `H_N`; they are not equal observations
on the same untransformed table.

One direct homogeneous residual observation is

```text
q_z^T (A X - b - R).
```

A hybrid application sumcheck could retain the existing column MLE point `v`
and terminate at

```text
(q_z^T A w(v)) * (w(v)^T X).
```

It would require generator-owned operations for `q_z^T b` and
`q_z^T A w(v)` and an authenticated opening of `q_z^T R`. The phase vector is
bit-separable, so the current carry automata may admit such operations, but the
affine realization above is the preferred first prototype because it can
reuse the existing public-MLE plan directly.

For the Bernstein coefficients above, define the homogeneous lift

```text
G(alpha, beta) = b_0*alpha^2 + 2*b_1*alpha*beta + b_2*beta^2.
```

The homogeneous geometry can fold each of the two factor tables in one
product-sumcheck round by

```text
(f_0 + z*f_1) / sqrt(2)
```

and evaluate the resulting round claim at `G(1,z)/2`. This yields the same
`abs(b_0 + b_2)^2 / 8` endpoint-energy lower bound as the affine
diameter-circle formulation, but uses a different opening/fold functional
(equivalently, a Hadamard-rotated message when comparing the two observations)
and an explicit irrational normalization in binary64. It does not by itself
require precommitting `H_N W`.

Neither homogeneous torus sampling nor its affine Hadamard rotation supplies
a distribution-free global norm theorem from a constant number of samples.
For the explicit table `f_s = 1`, the unnormalized torus observation is

```text
Y(z) = sum_s product_j z_j^s_j = product_j (1 + z_j),
norm(f)^2 = N,
E[abs(Y)^2] = N,
E[abs(Y)^4] = 6^m,
E[abs(Y)^4] / E[abs(Y)^2]^2 = (3/2)^m.
```

There is also a direct lower-tail obstruction. Since
`E[abs(1 + z_j)] = 4/pi`, Markov's inequality gives, for every fixed `c > 0`,

```text
Pr[abs(Y) >= c * norm(f)]
    <= (1 / c) * (2*sqrt(2)/pi)^m.
```

A finite even-order root grid does not cure this example. It contains
`z_j = -1`, so `Y` is exactly zero whenever any coordinate hits that phase,
with probability `1 - (1 - 1/K)^m` on a uniform `K`-root grid.

The probability of seeing even a fixed fraction of the norm therefore decays
exponentially with `m`; a constant number of samples cannot support the
proposed dimension-independent small-ball or sample-maximum upper bound in the
worst case. This calculation is not a minimax impossibility theorem for every
estimator allowed to use the sampled phase vectors. Because `H_N` is a
bijective isometry, the affine diameter-circle family inherits the same
small-ball limitation after a fixed rotation of this table.

This does not diminish the complex geometry's promise for one degree-two
round, numerical folding, or workload-conditional residual statements. It
does mean that Parseval must not be presented as the global residual theorem.
Any such theorem needs extra challenge-derived randomization, sample counts
that reflect a proved dimension-dependent small-ball bound, or an explicit
shape assumption.

These constructions are adjacent to, but distinct from, the current
unit-circle commitment code. The current code treats the bit-reversed Boolean
table as univariate monomial coefficients, evaluates at roots of unity, and
then folds source coefficients using real affine weights `[1 - r,r]`. The
affine diameter-circle application can reuse the public MLE operation plan,
but changing the application sumchecks or recursive folds to complex
challenges remains a protocol redesign. Every stopping rule and confidence
allocation must still be prespecified or anytime-valid.

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

An affine diameter-circle source-table fold instead has one-coordinate norm
`1`. Pairing the source folds for phases `z` and `-z` gives the ideal two-output
map

```text
B_z = (1 / 2) * [[1 + z, 1 - z], [1 - z, 1 + z]],
```

which is unitary when `abs(z) = 1`. The rate-one-half committed-evaluation map
retains only one child and carries the even/odd extraction's Parseval scale. If
the source butterfly is realized by the coefficient-aligned oracle fold, its
ideal operator norm in the proposal's unnormalized evaluation-space convention
is therefore `1 / sqrt(2)`, not `1`. Establishing that alignment with the
current paired-oracle map is a prototype obligation. Compared with the current
upper bound `sqrt(5) / 4`, the circle fold remains contractive but damps local
defects less strongly. The robust proximity prototype must compare both
backward-error recurrences; "unitary" at the full source-butterfly level is not
automatically a tighter committed-oracle numerical bound.

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
- canonical complex phase generation, complex sumcheck arithmetic, and the
  exact power-of-two normalization used by any circle sketch;
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
3. Add sequential, independently seeded Rademacher sketches, or a separately
   analyzed shared-diagonal SRHT, retaining each interval-valued observation.
4. Prototype versioned affine diameter-circle challenges for the degree-two
   sumchecks and perhaps recursive folds; do not treat their Parseval identity
   as the global residual theorem.
5. Split fold summaries by round and bind a useful oracle magnitude or energy
   cap.
6. Make the randomness/attempt model machine-readable.
7. Publish several confidence levels rather than one policy threshold.

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
residual_sketch_family=four-wise-rademacher-v1
residual_sketch_repetitions=15
residual_sketch_theta=2.50000000000000000e-1
residual_sketch_seed_family=gf2m-trace-cubic-v1
sumcheck_challenge_geometry=affine-diameter-circle-v1
sumcheck_phase_grid=...
randomness_model=sequential-fresh-challenges-one-attempt
transcript_attempt_budget=1
in_transcript_work_budget=...
```

This output remains neutral. An application may compare the interval with its
own quality requirement, but the proof protocol does not collapse it into a
generic `passes=true` field. A frozen `bound_theorem` may make some of these
fields redundant, but the certificate or theorem registry must expose the
same choices unambiguously.

## 8. Research plan

### Phase 1: reference semantics and decomposition

- Freeze the target residual semantics.
- Implement a proof-independent, exhaustive reference calculation for small
  instances.
- Implement the deterministic final composition from `B_N` and `D`.
- Validate interval conversion for squared L2, L2, and RMS.

### Phase 2: one-sumcheck a posteriori lemma

- Prove a degree-two anti-concentration lemma for the exact challenge grid.
- Compare the current real grid with the full affine diameter circle, the
  oriented diameter half-arc, and canonical finite phase grids. Exhaustively
  enumerate four- and eight-root prototypes while keeping their different
  grinding probabilities explicit.
- Apply the circle calculation to the conditionally fixed error polynomial,
  including the located round defect, rather than to the received round
  polynomial in isolation.
- Generalize it to ordered, heterogeneous absolute defects.
- Add deterministic binary64 and complex evaluation envelopes.
- Compare the rigorous bound with exhaustive small-dimensional challenge
  enumeration.

### Phase 3: residual-consistency sketch design

- Quantify the conditioning of the current MLE point on representative sizes.
- Implement a reference hybrid Hadamard/MLE check with public endpoint
  `h_a^T A w(v)` and compare it with direct computation.
- Measure plain-Hadamard oversampling, including errors concentrated in one or
  a few Hadamard modes.
- Implement the four-wise-independent Rademacher reference theorem and verify
  its moment identities and confidence coverage exhaustively for small `N`.
- Compare fresh-diagonal Rademacher repetitions with a shared-diagonal SRHT;
  do not apply independent-sample confidence multiplication to the latter.
- Prototype challenge-derived sign families that offer both the proved moment
  property and succinct generator and packed-opening contractions. Record an
  `O(N)` contraction as a failed succinctness result rather than hiding it.
- Implement affine diameter-circle evaluations through a tracked-complex
  version of the existing generator plan and compare them with an exhaustive
  reference. Verify `w_u = H_N q_z` and the ideal Parseval identities on small
  instances while testing the actual binary64 operation order separately.
- Retain direct homogeneous unit-torus challenges with endpoint
  `q_z^T A w(v)` as a comparative committed-basis design.
- Exercise the all-ones torus counterexample and measure its lower tail as
  dimension grows; Parseval agreement alone is not a success criterion.
- Compare predetermined sequential sample counts and anytime-valid stopping
  rules, retaining deterministic binary64 intervals for every observation.
- Retain direct-row sketches as a comparative design.
- Compare verifier work, proof bytes, memory, and interval tightness.
- Select the global residual sketch and, separately, the sumcheck/fold
  challenge geometry only after their respective benchmark and theorem
  constants are known.

### Phase 4: robust proximity lemma

- Derive exact without-replacement sampling bounds by fold round.
- Add and authenticate the selected magnitude/energy control.
- Prove distance to a valid packed oracle under bounded local perturbations and
  an allowed outlier fraction.
- Determine whether the affine source butterfly `B_z` is compatible with the
  coefficient-aligned committed-oracle fold. Compare its `1/sqrt(2)` ideal
  evaluation-space recurrence with the current contractive recurrence,
  including canonical phase error and complex binary64 roundoff.
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
- the parity/checkerboard mode above as a conditioning calibration;
- coordinate spikes and isolated non-parity Hadamard modes;
- the all-ones homogeneous-torus table, its affine Hadamard rotation, and
  random dense errors as lower-tail calibrations; and
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
5. How many fresh Rademacher repetitions are needed before worst-case bounds
   become practically informative, and how many dependent sampled rows does a
   shared-diagonal SRHT require under its separate theorem?
6. Which Rademacher sign family simultaneously gives useful distribution-free
   small-ball bounds and succinct public and packed-opening evaluation for the
   registered matrix generators?
7. Is fresh-diagonal Rademacher repetition preferable to a shared-diagonal
   SRHT after prover amortization, verifier contraction cost, and dependent
   sampling constants are included?
8. Does the affine Boolean-diameter circle give a useful degree-two
   anti-concentration constant on a canonical finite grid? Is a literal
   oriented half-arc useful enough to justify its weaker tensor geometry?
9. Should the first complex prototype preserve affine MLE coordinates, or use
   new homogeneous openings? If the latter, should it fold the existing
   committed source directly or explicitly commit a transformed basis?
10. Can application sumchecks and recursive commitment folds share one complex
    challenge geometry without unacceptable proof size or binary64 error
    growth?
11. Do homogeneous unit-torus residual challenges give useful
    dimension-dependent bounds under a meaningful shape condition, despite
    the all-ones worst-case lower tail?
12. Should services provide post-precommitment randomness, or is an explicit
   attempt budget sufficient for the intended deployment?
13. Should certificates carry per-round bound inputs, or rely on availability
    of the certificate-bound proof digest and deterministic replay?
14. Which confidence levels should be standardized for presentation without
    implying an application policy?

## 13. Suggested research narrative

A concise paper or blog-post progression is:

1. Local approximate relations are measurements, not Boolean verdicts.
2. Ordered transcript defects support backward robust-sumcheck analysis.
3. A deterministic decomposition converts committed-residual bounds into a
   final residual interval.
4. The current central MLE challenge exposes a concrete conditioning barrier.
5. Fresh Rademacher sketches or a separately analyzed shared-diagonal SRHT
   supply a concrete small-ball route for global residual sampling, provided
   their public and committed-vector contractions remain succinct.
6. Affine diameter-circle MLE challenges are Hadamard-rotated torus challenges;
   they offer unit-norm folds and fixed-degree anti-concentration without
   making Parseval a global norm theorem.
7. Sampled fold checks need magnitude control in addition to bad-fraction
   estimates.
8. Better sketches, deterministic roundoff envelopes, and a fixed randomness
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
- Joel A. Tropp,
  [Improved Analysis of the Subsampled Randomized Hadamard
  Transform](https://doi.org/10.1142/S1793536911000787), Advances in Adaptive
  Data Analysis 2011, [preprint](https://arxiv.org/abs/1011.1595).
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
