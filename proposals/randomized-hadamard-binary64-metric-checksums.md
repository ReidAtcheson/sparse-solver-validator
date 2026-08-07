# Randomized-Hadamard metric checksums for binary64 validation

Status: speculative research proposal; non-normative.

Scope: a possible commitment and proximity component for a future binary64
metric protocol. Nothing in this document changes a registered protocol,
certificate, validator decision, diagnostic policy, or service path.

This proposal investigates a systematic randomized-Hadamard row code and,
more importantly, the transcript ordering needed for its spreading theorem to
apply to a malicious discrepancy. It deliberately includes a public-transform
attack. The accompanying code is a cost and falsification surrogate, not a
proof system.

It should be read with:

- [the one-pass residual-witness proposal](one-pass-binary64-residual-witness-certificates.md),
  which describes the sparse relation and final residual interval;
- [the a-posteriori fast-path proposal](fast-path-a-posteriori-statistical-guarantees.md),
  which describes metric-valued approximate sumcheck; and
- [the current protocol](../docs/protocol.md), which remains normative.

## 1. Decision summary

Investigate two related constructions without conflating their guarantees:

1. A public systematic frame

   ```text
   Enc_D(u) = [u || H D u]
   ```

   gives a cheap, energy-preserving throughput baseline, but one public
   Walsh--Hadamard basis does not spread every adaptively selected alteration.

2. A Hadamard transform sampled only after the alleged alteration is fixed has
   the desired randomized spreading property. Authenticating those fresh
   checksums against an earlier source commitment is the central protocol gap.

The research objective is a staged metric transcript in which every alleged
discrepancy is fixed before the randomness used to measure it. A successful
argument need not reject every nonzero discrepancy. It should prove that a
small checksum-energy observation permits only a small change in the final
squared-residual metric.

The initial implementation measures the first construction and demonstrates
why it is not already the second. It does not register a `ProofProtocol`.

## 2. Why randomized Hadamard is attractive

Let `H` be the normalized `C x C` Walsh--Hadamard matrix and let `D` be a
diagonal matrix of independent signs. For a fixed vector `Delta` independent
of `D`, each coordinate

```text
(H D Delta)_j
```

is a normalized Rademacher sum. The transform preserves energy,

```text
norm(H D Delta)_2 = norm(Delta)_2,
```

and with high probability prevents one coordinate from retaining most of that
energy. This is the preconditioning role used by fast
Johnson--Lindenstrauss transforms.

The transform is also operationally attractive here:

- a length-`C` transform uses `C log2(C)` additions and subtractions;
- the same transform is applied independently to every matrix row;
- no trigonometric tables or complex arithmetic are required;
- an unnormalized transform uses only signed additions;
- for the measured `C = 4096`, normalization by `1 / 64` is exact binary64;
  and
- linear row combinations commute with the transform in exact real
  arithmetic.

This is not a linear-time code in the strict asymptotic sense. Encoding an
`R x C` matrix costs `O(R C log C) = O(N log C)`. The row-local working sets
and small butterfly constant may nevertheless make it substantially cheaper
than the current oversampled global complex transforms. That claim is decided
by release measurements, not asymptotic notation alone.

## 3. Public systematic construction

### 3.1 Layout and commitment

Pad the canonical binary64 message to `N = R C` and reshape it as

```text
U in F64^(R x C).
```

The canonical vector-to-matrix mapping, padding, sign seed, Hadamard ordering,
normalization, and floating-point operation order are transcript-bound. Apply
the same row transform to every row:

```text
P = U D H^T.
```

The implementation writes the systematic and parity matrices in column-major
form and commits the complete columns of

```text
M = [U || P]
```

under one BLAKE3 Merkle root. The first `C` encoded columns therefore bind the
exact canonical source bits. `D` is represented by a small public seed rather
than transmitted as `C` signs.

The prototype begins with full-rate parity. Subsampling Hadamard outputs saves
hashing and storage but discards deterministic energy preservation and makes
the adaptive analysis no easier. It should be considered only after a complete
full-frame statement exists.

### 3.2 Opening one MLE

Split the requested MLE point into row and column equality weights `alpha` and
`beta`. Then

```text
v = alpha^T U
y = v^T beta.
```

The prover supplies `v` and the claimed value `y`. Exact linearity predicts

```text
H D v = alpha^T P.
```

After `v` is fixed, the verifier derives `q` encoded-column indices. For each
index it authenticates the complete `R`-value column against the Merkle root
and compares its `alpha` combination with either:

- the corresponding systematic coordinate of `v`; or
- the corresponding coordinate of `H D v`.

The verifier may transform all of `v` in `O(C log C)` time, which is cheaper
than evaluating `q` dense Hadamard rows independently once `q > log2(C)`.

The naive opening contains approximately

```text
C + q R
```

binary64 values plus authentication paths. For `N = 2^20`, `R = 256`,
`C = 4096`, and `q = 16`, those two value terms are both 32 KiB.

### 3.3 Binary64 discrepancy

Even an honest prover generally observes

```text
d_j = (alpha^T P)_j - (H D v)_j != 0
```

because transform-then-combine and combine-then-transform use different
summation orders. The prototype records maximum and RMS absolute and relative
defects. A protocol must define the linear map over the exact dyadic values
represented by canonical binary64 and enclose implementation error separately.

Candidate arithmetic policies include:

- wider or compensated row-combination accumulators;
- exact superaccumulation for the signed dyadic transform;
- a frozen butterfly order with a deterministic forward-error enclosure; and
- outward-rounded intervals for non-dyadic MLE challenge weights.

Wider accumulation lowers the honest floor. It does not repair an adversarial
spreading failure.

## 4. The quantifier that controls soundness

Randomized-Hadamard spreading has the form

```text
for every fixed Delta:
    probability over fresh D that H D Delta is insufficiently spread
    is at most delta_spread.
```

It does not have the uniform form

```text
with high probability over public D:
    every later, adaptively chosen Delta is spread by H D.
```

For any fixed public `D`, an adversary can choose

```text
Delta = D H^T e_j,
```

which makes `H D Delta = e_j`. The systematic half is dense for this particular
example, so sampling both halves still sees many affected coordinates. A
balanced Walsh-subspace vector gives a stronger combined-frame example.

For `C = 4096`, choose a 64-coordinate Walsh subspace `S`, let `1_S` be its
normalized indicator, and after seeing `D` choose

```text
Delta = D 1_S.
```

Then:

```text
support(Delta)       = 64
support(H D Delta)   = 64
support([Delta | H D Delta]) = 128.
```

Only `128 / 8192 = 1/64` of the systematic-plus-parity coordinates expose this
alteration at the benchmark's half-natural-scale threshold. Sixteen uniform
queries miss all of them with probability about `0.777`.

Random signs do spread the same subspace vector when that vector is fixed
independently before `D`. The prototype runs both cases across independent
sign draws so that the distinction is executable rather than rhetorical.

## 5. Desired metric statement

Let

```text
v_star = alpha^T U
v_hat  = v_star + Delta.
```

For a transform sampled after `v_hat` is bound, let `Q` be a random set of
Hadamard checksum coordinates and define a sampled energy statistic such as

```text
T_Q = (C / |Q|) * sum_(j in Q) abs((H D Delta)_j)^2.
```

The target is a simultaneous or prespecified confidence statement

```text
norm(Delta)_2^2 <= B_hadamard(T_Q, roundoff, magnitude, alpha)
```

except with probability `alpha`. It may report a family of bounds at registered
confidence levels. It must account for sampling without replacement, binary64
enclosures, transcript retries, and any dependence among reused queries.

The resulting MLE error obeys

```text
abs(Delta^T beta) <= norm(Delta)_2 * norm(beta)_2.
```

This scalar bound then feeds the approximate-sumcheck calculator and ultimately
the squared-residual interval. There is no need to turn `T_Q` into one hidden
Boolean tolerance gate.

The theorem must control aggregate energy. Independent coordinate tolerances
would permit many individually small changes to accumulate into a large
alteration.

## 6. Staged transcript candidate

To use fixed-before-random spreading, the alleged combination must precede the
Hadamard seed:

```text
root_U
sumcheck prefix and row challenge alpha
commit(v_hat)
D = challenge(transcript)
fresh checksum material tied to U
checksum-energy observations
residual-bound composition.
```

The unresolved line is `fresh checksum material tied to U`. The Hadamard
checksums could not have been included under `root_U` because `D` did not yet
exist. Merely committing a new checksum matrix after `D` lets the prover commit
arbitrary values chosen to support `v_hat`.

Candidate ways to close the gap are:

1. **Recursive staged consistency.** Commit the fresh checksum matrix, then use
   a later challenge to reduce `P = U D H^T` to a smaller metric relation. The
   reduction must shrink; simply restating an equally large Hadamard relation
   recurses forever.

2. **Several precommitted frames.** Commit multiple independent fast frames,
   bind `v_hat`, and only then select which frame and coordinates to inspect.
   Since all frames are public before `v_hat`, the required statement is a
   uniform robust-frame property across the complete stack, not ordinary
   fixed-vector RHT concentration.

3. **Fast numerically erasure-robust frame.** Replace one `H D` with a cascade
   of randomized butterflies or transforms whose stacked systematic frame has
   a proved lower tail for every vector. Full spark is insufficient: very small
   coordinates and ill-conditioned erased subframes matter in binary64.

4. **Hybrid expander/Hadamard code.** Use a recursive sparse code to obtain
   uniform support expansion, then a fresh Hadamard layer only to flatten the
   already fixed remaining metric discrepancy.

5. **Interactive challenge.** A live verifier can keep the transform unknown
   until `v_hat` is fixed, but it still needs an authenticated linear query to
   `U`. Interactivity changes Fiat--Shamir retry behavior; it does not by itself
   create that authentication primitive.

Each option must state exactly which message is fixed before each challenge.
Transcript hashes, optional nonces, selective aborts, and proof retries are
part of the threat model.

## 7. Initial cost measurement

The accompanying release surrogate uses:

```text
N                  = 2^20 source values
R x C              = 256 x 4096
code               = [I || H D]
queries            = 16
threads            = 1
warmups/repetitions = 2 / 25
```

On the development machine it measured:

| Component | Median |
| --- | ---: |
| Hadamard encoding into committed layout | 7.757 ms |
| Systematic row-to-column transpose | 4.131 ms |
| Complete 16 MiB column/Merkle commitment | 17.067 ms |
| Encoded row combination | 1.060 ms |
| Combination Hadamard transform | 0.019 ms |
| Opening extraction | 0.080 ms |
| Defect scan | 0.038 ms |
| Total prover-side surrogate | 30.239 ms |
| Opening verification | 0.064 ms |

The 25 measured totals ranged from `26.491` to `33.389` ms. The naive opening
was `72,352` bytes, peak process RSS was `27,616` KiB, and the maximum honest
linearity defect was `1.39e-16`.

This cost is approximately:

- `0.99x` the earlier `30.491` ms half-bandwidth-1 factor-and-solve;
- `0.122x` the earlier `247.374` ms half-bandwidth-32 factor-and-solve;
- `0.019x` the `1.66--1.69` second complete chunked/unit-circle proof; and
- `1.81x` the `16.739` ms sparse-code commitment surrogate on the separate
  Brakedown-shaped research branch.

These cross-branch measurements share the same development machine but are not
one executable baseline. The Hadamard total is still a cost floor: it omits the
fresh-checksum authentication mechanism, relation sumchecks, final metric
composition, serialization, and retry handling.

The full parity block doubles source storage before tree overhead. The fused
row transform writes parity directly into committed column-major storage;
source transposition remains explicit and measured. A tiled canonical layout
may reduce that copy, but layout changes must not hide data movement from the
benchmark.

## 8. Query-count and escape-cost illustration

For the explicit public-`D` balanced-subspace attack, the measured `R = 256`
opening frontier is:

| Queries | Naive opening | Opening verification | Attack miss probability |
| ---: | ---: | ---: | ---: |
| 16 | 72,352 B | 0.061 ms | 0.7771 |
| 64 | 191,008 B | 0.240 ms | 0.3636 |
| 128 | 349,216 B | 0.504 ms | 0.1311 |
| 256 | 665,632 B | 1.141 ms | 0.01664 |

These numbers do not select a secure query count. They illustrate that this
particular attack can be made more expensive while retaining a sub-vector
artifact and cheap validation. A solve-relative attempt model must additionally
specify:

- whether a failed Fiat--Shamir attempt requires rebuilding and hashing the
  commitment;
- whether a cheap transcript nonce permits grinding without redoing the work;
- whether the attacker can amortize one encoded matrix across attempts;
- the solve cost used as the reference; and
- how this escape probability composes with all other protocol events.

No query count is justified until those costs and a worst-case metric tail
theorem are both available.

## 9. Falsification plan

Every candidate must test at least:

- one-coordinate source alterations;
- balanced Walsh-subspace indicators;
- vectors constructed from transform basis columns after public seeds;
- dense random alterations fixed before transform randomness;
- optimized vectors minimizing a selected encoded tail quantile;
- small discrepancies distributed across every coordinate;
- parity matrices inconsistent with their systematic source;
- row errors selected to cancel under the MLE row challenge;
- Fiat--Shamir grinding and selective aborts; and
- scale-separated, subnormal, overflow-adjacent, and non-finite arithmetic.

For multiple-frame candidates, attacks must optimize jointly across all public
frames. Showing that an attack tailored to one frame spreads under a second is
not a uniform theorem.

The primary diagnostic is a threshold-indexed tail curve, not only maximum
error or average random-vector behavior. Report source and parity contributions
separately so a dense systematic half cannot conceal a sparse parity weakness.

## 10. Research gates

Do not register a protocol until all of the following are satisfied:

1. A precise commit-before-challenge schedule fixes the relevant discrepancy
   before its spreading randomness.
2. Every post-challenge checksum is authenticated against the canonical source
   without a hidden dense fallback.
3. A robust metric theorem converts sampled observations into a global
   alteration bound for adaptive provers.
4. Honest binary64 discrepancy has a proved outward enclosure under the frozen
   arithmetic profile.
5. The MLE alteration bound composes with approximate sumcheck and the
   residual-witness interval.
6. Retry, grinding, and batch anti-cancellation probabilities are explicit.
7. End-to-end proof time remains suitably small relative to the measured solve,
   not merely relative to the old proof.
8. Proof bytes, prover RSS, and validator RSS remain within registered budgets.
9. Adversarial regression tests cover the public-transform constructions above.

Failure of one staged construction should identify which commitment or metric
role needs replacement. It should not be interpreted as evidence that
randomized spreading itself is unavailable.

## 11. References

- Nir Ailon and Bernard Chazelle, [The Fast Johnson--Lindenstrauss Transform
  and Approximate Nearest Neighbors](https://doi.org/10.1137/060673096).
- Alexander Golovnev, Jonathan Lee, Srinath Setty, Justin Thaler, and Riad
  Wahby, [Brakedown: Linear-time and Field-agnostic SNARKs for
  R1CS](https://eprint.iacr.org/2021/1043.pdf).
- Yang Wang, [Random Matrices and Erasure Robust
  Frames](https://arxiv.org/abs/1403.5969).
- Matthew Fickus and Dustin G. Mixon, [Numerically Erasure-Robust
  Frames](https://arxiv.org/abs/1202.4525).
