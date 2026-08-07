# Brakedown-inspired metric commitments for binary64 sparse validation

Status: speculative research proposal; non-normative.

Scope: a possible commitment successor for the binary64 metric path. Nothing
in this document changes a registered protocol, proof artifact, validator
decision, diagnostic policy, or certificate schema.

This proposal combines the matrix-code architecture of Brakedown with the
repository's approximate binary64 sumchecks and metric-valued transcripts. It
does **not** claim that Brakedown's finite-field proximity theorem applies to
floating-point arithmetic. The purpose is to preserve the architectural lesson
that a polynomial commitment can have a linear-time prover while deriving the
new numerical statements that such an architecture would need here.

It should be read with:

- [the one-pass residual-witness proposal](one-pass-binary64-residual-witness-certificates.md),
  which owns the sparse relation and final residual interval;
- [the a-posteriori fast-path proposal](fast-path-a-posteriori-statistical-guarantees.md),
  which owns approximate-sumcheck and global-defect questions; and
- the [current protocol specification](../docs/protocol.md), which remains
  normative.

## 1. Decision summary

Investigate a Brakedown-shaped commitment to a canonical binary64 message
`W`, initially either `x` or the residual-witness message `[x || r]`:

1. Pad and reshape `W` into an approximately square matrix `U`.
2. Apply a systematic, constant-degree linear code independently to every row.
3. Hash encoded columns into one Merkle commitment.
4. Reduce an MLE opening to a row combination and authenticate it by opening a
   small number of challenged encoded columns.
5. Record approximate code, combination, opening, and sumcheck identities as
   ordered metric observations rather than one Boolean tolerance decision.
6. Compose proved bounds derived from those observations into an interval for
   the final squared residual norm.

Do not add a separate randomized Hadamard layer to this path. Its intended role
was distance amplification, which belongs in the Brakedown code itself; a
Hadamard checksum layer without an authenticated distance test only adds
another committed table and another relation to prove.

The hoped-for prover cost is a small number of sequential passes:

```text
sparse row encoding:             O(n)
column commitment:               O(n) bytes hashed
row-combination preparation:     O(n)
sumcheck and relation passes:    O(nnz(A) + n)
sampled opening extraction:      O(q sqrt(n)) bytes
```

There is no global FFT. Merkle construction remains linear because a complete
binary tree over `L` leaves contains fewer than `2 L` nodes. Recursively
committing geometrically shrinking layers is also linear in aggregate; an
implementation becomes `O(n log n)` only if it recomputes shared paths or
subtrees.

This is a plausible route to the original operational target—proof generation
cost comparable to a few SpMVs—but it is not yet a protocol. The central gap is
a robust *metric proximity* theorem that binds the opened MLE value to the
canonical binary64 source while charging small inconsistencies quantitatively.

## 2. Why revisit a finite-field construction

[Brakedown](https://eprint.iacr.org/2021/1043.pdf) obtains a linear-time prover
by replacing Reed--Solomon encoding with a linear-time encodable code. Its
commitment views an MLE table as a matrix, encodes rows, commits columns, and
uses random row combinations plus sampled columns to test consistency. Its
proof and verifier are sublinear rather than automatically polylogarithmic;
Brakedown discusses proof composition as a separate way to obtain polylogarithmic
online work.

This project has already benefited from translating an algebraic construction
by role rather than by literal arithmetic. The current unit-circle code came
from asking what the Reed--Solomon machinery contributed—evaluation spreading,
foldability, and authenticated openings—and then finding numerically suitable
complex analogues. The same discipline applies here:

| Finite-field role | Binary64 research analogue |
| --- | --- |
| Exact systematic source symbols | Canonical IEEE-754 source bits interpreted as exact dyadic reals |
| Exact linear row encoding | Frozen sparse binary64 encoding plus a deterministic roundoff enclosure |
| Equality of code symbols | Absolute defect, scale, and interval-valued discrepancy |
| Codeword proximity | Distance or energy bound to a source-consistent encoded matrix |
| Schwartz--Zippel cancellation bound | Anti-concentration for the actual finite real/complex challenge grid |
| Accept/reject transcript | Ordered metric transcript culminating in a residual interval |
| Cryptographic security parameter | Separately reported binding assumption, statistical budget, and solve-relative retry model |

The translation may fail at a theorem or at a constant. A failed literal port
is not a reason to discard the architecture. It identifies which role needs a
different numerical object.

## 3. Target statement and transcript philosophy

The numerical target remains the exact-real interpretation of accepted
binary64 inputs. For the residual-witness variant, let

```text
e = b - A x - r
C = ||r||_2
D = ||e||_2.
```

If authenticated evidence establishes

```text
C in [C_minus, C_plus]
D <= D_plus,
```

then

```text
max(0, C_minus - D_plus)
    <= ||b - A x||_2
    <= C_plus + D_plus.
```

The desired output is this interval, its squared form, and its provenance. It
need not be a Boolean oracle. A valid transcript may say that an encoding or
sumcheck relation has a measurable defect and produce a wider final interval.

There are still exact structural failures:

- malformed or noncanonical framing;
- dimensions, padding, or code parameters inconsistent with the statement;
- invalid hashes or Merkle paths;
- messages or roots fixed after their challenges;
- non-finite arithmetic where the profile requires a finite enclosure; and
- work or allocation limits exceeded.

Everything else that is inherently approximate should first be represented as
a metric. Application policy may later decide whether an interval is useful;
the proof layer should not hide that evidence behind `passes=true`.

## 4. Matrix-shaped commitment

### 4.1 Layout

Let the padded message length be `N = R C`, with `R` and `C` powers of two and
as close as practical to `sqrt(N)`. Store the canonical source matrix

```text
U in F64^(R x C)
```

column-major so every committed column is contiguous. Padding coordinates are
exact positive zero and the shape, bit order, source semantics, and padding
rule are transcript-bound.

Let `Enc` be a systematic row code of rate `rho`:

```text
Enc(u) = [u || parity(u)]
```

and let `M` be the `R x C_enc` matrix obtained by encoding every row. The
initial commitment hashes each complete encoded column, then hashes the column
digests into one flat Merkle tree. Systematic columns therefore bind the exact
source bits as part of the same commitment; a separate source root is optional
rather than implicit.

At `N = 2^20` with `R = C = 1024`, one opened binary64 column is 8 KiB. Sixteen
naive column openings are about 128 KiB before paths and transcript data. This
square-root communication is not polylogarithmic, but it is substantially
smaller than the 8 MiB raw vector and is compatible with the present roughly
one-MiB artifact target. Multiple MLE claims must be batched before opening so
this cost is not paid independently for every sumcheck endpoint.

### 4.2 First encoding surrogate

The first implementation should not pretend to instantiate Brakedown's code.
It should benchmark a transparent throughput surrogate:

- systematic source columns;
- a fixed parity-column ratio;
- constant, distinct source neighbors per parity symbol;
- transcript-independent deterministic graph generation;
- signed dyadic weights and a frozen accumulation order; and
- flat source, parity, and hash storage.

This establishes whether sparse encoding plus column hashing can meet the
runtime budget. It establishes no distance or proximity result. A later phase
must implement and document a code with the required expansion, distance, and
local-test properties.

Signed dyadic weights are attractive because multiplication is exact while it
remains in range. If a degree-`d` parity is the ordered average

```text
p = sum_(ell=0)^(d-1) sign_ell * u[j_ell] / d,
```

with power-of-two `d`, only the additions introduce binary64 rounding. The
encoder records or derives an outward error bound from the exact input bits and
the fixed operation order. Alternative normalized kernels may have better
energy behavior; as with the unit-circle fold, local operator norm matters more
than superficial resemblance to a field formula.

### 4.3 Hashing remains computational binding

The code does not replace the hash. The Merkle root binds the encoded matrix,
and code tests connect that matrix to a source-consistent codeword. BLAKE3 or a
similarly reviewed hash should remain the default assumption unless profiling
shows it dominates the new linear pipeline.

Reducing statistical query counts does not justify weakening collision
binding. The two costs and two assumptions are separate. At the target sizes,
hashing roughly 8--16 MiB once should be measured rather than presumed to be
the bottleneck.

## 5. Opening a multilinear evaluation

Split an MLE point into row and column coordinates. Its equality weights factor
as

```text
ell_row in C^R
ell_col in C^C,
W_tilde(z) = ell_row^T U ell_col.
```

The real affine profile is one option. The Boolean-diameter unit-circle
geometry from the a-posteriori proposal is another: it keeps each tensor row
at unit Euclidean norm and extends the real row code complex-linearly only for
the challenged combination.

The prover computes

```text
v = ell_row^T U                 // C values
y = v^T ell_col                 // claimed MLE value
v_enc = Enc(v).                 // C_enc values
```

Linearity predicts

```text
v_enc ~= ell_row^T M.
```

In a field these values are equal for an honestly encoded matrix. In binary64
they generally differ because encoding rows before combining them changes the
operation order. The verifier therefore records, for each sampled encoded
column `j`,

```text
d_j = opened(ell_row^T M[:,j]) - v_enc[j]
```

with an exact-dyadic or outward-rounded enclosure for the verifier's small
calculation. It also records the terminal opening defect

```text
d_open = y - v^T ell_col.
```

No fixed scalar tolerance silently turns these observations into equality.
The proximity analysis consumes their magnitudes, scales, query locations,
and deterministic error envelopes.

The naive verifier must read every value in each sampled column to calculate
`ell_row^T M[:,j]`, giving `O(q sqrt(N))` work and communication. This is the
first target. Adding proof composition merely to call the verifier
polylogarithmic would likely reintroduce costs incompatible with a benchmark
certificate and is explicitly deferred.

## 6. From sampled defects to a metric proximity statement

### 6.1 Why finite-field proximity does not transfer automatically

Finite-field code tests use exact equality, Hamming distance, and algebraic
anti-cancellation. Binary64 introduces three different phenomena:

1. honest nonzero defects from operation ordering;
2. malicious small-amplitude defects that should widen a metric rather than
   necessarily invalidate a transcript; and
3. rare large defects that coordinate sampling can miss.

Moreover, a real linear code has no positive absolute Euclidean minimum
distance because codewords may be scaled continuously. The useful statement
must be relative, energy-based, threshold-indexed, or conditioned on an
authenticated magnitude bound.

### 6.2 Tail curves instead of one tolerance

For a vector of local discrepancies `d`, define its empirical tail function

```text
F_d(tau) = fraction_j(abs(d_j) > tau).
```

The identity

```text
||d||_2^2 = integral_(tau=0)^infinity 2 tau * count(abs(d_j) > tau) d tau
```

suggests a metric transcript containing a simultaneous upper confidence curve
for `F_d`, evaluated on a frozen dyadic threshold grid. Integrating the upper
curve with an authenticated magnitude cap yields an energy bound. This is more
informative than choosing one tolerance after seeing the transcript and more
faithful to the desired metric output.

Without-replacement column sampling can provide finite-population confidence
bounds for each prespecified threshold, with a simultaneous allocation across
thresholds and protocol rounds. This only bounds the sampled discrepancy
vector. A separate robust-code lemma must connect discrepancy energy to
distance from a source-consistent encoded matrix.

### 6.3 Candidate robust statement

A useful first theorem would have the following form. Conditional on the
commitment and all prover messages fixed before query sampling, the verifier
derives

```text
dist_metric(M, Enc(U_star)) <= D_code
```

for one canonical binary64 source matrix `U_star`, except with probability
`p_code`. Here `dist_metric` must specify:

- whether source coordinates are exact bits or permitted to move;
- the norm and per-coordinate scaling;
- deterministic binary64 encoding error;
- the sampled tail or energy contribution;
- the code's robust-test constant;
- the authenticated magnitude cap; and
- uniqueness or stability of `U_star` sufficient for later challenges.

For this application, the preferred target keeps systematic source
coordinates fixed exactly and moves only parity coordinates to
`Enc(U_source)`. That makes the decoded message unambiguous: it is the source
bits already contained in the systematic columns. The theorem then bounds how
far the committed parity is from the encoding of those exact bits.

This target avoids claiming a uniform minimum separation between nearby
binary64 messages. It does not avoid the hard part: sampled column checks must
still control the global parity discrepancy of a malicious matrix.

### 6.4 Random row combinations and cancellation

One row combination can hide several bad rows through cancellation. The
challenge distribution must be fixed after the matrix root and analyzed for
the actual real or complex grid. Repetitions, batching, and any supplied
combination vectors must follow commit-before-challenge ordering.

The theorem may report a family

```text
D_code(alpha),  alpha in registered confidence levels,
```

rather than one accept/reject threshold. Approximate-sumcheck defects and
roundoff intervals feed this family. Fiat--Shamir retries or selective aborts
are charged separately through the attempt model.

## 7. Composing with sumcheck and the residual metric

The current binary64 sumchecks remain useful once the PCS can open the required
MLE values. Their tables halve each round, so their arithmetic is linear in
the initial table size. The new commitment removes the rate-one-half global
FFT; it does not remove all vector passes.

The first concrete composition needs only **two** committed endpoints. Use the
repository sign convention

```text
r = A x - b.
```

Changing to `b - A x` only negates `r` and leaves its squared norm unchanged.
The noninteractive order is:

1. Compute `r`, pack `[x || r]`, encode its rows, and commit the encoded
   columns before drawing any algebraic challenge.
2. Prove the claim `S = sum_i r_i^2` with the product sumcheck. Its terminal
   point `rho` supplies both the value `r_tilde(rho)` and the random row
   compression used by the next relation.
3. Define the structured random vector

   ```text
   lambda_i = eq(rho, i)
   ```

   and make one sparse pass to form

   ```text
   w_j = sum_i lambda_i A_ij.
   ```

   The identity

   ```text
   b_tilde(rho) + r_tilde(rho) = sum_j w_j x_j
   ```

   is proved by a second product sumcheck. At its terminal point `sigma`, the
   verifier evaluates the public `A_tilde(rho, sigma)` succinctly and needs the
   committed value `x_tilde(sigma)`.
4. Reduce the two claims `r_tilde(rho)` and `x_tilde(sigma)` to two row
   combinations of the same matrix-shaped commitment. Send both source
   combinations, derive one shared set of column queries only after both are
   fixed, and authenticate both against every opened column.

This ordering is important. An arbitrary explicit random vector `lambda`
would force the verifier to form `A^T lambda` in `O(nnz(A))` work. Equality
weights derived from an MLE point give the same random linear-functional role
while letting the registered public evaluator compute the terminal matrix MLE
succinctly. Reusing the norm endpoint also eliminates a separate residual
opening point.

In particular, the current fast backend's third linear-opening sumcheck and
unit-circle fold are not part of this candidate. Brakedown-shaped column
testing is intended to authenticate the two terminal values directly. This is
an architectural simplification, not a theorem: the sampled test is sound only
after a real distance code and a binary64 metric proximity statement connect
the supplied row combinations to the committed systematic source.

The first prototype sends the two source combinations separately but shares
all opened columns and authentication paths. A later algebraic batching step
could reduce those vectors, but it would require an anti-cancellation analysis
and is not needed to test the main runtime hypothesis.

A future bound calculator consumes an ordered sequence such as:

```text
encoding_roundoff_envelope
sampled_column_defect_tail
row_combination_cancellation_bound
MLE_terminal_defect
per_round_sumcheck_defects
public_matrix_evaluation_enclosure
residual_sketch_intervals
residual_witness_norm_interval
```

and produces:

```text
code_distance_bound
committed_opening_interval
relation_defect_bound D_plus
residual_l2_interval
squared_residual_interval
failure_allocation_by_component.
```

Intermediate metric quantities are first-class authenticated outputs. If a
required lemma is unavailable, downstream theorem fields remain `null` while
the measured transcript remains useful for research and falsification.

## 8. Cost model and benchmark gates

The combined chunked-Merkle and reused-twiddle experiment at revision
`4c7d68f` measured the following 1M SPD banded cases on the development
machine:

| Half-bandwidth | SciPy factor + solve | Complete proof | Validation | Proof bytes |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 30.491 ms | 1,694.439 ms | 19.293 ms | 932,100 B |
| 32 | 247.374 ms | 1,663.883 ms | 28.889 ms | 927,338 B |

These are cross-branch research measurements, not a baseline present on this
branch. They show that communication and validation are already useful, while
proof construction is not a lightweight benchmark step.

The first sparse-code microbenchmark freezes:

```text
N                     = 2^20 source values
R x C                 = 1024 x 1024
parity/source columns = 1/2
local degree          = 4
column queries        = 16 initially
threads                = 1
```

It measures separately:

- parity construction;
- column hashing and internal Merkle hashing;
- one row-combination pass;
- encoding that combination;
- metric disagreement between combine-then-encode and encode-then-combine;
- estimated naive opening bytes; and
- peak process RSS externally.

The initial release measurement is recorded in the
[benchmark notes](../benchmarks/brakedown-metric-commitment/README.md). At 1M
values, a `256 x 4096` source layout, one parity column per two source columns,
degree 4, and 16 opened columns took 16.739 ms median and 15,300 KiB peak RSS.
BLAKE3 column/tree commitment took 13.854 ms of that total, while encoding took
2.052 ms. The naive opening was 72,352 bytes and its structural authentication
plus queried combination checks took 0.063 ms. Honest binary64 operation-order
disagreement had maximum absolute magnitude `7.63e-17`.

This is evidence only about the cost floor. The graph is a deterministic
throughput surrogate with no distance or proximity claim, and the measurement
omits relation sumchecks and global metric composition. It nevertheless
falsifies the concern that sparse encoding plus hashing must already be slower
than the 30.491 ms band-1 solve on this fixture.

### 8.1 Two-sumcheck composition experiment

The follow-up `--residual-composition` mode commits the padded message
`[x || r]` and implements the four-stage composition in Section 7. It uses the
existing binary64 product-sumcheck and registered succinct public evaluator,
not reimplementations. The timed prover includes:

- the sparse `r = A x - b` pass;
- packing `x` and `r`;
- row encoding and the full encoded-column Merkle commitment;
- the residual-norm sumcheck;
- the sparse row-compression pass and matvec sumcheck;
- both terminal row combinations; and
- extraction of one shared sampled-column opening.

Problem compilation and deterministic construction of the input candidate
`x` are outside the timer. The candidate is `1` plus a reproducible small
dyadic perturbation; it is not a hidden solve. The matrix is the registered
shifted graph Laplacian with either positive offset `[1]` or `[1, 32]`. The
`[1, 32]` case has half-bandwidth 32 but only five structural diagonals, matching
the sparse family used in the earlier solve comparison.

On the same single-threaded release setup, with `N = 2^20`, a `1024 x 2048`
source layout for the two-table message, parity/source `1/2`, degree 4, and 16
shared queries, 25 measured repetitions gave:

| Offsets | Structural nnz | Prover median | Verifier median | Estimated proof | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| `[1]` | 3,145,726 | 142.419 ms | 16.452 ms | 171,128 B | 60,224 KiB |
| `[1, 32]` | 5,242,814 | 171.202 ms | 30.584 ms | 171,128 B | 60,240 KiB |

The proof-byte value is a canonical-width estimate, not a serialized artifact.
It includes the root, two sumchecks, two source row combinations, 16 complete
columns, and naive independent authentication paths. At 2.04% of the 8 MiB
raw solution it is about 5.4 times smaller than the roughly 927--932 KiB
current fast artifacts.

Relative to the recorded factorization-plus-solve and current-proof numbers:

| Half-bandwidth | SciPy factor + solve | Composition / solve | Current proof / composition |
| ---: | ---: | ---: | ---: |
| 1 | 30.491 ms | 4.67x | 11.90x |
| 32 | 247.374 ms | 0.69x | 9.72x |

The important profile change is that the two sparse passes are now the main
cost. At offset `[1, 32]`, residual construction and row compression consumed
about 95.4 ms together; commitment hashing was 23.7 ms, norm sumcheck 23.4 ms,
and matvec sumcheck 13.4 ms. The experiment therefore supports the intended
algorithmic direction: after removing the global FFT and third opening
sumcheck, proof construction is within a small number of sequential sparse and
vector passes.

It does **not** establish a sound certificate. The throughput surrogate's
degree-4 graph has no distance amplification. In the measured `1024 x 2048`
layout at least one source column participates in no parity column, so a
one-coordinate change affects one of 3,072 encoded columns. Sixteen uniform
queries miss that change with probability `0.9947916667`. A real Brakedown
code must replace this graph and its encoding, memory, and query requirements
must be remeasured. The prototype status string is deliberately
`two-sumcheck-composition-with-assumed-code-proximity`.

The surrogate is promising if its complete encode/commit/open-preparation time
is comfortably below the 247 ms band-32 solve. Matching the 30 ms band-1 solve
is a stretch target, not an immediate reason to abandon a construction that
could remove the much larger current proof overhead. Every later protocol
stage must be charged against the remaining budget.

End-to-end targets remain:

| Quantity | Initial target | Stretch target |
| --- | ---: | ---: |
| Complete prover / 1M band-32 solve | less than 2x | at most 1x |
| Complete prover / 1M band-1 solve | report honestly | at most 3x |
| Complete verifier / solve | at most 1x | at most 0.25x |
| Artifact / raw binary64 vector | less than 25% | less than 12.5% |
| Peak prover RSS | less than 256 MiB | less than 128 MiB |

No conclusion is drawn from debug builds, one timing, or a kernel that omits
required source layout, hashing, or opening work.

## 9. Attack and falsification plan

The research implementation must include attacks that preserve small local
defects while changing the desired metric:

- corrupt one systematic source coordinate;
- corrupt one parity column, one row, or one expander neighborhood;
- distribute a dense defect just below one chosen tolerance;
- concentrate energy in unopened columns;
- choose rows whose random combination cancels on a weak challenge grid;
- supply an encoded matrix unrelated to its systematic source;
- alter a source bit while retaining stale parity;
- exploit zero, subnormal, overflow, cancellation, and scale separation;
- grind roots or combination messages before query sampling; and
- replay openings across shapes, code graphs, statements, or attempts.

For each attack, report the entire metric transcript, the directly computed
global source/parity discrepancy, whether the proposed confidence curve covers
it, and the cheapest known retry strategy. An empirical escape rate remains
empirical.

## 10. Research phases

### Phase A: cost floor

- Implement the throughput surrogate and a simple reference encoder.
- Confirm deterministic roots and reference equivalence on small shapes.
- Measure the 1M default above in release mode.
- Profile encoding, hashing, row combination, and allocation separately.

Gate: retain the architecture even if one component is slow; identify whether
the fault is the code layout, hash layout, or unavoidable bytes touched before
changing the theorem target.

### Phase B: exact structural prototype

- Freeze a real candidate code and graph generation.
- Commit systematic source bits and parity columns.
- Implement one matrix-shaped MLE opening with sampled full columns.
- Verify all opened calculations with exact dyadics or outward intervals.

Gate: honest small examples match exhaustive direct openings and every stale,
malformed, or reordered transcript fails structurally.

### Phase C: metric code testing

- Define the threshold-indexed defect transcript.
- Prove or import the code's robust local-test statement, then adapt its
  conclusion rather than its field arithmetic.
- Derive deterministic honest binary64 encoding envelopes.
- Test energy-concentrated and cancellation attacks.

Gate: no global distance or confidence field without an instantiated theorem
for the implemented graph, challenge distribution, magnitude cap, and retry
model.

### Phase D: batched MLE openings

- Batch current sumcheck endpoints into one matrix-code opening.
- Develop the a-posteriori anti-cancellation recurrence for observed defects.
- Compare real affine, Boolean-diameter circle, and finite complex grids.
- Preserve per-stage metric observations in proof replay.

Gate: exhaustive tiny instances and independent high-precision calculations
cover the reported opening intervals.

### Phase E: residual composition

- Combine the PCS opening bound with the one-pass residual-witness relation.
- Allocate failures across code testing, batching, sumcheck, residual sketches,
  and attempts.
- Produce several prespecified confidence-indexed residual intervals.
- Benchmark complete proof time, proof bytes, RSS, and validation time against
  the same solve fixtures.

Gate: an interval may be wide or unavailable, but it may not silently become a
Boolean certificate.

## 11. Repository boundaries

The initial work should add only:

- this non-normative proposal;
- an isolated release-mode throughput experiment; and
- reproducible benchmark notes.

It should not add a `ProofProtocol` variant, validation manifest, artifact
decoder, or service endpoint. Those belong after Phase C supplies a defensible
metric proximity statement.

A production implementation would likely introduce a separate PCS crate with:

- private validated code parameters and graph layout;
- flat source/parity buffers and reusable scratch;
- a source-bit commitment boundary;
- reference and optimized encoders;
- metric opening reports independent of application policy; and
- explicit allocation/work preflight.

The existing sumcheck, transcript, public evaluator, and service framing should
be reused only where their numerical contracts match the successor profile.

## 12. Current conclusion

Brakedown does not solve binary64 proximity for us. It does identify a credible
way to remove the global FFT while retaining a succinct MLE opening: matrix
layout, row encoding, column commitment, and sampled combination checks.

The two-sumcheck experiment sharpens that conclusion. The residual norm
endpoint can serve directly as the random row functional for the sparse
relation, leaving only `r_tilde(rho)` and `x_tilde(sigma)` to authenticate. On
the 1M offset-32 fixture, every implemented prover pass took about 171 ms in
aggregate, below the recorded 247 ms factor-and-solve and almost ten times
faster than the current complete proof. The remaining obstacle is no longer an
unexplained performance gap; it is the concrete distance/proximity statement
and the cost of the real code that supplies it.

The binary64 opportunity is not to weaken exact equality with an arbitrary
tolerance. It is to promote the sequence of discrepancies to authenticated
metric data and prove how their magnitudes propagate into the final residual
interval. The finite-field code supplies the combinatorial spreading
architecture; unit-circle and a-posteriori work supply numerical geometry and
error accounting; the residual-witness proposal supplies the final metric
composition.

That combination is speculative but falsifiable. It removes the known
`O(n log n)` FFT cost, preserves linear Merkle work, and gives the next
experiment a concrete performance budget without claiming that the missing
proximity theorem is routine.

## 13. References

- Alexander Golovnev, Jonathan Lee, Srinath Setty, Justin Thaler, and Riad
  Wahby, [Brakedown: Linear-time and Field-agnostic SNARKs for
  R1CS](https://eprint.iacr.org/2021/1043.pdf), CRYPTO 2023.
- Daniel A. Spielman, [Linear-time Encodable and Decodable Error-correcting
  Codes](https://doi.org/10.1109/18.556668), IEEE Transactions on Information
  Theory 42(6), 1996.
- Dor Bitan, Zachary DeStefano, Shafi Goldwasser, Yuval Ishai, Yael Tauman
  Kalai, and Justin Thaler, [Sum-Check Protocol for Approximate
  Computations](https://cs.nyu.edu/~zd2131/papers/25-2152.pdf), EUROCRYPT 2026.
