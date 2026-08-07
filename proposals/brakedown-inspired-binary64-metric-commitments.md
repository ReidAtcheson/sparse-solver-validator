# Brakedown-inspired metric commitments for binary64 sparse validation

Status: speculative research proposal with a recursive-layout prototype;
non-normative.

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

Retain a Brakedown-shaped commitment to a canonical binary64 message `W`,
initially either `x` or the residual-witness message `[x || r]`, as a research
candidate:

1. Pad and reshape `W` into an approximately square matrix `U`.
2. Apply Brakedown's recursive systematic expander-code layout independently to
   every row.
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

The recursive-layout experiment reaches the operational target on the 1M
band-32 fixture: its complete composed prover remains below the recorded
factorization-plus-solve time. This is not yet a protocol. The central gap is a
robust *metric proximity* theorem that binds the opened MLE value to the
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

Let the padded message length be `N = R C`, with `R` and `C` powers of two.
Choose the shape from the measured cost of source combinations, opened columns,
and authentication rather than fixing it to `sqrt(N)`. Store the canonical
source matrix

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
column openings are about 128 KiB before authentication and transcript data.
This square-root communication is not polylogarithmic, but it is substantially
smaller than the 8 MiB raw vector. When the query count rises, fewer rows and
more columns can reduce opening bytes at the cost of longer source
combinations. Multiple MLE claims must share the same queried columns so this
cost is not paid independently for every sumcheck endpoint.

### 4.2 Recursive encoder prototype

The first implementation used a one-layer degree-4 throughput surrogate. It
answered the cost-floor question but failed even a unit-coordinate spreading
test: some systematic coordinates had no parity neighbor. The current
prototype replaces it with Brakedown's recursive layout. At each level,

```text
y = x A
z = Enc(y)
v = z B
Enc(x) = (x, z, v).
```

`A` and `B` are input-row-regular sparse matrices, so every input coordinate
has a fixed number of distinct output neighbors. This orientation is important:
the proxy instead chose a fixed number of inputs for each parity output, which
left some inputs isolated. Recursion terminates at a small dense systematic
base code.

The prototype freezes the original paper's fastest parameter row for fields of
at least 127 bits:

```text
rate rho              = 0.704
relative distance delta = 0.02     // finite-field claim only
alpha                  = 0.1195
beta = delta / rho     = 0.0284
A row weight           = 6
B row weight           = 33
base threshold         = 30
```

For a 2,048-symbol source row this produces 2,910 encoded symbols through two
sparse levels and performs 27,084 multiply-adds, or 13.225 per source symbol.
The operation count is linear and closely follows the paper's reported `13.2n`
profile.

This is a faithful *layout and cost* prototype, not a faithful algebraic
instantiation. Sparse coefficients are deterministic signed 52-bit dyadic
binary64 values with magnitude in `[0.5, 1)`, and the base is a dense random
dyadic code rather than exact Reed--Solomon. Brakedown's proof relies on
uniform nonzero finite-field coefficients, exact cancellation probabilities,
and an exact base code. Replacing those objects invalidates the theorem even
though the graph dimensions and arithmetic count match.

The prototype exhaustively reports encoded support for unit messages. This can
falsify an isolated-coordinate bug, but it is not a minimum-distance
calculation: arbitrary linear combinations may have lower support, and support
alone does not bound the metric effect of a binary64 alteration.

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

The concrete composition needs two committed MLE endpoints plus one independent
Brakedown testing combination. Use the repository sign convention

```text
r = A x - b.
```

Changing to `b - A x` only negates `r` and leaves its squared norm unchanged.
The noninteractive order is:

1. Compute `r`, pack `[x || r]`, encode its rows, and commit the encoded
   columns before drawing any algebraic challenge.
2. Derive an independent random row vector from that root, return the
   corresponding source combination, and bind it to the transcript. This is
   the combination used by Brakedown's codeword test; a structured sumcheck
   endpoint is not a substitute for it.
3. Prove the claim `S = sum_i r_i^2` with the product sumcheck. Its terminal
   point `rho` supplies both the value `r_tilde(rho)` and the random row
   compression used by the next relation.
4. Define the structured random vector

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
5. Reduce the two claims `r_tilde(rho)` and `x_tilde(sigma)` to two row
   combinations of the same matrix-shaped commitment. Send both source
   combinations, derive one shared set of column queries only after all three
   combinations are fixed, and authenticate all three against every opened
   column.

This ordering is important. An arbitrary explicit random vector `lambda`
would force the verifier to form `A^T lambda` in `O(nnz(A))` work. Equality
weights derived from an MLE point give the same random linear-functional role
while letting the registered public evaluator compute the terminal matrix MLE
succinctly. Reusing the norm endpoint also eliminates a separate residual
opening point.

In particular, the current fast backend's third linear-opening sumcheck and
unit-circle fold are not part of this candidate. Brakedown-shaped column
testing is intended to authenticate the two terminal values directly. The
extra transmitted vector is an independent code test, not a third MLE-opening
sumcheck. This is an architectural simplification, not a theorem: the sampled
test is sound only after a real distance code and a binary64 metric proximity
statement connect the supplied row combinations to the committed systematic
source.

The prototype sends all three source combinations separately but shares all
opened columns and a canonical deduplicated Merkle multiproof. A later
algebraic batching step could reduce those vectors, but it would require an
anti-cancellation analysis and is not needed to test the main runtime
hypothesis.

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

The current `--residual-composition` experiment commits padded `[x || r]` and
implements the schedule in Section 7 using the existing binary64 product
sumcheck and registered succinct public evaluator. The timed prover includes:

- the sparse `r = A x - b` pass and packing;
- recursive row encoding and the complete encoded-column Merkle commitment;
- the independent commit-before-challenge code-testing combination;
- the residual-norm sumcheck;
- the sparse row-compression pass and matvec sumcheck;
- both terminal row combinations; and
- extraction of one shared compact column multiproof.

Problem compilation, deterministic input construction, graph generation, and
the exhaustive unit-message diagnostic are outside the timer. Verification of
the multiproof, all three combinations, both sumchecks, and the public MLEs is
reported separately.

The full measurements and reproduction commands are in the
[benchmark notes](../benchmarks/brakedown-metric-commitment/README.md). On the
same single-threaded release setup, with one million solution values and 25
measured repetitions, the 512-query proof-size stretch profile gave:

| Offsets | Prover median | Verifier median | Estimated artifact | Artifact / solution | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| `[1]` | 159.292 ms | 17.823 ms | 1,000,344 B | 11.93% | 63,968 KiB |
| `[1, 32]` | 192.992 ms | 34.635 ms | 999,288 B | 11.91% | 64,248 KiB |

The source layout is `128 x 16384`, and each row encodes to 23,273 columns.
On the band-32 case, recursive encoding took 11.498 ms median and commitment
took 29.484 ms. The independent random combination took 1.199 ms. The sparse
passes and sumchecks remain the dominant work, so replacing the proxy with the
recursive encoder does not consume the performance budget.

Relative to the recorded factorization-plus-solve measurements:

| Half-bandwidth | SciPy factor + solve | Composed prover | Prover / solve |
| ---: | ---: | ---: | ---: |
| 1 | 30.491 ms | 159.292 ms | 5.22x |
| 32 | 247.374 ms | 192.992 ms | 0.78x |

The 16-query cost floor is 150.551 ms at band 1 and 179.501 ms at band 32.
Against the old proxy's 142.419 ms and 171.202 ms, the faithful layout adds
only 5.7% and 4.8%, respectively. The band-32 candidate remains substantially
faster than the approximately 1.66-second current proof and below the solve
itself. The band-1 solve remains roughly five times faster.

### 8.1 Conditional query curve

For comparison with the finite-field analysis only, the executable prints the
without-replacement probability that `q` queries miss
`ceil(beta C) / 3` bad encoded columns:

```text
P_miss = product_(k=0)^(q-1) (N_enc - B - k) / (N_enc - k).
```

Here `C` is the source-column count, `N_enc` is the encoded width, and
`beta = 0.0284`, corresponding to relative distance `delta = 0.02` at rate
`rho = 0.704`. The measured band-32 proof-size/query frontier is:

| Rows x source columns | Queries | Prover median | Estimated artifact | Artifact / solution | Conditional miss |
| --- | ---: | ---: | ---: | ---: | ---: |
| `1024 x 2048` | 16 | 179.501 ms | 184,984 B | 2.21% | `8.95e-1` |
| `128 x 16384` | 512 | 192.992 ms | 999,288 B | 11.91% | `3.07e-2` |
| `64 x 32768` | 1,024 | 187.859 ms | 1,475,032 B | 17.58% | `9.67e-4` |
| `64 x 32768` | 1,536 | 195.855 ms | 1,789,048 B | 21.33% | `2.83e-5` |

The last two rows are exploratory five- and three-repetition runs. The
artifact estimate counts fixed-width proof payload fields but is not a
canonical serialization.

These probabilities are explicitly **conditional diagnostics, not soundness
bounds**. They assume the finite-field minimum-distance and proximity argument,
which is unavailable for the dyadic binary64 code. They also omit random-row
cancellation, code-generation failure, numerical thresholds, selective aborts,
and retries. The 512-query point shows the engineering tradeoff, not an
acceptable escape probability.

The unit-message scan found support between 4,703 and 4,727 columns at the
512-query shape, replacing the proxy's isolated-coordinate failure. It does not
bound arbitrary messages or metric amplitude. At 64 rows, honest operation
ordering produced sampled discrepancies up to about `2.18e-11`, which must
eventually be enclosed rather than treated as exact equality.

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

- Completed: implemented the throughput surrogate and reference checks.
- Completed: measured its isolated and residual-composed 1M costs in release
  mode.
- Completed: identified the surrogate's isolated systematic coordinates and
  rejected it as a code candidate.

Gate: retain the architecture even if one component is slow; identify whether
the fault is the code layout, hash layout, or unavoidable bytes touched before
changing the theorem target.

### Phase B: exact structural prototype

- Completed structurally: froze the recursive Brakedown profile and
  deterministic graph generation.
- Completed structurally: committed systematic source bits and recursive
  parity columns with compact multiproofs.
- Completed structurally: added the independent random combination, two MLE
  combinations, and shared sampled-column verification.
- Outstanding: replace diagnostic binary64 differences with exact-dyadic or
  outward interval enclosures.

Gate: honest small examples match exhaustive direct openings and every stale,
malformed, or reordered transcript fails structurally.

### Phase C: metric code testing

- Next: define the threshold-indexed defect transcript.
- Next: prove a binary64/dyadic robust local-test statement. The finite-field
  statement may guide its shape but cannot be imported as-is.
- Derive deterministic honest binary64 encoding envelopes.
- Test energy-concentrated and cancellation attacks.

Gate: no global distance or confidence field without an instantiated theorem
for the implemented graph, challenge distribution, magnitude cap, and retry
model.

### Phase D: batched MLE openings

- Completed structurally: batch current sumcheck endpoints and the independent
  code test into one shared matrix-code opening.
- Develop the a-posteriori anti-cancellation recurrence for observed defects.
- Compare real affine, Boolean-diameter circle, and finite complex grids.
- Preserve per-stage metric observations in proof replay.

Gate: exhaustive tiny instances and independent high-precision calculations
cover the reported opening intervals.

### Phase E: residual composition

- Completed as a cost experiment: composed the commitment with the two
  residual sumchecks and public MLE evaluation.
- Outstanding theoretically: combine a proved PCS opening bound with the
  one-pass residual-witness relation.
- Allocate failures across code testing, batching, sumcheck, residual sketches,
  and attempts.
- Produce several prespecified confidence-indexed residual intervals.
- Benchmark complete proof time, proof bytes, RSS, and validation time against
  the same solve fixtures.

Gate: an interval may be wide or unavailable, but it may not silently become a
Boolean certificate.

## 11. Repository boundaries

The research branch adds only:

- this non-normative proposal;
- an isolated release-mode recursive-layout and composition experiment; and
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

The true recursive *shape* is immediately useful; the finite-field theorem is
not. Replacing the one-layer proxy with `Enc(x) = (x, Enc(xA), Enc(xA)B)` removes
its obvious isolated-coordinate failure and costs only about 5% on the 16-query
composed benchmark. At the more useful 512-query point, the 1M band-32 prover
takes about 193 ms, below the recorded 247 ms factorization-plus-solve, while
the estimated artifact is about 999 KiB or 11.9% of the solution vector.

This closes the immediate engineering question: Brakedown's recursive encoding
constant is affordable here. Encoding is about 11.5 ms at the 512-query
band-32 shape; the sparse relation passes and sumchecks still dominate. More
work on the encoding kernel is not the next bottleneck.

The experiment also makes the theoretical blocker more precise. The paper's
distance proof is about Hamming support over a finite field with uniform
nonzero coefficients and exact arithmetic. The prototype has a finite dyadic
coefficient grid, binary64 rounding, and a dense random dyadic base. A large
unit-message support and a small conditional query-miss calculation do not
rule out low-support combinations, small-amplitude attacks, or challenge
cancellation. The reported sampling probabilities therefore remain
conditional diagnostics and must not become certificate confidence fields.

The next defensible research step is a metric authentication statement for the
implemented arithmetic: likely an exact rational shadow of the dyadic code plus
a binary64 roundoff tube, or a new expansion/anti-concentration argument for a
registered finite dyadic coefficient grid. It must connect sampled combined
columns to one canonical systematic source and charge alteration magnitude,
not merely count nonzero coordinates.

The binary64 opportunity remains to promote the sequence of discrepancies to
authenticated metric data and prove how they propagate into the final residual
interval. The recursive layout removes the global FFT and preserves linear
Merkle work; the experiment shows that the missing theorem, rather than the
real code's arithmetic cost, is now the limiting issue.

## 13. References

- Alexander Golovnev, Jonathan Lee, Srinath Setty, Justin Thaler, and Riad
  Wahby, [Brakedown: Linear-time and Field-agnostic SNARKs for
  R1CS](https://eprint.iacr.org/2021/1043.pdf), CRYPTO 2023.
- Ulrich Haböck,
  [Brakedown's expander code](https://eprint.iacr.org/2023/769.pdf), 2023.
- Daniel A. Spielman, [Linear-time Encodable and Decodable Error-correcting
  Codes](https://doi.org/10.1109/18.556668), IEEE Transactions on Information
  Theory 42(6), 1996.
- Dor Bitan, Zachary DeStefano, Shafi Goldwasser, Yuval Ishai, Yael Tauman
  Kalai, and Justin Thaler, [Sum-Check Protocol for Approximate
  Computations](https://cs.nyu.edu/~zd2131/papers/25-2152.pdf), EUROCRYPT 2026.
