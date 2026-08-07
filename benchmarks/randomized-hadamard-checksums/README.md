# Randomized-Hadamard checksum cost and attack surrogate

This benchmark measures the isolated construction proposed in
[randomized-Hadamard metric checksums](../../proposals/randomized-hadamard-binary64-metric-checksums.md).
It is not a proof benchmark and makes no soundness claim.

The primary example implements:

```text
Enc_D(u) = [u || H D u]
```

for every row of a canonical binary64 matrix, commits complete encoded columns
under a flat BLAKE3 Merkle tree, prepares one row combination, encodes that
combination, extracts naive complete-column openings, and authenticates the
sampled linearity checks. It also measures:

- the post-root structured functional

  ```text
  chi(r)^T p - (Q^T chi(r))^T u,    Q = H D,
  ```

  as an explicitly unauthenticated arithmetic control;
- a global approximate sumcheck for the random MLE of the complete checksum
  discrepancy;
- a factor-aware sumcheck prover that never materializes the `2 R C` public
  coefficient table; and
- cascades `Q = (H D_k) ... (H D_1)` that retain one parity block while
  applying several independently signed Hadamard layers.

The opening-query seed hashes both the matrix root and the exact claimed row
combination, so the measured opening indices are derived only after that claim
is fixed.

It also compares:

- alterations fixed before independent random sign draws; and
- a balanced Walsh-subspace alteration constructed after the public signs are
  known; and
- a sparse codeword-switch attack against a tempting recursive odd/even local
  fold test; and
- a forged appended-parity attack that defeats column sampling independently
  of the number of Hadamard layers.

The public-sign attack is an explicit falsification of a uniform spreading
claim for one public randomized-Hadamard basis. It does not contradict
fixed-vector RHT concentration. The appended-parity attack is stronger in a
different direction: even an empirically well-spread cascade cannot help when
the alleged parity table is not authenticated as the transform of the source.

## Environment

- CPU: 13th Gen Intel Core i7-1360P
- Logical CPUs: 16
- OS: Linux 7.0.11 x86-64
- Rust: 1.97.0
- Build: release with thin LTO
- Execution: one process, one Rust thread, no CPU affinity
- Timing: two warm-ups followed by 25 repetitions for the primary result
- Source generation and spreading study: outside the prover timer
- Base prover timer: includes output allocation, full Hadamard parity
  generation, systematic transposition, complete hashing, combination
  preparation, defect scan, and opening extraction
- Structured-functional timer: derives a tensor MLE weight after the root,
  applies the Hadamard adjoint, and evaluates two length-4096 inner products
- Staged prover timer: adds construction of one global relation table, a
  cached first round, and the remaining 20 rounds of a 21-round binary64
  product sumcheck; the public coefficient table remains factored
- Verification: timed separately

The source values are deterministic dyadic values spanning `[-1, 1)`. Row and
column combination weights are deterministic signed dyadic values. The master
seed defaults to `0x5eedc0ded15ca11e` and domain-separated seeds determine
source values, transform signs, combination weights, and queries.

## Primary result

Parameters:

```text
logical dimension = 2^20 = 1,048,576 binary64 values
matrix             = 256 x 4096
parity             = one complete Hadamard block
encoded columns    = 8192
queries            = 16
spreading trials   = 256
```

Command:

```sh
cargo +stable run --release -p ssv-fast \
  --example randomized_hadamard_checksums -- \
  --dimension 1048576 \
  --rows 256 \
  --queries 16 \
  --spreading-trials 256 \
  --warmups 2 \
  --repetitions 25
```

Measured timing:

| Component | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| Hadamard encoding into column layout | 7.827 ms | 8.378 ms | 9.117 ms |
| Systematic row-to-column transpose | 3.903 ms | 4.168 ms | 4.542 ms |
| Complete column/Merkle commitment | 15.440 ms | 16.465 ms | 18.067 ms |
| Encoded row combination | 0.954 ms | 1.012 ms | 1.496 ms |
| Combination Hadamard transform | 0.011 ms | 0.020 ms | 0.033 ms |
| Opening extraction | 0.067 ms | 0.078 ms | 0.144 ms |
| Defect scan and terminal claim | 0.034 ms | 0.037 ms | 0.110 ms |
| **Base prover-side surrogate** | **28.878 ms** | **30.210 ms** | **32.101 ms** |
| Structured-functional arithmetic control | 0.030 ms | 0.032 ms | 0.075 ms |
| **Base plus structured control** | **28.909 ms** | **30.243 ms** | **32.140 ms** |
| Global data/factor construction plus cached first round | 15.965 ms | 17.789 ms | 18.968 ms |
| Remaining factor-aware product sumcheck | 12.436 ms | 13.340 ms | 17.800 ms |
| **Endpoint-incomplete staged surrogate** | **58.792 ms** | **61.887 ms** | **67.604 ms** |
| Opening authentication and checks | 0.067 ms | 0.071 ms | 0.089 ms |
| Global sumcheck replay and public-factor endpoint | 0.046 ms | 0.050 ms | 0.068 ms |

Representation and artifact measurements:

| Quantity | Value |
| --- | ---: |
| Systematic source storage | 8,388,608 B |
| Hadamard parity storage | 8,388,608 B |
| Retained Merkle tree | 524,288 B |
| Naive opening | 72,352 B |
| Structured-functional scalar increment | 8 B |
| Global sumcheck increment | 520 B |
| Staged surrogate artifact | 72,872 B |
| Staged artifact / raw source vector | 0.8687% |
| Peak RSS, one cold factored staged process | 36,192 KiB |
| Peak RSS, materialized-coefficient control | 44,360 KiB |
| Butterfly additions/subtractions | 12,582,912 |

The retained root was
`d7b05ee680dcc2ef132a3ae1a048491dc03d102847dc9bfde6ea7f17920672b1`.

Honest transform-then-combine versus combine-then-transform disagreement was:

| Metric | Value |
| --- | ---: |
| Maximum absolute defect | `1.3877787807814457e-16` |
| RMS absolute defect | `2.932107118944541e-17` |
| Maximum relative defect | `2.237922130015587e-11` |
| RMS relative defect | `3.503807815584331e-13` |
| Maximum queried absolute defect | `6.938893903907228e-17` |
| RMS queried absolute defect | `2.4857329916268706e-17` |

Relative defects become large near cancellation and are observations, not
acceptance thresholds. A formal implementation must use absolute error and
outward arithmetic enclosures.

The RSS measurement used:

```sh
/usr/bin/time -v \
  target/release/examples/randomized_hadamard_checksums \
  --dimension 1048576 \
  --rows 256 \
  --queries 16 \
  --spreading-trials 1 \
  --warmups 0 \
  --repetitions 1
```

Peak RSS is a single process-wide maximum, not a repeated median. Parity is
written directly into committed column-major storage so the implementation
does not retain a second row-major parity copy. The canonical source still
requires a measured row-to-column transpose. The factor-aware global sumcheck
consumes those allocations into one 16 MiB mutable data table and retains only
`2 C + R` public factors. It does not allocate the former 16 MiB coefficient
table. The process peak fell by 8,168 KiB relative to the same executable's
materialized-coefficient control; allocator phase overlap means this is less
than the table's nominal size.

## Staged append and global sumcheck

The staged candidate first binds the source-side checkpoint, derives the signs
`D`, appends and commits the alleged checksum table `P_hat`, and only then
derives tensor points `r_R` and `r_C`. With MLE equality vectors `chi`, the
measured global claim is the random multilinear evaluation

```text
chi(r_R)^T P_hat chi(r_C)
    - chi(r_R)^T U Q^T chi(r_C)
  = MLE_(P_hat - U Q^T)(r_R, r_C),

Q = H D                         (one layer),
Q = (H D_k) ... (H D_1)        (a cascade).
```

For one layer, the column adjoint has the explicit real-valued form

```text
[D H chi(r_C)]_v
  = D_v / sqrt(C) * product_(i: v_i = 1) (1 - 2 r_(C,i)).
```

This is the structured-`y` identity under study. It is linear algebra over
binary64, not a finite-field analogy. Arbitrary independent signs `D_v` do
destroy a further tensor factorization at a fresh MLE endpoint, but the full
length-`C` adjoint costs only `O(C)` storage and verifier work here.

The implementation represents the complete relation as one product sum over
the concatenated `[P_hat || U]` table. Its public coefficient table factors as

```text
[chi(r_C) || -Q^T chi(r_C)] tensor chi(r_R).
```

The optimized prover retains those one-dimensional factors rather than a
`2 R C` coefficient allocation. It computes the initial claim as the sum of
the cached first round's two endpoints, then folds only the dense private data
table. A 21-round binary64 sumcheck reduces 2,097,152 products to one private
table evaluation and one public coefficient evaluation. The validator
recomputes the public endpoint in `O(R + C)` work.

For the honest primary input:

| Quantity | Value |
| --- | ---: |
| Initial metric contraction in cached-round order | `0.0` |
| Maximum sumcheck round absolute defect | `5.421010862427522e-20` |
| Public factored endpoint disagreement | `1.0587911840678754e-22` |
| Final product absolute defect | `2.5849394142282115e-26` |
| Sumcheck rounds | 21 |
| Incremental transcript payload | 520 B |

The even cheaper structured-functional control applies the same column
functional directly to the already prepared row combination:

```text
chi(r_C)^T p - (Q^T chi(r_C))^T u.
```

It took a median `0.032` ms and observed `7.70e-18`, or `3.70e-16` after
normalizing the functional to unit 2-norm. This is close to the desired
arithmetic shape: one short adjoint transform and two length-`C` dot products.
It is deliberately printed with
`structured_functional_data_authenticated=false`. Counting its 8-byte scalar
as a proof would assume precisely the linear authentication primitive that is
still missing.

This is a useful arithmetic and cost result, not a complete proof. The final
private table MLE was `3.187459924683081e-4`, and the executable deliberately
prints

```text
global_sumcheck_data_endpoint_authenticated=false
```

A Merkle root authenticates Boolean table leaves, not that fresh non-Boolean
MLE value. Supplying it without another opening argument merely moves the
commitment problem to the sumcheck endpoint. One rank-one contraction is also
not yet a norm bound: a complete metric theorem needs an anti-concentration or
sketching statement, repetition policy, magnitude controls, binary64
enclosures, and retry accounting.

The endpoint gap has an executable attack. A test keeps the Merkle root of a
table with a material checksum mutation, substitutes an uncommitted all-zero
private table in the sumcheck, and obtains zero defects in every round and at
the terminal product. The missing opening must therefore bind the private
endpoint to `[P_hat || U]`; transcript-binding the root alone is insufficient.

### Factor-aware control

The `--materialize-global-coefficients` flag retains the previous dense public
coefficient table as a same-executable control. At the primary shape:

| Component | Factored median | Materialized median |
| --- | ---: | ---: |
| Global preparation and initial claim | 17.789 ms | 21.832 ms |
| Global product sumcheck | 13.340 ms | 28.838 ms |
| Global extension only | 31.129 ms | 50.671 ms |
| Complete staged surrogate | 61.887 ms | 79.611 ms |
| Cold process peak RSS | 36,192 KiB | 44,360 KiB |

Factoring reduced the measured global extension by `38.6%`, the complete
staged time by `22.3%`, and peak RSS by `18.4%`. It changes neither proof bytes
nor the unauthenticated endpoint status.

### Why local odd/even folding is insufficient

The normalized Walsh identity does support a geometrically shrinking fold. If
`p = H_n z`, split each vector into halves and, after challenge `rho`, form

```text
z' = ((1 + rho) z_0 + (1 - rho) z_1) / sqrt(2)
p' = p_0 + rho p_1.
```

Then `p' = H_(n/2) z'`. However, this identity lacks the code-distance part of
the Reed--Solomon argument. The executable commits forged parity for a source
with one altered coordinate, switches to that nearby valid codeword in the
first child, and follows honest folds thereafter. Only one of the first
round's 2,048 local equations is false; the final scalar defect is
`8.88e-16`. Sixteen distinct local queries miss the false pair with probability
`0.9921875`.

The global contraction is the response to that counterexample: its randomness
is derived after the appended root and aggregates every relation cell. Its MLE
endpoint still needs a commitment mechanism such as the existing unit-circle
control, a Brakedown-shaped sparse proximity layer, or another linear/MLE
opening commitment.

### Cascades improve spreading, not authentication

The executable also evaluates

```text
Q_k = (H D_k) ... (H D_1)
```

with one systematic and one parity block. A second layer greatly improves the
three registered attacks against the public square transform:

| Adaptive construction | One-layer median miss | Two-layer median miss |
| --- | ---: | ---: |
| Concentrate the first layer on a Walsh subspace | `0.7771` | `1.42e-3` |
| Concentrate the final layer on a Walsh subspace | `0.7771` | `4.39e-4` |
| Force the final parity to one spike | `1.50e-5` | `2.41e-3` |

The corresponding two-layer median tail fractions were `0.3359`, `0.3828`,
and `0.3136`. This is encouraging empirical erasure robustness, not a uniform
lower-tail theorem. The two-layer staged median was `64.159` ms versus
`61.887` ms for one layer; proof bytes were unchanged because intermediate
layers are not committed.

More importantly, cascades do not close the appended-table gap. Set the
committed source table to zero, fix a false claimed combination `v = e_0`, and
choose any row with nonzero challenge weight `alpha_i`. After `Q` is known, a
malicious prover can set

```text
P_hat[i, :] = Q v / alpha_i
```

and all other parity rows to zero. Then `alpha^T P_hat = Q v` exactly in the
executable, so every parity-column query passes. Only the one systematic
coordinate where `v` differs from the zero source is marked. Sixteen queries
among 8192 encoded columns miss it with probability `0.998046875`, for one,
two, or more Hadamard layers. This attack is why the cascade data must not be
presented as a solution to authentication.

## Spreading and public-transform attack

The registered diagnostic threshold for these measurements was

```text
0.5 * norm(Delta)_2 / sqrt(C).
```

For every row-code coordinate above that scale, the table reports the fraction
of the complete systematic-plus-parity frame that is exposed. Query miss
probabilities are exact sampling-without-replacement calculations conditional
on that count.

| Alteration | Tail fraction | Median 16-query miss | Worst observed miss |
| --- | ---: | ---: | ---: |
| Fixed spike before random signs | 0.500122 | `1.50e-5` | `1.50e-5` |
| Fixed 64-coordinate subspace | 0.351562 median | `9.69e-4` | `8.43e-3` |
| Fixed dense vector | 0.661255 median | `2.92e-8` | `4.58e-8` |
| Subspace adapted to public signs | 0.015625 | `7.77e-1` | `7.77e-1` |

The adaptive construction sets

```text
Delta = D * normalized_indicator(S)
```

for a 64-coordinate Walsh subspace `S`. The systematic half has 64 coordinates
above the diagnostic scale and `H D Delta` has 64. Its total energy is not
small: the encoded-to-source energy ratio is exactly two up to measured
roundoff. The attack hides energy by concentrating it, not by reducing it.

The fixed-subspace row uses the same vector without adapting it to `D`. Across
256 independent sign draws, the randomized transform substantially spreads its
parity energy. This is the intended fixed-before-random behavior.

## Query-count sweep

The public-sign subspace attack is intentionally known, so it can be used to
display the artifact/verification tradeoff without treating any row as a
security parameter recommendation.

| Queries | Naive opening | Opening extraction | Opening verification | Attack miss probability |
| ---: | ---: | ---: | ---: | ---: |
| 16 | 72,352 B | 0.077 ms | 0.061 ms | 0.777084 |
| 64 | 191,008 B | 0.112 ms | 0.240 ms | 0.363556 |
| 128 | 349,216 B | 0.156 ms | 0.504 ms | 0.131112 |
| 256 | 665,632 B | 0.248 ms | 1.141 ms | 0.016636 |

All four openings remain smaller than the 8 MiB source vector. Increasing
queries barely changes prover time because the complete matrix has already
been encoded and committed. This does not establish solve-relative security:
cheap nonce grinding, amortized commitments, and attacks with still smaller
tails must be analyzed first.

## Shape sweep

The following separate sweep used two warm-ups, 15 repetitions, 64 spreading
trials, and 16 queries. It is useful for layout selection but does not replace
the 25-repetition primary measurement.

| Rows | Columns | Prover median | Opening | Verification | Adaptive attack miss |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 8,192 | 33.540 ms | 89,248 B | 0.050 ms | 0.8280 |
| 256 | 4,096 | 32.160 ms | 72,352 B | 0.063 ms | 0.7771 |
| 512 | 2,048 | 29.378 ms | 88,224 B | 0.090 ms | 0.6837 |
| 1,024 | 1,024 | 28.687 ms | 145,056 B | 0.153 ms | 0.6006 |
| 2,048 | 512 | 29.696 ms | 271,520 B | 0.273 ms | 0.4612 |

The `256 x 4096` layout remains the measured proof-byte minimum for 16 queries.
Larger row counts slightly reduce transform and hashing time but increase full
column openings. The attack column also changes because the width and its
balanced Walsh subspace change; it is not a security comparison between
layouts.

## Relation to previous measurements

Earlier same-machine cross-branch measurements at one million values were:

| Workload | Time | Base / workload | Staged / workload |
| --- | ---: | ---: | ---: |
| SciPy factor plus solve, half-bandwidth 1 | 30.491 ms | 0.992x | 2.03x |
| SciPy factor plus solve, half-bandwidth 32 | 247.374 ms | 0.122x | 0.250x |
| Complete chunked/unit-circle proof | 1.664--1.694 s | about 0.018x | about 0.037x |
| Sparse Brakedown-shaped commitment surrogate | 16.739 ms | 1.81x | 3.70x |

The 30.243 ms base-plus-structured control is almost exactly the earlier
30.491 ms band-1 factor-and-solve, but the control has no linear
authentication. The endpoint-incomplete staged surrogate is roughly 27 times
faster than the current complete proof. It remains about twice the band-1
factor-and-solve and one quarter of the band-32 solve. The comparison says that
the Hadamard metric arithmetic and global sumcheck are plausible. It does not
price the missing endpoint authentication.

## Limitations

- The public transform is deliberately vulnerable to adaptive structured
  alterations.
- Two- through four-layer cascades improve the registered adaptive spreading
  attacks but have no uniform erasure-robustness theorem.
- A forged appended-parity table defeats column sampling with `0.998046875`
  miss probability even when the transform is cascaded.
- The 0.032 ms structured-functional result assumes access to the honest dense
  row combination and is an unauthenticated arithmetic control, not a proof.
- The global sumcheck's final private table MLE is not authenticated. Therefore
  the experiment still has no complete mechanism authenticating fresh
  post-claim Hadamard checksums against an earlier source root.
- One rank-one global contraction is an observed metric, not a proved global
  norm bound or a selected repetition count.
- Local odd/even fold sampling is explicitly defeated by a one-coordinate
  nearby-codeword switch with 0.9921875 miss probability at the primary shape.
- It has no proximity theorem, residual relation, norm sumcheck, bound
  calculator, certificate codec, service path, or retry model.
- The 0.5 natural-scale tail threshold is a diagnostic slice, not an acceptance
  threshold. Other thresholds and aggregate energy must be considered
  simultaneously.
- Random-vector and fixed-vector measurements do not imply a worst-case bound.
- One Walsh-subspace attack does not establish the worst possible attack.
- Full parity doubles source storage and hashing traffic.
- The implementation is serial and release-only performance conclusions apply
  only to the measured machine and workload.

## Checks

The example has deterministic unit tests for:

- Hadamard energy preservation;
- the three-layer transform/transpose adjoint identity;
- the closed-form one-layer adjoint of an MLE equality vector;
- the honest structured functional for a two-layer cascade;
- the public-sign balanced-subspace attack;
- encode/combine commutation up to binary64 roundoff;
- Merkle opening authentication and mutation rejection;
- normalized odd/even fold completeness;
- the sparse local-fold codeword-switch attack;
- the factor-aware sumcheck against a materialized reference;
- observation of a committed checksum mutation by the global contraction;
- the forged-parity cancellation attack against a three-layer cascade; and
- a rejection target demonstrating that an unbound zero-table sumcheck
  currently passes every algebraic check.

Run them with:

```sh
cargo +stable test -p ssv-fast --example randomized_hadamard_checksums
```
