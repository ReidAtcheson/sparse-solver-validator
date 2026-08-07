# Randomized-Hadamard checksum cost and attack surrogate

This benchmark measures the isolated construction proposed in
[randomized-Hadamard metric checksums](../../proposals/randomized-hadamard-binary64-metric-checksums.md).
It is not a proof benchmark and makes no soundness claim.

The example implements:

```text
Enc_D(u) = [u || H D u]
```

for every row of a canonical binary64 matrix, commits complete encoded columns
under a flat BLAKE3 Merkle tree, prepares one row combination, encodes that
combination, extracts naive complete-column openings, and authenticates the
sampled linearity checks. It now also measures a global approximate sumcheck
for one post-commitment contraction of the complete checksum relation.

The opening-query seed hashes both the matrix root and the exact claimed row
combination, so the measured opening indices are derived only after that claim
is fixed.

It also compares:

- alterations fixed before independent random sign draws; and
- a balanced Walsh-subspace alteration constructed after the public signs are
  known; and
- a sparse codeword-switch attack against a tempting recursive odd/even local
  fold test.

The latter is an explicit falsification of a uniform spreading claim for one
public randomized-Hadamard basis. It does not contradict fixed-vector RHT
concentration.

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
- Staged prover timer: adds construction of one global relation/weight table,
  its initial contraction, and a 21-round binary64 product sumcheck
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
| Hadamard encoding into column layout | 6.072 ms | 6.617 ms | 7.118 ms |
| Systematic row-to-column transpose | 2.316 ms | 2.432 ms | 3.713 ms |
| Complete column/Merkle commitment | 15.035 ms | 16.175 ms | 17.608 ms |
| Encoded row combination | 0.928 ms | 1.001 ms | 1.071 ms |
| Combination Hadamard transform | 0.011 ms | 0.011 ms | 0.023 ms |
| Opening extraction | 0.053 ms | 0.056 ms | 0.060 ms |
| Defect scan and terminal claim | 0.021 ms | 0.022 ms | 0.040 ms |
| **Base prover-side surrogate** | **24.437 ms** | **26.410 ms** | **28.823 ms** |
| Global relation-table construction and initial contraction | 19.153 ms | 20.664 ms | 21.846 ms |
| Global product sumcheck | 26.696 ms | 29.125 ms | 30.179 ms |
| **Staged prover-side surrogate** | **72.259 ms** | **75.692 ms** | **80.281 ms** |
| Opening authentication and checks | 0.067 ms | 0.071 ms | 0.102 ms |
| Global sumcheck replay and public-factor endpoint | 0.049 ms | 0.052 ms | 0.083 ms |

Representation and artifact measurements:

| Quantity | Value |
| --- | ---: |
| Systematic source storage | 8,388,608 B |
| Hadamard parity storage | 8,388,608 B |
| Retained Merkle tree | 524,288 B |
| Naive opening | 72,352 B |
| Global sumcheck increment | 520 B |
| Staged surrogate artifact | 72,872 B |
| Staged artifact / raw source vector | 0.8687% |
| Peak RSS, one cold staged process | 52,284 KiB |
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
requires a measured row-to-column transpose. The global sumcheck consumes the
column-major source and parity allocations into a 16 MiB mutable data table and
materializes a second 16 MiB coefficient table. The earlier base-only process
peaked at 27,616 KiB; the endpoint-incomplete global extension therefore has a
material memory cost even though it adds only 520 artifact bytes.

## Staged append and global sumcheck

The staged candidate first binds the source-side checkpoint, derives the signs
`D`, appends and commits the alleged checksum table `P_hat`, and only then
derives random contraction weights. For row weights `lambda` and column weights
`L`, the measured global claim is

```text
lambda^T P_hat L - lambda^T U (D H^T L).
```

The implementation represents this as one product sum over the concatenated
`[P_hat || U]` table and a public factored coefficient table. A 21-round
binary64 sumcheck reduces 2,097,152 products to one private table evaluation
and one public coefficient evaluation. The public coefficient endpoint is
recomputed in `O(R + C)` work from its row/column factors rather than by
materializing the full table in the validator.

For the honest primary input:

| Quantity | Value |
| --- | ---: |
| Initial metric contraction | `-1.6669608401964631e-17` |
| Maximum sumcheck round absolute defect | `1.6669608401964631e-17` |
| Public factored endpoint disagreement | `1.0587911840678754e-22` |
| Final product absolute defect | `6.462348535570529e-27` |
| Sumcheck rounds | 21 |
| Incremental transcript payload | 520 B |

This is a useful arithmetic and cost result, not a complete proof. The final
private table MLE was `-5.320273864224703e-5`, and the executable deliberately
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
| SciPy factor plus solve, half-bandwidth 1 | 30.491 ms | 0.87x | 2.48x |
| SciPy factor plus solve, half-bandwidth 32 | 247.374 ms | 0.107x | 0.306x |
| Complete chunked/unit-circle proof | 1.664--1.694 s | about 0.016x | about 0.045x |
| Sparse Brakedown-shaped commitment surrogate | 16.739 ms | 1.58x | 4.52x |

The endpoint-incomplete staged surrogate is roughly 22 times faster than the
current complete proof. It remains about 2.5 times the band-1 factor-and-solve,
so it would still perturb that benchmark materially; it is about 31% of the
band-32 solve. The comparison says that the global sumcheck arithmetic and
artifact are plausible. It does not price the missing endpoint authentication.

## Limitations

- The public transform is deliberately vulnerable to adaptive structured
  alterations.
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
- the public-sign balanced-subspace attack;
- encode/combine commutation up to binary64 roundoff; and
- Merkle opening authentication and mutation rejection;
- normalized odd/even fold completeness;
- the sparse local-fold codeword-switch attack;
- factored versus materialized public sumcheck endpoints; and
- observation of a committed checksum mutation by the global contraction; and
- a rejection target demonstrating that an unbound zero-table sumcheck currently
  passes every algebraic check.

Run them with:

```sh
cargo +stable test -p ssv-fast --example randomized_hadamard_checksums
```
