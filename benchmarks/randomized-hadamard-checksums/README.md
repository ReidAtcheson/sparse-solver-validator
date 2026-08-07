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
sampled linearity checks.

The opening-query seed hashes both the matrix root and the exact claimed row
combination, so the measured opening indices are derived only after that claim
is fixed.

It also compares:

- alterations fixed before independent random sign draws; and
- a balanced Walsh-subspace alteration constructed after the public signs are
  known.

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
- Prover timer: includes output allocation, full Hadamard parity generation,
  systematic transposition, complete hashing, combination preparation, defect
  scan, and opening extraction
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
| Hadamard encoding into column layout | 5.845 ms | 7.757 ms | 10.009 ms |
| Systematic row-to-column transpose | 2.440 ms | 4.131 ms | 4.681 ms |
| Complete column/Merkle commitment | 16.536 ms | 17.067 ms | 17.982 ms |
| Encoded row combination | 0.998 ms | 1.060 ms | 2.149 ms |
| Combination Hadamard transform | 0.011 ms | 0.019 ms | 0.035 ms |
| Opening extraction | 0.056 ms | 0.080 ms | 0.225 ms |
| Defect scan and terminal claim | 0.024 ms | 0.038 ms | 0.066 ms |
| **Total prover-side surrogate** | **26.491 ms** | **30.239 ms** | **33.389 ms** |
| Opening authentication and checks | 0.062 ms | 0.064 ms | 0.082 ms |

Representation and artifact measurements:

| Quantity | Value |
| --- | ---: |
| Systematic source storage | 8,388,608 B |
| Hadamard parity storage | 8,388,608 B |
| Retained Merkle tree | 524,288 B |
| Naive opening | 72,352 B |
| Opening / raw source vector | 0.8625% |
| Peak RSS, one cold measured process | 27,616 KiB |
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
requires a measured row-to-column transpose.

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

| Workload | Time | Hadamard surrogate / workload |
| --- | ---: | ---: |
| SciPy factor plus solve, half-bandwidth 1 | 30.491 ms | 0.99x |
| SciPy factor plus solve, half-bandwidth 32 | 247.374 ms | 0.122x |
| Complete chunked/unit-circle proof | 1.664--1.694 s | about 0.019x |
| Sparse Brakedown-shaped commitment surrogate | 16.739 ms | 1.81x |

The Hadamard surrogate is roughly 55--56 times faster than the current complete
proof, but it is not a complete replacement. The comparison says that one
row-local full Hadamard block is computationally plausible. It does not say
that authenticating a transform chosen after the claim can fit in the remaining
budget.

## Limitations

- The public transform is deliberately vulnerable to adaptive structured
  alterations.
- The experiment has no mechanism authenticating fresh post-claim Hadamard
  checksums against an earlier source root.
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
- Merkle opening authentication and mutation rejection.

Run them with:

```sh
cargo +stable test -p ssv-fast --example randomized_hadamard_checksums
```
