# Brakedown-shaped binary64 commitment cost floor

Status: throughput experiment without a proximity or soundness claim.

This benchmark accompanies
[`brakedown-inspired-binary64-metric-commitments.md`](../../proposals/brakedown-inspired-binary64-metric-commitments.md).
It asks whether removing the global FFT is worth deeper theoretical work. It
does not instantiate Brakedown's code or register a proof protocol.

## Surrogate pipeline

The release example
[`brakedown_metric_commitment.rs`](../../crates/ssv-fast/examples/brakedown_metric_commitment.rs)
performs:

1. systematic degree-4 row encoding with signed dyadic weights;
2. BLAKE3 hashing of every encoded column and a retained flat Merkle tree;
3. one challenged linear combination of every encoded column;
4. encoding of the source part of that combination;
5. comparison of encode-then-combine with combine-then-encode;
6. extraction of 16 complete columns and their naive authentication paths; and
7. verifier-side authentication and metric comparison of those openings.

The synthetic source contains deterministic values in `[-1, 1)` with up to 52
fractional bits. This intentionally exposes binary64 operation-order defects;
a low-precision dyadic source made both linearity orders bit-identical.

The row code is only a data-movement surrogate. Its deterministic graph has no
claimed expansion, distance, local-test, or decoder theorem. Authentication
paths are stored independently rather than as a deduplicated multiproof, so
the byte figures are conservative for the implemented tree.

## Reproduction

```sh
cargo +stable build --release -p ssv-fast \
  --example brakedown_metric_commitment
target/release/examples/brakedown_metric_commitment \
  --dimension 1048576 \
  --rows 256 \
  --parity-denominator 2 \
  --degree 4 \
  --queries 16 \
  --warmups 2 \
  --repetitions 25
```

The master seed defaults to `0x5eedc0ded15ca11e`. Graph, source, row-weight,
column-weight, and query seeds are deterministically domain-separated in the
example. The output includes the commitment root and all benchmark parameters.

## Environment

- CPU: Intel Core i7-1360P
- OS: Linux 7.0.11 x86-64
- Rust: 1.97.0
- Build: release, thin LTO, one process and one thread
- Timing: two warm-ups followed by 25 repetitions
- Dimension: `2^20 = 1,048,576` source binary64 values
- Code surrogate: one parity column per two source columns, degree 4
- Queries: 16 complete columns

## Results

The total prover-side surrogate includes encoding, commitment, combination,
combination encoding, defect calculation, and opening extraction. It excludes
the separately reported opening verification.

| Rows | Source columns | Total | Encode | Commit | Combine | Opening bytes | Opening verification | Peak RSS |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 256 | 4,096 | 16.739 ms | 2.052 ms | 13.854 ms | 0.745 ms | 72,352 B | 0.063 ms | 15,300 KiB |
| 512 | 2,048 | 16.086 ms | 1.990 ms | 13.241 ms | 0.791 ms | 88,224 B | 0.093 ms | 15,076 KiB |
| 1,024 | 1,024 | 14.963 ms | 1.889 ms | 12.359 ms | 0.763 ms | 145,056 B | 0.145 ms | 15,040 KiB |
| 2,048 | 512 | 14.346 ms | 1.816 ms | 11.793 ms | 0.762 ms | 271,520 B | 0.256 ms | 15,132 KiB |
| 4,096 | 256 | 14.363 ms | 1.849 ms | 11.672 ms | 0.768 ms | 531,104 B | 0.491 ms | 15,204 KiB |

The `256 x 4096` layout minimizes bytes among the tested shapes because opening
cost is approximately

```text
8 * (source_columns + queries * rows) + authentication.
```

The square layout is slightly faster because it initializes fewer column
hashers, but sends twice as many bytes for this query count. Layout therefore
needs to be selected from the measured proof-size/runtime frontier rather than
fixed to `sqrt(N)` by analogy.

For the `256 x 4096` layout, the retained tree is 512 KiB, source storage is 8
MiB, and parity storage is 4 MiB. The opening is 0.86% of the raw vector size.
Commitment hashing accounts for about 83% of the measured pipeline.

The honest binary64 linearity observations were:

| Rows | Maximum absolute defect | RMS absolute defect | Maximum queried defect |
| ---: | ---: | ---: | ---: |
| 256 | 7.63e-17 | 1.44e-17 | 2.43e-17 |
| 512 | 9.71e-17 | 1.41e-17 | 3.12e-17 |
| 1,024 | 7.29e-17 | 1.38e-17 | 1.91e-17 |
| 2,048 | 5.38e-17 | 1.34e-17 | 2.21e-17 |
| 4,096 | 6.94e-17 | 1.54e-17 | 3.30e-17 |

These defects are measurements, not acceptance thresholds. In particular, the
queried maximum being smaller than the global maximum illustrates why sampled
observations require a confidence statement and magnitude or energy control.

## Relation to the measured solves

The earlier 1M SciPy banded-Cholesky measurements, including factorization and
triangular solve, were 30.491 ms at half-bandwidth 1 and 247.374 ms at
half-bandwidth 32. The `256 x 4096` surrogate therefore costs about 0.55 and
0.068 of those solves, respectively.

This is encouraging but incomplete. The surrogate omits:

- a defensible linear-time code and its metric proximity analysis;
- matrix/residual relation work;
- residual and norm sumchecks;
- batching and anti-cancellation transcripts;
- confidence-curve calculation;
- canonical artifact framing and serialization; and
- adversarial retry accounting.

Consequently, 16.7 ms is a measured cost floor, not a projected complete proof
time. It does show that sparse encoding plus a complete hash commitment need
not by themselves exceed the band-1 solve.

## Sensitivity

At the `256 x 4096` shape, a separate 25-repetition sweep measured:

| Parity/source | Degree | Encode | Commit | Total |
| ---: | ---: | ---: | ---: | ---: |
| 1/2 | 4 | 1.929 ms | 12.890 ms | 15.737 ms |
| 1/2 | 8 | 3.762 ms | 13.790 ms | 18.685 ms |
| 1/4 | 4 | 0.981 ms | 11.447 ms | 13.100 ms |

The high-rate surrogate is faster, but no query or rate reduction is justified
until a concrete code theorem and solve-relative retry model assign its cost.

## Correctness checks

The example tests cover deterministic graph/root construction, successful
opening authentication, rejection after changing an opened value, rejection
after changing an authentication hash, and invalid code degrees. The optimized
run recomputes every queried column combination and reports its numerical
defects after authenticating the path.
