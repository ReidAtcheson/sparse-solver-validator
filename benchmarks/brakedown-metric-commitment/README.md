# Brakedown-shaped binary64 commitment cost floor

Status: throughput and two-sumcheck composition experiments without a
proximity or soundness claim.

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

## Residual-composition mode

The same example has an explicit `--residual-composition` mode. It keeps the
surrogate commitment but replaces the synthetic source with the padded message
`[x || r]` for a registered shifted graph-Laplacian problem. It then performs:

1. the sparse pass `r = A x - b`;
2. a product sumcheck for `sum_i r_i^2`, yielding `rho` and
   `r_tilde(rho)`;
3. a sparse pass forming `w_j = sum_i eq(rho,i) A_ij`;
4. a product sumcheck for
   `b_tilde(rho) + r_tilde(rho) = sum_j w_j x_j`, yielding `sigma` and
   `x_tilde(sigma)`;
5. two row combinations of the one committed matrix for the packed MLE points
   `(0, sigma)` and `(1, rho)`; and
6. one shared set of sampled encoded columns authenticating both combinations.

The verifier replays both sumchecks, evaluates the registered public matrix
and RHS MLEs, authenticates each opened column once, and reports every
binary64 defect. Changing a terminal claim changes the subsequent query
schedule; stale claims or Merkle paths fail structural verification.

This is an end-to-end **composition cost**, not an end-to-end sound proof. The
implemented degree-4 graph is not a distance code, so the sampled-column step
is explicitly conditioned on an unavailable proximity theorem. The benchmark
prints the minimum encoded weight of a one-source-coordinate change and its
exact without-replacement query miss probability to make that limitation
visible in every run.

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

The composed 1M offset-32 run is:

```sh
target/release/examples/brakedown_metric_commitment \
  --residual-composition \
  --dimension 1048576 \
  --rows 1024 \
  --offsets 1,32 \
  --parity-denominator 2 \
  --degree 4 \
  --queries 16 \
  --warmups 2 \
  --repetitions 25
```

Use `--offsets 1` for the half-bandwidth-1 comparison. The candidate solution
is generated outside the timer as `1` plus a deterministic integer multiple
of `2^-24`; `--perturbation-bits` changes that scale. Problem compilation is
also excluded. Residual construction, all commitment work, both sumchecks,
both sparse proof scans, and opening extraction are included.

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

## Two-sumcheck composition results

The composed runs used the same machine and release profile, one thread, two
warm-ups, and 25 measured repetitions. The packed two-table message used 1,024
rows and 2,048 source columns, one parity column per two source columns,
degree 4, and 16 shared column queries.

| Offsets | Structural nnz | Prover median | Min--max | Verifier median | Estimated proof | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `[1]` | 3,145,726 | 142.419 ms | 133.973--148.457 ms | 16.452 ms | 171,128 B | 60,224 KiB |
| `[1, 32]` | 5,242,814 | 171.202 ms | 160.415--180.859 ms | 30.584 ms | 171,128 B | 60,240 KiB |

The proof estimate includes one 32-byte root, the three scalar claims, both
20-round quadratic sumchecks, both complete source row combinations, 16 full
opened columns, indices, and naive authentication paths. It is not canonical
serialization. It is 2.04% of the 8 MiB raw solution.

Median offset-32 prover stages were:

| Stage | Time |
| --- | ---: |
| Residual sparse pass | 46.463 ms |
| Packed-message copy | 5.934 ms |
| Sparse row encoding | 5.594 ms |
| Column/tree commitment | 23.722 ms |
| Residual-norm sumcheck | 23.388 ms |
| Matvec row-compression sparse pass | 48.935 ms |
| Matvec sumcheck | 13.441 ms |
| Two terminal row combinations | 3.512 ms |
| Opening extraction | 0.024 ms |

The two sparse passes account for about 95.4 ms and are now the largest cost.
There is no global FFT and no third linear-opening sumcheck.

The honest maximum defects were `2.07e-25` in the norm transcript,
`1.11e-16` in the matvec transcript, `9.05e-26` at the residual opening,
`1.11e-15` at the solution opening, and `5.55e-16` among sampled code
combinations. These are diagnostic observations, not a derived acceptance
threshold.

### Deliberate falsification result

For this shape the surrogate has 3,072 encoded columns. Its minimum encoded
weight for changing one source coordinate is only one: at least one systematic
source coordinate happens to have no adjacent parity column. Sixteen uniform
queries without replacement miss that coordinate with probability

```text
3056 / 3072 = 0.9947916667.
```

This is decisive evidence that the throughput graph cannot serve as the final
code. The good runtime answers only the composition-cost question. A real
linear-time code with proved distance and robust local testing must replace the
surrogate, and the complete benchmark must then be rerun.

## Relation to the measured solves

The earlier 1M SciPy banded-Cholesky measurements, including factorization and
triangular solve, were 30.491 ms at half-bandwidth 1 and 247.374 ms at
half-bandwidth 32. The `256 x 4096` surrogate therefore costs about 0.55 and
0.068 of those solves, respectively.

The two-sumcheck composition is the more relevant comparison:

| Half-bandwidth | SciPy factor + solve | Composed prover | Prover / solve | Current proof / composed prover |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 30.491 ms | 142.419 ms | 4.67x | 11.90x |
| 32 | 247.374 ms | 171.202 ms | 0.69x | 9.72x |

Thus the measured offset-32 composition no longer perturbs the benchmark more
than the solve itself. The offset-1 case remains about 4.7 times the very fast
banded factor-and-solve. Neither comparison includes the unknown cost needed
to replace the unsound sparse graph with a defensible Brakedown code.

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
