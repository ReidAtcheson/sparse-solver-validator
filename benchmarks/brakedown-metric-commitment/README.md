# Recursive Brakedown-layout binary64 experiment

Status: faithful implementation of Brakedown's recursive encoder layout and
testing schedule, but **not** an instantiation of its finite-field distance or
soundness theorem.

This benchmark accompanies
[`brakedown-inspired-binary64-metric-commitments.md`](../../proposals/brakedown-inspired-binary64-metric-commitments.md).
It replaces the first degree-4 throughput proxy with the actual recursive
shape from Brakedown and composes that commitment with the repository's two
binary64 residual sumchecks. The experiment asks two separate questions:

1. Does the recursive code destroy the attractive prover cost measured for the
   proxy? No: its encoding cost is small enough that the band-32 composed prover
   remains faster than the recorded factorization-plus-solve.
2. Does using the recursive shape establish binary64 soundness? No: the
   finite-field distance proof does not transfer to dyadic binary64 arithmetic.

The executable prints the second limitation in its status line and labels every
distance-derived escape probability as conditional.

## What is implemented

For a source row `x`, the encoder recursively computes

```text
y = x A
z = Enc(y)
v = z B
Enc(x) = (x, z, v).
```

Both `A` and `B` are stored as flat input-row-regular sparse matrices. Each
input coordinate chooses distinct output coordinates, matching the orientation
of Brakedown's matrix distribution rather than the proxy's fixed-neighbor
parity columns. The profile uses the fastest large-field parameter row reported
by the original paper:

```text
rate rho              = 0.704
claimed distance delta = 0.02
alpha                  = 0.1195
beta = delta / rho     = 0.0284
A row weight           = 6
B row weight           = 33
base threshold         = 30
```

The resulting 2,048-column code has 2,910 encoded columns, two sparse levels,
and 27,084 multiply-adds per row, or 13.225 per source value. Encoding all rows
is therefore linear in the source table size.

The experiment deliberately differs from Brakedown in two decisive ways:

- sparse coefficients are signed 52-bit dyadic binary64 values with magnitude
  in `[0.5, 1)`, not uniform nonzero elements of a large finite field; and
- the terminal code is a small dense random systematic dyadic code, not the
  paper's exact Reed--Solomon base code.

Those substitutions retain the data layout and arithmetic count, but invalidate
the paper's cancellation and minimum-distance arguments. A unit-vector scan is
reported only as a falsification diagnostic; it is not a minimum-distance
calculation because linear combinations can have lower support or much smaller
metric amplitude.

## Commitment and testing schedule

The source and recursively generated parity columns are committed by a BLAKE3
Merkle tree. Openings use one canonical, deduplicated multiproof frontier rather
than independent paths.

Residual-composition mode commits the padded table `[x || r]`, where
`r = A x - b`, before deriving any testing challenge. It then performs:

1. an independent transcript-derived random row combination for the Brakedown
   codeword test;
2. a product sumcheck for `sum_i r_i^2`;
3. a sparse pass forming `w_j = sum_i eq(rho,i) A_ij`;
4. a product sumcheck for
   `b_tilde(rho) + r_tilde(rho) = sum_j w_j x_j`;
5. source row combinations for the two terminal MLE points; and
6. one shared set of sampled encoded columns authenticating all three supplied
   combinations.

The commitment root fixes the table before the independent random row vector.
All three source combinations are fixed before the shared query set. The
verifier replays both sumchecks, evaluates the registered public matrix and RHS
MLEs, verifies the compact multiproof, re-encodes each supplied source
combination, and reports binary64 discrepancies.

This is the relevant Brakedown test order. The earlier proxy reused structured
sumcheck endpoint weights and therefore omitted the independent random row
combination that is central to the codeword test.

## Reproduction

Build the isolated release example:

```sh
cargo +stable build --release -p ssv-fast \
  --example brakedown_metric_commitment
```

The stable 1M band-32 run at the proof-size stretch target was:

```sh
/usr/bin/time -v target/release/examples/brakedown_metric_commitment \
  --residual-composition \
  --dimension 1048576 \
  --rows 128 \
  --offsets 1,32 \
  --queries 512 \
  --warmups 2 \
  --repetitions 25
```

Use `--offsets 1` for the half-bandwidth-1 comparison. The low-query cost floor
uses `--rows 1024 --queries 16`. The more aggressive sampling points use
`--rows 64 --queries 1024` or `--rows 64 --queries 1536`.

The candidate solution is generated outside the timer as `1` plus a
deterministic integer multiple of `2^-24`. Problem compilation, graph
construction, and the exhaustive unit-vector diagnostic are also outside the
timer. Residual construction, packing, recursive encoding, commitment, the
independent code test combination, both sumchecks, both sparse proof scans,
terminal combinations, opening extraction, and proof verification are timed.

## Environment

- CPU: Intel Core i7-1360P
- OS: Linux 7.0.11 x86-64
- Rust: stable 1.97.0
- Build: release, thin LTO, one process and one thread
- Logical solution dimension: `2^20 = 1,048,576`
- Committed source: padded `[x || r]`, or `2^21` binary64 values
- Timing: two warm-ups followed by 25 repetitions unless marked exploratory

The laptop exhibited run-to-run and thermal variation. Tables therefore retain
the observed min--max range instead of treating the median as an exact machine
constant.

## Stable results

### Sixteen-query cost floor

These runs use 1,024 rows, 2,048 source columns, 2,910 encoded columns, and 16
shared column queries.

| Offsets | Structural nnz | Prover median | Min--max | Verifier median | Estimated artifact | Artifact / solution | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `[1]` | 3,145,726 | 150.551 ms | 146.954--158.313 ms | 16.737 ms | 184,728 B | 2.20% | 61,688 KiB |
| `[1, 32]` | 5,242,814 | 179.501 ms | 161.878--187.378 ms | 33.770 ms | 184,984 B | 2.21% | 61,608 KiB |

Sixteen queries are not a useful proximity setting. Conditional even on the
unavailable 2%-distance theorem, the paper's `beta/3` proximity event is missed
with probability about `0.8953`.

### 512-query proof-size stretch point

These runs use 128 rows, 16,384 source columns, 23,273 encoded columns, and 512
shared queries. This shape balances the three source combinations against the
opened columns and compact authentication frontier.

| Offsets | Prover median | Min--max | Verifier median | Estimated artifact | Artifact / solution | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `[1]` | 159.292 ms | 147.005--166.129 ms | 17.823 ms | 1,000,344 B | 11.93% | 63,968 KiB |
| `[1, 32]` | 192.992 ms | 181.240--202.093 ms | 34.635 ms | 999,288 B | 11.91% | 64,248 KiB |

For the band-32 run, median recursive encoding was 11.498 ms and commitment was
29.484 ms. The random test combination was 1.199 ms. The sparse residual and
row-compression work plus the two sumchecks remain the dominant work. The code
graph itself occupies 2,590,884 bytes and is reusable across proofs.

The smallest observed encoded support among all unit source messages was 4,703
of 23,273 columns. This is encouraging evidence that the isolated-coordinate
failure of the proxy is gone, but it is not a bound for arbitrary nonzero
messages. The conditional `beta/3` proximity miss probability at 512 queries is
`0.0307455`.

## Exploratory query curve

The following band-32 points used 64 rows and 32,768 source columns. They used
five and three repetitions, respectively, so they are feasibility measurements
rather than stable timing comparisons.

| Queries | Prover median | Verifier median | Estimated artifact | Artifact / solution | Conditional `beta/3` miss | Peak RSS |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 | 187.859 ms | 34.789 ms | 1,475,032 B | 17.58% | `9.67e-4` | 76,104 KiB |
| 1,536 | 195.855 ms | 37.898 ms | 1,789,048 B | 21.33% | `2.83e-5` | 72,588 KiB |

The last row is a useful engineering point: substantially more sampling still
keeps the prover below the band-32 solve and the artifact below the proposal's
25% initial limit. It is **not** a soundness estimate. The probability is the
exact without-replacement miss probability for `ceil(beta C)/3` bad encoded
columns, conditional on a finite-field theorem that has not been established
for this code or arithmetic. It also omits random-row cancellation, graph
generation failure, numerical tolerance, and retry terms.

## Relation to the measured solves

The recorded SciPy banded-Cholesky baselines include factorization and
triangular solve: 30.491 ms at half-bandwidth 1 and 247.374 ms at
half-bandwidth 32.

| Profile | Half-bandwidth | SciPy factor + solve | Composed prover | Prover / solve |
| --- | ---: | ---: | ---: | ---: |
| 16 queries | 1 | 30.491 ms | 150.551 ms | 4.94x |
| 16 queries | 32 | 247.374 ms | 179.501 ms | 0.73x |
| 512 queries | 1 | 30.491 ms | 159.292 ms | 5.22x |
| 512 queries | 32 | 247.374 ms | 192.992 ms | 0.78x |

The actual recursive encoder adds only a few milliseconds over the prior proxy;
it does not consume the performance budget. On the intended band-32 benchmark,
the complete experimental prover—including the commitment test and residual
sumchecks—remains faster than factorization plus solve. The very narrow band-1
solve remains roughly five times faster than proof construction.

For context, the previous degree-4 proxy measured 142.419 ms and 171.202 ms at
bands 1 and 32, with a 171,128-byte artifact. The recursive experiment is 5.7%
and 4.8% slower at the 16-query cost floor, respectively. Its important gain is
structural, not speed: every input coordinate now participates in the recursive
expander layout and a separate random combination actually tests the committed
codeword.

## What the result does not prove

The experiment has not crossed the central theoretical gap:

- Brakedown's Hamming-distance theorem is over a finite field; the implemented
  coefficients and operations are binary64.
- The dense base code is only a shape-compatible stand-in for exact
  Reed--Solomon encoding.
- Hamming support does not control alteration magnitude. Subnormal, scaling,
  and cancellation attacks can be metrically significant even if a support
  statement holds.
- Honest encode-then-combine and combine-then-encode orders differ. The largest
  sampled defect reached about `2.18e-11` in the 64-row experiments.
- Unit-message enumeration does not find the minimum-weight codeword and cannot
  exclude adversarial linear combinations.
- The conditional sampling curve excludes anti-cancellation and selective-retry
  accounting.

The most useful conclusion is therefore narrower: a faithful recursive
Brakedown *layout* is operationally viable, and the old proxy's obvious
distance failure is gone. Turning it into a certificate now depends on a
binary64 metric authentication theorem, not another encoding optimization.

## Correctness checks

The example tests cover:

- deterministic graph construction and roots;
- exact recursive dimensions and multiplication counts;
- distinct, input-row-regular sparse neighbors;
- equivalence of batched row encoding and independent vector encoding;
- exhaustive unit and two-sparse-message support checks on a tiny code;
- compact multiproof verification and rejection of changed values, missing
  frontier nodes, extra frontier nodes, and changed authentication nodes;
- residual transcript replay and rejection after changing a terminal claim,
  testing combination, or authentication node; and
- invalid shapes and allocation boundaries.

These are implementation checks, not evidence for the missing binary64
distance or metric-proximity theorem.
