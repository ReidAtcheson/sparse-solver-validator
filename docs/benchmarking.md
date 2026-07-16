# Benchmarking and performance claims

**Status:** measurement protocol. This repository does not yet publish a
current-revision benchmark result set.

The research implementation's validated-solution post contains useful historical
exact and fast measurements. Those values were produced by different code,
dependencies, compilers, and in some cases different machines. They are external
comparison targets, not measurements of this repository.

## 1. Questions a benchmark must answer

Measure the direct, exact, and fast profiles separately. A useful report answers:

1. How much prover work, wall time, and peak memory are required?
2. How much verifier work, wall time, and peak memory are required?
3. How many bytes cross the trust boundary?
4. Does the succinct verifier avoid matrix/RHS scans and private-vector
   materialization?
5. At what problem size, if any, is the complete proof exchange smaller than
   transmitting binary64 `x`?
6. Does an optimization improve the intended workload without changing protocol
   bytes, acceptance, numerical policy, or memory elsewhere?

A debug build, one timing, an internal allocation estimate, or a result copied
from the research repository does not answer these questions.

## 2. Required baselines

### 2.1 Raw solution transport

For a dimension-`n` binary64 solution, the transport baseline is:

```text
raw_solution_bytes = 8 * n.
```

This is independent of the solver-facing JSON file, whose decimal text and
framing are not the comparison of interest. Report:

```text
proof_to_solution_ratio = transmitted_proof_bytes / raw_solution_bytes.
```

For exact and fast mode, `transmitted_proof_bytes` is the complete outer
artifact. The fast artifact already contains its canonical precommitment; a
precommitment file produced by the diagnostic staged commands is not an
additional wire object. Report the ordinary signed problem challenge separately
when measuring hosted operation, and state whether it is amortized across more
than one submission.

### 2.2 Direct validation

`direct-reference-v1` is the integration and relation-check baseline. Report its
artifact size, validation time, RSS, rows visited, and nonzeros visited. It is
expected to transmit `x` and scan `A`; it is not a succinct competitor.

Direct binary64 residuals and exact Q63.64 residuals have different semantics for
some inputs. Compare only after applying the profile's documented conversion, or
state the difference rather than treating it as an error.

### 2.3 Research implementation

When comparing with `sparse-solution-stark`, run both repositories on the same
machine, compiler policy, thread count, problem generator/version, seed,
dimension, and solution whenever possible. Record both commit IDs. If generator
or protocol versions differ, call the result a historical comparison rather than
a regression measurement.

Never compute a speedup from runs made on different processors. Proof sizes may
still be compared if the exact protocol versions and framing inclusions are
identified.

## 3. Fixed benchmark matrix

Use powers of two spanning small overhead-dominated cases through the largest
case that fits the prover resource budget. A typical sequence is:

```text
2^10, 2^11, ..., 2^20
```

For every row of a comparison table, freeze and report:

- problem-template bytes and digest;
- finalized problem digest and seed origin;
- matrix/RHS generator and versions;
- matrix and RHS periodic term counts;
- validation manifest bytes and digest;
- backend and all protocol versions;
- solution digest and how `x` was obtained; and
- whether the public statement uses a literal local problem or a signed hosted
  problem challenge. Proof challenges in both cases are noninteractive
  Fiat--Shamir challenges.

Use one deterministic seed series for regression benchmarks. Random exploratory
runs are useful only when the seed is recorded and failures reproduce.

Include at least:

- an exact manufactured zero-residual solution;
- a deterministic nonzero-residual solution;
- dimensions just below and above powers of two to exercise padding;
- the largest allowed public periods; and
- scale-separated values near profile range and numerical-policy boundaries.

## 4. Build and machine record

Build before timing:

```sh
cargo build --release --workspace --all-features
```

Every published table records:

- repository commit and dirty-worktree status;
- `Cargo.lock` hash and relevant pinned dependency revisions;
- `rustc -Vv` output and target triple;
- release profile and enabled features;
- CPU model, physical/logical core count, RAM, swap policy, OS, and kernel;
- `RAYON_NUM_THREADS` and service validation concurrency;
- power/performance governor or cloud VM type when known; and
- exact command lines and environment.

Build and dependency-download time are not prover or validator time. Run the
already-built binaries from `target/release`.

## 5. Process measurements

Run prove, verify, and service tests as separate processes so allocator history
from one phase does not contaminate another phase's peak RSS. When measuring the
fast implementation stages, also run `fast-commit` and `fast-prove` as separate
processes. On Linux, an initial portable method is:

```sh
/usr/bin/time -v target/release/<binary> <recorded arguments>
```

Record at least:

- wall time;
- user and system CPU time;
- maximum resident set size;
- artifact and auxiliary object bytes; and
- backend-reported deterministic work counters.

`accounted_high_watermark_bytes` is useful implementation accounting. It is not
process RSS and must not be labeled as such. Likewise, a payload decoder's byte
limit is not a measured memory bound.

Perform one untimed warm-up when cache state is intentionally warm, followed by
at least five measured runs. Report median and a spread such as minimum/maximum
or interquartile range. If cold-cache or first-request service latency matters,
measure and label it separately rather than mixing it with warm runs.

## 6. Phase-specific metrics

### 6.1 Problem generation and direct path

Report template/finalization time, generator compilation time, Matrix Market
export throughput when relevant, direct relation time, rows/nonzeros visited, and
RSS. Do not include dense materialization unless it is the operation being
benchmarked.

### 6.2 Exact path

Report:

- relation and matvec sparse nonzeros visited by the prover;
- range rows, sumcheck rounds, field elements, and combine evaluations;
- WHIR encode, commit, opening, and verification work where exposed;
- complete artifact bytes;
- prover and validator RSS and wall time; and
- exact numerator and denominator-power agreement with the independent fixed
  relation.

The exact verifier regression conditions are:

```text
generator_row_queries == 0
solution_elements_materialized == 0
residual_elements_materialized == 0
```

Also report matrix and RHS public-evaluator term counts and arithmetic operations.

### 6.3 Fast path

Use one-step `sparse-prover prove` for user-visible latency, RSS, and artifact
size. To compare phase costs with the research implementation or isolate memory
peaks, additionally measure local `fast-commit` and `fast-prove` as separate
processes and report their maximum RSS individually as well as the maximum of the
two. These commands implement the same noninteractive transcript and introduce
no issuer interaction. Report:

- complete artifact bytes and, when staged measurements are included, the
  diagnostic precommitment-file bytes without adding them to transmitted bytes;
- codeword length and the 1-to-64 distinct recursive query trajectories reused
  across rounds;
- sumcheck rounds and scalar values;
- opening paths and Merkle hashes;
- four defect summaries and consistency-policy result;
- residual squared L2; and
- commit, prove, and verify time/RSS.

The fast verifier regression conditions are:

```text
generator_row_queries == 0
solution_elements_materialized == 0
residual_elements_materialized == 0
codeword_elements_materialized == 0
```

Conditional miss-probability curves are protocol diagnostics, not benchmark
success probabilities and not a global soundness claim.

### 6.4 HTTP service

Measure core verification and end-to-end HTTP latency separately. The latter may
include upload, queueing, TLS/proxy, cold start, and certificate signing. Report
request size, configured body limit, timeout, concurrency, instance resources,
warm/cold status, response size, and whether the client and service share a
region.

If deployment policy limits repeated submissions under one signed problem
challenge, report the quota, authentication, expiry, rate limiting, and logging
configuration used by the load test. Those infrastructure controls are distinct
from the noninteractive proof transcript.

## 7. Correctness gates before recording a number

Every measured artifact must pass the independent validator. Additionally:

- exact results match the proof-independent fixed relation exactly;
- fast results pass structural verification and the frozen consistency policy;
- fast residual and defect data are retained even when comparing with exact;
- the expected problem, manifest, proof, and challenge digests match;
- strict EOF and mutation tests remain green; and
- succinct-verifier no-scan/materialization counters remain zero.

Discard and investigate a run that fails these gates. Do not average failed and
accepted proofs together.

## 8. How to state results

A performance claim includes its scope in the same paragraph. For example:

```text
On <hardware>, at <commit>, with <threads> and <problem digest>, the release
<backend/version> verifier had median <time> over <runs>, measured peak RSS
<memory>, and consumed an artifact of <bytes>. The verifier reported zero row
queries and <public evaluator work>.
```

Avoid statements such as “the validator uses constant memory,” “the fast path is
N times faster,” or “proofs are smaller than solutions” without the tested size
range, included wire objects, hardware, and measurements. Algorithmic interfaces
can guarantee no row scan; actual RSS and crossover points still require data.

Treat proof-size, validator-memory, and verifier-work regressions like test
regressions. If a change intentionally trades one resource for another, quantify
both and record the rationale.
