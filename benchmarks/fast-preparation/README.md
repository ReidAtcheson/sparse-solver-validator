# Fast preparation benchmark fixture

This deterministic fixture compares ordinary one-step fast proving with the
checkpointable `fast-commit` and `fast-prove` stages. It uses dimension
`131072`, literal seed `01…01`, the checked-in fast validation manifest, and the
manufactured `x = 1` solution.

The expected template digest is
`095985b21ecf2f0fe656e61cf23cc8bb0e48b5cb6f489f4d75fddfc4a96e82a8`;
the finalized problem digest is
`1a893866ecc03b5c6b2579f1baa2f36d6cf23512945644edf561cb386e47cd92`.

Build and generate the inputs:

```sh
cargo +stable build --release --workspace --all-features --locked

target/release/sparse-problem finalize-local \
  --template benchmarks/fast-preparation/template.json \
  --problem /tmp/ssv-fast-preparation-problem.json

target/release/sparse-problem manufactured-solution \
  --problem /tmp/ssv-fast-preparation-problem.json \
  --solution /tmp/ssv-fast-preparation-solution.json
```

Measure the ordinary operation as one process:

```sh
RAYON_NUM_THREADS=1 /usr/bin/time -v \
  target/release/sparse-prover prove \
  --problem /tmp/ssv-fast-preparation-problem.json \
  --validation examples/fast-validation.json \
  --solution /tmp/ssv-fast-preparation-solution.json \
  --proof /tmp/ssv-fast-preparation-one-step.proof
```

Measure the checkpointable stages as separate processes:

```sh
RAYON_NUM_THREADS=1 /usr/bin/time -v \
  target/release/sparse-prover fast-commit \
  --problem /tmp/ssv-fast-preparation-problem.json \
  --validation examples/fast-validation.json \
  --solution /tmp/ssv-fast-preparation-solution.json \
  --precommitment /tmp/ssv-fast-preparation.precommitment

RAYON_NUM_THREADS=1 /usr/bin/time -v \
  target/release/sparse-prover fast-prove \
  --problem /tmp/ssv-fast-preparation-problem.json \
  --validation examples/fast-validation.json \
  --solution /tmp/ssv-fast-preparation-solution.json \
  --precommitment /tmp/ssv-fast-preparation.precommitment \
  --proof /tmp/ssv-fast-preparation-staged.proof
```

Run one untimed warm-up and at least five measured repetitions. For staged wall
time, add the two phase times. For staged peak RSS, report the larger phase
maximum rather than adding them. Verify every resulting artifact and record the
commit, toolchain, hardware, thread count, proof digest, and deterministic work
counters alongside the timing summary.

For process-wide allocation counts and allocated bytes, run the same one-step
command under Valgrind:

```sh
RAYON_NUM_THREADS=1 valgrind \
  --tool=memcheck \
  --leak-check=no \
  --track-origins=no \
  target/release/sparse-prover prove \
  --problem /tmp/ssv-fast-preparation-problem.json \
  --validation examples/fast-validation.json \
  --solution /tmp/ssv-fast-preparation-solution.json \
  --proof /tmp/ssv-fast-preparation-valgrind.proof
```

## Issue 8 folding and allocation result

The issue 8 implementation at `8d6a88960b09` was compared with `main` at
`7a15517b3c9d`. Both builds used stable Rust 1.97.0 in release mode, one Rayon
thread, and the fixture above. Measurements ran on Linux 7.0.11 with an Intel
Core i7-1360P. Five timed repetitions followed one untimed warm-up; Valgrind
3.22.0 supplied the process-wide allocation totals.

| Metric | `main` | Issue 8 change | Difference |
| --- | ---: | ---: | ---: |
| Median wall time | 1.64 s | 1.15 s | -29.9% |
| Wall-time range | 1.57–1.70 s | 1.12–1.18 s | — |
| Median peak RSS | 31,592 KiB | 27,268 KiB | -13.7% |
| Peak-RSS range | 31,448–31,872 KiB | 27,036–27,348 KiB | — |
| Heap allocations | 2,955 | 1,114 | -62.3% |
| Bytes allocated | 55,910,710 | 33,447,975 | -40.2% |
| Codeword folds | 36 | 18 | -50.0% |
| Complete Merkle-root computations | 56 | 19 | -66.1% |

The optimized prover additionally reports 18 root-free multiproof scans, one
per retained nonconstant folding level. The old multiproof scans reconstructed
the root and are included in its 56 complete root computations.

`cmp` confirmed identical artifacts. Both have proof digest
`6c4b3425ed9367773b4c9d256fca3fb24fef0a4dcf39c94488bece43352b9255`
and artifact SHA-256
`105be9b27454150c3ec99b4243318e13d96a6cd7b4fa2b56cdd4191fc32d01f9`.
The optimized artifact also passed `sparse-validator verify --allow-literal`.
