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
