# Resumable benchmark runner

`sparse-benchmark` turns one immutable benchmark configuration into independent,
recoverable problem runs. It owns challenge acquisition, problem finalization,
optional Matrix Market materialization, proof construction, service submission,
and portable result-card construction. A solver owns only `x.json`.

The runner is intentionally staged. It does not keep a daemon or a mutable
global database. Each run directory is its transaction boundary, and every
transition writes bounded typed artifacts before atomically updating
`state.json`.

## 1. Benchmark configuration

A configuration fixes a benchmark identifier, an authority, a complete problem
template, and one validation manifest. Its digest covers all of these fields.
The exact configuration is copied into every run and is also embedded in the
result card.

Local authority uses the template's literal seed. The complete checked-in
example is
[`examples/benchmark-local.json`](../examples/benchmark-local.json).

Remote authority replaces the literal seed with challenge-derived randomness
and pins the service identity independently of its HTTP responses:

```json
{
  "kind": "remote-v1",
  "service_url": "https://validator.example",
  "issuer": "public-benchmark-validator",
  "key_id": "benchmark-key-v1",
  "public_key": "64-lowercase-hexadecimal-characters",
  "authentication": {
    "kind": "gcloud-identity-token-v1",
    "audience": null
  },
  "maximum_future_skew_seconds": 30,
  "maximum_challenge_lifetime_seconds": 3600
}
```

Use `{ "kind": "none-v1" }` authentication for a public service. Private
Cloud Run mode invokes `gcloud auth print-identity-token` immediately before
each HTTP request; tokens are neither printed nor persisted. A server on
localhost still uses `remote-v1` when signed service evidence is wanted.

Remote templates must use `challenge-derived-v1`; local templates must use
`literal-v1`. The runner rejects a template whose dimension or public evaluator
terms exceed its manifest.

## 2. Start, solve, and resume

Build release binaries before a measured run. Then create one problem:

```sh
target/release/sparse-benchmark start \
  --config benchmark.json \
  --runs-dir runs
```

The default `--materialize matrix-and-rhs` writes `public/A.mtx` and
`public/b.mtx`. The other modes are `matrix-only`, `rhs-only`, and `none`.
`public/problem.json` is always written, so a custom-format or matrix-free
solver can use the registered generator API without paying the export cost.

The first invocation exits at `awaiting-solution` and prints exact paths. Write
one finite value per unknown to the indicated file:

```json
{
  "schema": "sparse-solve/solution/binary64-v1",
  "values": ["1.0", "-2.5", "0"]
}
```

Then advance the same run:

```sh
target/release/sparse-benchmark resume runs/run-UNIXTIME-PID
```

The runner validates `x.json`, constructs and locally verifies the selected
proof, submits it when authority is remote, authenticates every signed and
digest-bound field, and writes `result-card.json`. `status` is read-only and
`card` authenticates an existing card or reconstructs a missing card from a
completed validation:

```sh
target/release/sparse-benchmark status runs/run-UNIXTIME-PID
target/release/sparse-benchmark card runs/run-UNIXTIME-PID
```

Starting the same configuration again creates an independent directory and,
for remote authority, an independent signed problem. There is no mutable global
run index; a caller can list or archive the flat run directories directly.

## 3. Recovery semantics

The durable stages are `created`, `challenge-issued`, `problem-ready`,
`awaiting-solution`, `proof-ready`, `certificate-received`, and `complete`.
`resume` validates the configuration digest and all applicable artifact digests
before advancing.

- A missing `x.json` leaves the run at `awaiting-solution` and prints the handoff
  again.
- A network failure after proof construction retains the exact proof for a safe
  retry. The stateless service's `replay-allowed-v1` policy permits this.
- A received certificate is reused; only card construction is repeated.
- Changing `x.json` after proof construction is rejected instead of silently
  producing a different submission.
- An expired challenge is never renewed in place. Fresh signed entropy would
  define a different `A,b`, so the old run is preserved and the participant must
  explicitly start and solve a new run.
- An advisory file lock prevents two runner processes from advancing the same
  run concurrently.

The challenge issue time precedes finalization and optional export. It is not a
precise solver-start timestamp. A remote card provides signed challenge and
certificate times; any finer solver timing remains participant-reported unless
a separate trusted execution policy is introduced.

## 4. Result cards and trust

The JSON card embeds the benchmark configuration, derived problem summary,
proof digest, and authority evidence. Remote evidence contains the original
signed challenge and signed validation certificate. The proof bytes and
solution values are deliberately omitted.

Remote card verification checks:

- the externally pinned benchmark configuration digest;
- challenge and certificate signatures under the configured public key;
- issuer, key ID, challenge lifetime, and certification time;
- template-to-challenge and challenge-to-instance derivation;
- problem, manifest, protocol, and proof digest bindings; and
- the typed protocol-specific certified score.

Always supply the benchmark configuration through an independent channel when
verifying a card. Trusting the public key embedded in an unpinned card would
only establish self-consistency:

```sh
target/release/sparse-benchmark verify-card result-card.json \
  --benchmark benchmark.json
```

Local cards reuse the same problem and score validation but report
`server_attested=false`; without a signed certificate they are reproducible
local records, not issuer-attested credentials. A card without its proof can
authenticate what the remote validator certified, but cannot independently
rerun the proof verification.
