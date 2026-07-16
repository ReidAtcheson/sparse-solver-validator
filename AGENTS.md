# AGENTS.md

This file defines the engineering expectations for all Rust code in this
repository. Apply it to every crate unless a more specific `AGENTS.md` in a
subdirectory overrides part of it.

## Priorities

In order of importance:

1. Correctness and memory safety.
2. Measured performance on representative workloads.
3. Predictable memory use and good data locality.
4. Clear APIs and maintainable implementations.

Do not trade correctness or a clear ownership model for speculative speed.
When performance motivates a non-obvious design, document the workload and
measurement that justify it.

## Workflow

- Inspect nearby code and existing abstractions before adding new ones.
- Make the smallest coherent change that solves the problem.
- Keep unrelated cleanup out of feature and bug-fix patches.
- Before optimizing, identify the hot path and establish a benchmark or
  profile. Preserve benchmark inputs so results remain comparable.
- Validate optimized code against a simple reference implementation when
  practical.
- Run formatting, linting, tests, and relevant benchmarks before considering
  work complete.

Typical checks are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --doc
```

Use release builds for performance measurements. Never draw performance
conclusions from debug builds.

## Data-Oriented Design

- Prefer flat, contiguous storage such as `Vec<T>`, boxed slices, and compact
  index arrays over pointer-rich trees, linked lists, or deeply nested
  collections.
- Prefer indices or stable typed IDs over internal references when they make
  ownership simpler and allow data to remain contiguous.
- Consider structure-of-arrays storage when hot loops consume only a subset of
  a record's fields. Use array-of-structures when fields are normally accessed
  together. Let access patterns decide.
- Keep hot data compact. Move rarely used metadata, diagnostics, and optional
  payloads out of frequently traversed records when doing so improves cache
  behavior.
- Avoid per-element heap allocations. Batch allocations, reserve known
  capacity, and reuse scratch buffers in repeated operations.
- Avoid unnecessary cloning and intermediate collections. Prefer iterators,
  slices, and writing into caller-provided or reusable output buffers where
  this remains readable.
- Use sparse and compressed representations when density warrants them, but
  document invariants such as ordering, uniqueness, and index bounds.
- Choose integer widths deliberately. Narrow indices can reduce memory traffic,
  but conversions must be checked at construction boundaries.
- Do not introduce an abstraction that hides important allocation, copying, or
  traversal costs in a hot path.

## Performance Practices

- Optimize algorithms and memory access patterns before low-level instruction
  tweaks.
- Keep hot loops simple and make bounds, aliasing, and mutation patterns easy
  for the compiler to understand.
- Hoist validation and invariant checks out of inner loops when inputs can be
  validated once at a safe boundary.
- Prefer monomorphized generics for small, performance-critical abstractions.
  Use dynamic dispatch when flexibility is worth its runtime and locality cost.
- Be alert to accidental allocations from `collect`, `format!`, implicit
  conversions, temporary `String`s, and repeated growth of collections.
- For parallel code, account for scheduling overhead, false sharing,
  synchronization, determinism, and the size at which parallelism becomes a
  win. Retain a serial path when appropriate.
- Treat I/O, parsing, and serialization as part of the performance profile.
  Stream or buffer them intentionally rather than assuming computation is the
  only bottleneck.
- Benchmark throughput and latency as appropriate, and record memory usage when
  representation is part of the change.
- Compare against a meaningful baseline and report input sizes, build profile,
  hardware-relevant details, and variance. A single timing is not evidence.

## Rust Practices

- Use stable Rust unless the repository explicitly pins nightly and documents
  why it is required.
- Express invariants in types and constructors. Keep fields private when direct
  mutation could violate those invariants.
- Prefer borrowing (`&T`, `&mut T`, slices) over transferring ownership when
  ownership is not needed.
- Prefer concrete error types for libraries and add context at application
  boundaries. Do not use `unwrap` or `expect` for recoverable failures.
- `panic!` is acceptable only for violated internal invariants or genuinely
  unrecoverable programmer errors; make the invariant clear.
- Use exhaustive matching when new enum variants should force callers to make
  a decision.
- Keep public APIs small. Add `#[must_use]` where silently discarding a result
  is likely to be a bug, and document public items and non-obvious invariants.
- Avoid global mutable state. Make ownership, synchronization, and lifetime of
  shared resources explicit.
- Keep dependencies minimal and review their maintenance status, feature flags,
  compile-time cost, and runtime implications. Disable unused default features.
- Do not silence Clippy lints broadly. Apply narrow exceptions with a comment
  explaining why the lint is inappropriate there.

## Unsafe Code

- Prefer safe Rust. Introduce `unsafe` only when profiling demonstrates a
  meaningful need or when required for FFI or a low-level abstraction.
- Encapsulate unsafe operations behind a small safe API.
- Every unsafe block must have a nearby `SAFETY:` comment explaining all
  required invariants and why they hold at that point.
- Test boundary conditions aggressively. Run Miri and sanitizers where they are
  applicable to changed unsafe or concurrent code.
- An unsafe optimization must have benchmarks showing its value and tests that
  compare it with a safe or obviously correct implementation.

## Correctness and Testing

- Add unit tests for local invariants and integration tests for public behavior.
- Cover empty inputs, singleton inputs, maximum/minimum values, malformed data,
  overflow boundaries, and aliasing or ordering assumptions as applicable.
- Use property-based tests for parsers, indexing schemes, sparse structures,
  numerical invariants, and optimized/reference implementation equivalence.
- For floating-point code, define the expected tolerance and justify absolute,
  relative, or ULP-based comparisons. Do not assert exact equality unless the
  operation guarantees it.
- Regression tests should fail before the fix and describe the behavior being
  protected.
- Keep tests deterministic. If randomness is useful, use reproducible seeds and
  report the seed on failure.

## Numerical and Sparse-Data Code

- Document matrix layout, index base, dimensions, ordering, duplicate-entry
  policy, and symmetry assumptions at API boundaries.
- Validate structural invariants when constructing a representation, then rely
  on the validated type internally rather than rechecking every access.
- Distinguish structural zeros from stored numerical zeros where it affects
  algorithms or performance.
- Handle integer overflow in dimension, offset, and allocation calculations
  explicitly with checked arithmetic at untrusted boundaries.
- State numerical stability expectations. Include ill-conditioned, singular,
  degenerate, and scale-separated cases when relevant.
- Avoid hidden dense fallbacks or unexpectedly superlinear temporary storage.
  If an algorithm can change complexity based on input structure, document it.

## Documentation and Review

- Explain why a design was chosen, especially for custom layouts, unsafe code,
  concurrency, or counterintuitive optimizations. Do not narrate obvious syntax.
- Include complexity and allocation behavior in documentation for important
  algorithms and public operations.
- In performance-sensitive reviews, look specifically for allocation count,
  data layout, iteration order, branch behavior, synchronization, and copies.
- Treat benchmark regressions like test regressions. If a regression is an
  intentional tradeoff, quantify it and record the rationale.

## Definition of Done

A change is complete when it is formatted, warning-free under Clippy, covered
by appropriate tests, and documented where behavior or invariants are not
obvious. Performance-sensitive changes must also include reproducible evidence
that they improve the intended workload without unacceptable regressions or
memory growth.
