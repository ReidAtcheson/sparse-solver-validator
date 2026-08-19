# AGENTS.md

This repository is an intentionally minimal C++ skeleton.

## Priorities

1. Correctness and memory safety.
2. Measured performance on representative workloads.
3. Predictable memory use and good data locality.
4. Clear APIs and maintainable implementations.

Do not invent protocol APIs before their requirements are agreed. Keep changes
small, use standard C++ where practical, and avoid dependencies without a clear
need.

## C++ practices

- Target the C++20 language standard.
- Prefer value semantics, RAII, and explicit ownership.
- Avoid raw owning pointers and unchecked arithmetic at input boundaries.
- Keep public headers self-contained and minimize what they expose.
- Add tests for new behavior and regression tests for fixes.
- Benchmark before and after performance-sensitive changes using release builds.

## Checks

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```
