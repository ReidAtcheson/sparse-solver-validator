# sparse-solver-validator

An initial C++ skeleton for the sparse solver validator redesign.

The project currently exposes only an empty public header and a placeholder test
executable. Protocol and API design will be added separately.

## Build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```
