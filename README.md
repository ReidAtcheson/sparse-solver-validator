# sparse-solver-validator

An initial C++ skeleton for the sparse solver validator redesign.

The project currently exposes only an empty public header. Protocol and API
design will be added separately.

## Build and test in the toolchain container

The container runs the build and tests with GCC 16 and Clang 22, with both
compilers using libstdc++ 16.

```sh
./test.sh
```

## Native build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```
