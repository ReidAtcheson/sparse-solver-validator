#!/bin/sh

set -eu

run_tests() {
  name=$1
  compiler=$2
  shift 2

  cmake --fresh -S . -B "build/$name" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER="$compiler" \
    -DBUILD_TESTING=ON \
    "$@"
  cmake --build "build/$name"
  ctest --test-dir "build/$name" --output-on-failure
}

run_tests gcc-16 g++

gcc_install_dir=$(dirname "$(g++ -print-file-name=crtbegin.o)")
run_tests clang-22 clang++-22 \
  "-DCMAKE_CXX_FLAGS=--gcc-install-dir=$gcc_install_dir"
