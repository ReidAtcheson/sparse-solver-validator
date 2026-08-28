#!/bin/sh

set -eu

repository_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
image=localhost/sparse-solver-validator-toolchain:gcc-16.2-clang-22

podman build \
  --file "$repository_dir/Containerfile" \
  --tag "$image" \
  "$repository_dir"

podman run --rm \
  --userns=keep-id \
  --volume "$repository_dir:/workspace" \
  --workdir /workspace \
  "$image" \
  sh toolchain/run-tests.sh
