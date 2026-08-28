FROM docker.io/library/gcc:16.2.0-trixie

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake \
        curl \
        ninja-build \
    && install -d -m 0755 /etc/apt/keyrings \
    && curl --fail --location --silent --show-error \
        https://apt.llvm.org/llvm-snapshot.gpg.key \
        --output /etc/apt/keyrings/apt.llvm.org.asc \
    && rm -rf /var/lib/apt/lists/*

COPY toolchain/llvm.list /etc/apt/sources.list.d/llvm.list

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang-22 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
