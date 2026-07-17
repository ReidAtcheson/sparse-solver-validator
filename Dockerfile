# syntax=docker/dockerfile:1

FROM rust:1.97.0-bookworm AS builder

WORKDIR /workspace

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY bins ./bins

RUN cargo build --locked --release --bin sparse-validator-server

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder --chown=nonroot:nonroot \
    /workspace/target/release/sparse-validator-server \
    /usr/local/bin/sparse-validator-server

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/sparse-validator-server"]
CMD ["serve"]
