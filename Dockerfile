# Multi-arch Dockerfile for keyrack-service and keyrack-cedar-pdp.
#
# Supports linux/amd64 and linux/arm64 via buildx / QEMU.
#
#   docker buildx build --platform linux/amd64,linux/arm64 -t keyrack-service .
#
# For a single-platform build:
#   docker build -t keyrack-service .
#
# The cedar-pdp binary is also included; override the entrypoint:
#   docker run --entrypoint keyrack-cedar-pdp keyrack-service

# ---- Build stage ----
FROM rust:1.87-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        libprotobuf-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY proto/ proto/

RUN cargo build --release \
    -p keyrack-service \
    -p keyrack-cedar-pdp \
    --quiet

# ---- Runtime stage ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/keyrack-service /usr/local/bin/
COPY --from=builder /build/target/release/keyrack-cedar-pdp /usr/local/bin/

ENV KEYRACK_CONFIG=/etc/keyrack/config.yaml

EXPOSE 50051 8080

ENTRYPOINT ["keyrack-service"]
