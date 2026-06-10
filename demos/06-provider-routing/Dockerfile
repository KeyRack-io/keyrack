# Multi-stage: build KeyRack, then a runtime with SoftHSM2 holding TWO tokens
# (tenant-a, tenant-b) so the service can route keys to different HSM
# partitions via provider routing.
#
# Build context: the keyrack-oss repository root (../.. from this demo dir)

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
COPY examples/ examples/

RUN cargo build --release \
    -p keyrack-service \
    --quiet

# ---- Runtime stage ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        softhsm2 \
        opensc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/lib/softhsm \
    && ln -sf "$(find /usr/lib -name 'libsofthsm2.so' -path '*/softhsm/*' | head -1)" \
       /usr/lib/softhsm/libsofthsm2.so

COPY --from=builder /build/target/release/keyrack-service /usr/local/bin/

# Initialize TWO SoftHSM tokens, one per tenant. Both are driven by the same
# libsofthsm2.so in one process — which only works because keyrack-pkcs11
# shares a single initialized PKCS#11 module per library path.
RUN mkdir -p /var/lib/softhsm/tokens && \
    softhsm2-util --init-token --free --label tenant-a --pin 1234 --so-pin 0000 && \
    softhsm2-util --init-token --free --label tenant-b --pin 5678 --so-pin 0000

EXPOSE 50051 8080

ENV KEYRACK_CONFIG=/config/keyrack.yaml
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

ENTRYPOINT ["keyrack-service"]
