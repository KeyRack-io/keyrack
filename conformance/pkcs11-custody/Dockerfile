# Proof fixture: the real keyrack-service binary against a real PKCS#11
# module (SoftHSM2), losing custody of a token and getting it back while the
# process keeps running.
#
# Build context: the keyrack-oss repository root.

FROM rust:1-bookworm AS builder

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

RUN cargo build --release -p keyrack-service --bin keyrack-service

# ---- Runtime ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl jq softhsm2 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/lib/softhsm \
    && ln -sf "$(find /usr/lib -name 'libsofthsm2.so' -path '*/softhsm/*' | head -1)" \
       /usr/lib/softhsm/libsofthsm2.so \
    && mkdir -p /var/lib/softhsm/tokens \
    && echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm/softhsm2.conf

COPY --from=builder /build/target/release/keyrack-service /usr/local/bin/
COPY conformance/pkcs11-custody/keyrack.yaml /config/keyrack.yaml
COPY conformance/pkcs11-custody/proof.sh /usr/local/bin/proof.sh
RUN chmod +x /usr/local/bin/proof.sh

CMD ["/usr/local/bin/proof.sh"]
