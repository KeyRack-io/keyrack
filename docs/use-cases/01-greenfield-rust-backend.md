# Use Case: Greenfield Rust Backend

## Who

Backend engineers building a new service or platform in Rust who need
key management from day one.

**Examples:** cloud platforms, SaaS startups, fintech services,
any Rust service that handles sensitive data.

## The problem

You need to encrypt data at rest, sign things, manage key rotation, and
prove to auditors that you do it properly. Building this yourself means:

- Choosing and integrating cryptographic libraries
- Designing key lifecycle and rotation
- Building audit trails
- Wiring up HSM support when compliance requires it
- All of the above being correct from a security standpoint

## How KeyRack helps

KeyRack is a Rust-native KMS. It ships as both a standalone service (gRPC/REST)
and an embeddable library (`keyrack-core`).

### As a service

```bash
# Start KeyRack
docker compose up -d keyrack-service

# From your application, use gRPC or REST
curl -s http://localhost:8080/v1/keys -X POST \
  -d '{"key_spec": "AES_256", "description": "user-data-dek"}'
```

Your app talks to KeyRack over the network. KeyRack handles key storage,
rotation, audit events, and HSM integration. You just call encrypt/decrypt.

### As a library

```toml
[dependencies]
keyrack-core = "0.1"
```

```rust
use keyrack_core::provider::software::SoftwareProvider;
use keyrack_core::provider::CryptoProvider;

let provider = SoftwareProvider::new();
let key = provider.generate_key(&KeySpec::Aes256).await?;
let ct = provider.encrypt(&key, plaintext, aad).await?;
```

Embed key management directly in your binary. Swap in `Pkcs11Provider` or
`KmipProvider` for HSM-backed production deployments without changing
application code.

## Fit rating

**Excellent.** This is KeyRack's primary use case. The API, libraries, and
documentation are designed for this scenario.

## What's ready today (v0.1)

- Full key lifecycle over gRPC and REST
- AES-256-GCM, Ed25519, ECDSA P-256, RSA 2048/3072/4096
- Software and PKCS#11 providers
- KMIP client for external HSMs
- Encryption context (AAD) binding
- Key hierarchy and dependency tracking
- Cooperative rotation protocol
- Prometheus metrics and structured audit events
- Docker Compose quickstart

## What's missing for production

- Published crates on crates.io
- Stable API guarantees (pre-1.0)
- Production deployment guides (multi-node, HA)
- SDK wrapper (currently raw gRPC/REST)
