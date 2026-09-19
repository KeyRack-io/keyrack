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

The crate is not published on crates.io. Use the pinned git dependency below.

```toml
[dependencies]
keyrack-core = { git = "https://github.com/KeyRack-io/keyrack.git", rev = "70bf446def1cac32881e5e24d36f653551cdc25f" }
tokio = { version = "1", features = ["macros", "rt"] }
```

```rust
use keyrack_core::key::KeySpec;
use keyrack_core::provider::software::SoftwareProvider;
use keyrack_core::provider::CryptoProvider;

#[tokio::main(flavor = "current_thread")]
async fn main() -> keyrack_core::error::Result<()> {
    // Development only: this provider loses its keys when the process exits.
    let provider = SoftwareProvider::new();
    let key = provider.generate_key(&KeySpec::Aes256).await?;
    let plaintext = b"secret data";
    let aad = b"example context";
    let ct = provider.encrypt(&key, plaintext, aad).await?;
    let pt = provider.decrypt(&key, &ct.ciphertext, aad).await?;
    assert_eq!(pt.expose().as_slice(), plaintext);
    Ok(())
}
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
