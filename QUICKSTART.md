# KeyRack Quickstart

Get KeyRack running and perform your first encrypt/decrypt in under 5 minutes.

---

## Option A: Docker Compose (recommended)

This starts KeyRack with a Cedar PDP for authorization. Requires Docker.

```bash
git clone https://github.com/keyrack/keyrack.git
cd keyrack
docker compose up -d keyrack-service
```

Wait for the health check to pass:

```bash
curl -sf http://localhost:8080/healthz && echo "ready"
```

Then run the end-to-end demo:

```bash
./examples/quickstart.sh
```

Or do it manually:

```bash
# Create an AES-256 key
KEY_ID=$(curl -s http://localhost:8080/v1/keys -X POST \
  -H 'Content-Type: application/json' \
  -d '{"key_spec": "AES_256", "description": "my first key"}' \
  | jq -r '.lid')

echo "Key ID: $KEY_ID"

# Encrypt (plaintext must be base64-encoded)
CIPHERTEXT=$(curl -s "http://localhost:8080/v1/keys/$KEY_ID/actions-encrypt" \
  -X POST -H 'Content-Type: application/json' \
  -d '{"plaintext": "aGVsbG8ga2V5cmFjaw=="}' \
  | jq -r '.ciphertext_blob')

# Decrypt
curl -s "http://localhost:8080/v1/keys/$KEY_ID/actions-decrypt" \
  -X POST -H 'Content-Type: application/json' \
  -d "{\"ciphertext_blob\": \"$CIPHERTEXT\"}" \
  | jq -r '.plaintext' | base64 -d
# Output: hello keyrack
```

To stop: `docker compose down`

---

## Option B: Build from source (no Docker)

Requires Rust 1.80+ and protobuf compiler.

### 1. Build

```bash
git clone https://github.com/keyrack/keyrack.git
cd keyrack
cargo build --release -p keyrack-service
```

### 2. Start the service

With no config file, KeyRack starts with sensible defaults: in-memory
storage, software crypto provider, no authentication, and `always_allow`
authorization. No PDP needed.

```bash
./target/release/keyrack-service
```

The service listens on:
- gRPC: `[::1]:50051`
- REST: `[::1]:8080`

### 3. Use it

```bash
# Create a key
KEY_ID=$(curl -s http://localhost:8080/v1/keys -X POST \
  -H 'Content-Type: application/json' \
  -d '{"key_spec": "AES_256"}' | jq -r '.lid')

# Encrypt
CIPHERTEXT=$(curl -s "http://localhost:8080/v1/keys/$KEY_ID/actions-encrypt" \
  -X POST -H 'Content-Type: application/json' \
  -d '{"plaintext": "aGVsbG8ga2V5cmFjaw=="}' | jq -r '.ciphertext_blob')

# Decrypt
curl -s "http://localhost:8080/v1/keys/$KEY_ID/actions-decrypt" \
  -X POST -H 'Content-Type: application/json' \
  -d "{\"ciphertext_blob\": \"$CIPHERTEXT\"}" | jq -r '.plaintext' | base64 -d
```

---

## Option C: Use as a library

Add `keyrack-core` to your Rust project:

```toml
[dependencies]
keyrack-core = { path = "crates/keyrack-core" }
tokio = { version = "1", features = ["full"] }
```

```rust
use keyrack_core::key::KeySpec;
use keyrack_core::provider::software::SoftwareProvider;
use keyrack_core::provider::CryptoProvider;

#[tokio::main]
async fn main() {
    let provider = SoftwareProvider::new();

    // Generate an AES-256 key
    let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

    // Encrypt
    let ct = provider.encrypt(&handle, b"hello keyrack", b"").await.unwrap();

    // Decrypt
    let pt = provider.decrypt(&handle, &ct.ciphertext, b"").await.unwrap();
    assert_eq!(pt.expose(), b"hello keyrack");

    println!("Round-trip OK: {}", String::from_utf8_lossy(pt.expose()));
}
```

---

## What's next?

- **Production config**: See [docs/OPERATOR.md](docs/OPERATOR.md) for storage, HSM, auth, and PDP setup.
- **Authorization**: Deploy the bundled Cedar PDP or point at your own OPA/Cedar instance. See [docs/CEDAR_STARTER_SCHEMA.md](docs/CEDAR_STARTER_SCHEMA.md).
- **gRPC**: The same operations are available over gRPC on port 50051. See `proto/keyrack/v1/` for the service definition.
- **Signing**: Create an Ed25519 key (`"key_spec": "ED25519"`) and use `/actions-sign` and `/actions-verify`.
- **Encryption context**: Add `"encryption_context": {"purpose": "demo"}` to encrypt/decrypt requests for AAD binding.
- **Key hierarchy**: Use the CLI to define namespace rules and resolve hierarchical key chains.
- **WASM**: Use `keyrack-wasm` for in-browser encrypt/decrypt. See `examples/browser-wasm/`.

---

## Supported key specs

| Spec | Value | Usage |
|---|---|---|
| AES-256-GCM | `AES_256` | Symmetric encrypt/decrypt |
| Ed25519 | `ED25519` | Signing |
| ECDSA P-256 | `ECDSA_P256` | Signing (FIPS) |
| RSA 2048 | `RSA_2048` | Signing (legacy) |
| RSA 3072 | `RSA_3072` | Signing |
| RSA 4096 | `RSA_4096` | Signing |

---

## REST API cheat sheet

| Action | Method | Path |
|---|---|---|
| Create key | `POST` | `/v1/keys` |
| List keys | `GET` | `/v1/keys` |
| Get key | `GET` | `/v1/keys/:id` |
| Describe key | `GET` | `/v1/keys/:id/describe` |
| Encrypt | `POST` | `/v1/keys/:id/actions-encrypt` |
| Decrypt | `POST` | `/v1/keys/:id/actions-decrypt` |
| Sign | `POST` | `/v1/keys/:id/actions-sign` |
| Verify | `POST` | `/v1/keys/:id/actions-verify` |
| Generate data key | `POST` | `/v1/keys/:id/actions-generate-data-key` |
| Rotate | `POST` | `/v1/keys/:id/actions-rotate` |
| Enable | `POST` | `/v1/keys/:id/actions-enable` |
| Disable | `POST` | `/v1/keys/:id/actions-disable` |
| Health | `GET` | `/healthz` |
| Metrics | `GET` | `/metrics` |
