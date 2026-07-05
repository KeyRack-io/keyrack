# KeyRack Developer Guide

Using the library, authoring shims, and extending providers.

---

## Using `keyrack-core` directly

Add to your `Cargo.toml`:

```toml
[dependencies]
keyrack-core = "0.3"
```

### Resolving a key hierarchy

```rust
use keyrack_core::rule::RuleRegistry;
use keyrack_core::resolver::{resolve_chain, ResolverConfig};
use std::collections::BTreeMap;

// Load namespace definitions
let yaml = std::fs::read_to_string("namespaces.yaml")?;
let registry = RuleRegistry::from_yaml(&yaml)?;

// Resolve a hierarchy chain for an attribute set
let attrs = BTreeMap::from([
    ("kind".to_string(), "dek".to_string()),
    ("user".to_string(), "alice".to_string()),
]);
let config = ResolverConfig::default();
let chain = resolve_chain(&registry, &attrs, &config)?;
// chain: [leaf_lid, ..., root_lid]
```

### Computing a Logical ID (LID)

```rust
use keyrack_core::attr::{AttributeSet, AttributeValue};
use keyrack_core::canon::{canonicalize, CanonicalizationVersion};
use keyrack_core::lid::Lid;

let mut attrs = AttributeSet::new();
attrs.insert("tenant", AttributeValue::String("acme".into()));
attrs.insert("kind", AttributeValue::String("root".into()));

let form = canonicalize(CanonicalizationVersion::V1, &attrs);
let lid = Lid::derive(CanonicalizationVersion::V1, &form);
println!("LID: {lid}"); // lid:a1b2c3...
```

### Encrypt / Decrypt with the software provider

```rust
use keyrack_core::key::KeySpec;
use keyrack_core::provider::software::SoftwareProvider;
use keyrack_core::provider::CryptoProvider;

let provider = SoftwareProvider::new();
let handle = provider.generate_key(&KeySpec::Aes256).await?;

let ct = provider.encrypt(&handle, b"secret data", b"context").await?;
let pt = provider.decrypt(&handle, &ct.ciphertext, b"context").await?;
assert_eq!(pt.expose().as_slice(), b"secret data");
```

---

## Writing a custom `CryptoProvider`

Implement the `CryptoProvider` trait to integrate a new key backend:

```rust
use keyrack_core::provider::{CryptoProvider, KeyHandle, EncryptOutput, SigningAlgorithm};
use keyrack_core::key::KeySpec;
use keyrack_core::sensitive::Sensitive;
use keyrack_core::error::Result;
use async_trait::async_trait;

pub struct MyHsmProvider { /* ... */ }

#[async_trait]
impl CryptoProvider for MyHsmProvider {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        // Call your HSM's key generation API
        todo!()
    }

    async fn encrypt(&self, handle: &KeyHandle, plaintext: &[u8], aad: &[u8]) -> Result<EncryptOutput> {
        todo!()
    }

    async fn decrypt(&self, handle: &KeyHandle, ciphertext: &[u8], aad: &[u8]) -> Result<Sensitive<Vec<u8>>> {
        todo!()
    }

    async fn sign(&self, handle: &KeyHandle, algorithm: SigningAlgorithm, message: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }

    async fn verify(&self, handle: &KeyHandle, algorithm: SigningAlgorithm, message: &[u8], signature: &[u8]) -> Result<bool> {
        todo!()
    }

    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        todo!()
    }

    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()> {
        todo!()
    }
}
```

The `generate_data_key` and `re_encrypt` methods have default implementations that compose `generate_random`+`encrypt` and `decrypt`+`encrypt` respectively. Override them if your HSM supports atomic operations.

---

## Writing a custom `StorageBackend`

Implement `StorageBackend` to add a new persistence layer:

```rust
use keyrack_core::storage::{StorageBackend, KeyFilter, Page, AliasRecord};
use keyrack_core::key::KeyRecord;
use keyrack_core::lid::Lid;
use keyrack_core::error::Result;
use async_trait::async_trait;

pub struct MyStorage { /* ... */ }

#[async_trait]
impl StorageBackend for MyStorage {
    async fn ping(&self) -> Result<()> { todo!() }
    async fn create_key(&self, record: &KeyRecord) -> Result<()> { todo!() }
    async fn get_key(&self, lid: &Lid) -> Result<KeyRecord> { todo!() }
    async fn update_key(&self, record: &KeyRecord) -> Result<()> { todo!() }
    async fn list_keys(&self, filter: &KeyFilter) -> Result<Page<KeyRecord>> { todo!() }
    async fn create_alias(&self, alias: &AliasRecord) -> Result<()> { todo!() }
    async fn delete_alias(&self, alias_name: &str) -> Result<()> { todo!() }
    async fn resolve_alias(&self, alias_name: &str) -> Result<Lid> { todo!() }
    async fn list_aliases(&self, filter: &KeyFilter) -> Result<Page<AliasRecord>> { todo!() }
}
```

---

## Writing a custom `AuditSink`

```rust
use keyrack_core::audit::{AuditSink, AuditEvent};
use keyrack_core::error::Result;
use async_trait::async_trait;

pub struct MyAuditSink { /* ... */ }

#[async_trait]
impl AuditSink for MyAuditSink {
    async fn emit(&self, event: &AuditEvent) -> Result<()> {
        // Forward to your SIEM, logging pipeline, etc.
        todo!()
    }
}
```

---

## PII tokenization

The `keyrack-pii` crate provides helpers for tokenizing PII before
passing it as a key attribute, using a BLAKE3-based tokenizer.

---

## WASM usage

The `keyrack-wasm` crate provides JS/TS bindings:

```js
import init, { WasmKeyRack } from "keyrack-wasm";
await init();

const kr = new WasmKeyRack();
const keyId = await kr.generateKey("AES_256");
const ct = await kr.encrypt(keyId, plaintext, new Uint8Array());
const pt = await kr.decrypt(keyId, ct, new Uint8Array());
```

---

## Linting namespace files

Use the CLI to validate namespace YAML before deployment:

```bash
keyrack lint --file namespaces.yaml
keyrack lint --file namespaces.yaml --format=json  # machine-readable
```

Exit codes: 0 = clean, 1 = warnings only, 2 = errors found.

---

## Project structure

```
keyrack-core/        # Library: types, traits, canonicalization, LID, providers
keyrack-service/     # gRPC + REST server binary
keyrack-cedar-pdp/   # Optional Cedar PDP companion
keyrack-cli/         # CLI tools: lint, provision, admin, migrate
keyrack-pii/         # PII tokenization helper (BLAKE3 tokenizer)
keyrack-wasm/        # WASM target + JS/TS bindings
keyrack-sqlite/      # SQLite storage backend
keyrack-postgres/    # PostgreSQL storage backend
keyrack-pkcs11/      # PKCS#11 HSM provider
keyrack-kmip/        # KMIP HYOK provider
keyrack-nats/        # NATS audit sink
```
