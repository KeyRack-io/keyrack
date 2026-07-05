# Rust — Before and After

## Scenario

A multi-tenant SaaS API server encrypts user documents before storing
them in object storage. Each tenant's data must be encrypted under
tenant-specific keys, rotatable independently.

---

## Before: raw `aes-gcm` crate

```rust
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Mutex;

// Keys stored in memory, loaded from env or a config file.
// No versioning, no rotation, no hierarchy.
struct KeyStore {
    keys: Mutex<HashMap<String, Vec<u8>>>,
}

impl KeyStore {
    fn encrypt(&self, tenant_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let keys = self.keys.lock().unwrap();
        let key_bytes = keys.get(tenant_id)
            .ok_or("no key for tenant")?;

        let cipher = Aes256Gcm::new_from_slice(key_bytes)?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext)?;

        // Prepend nonce to ciphertext. No key ID, no version, no AAD.
        // If we rotate the key, we have no way to know which key
        // encrypted this blob.
        let mut output = nonce_bytes.to_vec();
        output.extend(ciphertext);
        Ok(output)
    }

    fn decrypt(&self, tenant_id: &str, blob: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let keys = self.keys.lock().unwrap();
        let key_bytes = keys.get(tenant_id)
            .ok_or("no key for tenant")?;

        let cipher = Aes256Gcm::new_from_slice(key_bytes)?;
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        Ok(cipher.decrypt(nonce, ciphertext)?)
    }
}

// Problems:
// - Raw key material in memory with no zeroization
// - No key hierarchy (tenant KEK → document DEK)
// - No versioning — rotation requires re-encrypting everything
// - No audit trail
// - No encryption context — blobs can be swapped between tenants
// - Adding HSM support means rewriting the crypto layer
```

---

## After: `keyrack-core` as embedded library

```rust
use keyrack_core::provider::software::SoftwareProvider;
use keyrack_core::provider::CryptoProvider;
use keyrack_core::key::KeySpec;
use keyrack_core::encryption_context::EncryptionContext;

struct DocumentStore {
    provider: SoftwareProvider,
}

impl DocumentStore {
    async fn encrypt_document(
        &self,
        tenant_id: &str,
        doc_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, keyrack_core::error::KeyRackError> {
        let key = self.provider.generate_key(&KeySpec::Aes256).await?;

        // Encryption context binds ciphertext to this tenant + document.
        // Decrypt with wrong context fails cryptographically.
        let mut ec = EncryptionContext::new();
        ec.insert("tenant", tenant_id);
        ec.insert("document", doc_id);

        // Returns ciphertext with self-describing header:
        // key ID, version, algorithm, encryption context hash.
        // After rotation, decrypt reads the header to find the right key version.
        self.provider.encrypt(&key, plaintext, Some(&ec)).await
    }

    async fn decrypt_document(
        &self,
        tenant_id: &str,
        doc_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, keyrack_core::error::KeyRackError> {
        let mut ec = EncryptionContext::new();
        ec.insert("tenant", tenant_id);
        ec.insert("document", doc_id);

        // Header in ciphertext tells KeyRack which key + version to use.
        // Works even after rotation — old versions retained for decrypt.
        self.provider.decrypt(ciphertext, Some(&ec)).await
    }
}

// Swap provider without changing application code:
//   SoftwareProvider::new()        → dev/test
//   Pkcs11Provider::new(&config)   → production HSM
//   KmipProvider::new(&config)     → tenant-managed HYOK HSM
//   VaultTransitProvider::new(url) → existing Vault infrastructure
```

## After (alternative): `keyrack` facade as service client

```rust
use keyrack::{KeyRack, attrs};

#[tokio::main]
async fn main() -> Result<(), keyrack::KeyRackError> {
    let kr = KeyRack::builder()
        .service_url("http://localhost:50051")
        .build()?;

    // Create a tenant-specific DEK under the tenant's KEK
    let key = kr.create_key(keyrack::AES256)
        .parent("tenant-kek-acme")
        .description("document-dek")
        .tags(attrs! { "tenant" => "acme", "purpose" => "documents" })
        .send().await?;

    let ciphertext = kr.encrypt(&key.id, b"patient record contents")
        .context(attrs! { "tenant" => "acme", "doc" => "D-9921" })
        .send().await?;

    // Later: rotate the tenant KEK. All dependent DEKs get rotation jobs.
    kr.rotate_key("tenant-kek-acme").send().await?;
}
```

### What changed

| Concern | Before | After |
|---------|--------|-------|
| Key material | Raw bytes in `HashMap` | Managed by provider (HSM, software, Vault) |
| Memory safety | No zeroization | `Sensitive<T>` wrapper, `zeroize` on drop |
| Key versioning | None | Self-describing ciphertext header |
| Encryption context | None | AAD-bound, cross-tenant swap prevented |
| Provider swap | Rewrite crypto layer | Change one constructor |
| Rotation | Re-encrypt everything offline | `rotate_key()` + re-encryption |
| Audit | None | Every operation emitted as structured event |
