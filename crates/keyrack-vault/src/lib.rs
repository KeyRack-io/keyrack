// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of KeyRack.
//
// KeyRack is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// KeyRack is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with KeyRack. If not, see <https://www.gnu.org/licenses/>.
//
// Alternative commercial licensing is available; contact the Licensor.

//! `HashiCorp` Vault Transit secrets engine provider for `KeyRack`.
//!
//! Delegates all cryptographic operations to Vault's Transit engine
//! over its HTTP API. Key material never leaves Vault.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::KeySpec;
use keyrack_core::provider::{
    CryptoOperation, CryptoProvider, EncryptOutput, KeyHandle, KeySpecCapability,
    ProviderCapabilities, SigningAlgorithm,
};
use keyrack_core::sensitive::Sensitive;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Crypto provider backed by `HashiCorp` Vault's Transit secrets engine.
pub struct VaultTransitProvider {
    client: Client,
    vault_addr: String,
    token: String,
    mount: String,
}

impl VaultTransitProvider {
    /// Connect to a Vault Transit engine.
    ///
    /// `mount_path` defaults to `"transit"` when `None`.
    pub async fn new(
        vault_addr: &str,
        vault_token: &str,
        mount_path: Option<&str>,
    ) -> Result<Self> {
        let addr = vault_addr.trim_end_matches('/').to_owned();
        let client = Client::builder()
            .build()
            .map_err(|e| KeyRackError::Provider(format!("failed to build HTTP client: {e}")))?;

        let provider = Self {
            client,
            vault_addr: addr,
            token: vault_token.to_owned(),
            mount: mount_path.unwrap_or("transit").to_owned(),
        };

        // Health-check: read the mount tuning to verify connectivity.
        provider.health_check().await?;

        Ok(provider)
    }

    async fn health_check(&self) -> Result<()> {
        let url = format!("{}/v1/sys/mounts/{}/tune", self.vault_addr, self.mount);
        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| KeyRackError::Provider(format!("vault health check failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(KeyRackError::Provider(format!(
                "vault health check returned {status}: {body}"
            )));
        }
        Ok(())
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{}/{}", self.vault_addr, self.mount, path)
    }

    async fn vault_post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let url = self.url(path);
        let resp = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| KeyRackError::Provider(format!("vault request failed: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| KeyRackError::Provider(format!("failed to read vault response: {e}")))?;

        if !status.is_success() {
            let msg = parse_vault_errors(&text).unwrap_or(text);
            return Err(KeyRackError::Provider(format!(
                "vault {path} returned {status}: {msg}"
            )));
        }

        serde_json::from_str(&text)
            .map_err(|e| KeyRackError::Provider(format!("failed to parse vault response: {e}")))
    }

    async fn vault_post_no_body<T: Serialize>(&self, path: &str, body: &T) -> Result<()> {
        let url = self.url(path);
        let resp = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| KeyRackError::Provider(format!("vault request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let msg = parse_vault_errors(&text).unwrap_or(text);
            return Err(KeyRackError::Provider(format!(
                "vault {path} returned {status}: {msg}"
            )));
        }
        Ok(())
    }

    async fn vault_delete(&self, path: &str) -> Result<()> {
        let url = self.url(path);
        let resp = self
            .client
            .delete(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| KeyRackError::Provider(format!("vault delete failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let msg = parse_vault_errors(&body).unwrap_or(body);
            return Err(KeyRackError::Provider(format!(
                "vault DELETE {path} returned {status}: {msg}"
            )));
        }
        Ok(())
    }

    async fn vault_get<R: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<R> {
        let url = self.url(path);
        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| KeyRackError::Provider(format!("vault GET failed: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| KeyRackError::Provider(format!("failed to read vault response: {e}")))?;

        if !status.is_success() {
            let msg = parse_vault_errors(&text).unwrap_or(text);
            return Err(KeyRackError::Provider(format!(
                "vault GET {path} returned {status}: {msg}"
            )));
        }

        serde_json::from_str(&text)
            .map_err(|e| KeyRackError::Provider(format!("failed to parse vault response: {e}")))
    }
}

fn parse_vault_errors(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct VaultErrorResponse {
        errors: Vec<String>,
    }
    serde_json::from_str::<VaultErrorResponse>(body)
        .ok()
        .map(|e| e.errors.join("; "))
}

fn vault_key_type(spec: &KeySpec) -> Result<&'static str> {
    Ok(match spec {
        KeySpec::Aes256 => "aes256-gcm96",
        KeySpec::Ed25519 => "ed25519",
        KeySpec::EcdsaP256Sha256 => "ecdsa-p256",
        KeySpec::RsaPkcs1v15Sha256 { key_size } | KeySpec::RsaPssSha256 { key_size } => {
            match key_size {
                ..=2048 => "rsa-2048",
                ..=3072 => "rsa-3072",
                _ => "rsa-4096",
            }
        }
        // TODO(proto-align): wire P-384/SHA-384-512/HMAC into vault-transit.
        other => {
            return Err(KeyRackError::Provider(format!(
                "unsupported key spec for vault-transit: {other:?}"
            )))
        }
    })
}

fn vault_hash_algorithm(alg: SigningAlgorithm) -> Result<&'static str> {
    match alg {
        SigningAlgorithm::Ed25519
        | SigningAlgorithm::EcdsaP256Sha256
        | SigningAlgorithm::RsaPkcs1v15Sha256
        | SigningAlgorithm::RsaPssSha256 => Ok("sha2-256"),
        // TODO(proto-align): wire P-384/SHA-384-512/HMAC into vault-transit.
        other => Err(KeyRackError::Provider(format!(
            "unsupported signing algorithm for vault-transit: {other:?}"
        ))),
    }
}

fn vault_signature_algorithm(alg: SigningAlgorithm) -> Option<&'static str> {
    match alg {
        SigningAlgorithm::RsaPkcs1v15Sha256 => Some("pkcs1v15"),
        SigningAlgorithm::RsaPssSha256 => Some("pss"),
        _ => None,
    }
}

// ── Vault API request/response shapes ──────────────────────────────────

#[derive(Serialize)]
struct CreateKeyRequest {
    #[serde(rename = "type")]
    key_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    exportable: Option<bool>,
}

#[derive(Serialize)]
struct EncryptRequest {
    plaintext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

#[derive(Deserialize)]
struct EncryptResponse {
    data: EncryptData,
}

#[derive(Deserialize)]
struct EncryptData {
    ciphertext: String,
}

#[derive(Serialize)]
struct DecryptRequest {
    ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

#[derive(Deserialize)]
struct DecryptResponse {
    data: DecryptData,
}

#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

#[derive(Serialize)]
struct SignRequest {
    input: String,
    hash_algorithm: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<&'static str>,
    prehashed: bool,
}

#[derive(Deserialize)]
struct SignResponse {
    data: SignData,
}

#[derive(Deserialize)]
struct SignData {
    signature: String,
}

#[derive(Serialize)]
struct VerifyRequest {
    input: String,
    signature: String,
    hash_algorithm: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<&'static str>,
    prehashed: bool,
}

#[derive(Deserialize)]
struct VerifyResponse {
    data: VerifyData,
}

#[derive(Deserialize)]
struct VerifyData {
    valid: bool,
}

#[derive(Serialize)]
struct RandomRequest {
    bytes: usize,
    format: &'static str,
}

#[derive(Deserialize)]
struct RandomResponse {
    data: RandomData,
}

#[derive(Deserialize)]
struct RandomData {
    random_bytes: String,
}

#[derive(Serialize)]
struct KeyConfigRequest {
    deletion_allowed: bool,
}

#[derive(Serialize)]
struct ExportableConfigRequest {
    exportable: bool,
}

/// GET /transit/export/encryption-key/{name}/{version}
#[derive(Deserialize)]
struct ExportKeyResponse {
    data: ExportKeyData,
}

#[derive(Deserialize)]
struct ExportKeyData {
    keys: std::collections::HashMap<String, String>,
}

// ── CryptoProvider impl ────────────────────────────────────────────────

#[async_trait]
impl CryptoProvider for VaultTransitProvider {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        let key_name = uuid::Uuid::new_v4().to_string();
        let key_type = vault_key_type(spec)?;
        let body = CreateKeyRequest {
            key_type,
            exportable: None,
        };

        self.vault_post_no_body(&format!("keys/{key_name}"), &body)
            .await?;

        tracing::info!(key_name = %key_name, key_type, "vault transit key created");

        Ok(KeyHandle {
            key_id: key_name,
            key_spec: spec.clone(),
        })
    }

    async fn encrypt(
        &self,
        handle: &KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        let body = EncryptRequest {
            plaintext: B64.encode(plaintext),
            context: if aad.is_empty() {
                None
            } else {
                Some(B64.encode(aad))
            },
        };

        let resp: EncryptResponse = self
            .vault_post(&format!("encrypt/{}", handle.key_id), &body)
            .await?;

        // Store the full vault ciphertext (including prefix) so we can
        // round-trip without version guessing.
        let ciphertext = resp.data.ciphertext.into_bytes();
        Ok(EncryptOutput { ciphertext })
    }

    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        let ct_str = std::str::from_utf8(ciphertext)
            .map_err(|e| KeyRackError::Provider(format!("ciphertext is not valid UTF-8: {e}")))?;

        let body = DecryptRequest {
            ciphertext: ct_str.to_owned(),
            context: if aad.is_empty() {
                None
            } else {
                Some(B64.encode(aad))
            },
        };

        let resp: DecryptResponse = self
            .vault_post(&format!("decrypt/{}", handle.key_id), &body)
            .await?;

        let plaintext = B64.decode(&resp.data.plaintext).map_err(|e| {
            KeyRackError::Provider(format!("base64 decode of plaintext failed: {e}"))
        })?;

        Ok(Sensitive::new(plaintext))
    }

    async fn sign(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let body = SignRequest {
            input: B64.encode(message),
            hash_algorithm: vault_hash_algorithm(algorithm)?,
            signature_algorithm: vault_signature_algorithm(algorithm),
            prehashed: false,
        };

        let resp: SignResponse = self
            .vault_post(&format!("sign/{}", handle.key_id), &body)
            .await?;

        // Preserve the full Vault-formatted signature (vault:vN:base64)
        // so verify() can pass it back without hardcoding the version.
        Ok(resp.data.signature.into_bytes())
    }

    async fn verify(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let vault_sig = std::str::from_utf8(signature)
            .map_err(|e| KeyRackError::Provider(format!("signature is not valid UTF-8: {e}")))?
            .to_owned();

        let body = VerifyRequest {
            input: B64.encode(message),
            signature: vault_sig,
            hash_algorithm: vault_hash_algorithm(algorithm)?,
            signature_algorithm: vault_signature_algorithm(algorithm),
            prehashed: false,
        };

        let resp: VerifyResponse = self
            .vault_post(&format!("verify/{}", handle.key_id), &body)
            .await?;

        Ok(resp.data.valid)
    }

    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        let body = RandomRequest {
            bytes: length,
            format: "base64",
        };

        let resp: RandomResponse = self.vault_post(&format!("random/{length}"), &body).await?;

        let bytes = B64.decode(&resp.data.random_bytes).map_err(|e| {
            KeyRackError::Provider(format!("base64 decode of random bytes failed: {e}"))
        })?;

        Ok(Sensitive::new(bytes))
    }

    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()> {
        // Step 1: enable deletion on the key.
        let config = KeyConfigRequest {
            deletion_allowed: true,
        };
        self.vault_post_no_body(&format!("keys/{}/config", handle.key_id), &config)
            .await?;

        // Step 2: delete the key.
        self.vault_delete(&format!("keys/{}", handle.key_id))
            .await?;

        tracing::info!(key_id = %handle.key_id, "vault transit key destroyed");
        Ok(())
    }

    fn capabilities(&self) -> ProviderCapabilities {
        use CryptoOperation::{Decrypt, DestroyKey, Encrypt, GenerateKey, Sign, Verify};

        let encrypt_ops = vec![GenerateKey, Encrypt, Decrypt, DestroyKey];
        let sign_ops = vec![GenerateKey, Sign, Verify, DestroyKey];

        ProviderCapabilities {
            provider_name: "vault-transit".into(),
            key_specs: vec![
                KeySpecCapability {
                    key_spec: KeySpec::Aes256,
                    operations: encrypt_ops,
                },
                KeySpecCapability {
                    key_spec: KeySpec::Ed25519,
                    operations: sign_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::EcdsaP256Sha256,
                    operations: sign_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 },
                    operations: sign_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::RsaPssSha256 { key_size: 2048 },
                    operations: sign_ops,
                },
            ],
            supports_generate_random: true,
            supports_atomic_data_key: false,
            supports_atomic_re_encrypt: false,
            supports_key_import: true,
        }
    }

    async fn export_key_material(&self, handle: &KeyHandle) -> Result<Sensitive<Vec<u8>>> {
        let resp: ExportKeyResponse = self
            .vault_get(&format!("export/encryption-key/{}", handle.key_id))
            .await?;

        // The export response `keys` map is version_number→base64(material).
        // When no version suffix is given, Vault returns the latest version.
        let b64_material = resp.data.keys.values().next().ok_or_else(|| {
            KeyRackError::Provider("vault export returned no key versions".into())
        })?;

        let material = B64.decode(b64_material).map_err(|e| {
            KeyRackError::Provider(format!("base64 decode of exported key failed: {e}"))
        })?;

        Ok(Sensitive::new(material))
    }

    async fn make_key_exportable(&self, handle: &KeyHandle) -> Result<()> {
        let config = ExportableConfigRequest { exportable: true };
        self.vault_post_no_body(&format!("keys/{}/config", handle.key_id), &config)
            .await?;

        tracing::info!(
            key_id = %handle.key_id,
            "vault transit key marked exportable"
        );
        Ok(())
    }

    async fn revoke_key_exportability(&self, _handle: &KeyHandle) -> Result<Option<KeyHandle>> {
        // SOFT REVOKE — no-op at the Vault backend level.
        //
        // Vault Transit's `exportable` flag is one-way (cannot be turned off
        // once set), so the backend key retains its exportable flag. However
        // the KeyRack service layer marks the KeyRecord `NonExportable` and
        // GetKeyMaterial refuses requests for non-exportable records, making
        // this a KeyRack-POLICY revocation — not a cryptographic one.
        //
        // HONESTY: the backend key's material remains theoretically
        // extractable by a Vault admin with direct Transit /export access.
        // Full backend-level (cryptographic) revocation — destroying the key
        // so the material is irrecoverable — requires a SEPARATE explicit
        // destroy/crypto-shred operation (not part of RevokeKeyExportability).
        //
        // Rationale: RevokeKeyExportability must never destroy keys or cause
        // silent data loss. Existing ciphertext encrypted with this key
        // remains decryptable after a soft revoke.

        tracing::info!(
            key_id = %_handle.key_id,
            "vault transit: soft revoke — KeyRack policy marks key non-exportable; \
             Vault-level exportable flag unchanged (one-way)"
        );

        Ok(None)
    }

    async fn import_key_material(
        &self,
        spec: &KeySpec,
        material: Sensitive<Vec<u8>>,
    ) -> Result<KeyHandle> {
        let key_name = uuid::Uuid::new_v4().to_string();
        let key_type = vault_key_type(spec)?;

        let wrapping_key_resp: WrappingKeyResponse = self.vault_get("wrapping_key").await?;
        let wrapping_pem = wrapping_key_resp.data.public_key;

        let wrapped = wrap_key_for_vault_import(&wrapping_pem, material.expose())?;
        let ciphertext = B64.encode(&wrapped);

        let body = VaultImportKeyRequest {
            key_type,
            ciphertext,
            exportable: true,
            allow_rotation: true,
        };
        self.vault_post_no_body(&format!("keys/{key_name}/import"), &body)
            .await?;

        tracing::info!(key_name = %key_name, key_type, "vault transit key imported (BYOK)");

        Ok(KeyHandle {
            key_id: key_name,
            key_spec: spec.clone(),
        })
    }
}

// ── Vault BYOK import helpers ─────────────────────────────────────────

#[derive(Deserialize)]
struct WrappingKeyResponse {
    data: WrappingKeyData,
}

#[derive(Deserialize)]
struct WrappingKeyData {
    public_key: String,
}

#[derive(Serialize)]
struct VaultImportKeyRequest {
    #[serde(rename = "type")]
    key_type: &'static str,
    ciphertext: String,
    exportable: bool,
    allow_rotation: bool,
}

fn wrap_key_for_vault_import(wrapping_pem: &str, key_material: &[u8]) -> Result<Vec<u8>> {
    use aes_kw::KekAes256;
    use rand::RngCore;
    use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
    use zeroize::Zeroize;

    let rsa_pub = RsaPublicKey::from_public_key_pem(wrapping_pem)
        .map_err(|e| KeyRackError::Provider(format!("failed to parse vault wrapping key: {e}")))?;

    let mut ephemeral_aes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ephemeral_aes);

    let kek = KekAes256::new(&ephemeral_aes.into());
    let mut wrapped_key = vec![0u8; key_material.len() + 8];
    kek.wrap_with_padding(key_material, &mut wrapped_key)
        .map_err(|e| KeyRackError::Provider(format!("AES-KWP wrap failed: {e:?}")))?;

    let padding = Oaep::new::<sha2::Sha256>();
    let mut rng = rand::thread_rng();
    let wrapped_aes = rsa_pub
        .encrypt(&mut rng, padding, &ephemeral_aes)
        .map_err(|e| KeyRackError::Provider(format!("RSA-OAEP wrap failed: {e}")))?;

    ephemeral_aes.zeroize();

    let mut result = wrapped_aes;
    result.extend_from_slice(&wrapped_key);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // If you flip either flag to true you MUST have overridden the
    // corresponding method to keep plaintext in-boundary AND added a
    // test proving it. This guard converts a silent capability lie
    // into a conscious, reviewed change.
    //
    // VaultTransitProvider::new() requires a live Vault server, so we
    // construct the struct directly to bypass the health-check.
    #[test]
    fn capability_flags_are_honest() {
        let provider = VaultTransitProvider {
            client: Client::new(),
            vault_addr: String::new(),
            token: String::new(),
            mount: String::new(),
        };
        let caps = provider.capabilities();
        assert!(
            !caps.supports_atomic_data_key,
            "supports_atomic_data_key must be false without a generate_data_key override"
        );
        assert!(
            !caps.supports_atomic_re_encrypt,
            "supports_atomic_re_encrypt must be false without a re_encrypt override"
        );
    }

    // ── Live Vault integration tests ───────────────────────────────────
    //
    // Require VAULT_ADDR + VAULT_TOKEN pointing at a running Vault with
    // Transit enabled (`vault secrets enable transit`).
    //
    // Run: cargo test -p keyrack-vault -- --ignored

    async fn live_provider() -> Option<VaultTransitProvider> {
        let addr = std::env::var("VAULT_ADDR").ok()?;
        let token = std::env::var("VAULT_TOKEN").ok()?;
        VaultTransitProvider::new(&addr, &token, None).await.ok()
    }

    #[tokio::test]
    #[ignore = "requires live Vault (VAULT_ADDR + VAULT_TOKEN)"]
    async fn exportable_round_trip() {
        let provider = live_provider().await.expect("live Vault required");

        // Create a key, then make it exportable.
        let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();
        provider.make_key_exportable(&handle).await.unwrap();

        // Export the key material.
        let material = provider.export_key_material(&handle).await.unwrap();
        assert_eq!(material.expose().len(), 32, "AES-256 = 32 bytes");

        // Encrypt with the key, then decrypt — the key still works.
        let ct = provider.encrypt(&handle, b"hello", b"").await.unwrap();
        let pt = provider
            .decrypt(&handle, &ct.ciphertext, b"")
            .await
            .unwrap();
        assert_eq!(pt.expose().as_slice(), b"hello");

        provider.destroy_key(&handle).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires live Vault (VAULT_ADDR + VAULT_TOKEN)"]
    async fn loosen_then_export() {
        let provider = live_provider().await.expect("live Vault required");

        // Create a non-exportable key.
        let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

        // Export should fail (non-exportable Vault key has no /export path).
        let err = provider.export_key_material(&handle).await;
        assert!(err.is_err(), "export on non-exportable key must fail");

        // Loosen: make it exportable via config update.
        provider.make_key_exportable(&handle).await.unwrap();

        // Now export succeeds.
        let material = provider.export_key_material(&handle).await.unwrap();
        assert_eq!(material.expose().len(), 32);

        provider.destroy_key(&handle).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires live Vault (VAULT_ADDR + VAULT_TOKEN)"]
    async fn tighten_soft_revoke_preserves_data() {
        let provider = live_provider().await.expect("live Vault required");

        // Create and make exportable.
        let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();
        provider.make_key_exportable(&handle).await.unwrap();

        // Encrypt some data with the exportable key.
        let ct = provider.encrypt(&handle, b"secret", b"").await.unwrap();

        // Soft revoke: provider returns None (no re-key, no destroy).
        let result = provider.revoke_key_exportability(&handle).await.unwrap();
        assert!(
            result.is_none(),
            "soft revoke must NOT re-key — should return None"
        );

        // POSITIVE CONTROL: old ciphertext still decrypts (data preserved).
        let pt = provider
            .decrypt(&handle, &ct.ciphertext, b"")
            .await
            .expect("old ciphertext must still decrypt after soft revoke");
        assert_eq!(pt.expose().as_slice(), b"secret");

        // Key still works for new encrypt/decrypt operations.
        let ct2 = provider.encrypt(&handle, b"new data", b"").await.unwrap();
        let pt2 = provider
            .decrypt(&handle, &ct2.ciphertext, b"")
            .await
            .unwrap();
        assert_eq!(pt2.expose().as_slice(), b"new data");

        // Vault-level exportable flag is still set (one-way, cannot be unset).
        // The service layer's NonExportable posture is the actual gate.
        let material = provider.export_key_material(&handle).await;
        assert!(
            material.is_ok(),
            "Vault-level export still works (one-way flag); \
             KeyRack service layer is the real gate"
        );

        provider.destroy_key(&handle).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires live Vault (VAULT_ADDR + VAULT_TOKEN)"]
    async fn non_exportable_has_no_export_path() {
        let provider = live_provider().await.expect("live Vault required");

        let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

        // Default key is non-exportable → export must fail.
        let err = provider.export_key_material(&handle).await;
        assert!(err.is_err(), "non-exportable key must refuse export");

        provider.destroy_key(&handle).await.unwrap();
    }
}
