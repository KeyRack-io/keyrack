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

//! `KeyRack` WASM bindings.
//!
//! Exposes the pure-Rust [`SoftwareProvider`] via `wasm-bindgen` so
//! browser and Node.js code can perform encrypt/decrypt/sign/verify
//! locally without network round-trips after fetching a key.
//!
//! ## Quick start (JS/TS)
//!
//! ```js
//! import init, { WasmKeyRack } from "keyrack-wasm";
//! await init();
//!
//! const kr = new WasmKeyRack();
//! const keyId = await kr.generateKey("AES_256");
//! const ct = await kr.encrypt(keyId, plaintext, aad);
//! const pt = await kr.decrypt(keyId, ct, aad);
//! ```

#![forbid(unsafe_code)]

use keyrack_core::key::KeySpec;
use keyrack_core::provider::software::SoftwareProvider;
use keyrack_core::provider::{CryptoProvider, SigningAlgorithm};
use wasm_bindgen::prelude::*;

/// `KeyRack` client for WASM environments.
///
/// Uses the pure-Rust `SoftwareProvider` under the hood. All key
/// material lives in WASM linear memory and is dropped when the
/// instance is garbage-collected.
#[wasm_bindgen]
pub struct WasmKeyRack {
    provider: SoftwareProvider,
}

impl Default for WasmKeyRack {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmKeyRack {
    /// Create a new instance with an ephemeral in-memory key store.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            provider: SoftwareProvider::new(),
        }
    }

    /// Generate a key. Returns the key ID (string handle).
    ///
    /// `spec` must be one of: `"AES_256"`, `"ED25519"`, `"RSA_2048"`,
    /// `"RSA_3072"`, `"RSA_4096"`, `"ECDSA_P256"`.
    #[wasm_bindgen(js_name = "generateKey")]
    pub async fn generate_key(&self, spec: &str) -> Result<String, JsError> {
        let key_spec = parse_key_spec(spec)?;
        let handle = self
            .provider
            .generate_key(&key_spec)
            .await
            .map_err(|e| to_js_error(&e))?;
        Ok(handle.key_id)
    }

    /// Encrypt `plaintext` using the key identified by `key_id`.
    ///
    /// `aad` is optional additional authenticated data (pass empty
    /// `Uint8Array` for none). Returns the ciphertext as `Uint8Array`.
    pub async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let handle = keyrack_core::provider::KeyHandle {
            key_id: key_id.to_string(),
            key_spec: KeySpec::Aes256,
        };
        let output = self
            .provider
            .encrypt(&handle, plaintext, aad)
            .await
            .map_err(|e| to_js_error(&e))?;
        Ok(output.ciphertext)
    }

    /// Decrypt `ciphertext` that was produced by [`encrypt`](Self::encrypt).
    pub async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let handle = keyrack_core::provider::KeyHandle {
            key_id: key_id.to_string(),
            key_spec: KeySpec::Aes256,
        };
        let pt = self
            .provider
            .decrypt(&handle, ciphertext, aad)
            .await
            .map_err(|e| to_js_error(&e))?;
        Ok(pt.expose().clone())
    }

    /// Sign `message` using Ed25519.
    #[wasm_bindgen(js_name = "signEd25519")]
    pub async fn sign_ed25519(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, JsError> {
        let handle = keyrack_core::provider::KeyHandle {
            key_id: key_id.to_string(),
            key_spec: KeySpec::Ed25519,
        };
        self.provider
            .sign(&handle, SigningAlgorithm::Ed25519, message)
            .await
            .map_err(|e| to_js_error(&e))
    }

    /// Verify an Ed25519 signature.
    #[wasm_bindgen(js_name = "verifyEd25519")]
    pub async fn verify_ed25519(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, JsError> {
        let handle = keyrack_core::provider::KeyHandle {
            key_id: key_id.to_string(),
            key_spec: KeySpec::Ed25519,
        };
        self.provider
            .verify(&handle, SigningAlgorithm::Ed25519, message, signature)
            .await
            .map_err(|e| to_js_error(&e))
    }

    /// Sign `message` using ECDSA P-256 SHA-256.
    #[wasm_bindgen(js_name = "signEcdsaP256")]
    pub async fn sign_ecdsa_p256(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, JsError> {
        let handle = keyrack_core::provider::KeyHandle {
            key_id: key_id.to_string(),
            key_spec: KeySpec::EcdsaP256Sha256,
        };
        self.provider
            .sign(&handle, SigningAlgorithm::EcdsaP256Sha256, message)
            .await
            .map_err(|e| to_js_error(&e))
    }

    /// Verify an ECDSA P-256 SHA-256 signature.
    #[wasm_bindgen(js_name = "verifyEcdsaP256")]
    pub async fn verify_ecdsa_p256(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, JsError> {
        let handle = keyrack_core::provider::KeyHandle {
            key_id: key_id.to_string(),
            key_spec: KeySpec::EcdsaP256Sha256,
        };
        self.provider
            .verify(
                &handle,
                SigningAlgorithm::EcdsaP256Sha256,
                message,
                signature,
            )
            .await
            .map_err(|e| to_js_error(&e))
    }

    /// Generate cryptographically secure random bytes.
    #[wasm_bindgen(js_name = "generateRandom")]
    pub async fn generate_random(&self, length: u32) -> Result<Vec<u8>, JsError> {
        let result = self
            .provider
            .generate_random(length as usize)
            .await
            .map_err(|e| to_js_error(&e))?;
        Ok(result.expose().clone())
    }

    /// Destroy key material. The key ID becomes invalid after this call.
    #[wasm_bindgen(js_name = "destroyKey")]
    pub async fn destroy_key(&self, key_id: &str) -> Result<(), JsError> {
        let handle = keyrack_core::provider::KeyHandle {
            key_id: key_id.to_string(),
            key_spec: KeySpec::Aes256,
        };
        self.provider
            .destroy_key(&handle)
            .await
            .map_err(|e| to_js_error(&e))
    }

    /// Compute a Logical ID (LID) from a set of attributes (JSON object).
    ///
    /// Useful for client-side LID pre-computation without a server
    /// round-trip.
    #[wasm_bindgen(js_name = "computeLid")]
    pub fn compute_lid(&self, attrs_json: &str) -> Result<String, JsError> {
        let attrs: std::collections::BTreeMap<String, String> = serde_json::from_str(attrs_json)
            .map_err(|e| JsError::new(&format!("invalid JSON: {e}")))?;
        let mut attr_set = keyrack_core::attr::AttributeSet::new();
        for (k, v) in &attrs {
            attr_set.insert(k, keyrack_core::attr::AttributeValue::String(v.clone()));
        }
        let form = keyrack_core::canon::canonicalize(
            keyrack_core::canon::CanonicalizationVersion::V1,
            &attr_set,
        );
        let lid =
            keyrack_core::lid::Lid::derive(keyrack_core::canon::CanonicalizationVersion::V1, &form);
        Ok(lid.to_string())
    }
}

fn parse_key_spec(s: &str) -> Result<KeySpec, JsError> {
    match s {
        "AES_256" => Ok(KeySpec::Aes256),
        "ED25519" => Ok(KeySpec::Ed25519),
        "RSA_2048" => Ok(KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 }),
        "RSA_3072" => Ok(KeySpec::RsaPkcs1v15Sha256 { key_size: 3072 }),
        "RSA_4096" => Ok(KeySpec::RsaPkcs1v15Sha256 { key_size: 4096 }),
        "ECDSA_P256" => Ok(KeySpec::EcdsaP256Sha256),
        _ => Err(JsError::new(&format!("unknown key spec: {s}"))),
    }
}

fn to_js_error(e: &keyrack_core::error::KeyRackError) -> JsError {
    JsError::new(&e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let kr = WasmKeyRack::new();
        let key_id = kr.generate_key("AES_256").await.unwrap();
        let ct = kr.encrypt(&key_id, b"hello wasm", b"").await.unwrap();
        let pt = kr.decrypt(&key_id, &ct, b"").await.unwrap();
        assert_eq!(pt, b"hello wasm");
    }

    #[tokio::test]
    async fn sign_verify_ed25519() {
        let kr = WasmKeyRack::new();
        let key_id = kr.generate_key("ED25519").await.unwrap();
        let sig = kr.sign_ed25519(&key_id, b"test message").await.unwrap();
        let valid = kr
            .verify_ed25519(&key_id, b"test message", &sig)
            .await
            .unwrap();
        assert!(valid);
        let invalid = kr
            .verify_ed25519(&key_id, b"wrong message", &sig)
            .await
            .unwrap();
        assert!(!invalid);
    }

    #[tokio::test]
    async fn compute_lid_deterministic() {
        let kr = WasmKeyRack::new();
        let lid1 = kr.compute_lid(r#"{"kind":"dek","user":"alice"}"#).unwrap();
        let lid2 = kr.compute_lid(r#"{"kind":"dek","user":"alice"}"#).unwrap();
        assert_eq!(lid1, lid2);
        let lid3 = kr.compute_lid(r#"{"kind":"dek","user":"bob"}"#).unwrap();
        assert_ne!(lid1, lid3);
    }

    #[tokio::test]
    async fn generate_random_bytes() {
        let kr = WasmKeyRack::new();
        let bytes = kr.generate_random(32).await.unwrap();
        assert_eq!(bytes.len(), 32);
    }
}
