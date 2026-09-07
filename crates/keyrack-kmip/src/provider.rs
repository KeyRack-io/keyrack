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

//! KMIP `CryptoProvider` implementation.
//!
//! Delegates all cryptographic operations to a remote KMIP 2.1 server
//! over TLS using TTLV wire encoding. Connections are established
//! lazily and held behind a lock for serialized access; connection
//! pooling is a future enhancement.
//!
//! # Additional authenticated data is not supported
//!
//! KMIP 2.1 does define the transport for AAD: `Authenticated Encryption
//! Additional Data` (tag `0x4200FE`) is an optional field of both the Encrypt
//! and the Decrypt request payload, paired with `Authenticated Encryption Tag`
//! (`0x4200FF`), which the server returns on Encrypt and which the client must
//! replay on Decrypt (OASIS KMIP 2.1 §6.1.16, §6.1.17, §7.3, §7.4).
//!
//! This client implements neither half of that exchange. It sends no AAD field,
//! and it neither captures the Authenticated Encryption Tag from an Encrypt
//! response nor returns it on Decrypt — so even if the AAD were transmitted,
//! there would be no tag through which the binding could be verified, and
//! whether a given server honours the field at all is a per-server capability
//! this client never probes.
//!
//! Consequently [`KmipProvider::encrypt`] and [`KmipProvider::decrypt`] **reject
//! a non-empty `aad`** rather than dropping it. A caller that supplies an
//! encryption context is asserting a binding that this provider cannot deliver;
//! failing tells them so, whereas succeeding would not. An empty `aad` asserts
//! no binding and is still accepted.

use crate::connection::KmipConnection;
use crate::messages;
use crate::ttlv::{self, tag};
use async_trait::async_trait;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::KeySpec;
use keyrack_core::provider::{
    CryptoOperation, CryptoProvider, EncryptOutput, KeyHandle, KeySpecCapability,
    ProviderCapabilities, SigningAlgorithm,
};
use keyrack_core::sensitive::Sensitive;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Configuration for a KMIP connection.
///
/// Deliberately does **not** derive `Debug`: it holds `password` in plain
/// text, and a derived `Debug` puts that password into any log line or error
/// that formats the config. `Pkcs11ProviderConfig` omits `Debug` for the same
/// reason.
#[derive(Clone, Serialize, Deserialize)]
pub struct KmipProviderConfig {
    /// KMIP server endpoint (e.g. `kmip://hsm.example.com:5696`).
    pub endpoint: String,

    /// Path to the client TLS certificate (PEM).
    pub client_cert_path: Option<String>,

    /// Path to the client TLS private key (PEM).
    pub client_key_path: Option<String>,

    /// Path to the CA certificate bundle (PEM) for server verification.
    pub ca_cert_path: Option<String>,

    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// KMIP username for credential-based authentication (optional,
    /// most deployments use mutual TLS).
    pub username: Option<String>,

    /// KMIP password (optional).
    pub password: Option<String>,
}

fn default_timeout() -> u64 {
    30
}

/// KMIP cryptographic provider.
///
/// All operations delegate to the remote KMIP server via the TTLV
/// wire protocol over TLS. The connection is established lazily on
/// first use.
pub struct KmipProvider {
    config: KmipProviderConfig,
    connection: Mutex<Option<KmipConnection>>,
}

impl KmipProvider {
    /// Create a new KMIP provider from configuration.
    ///
    /// Does not establish a connection until the first operation.
    pub fn new(config: KmipProviderConfig) -> Self {
        tracing::info!(
            endpoint = %config.endpoint,
            "KMIP provider configured"
        );
        Self {
            config,
            connection: Mutex::new(None),
        }
    }

    /// Return the configured endpoint.
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    async fn get_connection(&self) -> Result<tokio::sync::MutexGuard<'_, Option<KmipConnection>>> {
        let mut guard = self.connection.lock().await;
        if guard.is_none() {
            let conn = KmipConnection::connect(&self.config).await?;
            *guard = Some(conn);
        }
        Ok(guard)
    }

    async fn send_request(&self, request: &ttlv::TtlvItem) -> Result<messages::KmipResponse> {
        let mut guard = self.get_connection().await?;
        let conn = guard.as_mut().unwrap();

        let response_item = if let Ok(item) = conn.round_trip(request).await {
            item
        } else {
            // Connection may be stale; reconnect once.
            tracing::debug!(endpoint = %self.config.endpoint, "reconnecting after error");
            let new_conn = KmipConnection::connect(&self.config).await?;
            *conn = new_conn;
            conn.round_trip(request).await?
        };

        messages::parse_response(&response_item)
            .map_err(|e| KeyRackError::Provider(format!("KMIP response parse error: {e}")))
    }

    fn check_response(resp: &messages::KmipResponse) -> Result<()> {
        if resp.result_status != ttlv::result_status::SUCCESS {
            let msg = resp.result_message.as_deref().unwrap_or("unknown error");
            return Err(KeyRackError::Provider(format!(
                "KMIP operation failed (status=0x{:02X}): {msg}",
                resp.result_status
            )));
        }
        Ok(())
    }

    fn key_spec_to_kmip(spec: &KeySpec) -> Result<(u32, i32, bool)> {
        Ok(match spec {
            KeySpec::Aes256 => (ttlv::crypto_algorithm::AES, 256, true),
            KeySpec::Ed25519 => (ttlv::crypto_algorithm::ED25519, 256, false),
            KeySpec::EcdsaP256Sha256 => (ttlv::crypto_algorithm::ECDSA, 256, false),
            KeySpec::RsaPkcs1v15Sha256 { key_size } | KeySpec::RsaPssSha256 { key_size } => {
                (ttlv::crypto_algorithm::RSA, *key_size as i32, false)
            }
            // TODO(proto-align): wire P-384/SHA-384-512/HMAC into kmip.
            other => {
                return Err(KeyRackError::Provider(format!(
                    "unsupported key spec for kmip: {other:?}"
                )))
            }
        })
    }

    /// Fail closed when the caller supplies additional authenticated data.
    ///
    /// See the module documentation: this client transmits neither the KMIP
    /// `Authenticated Encryption Additional Data` field nor the
    /// `Authenticated Encryption Tag` that would authenticate it, so a
    /// non-empty `aad` cannot be bound to the ciphertext. Refusing keeps the
    /// caller's belief and the cryptographic reality in agreement; silently
    /// discarding it would not. An empty `aad` binds nothing and is accepted.
    fn reject_unbindable_aad(aad: &[u8], operation: &str) -> Result<()> {
        if aad.is_empty() {
            return Ok(());
        }
        Err(KeyRackError::Provider(format!(
            "kmip provider cannot bind additional authenticated data: {operation} was given \
             {} byte(s) of AAD, but this client does not transmit the KMIP Authenticated \
             Encryption Additional Data field and cannot verify the Authenticated Encryption \
             Tag. Refusing rather than discarding the encryption context — use a provider that \
             supports AAD, or call with an empty AAD if no binding is required.",
            aad.len()
        )))
    }
}

#[async_trait]
impl CryptoProvider for KmipProvider {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        let (algorithm, key_length, is_symmetric) = Self::key_spec_to_kmip(spec)?;

        let request = if is_symmetric {
            messages::create_symmetric_key(algorithm, key_length)
        } else {
            messages::create_asymmetric_key(algorithm, key_length)
        };

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        let unique_id = resp
            .payload
            .as_ref()
            .and_then(|p| p.find(tag::UNIQUE_ID))
            .and_then(|i| i.as_text())
            .ok_or_else(|| {
                KeyRackError::Provider("KMIP Create: no UniqueIdentifier in response".into())
            })?;

        tracing::info!(
            key_id = unique_id,
            spec = ?spec,
            endpoint = %self.config.endpoint,
            "KMIP key created"
        );

        Ok(KeyHandle {
            key_id: unique_id.to_string(),
            key_spec: spec.clone(),
        })
    }

    async fn encrypt(
        &self,
        handle: &KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        Self::reject_unbindable_aad(aad, "encrypt")?;

        let request = messages::encrypt_request(
            &handle.key_id,
            plaintext,
            None,
            Some(ttlv::block_cipher_mode::GCM),
        );

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        let payload = resp
            .payload
            .as_ref()
            .ok_or_else(|| KeyRackError::Provider("KMIP Encrypt: no payload in response".into()))?;

        let ciphertext = payload
            .find(tag::DATA)
            .and_then(|i| i.as_bytes())
            .ok_or_else(|| KeyRackError::Provider("KMIP Encrypt: no Data in response".into()))?
            .to_vec();

        let iv = payload
            .find(tag::IV_COUNTER_NONCE)
            .and_then(|i| i.as_bytes())
            .unwrap_or_default()
            .to_vec();

        let mut combined = iv;
        combined.extend_from_slice(&ciphertext);

        Ok(EncryptOutput {
            ciphertext: combined,
        })
    }

    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        Self::reject_unbindable_aad(aad, "decrypt")?;

        // For AES-GCM, the first 12 bytes are the IV.
        let (iv, ct) = if matches!(handle.key_spec, KeySpec::Aes256) && ciphertext.len() > 12 {
            (&ciphertext[..12], &ciphertext[12..])
        } else {
            (&[][..], ciphertext)
        };

        let request = messages::decrypt_request(
            &handle.key_id,
            ct,
            if iv.is_empty() { None } else { Some(iv) },
            Some(ttlv::block_cipher_mode::GCM),
        );

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        let data = resp
            .payload
            .as_ref()
            .and_then(|p| p.find(tag::DATA))
            .and_then(|i| i.as_bytes())
            .ok_or_else(|| KeyRackError::Provider("KMIP Decrypt: no Data in response".into()))?
            .to_vec();

        Ok(Sensitive::new(data))
    }

    async fn sign(
        &self,
        handle: &KeyHandle,
        _algorithm: SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let request = messages::sign_request(&handle.key_id, message, None);

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        let signature = resp
            .payload
            .as_ref()
            .and_then(|p| p.find(tag::SIGNATURE_DATA))
            .and_then(|i| i.as_bytes())
            .ok_or_else(|| {
                KeyRackError::Provider("KMIP Sign: no SignatureData in response".into())
            })?
            .to_vec();

        Ok(signature)
    }

    async fn verify(
        &self,
        handle: &KeyHandle,
        _algorithm: SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let request = messages::verify_request(&handle.key_id, message, signature, None);

        let resp = self.send_request(&request).await?;

        // KMIP returns Success if the signature is valid, or
        // OperationFailed with a specific reason if invalid.
        Ok(resp.result_status == ttlv::result_status::SUCCESS)
    }

    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        let request = messages::rng_retrieve_request(length as i32);

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        let data = resp
            .payload
            .as_ref()
            .and_then(|p| p.find(tag::DATA))
            .and_then(|i| i.as_bytes())
            .ok_or_else(|| KeyRackError::Provider("KMIP RNGRetrieve: no Data in response".into()))?
            .to_vec();

        Ok(Sensitive::new(data))
    }

    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()> {
        let request = messages::destroy_request(&handle.key_id);

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        tracing::info!(
            key_id = %handle.key_id,
            endpoint = %self.config.endpoint,
            "KMIP key destroyed"
        );

        Ok(())
    }

    fn capabilities(&self) -> ProviderCapabilities {
        use CryptoOperation::{
            Decrypt, DestroyKey, Encrypt, GenerateDataKey, GenerateKey, ReEncrypt, Sign, Verify,
        };

        let symmetric_ops = vec![
            GenerateKey,
            Encrypt,
            Decrypt,
            GenerateDataKey,
            ReEncrypt,
            DestroyKey,
        ];
        let signing_ops = vec![GenerateKey, Sign, Verify, DestroyKey];

        ProviderCapabilities {
            provider_name: "kmip".into(),
            key_specs: vec![
                KeySpecCapability {
                    key_spec: KeySpec::Aes256,
                    operations: symmetric_ops,
                },
                KeySpecCapability {
                    key_spec: KeySpec::Ed25519,
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::EcdsaP256Sha256,
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 },
                    operations: signing_ops,
                },
            ],
            supports_generate_random: true,
            supports_atomic_data_key: false,
            supports_atomic_re_encrypt: false,
            supports_key_import: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> KmipProviderConfig {
        KmipProviderConfig {
            endpoint: "kmip://localhost:5696".into(),
            client_cert_path: None,
            client_key_path: None,
            ca_cert_path: None,
            timeout_secs: 10,
            username: None,
            password: None,
        }
    }

    #[test]
    fn config_serialization() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: KmipProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.endpoint, "kmip://localhost:5696");
        assert_eq!(parsed.timeout_secs, 10);
    }

    #[test]
    fn provider_endpoint() {
        let provider = KmipProvider::new(test_config());
        assert_eq!(provider.endpoint(), "kmip://localhost:5696");
    }

    #[test]
    fn capabilities_report_kmip() {
        let provider = KmipProvider::new(test_config());
        let caps = provider.capabilities();
        assert_eq!(caps.provider_name, "kmip");
        assert!(caps.supports_generate_random);
        assert_eq!(caps.key_specs.len(), 4);
    }

    // If you flip either flag to true you MUST have overridden the
    // corresponding method to keep plaintext in-boundary AND added a
    // test proving it. This guard converts a silent capability lie
    // into a conscious, reviewed change.
    #[test]
    fn capability_flags_are_honest() {
        let provider = KmipProvider::new(test_config());
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

    fn test_handle() -> KeyHandle {
        KeyHandle {
            key_id: "kmip-key-1".into(),
            key_spec: KeySpec::Aes256,
        }
    }

    // ── AAD contract ────────────────────────────────────────────────
    //
    // These tests run in-process under `cargo test --workspace`; they need no
    // KMIP server. `test_config` points at a port nothing is listening on, so
    // an assertion that the error names the AAD problem — rather than a
    // connection failure — is itself the proof that the request was refused
    // before it could reach the wire and lose the caller's context.

    #[test]
    fn empty_aad_is_accepted_by_the_guard() {
        assert!(
            KmipProvider::reject_unbindable_aad(&[], "encrypt").is_ok(),
            "an empty AAD asserts no binding and must remain usable"
        );
    }

    #[tokio::test]
    async fn encrypt_rejects_non_empty_aad() {
        let provider = KmipProvider::new(test_config());
        let err = provider
            .encrypt(&test_handle(), b"plaintext", b"tenant=acme")
            .await
            .expect_err("non-empty AAD must be refused, not silently discarded");

        assert!(
            matches!(err, KeyRackError::Provider(_)),
            "expected a provider error, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("additional authenticated data") && msg.contains("encrypt"),
            "error must name the unsupported AAD binding and the operation: {msg}"
        );
    }

    #[tokio::test]
    async fn decrypt_rejects_non_empty_aad() {
        let provider = KmipProvider::new(test_config());
        let err = provider
            .decrypt(&test_handle(), b"ciphertext", b"tenant=acme")
            .await
            .expect_err("non-empty AAD must be refused, not silently discarded");

        let msg = err.to_string();
        assert!(
            msg.contains("additional authenticated data") && msg.contains("decrypt"),
            "error must name the unsupported AAD binding and the operation: {msg}"
        );
    }

    // `re_encrypt` and `generate_data_key` use the trait's default
    // implementations, which compose `encrypt`/`decrypt` — so they must inherit
    // the refusal rather than route around it. `re_encrypt` decrypts first, so
    // the guard is reachable without a server; `generate_data_key` calls
    // `generate_random` first, so it only fails once the server has been
    // contacted and is therefore not covered in-process here.
    #[tokio::test]
    async fn re_encrypt_inherits_the_aad_refusal() {
        let provider = KmipProvider::new(test_config());
        let err = provider
            .re_encrypt(
                &test_handle(),
                b"ciphertext",
                b"tenant=acme",
                &test_handle(),
                b"tenant=acme",
            )
            .await
            .expect_err("re_encrypt must not launder a non-empty AAD");

        assert!(
            err.to_string().contains("additional authenticated data"),
            "expected the AAD refusal to propagate, got: {err}"
        );
    }

    #[test]
    fn key_spec_mapping() {
        let (alg, len, sym) = KmipProvider::key_spec_to_kmip(&KeySpec::Aes256).unwrap();
        assert_eq!(alg, crate::ttlv::crypto_algorithm::AES);
        assert_eq!(len, 256);
        assert!(sym);

        let (alg, len, sym) = KmipProvider::key_spec_to_kmip(&KeySpec::Ed25519).unwrap();
        assert_eq!(alg, crate::ttlv::crypto_algorithm::ED25519);
        assert_eq!(len, 256);
        assert!(!sym);

        let (alg, len, sym) =
            KmipProvider::key_spec_to_kmip(&KeySpec::RsaPkcs1v15Sha256 { key_size: 4096 }).unwrap();
        assert_eq!(alg, crate::ttlv::crypto_algorithm::RSA);
        assert_eq!(len, 4096);
        assert!(!sym);
    }
}
