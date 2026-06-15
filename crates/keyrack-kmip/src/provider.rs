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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        _aad: &[u8],
    ) -> Result<EncryptOutput> {
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
        _aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
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
            supports_atomic_data_key: true,
            supports_atomic_re_encrypt: true,
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
        assert!(caps.supports_atomic_data_key);
        assert_eq!(caps.key_specs.len(), 4);
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
