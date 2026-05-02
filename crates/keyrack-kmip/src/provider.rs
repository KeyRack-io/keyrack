// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Change Date: 2030-01-01
// Change License: Apache License, Version 2.0

//! KMIP `CryptoProvider` implementation.
//!
//! W1 delivers the typed contract and configuration model.
//! The actual TTLV wire protocol will be implemented when a KMIP
//! test server (e.g. `PyKMIP`) is integrated into the CI environment.

use async_trait::async_trait;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::KeySpec;
use keyrack_core::provider::{CryptoProvider, EncryptOutput, KeyHandle, SigningAlgorithm};
use keyrack_core::sensitive::Sensitive;
use serde::{Deserialize, Serialize};

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
/// All operations delegate to the remote KMIP server. In W1, the
/// implementation returns [`KeyRackError::Provider`] with an
/// "unimplemented" message — the typed interface is the deliverable.
pub struct KmipProvider {
    config: KmipProviderConfig,
}

impl KmipProvider {
    /// Create a new KMIP provider from configuration.
    ///
    /// Does not establish a connection until the first operation.
    pub fn new(config: KmipProviderConfig) -> Self {
        tracing::info!(
            endpoint = %config.endpoint,
            "KMIP provider configured (operations not yet wired)"
        );
        Self { config }
    }

    /// Return the configured endpoint.
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    fn not_yet(&self, op: &str) -> KeyRackError {
        KeyRackError::Provider(format!(
            "KMIP {op} not yet implemented (endpoint: {}). \
             Full TTLV encoding lands in a follow-up.",
            self.config.endpoint
        ))
    }
}

#[async_trait]
impl CryptoProvider for KmipProvider {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        // KMIP Create operation: sends a Create request with the
        // appropriate cryptographic algorithm and key length, receives
        // a Unique Identifier.
        tracing::debug!(
            spec = ?spec,
            endpoint = %self.config.endpoint,
            "KMIP Create (stubbed)"
        );
        Err(self.not_yet("Create"))
    }

    async fn encrypt(
        &self,
        handle: &KeyHandle,
        _plaintext: &[u8],
        _aad: &[u8],
    ) -> Result<EncryptOutput> {
        tracing::debug!(
            key_id = %handle.key_id,
            "KMIP Encrypt (stubbed)"
        );
        Err(self.not_yet("Encrypt"))
    }

    async fn decrypt(
        &self,
        handle: &KeyHandle,
        _ciphertext: &[u8],
        _aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        tracing::debug!(
            key_id = %handle.key_id,
            "KMIP Decrypt (stubbed)"
        );
        Err(self.not_yet("Decrypt"))
    }

    async fn sign(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        _message: &[u8],
    ) -> Result<Vec<u8>> {
        tracing::debug!(
            key_id = %handle.key_id,
            algorithm = ?algorithm,
            "KMIP Sign (stubbed)"
        );
        Err(self.not_yet("Sign"))
    }

    async fn verify(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool> {
        tracing::debug!(
            key_id = %handle.key_id,
            algorithm = ?algorithm,
            "KMIP Verify (stubbed)"
        );
        Err(self.not_yet("Verify"))
    }

    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        tracing::debug!(
            length = length,
            "KMIP RNGRetrieve (stubbed)"
        );
        Err(self.not_yet("RNGRetrieve"))
    }

    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()> {
        // KMIP Destroy operation: sends a Destroy request with the
        // Unique Identifier, receives confirmation.
        tracing::debug!(
            key_id = %handle.key_id,
            "KMIP Destroy (stubbed)"
        );
        Err(self.not_yet("Destroy"))
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

    #[tokio::test]
    async fn operations_return_not_implemented() {
        let provider = KmipProvider::new(test_config());

        let gen_err = provider.generate_key(&KeySpec::Aes256).await;
        assert!(gen_err.is_err());
        let msg = format!("{}", gen_err.unwrap_err());
        assert!(msg.contains("not yet implemented"));

        let handle = KeyHandle {
            key_id: "test-id".into(),
            key_spec: KeySpec::Aes256,
        };
        assert!(provider.encrypt(&handle, b"pt", b"aad").await.is_err());
        assert!(provider.decrypt(&handle, b"ct", b"aad").await.is_err());
        assert!(
            provider
                .sign(&handle, SigningAlgorithm::Ed25519, b"msg")
                .await
                .is_err()
        );
        assert!(
            provider
                .verify(&handle, SigningAlgorithm::Ed25519, b"msg", b"sig")
                .await
                .is_err()
        );
        assert!(provider.generate_random(32).await.is_err());
        assert!(provider.destroy_key(&handle).await.is_err());
    }
}
