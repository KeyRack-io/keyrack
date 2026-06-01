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

//! Parsec-backed CryptoProvider for KeyRack.
//!
//! This crate implements `keyrack_core::provider::CryptoProvider` by
//! delegating to Parsec, which abstracts over TPM 2.0, PKCS#11,
//! Mbed Crypto (PSA), and other hardware security backends.
//!
//! ## Architecture
//!
//! ```text
//! KeyRack Service
//!   └── keyrack-parsec (CryptoProvider)
//!         └── parsec-client (IPC to parsec daemon)
//!               └── Parsec daemon
//!                     ├── TPM 2.0 provider
//!                     ├── PKCS#11 provider
//!                     ├── Mbed Crypto (PSA) provider
//!                     └── ...
//! ```
//!
//! ## Status
//!
//! This is a structural stub. The real implementation requires the
//! `parsec-client` crate connected to a running Parsec daemon.
//! All crypto operations currently return a `Provider` error indicating
//! the integration is pending.

use async_trait::async_trait;
use keyrack_core::error::KeyRackError;
use keyrack_core::key::KeySpec;
use keyrack_core::provider::{
    CryptoProvider, EncryptOutput, GenerateDataKeyOutput, KeyHandle, ProviderCapabilities,
    SigningAlgorithm,
};
use keyrack_core::sensitive::Sensitive;

/// Configuration for connecting to a Parsec daemon.
#[derive(Debug, Clone)]
pub struct ParsecProviderConfig {
    /// Unix socket path to the Parsec daemon (e.g. `/run/parsec/parsec.sock`).
    pub service_endpoint: String,
}

impl Default for ParsecProviderConfig {
    fn default() -> Self {
        Self {
            service_endpoint: "/run/parsec/parsec.sock".to_string(),
        }
    }
}

/// Parsec-backed `CryptoProvider`.
///
/// In production, this struct would hold a `parsec_client::BasicClient`
/// connected to the Parsec daemon over the configured Unix socket.
/// The daemon then routes crypto operations to whichever hardware
/// backend (TPM, PKCS#11, PSA Crypto) is configured on the host.
#[derive(Debug)]
pub struct ParsecProvider {
    config: ParsecProviderConfig,
}

impl ParsecProvider {
    pub fn new(config: ParsecProviderConfig) -> Self {
        tracing::info!(
            endpoint = %config.service_endpoint,
            "creating Parsec crypto provider (stub)"
        );
        Self { config }
    }

    fn stub_error() -> KeyRackError {
        KeyRackError::Provider(
            "parsec integration pending: install parsec-client and connect to daemon".into(),
        )
    }

    /// Returns the configured daemon endpoint.
    pub fn endpoint(&self) -> &str {
        &self.config.service_endpoint
    }
}

#[async_trait]
impl CryptoProvider for ParsecProvider {
    async fn generate_key(&self, _spec: &KeySpec) -> keyrack_core::error::Result<KeyHandle> {
        // Real impl: parsec_client::BasicClient::psa_generate_key(key_name, attributes)
        Err(Self::stub_error())
    }

    async fn encrypt(
        &self,
        _handle: &KeyHandle,
        _plaintext: &[u8],
        _aad: &[u8],
    ) -> keyrack_core::error::Result<EncryptOutput> {
        // Real impl: parsec_client::BasicClient::psa_aead_encrypt(key_name, alg, nonce, aad, plaintext)
        Err(Self::stub_error())
    }

    async fn decrypt(
        &self,
        _handle: &KeyHandle,
        _ciphertext: &[u8],
        _aad: &[u8],
    ) -> keyrack_core::error::Result<Sensitive<Vec<u8>>> {
        // Real impl: parsec_client::BasicClient::psa_aead_decrypt(key_name, alg, nonce, aad, ciphertext)
        Err(Self::stub_error())
    }

    async fn sign(
        &self,
        _handle: &KeyHandle,
        _algorithm: SigningAlgorithm,
        _message: &[u8],
    ) -> keyrack_core::error::Result<Vec<u8>> {
        // Real impl: parsec_client::BasicClient::psa_sign_hash(key_name, hash, sign_algorithm)
        Err(Self::stub_error())
    }

    async fn verify(
        &self,
        _handle: &KeyHandle,
        _algorithm: SigningAlgorithm,
        _message: &[u8],
        _signature: &[u8],
    ) -> keyrack_core::error::Result<bool> {
        // Real impl: parsec_client::BasicClient::psa_verify_hash(key_name, hash, signature, sign_algorithm)
        Err(Self::stub_error())
    }

    async fn generate_random(
        &self,
        _length: usize,
    ) -> keyrack_core::error::Result<Sensitive<Vec<u8>>> {
        // Real impl: parsec_client::BasicClient::psa_generate_random(length)
        Err(Self::stub_error())
    }

    async fn generate_data_key(
        &self,
        _wrapping_handle: &KeyHandle,
        _dek_length: usize,
        _aad: &[u8],
    ) -> keyrack_core::error::Result<GenerateDataKeyOutput> {
        // Real impl: generate random DEK via PSA, then encrypt it with the wrapping key.
        // Parsec doesn't have an atomic generate-data-key primitive, so this
        // composes psa_generate_random + psa_aead_encrypt.
        Err(Self::stub_error())
    }

    async fn destroy_key(&self, _handle: &KeyHandle) -> keyrack_core::error::Result<()> {
        // Real impl: parsec_client::BasicClient::psa_destroy_key(key_name)
        Err(Self::stub_error())
    }

    fn capabilities(&self) -> ProviderCapabilities {
        // In production this would query the Parsec daemon for its list of
        // providers and supported algorithms via `list_providers()` +
        // `list_opcodes()`, then map those to KeyRack's KeySpec/CryptoOperation
        // model. For now, return an empty capability set.
        ProviderCapabilities {
            provider_name: format!("parsec({})", self.config.service_endpoint),
            key_specs: Vec::new(),
            supports_generate_random: false,
            supports_atomic_data_key: false,
            supports_atomic_re_encrypt: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_standard_socket() {
        let cfg = ParsecProviderConfig::default();
        assert_eq!(cfg.service_endpoint, "/run/parsec/parsec.sock");
    }

    #[tokio::test]
    async fn stub_generate_key_returns_error() {
        let provider = ParsecProvider::new(ParsecProviderConfig::default());
        let result = provider.generate_key(&KeySpec::Aes256).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("parsec integration pending"));
    }

    #[test]
    fn capabilities_report_provider_name() {
        let provider = ParsecProvider::new(ParsecProviderConfig::default());
        let caps = provider.capabilities();
        assert!(caps.provider_name.starts_with("parsec("));
        assert!(caps.key_specs.is_empty());
    }
}
