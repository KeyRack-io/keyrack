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

//! In-memory provider for test fixtures.
//!
//! A thin wrapper around [`SoftwareProvider`](super::software::SoftwareProvider)
//! that adds nothing except a distinct type. This lets tests and
//! conformance harnesses distinguish "I'm using the fixture provider"
//! from "I'm using the software provider configured for dev".
//!
//! All key material is ephemeral — dropped when the provider is dropped.

use crate::error::Result;
use crate::key::KeySpec;
use crate::provider::{
    CryptoProvider, EncryptOutput, KeyHandle, ProviderCapabilities, SigningAlgorithm,
};
use crate::sensitive::Sensitive;
use async_trait::async_trait;

/// Ephemeral in-memory provider for test fixtures.
///
/// Delegates every operation to a private `SoftwareProvider`. Exists
/// as a separate type so `ProviderClass::InMemory` has a concrete
/// implementation distinct from `ProviderClass::Software`.
pub struct InMemoryProvider {
    inner: super::software::SoftwareProvider,
}

impl InMemoryProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: super::software::SoftwareProvider::new(),
        }
    }
}

impl Default for InMemoryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CryptoProvider for InMemoryProvider {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        self.inner.generate_key(spec).await
    }

    async fn encrypt(
        &self,
        handle: &KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        self.inner.encrypt(handle, plaintext, aad).await
    }

    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        self.inner.decrypt(handle, ciphertext, aad).await
    }

    async fn sign(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.inner.sign(handle, algorithm, message).await
    }

    async fn verify(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.inner
            .verify(handle, algorithm, message, signature)
            .await
    }

    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        self.inner.generate_random(length).await
    }

    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()> {
        self.inner.destroy_key(handle).await
    }

    fn capabilities(&self) -> ProviderCapabilities {
        let mut caps = self.inner.capabilities();
        caps.provider_name = "in_memory".into();
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // If you flip either flag to true you MUST have overridden the
    // corresponding method to keep plaintext in-boundary AND added a
    // test proving it. This guard converts a silent capability lie
    // into a conscious, reviewed change.
    #[test]
    fn capability_flags_are_honest() {
        let provider = InMemoryProvider::new();
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

    #[tokio::test]
    async fn inmem_encrypt_decrypt_round_trip() {
        let provider = InMemoryProvider::new();
        let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

        let ct = provider.encrypt(&handle, b"test", b"").await.unwrap();
        let pt = provider
            .decrypt(&handle, &ct.ciphertext, b"")
            .await
            .unwrap();
        assert_eq!(pt.expose().as_slice(), b"test");
    }

    #[tokio::test]
    async fn inmem_sign_verify_ed25519() {
        let provider = InMemoryProvider::new();
        let handle = provider.generate_key(&KeySpec::Ed25519).await.unwrap();

        let sig = provider
            .sign(&handle, SigningAlgorithm::Ed25519, b"msg")
            .await
            .unwrap();

        assert!(provider
            .verify(&handle, SigningAlgorithm::Ed25519, b"msg", &sig)
            .await
            .unwrap());
    }
}
