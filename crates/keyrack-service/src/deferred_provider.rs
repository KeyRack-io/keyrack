// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deferred backend construction. Requests never wait for a constructor or
//! replay an operation after an ambiguous backend failure.

use async_trait::async_trait;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::KeySpec;
use keyrack_core::provider::{
    CryptoProvider, EncryptOutput, GenerateDataKeyOutput, GeneratedWrappedKey, KeyHandle,
    MacAlgorithm, ProviderCapabilities, SigningAlgorithm, WrappedKeyClosure, WrappedKeyLease,
};
use keyrack_core::sensitive::Sensitive;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub type ProviderFactory = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<Arc<dyn CryptoProvider>>> + Send>> + Send + Sync,
>;
pub type AvailabilityProbe =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

/// Adapt a native constructor without allowing timeout cancellation to start
/// overlapping blocking calls. The permit lives inside the native work.
pub fn blocking_factory(
    construct: impl Fn() -> Result<Arc<dyn CryptoProvider>> + Send + Sync + 'static,
) -> ProviderFactory {
    let construct = Arc::new(construct);
    let gate = Arc::new(tokio::sync::Semaphore::new(1));
    Arc::new(move || {
        let construct = construct.clone();
        let gate = gate.clone();
        Box::pin(async move {
            let permit = gate.try_acquire_owned().map_err(|_| {
                KeyRackError::ProviderUnavailable("construction still in flight".into())
            })?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                construct()
            })
            .await
            .map_err(|_| KeyRackError::ProviderUnavailable("constructor task failed".into()))?
        })
    })
}

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DeferredProvider {
    name: String,
    provider: Arc<OnceLock<Arc<dyn CryptoProvider>>>,
    capabilities: ProviderCapabilities,
    probe: Option<AvailabilityProbe>,
    initialization: tokio::task::AbortHandle,
}

impl DeferredProvider {
    /// Local configuration must be validated before calling this constructor.
    /// Native factories must retain their admission permit until blocking work
    /// actually exits: cancelling a future cannot cancel a native library call.
    pub fn new(
        name: String,
        capabilities: ProviderCapabilities,
        factory: ProviderFactory,
        probe: Option<AvailabilityProbe>,
    ) -> Self {
        let provider = Arc::new(OnceLock::new());
        let target = Arc::clone(&provider);
        let task = tokio::spawn(async move {
            let mut backoff = INITIAL_BACKOFF;
            loop {
                if let Ok(Ok(ready)) = tokio::time::timeout(ATTEMPT_TIMEOUT, factory()).await {
                    let _ = target.set(ready);
                    break;
                }
                // Authentication refusal is also unavailability. Revocation
                // can be reversed without replacing the service process.
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        });
        Self {
            name,
            provider,
            capabilities,
            probe,
            initialization: task.abort_handle(),
        }
    }

    fn unavailable(&self) -> KeyRackError {
        KeyRackError::ProviderUnavailable(format!("provider '{}' is unavailable", self.name))
    }

    fn get(&self) -> Result<&Arc<dyn CryptoProvider>> {
        self.provider.get().ok_or_else(|| self.unavailable())
    }

    fn backend_result<T>(&self, result: Result<T>) -> Result<T> {
        // These errors came from the selected backend, not service policy or
        // local configuration. Never infer permanent availability from an
        // error class chosen by a remote server or native module.
        result.map_err(|_| self.unavailable())
    }
}

impl Drop for DeferredProvider {
    fn drop(&mut self) {
        self.initialization.abort();
    }
}

#[async_trait]
impl CryptoProvider for DeferredProvider {
    async fn check_readiness(&self) -> Result<()> {
        let provider = self.get()?;
        let result = if let Some(probe) = &self.probe {
            probe().await
        } else {
            provider.check_readiness().await
        };
        self.backend_result(result)
    }

    fn capabilities(&self) -> ProviderCapabilities {
        self.provider.get().map_or_else(
            || self.capabilities.clone(),
            |provider| provider.capabilities(),
        )
    }

    fn wrapping_capabilities(&self) -> keyrack_core::wrapping::WrappingCapabilities {
        self.provider
            .get()
            .map_or_else(Default::default, |provider| {
                provider.wrapping_capabilities()
            })
    }

    fn wrapping_closure_verifier(
        &self,
    ) -> Option<Arc<dyn keyrack_core::creation::A2ClosureVerifier>> {
        self.provider
            .get()
            .and_then(|provider| provider.wrapping_closure_verifier())
    }

    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        self.backend_result(self.get()?.generate_key(spec).await)
    }

    async fn encrypt(
        &self,
        handle: &KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        self.backend_result(self.get()?.encrypt(handle, plaintext, aad).await)
    }

    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        self.backend_result(self.get()?.decrypt(handle, ciphertext, aad).await)
    }

    async fn sign(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.backend_result(self.get()?.sign(handle, algorithm, message).await)
    }

    async fn verify(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.backend_result(
            self.get()?
                .verify(handle, algorithm, message, signature)
                .await,
        )
    }

    async fn sign_digest(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        self.backend_result(self.get()?.sign_digest(handle, algorithm, digest).await)
    }

    async fn verify_digest(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.backend_result(
            self.get()?
                .verify_digest(handle, algorithm, digest, signature)
                .await,
        )
    }

    async fn generate_mac(
        &self,
        handle: &KeyHandle,
        algorithm: MacAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.backend_result(self.get()?.generate_mac(handle, algorithm, message).await)
    }

    async fn verify_mac(
        &self,
        handle: &KeyHandle,
        algorithm: MacAlgorithm,
        message: &[u8],
        mac: &[u8],
    ) -> Result<bool> {
        self.backend_result(
            self.get()?
                .verify_mac(handle, algorithm, message, mac)
                .await,
        )
    }

    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        self.backend_result(self.get()?.generate_random(length).await)
    }

    async fn generate_data_key(
        &self,
        wrapping_handle: &KeyHandle,
        dek_length: usize,
        aad: &[u8],
    ) -> Result<GenerateDataKeyOutput> {
        self.backend_result(
            self.get()?
                .generate_data_key(wrapping_handle, dek_length, aad)
                .await,
        )
    }

    async fn re_encrypt(
        &self,
        source_handle: &KeyHandle,
        ciphertext: &[u8],
        source_aad: &[u8],
        dest_handle: &KeyHandle,
        dest_aad: &[u8],
    ) -> Result<EncryptOutput> {
        self.backend_result(
            self.get()?
                .re_encrypt(source_handle, ciphertext, source_aad, dest_handle, dest_aad)
                .await,
        )
    }

    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()> {
        self.backend_result(self.get()?.destroy_key(handle).await)
    }

    async fn generate_wrapped_key(
        &self,
        context: &keyrack_core::wrapping::WrappingContext,
        parent: &KeyHandle,
        creation: &keyrack_core::creation::CreationBinding,
    ) -> Result<GeneratedWrappedKey> {
        self.backend_result(
            self.get()?
                .generate_wrapped_key(context, parent, creation)
                .await,
        )
    }

    async fn open_wrapped_key(
        &self,
        context: &keyrack_core::wrapping::WrappingContext,
        parent: &KeyHandle,
        envelope: &[u8],
    ) -> Result<WrappedKeyLease> {
        self.backend_result(
            self.get()?
                .open_wrapped_key(context, parent, envelope)
                .await,
        )
    }

    async fn close_wrapped_key(&self, lease: &WrappedKeyLease) -> Result<WrappedKeyClosure> {
        self.backend_result(self.get()?.close_wrapped_key(lease).await)
    }

    async fn export_key_material(&self, handle: &KeyHandle) -> Result<Sensitive<Vec<u8>>> {
        self.backend_result(self.get()?.export_key_material(handle).await)
    }

    async fn make_key_exportable(&self, handle: &KeyHandle) -> Result<()> {
        self.backend_result(self.get()?.make_key_exportable(handle).await)
    }

    async fn revoke_key_exportability(&self, handle: &KeyHandle) -> Result<Option<KeyHandle>> {
        self.backend_result(self.get()?.revoke_key_exportability(handle).await)
    }

    async fn import_key_material(
        &self,
        spec: &KeySpec,
        material: Sensitive<Vec<u8>>,
    ) -> Result<KeyHandle> {
        self.backend_result(self.get()?.import_key_material(spec, material).await)
    }
}
