// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit experimental context-derived wrapping. Opaque leases retain their
//! original native owner; no key material enters this registry.

mod native;
#[cfg(all(test, feature = "softhsm-tests"))]
mod tests;

use super::Pkcs11Provider;
use keyrack_core::creation::{
    A2ClosureClaim, A2ClosureFact, A2ClosureVerifier, CreationBinding, CreationRequest,
};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::{KeySpec, ProviderRef};
use keyrack_core::lid::Lid;
use keyrack_core::provider::{
    EncryptOutput, GeneratedWrappedKey, KeyHandle, WrappedKeyClosure, WrappedKeyLease,
};
use keyrack_core::sensitive::Sensitive;
use keyrack_core::wrapping::{
    VersionedKeyId, WrappedKeyFormat, WrappedKeyLifecycle, WrappingCapabilities,
    WrappingCapability, WrappingContext, WrappingContextVersion, WrappingIdentifier,
    WrappingKeyPurpose, WrappingOperation,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub const CONTEXT_DERIVED_WRAPPING_MECHANISM: &str = "pkcs11:aes256-cbc-sha256-kw:v1";
const FRAME: &[u8; 8] = b"KRCBKW01";
// Closed evidence is retained; restart clears it, never reconstructs closure.
const MAX_OWNERS: usize = 4096;

pub(super) fn ensure_cleanup_confirmed(module: &super::SharedModule) -> Result<()> {
    native::ensure_cleanup_confirmed(module)
}

fn failure(message: &str) -> KeyRackError {
    KeyRackError::Provider(format!("context-derived PKCS#11 wrapping: {message}"))
}

fn finish<T>(outcome: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (outcome, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(failure(&format!(
            "operation failed ({error}); original cleanup unconfirmed ({cleanup})"
        ))),
    }
}

fn key_size(spec: &KeySpec) -> Result<usize> {
    match spec {
        KeySpec::Aes128 => Ok(16),
        KeySpec::Aes256 => Ok(32),
        _ => Err(failure("only AES128/AES256 children supported")),
    }
}

struct Profile {
    provider_ref: ProviderRef,
    mechanism: WrappingIdentifier,
    security_domain: WrappingIdentifier,
    capabilities: WrappingCapabilities,
}

impl Profile {
    fn new(
        provider_ref: ProviderRef,
        mechanism: WrappingIdentifier,
        security_domain: WrappingIdentifier,
    ) -> Result<Self> {
        WrappingIdentifier::new(provider_ref.as_str()).map_err(|e| failure(&e.to_string()))?;
        if mechanism.as_str() != CONTEXT_DERIVED_WRAPPING_MECHANISM {
            return Err(failure("unsupported explicitly selected mechanism"));
        }
        let mut tuples = Vec::new();
        for child_spec in [KeySpec::Aes128, KeySpec::Aes256] {
            for operation in [
                WrappingOperation::Generate,
                WrappingOperation::Open,
                WrappingOperation::Close,
            ] {
                tuples.push(WrappingCapability {
                    parent_spec: KeySpec::Aes256,
                    child_spec: child_spec.clone(),
                    key_format: WrappedKeyFormat::RawSecret,
                    purpose: WrappingKeyPurpose::EncryptDecrypt,
                    mechanism: mechanism.clone(),
                    context_version: WrappingContextVersion::V1,
                    operation,
                    lifecycle: WrappedKeyLifecycle::SessionObject,
                });
            }
        }
        let capabilities =
            WrappingCapabilities::new(tuples).map_err(|e| failure(&e.to_string()))?;
        Ok(Self {
            provider_ref,
            mechanism,
            security_domain,
            capabilities,
        })
    }

    fn validate(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        operation: WrappingOperation,
    ) -> Result<()> {
        context
            .canonical_bytes()
            .map_err(|e| failure(&e.to_string()))?;
        if context.provider_ref != self.provider_ref
            || context.security_domain != self.security_domain
            || context.mechanism != self.mechanism
            || context.child.lid == context.parent.lid
            || parent.key_spec != KeySpec::Aes256
            || context.public_material_sha256.is_some()
        {
            return Err(failure("exact provider/domain/context/parent mismatch"));
        }
        WrappingIdentifier::new(&parent.key_id).map_err(|e| failure(&e.to_string()))?;
        self.capabilities
            .require(&WrappingCapability::requested(
                context,
                operation,
                WrappedKeyLifecycle::SessionObject,
            ))
            .map_err(|e| failure(&e.to_string()))
    }

    fn self_test_context(&self, child_spec: KeySpec) -> Result<WrappingContext> {
        Ok(WrappingContext {
            version: WrappingContextVersion::V1,
            child: VersionedKeyId::new(Lid::from_bytes([1; 32]), 1)
                .map_err(|e| failure(&e.to_string()))?,
            parent: VersionedKeyId::new(Lid::from_bytes([2; 32]), 1)
                .map_err(|e| failure(&e.to_string()))?,
            parent_spec: KeySpec::Aes256,
            child_spec,
            key_format: WrappedKeyFormat::RawSecret,
            purpose: WrappingKeyPurpose::EncryptDecrypt,
            provider_ref: self.provider_ref.clone(),
            security_domain: self.security_domain.clone(),
            mechanism: self.mechanism.clone(),
            public_material_sha256: None,
        })
    }
}

struct Entry {
    context: WrappingContext,
    parent: KeyHandle,
    creation: Option<CreationBinding>,
    owner: Option<native::Owner>,
    envelope_digest: Option<[u8; 32]>,
    issued: Option<WrappedKeyLease>,
    label: String,
}

impl Entry {
    fn owner(&mut self) -> Result<&mut native::Owner> {
        self.owner
            .as_mut()
            .ok_or_else(|| failure("original owner unavailable"))
    }
    fn issue(&mut self, id: &str) -> Result<WrappedKeyLease> {
        let lease = WrappedKeyLease::new(
            KeyHandle {
                key_id: id.into(),
                key_spec: self.context.child_spec.clone(),
            },
            WrappingIdentifier::new(id).map_err(|e| failure(&e.to_string()))?,
            &self.context,
        )?;
        self.issued = Some(lease.clone());
        Ok(lease)
    }
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    attempts: HashMap<(Uuid, Uuid), String>,
}

pub(super) struct ContextWrapping {
    profile: Profile,
    incarnation: Uuid,
    state: Mutex<State>,
    #[cfg(test)]
    next_fault: Mutex<Option<native::Fault>>,
}

impl ContextWrapping {
    pub(super) fn new(
        provider: &Pkcs11Provider,
        provider_ref: ProviderRef,
        mechanism: WrappingIdentifier,
        security_domain: WrappingIdentifier,
    ) -> Result<Arc<Self>> {
        native::ensure_cleanup_confirmed(&provider.module)?;
        let profile = Profile::new(provider_ref, mechanism, security_domain)?;
        native::self_test(provider, &profile)?;
        Ok(Arc::new(Self {
            profile,
            incarnation: Uuid::new_v4(),
            state: Mutex::new(State::default()),
            #[cfg(test)]
            next_fault: Mutex::new(None),
        }))
    }

    pub(super) fn capabilities(&self) -> WrappingCapabilities {
        self.profile.capabilities.clone()
    }

    async fn serialized<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&Self, &mut State) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let engine = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let mut state = engine
                .state
                .lock()
                .map_err(|_| failure("owner registry poisoned"))?;
            operation(&engine, &mut state)
        })
        .await
        .map_err(|e| failure(&format!("owned native task failed: {e}")))?
    }

    fn reserve(
        &self,
        state: &mut State,
        context: WrappingContext,
        parent: KeyHandle,
        creation: Option<CreationBinding>,
    ) -> Result<String> {
        if state.entries.len() >= MAX_OWNERS {
            return Err(failure(
                "owner evidence ledger exhausted (4096); no evidence evicted",
            ));
        }
        if let Some(binding) = &creation {
            if state
                .attempts
                .contains_key(&(binding.operation(), binding.attempt()))
            {
                return Err(failure(
                    "creation already dispatched; reconcile original attempt",
                ));
            }
        }
        let id = format!("kr-cbc-{}-{}", self.incarnation, Uuid::new_v4());
        let label = creation
            .as_ref()
            .map_or_else(|| id.clone(), |c| c.correlation().to_owned());
        if let Some(binding) = &creation {
            state
                .attempts
                .insert((binding.operation(), binding.attempt()), id.clone());
        }
        state.entries.insert(
            id.clone(),
            Entry {
                context,
                parent,
                creation,
                owner: None,
                envelope_digest: None,
                issued: None,
                label,
            },
        );
        Ok(id)
    }

    pub(super) async fn generate(
        self: &Arc<Self>,
        provider: Pkcs11Provider,
        context: &WrappingContext,
        parent: &KeyHandle,
        creation: &CreationBinding,
    ) -> Result<GeneratedWrappedKey> {
        native::ensure_cleanup_confirmed(&provider.module)?;
        self.profile
            .validate(context, parent, WrappingOperation::Generate)?;
        let (context, parent, creation) = (context.clone(), parent.clone(), creation.clone());
        self.serialized(move |engine, state| {
            let id = engine.reserve(state, context.clone(), parent.clone(), Some(creation))?;
            let entry = state.entries.get_mut(&id).expect("reserved");
            entry.owner = Some(native::Owner::new(&provider)?);
            #[cfg(test)]
            {
                entry.owner()?.fault = engine.next_fault.lock().unwrap().take();
            }
            let label = entry.label.clone();
            let wrapped = match entry.owner()?.generate(&context, &parent, &label) {
                Ok(bytes) => bytes,
                Err(error) => return finish(Err(error), entry.owner()?.close()),
            };
            let mut envelope = FRAME.to_vec();
            envelope.extend(wrapped);
            entry.envelope_digest = Some(*blake3::hash(&envelope).as_bytes());
            let lease = entry.issue(&id)?;
            Ok(GeneratedWrappedKey { envelope, lease })
        })
        .await
    }

    pub(super) async fn open(
        self: &Arc<Self>,
        provider: Pkcs11Provider,
        context: &WrappingContext,
        parent: &KeyHandle,
        envelope: &[u8],
    ) -> Result<WrappedKeyLease> {
        native::ensure_cleanup_confirmed(&provider.module)?;
        self.profile
            .validate(context, parent, WrappingOperation::Open)?;
        if envelope.len() != FRAME.len() + key_size(&context.child_spec)? + 8
            || !envelope.starts_with(FRAME)
        {
            return Err(failure("invalid context-derived frame or length"));
        }
        let (context, parent, wrapped) = (
            context.clone(),
            parent.clone(),
            envelope[FRAME.len()..].to_vec(),
        );
        self.serialized(move |engine, state| {
            let id = engine.reserve(state, context.clone(), parent.clone(), None)?;
            let entry = state.entries.get_mut(&id).expect("reserved");
            entry.owner = Some(native::Owner::new(&provider)?);
            #[cfg(test)]
            {
                entry.owner()?.fault = engine.next_fault.lock().unwrap().take();
            }
            let label = entry.label.clone();
            if let Err(error) = entry.owner()?.open(&context, &parent, &wrapped, &label) {
                return finish(Err(error), entry.owner()?.close());
            }
            entry.issue(&id)
        })
        .await
    }

    pub(super) async fn close(
        self: &Arc<Self>,
        lease: &WrappedKeyLease,
    ) -> Result<WrappedKeyClosure> {
        let lease = lease.clone();
        self.serialized(move |_, state| {
            let entry = state
                .entries
                .get_mut(lease.object().as_str())
                .ok_or_else(|| failure("unknown/foreign lease"))?;
            if entry.issued.as_ref() != Some(&lease) {
                return Err(failure("lease not issued with these exact bindings"));
            }
            entry.owner()?.close()?;
            Ok(WrappedKeyClosure {
                fact: A2ClosureFact::SessionClosed {
                    session: lease.object().as_str().into(),
                },
                context_sha256: lease.context_sha256(),
            })
        })
        .await
    }

    pub(super) async fn encrypt(
        self: &Arc<Self>,
        handle: &KeyHandle,
        data: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        let (handle, data, aad) = (handle.clone(), data.to_vec(), aad.to_vec());
        self.serialized(move |_, state| {
            let entry = state.entries.get_mut(&handle.key_id).ok_or_else(|| {
                failure("unknown/foreign handle; derive-only roots cannot encrypt")
            })?;
            if entry.issued.as_ref().map(WrappedKeyLease::handle) != Some(&handle) {
                return Err(failure("handle not issued"));
            }
            let (context, label) = (entry.context.clone(), entry.label.clone());
            entry.owner()?.encrypt(&context, &label, &data, &aad)
        })
        .await
    }

    pub(super) async fn decrypt(
        self: &Arc<Self>,
        handle: &KeyHandle,
        data: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        let (handle, data, aad) = (handle.clone(), data.to_vec(), aad.to_vec());
        self.serialized(move |_, state| {
            let entry = state.entries.get_mut(&handle.key_id).ok_or_else(|| {
                failure("unknown/foreign handle; derive-only roots cannot decrypt")
            })?;
            if entry.issued.as_ref().map(WrappedKeyLease::handle) != Some(&handle) {
                return Err(failure("handle not issued"));
            }
            let (context, label) = (entry.context.clone(), entry.label.clone());
            entry.owner()?.decrypt(&context, &label, &data, &aad)
        })
        .await
    }

    pub(super) async fn generate_root(
        provider: Pkcs11Provider,
        spec: &KeySpec,
    ) -> Result<KeyHandle> {
        if *spec != KeySpec::Aes256 {
            return Err(failure(
                "dedicated provider creates only AES256 derive-only roots",
            ));
        }
        tokio::task::spawn_blocking(move || {
            let label = Uuid::new_v4().to_string();
            let mut owner = native::Owner::new(&provider)?;
            let outcome = owner.generate_root(&label);
            finish(outcome, owner.close())?;
            Ok(KeyHandle {
                key_id: label,
                key_spec: KeySpec::Aes256,
            })
        })
        .await
        .map_err(|e| failure(&format!("root generation task: {e}")))?
    }
}

impl A2ClosureVerifier for ContextWrapping {
    fn verify(&self, request: &CreationRequest, claim: &A2ClosureClaim) -> Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| failure("owner registry poisoned"))?;
        let id = state
            .attempts
            .get(&(request.operation, request.attempt))
            .ok_or_else(|| failure("unknown creation attempt"))?;
        let entry = state
            .entries
            .get(id)
            .ok_or_else(|| failure("original creation evidence lost"))?;
        entry
            .creation
            .as_ref()
            .ok_or_else(|| failure("ordinary open has no creation proof"))?
            .require(request)?;
        if entry.context != request.context()?
            || claim.intent_fingerprint != request.fingerprint()?
            || entry.envelope_digest != Some(claim.envelope_digest)
            || entry.issued.is_none()
            || !entry.owner.as_ref().is_some_and(|owner| owner.closed)
            || claim.fact
                != (A2ClosureFact::SessionClosed {
                    session: id.clone(),
                })
        {
            return Err(failure("no exact matching successfully closed creation"));
        }
        self.profile
            .validate(&entry.context, &entry.parent, WrappingOperation::Generate)
    }
}
