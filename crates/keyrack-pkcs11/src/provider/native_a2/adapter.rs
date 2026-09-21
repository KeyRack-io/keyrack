// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared-contract-shaped, native-only conformance adapter. NOT a `CryptoProvider`.
//!
//! The distinction is intentional: KW cannot authenticate `WrappingContext` and
//! no token/profile is qualified. Returning its mechanics result through the
//! authenticated `CryptoProvider` trait would violate that trait. The production
//! provider keeps empty wrapping capabilities, unsupported wrapping operations,
//! and no A2 closure verifier. This explicit feature-gated adapter exercises the
//! corrected `CreationBinding` and lease/result shapes without enabling publication.
//!
//! One blocking mutex owns all original sessions. Reservation precedes Generate;
//! issuance follows material creation under the SAME lock. Cancellation cannot
//! drop the effect owner. No token operation is retried. Closed/failed entries
//! remain bounded tombstones; exhaustion refuses work, never evicts evidence.

use super::{refused, NativeA2Session, NativeEnvelope, NativeWrapMode, Pkcs11Provider};
use keyrack_core::creation::{A2ClosureFact, CreationBinding};
use keyrack_core::error::Result;
use keyrack_core::provider::{
    EncryptOutput, GeneratedWrappedKey, KeyHandle, WrappedKeyClosure, WrappedKeyLease,
};
use keyrack_core::sensitive::Sensitive;
use keyrack_core::wrapping::{WrappingContext, WrappingIdentifier};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const MAX_OWNERS: usize = 256;
// Only this conformance adapter consumes this frame. It is NOT a durable product
// codec or a modification of custody v1. In particular, do not persist it as a
// qualified ParentWrapped envelope. The explicit mode prohibits KW fallback.
const FRAME: &[u8; 8] = b"KRTEST01";
const HEADER: usize = 8 + 1 + 12 + 32;

fn encode(envelope: &NativeEnvelope) -> Vec<u8> {
    let mut bytes = FRAME.to_vec();
    bytes.push(match envelope.mode {
        NativeWrapMode::GcmCandidate => 1,
        NativeWrapMode::KwMechanicsOnly => 2,
    });
    bytes.extend_from_slice(&envelope.iv);
    bytes.extend_from_slice(&envelope.context_sha256);
    bytes.extend_from_slice(&envelope.ciphertext);
    bytes
}

fn decode(bytes: &[u8], mode: NativeWrapMode, context: &WrappingContext) -> Result<NativeEnvelope> {
    let tag = match mode {
        NativeWrapMode::GcmCandidate => 1,
        NativeWrapMode::KwMechanicsOnly => 2,
    };
    let size = super::key_length(&context.child_spec)?
        + if mode == NativeWrapMode::GcmCandidate {
            16
        } else {
            8
        };
    if bytes.len() != HEADER + size || &bytes[..8] != FRAME || bytes[8] != tag {
        return Err(refused("invalid conformance envelope framing/mode/length"));
    }
    let digest = context
        .context_sha256()
        .map_err(|_| refused("invalid context"))?;
    if bytes[21..HEADER] != digest {
        return Err(refused(
            "conformance context mismatch (host comparison, not authentication)",
        ));
    }
    let mut iv = [0; 12];
    iv.copy_from_slice(&bytes[9..21]);
    if mode == NativeWrapMode::KwMechanicsOnly && iv != [0; 12] {
        return Err(refused("noncanonical KW conformance IV"));
    }
    Ok(NativeEnvelope {
        mode,
        iv,
        context_sha256: digest,
        ciphertext: bytes[HEADER..].to_vec(),
    })
}

struct Entry {
    context: WrappingContext,
    parent: KeyHandle,
    creation: Option<CreationBinding>,
    owner: Option<NativeA2Session>,
    envelope: Option<NativeEnvelope>,
    issued: Option<WrappedKeyLease>,
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    attempts: HashMap<(Uuid, Uuid), String>,
    closing: bool,
}

impl State {
    fn capacity(&self) -> Result<()> {
        if self.closing {
            return Err(refused("native conformance adapter is closed to admission"));
        }
        if self.entries.len() >= MAX_OWNERS {
            return Err(refused("conformance owner capacity exhausted"));
        }
        Ok(())
    }

    fn lease_entry(&mut self, lease: &WrappedKeyLease) -> Result<&mut Entry> {
        let entry = self
            .entries
            .get_mut(lease.object().as_str())
            .ok_or_else(|| refused("unknown/foreign native lease"))?;
        // Public construction of a syntactically valid lease mints no ownership.
        // An entry reserved before generation is not yet an issued lease.
        if entry.issued.as_ref() != Some(lease) {
            return Err(refused(
                "native lease was not issued with these exact bindings",
            ));
        }
        Ok(entry)
    }

    fn handle_entry(&mut self, handle: &KeyHandle) -> Result<&mut Entry> {
        let entry = self
            .entries
            .get_mut(&handle.key_id)
            .ok_or_else(|| refused("unknown/foreign native handle"))?;
        if entry.issued.as_ref().map(WrappedKeyLease::handle) != Some(handle) {
            return Err(refused("native handle was not issued"));
        }
        Ok(entry)
    }
}

impl Entry {
    fn owner(&mut self) -> Result<&mut NativeA2Session> {
        self.owner
            .as_mut()
            .ok_or_else(|| refused("original native owner unavailable"))
    }

    fn issue(&mut self, id: &str) -> Result<WrappedKeyLease> {
        let lease = WrappedKeyLease::new(
            KeyHandle {
                key_id: id.into(),
                key_spec: self.context.child_spec.clone(),
            },
            WrappingIdentifier::new(id).map_err(|_| refused("native lease identifier"))?,
            &self.context,
        )?;
        self.issued = Some(lease.clone());
        Ok(lease)
    }
}

/// Unqualified, explicitly requested native conformance only. No authorization,
/// durable recovery, A2 evidence, or public service registration is supplied.
#[derive(Clone)]
pub struct NativeA2ConformanceAdapter {
    provider: Pkcs11Provider,
    mode: NativeWrapMode,
    incarnation: Uuid,
    state: Arc<Mutex<State>>,
    #[cfg(test)]
    pause: Arc<Mutex<Option<tests::Pause>>>,
}

impl Pkcs11Provider {
    #[must_use]
    pub fn native_a2_conformance_adapter(
        &self,
        mode: NativeWrapMode,
    ) -> NativeA2ConformanceAdapter {
        NativeA2ConformanceAdapter {
            provider: self.clone(),
            mode,
            incarnation: Uuid::new_v4(),
            state: Arc::new(Mutex::new(State::default())),
            #[cfg(test)]
            pause: Arc::new(Mutex::new(None)),
        }
    }
}

impl NativeA2ConformanceAdapter {
    async fn serialized<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Self, &mut State) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let adapter = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = adapter
                .state
                .lock()
                .map_err(|_| refused("native owner lock poisoned"))?;
            work(&adapter, &mut state)
        })
        .await
        .map_err(|_| refused("native owner task failed; outcome unconfirmed"))?
    }

    fn identity(&self) -> String {
        format!("native-a2:{}:{}", self.incarnation, Uuid::new_v4())
    }

    /// Same input/result types as `CryptoProvider`; this explicit conformance route
    /// does NOT promise authenticated wrapping. `CreationBinding` is provenance,
    /// never authority. Only a future qualified profile can enable the trait.
    pub async fn generate_wrapped_key(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        creation: &CreationBinding,
    ) -> Result<GeneratedWrappedKey> {
        let (context, parent, creation) = (context.clone(), parent.clone(), creation.clone());
        self.serialized(move |adapter, state| {
            context
                .canonical_bytes()
                .map_err(|_| refused("invalid context"))?;
            let attempt = (creation.operation(), creation.attempt());
            if state.attempts.contains_key(&attempt) {
                return Err(refused(
                    "creation already dispatched; reconcile original owner",
                ));
            }
            state.capacity()?;
            let id = adapter.identity();
            state.attempts.insert(attempt, id.clone());
            let entry = state.entries.entry(id.clone()).or_insert(Entry {
                context: context.clone(),
                parent: parent.clone(),
                creation: Some(creation.clone()),
                owner: None,
                envelope: None,
                issued: None,
            });
            entry.owner = Some(adapter.provider.native_a2_conformance_session(
                parent.clone(),
                context.clone(),
                Some(creation.clone()),
                adapter.mode,
            )?);
            // The registry owns the original session BEFORE Generate may act.
            #[cfg(test)]
            tests::pause(adapter, false, &id);
            let envelope = entry
                .owner()?
                .generate_wrapped_key(&context, &parent, &creation)?;
            #[cfg(test)]
            tests::pause(adapter, true, &id);
            let bytes = encode(&envelope);
            entry.envelope = Some(envelope);
            let lease = entry.issue(&id)?;
            Ok(GeneratedWrappedKey {
                envelope: bytes,
                lease,
            })
        })
        .await
    }

    /// Ordinary opening carries no creation identity and cannot certify creation.
    pub async fn open_wrapped_key(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        envelope: &[u8],
    ) -> Result<WrappedKeyLease> {
        // Bounded decode precedes allocation/native effects. No raw-key fallback.
        let envelope = decode(envelope, self.mode, context)?;
        let (context, parent) = (context.clone(), parent.clone());
        self.serialized(move |adapter, state| {
            state.capacity()?;
            let id = adapter.identity();
            let entry = state.entries.entry(id.clone()).or_insert(Entry {
                context: context.clone(),
                parent: parent.clone(),
                creation: None,
                owner: None,
                envelope: None,
                issued: None,
            });
            entry.owner = Some(adapter.provider.native_a2_conformance_session(
                parent.clone(),
                context.clone(),
                None,
                adapter.mode,
            )?);
            let result = entry
                .owner()?
                .open_wrapped_key(&context, &parent, &envelope);
            if let Err(error) = result {
                // An errored Unwrap can still have made objects. Retain its owner
                // and explicitly close; failure remains unconfirmed, not evidence.
                let _ = entry.owner()?.close_wrapped_key();
                return Err(error);
            }
            #[cfg(test)]
            tests::pause(adapter, true, &id);
            entry.envelope = Some(envelope);
            entry.issue(&id)
        })
        .await
    }

    pub async fn close_wrapped_key(&self, lease: &WrappedKeyLease) -> Result<WrappedKeyClosure> {
        let lease = lease.clone();
        self.serialized(move |_, state| {
            let entry = state.lease_entry(&lease)?;
            entry.owner()?.close_wrapped_key()?;
            let session = entry
                .owner()?
                .closed_session()
                .ok_or_else(|| refused("close unconfirmed"))?;
            // A report, NOT VerifiedA2Closure. No verifier converts this adapter's
            // reports into creation evidence, including for a successful KW run.
            Ok(WrappedKeyClosure {
                fact: A2ClosureFact::SessionClosed {
                    session: session.to_string(),
                },
                context_sha256: lease.context_sha256(),
            })
        })
        .await
    }

    /// Permanently fence this adapter and close every retained original owner,
    /// including an Open whose result was lost to caller cancellation. A cancelled
    /// Open has no caller-known lease; the conformance runner MUST use this at
    /// teardown, not infer cleanup from the absence of a returned handle.
    ///
    /// Attempts/closed records are retained. Every owner is visited even if one
    /// close fails; unknown/failed closure returns Err and never becomes evidence.
    /// No replacement session, token-wide logout, or module finalization is used.
    pub async fn close_all(&self) -> Result<()> {
        self.serialized(|_, state| {
            state.closing = true;
            let mut failure = None;
            for entry in state.entries.values_mut() {
                if let Err(error) = entry.owner().and_then(NativeA2Session::close_wrapped_key) {
                    failure.get_or_insert(error);
                }
            }
            failure.map_or(Ok(()), Err)
        })
        .await
    }

    /// Close the retained original attempt after Generate errors/caller timeout.
    /// No lease fabrication, fresh session search, retry or evidence conversion.
    pub async fn close_creation_attempt(&self, creation: &CreationBinding) -> Result<()> {
        let creation = creation.clone();
        self.serialized(move |_, state| {
            let id = state
                .attempts
                .get(&(creation.operation(), creation.attempt()))
                .ok_or_else(|| refused("unknown creation attempt"))?;
            let entry = state
                .entries
                .get_mut(id)
                .ok_or_else(|| refused("lost creation owner"))?;
            if entry.creation.as_ref() != Some(&creation) {
                return Err(refused("creation binding mismatch"));
            }
            entry.owner()?.close_wrapped_key()
        })
        .await
    }

    /// Verify retained output, provenance and explicit original-session closure
    /// for conformance assertions only. Not an `A2ClosureVerifier` implementation.
    pub async fn verify_closed_creation(
        &self,
        creation: &CreationBinding,
        envelope: &[u8],
    ) -> Result<()> {
        if envelope.len() > HEADER + 48 {
            return Err(refused("oversized conformance envelope"));
        }
        let (creation, bytes) = (creation.clone(), envelope.to_vec());
        self.serialized(move |_, state| {
            let id = state
                .attempts
                .get(&(creation.operation(), creation.attempt()))
                .ok_or_else(|| refused("unknown creation attempt"))?;
            let entry = state
                .entries
                .get(id)
                .ok_or_else(|| refused("lost creation owner"))?;
            if entry.creation.as_ref() != Some(&creation) {
                return Err(refused("creation binding mismatch"));
            }
            let envelope = entry
                .envelope
                .as_ref()
                .ok_or_else(|| refused("no generated output"))?;
            if encode(envelope) != bytes {
                return Err(refused("generated envelope mismatch"));
            }
            entry
                .owner
                .as_ref()
                .ok_or_else(|| refused("original owner unavailable"))?
                .verify_closed_creation(&entry.context, &entry.parent, &creation, envelope)
        })
        .await
    }

    pub async fn encrypt(
        &self,
        handle: &KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        let (handle, plaintext, aad) = (
            handle.clone(),
            Sensitive::new(plaintext.to_vec()),
            aad.to_vec(),
        );
        self.serialized(move |_, state| {
            state
                .handle_entry(&handle)?
                .owner()?
                .encrypt(plaintext.expose(), &aad)
        })
        .await
    }

    pub async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        let (handle, ciphertext, aad) = (handle.clone(), ciphertext.to_vec(), aad.to_vec());
        self.serialized(move |_, state| {
            state
                .handle_entry(&handle)?
                .owner()?
                .decrypt(&ciphertext, &aad)
        })
        .await
    }
}

#[cfg(test)]
pub(super) mod tests;
