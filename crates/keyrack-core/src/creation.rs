// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A2 creation reservations and publication transitions.
//!
//! This is storage machinery, not a provider qualification or an A3 contract.
//! The first slice admits AES leaves under an explicitly bound resident AES
//! parent. Context encoding is unchanged. Transactions establish database
//! consistency, not authorization freshness against a malicious coordinator.
//! No provider call belongs inside a database transaction.

use crate::error::{KeyRackError, Result};
use crate::key::{Exportability, KeyMaterial, KeyRecord, KeySpec, KeyState, KeyUsage};
use crate::material::ParentWrappedMaterial;
use crate::wrapping::{VersionedKeyId, WrappingContext, WrappingIdentifier, WrappingKeyPurpose};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Initial bound for provider envelope bytes, not a general blob service.
pub const MAX_CREATION_ENVELOPE_BYTES: usize = 65_536;
pub const MAX_CREATION_PAGE_SIZE: u32 = 100;

/// Stable recovery identity. A provider adapter may encode this for its native
/// correlation mechanism, but must prove collision-free recovery in its domain.
pub fn creation_correlation(operation: Uuid, attempt: Uuid) -> String {
    format!("kr-a2-{operation}-{attempt}")
}

pub fn invalid(message: &'static str) -> KeyRackError {
    KeyRackError::Storage(format!("A2 creation: {message}"))
}

/// A process incarnation and its fencing generation, distinct from authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreationOwner {
    pub instance: Uuid,
    pub generation: u64,
}

/// Immutable intent. `record` is the proposed committed snapshot, never exposed
/// by normal key reads until publication. Retries must supply the same intent.
/// An existing reservation is not fresh authorization or permission to generate
/// again: lost provider responses require correlation-based reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreationRequest {
    pub operation: Uuid,
    pub attempt: Uuid,
    pub owner: CreationOwner,
    pub correlation: String,
    pub record: KeyRecord,
    pub expected_key_occ: Option<u64>,
    pub expected_parent_occ: u64,
    pub parent_spec: KeySpec,
    pub context_bytes: Vec<u8>,
}

impl CreationRequest {
    pub fn material(&self) -> Result<&ParentWrappedMaterial> {
        let version = self
            .record
            .primary_version()
            .ok_or(invalid("missing proposed version"))?;
        match &version.material {
            KeyMaterial::ParentWrapped(material) => Ok(material),
            KeyMaterial::ProviderResident { .. } => Err(invalid("proposed version is not wrapped")),
        }
    }

    pub fn child(&self) -> Result<VersionedKeyId> {
        VersionedKeyId::new(self.record.lid, self.record.current_key_version)
            .map_err(|_| invalid("zero child version"))
    }

    pub fn context(&self) -> Result<WrappingContext> {
        let material = self.material()?;
        Ok(WrappingContext {
            version: material.wrapping_context_version(),
            child: self.child()?,
            parent: material.parent(),
            parent_spec: self.parent_spec.clone(),
            child_spec: self.record.key_spec.clone(),
            key_format: material.key_format().clone(),
            purpose: WrappingKeyPurpose::EncryptDecrypt,
            provider_ref: material.provider_ref().clone(),
            security_domain: material.security_domain().clone(),
            mechanism: material.mechanism().clone(),
            public_material_sha256: None,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.operation.is_nil()
            || self.attempt.is_nil()
            || self.owner.instance.is_nil()
            || self.owner.generation == 0
            || self.owner.generation > i64::MAX as u64
        {
            return Err(invalid("invalid operation or owner identity"));
        }
        WrappingIdentifier::new(self.correlation.clone())
            .map_err(|_| invalid("invalid correlation"))?;
        if self.correlation != creation_correlation(self.operation, self.attempt) {
            return Err(invalid("correlation must bind operation and attempt"));
        }
        let record = &self.record;
        let material = self.material()?;
        if record.state != KeyState::Enabled
            || record.has_compromise_history()
            || record.exportability != Exportability::NonExportable
            || record.first_exported_at.is_some()
            || record.scheduled_deletion_at.is_some()
            || record.key_usage != KeyUsage::EncryptDecrypt
            || !matches!(record.key_spec, KeySpec::Aes128 | KeySpec::Aes256)
            || record.lid == material.parent().lid
            || record.occ_version == 0
            || record.occ_version > i64::MAX as u64
            || self.expected_parent_occ > i64::MAX as u64
            || self.expected_key_occ.is_some_and(|v| v >= i64::MAX as u64)
        {
            return Err(invalid("unsupported creation record"));
        }
        let mut versions = std::collections::HashSet::new();
        for version in &record.key_versions {
            if version.version_number == 0
                || !versions.insert(version.version_number)
                || version.is_primary != (version.version_number == record.current_key_version)
            {
                return Err(invalid("invalid version history"));
            }
        }
        let expected = self
            .context()?
            .canonical_bytes()
            .map_err(|_| invalid("invalid context"))?;
        if self.context_bytes != expected {
            return Err(invalid("context does not match proposed material"));
        }
        Ok(())
    }

    /// Stable equality fingerprint for storage retries; not a MAC/signature.
    pub fn fingerprint(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|_| invalid("intent serialization failed"))?;
        let bytes =
            serde_json::to_vec(&value).map_err(|_| invalid("intent serialization failed"))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    /// Rechecked inside reservation and publication transactions. This is the
    /// narrow resident-parent storage profile, not recursive materialization.
    pub fn validate_records(&self, current: Option<&KeyRecord>, parent: &KeyRecord) -> Result<()> {
        self.validate()?;
        let material = self.material()?;
        if parent.lid != material.parent().lid
            || parent.occ_version != self.expected_parent_occ
            || parent.state != KeyState::Enabled
            || parent.has_compromise_history()
            || parent.scheduled_deletion_at.is_some()
            || parent.key_spec != self.parent_spec
        {
            return Err(invalid("parent snapshot is no longer eligible"));
        }
        let parent_version = parent
            .get_version(material.parent().version.get())
            .ok_or(invalid("parent version missing"))?;
        let KeyMaterial::ProviderResident {
            key_handle,
            provider_ref: Some(provider),
        } = &parent_version.material
        else {
            return Err(invalid("requires explicitly bound resident parent"));
        };
        if provider != material.provider_ref() || key_handle.key_spec != self.parent_spec {
            return Err(invalid("parent binding mismatch"));
        }
        match (self.expected_key_occ, current) {
            (None, None)
                if self.record.occ_version == 1
                    && self.record.current_key_version == 1
                    && self.record.key_versions.len() == 1 =>
            {
                Ok(())
            }
            (Some(expected), Some(current)) if current.occ_version == expected => {
                let next_version = current
                    .key_versions
                    .iter()
                    .map(|v| v.version_number)
                    .max()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(invalid("version overflow"))?;
                if self.record.current_key_version != next_version
                    || current.state != KeyState::Enabled
                    || current.has_compromise_history()
                {
                    return Err(invalid("invalid new version"));
                }
                let mut proposed = current.clone();
                proposed.occ_version = expected.checked_add(1).ok_or(invalid("OCC overflow"))?;
                proposed.current_key_version = next_version;
                proposed.updated_at = self.record.updated_at;
                for version in &mut proposed.key_versions {
                    version.is_primary = false;
                }
                proposed.key_versions.push(
                    self.record
                        .primary_version()
                        .ok_or(invalid("missing version"))?
                        .clone(),
                );
                if !same_json(&proposed, &self.record)? {
                    return Err(invalid("creation changes unrelated key fields or history"));
                }
                Ok(())
            }
            _ => Err(invalid("child reservation or OCC conflict")),
        }
    }
}

pub fn same_json<T: Serialize>(left: &T, right: &T) -> Result<bool> {
    Ok(
        serde_json::to_value(left).map_err(|_| invalid("serialization failed"))?
            == serde_json::to_value(right).map_err(|_| invalid("serialization failed"))?,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreationPhase {
    Reserved,
    Staged,
    Resolved,
    Committed,
}

impl CreationPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Staged => "staged",
            Self::Resolved => "resolved",
            Self::Committed => "committed",
        }
    }
}

/// Provider creation-object closure only. Not operation-lease closure, authority
/// fencing, or a boolean assertion that a worker is done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields, rename_all = "snake_case")]
pub enum A2ClosureFact {
    SessionClosed { session: String },
    TemporaryObjectDestroyed { object: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2ClosureClaim {
    pub intent_fingerprint: [u8; 32],
    /// Exact staged-byte binding, using the journal's BLAKE3 consistency digest.
    /// This is not the custody contract's SHA-256 or an authenticity proof.
    pub envelope_digest: [u8; 32],
    pub fact: A2ClosureFact,
}

impl A2ClosureClaim {
    fn validate_for(&self, request: &CreationRequest) -> Result<()> {
        if self.intent_fingerprint != request.fingerprint()? {
            return Err(invalid("closure target mismatch"));
        }
        let target = match &self.fact {
            A2ClosureFact::SessionClosed { session } => session,
            A2ClosureFact::TemporaryObjectDestroyed { object } => object,
        };
        WrappingIdentifier::new(target.clone()).map_err(|_| invalid("invalid closure target"))?;
        Ok(())
    }
}

/// Trusted provider integration must verify provenance, exact object/session
/// ownership, and completion. There is deliberately no production accept-all
/// implementation. Storage cannot turn a caller's success flag into evidence.
pub trait A2ClosureVerifier: Send + Sync {
    fn verify(&self, request: &CreationRequest, claim: &A2ClosureClaim) -> Result<()>;
}

/// In-process result of verification. Cannot be deserialized from a coordinator
/// request. Installing a verifier is part of the trusted provider integration;
/// this type does not defend against arbitrary code execution in that integration.
#[derive(Debug)]
pub struct VerifiedA2Closure {
    claim: A2ClosureClaim,
}

impl VerifiedA2Closure {
    pub fn verify<V: A2ClosureVerifier + ?Sized>(
        request: &CreationRequest,
        envelope: &[u8],
        claim: A2ClosureClaim,
        verifier: &V,
    ) -> Result<Self> {
        claim.validate_for(request)?;
        if envelope.is_empty()
            || envelope.len() > MAX_CREATION_ENVELOPE_BYTES
            || claim.envelope_digest != *blake3::hash(envelope).as_bytes()
        {
            return Err(invalid("closure envelope mismatch"));
        }
        verifier.verify(request, &claim)?;
        Ok(Self { claim })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreationJournal {
    pub request: CreationRequest,
    /// Durable, one-shot provider-dispatch decision, independent of publication
    /// revision. Required on decode: an old Reserved row cannot safely be assumed
    /// to have had no provider effects. No automatic migration guesses that fact.
    pub dispatch_started: bool,
    pub revision: u64,
    pub phase: CreationPhase,
    pub envelope_digest: Option<[u8; 32]>,
    pub closure: Option<A2ClosureClaim>,
    pub committed_record: Option<KeyRecord>,
}

impl CreationJournal {
    pub fn reserved(request: CreationRequest) -> Result<Self> {
        request.validate()?;
        Ok(Self {
            request,
            dispatch_started: false,
            revision: 1,
            phase: CreationPhase::Reserved,
            envelope_digest: None,
            closure: None,
            committed_record: None,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        let expected_revision = match self.phase {
            CreationPhase::Reserved => 1,
            CreationPhase::Staged => 2,
            CreationPhase::Resolved => 3,
            CreationPhase::Committed => 4,
        };
        if self.revision != expected_revision
            || (self.phase != CreationPhase::Reserved && !self.dispatch_started)
            || self.envelope_digest.is_some() != (self.phase != CreationPhase::Reserved)
            || self.closure.is_some()
                != matches!(
                    self.phase,
                    CreationPhase::Resolved | CreationPhase::Committed
                )
            || self.committed_record.is_some() != (self.phase == CreationPhase::Committed)
        {
            return Err(invalid("inconsistent journal"));
        }
        if let Some(claim) = &self.closure {
            claim.validate_for(&self.request)?;
            if Some(claim.envelope_digest) != self.envelope_digest {
                return Err(invalid("closure does not bind staged envelope"));
            }
        }
        if let Some(record) = &self.committed_record {
            if !same_json(record, &self.request.record)? {
                return Err(invalid("persisted result mismatch"));
            }
        }
        Ok(())
    }

    fn fence(&self, owner: CreationOwner, expected_revision: u64) -> Result<()> {
        self.validate()?;
        if self.request.owner != owner || self.revision != expected_revision {
            return Err(invalid("stale creation owner or revision"));
        }
        Ok(())
    }

    /// Storage must execute this under its writer transaction and return `true`
    /// only after committing the decision. An identical retry is NOT another
    /// dispatch ticket, including after a lost commit response.
    pub fn claim_dispatch(&mut self, owner: CreationOwner) -> Result<bool> {
        self.validate()?;
        if owner != self.request.owner {
            return Err(invalid("stale creation owner"));
        }
        if self.dispatch_started {
            return Ok(false);
        }
        if self.phase != CreationPhase::Reserved {
            return Err(invalid("creation is not reserved"));
        }
        self.dispatch_started = true;
        Ok(true)
    }

    pub fn stage(
        &mut self,
        owner: CreationOwner,
        expected_revision: u64,
        envelope: &[u8],
    ) -> Result<()> {
        self.validate()?;
        if !self.dispatch_started {
            return Err(invalid("provider dispatch was not claimed"));
        }
        if envelope.is_empty() || envelope.len() > MAX_CREATION_ENVELOPE_BYTES {
            return Err(invalid("invalid envelope length"));
        }
        let digest = *blake3::hash(envelope).as_bytes();
        if self.request.owner == owner
            && self.envelope_digest == Some(digest)
            && (expected_revision == 1 || expected_revision == self.revision)
        {
            return Ok(());
        }
        self.fence(owner, expected_revision)?;
        if self.phase != CreationPhase::Reserved {
            return Err(invalid("envelope is immutable"));
        }
        self.envelope_digest = Some(digest);
        self.phase = CreationPhase::Staged;
        self.revision = 2;
        Ok(())
    }

    pub fn resolve(
        &mut self,
        owner: CreationOwner,
        expected_revision: u64,
        closure: &VerifiedA2Closure,
    ) -> Result<()> {
        self.validate()?;
        if closure.claim.intent_fingerprint != self.request.fingerprint()?
            || Some(closure.claim.envelope_digest) != self.envelope_digest
        {
            return Err(invalid("closure target mismatch"));
        }
        if self.request.owner == owner
            && self.closure.as_ref() == Some(&closure.claim)
            && (expected_revision == 2 || expected_revision == self.revision)
        {
            return Ok(());
        }
        self.fence(owner, expected_revision)?;
        if self.phase != CreationPhase::Staged {
            return Err(invalid("envelope must be staged before closure"));
        }
        self.closure = Some(closure.claim.clone());
        self.phase = CreationPhase::Resolved;
        self.revision = 3;
        Ok(())
    }

    pub fn publication(
        &mut self,
        owner: CreationOwner,
        expected_revision: u64,
        current: Option<&KeyRecord>,
        parent: &KeyRecord,
    ) -> Result<KeyRecord> {
        self.fence(owner, expected_revision)?;
        if self.phase != CreationPhase::Resolved {
            return Err(invalid("creation is not resolved"));
        }
        self.request.validate_records(current, parent)?;
        let record = self.request.record.clone();
        self.committed_record = Some(record.clone());
        self.phase = CreationPhase::Committed;
        self.revision = 4;
        Ok(record)
    }

    /// Lost-response retry returns the original result, never overwrites newer
    /// key metadata. Backend must use this before rechecking parent availability.
    pub fn committed_retry(
        &self,
        owner: CreationOwner,
        expected_revision: u64,
    ) -> Result<Option<KeyRecord>> {
        self.validate()?;
        if self.request.owner != owner {
            return Err(invalid("stale creation owner"));
        }
        if self.phase == CreationPhase::Committed {
            if !matches!(expected_revision, 3 | 4) {
                return Err(invalid("stale publication revision"));
            }
            return Ok(self.committed_record.clone());
        }
        Ok(None)
    }
}

/// A fresh claim is an execution decision, not authority or provider evidence.
/// Losing its response strands the attempt for reconciliation; no retry can
/// manufacture a second `Started`. Backends without this transaction deny.
#[derive(Debug)]
pub enum CreationDispatch {
    Started(CreationJournal),
    Existing(CreationJournal),
}

/// Internal recovery snapshot. Its owner check is storage fencing, not client
/// authorization. This read must not be exposed as ordinary key/envelope access.
#[derive(Debug, Clone)]
pub struct CreationSnapshot {
    pub journal: CreationJournal,
    pub envelope: Option<Vec<u8>>,
}

impl CreationSnapshot {
    pub fn new(
        journal: CreationJournal,
        envelope: Option<Vec<u8>>,
        owner: CreationOwner,
    ) -> Result<Self> {
        journal.validate()?;
        if journal.request.owner != owner {
            return Err(invalid("stale creation owner"));
        }
        match (&envelope, journal.phase) {
            (None, CreationPhase::Reserved) => {}
            (Some(bytes), phase) if phase != CreationPhase::Reserved => {
                validate_envelope(&journal, bytes)?;
            }
            _ => return Err(invalid("snapshot envelope phase mismatch")),
        }
        Ok(Self { journal, envelope })
    }
}

/// Storage reads must validate both bounded bytes and their journal binding.
pub fn validate_envelope(journal: &CreationJournal, bytes: &[u8]) -> Result<()> {
    journal.validate()?;
    if bytes.is_empty()
        || bytes.len() > MAX_CREATION_ENVELOPE_BYTES
        || journal.envelope_digest != Some(*blake3::hash(bytes).as_bytes())
    {
        return Err(invalid("envelope/journal mismatch"));
    }
    Ok(())
}

/// Conservative guard for a key referenced by a pending or committed edge.
/// Allow state changes to preempt publication, but not destruction, removal or
/// replacement of version material. Authorized subtree erasure is a later API.
pub fn guard_referenced_parent(previous: &KeyRecord, next: &KeyRecord) -> Result<()> {
    if next.state == KeyState::Destroyed
        || next.key_spec != previous.key_spec
        || next.provider_ref != previous.provider_ref
    {
        return Err(invalid("parent is referenced by a creation or envelope"));
    }
    for old in &previous.key_versions {
        let new = next
            .get_version(old.version_number)
            .ok_or(invalid("referenced parent version removed"))?;
        if old.material != new.material {
            return Err(invalid("referenced parent material changed"));
        }
    }
    Ok(())
}

/// Nonterminal operations are deliberately retained: no timeout or owner expiry
/// releases a reservation or implies cleanup. Recovery can inspect these pages;
/// takeover/abort require a later qualified cleanup protocol, not blind retries.
#[derive(Debug, Clone)]
pub struct CreationPage {
    pub items: Vec<CreationJournal>,
    pub next_after: Option<Uuid>,
}

pub fn validate_page_size(limit: u32) -> Result<()> {
    if limit == 0 || limit > MAX_CREATION_PAGE_SIZE {
        return Err(invalid("invalid recovery page size"));
    }
    Ok(())
}
