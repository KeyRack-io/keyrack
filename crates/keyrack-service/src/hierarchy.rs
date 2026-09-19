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

//! Creating a key whose material is wrapped under another key (ADR-0004 A2).
//!
//! From 0.5.0 a `parent_key_id` on `CreateKey` means the child's material is
//! wrapped under that parent, not that the two are related by lineage. A child
//! is therefore only creatable where a provider implements the ADR-0005
//! wrapping operations for the exact profile the deployment declares, and is
//! refused everywhere else rather than created with unrelated resident
//! material that a parent binding would then misdescribe.
//!
//! The profile is deployment configuration, not provider preference: an
//! operator names the mechanism and the security domain, and the provider is
//! asked whether it serves that exact tuple. A provider that offers something
//! adjacent is refused, because the descriptor written on the version is what a
//! future reader will trust.
//!
//! A software mechanism satisfies this contract without holding custody of
//! anything: the child is unwrapped into this process's memory for the length
//! of a lease. It activates the path for development and for conformance; it is
//! not an HSM, and a deployment that configures it has a hierarchy in shape
//! only. Custody arrives when a custody-bearing provider implements the same
//! operations.

use crate::domain::DomainError;
use crate::state::ServiceState;
use keyrack_core::creation::{creation_correlation, CreationOwner, CreationRequest};
use keyrack_core::creation_driver::{A2CreationDriver, CreationProgress, WrappingCreationProvider};
use keyrack_core::key::{
    Exportability, KeyMaterial, KeyRecord, KeySpec, KeyState, KeyVersionRecord, ProviderRef,
};
use keyrack_core::lid::Lid;
use keyrack_core::material::ParentWrappedMaterial;
use keyrack_core::registry::ProviderEntry;
use keyrack_core::wrapping::{
    VersionedKeyId, WrappedKeyFormat, WrappedKeyLifecycle, WrappingContextVersion,
    WrappingIdentifier, WrappingOperation,
};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

/// The one wrapping profile a deployment activates on one provider.
///
/// Both halves are written into the child's durable descriptor: `mechanism`
/// says what construction wrapped it, and `security_domain` names the backend
/// that can unwrap it. Neither is inferred from the provider name, which would
/// bake an identity nobody stated into records that outlive this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappingProfile {
    pub mechanism: WrappingIdentifier,
    pub security_domain: WrappingIdentifier,
}

/// Which providers may wrap child keys, by name.
///
/// Empty is the default and means child creation is refused everywhere: a
/// hierarchy is a deployment decision, not something a caller turns on by
/// sending a `parent_key_id`.
#[derive(Debug, Clone, Default)]
pub struct WrappingProfiles(HashMap<ProviderRef, WrappingProfile>);

impl WrappingProfiles {
    /// No provider wraps child keys.
    #[must_use]
    pub fn none() -> Self {
        Self(HashMap::new())
    }

    /// Build from validated configuration.
    #[must_use]
    pub fn new(profiles: impl IntoIterator<Item = (ProviderRef, WrappingProfile)>) -> Self {
        Self(profiles.into_iter().collect())
    }

    #[must_use]
    pub fn get(&self, provider: &ProviderRef) -> Option<&WrappingProfile> {
        self.0.get(provider)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ProviderRef, &WrappingProfile)> {
        self.0.iter()
    }

    /// The profile for `provider`, or a refusal naming what is missing.
    fn require(&self, provider: &ProviderRef) -> Result<&WrappingProfile, DomainError> {
        self.get(provider).ok_or_else(|| {
            DomainError::FailedPrecondition(format!(
                "provider '{provider}' is not configured to wrap child keys: \
                 creating a key with a parent requires a wrapping profile for that provider"
            ))
        })
    }
}

/// This process's creation-journal identity.
///
/// A fresh instance per start, so objects and closure records from an earlier
/// run are never mistaken for this one's. The generation is fixed at 1: one
/// incarnation owns one identity for its whole life, and fencing across
/// instances is the journal's business, not a counter kept here.
fn creation_owner() -> CreationOwner {
    static OWNER: OnceLock<CreationOwner> = OnceLock::new();
    *OWNER.get_or_init(|| CreationOwner {
        instance: Uuid::new_v4(),
        generation: 1,
    })
}

/// Name under which the creation journal holds this child's wrapped material.
///
/// An opaque identifier, not a path: it binds the version to the journal row
/// that the envelope was staged in, which is the only place it is stored.
fn material_ref(operation: Uuid) -> Result<WrappingIdentifier, DomainError> {
    WrappingIdentifier::new(format!("creation:{operation}"))
        .map_err(|e| DomainError::Internal(format!("invalid material reference: {e}")))
}

/// A child record with everything but its material.
///
/// The surfaces build the record they would have created anyway; the material
/// is not theirs to invent, because only a completed journaled creation knows
/// what was actually wrapped.
pub struct ChildProposal(KeyRecord);

impl ChildProposal {
    /// Accept a record that states a parent and carries no versions yet.
    pub fn new(record: KeyRecord) -> Result<Self, DomainError> {
        if record.parent_lid.is_none() {
            return Err(DomainError::Internal(
                "child proposal without a parent".into(),
            ));
        }
        if !record.key_versions.is_empty() {
            return Err(DomainError::Internal(
                "child proposal must not carry material".into(),
            ));
        }
        Ok(Self(record))
    }
}

/// Create a child whose material is wrapped under its parent.
///
/// Every refusal here is deliberate and separately provable: an unsupported
/// child, an exportable child, a parent that cannot be wrapped under, a parent
/// in another security domain, a provider with no configured profile, and a
/// provider that does not implement the profile it is configured for.
pub async fn create_wrapped_child(
    state: &Arc<ServiceState>,
    provider_name: &ProviderRef,
    entry: &ProviderEntry,
    proposal: ChildProposal,
) -> Result<KeyRecord, DomainError> {
    let mut record = proposal.0;
    let parent_lid = record
        .parent_lid
        .ok_or_else(|| DomainError::Internal("child proposal without a parent".into()))?;

    refuse_unwrappable_child(&record)?;
    let profile = state.wrapping.require(provider_name)?;

    let parent = state
        .storage
        .get_key(&parent_lid)
        .await
        .map_err(DomainError::from)?;
    refuse_unwrappable_parent(&parent)?;
    let parent_provider = parent_provider_ref(&parent)?;
    refuse_cross_domain(provider_name, parent_provider)?;

    let parent_version = parent
        .primary_version()
        .ok_or_else(|| DomainError::FailedPrecondition("parent has no primary version".into()))?;
    let parent_handle = parent_version
        .resident_handle()
        .map_err(DomainError::from)?
        .clone();

    let operation = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let material = ParentWrappedMaterial::new(
        provider_name.clone(),
        profile.security_domain.clone(),
        VersionedKeyId::new(parent.lid, parent.current_key_version)
            .map_err(|e| DomainError::Internal(format!("invalid parent version: {e}")))?,
        WrappingContextVersion::V1,
        WrappedKeyFormat::RawSecret,
        profile.mechanism.clone(),
        material_ref(operation)?,
    )
    .map_err(|e| DomainError::InvalidArgument(format!("invalid wrapped material: {e}")))?;

    record.occ_version = 1;
    record.current_key_version = 1;
    record.provider_ref = Some(provider_name.clone());
    record.provider_class = entry.class;
    record.key_versions = vec![KeyVersionRecord {
        version_number: 1,
        material: KeyMaterial::ParentWrapped(material),
        created_at: record.created_at,
        is_primary: true,
    }];

    let mut request = CreationRequest {
        operation,
        attempt,
        owner: creation_owner(),
        correlation: creation_correlation(operation, attempt),
        record,
        expected_key_occ: None,
        expected_parent_occ: parent.occ_version,
        parent_spec: parent.key_spec.clone(),
        context_bytes: Vec::new(),
    };
    request.context_bytes = request
        .context()
        .and_then(|context| {
            context
                .canonical_bytes()
                .map_err(|e| keyrack_core::error::KeyRackError::Other(e.to_string()))
        })
        .map_err(DomainError::from)?;

    // The provider is asked for the whole profile before anything is created:
    // a child that cannot later be opened and closed must not exist.
    let driver = WrappingCreationProvider::new(
        Arc::clone(&entry.provider),
        parent_handle,
        WrappedKeyLifecycle::SessionObject,
    )
    .map_err(|e| {
        DomainError::FailedPrecondition(format!(
            "provider '{provider_name}' cannot wrap child keys: {e}"
        ))
    })?;

    let progress = A2CreationDriver::new(Arc::clone(&state.storage), Arc::new(driver))
        .run(request)
        .await
        .map_err(DomainError::from)?;

    match progress {
        CreationProgress::Committed(record) => Ok(*record),
        // Not a failure and not a success: the attempt owns durable state that
        // only reconciliation may resolve. Retrying the same call would be a
        // second attempt, which is why this does not retry itself.
        CreationProgress::Pending(reason) => Err(DomainError::ProviderUnavailable(format!(
            "child creation is unresolved ({reason:?}); it requires reconciliation \
             and must not be assumed to have failed"
        ))),
    }
}

/// A child must be exactly what a wrapped version can durably represent.
fn refuse_unwrappable_child(record: &KeyRecord) -> Result<(), DomainError> {
    if !matches!(record.key_spec, KeySpec::Aes128 | KeySpec::Aes256) {
        return Err(DomainError::InvalidArgument(format!(
            "a key with a parent is wrapped under that parent, which is implemented \
             for symmetric encryption keys only; {:?} cannot be a child",
            record.key_spec
        )));
    }
    // Usage is not checked separately: it is derived from the spec, so a second
    // gate over the same fact would be one no test could make fail on its own,
    // and the creation journal revalidates both inside its transaction.
    //
    // Export means handing out material this service never holds: the child is
    // only ever a wrapped envelope plus a lease inside the provider.
    if record.exportability != Exportability::NonExportable {
        return Err(DomainError::InvalidArgument(
            "a wrapped child cannot be exportable".into(),
        ));
    }
    Ok(())
}

/// A parent must be usable now, and must mean what 0.5.0 says a parent means.
fn refuse_unwrappable_parent(parent: &KeyRecord) -> Result<(), DomainError> {
    if parent.has_legacy_parent_semantics() {
        return Err(DomainError::FailedPrecondition(format!(
            "parent {}: {}",
            parent.lid,
            keyrack_core::key::LEGACY_PARENT_SEMANTICS
        )));
    }
    if parent.state != KeyState::Enabled || parent.has_compromise_history() {
        return Err(DomainError::FailedPrecondition(format!(
            "parent {} is not an eligible wrapping key in state {:?}",
            parent.lid, parent.state
        )));
    }
    if parent.scheduled_deletion_at.is_some() {
        return Err(DomainError::FailedPrecondition(format!(
            "parent {} is scheduled for deletion",
            parent.lid
        )));
    }
    // A parent whose own material can leave the provider protects nothing it
    // wraps: whoever holds the parent holds every child under it.
    if parent.exportability != Exportability::NonExportable || parent.first_exported_at.is_some() {
        return Err(DomainError::FailedPrecondition(format!(
            "parent {} is exportable and cannot wrap child keys",
            parent.lid
        )));
    }
    // A wrapped child is reachable only through its parent, so a parent that is
    // itself wrapped would need recursive materialization, which is not built.
    if !parent
        .primary_version()
        .is_some_and(|v| matches!(v.material, KeyMaterial::ProviderResident { .. }))
    {
        return Err(DomainError::FailedPrecondition(format!(
            "parent {} is not an independently resident key; a wrapped key \
             cannot itself wrap children",
            parent.lid
        )));
    }
    Ok(())
}

/// The parent's explicit binding. An inherited default is not good enough: the
/// descriptor records one exact backend, and a default can be reconfigured.
fn parent_provider_ref(parent: &KeyRecord) -> Result<&ProviderRef, DomainError> {
    parent
        .primary_version()
        .and_then(KeyVersionRecord::provider_ref)
        .or(parent.provider_ref.as_ref())
        .ok_or_else(|| {
            DomainError::FailedPrecondition(format!(
                "parent {} has no explicit provider binding and cannot wrap a child",
                parent.lid
            ))
        })
}

/// ADR-0004 A2: parent and child live in one security domain.
///
/// A refusal, not a deferred feature. Wrapping across two backends would mean
/// one of them holding the other's key material in the clear at some point,
/// which is the property the hierarchy exists to avoid.
fn refuse_cross_domain(child: &ProviderRef, parent: &ProviderRef) -> Result<(), DomainError> {
    if child != parent {
        return Err(DomainError::FailedPrecondition(format!(
            "parent is on provider '{parent}' and the child would be created on \
             '{child}': a wrapped child must be in the same security domain as its parent"
        )));
    }
    Ok(())
}

/// Check at startup that a provider implements the profile it was activated
/// with, and say plainly when that profile is not custody.
///
/// An operator who configures wrapping on a provider that cannot wrap has made
/// a mistake that only shows up on the first `CreateKey` with a parent. This
/// turns it into a refusal to start. It checks what is checkable without a
/// request — the mechanism and the ability to evidence closure — while the
/// exact tuple for one child stays with the per-request check, because the
/// specs of that child are not known here.
///
/// # Errors
/// Returns a startup error when the provider declares no such mechanism for
/// generate, open and close, or cannot evidence its own closures.
pub fn verify_wrapping_profile(
    name: &ProviderRef,
    profile: &WrappingProfile,
    provider: &dyn keyrack_core::provider::CryptoProvider,
) -> Result<(), String> {
    let declared = provider.wrapping_capabilities();
    for operation in [
        WrappingOperation::Generate,
        WrappingOperation::Open,
        WrappingOperation::Close,
    ] {
        if !declared
            .tuples()
            .iter()
            .any(|tuple| tuple.mechanism == profile.mechanism && tuple.operation == operation)
        {
            return Err(format!(
                "config error: `wrapping` activates mechanism '{}' on provider '{name}', which \
                 does not declare it for {operation:?}. A child created under this profile could \
                 not be {}.",
                profile.mechanism.as_str(),
                match operation {
                    WrappingOperation::Generate => "created",
                    WrappingOperation::Open => "used",
                    _ => "released",
                }
            ));
        }
    }
    if provider.wrapping_closure_verifier().is_none() {
        return Err(format!(
            "config error: provider '{name}' cannot evidence wrapped-key closure, so a \
             journaled creation on it could never be resolved"
        ));
    }
    if profile.mechanism.as_str().contains("software") {
        tracing::warn!(
            provider = %name,
            mechanism = profile.mechanism.as_str(),
            security_domain = profile.security_domain.as_str(),
            "wrapping is activated with a software mechanism: child keys are unwrapped into \
             this process's memory for the length of a lease. This makes the hierarchy usable \
             for development and conformance; it is not custody, and the hierarchy it forms is \
             shape only."
        );
    }
    Ok(())
}

/// Warn once at startup about keys whose parent binding predates 0.5.0.
///
/// An operator should learn from the log that migration is needed, rather than
/// from the first refused use. This reads metadata only and never blocks start:
/// a scan that cannot complete is not a reason to refuse traffic for keys that
/// are unaffected.
pub async fn warn_about_legacy_parents(storage: &Arc<dyn keyrack_core::storage::StorageBackend>) {
    const SCAN_LIMIT: u32 = 1000;
    let filter = keyrack_core::storage::KeyFilter {
        user_tags: vec![],
        state: None,
        owner_principal_id: None,
        limit: Some(SCAN_LIMIT),
        cursor: None,
    };
    match storage.list_keys(&filter).await {
        Ok(page) => {
            let legacy: Vec<Lid> = page
                .items
                .iter()
                .filter(|record| record.has_legacy_parent_semantics())
                .map(|record| record.lid)
                .collect();
            if !legacy.is_empty() {
                tracing::warn!(
                    count = legacy.len(),
                    keys = ?legacy,
                    scanned = page.items.len(),
                    truncated = page.next_cursor.is_some(),
                    "{}",
                    keyrack_core::key::LEGACY_PARENT_SEMANTICS
                );
            }
        }
        Err(e) => tracing::warn!(
            error = %e,
            "could not scan for keys with pre-0.5.0 parent semantics"
        ),
    }
}
