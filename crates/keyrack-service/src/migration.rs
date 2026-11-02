// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synchronous, journaled migration of every version of one logical key.
//! Authorization belongs to the shared ops executor. Storage revalidates the
//! authorized snapshots under its writer fence before any provider dispatch.

use crate::{domain::DomainError, state::ServiceState};
use keyrack_core::key::{KeyMaterial, KeyRecord, KeyVersionRecord};
use keyrack_core::lid::Lid;
use keyrack_core::migration::{MigrationPhase, MigrationRequest};
use keyrack_core::wrapping::{
    VersionedKeyId, WrappedKeyLifecycle, WrappingCapability, WrappingContext, WrappingKeyPurpose,
    WrappingOperation,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use uuid::Uuid;

/// Resolve intent once. A retry retains the original old parent and pinned
/// target version, even if the child's current parent has subsequently changed.
pub async fn prepare_migration(
    state: &Arc<ServiceState>,
    child_lid: Lid,
    requested_parent: Option<Lid>,
    operation: Uuid,
) -> Result<MigrationRequest, DomainError> {
    if operation.is_nil() {
        return Err(DomainError::InvalidArgument(
            "operation_id must be a non-nil UUID".into(),
        ));
    }
    if let Some(journal) = state
        .storage
        .get_migration(operation)
        .await
        .map_err(DomainError::from)?
    {
        if journal.request.child.lid != child_lid
            || journal.request.requested_parent != requested_parent
        {
            return Err(DomainError::FailedPrecondition(
                "operation_id already names different migration intent".into(),
            ));
        }
        return Ok(journal.request);
    }
    let child = state
        .storage
        .get_key_for_use(&child_lid)
        .await
        .map_err(DomainError::from)?;
    let old_lid = child
        .parent_lid
        .ok_or_else(|| DomainError::FailedPrecondition("rewrap requires a wrapped child".into()))?;
    let old_parent = state
        .storage
        .get_key_for_use(&old_lid)
        .await
        .map_err(DomainError::from)?;
    let new_parent = if requested_parent.unwrap_or(old_lid) == old_lid {
        old_parent.clone()
    } else {
        state
            .storage
            .get_key_for_use(&requested_parent.expect("different parent is present"))
            .await
            .map_err(DomainError::from)?
    };
    MigrationRequest::new(operation, requested_parent, child, old_parent, new_parent)
        .map_err(|error| DomainError::FailedPrecondition(error.to_string()))
}

fn context(
    record: &KeyRecord,
    version: &KeyVersionRecord,
    parent: &KeyRecord,
) -> Result<WrappingContext, DomainError> {
    let KeyMaterial::ParentWrapped(material) = &version.material else {
        return Err(DomainError::FailedPrecondition(
            "every child version must be wrapped".into(),
        ));
    };
    Ok(WrappingContext {
        version: material.wrapping_context_version(),
        child: VersionedKeyId::new(record.lid, version.version_number)
            .map_err(|e| DomainError::FailedPrecondition(e.to_string()))?,
        parent: material.parent(),
        parent_spec: parent.key_spec.clone(),
        child_spec: record.key_spec.clone(),
        key_format: material.key_format().clone(),
        purpose: WrappingKeyPurpose::EncryptDecrypt,
        provider_ref: material.provider_ref().clone(),
        security_domain: material.security_domain().clone(),
        mechanism: material.mechanism().clone(),
        public_material_sha256: None,
    })
}

/// Read exactly the envelope named by a stored descriptor. Superseded references
/// fail closed after commit; no fallback to old contexts or old envelopes.
pub(crate) async fn read_envelope(
    state: &ServiceState,
    reference: &str,
) -> Result<Vec<u8>, DomainError> {
    if let Some(operation) = reference
        .strip_prefix("creation:")
        .and_then(|v| v.parse().ok())
    {
        return state
            .storage
            .read_creation_envelope(operation)
            .await
            .map_err(DomainError::from);
    }
    if let Some((operation, version)) = reference
        .strip_prefix("migration:")
        .and_then(|v| v.split_once(':'))
    {
        if let (Ok(operation), Ok(version)) = (operation.parse(), version.parse()) {
            return state
                .storage
                .read_migration_envelope(operation, version)
                .await
                .map_err(DomainError::from);
        }
    }
    Err(DomainError::FailedPrecondition(
        "wrapped envelope reference is not journaled".into(),
    ))
}

/// Execute or recover an authorized intent. Reserved retries may reproduce
/// envelopes: the provider primitive has no durable usable-child side effect.
/// Staged retries only commit. Committed retries return the original result.
pub async fn rewrap_key(
    state: &Arc<ServiceState>,
    request: MigrationRequest,
) -> Result<KeyRecord, DomainError> {
    // Coalesce retries within this process. Across instances the journal's
    // first staged result wins; the pure provider primitive may be repeated.
    static OPERATIONS: OnceLock<Mutex<HashMap<Uuid, Weak<tokio::sync::Mutex<()>>>>> =
        OnceLock::new();
    let serial = {
        let mut operations = OPERATIONS
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| DomainError::Internal("migration admission lock poisoned".into()))?;
        operations.retain(|_, lock| lock.strong_count() > 0);
        let serial = operations
            .get(&request.operation)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| Arc::new(tokio::sync::Mutex::new(())));
        operations.insert(request.operation, Arc::downgrade(&serial));
        serial
    };
    let _guard = serial.lock().await;
    let mut request = request;
    if let Some(journal) = state
        .storage
        .get_migration(request.operation)
        .await
        .map_err(DomainError::from)?
    {
        // Two independently prepared requests can differ only in their local
        // proposal timestamp. That timestamp is not caller intent; the first
        // reservation owns it. Every authorized snapshot must still match.
        request.proposed.updated_at = journal.request.proposed.updated_at;
    }
    let result = run_migration(state, &request).await;
    if result.is_err() {
        // Another instance may have committed while this retry was reading an
        // old envelope or completing a duplicate pure provider call. Its result
        // wins; never turn a committed operation into a reported failure.
        if let Ok(Some(journal)) = state.storage.get_migration(request.operation).await {
            if journal.request.same_intent(&request).unwrap_or(false) {
                if journal.phase != MigrationPhase::Reserved {
                    return state
                        .storage
                        .commit_migration(request.operation)
                        .await
                        .map_err(DomainError::from);
                }
                return Err(DomainError::ProviderUnavailable(
                    "migration remains reserved; retry the same operation ID".into(),
                ));
            }
        }
    }
    result
}

async fn run_migration(
    state: &Arc<ServiceState>,
    request: &MigrationRequest,
) -> Result<KeyRecord, DomainError> {
    request
        .validate()
        .map_err(|e| DomainError::FailedPrecondition(e.to_string()))?;
    if let Some(journal) = state
        .storage
        .get_migration(request.operation)
        .await
        .map_err(DomainError::from)?
    {
        if !journal
            .request
            .same_intent(request)
            .map_err(DomainError::from)?
        {
            return Err(DomainError::FailedPrecondition(
                "operation_id already names different migration intent".into(),
            ));
        }
        if journal.phase != MigrationPhase::Reserved {
            return state
                .storage
                .commit_migration(request.operation)
                .await
                .map_err(DomainError::from);
        }
    }
    // Capability and deployment checks precede reservation, so unsupported
    // providers do not leave an unfinishable migration fence behind.
    let mut prepared = Vec::new();
    for (old, new) in request
        .child
        .key_versions
        .iter()
        .zip(&request.proposed.key_versions)
    {
        let old_context = context(&request.child, old, &request.old_parent)?;
        let new_context = context(&request.proposed, new, &request.new_parent)?;
        let profile = state
            .wrapping
            .get(&old_context.provider_ref)
            .ok_or_else(|| {
                DomainError::FailedPrecondition("provider has no activated wrapping profile".into())
            })?;
        if profile.security_domain != old_context.security_domain
            || profile.mechanism != old_context.mechanism
        {
            return Err(DomainError::FailedPrecondition(
                "migration security domain or mechanism differs from configured profile".into(),
            ));
        }
        let entry = state
            .providers
            .resolve(&old_context.provider_ref)
            .map_err(DomainError::from)?;
        for context in [&old_context, &new_context] {
            entry
                .provider
                .wrapping_capabilities()
                .require(&WrappingCapability::requested(
                    context,
                    WrappingOperation::Rewrap,
                    WrappedKeyLifecycle::SessionObject,
                ))
                .map_err(|e| {
                    DomainError::FailedPrecondition(format!(
                        "provider cannot rewrap this profile: {e}"
                    ))
                })?;
        }
        let old_parent = request
            .old_parent
            .get_version(old_context.parent.version.get())
            .ok_or_else(|| DomainError::FailedPrecondition("old parent version missing".into()))?
            .resident_handle()
            .map_err(DomainError::from)?
            .clone();
        let new_parent = request
            .new_parent
            .get_version(new_context.parent.version.get())
            .ok_or_else(|| DomainError::FailedPrecondition("new parent version missing".into()))?
            .resident_handle()
            .map_err(DomainError::from)?
            .clone();
        prepared.push((
            entry.provider,
            old_context,
            new_context,
            old_parent,
            new_parent,
        ));
    }
    let journal = state
        .storage
        .reserve_migration(request)
        .await
        .map_err(DomainError::from)?;
    if journal.phase == MigrationPhase::Reserved {
        let mut envelopes = Vec::with_capacity(prepared.len());
        for (version, (provider, old_context, new_context, old_parent, new_parent)) in
            request.child.key_versions.iter().zip(prepared)
        {
            let KeyMaterial::ParentWrapped(material) = &version.material else {
                unreachable!("validated wrapped version")
            };
            let old_envelope =
                read_envelope(state, material.wrapped_material_ref().as_str()).await?;
            envelopes.push(
                provider
                    .rewrap_wrapped_key(
                        &old_context,
                        &old_parent,
                        &old_envelope,
                        &new_context,
                        &new_parent,
                    )
                    .await
                    .map_err(DomainError::from)?,
            );
        }
        state
            .storage
            .stage_migration(request.operation, &envelopes)
            .await
            .map_err(DomainError::from)?;
    }
    state
        .storage
        .commit_migration(request.operation)
        .await
        .map_err(DomainError::from)
}
