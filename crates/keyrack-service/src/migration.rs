// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synchronous, journaled migration of every version of one logical key.
//! Authorization belongs to the shared ops executor. Storage revalidates the
//! authorized snapshots under its writer fence before any provider dispatch.

use crate::{domain::DomainError, state::ServiceState};
use keyrack_core::error::KeyRackError;
use keyrack_core::key::{KeyMaterial, KeyRecord, KeyVersionRecord};
use keyrack_core::lid::Lid;
use keyrack_core::migration::{MigrationConditions, MigrationPhase, MigrationRequest};
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
    prepare_migration_with_conditions(
        state,
        child_lid,
        requested_parent,
        operation,
        MigrationConditions::default(),
    )
    .await
}

/// Caller assertions are part of immutable intent, including optional presence.
pub async fn prepare_migration_with_conditions(
    state: &Arc<ServiceState>,
    child_lid: Lid,
    requested_parent: Option<Lid>,
    operation: Uuid,
    conditions: MigrationConditions,
) -> Result<MigrationRequest, DomainError> {
    let conditions = conditions
        .canonicalize()
        .map_err(|e| DomainError::InvalidArgument(e.to_string()))?;
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
            || journal.request.conditions != conditions
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
        .and_then(|request| request.with_conditions(conditions))
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

/// Execute or recover an authorized intent under a storage ownership epoch.
/// Reserved retries repeat only providers explicitly declaring retry safety.
/// Staged retries only commit. Committed retries read the original result.
pub async fn rewrap_key(
    state: &Arc<ServiceState>,
    request: MigrationRequest,
) -> Result<KeyRecord, DomainError> {
    // Coalesce retries within this process. Across instances ownership epochs
    // fence stale publishers; a durable dispatch marker protects unknown effects.
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
    if let Err(error) = &result {
        // A stale worker may READ an already committed result but must never
        // stage or commit using the new owner's authority.
        if let Ok(Some(journal)) = state.storage.get_migration(request.operation).await {
            if journal.request.same_intent(&request).unwrap_or(false) {
                if journal.phase == MigrationPhase::Committed {
                    return Ok(journal.request.proposed);
                }
                if journal.phase == MigrationPhase::Reserved
                    && journal
                        .dispatch
                        .is_some_and(|dispatch| !dispatch.retry_safe)
                {
                    // A rejected local precondition does not prove what a
                    // previously dispatched nonrepeatable effect did. Keep the
                    // reconciliation obligation ahead of error classification.
                    return Err(DomainError::ProviderUnavailable(
                        "unknown migration provider outcome requires reconciliation; reservation retained".into(),
                    ));
                }
                if deterministic_rejection(error) {
                    // This is not cancellation: a nonterminal journal and all
                    // its dependency fences remain until explicit recovery.
                    return Err(DomainError::from(KeyRackError::MigrationRejected {
                        reason: format!(
                            "operation {} requires repair or reconciliation; reservation retained: {error}",
                            request.operation
                        ),
                    }));
                }
                return Err(DomainError::ProviderUnavailable(
                    "migration remains pending; retry the same operation ID".into(),
                ));
            }
        }
    }
    result
}

/// Classify explicit semantic failures only. Storage/opaque provider failures
/// and OCC conflicts do not establish a deterministic rejection.
fn deterministic_rejection(error: &DomainError) -> bool {
    match error {
        DomainError::NotFound(_)
        | DomainError::InvalidArgument(_)
        | DomainError::FailedPrecondition(_)
        | DomainError::PermissionDenied(_) => true,
        DomainError::Core(error) => matches!(
            error,
            KeyRackError::MigrationRejected { .. }
                | KeyRackError::MigrationIntentConflict { .. }
                | KeyRackError::KeyNotFound(_)
                | KeyRackError::InvalidStateTransition { .. }
                | KeyRackError::OperationNotPermitted { .. }
                | KeyRackError::KeyDestructionFenced(_)
                | KeyRackError::WrappingParentDestroyed
                | KeyRackError::EncryptionContextMismatch
                | KeyRackError::AuthorizationDenied { .. }
                | KeyRackError::DeletionDependencyRefused { .. }
                | KeyRackError::InvalidIdentity(_)
                | KeyRackError::ImmutableTag { .. }
                | KeyRackError::DepthLimitExceeded { .. }
                | KeyRackError::CycleDetected { .. }
        ),
        DomainError::ProviderUnavailable(_) | DomainError::Internal(_) => false,
    }
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
        if journal.phase == MigrationPhase::Committed {
            return Ok(journal.request.proposed);
        }
        if journal.phase == MigrationPhase::Staged {
            let owned = state
                .storage
                .claim_migration(request.operation, Uuid::new_v4(), journal.epoch)
                .await
                .map_err(DomainError::from)?;
            return state
                .storage
                .commit_migration(
                    request.operation,
                    owned.ownership().map_err(DomainError::from)?,
                )
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
    if journal.phase == MigrationPhase::Committed {
        return Ok(journal.request.proposed);
    }
    let journal = state
        .storage
        .claim_migration(request.operation, Uuid::new_v4(), journal.epoch)
        .await
        .map_err(DomainError::from)?;
    let ownership = journal.ownership().map_err(DomainError::from)?;
    if journal.phase == MigrationPhase::Reserved {
        // Resolve old envelopes before recording dispatch. Once the marker is
        // durable, even a lost response before the first call is unknown for a
        // non-repeatable provider and cannot release the reservation.
        let mut old_envelopes = Vec::with_capacity(prepared.len());
        for version in &request.child.key_versions {
            let KeyMaterial::ParentWrapped(material) = &version.material else {
                unreachable!("validated wrapped version")
            };
            old_envelopes
                .push(read_envelope(state, material.wrapped_material_ref().as_str()).await?);
        }
        let retry_safe = prepared
            .iter()
            .all(|(provider, ..)| provider.rewrap_is_retry_safe());
        state
            .storage
            .begin_migration_dispatch(request.operation, ownership, retry_safe)
            .await
            .map_err(DomainError::from)?;
        let mut envelopes = Vec::with_capacity(prepared.len());
        for (old_envelope, (provider, old_context, new_context, old_parent, new_parent)) in
            old_envelopes.into_iter().zip(prepared)
        {
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
            .stage_migration(request.operation, ownership, &envelopes)
            .await
            .map_err(DomainError::from)?;
    }
    state
        .storage
        .commit_migration(request.operation, ownership)
        .await
        .map_err(DomainError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postreserve_failure_classification_does_not_guess_from_opaque_messages() {
        for error in [
            KeyRackError::Storage("database temporarily unavailable".into()),
            KeyRackError::Provider("unknown backend outcome".into()),
            KeyRackError::ProviderUnavailable("custody unavailable".into()),
        ] {
            assert!(!deterministic_rejection(&DomainError::from(error)));
        }
        assert!(deterministic_rejection(&DomainError::from(
            KeyRackError::MigrationRejected {
                reason: "source snapshot changed".into()
            },
        )));
    }
}
