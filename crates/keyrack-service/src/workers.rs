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

//! Background workers for periodic maintenance tasks.
//!
//! Scanners keep lifecycle state in storage. Destruction uses one durable
//! claim before provider effects; interrupted claims retain their fence and are
//! resumed from the durable snapshot using idempotent provider deletion.

use crate::state::ServiceState;
use keyrack_core::audit::{
    AuditAction, AuditEvent, AuditPrincipal, AuditResource, AuditResult, EventType,
};
use keyrack_core::key::KeyState;
use keyrack_core::provider::DestroyKeyOutcome;
use keyrack_core::rotation::RotationJobState;
use keyrack_core::storage::KeyFilter;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const SCAN_INTERVAL: Duration = Duration::from_secs(60);

/// Destroys the provider-side material of keys in `PendingDeletion` past their
/// `scheduled_deletion_at`, then transitions them to `Destroyed`.
pub async fn deletion_worker(state: Arc<ServiceState>, cancel: CancellationToken) {
    tracing::info!("deletion worker started (interval: {SCAN_INTERVAL:?})");
    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                tracing::info!("deletion worker shutting down");
                return;
            }
            () = tokio::time::sleep(SCAN_INTERVAL) => {}
        }

        if let Err(e) = run_deletion_scan(&state).await {
            tracing::error!(error = %e, "deletion worker scan failed");
        }
    }
}

/// One pass of the deletion reaper.
///
/// Public so tests can drive a single deterministic scan instead of waiting on
/// [`deletion_worker`]'s timer.
pub async fn run_deletion_scan(state: &ServiceState) -> Result<(), Box<dyn std::error::Error>> {
    run_deletion_scan_at(state, chrono::Utc::now()).await
}

/// Deterministic scan time; storage still authoritatively checks each due row
/// under its writer fence. Tests can advance time without modifying approvals.
pub async fn run_deletion_scan_at(
    state: &ServiceState,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Box<dyn std::error::Error>> {
    let filter = KeyFilter {
        state: Some(KeyState::PendingDeletion),
        ..KeyFilter::default()
    };
    let page = state.storage.list_keys(&filter).await?;

    let mut destroyed = 0u64;
    let mut failed = 0u64;
    for record in &page.items {
        let past_due = record.scheduled_deletion_at.is_some_and(|t| now >= t);
        if !past_due {
            continue;
        }

        let claim = match state
            .storage
            .claim_destruction(&record.lid, record.occ_version, now)
            .await
        {
            Ok(Some(claim)) => claim,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(lid = %record.lid, %error, "destruction claim refused; no provider effect");
                let reason = match &error {
                    keyrack_core::error::KeyRackError::DeletionDependencyRefused {
                        reason, ..
                    } => match reason.as_str() {
                        "in_flight_journal" => "in_flight_journal",
                        "dependent_data_loss_not_approved" => "dependent_data_loss_not_approved",
                        "dependent_outside_approved_snapshot" => {
                            "dependent_outside_approved_snapshot"
                        }
                        _ => "storage_refusal",
                    },
                    _ => "storage_refusal",
                };
                metrics::counter!("keyrack_deletion_claim_refusals_total", "reason" => reason)
                    .increment(1);
                let mut event = AuditEvent::new(
                    EventType::KeyDeleted,
                    AuditAction::KeyDestructionRefused,
                    system_principal(),
                    AuditResource {
                        id: record.lid.to_string(),
                        resource_type: "Key".into(),
                    },
                    AuditResult::Error,
                );
                event.add_metadata("reason", reason);
                if let keyrack_core::error::KeyRackError::DeletionDependencyRefused {
                    counts, ..
                } = &error
                {
                    event.add_metadata("dependency_counts", counts.as_str());
                }
                let _ = state.audit.emit(&event).await;
                failed += 1;
                continue;
            }
        };
        if claim.is_recovered() {
            emit_destruction_progress(
                state,
                &claim,
                AuditAction::KeyDestructionRetried,
                "durable_claim_resumed",
            )
            .await;
            metrics::counter!("keyrack_deletion_retries_total").increment(1);
        }
        // The transactionally fenced snapshot, NEVER the scan row.
        if !destroy_backend_material(state, &claim).await {
            emit_destruction_progress(
                state,
                &claim,
                AuditAction::KeyDestructionDeferred,
                "provider_outcome_unconfirmed",
            )
            .await;
            failed += 1;
            continue;
        }

        let operation_id = claim.operation();
        if let Err(e) = state.storage.complete_destruction(claim).await {
            tracing::warn!(lid = %record.lid, %operation_id, error = %e, "destruction completion ambiguous; fence retained");
            let mut event = AuditEvent::new(
                EventType::KeyDeleted,
                AuditAction::KeyDestructionDeferred,
                system_principal(),
                AuditResource {
                    id: record.lid.to_string(),
                    resource_type: "Key".into(),
                },
                AuditResult::Error,
            );
            event.add_metadata("operation_id", operation_id.to_string());
            event.add_metadata("reason", "completion_unconfirmed");
            let _ = state.audit.emit(&event).await;
            failed += 1;
            continue;
        }

        let event = AuditEvent::new(
            EventType::KeyDeleted,
            AuditAction::KeyDestroyed,
            system_principal(),
            AuditResource {
                id: record.lid.to_string(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );
        let _ = state.audit.emit(&event).await;
        destroyed += 1;
    }

    if destroyed > 0 {
        tracing::info!(destroyed, "deletion worker destroyed expired keys");
    }
    if failed > 0 {
        tracing::error!(
            failed,
            "deletion worker could not destroy backend material; keys left in \
             pending_deletion; retained claims will be retried"
        );
    }
    Ok(())
}

async fn emit_destruction_progress(
    state: &ServiceState,
    claim: &keyrack_core::destruction::DestructionClaim,
    action: AuditAction,
    reason: &str,
) {
    // A resumed attempt is not itself a failure or proof of completion.
    let result = if action == AuditAction::KeyDestructionRetried {
        AuditResult::Success
    } else {
        AuditResult::Error
    };
    let mut event = AuditEvent::new(
        EventType::KeyDeleted,
        action,
        system_principal(),
        AuditResource {
            id: claim.record().lid.to_string(),
            resource_type: "Key".into(),
        },
        result,
    );
    event.add_metadata("operation_id", claim.operation().to_string());
    event.add_metadata("reason", reason);
    let _ = state.audit.emit(&event).await;
}

/// Destroy the provider-side material of every version of `record`.
///
/// Returns `true` only when every version was destroyed. Returns `false` on the
/// first provider-resolution or delete failure, having audited that failure —
/// the caller must then leave the record in `PendingDeletion`.
///
/// A retained claim may retry the same immutable handles after restart. Providers
/// must treat confirmed absence as success; unknown outcomes keep the fence.
async fn destroy_backend_material(
    state: &ServiceState,
    claim: &keyrack_core::destruction::DestructionClaim,
) -> bool {
    let record = claim.record();
    // Envelope bytes are erased only by fenced storage completion. Never ask a
    // provider to destroy the wrapped child's parent handle or transient lease.
    if let Err(error) = keyrack_core::destruction::validate_destruction_history(record) {
        emit_destroy_event(
            state,
            claim,
            record.current_key_version,
            Err(&error.to_string()),
        )
        .await;
        return false;
    }
    let mut providers = std::collections::HashMap::new();
    for version in record.key_versions.iter().filter(|v| {
        matches!(
            v.material,
            keyrack_core::key::KeyMaterial::ProviderResident { .. }
        )
    }) {
        let binding = record
            .effective_provider_ref(version.version_number)
            .cloned()
            .unwrap_or_else(|| state.providers.default_ref().clone());
        if providers.contains_key(&binding) {
            continue;
        }
        match state
            .providers
            .resolve_for_version(record, version.version_number)
        {
            Ok(entry) => {
                providers.insert(binding, entry);
            }
            Err(e) => {
                emit_destroy_event(state, claim, version.version_number, Err(&e.to_string())).await;
                return false;
            }
        }
    }
    // Pin one instance per effective binding before the first effect; a registry
    // replacement cannot redirect later versions mid-destruction.
    for version in record.key_versions.iter().filter(|v| {
        matches!(
            v.material,
            keyrack_core::key::KeyMaterial::ProviderResident { .. }
        )
    }) {
        let Ok(handle) = version.resident_handle() else {
            return false;
        };
        let binding = record
            .effective_provider_ref(version.version_number)
            .cloned()
            .unwrap_or_else(|| state.providers.default_ref().clone());
        let Some(entry) = providers.get(&binding) else {
            return false;
        };

        match entry.provider.destroy_key_with_outcome(handle).await {
            Ok(outcome) => {
                emit_destroy_event(state, claim, version.version_number, Ok(outcome)).await;
            }
            Err(e) => {
                let reason = e.to_string();
                tracing::error!(
                    lid = %record.lid,
                    key_version = version.version_number,
                    provider = %entry.provider.capabilities().provider_name,
                    error = %reason,
                    "provider failed to destroy key material; key NOT destroyed"
                );
                emit_destroy_event(state, claim, version.version_number, Err(&reason)).await;
                return false;
            }
        }
    }
    true
}

/// Audit the provider-side delete outcome for one key version, separately from
/// the record's `KeyDestroyed` transition. Error means unconfirmed/possibly
/// partial destruction, not proof that the backend material survives.
async fn emit_destroy_event(
    state: &ServiceState,
    claim: &keyrack_core::destruction::DestructionClaim,
    version_number: u64,
    outcome: Result<DestroyKeyOutcome, &str>,
) {
    let record = claim.record();
    let mut event = AuditEvent::new(
        EventType::KeyDeleted,
        AuditAction::ProviderDestroyKey,
        system_principal(),
        AuditResource {
            id: record.lid.to_string(),
            resource_type: "Key".into(),
        },
        if outcome.is_ok() {
            AuditResult::Success
        } else {
            AuditResult::Error
        },
    );
    event.add_metadata("key_version", version_number);
    event.add_metadata("operation_id", claim.operation().to_string());
    event.add_metadata("recovered", claim.is_recovered());
    if matches!(outcome, Ok(DestroyKeyOutcome::AlreadyAbsent)) {
        event.add_metadata("reason", "provider_key_already_absent");
    }
    if let Err(reason) = outcome {
        event.add_metadata("error", reason);
    }
    if let Err(e) = state.audit.emit(&event).await {
        tracing::error!(
            lid = %record.lid,
            error = %e,
            "failed to emit provider_destroy_key audit event"
        );
    }
}

fn system_principal() -> AuditPrincipal {
    AuditPrincipal {
        id: "keyrack:system".into(),
        principal_type: "System".into(),
    }
}

/// Transitions rotation jobs past their `expires_at` that are still
/// in `Pending` or `Acknowledged` to `Expired`.
pub async fn rotation_expiry_worker(state: Arc<ServiceState>, cancel: CancellationToken) {
    tracing::info!("rotation expiry worker started (interval: {SCAN_INTERVAL:?})");
    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                tracing::info!("rotation expiry worker shutting down");
                return;
            }
            () = tokio::time::sleep(SCAN_INTERVAL) => {}
        }

        if let Err(e) = run_rotation_expiry_scan(&state).await {
            tracing::error!(error = %e, "rotation expiry worker scan failed");
        }
    }
}

async fn run_rotation_expiry_scan(state: &ServiceState) -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Utc::now();
    let mut expired = 0u64;

    for filter_state in [RotationJobState::Pending, RotationJobState::Acknowledged] {
        let jobs = state.storage.list_rotation_jobs(Some(filter_state)).await?;
        for job in &jobs {
            if now < job.expires_at {
                continue;
            }

            let mut updated = job.clone();
            if updated.transition_to(RotationJobState::Expired).is_err() {
                continue;
            }
            if let Err(e) = state.storage.update_rotation_job(&updated).await {
                tracing::warn!(job_id = %job.job_id, error = %e, "failed to expire rotation job");
                continue;
            }

            let event = AuditEvent::new(
                EventType::RotationJobStateChanged,
                AuditAction::RotationJobExpired,
                AuditPrincipal {
                    id: "keyrack:system".into(),
                    principal_type: "System".into(),
                },
                AuditResource {
                    id: job.job_id.clone(),
                    resource_type: "RotationJob".into(),
                },
                AuditResult::Success,
            );
            let _ = state.audit.emit(&event).await;
            expired += 1;
        }
    }

    if expired > 0 {
        tracing::info!(expired, "rotation expiry worker expired stale jobs");
    }
    Ok(())
}
