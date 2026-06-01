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
//! Both workers are idempotent storage scanners — they query for records
//! matching a condition and transition them. State lives in the database,
//! not in worker memory. A crash resumes on next startup.

use crate::state::ServiceState;
use keyrack_core::audit::{
    AuditAction, AuditEvent, AuditPrincipal, AuditResource, AuditResult, EventType,
};
use keyrack_core::key::KeyState;
use keyrack_core::rotation::RotationJobState;
use keyrack_core::storage::KeyFilter;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const SCAN_INTERVAL: Duration = Duration::from_secs(60);

/// Transitions keys in `PendingDeletion` past their `scheduled_deletion_at`
/// to `Destroyed`.
pub async fn deletion_worker(state: Arc<ServiceState>, cancel: CancellationToken) {
    tracing::info!("deletion worker started (interval: {SCAN_INTERVAL:?})");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("deletion worker shutting down");
                return;
            }
            _ = tokio::time::sleep(SCAN_INTERVAL) => {}
        }

        if let Err(e) = run_deletion_scan(&state).await {
            tracing::error!(error = %e, "deletion worker scan failed");
        }
    }
}

async fn run_deletion_scan(state: &ServiceState) -> Result<(), Box<dyn std::error::Error>> {
    let filter = KeyFilter {
        state: Some(KeyState::PendingDeletion),
        ..KeyFilter::default()
    };
    let page = state.storage.list_keys(&filter).await?;
    let now = chrono::Utc::now();

    let mut destroyed = 0u64;
    for record in &page.items {
        let past_due = record
            .scheduled_deletion_at
            .is_some_and(|t| now >= t);
        if !past_due {
            continue;
        }

        let mut updated = record.clone();
        if updated.transition_to(KeyState::Destroyed).is_err() {
            continue;
        }
        if let Err(e) = state.storage.update_key(&updated).await {
            tracing::warn!(lid = %record.lid, error = %e, "failed to destroy key");
            continue;
        }

        let event = AuditEvent::new(
            EventType::KeyDeleted,
            AuditAction::KeyDestroyed,
            AuditPrincipal {
                id: "keyrack:system".into(),
                principal_type: "System".into(),
            },
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
    Ok(())
}

/// Transitions rotation jobs past their `expires_at` that are still
/// in `Pending` or `Acknowledged` to `Expired`.
pub async fn rotation_expiry_worker(state: Arc<ServiceState>, cancel: CancellationToken) {
    tracing::info!("rotation expiry worker started (interval: {SCAN_INTERVAL:?})");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("rotation expiry worker shutting down");
                return;
            }
            _ = tokio::time::sleep(SCAN_INTERVAL) => {}
        }

        if let Err(e) = run_rotation_expiry_scan(&state).await {
            tracing::error!(error = %e, "rotation expiry worker scan failed");
        }
    }
}

async fn run_rotation_expiry_scan(
    state: &ServiceState,
) -> Result<(), Box<dyn std::error::Error>> {
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
