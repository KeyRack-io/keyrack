// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable storage fencing for key-material destruction, not authorization,
//! provider evidence, subtree erasure, or distributed revocation. A durable
//! claim is never released by timeout, cancellation, crash, or provider error.

use crate::error::{KeyRackError, Result};
use crate::key::{KeyMaterial, KeyRecord, KeyState};
use crate::lid::Lid;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub fn invalid(message: &str) -> KeyRackError {
    KeyRackError::Storage(format!("destruction: {message}"))
}

/// Durable identity of a dependency approved for deliberate data loss. Binding
/// the version, parent version and envelope prevents approval of a new edge on
/// an already-listed logical key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct DestructionDependent {
    pub lid: Lid,
    pub version: u64,
    pub parent_version: u64,
    pub envelope_ref: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeletionIntent {
    pub allow_dependent_data_loss: bool,
    pub approved_dependents: Vec<DestructionDependent>,
}

/// A committed schedule and the informational count from its fenced admission query.
#[derive(Debug)]
pub struct ScheduledDeletion {
    pub record: KeyRecord,
    pub logical_only_children: u64,
    pub approved_dependents: Vec<DestructionDependent>,
}

/// Durable, version-specific metadata; the dependent's material and state are
/// left unchanged when its wrapping parent is destroyed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DestroyedWrappingParent {
    pub version: u64,
    pub parent_lid: Lid,
    pub parent_version: u64,
}

/// A consistent observation shared by scheduling and the fenced claim. Logical
/// ancestry is not cryptographic dependence. Committed receipts are metadata;
/// only live envelopes and nonterminal journals prevent ordinary destruction.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DestructionDependencies {
    /// Informational; direct persisted children with nonempty all-resident histories.
    pub logical_only_children: u64,
    pub own_parent_wrapped_versions: u64,
    pub dependent_wrapping_edges: u64,
    pub creation_journal_rows: u64,
    pub in_flight_creation_journal_rows: u64,
    pub migration_journal_rows: u64,
    pub dependents: Vec<DestructionDependent>,
}

impl DestructionDependencies {
    pub fn is_empty(&self) -> bool {
        self.dependents.is_empty()
            && self.in_flight_creation_journal_rows == 0
            && self.migration_journal_rows == 0
    }

    pub fn summary(&self) -> String {
        format!(
            "own_parent_wrapped_versions={}, dependent_wrapping_edges={}, creation_journal_rows={}, in_flight_creation_journal_rows={}, migration_journal_rows={}",
            self.own_parent_wrapped_versions, self.dependent_wrapping_edges,
            self.creation_journal_rows, self.in_flight_creation_journal_rows, self.migration_journal_rows,
        )
    }

    pub fn include_record(&mut self, lid: &Lid, record: &KeyRecord) -> Result<()> {
        if record.lid != *lid
            && record.parent_lid == Some(*lid)
            && !record.key_versions.is_empty()
            && record
                .key_versions
                .iter()
                .all(|version| matches!(version.material, KeyMaterial::ProviderResident { .. }))
        {
            self.logical_only_children = self
                .logical_only_children
                .checked_add(1)
                .ok_or_else(|| invalid("dependency count overflow"))?;
        }
        if record.state == KeyState::Destroyed {
            return Ok(());
        }
        for version in &record.key_versions {
            if let KeyMaterial::ParentWrapped(material) = &version.material {
                if record.lid == *lid {
                    self.own_parent_wrapped_versions += 1;
                } else if material.parent().lid == *lid {
                    self.dependent_wrapping_edges += 1;
                    self.dependents.push(DestructionDependent {
                        lid: record.lid,
                        version: version.version_number,
                        parent_version: material.parent().version.get(),
                        envelope_ref: material.wrapped_material_ref().as_str().to_owned(),
                    });
                }
            }
        }
        self.dependents.sort();
        self.dependents.dedup();
        Ok(())
    }

    /// Never override in-flight work. A subset is allowed so retiring a
    /// dependency does not invalidate approval; every new edge requires it anew.
    pub fn validate_intent(&self, intent: &DeletionIntent) -> Result<()> {
        let reason = if self.in_flight_creation_journal_rows > 0 || self.migration_journal_rows > 0
        {
            Some("in_flight_journal")
        } else if !self.dependents.is_empty() && !intent.allow_dependent_data_loss {
            Some("dependent_data_loss_not_approved")
        } else if self
            .dependents
            .iter()
            .any(|edge| !intent.approved_dependents.contains(edge))
        {
            Some("dependent_outside_approved_snapshot")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(KeyRackError::DeletionDependencyRefused {
                reason: reason.into(),
                counts: self.summary(),
            });
        }
        Ok(())
    }

    pub fn approval(&self, allow: bool) -> Result<DeletionIntent> {
        let intent = DeletionIntent {
            allow_dependent_data_loss: allow,
            approved_dependents: if allow {
                self.dependents.clone()
            } else {
                Vec::new()
            },
        };
        self.validate_intent(&intent)?;
        Ok(intent)
    }
}

/// Execution authority for a committed destruction operation. A recovered ticket
/// retains the exact operation and immutable material snapshot from its journal.
/// Provider deletion is retried idempotently; the durable fence never expires.
#[derive(Debug)]
pub struct DestructionClaim {
    operation: Uuid,
    record: KeyRecord,
    recovered: bool,
}

impl DestructionClaim {
    /// For trusted `StorageBackend` implementors, after successful commit only.
    /// This constructor alone supplies no authority or provider confirmation.
    pub fn committed(operation: Uuid, record: KeyRecord) -> Result<Self> {
        if operation.is_nil() || record.state != KeyState::PendingDeletion {
            return Err(invalid("invalid committed claim"));
        }
        validate_destruction_history(&record)?;
        Ok(Self {
            operation,
            record,
            recovered: false,
        })
    }

    /// Reissue only after validating the durable journal against the fenced row.
    pub fn recovered(operation: Uuid, record: KeyRecord) -> Result<Self> {
        let mut claim = Self::committed(operation, record)?;
        claim.recovered = true;
        Ok(claim)
    }

    pub fn is_recovered(&self) -> bool {
        self.recovered
    }

    pub fn operation(&self) -> Uuid {
        self.operation
    }

    pub fn record(&self) -> &KeyRecord {
        &self.record
    }
}

/// Validate the entire history, never just the current version. Empty, duplicate
/// or unsupported material must not become a vacuous successful destruction.
pub fn validate_destruction_history(record: &KeyRecord) -> Result<()> {
    let mut versions = std::collections::HashSet::new();
    if record.key_versions.is_empty() || record.primary_version().is_none() {
        return Err(invalid("missing material history"));
    }
    for version in &record.key_versions {
        if version.version_number == 0
            || !versions.insert(version.version_number)
            || version.is_primary != (version.version_number == record.current_key_version)
        {
            return Err(invalid("invalid material history"));
        }
        match &version.material {
            KeyMaterial::ProviderResident { key_handle, .. } => {
                if key_handle.key_id.is_empty() || key_handle.key_spec != record.key_spec {
                    return Err(invalid("invalid resident history"));
                }
            }
            KeyMaterial::ParentWrapped(material) => {
                if material.parent().lid == record.lid {
                    return Err(invalid("self-wrapped destruction history"));
                }
            }
        }
    }
    Ok(())
}

/// Called on a fresh row under the same write lock as journal/CRUD mutations.
pub fn prepare_claim(
    mut record: KeyRecord,
    expected_occ: u64,
    now: DateTime<Utc>,
) -> Result<KeyRecord> {
    if record.occ_version != expected_occ {
        return Err(KeyRackError::OptimisticConcurrencyConflict {
            lid: record.lid,
            expected: expected_occ,
            actual: record.occ_version,
        });
    }
    if record.state != KeyState::PendingDeletion
        || !record.scheduled_deletion_at.is_some_and(|due| due <= now)
    {
        return Err(invalid("key is not due for destruction"));
    }
    validate_destruction_history(&record)?;
    // Reserve room for both the claim and its final completion in SQL BIGINT.
    if expected_occ == 0 || expected_occ > i64::MAX as u64 - 2 {
        return Err(invalid("OCC out of range"));
    }
    record.occ_version += 1;
    record.updated_at = now;
    Ok(record)
}

/// Completion requires the identical fenced snapshot, including provider
/// bindings and every historical handle. This is not a provider receipt check:
/// the trusted caller must first confirm every provider operation succeeded.
pub fn completed_record(claim: &DestructionClaim, current: &KeyRecord) -> Result<KeyRecord> {
    if !crate::creation::same_json(claim.record(), current)? {
        return Err(invalid("claimed snapshot changed"));
    }
    let mut record = current.clone();
    record.occ_version = record
        .occ_version
        .checked_add(1)
        .filter(|v| i64::try_from(*v).is_ok())
        .ok_or(invalid("OCC overflow"))?;
    record.state = KeyState::Destroyed;
    record.updated_at = Utc::now();
    Ok(record)
}

/// Validate a repeat completion without changing the original completion time.
/// Only the same operation's exact terminal snapshot may be accepted.
pub fn validate_completed_record(claim: &DestructionClaim, current: &KeyRecord) -> Result<()> {
    let mut expected = completed_record(claim, claim.record())?;
    expected.updated_at = current.updated_at;
    if !crate::creation::same_json(&expected, current)? {
        return Err(invalid("completed snapshot changed"));
    }
    Ok(())
}
