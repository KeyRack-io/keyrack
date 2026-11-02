// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One-shot storage fencing for resident-key destruction, not authorization,
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

/// Counts that block destruction, without disclosing dependent key identities.
/// Every stored version and every journal phase counts, including historical
/// material and completed creation journals. Logical `parent_lid` is not an edge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DestructionDependencies {
    pub own_parent_wrapped_versions: u64,
    pub dependent_parent_wrapped_versions: u64,
    pub creation_journal_rows: u64,
}

impl DestructionDependencies {
    pub fn is_empty(&self) -> bool {
        self.own_parent_wrapped_versions == 0
            && self.dependent_parent_wrapped_versions == 0
            && self.creation_journal_rows == 0
    }

    pub fn summary(&self) -> String {
        format!(
            "own_parent_wrapped_versions={}, dependent_parent_wrapped_versions={}, creation_journal_rows={}",
            self.own_parent_wrapped_versions,
            self.dependent_parent_wrapped_versions,
            self.creation_journal_rows,
        )
    }

    /// Shared material counting for storage implementors scanning a consistent
    /// snapshot. A version belongs to the own OR other-key category, never both.
    pub fn include_record(&mut self, lid: &Lid, record: &KeyRecord) -> Result<()> {
        for version in &record.key_versions {
            if let KeyMaterial::ParentWrapped(material) = &version.material {
                let count = if record.lid == *lid {
                    &mut self.own_parent_wrapped_versions
                } else if material.parent().lid == *lid {
                    &mut self.dependent_parent_wrapped_versions
                } else {
                    continue;
                };
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| invalid("dependency count overflow"))?;
            }
        }
        Ok(())
    }
}

/// Execution ticket issued only after committing a fresh destruction claim.
/// Deliberately neither Clone nor Deserialize. Reading/retrying a journal must
/// never mint another ticket. Dropping it leaves the durable fence in place.
#[derive(Debug)]
pub struct DestructionClaim {
    operation: Uuid,
    record: KeyRecord,
}

impl DestructionClaim {
    /// For trusted `StorageBackend` implementors, after successful commit only.
    /// This constructor alone supplies no authority or provider confirmation.
    pub fn committed(operation: Uuid, record: KeyRecord) -> Result<Self> {
        if operation.is_nil() || record.state != KeyState::PendingDeletion {
            return Err(invalid("invalid committed claim"));
        }
        validate_resident_history(&record)?;
        Ok(Self { operation, record })
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
pub fn validate_resident_history(record: &KeyRecord) -> Result<()> {
    let mut versions = std::collections::HashSet::new();
    if record.key_versions.is_empty() || record.primary_version().is_none() {
        return Err(invalid("missing resident history"));
    }
    for version in &record.key_versions {
        let handle = version.resident_handle()?;
        if version.version_number == 0
            || !versions.insert(version.version_number)
            || version.is_primary != (version.version_number == record.current_key_version)
            || handle.key_id.is_empty()
            || handle.key_spec != record.key_spec
        {
            return Err(invalid("invalid resident history"));
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
    validate_resident_history(&record)?;
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
