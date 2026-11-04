// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Atomic replacement of every wrapped version of one logical key.
use crate::creation::same_json;
use crate::error::{KeyRackError, Result};
use crate::key::{Exportability, KeyMaterial, KeyRecord, KeySpec, KeyState};
use crate::lid::Lid;
use crate::material::ParentWrappedMaterial;
use crate::wrapping::{VersionedKeyId, WrappingIdentifier};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub fn migration_invalid(message: &str) -> KeyRackError {
    KeyRackError::Storage(format!("wrapped-key migration: {message}"))
}

pub fn migration_busy() -> KeyRackError {
    KeyRackError::ProviderUnavailable(
        "key participates in an in-flight migration; retry the operation".into(),
    )
}

/// Optional caller assertions are immutable intent, including their presence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationConditions {
    pub expected_child_occ: Option<u64>,
    pub expected_old_parent_occ: Option<u64>,
    pub expected_new_parent_occ: Option<u64>,
    pub expected_old_parent: Option<Lid>,
    pub covered_versions: Option<Vec<u64>>,
}

impl MigrationConditions {
    pub fn canonicalize(mut self) -> Result<Self> {
        if let Some(versions) = &mut self.covered_versions {
            versions.sort_unstable();
            if versions.is_empty() || versions[0] == 0 || versions.windows(2).any(|v| v[0] == v[1])
            {
                return Err(migration_invalid(
                    "covered_versions must be a nonempty set of nonzero versions",
                ));
            }
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRequest {
    pub operation: Uuid,
    pub requested_parent: Option<Lid>,
    pub conditions: MigrationConditions,
    pub child: KeyRecord,
    pub old_parent: KeyRecord,
    pub new_parent: KeyRecord,
    pub proposed: KeyRecord,
}

impl MigrationRequest {
    pub fn new(
        operation: Uuid,
        requested_parent: Option<Lid>,
        child: KeyRecord,
        old_parent: KeyRecord,
        new_parent: KeyRecord,
    ) -> Result<Self> {
        let mut proposed = child.clone();
        proposed.parent_lid = Some(new_parent.lid);
        proposed.occ_version = child
            .occ_version
            .checked_add(1)
            .ok_or_else(|| migration_invalid("OCC overflow"))?;
        proposed.updated_at = chrono::Utc::now();
        let parent = VersionedKeyId::new(new_parent.lid, new_parent.current_key_version)
            .map_err(|_| migration_invalid("invalid parent version"))?;
        for version in &mut proposed.key_versions {
            let KeyMaterial::ParentWrapped(material) = &version.material else {
                return Err(migration_invalid("every child version must be wrapped"));
            };
            version.material = KeyMaterial::ParentWrapped(
                ParentWrappedMaterial::new(
                    material.provider_ref().clone(),
                    material.security_domain().clone(),
                    parent,
                    material.wrapping_context_version(),
                    material.key_format().clone(),
                    material.mechanism().clone(),
                    WrappingIdentifier::new(format!(
                        "migration:{operation}:{}",
                        version.version_number
                    ))
                    .map_err(|_| migration_invalid("invalid envelope reference"))?,
                )
                .map_err(|_| migration_invalid("invalid proposed material"))?,
            );
        }
        let request = Self {
            operation,
            requested_parent,
            conditions: MigrationConditions::default(),
            child,
            old_parent,
            new_parent,
            proposed,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn with_conditions(mut self, conditions: MigrationConditions) -> Result<Self> {
        self.conditions = conditions.canonicalize()?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        let conditions = self.conditions.clone().canonicalize()?;
        if conditions != self.conditions {
            return Err(migration_invalid("noncanonical migration conditions"));
        }
        let mut covered: Vec<u64> = self
            .child
            .key_versions
            .iter()
            .map(|v| v.version_number)
            .collect();
        covered.sort_unstable();
        if conditions
            .expected_child_occ
            .is_some_and(|v| v != self.child.occ_version)
            || conditions
                .expected_old_parent_occ
                .is_some_and(|v| v != self.old_parent.occ_version)
            || conditions
                .expected_new_parent_occ
                .is_some_and(|v| v != self.new_parent.occ_version)
            || conditions
                .expected_old_parent
                .is_some_and(|v| v != self.old_parent.lid)
            || conditions
                .covered_versions
                .as_ref()
                .is_some_and(|v| v != &covered)
        {
            return Err(migration_invalid(
                "caller migration conditions do not match the reserved snapshots",
            ));
        }
        let child = &self.child;
        let old = &self.old_parent;
        let new = &self.new_parent;
        if self.operation.is_nil()
            || child.occ_version == 0
            || child.occ_version >= i64::MAX as u64
            || child.key_versions.is_empty()
            || child.parent_lid != Some(old.lid)
            || child.lid == old.lid
            || child.lid == new.lid
            || self.requested_parent.unwrap_or(old.lid) != new.lid
            || child.state != KeyState::Enabled
            || child.scheduled_deletion_at.is_some()
            || child.has_compromise_history()
            || child.exportability != Exportability::NonExportable
        {
            return Err(migration_invalid(
                "invalid migration identity or child state",
            ));
        }
        for parent in [old, new] {
            if parent.parent_lid.is_some()
                || parent.has_compromise_history()
                || parent.state != KeyState::Enabled
                || parent.scheduled_deletion_at.is_some()
                || parent.exportability != Exportability::NonExportable
                || parent.first_exported_at.is_some()
                || !matches!(parent.key_spec, KeySpec::Aes128 | KeySpec::Aes256)
                || parent.key_versions.is_empty()
                || parent
                    .key_versions
                    .iter()
                    .any(|v| !matches!(v.material, KeyMaterial::ProviderResident { .. }))
            {
                return Err(migration_invalid(
                    "parent must be an enabled, resident, non-exportable wrapping key",
                ));
            }
        }
        let target = new
            .primary_version()
            .ok_or_else(|| migration_invalid("missing target primary"))?;
        let mut expected = child.clone();
        expected.parent_lid = Some(new.lid);
        expected.occ_version += 1;
        expected.updated_at = self.proposed.updated_at;
        let mut seen = std::collections::HashSet::new();
        for version in &mut expected.key_versions {
            if version.version_number == 0
                || !seen.insert(version.version_number)
                || version.is_primary != (version.version_number == child.current_key_version)
            {
                return Err(migration_invalid("invalid child version history"));
            }
            let KeyMaterial::ParentWrapped(material) = &version.material else {
                return Err(migration_invalid("every child version must be wrapped"));
            };
            let source = old
                .get_version(material.parent().version.get())
                .ok_or_else(|| migration_invalid("missing source parent version"))?;
            if material.parent().lid != old.lid
                || source.provider_ref() != Some(material.provider_ref())
                || target.provider_ref() != Some(material.provider_ref())
            {
                return Err(migration_invalid(
                    "cross-provider migration is not implemented",
                ));
            }
            let replacement = ParentWrappedMaterial::new(
                material.provider_ref().clone(),
                material.security_domain().clone(),
                VersionedKeyId::new(new.lid, new.current_key_version)
                    .map_err(|_| migration_invalid("zero parent version"))?,
                material.wrapping_context_version(),
                material.key_format().clone(),
                material.mechanism().clone(),
                WrappingIdentifier::new(format!(
                    "migration:{}:{}",
                    self.operation, version.version_number
                ))
                .map_err(|_| migration_invalid("invalid envelope reference"))?,
            )
            .map_err(|_| migration_invalid("invalid material"))?;
            version.material = KeyMaterial::ParentWrapped(replacement);
        }
        if !seen.contains(&child.current_key_version) || !same_json(&expected, &self.proposed)? {
            return Err(migration_invalid(
                "proposal changes unrelated fields or omits a version",
            ));
        }
        // Compare original immutable profile values across the whole history.
        let first = wrapped(&child.key_versions[0].material)?;
        for version in &child.key_versions {
            let material = wrapped(&version.material)?;
            if material.provider_ref() != first.provider_ref()
                || material.security_domain() != first.security_domain()
                || material.mechanism() != first.mechanism()
            {
                return Err(migration_invalid(
                    "cross-domain migration is not implemented",
                ));
            }
        }
        Ok(())
    }

    /// Ignore only the proposal timestamp when concurrent identical requests reserve.
    pub fn same_intent(&self, other: &Self) -> Result<bool> {
        let mut normalized = other.clone();
        normalized.proposed.updated_at = self.proposed.updated_at;
        same_json(self, &normalized)
    }

    pub fn validate_snapshots(
        &self,
        child: &KeyRecord,
        old: &KeyRecord,
        new: &KeyRecord,
    ) -> Result<()> {
        self.validate()?;
        for (expected, actual) in [
            (&self.child, child),
            (&self.old_parent, old),
            (&self.new_parent, new),
        ] {
            if !same_json(expected, actual)? {
                return Err(migration_busy());
            }
        }
        Ok(())
    }
}

fn wrapped(material: &KeyMaterial) -> Result<&ParentWrappedMaterial> {
    match material {
        KeyMaterial::ParentWrapped(value) => Ok(value),
        KeyMaterial::ProviderResident { .. } => Err(migration_invalid("resident child version")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    Reserved,
    Staged,
    Committed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationJournal {
    pub owner: Option<Uuid>,
    pub epoch: u64,
    pub dispatch: Option<MigrationDispatch>,
    pub result: Option<MigrationResult>,
    pub request: MigrationRequest,
    pub phase: MigrationPhase,
    pub envelope_digests: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationOwnership {
    pub owner: Uuid,
    pub epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationDispatch {
    pub epoch: u64,
    pub retry_safe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationVersionResult {
    pub version: u64,
    pub old_parent_version: u64,
    pub new_parent_version: u64,
    pub old_envelope_digest: String,
    pub new_envelope_digest: String,
    pub old_reference: String,
    pub new_reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationResult {
    pub operation_id: Uuid,
    pub child: Lid,
    pub old_parent: Lid,
    pub old_parent_versions: Vec<u64>,
    pub new_parent: Lid,
    pub new_parent_version: u64,
    pub digest_algorithm: String,
    pub versions: Vec<MigrationVersionResult>,
}

#[derive(Debug, Clone)]
pub struct WrappedKeySnapshot {
    pub record: KeyRecord,
    pub parent: KeyRecord,
    pub envelope: Vec<u8>,
}

impl MigrationJournal {
    pub fn reserved(request: MigrationRequest) -> Self {
        Self {
            request,
            phase: MigrationPhase::Reserved,
            envelope_digests: Vec::new(),
            owner: None,
            epoch: 0,
            dispatch: None,
            result: None,
        }
    }

    pub fn ownership(&self) -> Result<MigrationOwnership> {
        Ok(MigrationOwnership {
            owner: self
                .owner
                .ok_or_else(|| migration_invalid("migration has no owner"))?,
            epoch: self.epoch,
        })
    }

    pub fn require_owner(&self, ownership: MigrationOwnership) -> Result<()> {
        if ownership.owner.is_nil()
            || self.owner != Some(ownership.owner)
            || ownership.epoch != self.epoch
            || self.epoch == 0
        {
            return Err(migration_busy());
        }
        Ok(())
    }

    pub fn claim(&mut self, owner: Uuid, expected_epoch: u64) -> Result<()> {
        if owner.is_nil() || self.epoch != expected_epoch {
            return Err(migration_busy());
        }
        if self.phase == MigrationPhase::Committed {
            return Err(migration_invalid(
                "committed migration cannot be taken over",
            ));
        }
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| migration_invalid("ownership epoch exhausted"))?;
        self.owner = Some(owner);
        Ok(())
    }

    pub fn begin_dispatch(
        &mut self,
        ownership: MigrationOwnership,
        retry_safe: bool,
    ) -> Result<()> {
        self.require_owner(ownership)?;
        if self.phase != MigrationPhase::Reserved {
            return Err(migration_invalid(
                "provider dispatch requires a reserved migration",
            ));
        }
        if self.dispatch.is_some_and(|dispatch| !dispatch.retry_safe) {
            return Err(KeyRackError::ProviderUnavailable(
                "unknown migration provider outcome requires reconciliation; reservation retained"
                    .into(),
            ));
        }
        self.dispatch = Some(MigrationDispatch {
            epoch: ownership.epoch,
            retry_safe,
        });
        Ok(())
    }

    pub fn terminal_result(&self, old_envelopes: &[Vec<u8>]) -> Result<MigrationResult> {
        self.validate_envelopes(old_envelopes)?;
        let mut versions = Vec::new();
        for ((old, new), bytes) in self
            .request
            .child
            .key_versions
            .iter()
            .zip(&self.request.proposed.key_versions)
            .zip(old_envelopes)
        {
            let old_material = wrapped(&old.material)?;
            let new_material = wrapped(&new.material)?;
            let index = versions.len();
            let digest = self
                .envelope_digests
                .get(index)
                .ok_or_else(|| migration_invalid("missing staged digest"))?;
            versions.push(MigrationVersionResult {
                version: old.version_number,
                old_parent_version: old_material.parent().version.get(),
                new_parent_version: new_material.parent().version.get(),
                old_envelope_digest: blake3::hash(bytes).to_hex().to_string(),
                new_envelope_digest: blake3::Hash::from_bytes(*digest).to_hex().to_string(),
                old_reference: old_material.wrapped_material_ref().as_str().into(),
                new_reference: new_material.wrapped_material_ref().as_str().into(),
            });
        }
        let mut old_parent_versions: Vec<u64> =
            versions.iter().map(|v| v.old_parent_version).collect();
        old_parent_versions.sort_unstable();
        old_parent_versions.dedup();
        Ok(MigrationResult {
            operation_id: self.request.operation,
            child: self.request.child.lid,
            old_parent: self.request.old_parent.lid,
            old_parent_versions,
            new_parent: self.request.new_parent.lid,
            new_parent_version: self.request.new_parent.current_key_version,
            digest_algorithm: "blake3".into(),
            versions,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        if self.owner.is_some_and(|owner| owner.is_nil())
            || self.owner.is_some() != (self.epoch > 0)
            || self
                .dispatch
                .is_some_and(|dispatch| dispatch.epoch == 0 || dispatch.epoch > self.epoch)
            || self.result.is_some() != (self.phase == MigrationPhase::Committed)
        {
            return Err(migration_invalid(
                "invalid migration ownership or terminal state",
            ));
        }
        if let Some(result) = &self.result {
            if result.operation_id != self.request.operation
                || result.child != self.request.child.lid
                || result.old_parent != self.request.old_parent.lid
                || result.new_parent != self.request.new_parent.lid
                || result.new_parent_version != self.request.new_parent.current_key_version
                || result.digest_algorithm != "blake3"
                || result.versions.len() != self.request.child.key_versions.len()
            {
                return Err(migration_invalid("terminal result binding mismatch"));
            }
            let mut old_versions = Vec::new();
            for (index, ((entry, old), new)) in result
                .versions
                .iter()
                .zip(&self.request.child.key_versions)
                .zip(&self.request.proposed.key_versions)
                .enumerate()
            {
                let old_material = wrapped(&old.material)?;
                let new_material = wrapped(&new.material)?;
                let digest = self
                    .envelope_digests
                    .get(index)
                    .ok_or_else(|| migration_invalid("terminal envelope digest missing"))?;
                if entry.version != old.version_number
                    || entry.old_parent_version != old_material.parent().version.get()
                    || entry.new_parent_version != new_material.parent().version.get()
                    || entry.old_reference != old_material.wrapped_material_ref().as_str()
                    || entry.new_reference != new_material.wrapped_material_ref().as_str()
                    || entry.new_envelope_digest
                        != blake3::Hash::from_bytes(*digest).to_hex().as_str()
                    || entry.old_envelope_digest.len() != 64
                    || !entry
                        .old_envelope_digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(migration_invalid("terminal version binding mismatch"));
                }
                old_versions.push(entry.old_parent_version);
            }
            old_versions.sort_unstable();
            old_versions.dedup();
            if result.old_parent_versions != old_versions {
                return Err(migration_invalid(
                    "terminal old-parent version set mismatch",
                ));
            }
        }
        let expected = if self.phase == MigrationPhase::Reserved {
            0
        } else {
            self.request.child.key_versions.len()
        };
        if self.envelope_digests.len() != expected {
            return Err(migration_invalid("journal envelope digest count mismatch"));
        }
        Ok(())
    }

    pub fn record_envelope_digests(&mut self, envelopes: &[Vec<u8>]) {
        self.envelope_digests = envelopes
            .iter()
            .map(|bytes| *blake3::hash(bytes).as_bytes())
            .collect();
    }

    pub fn verify_envelope(&self, version: u64, envelope: &[u8]) -> Result<()> {
        let index = self
            .request
            .proposed
            .key_versions
            .iter()
            .position(|v| v.version_number == version)
            .ok_or_else(|| migration_invalid("unknown envelope version"))?;
        if envelope.is_empty()
            || envelope.len() > crate::creation::MAX_CREATION_ENVELOPE_BYTES
            || self.envelope_digests.get(index) != Some(blake3::hash(envelope).as_bytes())
        {
            return Err(migration_invalid("staged envelope binding mismatch"));
        }
        Ok(())
    }

    pub fn validate_envelopes(&self, envelopes: &[Vec<u8>]) -> Result<()> {
        if envelopes.len() != self.request.child.key_versions.len()
            || envelopes.iter().any(|bytes| {
                bytes.is_empty() || bytes.len() > crate::creation::MAX_CREATION_ENVELOPE_BYTES
            })
        {
            return Err(migration_invalid(
                "requires one bounded envelope per version",
            ));
        }
        Ok(())
    }
}
