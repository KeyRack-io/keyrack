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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRequest {
    pub operation: Uuid,
    pub requested_parent: Option<Lid>,
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
            child,
            old_parent,
            new_parent,
            proposed,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
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
    pub request: MigrationRequest,
    pub phase: MigrationPhase,
    pub envelope_digests: Vec<[u8; 32]>,
}

impl MigrationJournal {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
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
