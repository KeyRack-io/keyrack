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

//! Migration plan types for canonicalization version upgrades.
//!
//! Phase 1 scope: canonicalization migration only (re-derive LIDs
//! under a new canonicalization version, create old→new aliases,
//! update key records).

use crate::canon::CanonicalizationVersion;
use crate::lid::Lid;
use serde::{Deserialize, Serialize};

/// Action to take for a single key during migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationAction {
    /// Re-derive LID, update record, create alias from old LID.
    RederiveLid,
    /// Skip — key already at target version.
    Skip,
}

/// A single entry in a migration plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationEntry {
    pub old_lid: String,
    pub new_lid: Option<String>,
    pub from_version: u32,
    pub to_version: u32,
    pub action: MigrationAction,
    pub applied: bool,
}

/// A complete migration plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub from_canonicalization: u32,
    pub to_canonicalization: u32,
    pub entries: Vec<MigrationEntry>,
    pub created_at: String,
}

/// Checkpoint for resumable migration execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationState {
    pub plan_file: String,
    pub completed: Vec<String>,
    pub failed: Vec<(String, String)>,
}

/// Parse a version string like "v1" into a `CanonicalizationVersion`.
pub fn parse_canon_version(s: &str) -> Result<CanonicalizationVersion, String> {
    match s.to_lowercase().trim_start_matches('v') {
        "1" => Ok(CanonicalizationVersion::V1),
        other => Err(format!("unknown canonicalization version: {other}")),
    }
}

/// Map a `CanonicalizationVersion` to a plan-level u32.
pub fn canon_version_to_u32(v: CanonicalizationVersion) -> u32 {
    v as u32
}

/// Compute a new LID for a key record under a target canonicalization version.
pub fn rederive_lid(
    old_lid: &Lid,
    identity_tags: &crate::tags::IdentityTags,
    target_version: CanonicalizationVersion,
) -> Lid {
    let mut attr_set = crate::attr::AttributeSet::new();
    for (k, v) in identity_tags.as_map() {
        attr_set.insert(k, crate::attr::AttributeValue::String(v.clone()));
    }
    let form = crate::canon::canonicalize(target_version, &attr_set);
    let new_lid = Lid::derive(target_version, &form);

    tracing::debug!(
        old = %old_lid,
        new = %new_lid,
        "re-derived LID under {:?}",
        target_version,
    );

    new_lid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_strings() {
        assert!(parse_canon_version("v1").is_ok());
        assert!(parse_canon_version("V1").is_ok());
        assert!(parse_canon_version("1").is_ok());
        assert!(parse_canon_version("v99").is_err());
    }

    #[test]
    fn plan_roundtrip() {
        let plan = MigrationPlan {
            from_canonicalization: 1,
            to_canonicalization: 2,
            entries: vec![MigrationEntry {
                old_lid: "old-lid-hex".into(),
                new_lid: Some("new-lid-hex".into()),
                from_version: 1,
                to_version: 2,
                action: MigrationAction::RederiveLid,
                applied: false,
            }],
            created_at: "2026-01-01T00:00:00Z".into(),
        };

        let json = serde_json::to_string_pretty(&plan).unwrap();
        let restored: MigrationPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.entries.len(), 1);
        assert_eq!(restored.entries[0].old_lid, "old-lid-hex");
    }
}
