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

//! Storage backend trait for `KeyRack` metadata persistence.
//!
//! All operations are async. Implementations must enforce optimistic
//! concurrency control via `occ_version` (§9.2): any mutation that
//! finds a version mismatch returns
//! [`KeyRackError::OptimisticConcurrencyConflict`](crate::error::KeyRackError::OptimisticConcurrencyConflict).
//!
//! Out-of-tree implementations live in `keyrack-postgres` and
//! `keyrack-sqlite`.

use crate::error::Result;
use crate::hsm::HsmConnection;
use crate::key::KeyRecord;
use crate::lid::Lid;
use crate::rotation::RotationJob;
use async_trait::async_trait;

/// Page of results for list operations.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Page<T: serde::Serialize> {
    pub items: Vec<T>,
    /// Opaque cursor for the next page. `None` when no more pages.
    pub next_cursor: Option<String>,
}

/// Filter for listing keys.
#[derive(Debug, Clone, Default)]
pub struct KeyFilter {
    /// Only return keys matching these user-tag key-value pairs (AND).
    pub user_tags: Vec<(String, String)>,
    /// Only return keys in this state (if set).
    pub state: Option<crate::key::KeyState>,
    /// Maximum items to return per page.
    pub limit: Option<u32>,
    /// Opaque cursor from a previous `list_keys` call.
    pub cursor: Option<String>,
}

/// Human-readable alias for a key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AliasRecord {
    pub alias_name: String,
    pub target_lid: Lid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Storage backend trait.
///
/// Each method documents its OCC and error semantics.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    // ── Keys ──────────────────────────────────────────────────────

    /// Insert a new key record. Fails if the LID already exists.
    async fn create_key(&self, record: &KeyRecord) -> Result<()>;

    /// Fetch a key by LID. Returns `KeyNotFound` if absent.
    async fn get_key(&self, lid: &Lid) -> Result<KeyRecord>;

    /// Atomic update with OCC. Checks `occ_version` matches; on
    /// mismatch returns `OptimisticConcurrencyConflict`.
    async fn update_key(&self, record: &KeyRecord) -> Result<()>;

    /// List keys with optional filtering and pagination.
    async fn list_keys(&self, filter: &KeyFilter) -> Result<Page<KeyRecord>>;

    /// List keys whose `parent_lid` matches the given LID (direct children).
    async fn list_children(&self, parent: &Lid) -> Result<Vec<KeyRecord>>;

    // ── Aliases ───────────────────────────────────────────────────

    /// Create an alias. Fails if the name is already taken.
    async fn create_alias(&self, alias: &AliasRecord) -> Result<()>;

    /// Resolve an alias name to a LID.
    async fn resolve_alias(&self, alias_name: &str) -> Result<Lid>;

    /// Delete an alias by name.
    async fn delete_alias(&self, alias_name: &str) -> Result<()>;

    /// List all aliases.
    async fn list_aliases(&self) -> Result<Vec<AliasRecord>>;

    // ── HSM connections ──────────────────────────────────────────

    async fn create_hsm_connection(&self, conn: &HsmConnection) -> Result<()>;
    async fn get_hsm_connection(&self, connection_id: &str) -> Result<HsmConnection>;
    async fn update_hsm_connection(&self, conn: &HsmConnection) -> Result<()>;
    async fn list_hsm_connections(&self) -> Result<Vec<HsmConnection>>;
    async fn delete_hsm_connection(&self, connection_id: &str) -> Result<()>;

    // ── Rotation jobs ────────────────────────────────────────────

    async fn create_rotation_job(&self, job: &RotationJob) -> Result<()>;
    async fn get_rotation_job(&self, job_id: &str) -> Result<RotationJob>;
    async fn update_rotation_job(&self, job: &RotationJob) -> Result<()>;

    /// List rotation jobs, optionally filtered by state.
    async fn list_rotation_jobs(
        &self,
        state_filter: Option<crate::rotation::RotationJobState>,
    ) -> Result<Vec<RotationJob>>;

    // ── Health ───────────────────────────────────────────────────

    /// Liveness probe (e.g. SELECT 1).
    async fn ping(&self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AttributeSet, AttributeValue};
    use crate::canon::{canonicalize, CanonicalizationVersion};
    use crate::error::KeyRackError;
    use crate::hsm::{HsmConnectionStatus, HsmProviderType};
    use crate::key::{
        KeyOrigin, KeyRecord, KeySpec, KeyState, KeyUsage, KeyVersionRecord, ProviderClass,
    };
    use crate::lid::Lid;
    use crate::provider::KeyHandle;
    use crate::rotation::RotationJobState;
    use crate::tags::{IdentityTags, UserTags};
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn make_test_record(state: KeyState) -> KeyRecord {
        let mut attrs = AttributeSet::new();
        attrs.insert("tenant", AttributeValue::String("test-tenant".into()));
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        let lid = Lid::derive(CanonicalizationVersion::V1, &form);
        KeyRecord {
            lid,
            canonicalization_version: CanonicalizationVersion::V1,
            parent_lid: None,
            occ_version: 1,
            current_key_version: 1,
            state,
            key_usage: KeyUsage::EncryptDecrypt,
            key_spec: KeySpec::Aes256,
            origin: KeyOrigin::KeyRack,
            provider_class: ProviderClass::Software,
            provider_ref: None,
            exportability: crate::key::Exportability::default(),
            first_exported_at: None,
            identity_tags: IdentityTags::from_attribute_set(&attrs),
            user_tags: UserTags::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            scheduled_deletion_at: None,
            description: String::new(),
            key_versions: vec![KeyVersionRecord {
                version_number: 1,
                key_handle: KeyHandle {
                    key_id: "test".into(),
                    key_spec: KeySpec::Aes256,
                },
                provider_ref: None,
                created_at: chrono::Utc::now(),
                is_primary: true,
            }],
        }
    }

    /// In-memory storage for unit tests.
    struct MemoryStorage {
        keys: Mutex<HashMap<String, KeyRecord>>,
        aliases: Mutex<HashMap<String, AliasRecord>>,
        hsm_conns: Mutex<HashMap<String, HsmConnection>>,
        rotation_jobs: Mutex<HashMap<String, RotationJob>>,
    }

    impl MemoryStorage {
        fn new() -> Self {
            Self {
                keys: Mutex::new(HashMap::new()),
                aliases: Mutex::new(HashMap::new()),
                hsm_conns: Mutex::new(HashMap::new()),
                rotation_jobs: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl StorageBackend for MemoryStorage {
        async fn create_key(&self, record: &KeyRecord) -> Result<()> {
            let mut keys = self.keys.lock().unwrap();
            let lid_str = record.lid.to_string();
            if keys.contains_key(&lid_str) {
                return Err(KeyRackError::Other("key already exists".into()));
            }
            keys.insert(lid_str, record.clone());
            Ok(())
        }

        async fn get_key(&self, lid: &Lid) -> Result<KeyRecord> {
            let keys = self.keys.lock().unwrap();
            keys.get(&lid.to_string())
                .cloned()
                .ok_or(KeyRackError::KeyNotFound(*lid))
        }

        async fn update_key(&self, record: &KeyRecord) -> Result<()> {
            let mut keys = self.keys.lock().unwrap();
            let lid_str = record.lid.to_string();
            match keys.get(&lid_str) {
                Some(existing) if existing.occ_version + 1 == record.occ_version => {
                    keys.insert(lid_str, record.clone());
                    Ok(())
                }
                Some(existing) => Err(KeyRackError::OptimisticConcurrencyConflict {
                    lid: record.lid,
                    expected: record.occ_version - 1,
                    actual: existing.occ_version,
                }),
                None => Err(KeyRackError::KeyNotFound(record.lid)),
            }
        }

        async fn list_keys(&self, filter: &KeyFilter) -> Result<Page<KeyRecord>> {
            let keys = self.keys.lock().unwrap();
            let mut items: Vec<_> = keys.values().cloned().collect();
            if let Some(state) = filter.state {
                items.retain(|r| r.state == state);
            }
            for (k, v) in &filter.user_tags {
                items.retain(|r| r.user_tags.get(k) == Some(v.as_str()));
            }
            let limit = filter.limit.unwrap_or(100) as usize;
            items.truncate(limit);
            Ok(Page {
                items,
                next_cursor: None,
            })
        }

        async fn list_children(&self, parent: &Lid) -> Result<Vec<KeyRecord>> {
            let keys = self.keys.lock().unwrap();
            Ok(keys
                .values()
                .filter(|r| r.parent_lid.as_ref() == Some(parent))
                .cloned()
                .collect())
        }

        async fn create_alias(&self, alias: &AliasRecord) -> Result<()> {
            let mut aliases = self.aliases.lock().unwrap();
            if aliases.contains_key(&alias.alias_name) {
                return Err(KeyRackError::Other("alias already exists".into()));
            }
            aliases.insert(alias.alias_name.clone(), alias.clone());
            Ok(())
        }

        async fn resolve_alias(&self, alias_name: &str) -> Result<Lid> {
            let aliases = self.aliases.lock().unwrap();
            aliases
                .get(alias_name)
                .map(|a| a.target_lid)
                .ok_or_else(|| KeyRackError::Other(format!("alias not found: {alias_name}")))
        }

        async fn delete_alias(&self, alias_name: &str) -> Result<()> {
            let mut aliases = self.aliases.lock().unwrap();
            aliases.remove(alias_name);
            Ok(())
        }

        async fn list_aliases(&self) -> Result<Vec<AliasRecord>> {
            let aliases = self.aliases.lock().unwrap();
            Ok(aliases.values().cloned().collect())
        }

        async fn create_hsm_connection(&self, conn: &HsmConnection) -> Result<()> {
            let mut conns = self.hsm_conns.lock().unwrap();
            conns.insert(conn.connection_id.clone(), conn.clone());
            Ok(())
        }

        async fn get_hsm_connection(&self, connection_id: &str) -> Result<HsmConnection> {
            let conns = self.hsm_conns.lock().unwrap();
            conns.get(connection_id).cloned().ok_or_else(|| {
                KeyRackError::Other(format!("hsm connection not found: {connection_id}"))
            })
        }

        async fn update_hsm_connection(&self, conn: &HsmConnection) -> Result<()> {
            let mut conns = self.hsm_conns.lock().unwrap();
            conns.insert(conn.connection_id.clone(), conn.clone());
            Ok(())
        }

        async fn list_hsm_connections(&self) -> Result<Vec<HsmConnection>> {
            let conns = self.hsm_conns.lock().unwrap();
            Ok(conns.values().cloned().collect())
        }

        async fn delete_hsm_connection(&self, connection_id: &str) -> Result<()> {
            let mut conns = self.hsm_conns.lock().unwrap();
            conns.remove(connection_id);
            Ok(())
        }

        async fn create_rotation_job(&self, job: &RotationJob) -> Result<()> {
            let mut jobs = self.rotation_jobs.lock().unwrap();
            jobs.insert(job.job_id.clone(), job.clone());
            Ok(())
        }

        async fn get_rotation_job(&self, job_id: &str) -> Result<RotationJob> {
            let jobs = self.rotation_jobs.lock().unwrap();
            jobs.get(job_id)
                .cloned()
                .ok_or_else(|| KeyRackError::Other(format!("rotation job not found: {job_id}")))
        }

        async fn update_rotation_job(&self, job: &RotationJob) -> Result<()> {
            let mut jobs = self.rotation_jobs.lock().unwrap();
            jobs.insert(job.job_id.clone(), job.clone());
            Ok(())
        }

        async fn list_rotation_jobs(
            &self,
            state_filter: Option<RotationJobState>,
        ) -> Result<Vec<RotationJob>> {
            let jobs = self.rotation_jobs.lock().unwrap();
            let items: Vec<_> = jobs
                .values()
                .filter(|j| state_filter.map_or(true, |s| j.state == s))
                .cloned()
                .collect();
            Ok(items)
        }

        async fn ping(&self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn key_crud_with_occ() {
        let store = MemoryStorage::new();

        let record = make_test_record(KeyState::Creating);
        store.create_key(&record).await.unwrap();

        let fetched = store.get_key(&record.lid).await.unwrap();
        assert_eq!(fetched.state, KeyState::Creating);

        let mut updated = fetched.clone();
        updated.state = KeyState::Enabled;
        updated.occ_version += 1;
        store.update_key(&updated).await.unwrap();

        let stale = fetched; // old version
        let mut stale_update = stale.clone();
        stale_update.occ_version += 1;
        let err = store.update_key(&stale_update).await;
        assert!(matches!(
            err,
            Err(KeyRackError::OptimisticConcurrencyConflict { .. })
        ));
    }

    #[tokio::test]
    async fn alias_lifecycle() {
        let store = MemoryStorage::new();

        let record = make_test_record(KeyState::Enabled);
        store.create_key(&record).await.unwrap();

        let alias = AliasRecord {
            alias_name: "alias/prod/root".into(),
            target_lid: record.lid,
            created_at: chrono::Utc::now(),
        };
        store.create_alias(&alias).await.unwrap();

        let resolved = store.resolve_alias("alias/prod/root").await.unwrap();
        assert_eq!(resolved, record.lid);

        store.delete_alias("alias/prod/root").await.unwrap();
        assert!(store.resolve_alias("alias/prod/root").await.is_err());
    }

    #[tokio::test]
    async fn hsm_connection_lifecycle() {
        let store = MemoryStorage::new();

        let conn = HsmConnection::new(
            "conn-test",
            HsmProviderType::Hyok,
            "kmip://localhost:5696",
            "test HYOK",
        );
        store.create_hsm_connection(&conn).await.unwrap();

        let fetched = store.get_hsm_connection("conn-test").await.unwrap();
        assert_eq!(fetched.status, HsmConnectionStatus::Healthy);

        let mut updated = fetched;
        updated.update_status(HsmConnectionStatus::Degraded);
        store.update_hsm_connection(&updated).await.unwrap();

        let conns = store.list_hsm_connections().await.unwrap();
        assert_eq!(conns.len(), 1);

        store.delete_hsm_connection("conn-test").await.unwrap();
        assert!(store.list_hsm_connections().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rotation_job_lifecycle() {
        use crate::attr::{AttributeSet, AttributeValue};
        use crate::canon::{canonicalize, CanonicalizationVersion};

        let store = MemoryStorage::new();

        let mut attrs = AttributeSet::new();
        attrs.insert("name", AttributeValue::String("parent".into()));
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        let parent_lid = Lid::derive(CanonicalizationVersion::V1, &form);

        let mut attrs2 = AttributeSet::new();
        attrs2.insert("name", AttributeValue::String("child".into()));
        let form2 = canonicalize(CanonicalizationVersion::V1, &attrs2);
        let child_lid = Lid::derive(CanonicalizationVersion::V1, &form2);

        let job = RotationJob::new("job-1", parent_lid, child_lid, 2);
        store.create_rotation_job(&job).await.unwrap();

        let pending = store
            .list_rotation_jobs(Some(RotationJobState::Pending))
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);

        let mut j = store.get_rotation_job("job-1").await.unwrap();
        j.transition_to(RotationJobState::Acknowledged).unwrap();
        store.update_rotation_job(&j).await.unwrap();

        let pending_after = store
            .list_rotation_jobs(Some(RotationJobState::Pending))
            .await
            .unwrap();
        assert!(pending_after.is_empty());
    }

    #[tokio::test]
    async fn ping_succeeds() {
        let store = MemoryStorage::new();
        store.ping().await.unwrap();
    }
}
