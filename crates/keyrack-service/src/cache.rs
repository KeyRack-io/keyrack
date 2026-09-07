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

//! Caching layer for `StorageBackend`.
//!
//! Wraps any storage backend with a moka-based async cache for `get_key`
//! operations. The cache is automatically invalidated on mutations
//! (`create_key`, `update_key`) and can be externally invalidated via
//! NATS events for multi-replica deployments.

use keyrack_core::error::Result;
use keyrack_core::hsm::HsmConnection;
use keyrack_core::key::KeyRecord;
use keyrack_core::lid::Lid;
use keyrack_core::rotation::RotationJob;
use keyrack_core::storage::{AliasRecord, KeyFilter, Page, StorageBackend};
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

/// A caching wrapper around any `StorageBackend`.
///
/// Caches `get_key` results by LID with a configurable TTL and max capacity.
/// Writes always go through to the underlying backend and evict the cache entry.
///
/// Metadata TTL is not a crypto-worker lease or a revocation guarantee. Durable
/// destruction claims bypass this cache; storage fences remain authoritative
/// even if another replica or an in-flight read retains an older record.
pub struct CachingStorage {
    inner: Arc<dyn StorageBackend>,
    key_cache: Cache<Lid, KeyRecord>,
}

impl CachingStorage {
    /// Create a new caching storage wrapper.
    ///
    /// - `max_capacity`: Maximum number of key records to cache.
    /// - `ttl`: Time-to-live for cached metadata entries, not crypto leases.
    pub fn new(inner: Arc<dyn StorageBackend>, max_capacity: u64, ttl: Duration) -> Self {
        let key_cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(ttl)
            .build();
        Self { inner, key_cache }
    }

    /// Explicitly invalidate a key from the cache.
    ///
    /// Used by NATS invalidation subscriber for cross-replica consistency.
    pub async fn invalidate(&self, lid: &Lid) {
        self.key_cache.invalidate(lid).await;
    }

    /// Invalidate all cached entries.
    pub fn invalidate_all(&self) {
        self.key_cache.invalidate_all();
    }

    /// Number of entries currently in the cache.
    pub fn entry_count(&self) -> u64 {
        self.key_cache.entry_count()
    }
}

#[async_trait::async_trait]
impl StorageBackend for CachingStorage {
    async fn claim_destruction(
        &self,
        lid: &Lid,
        expected_occ: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<keyrack_core::destruction::DestructionClaim>> {
        self.invalidate(lid).await;
        let result = self.inner.claim_destruction(lid, expected_occ, now).await;
        // Include ambiguous commit errors and already-claimed responses.
        self.invalidate(lid).await;
        result
    }

    async fn complete_destruction(
        &self,
        claim: keyrack_core::destruction::DestructionClaim,
    ) -> Result<KeyRecord> {
        let lid = claim.record().lid;
        self.invalidate(&lid).await;
        let result = self.inner.complete_destruction(claim).await;
        self.invalidate(&lid).await;
        result
    }

    // ── Keys ──────────────────────────────────────────────────────

    async fn create_key(&self, record: &KeyRecord) -> Result<()> {
        self.inner.create_key(record).await?;
        self.key_cache.insert(record.lid, record.clone()).await;
        Ok(())
    }

    async fn get_key(&self, lid: &Lid) -> Result<KeyRecord> {
        if let Some(cached) = self.key_cache.get(lid).await {
            return Ok(cached);
        }
        let record = self.inner.get_key(lid).await?;
        self.key_cache.insert(*lid, record.clone()).await;
        Ok(record)
    }

    async fn update_key(&self, record: &KeyRecord) -> Result<()> {
        self.inner.update_key(record).await?;
        self.key_cache.insert(record.lid, record.clone()).await;
        Ok(())
    }

    async fn list_keys(&self, filter: &KeyFilter) -> Result<Page<KeyRecord>> {
        self.inner.list_keys(filter).await
    }

    async fn list_children(&self, parent: &Lid) -> Result<Vec<KeyRecord>> {
        self.inner.list_children(parent).await
    }

    // ── Aliases ───────────────────────────────────────────────────

    async fn create_alias(&self, alias: &AliasRecord) -> Result<()> {
        self.inner.create_alias(alias).await
    }

    async fn resolve_alias(&self, alias_name: &str) -> Result<Lid> {
        self.inner.resolve_alias(alias_name).await
    }

    async fn delete_alias(&self, alias_name: &str) -> Result<()> {
        self.inner.delete_alias(alias_name).await
    }

    async fn list_aliases(&self) -> Result<Vec<AliasRecord>> {
        self.inner.list_aliases().await
    }

    // ── HSM connections ──────────────────────────────────────────

    async fn create_hsm_connection(&self, conn: &HsmConnection) -> Result<()> {
        self.inner.create_hsm_connection(conn).await
    }

    async fn get_hsm_connection(&self, connection_id: &str) -> Result<HsmConnection> {
        self.inner.get_hsm_connection(connection_id).await
    }

    async fn update_hsm_connection(&self, conn: &HsmConnection) -> Result<()> {
        self.inner.update_hsm_connection(conn).await
    }

    async fn list_hsm_connections(&self) -> Result<Vec<HsmConnection>> {
        self.inner.list_hsm_connections().await
    }

    async fn delete_hsm_connection(&self, connection_id: &str) -> Result<()> {
        self.inner.delete_hsm_connection(connection_id).await
    }

    // ── Rotation jobs ────────────────────────────────────────────

    async fn create_rotation_job(&self, job: &RotationJob) -> Result<()> {
        self.inner.create_rotation_job(job).await
    }

    async fn get_rotation_job(&self, job_id: &str) -> Result<RotationJob> {
        self.inner.get_rotation_job(job_id).await
    }

    async fn update_rotation_job(&self, job: &RotationJob) -> Result<()> {
        self.inner.update_rotation_job(job).await
    }

    async fn list_rotation_jobs(
        &self,
        state_filter: Option<keyrack_core::rotation::RotationJobState>,
    ) -> Result<Vec<RotationJob>> {
        self.inner.list_rotation_jobs(state_filter).await
    }

    // ── Health ───────────────────────────────────────────────────

    async fn ping(&self) -> Result<()> {
        self.inner.ping().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyrack_core::key::KeyState;
    use keyrack_test_support::destruction_conformance::due;
    use keyrack_test_support::fixtures::unique_test_key_record;

    #[tokio::test]
    async fn destruction_uses_inner_state_and_evicts_on_error_claim_and_completion() {
        let inner = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap());
        let cache = CachingStorage::new(inner.clone(), 100, Duration::from_secs(3600));
        let record = unique_test_key_record(KeyState::Enabled);
        cache.create_key(&record).await.unwrap();
        assert_eq!(
            cache.get_key(&record.lid).await.unwrap().state,
            KeyState::Enabled
        );
        let mut pending = due(record.clone());
        pending.occ_version += 1;
        inner.update_key(&pending).await.unwrap();
        // The cache deliberately holds Enabled. It cannot authorize a claim.
        assert!(cache
            .claim_destruction(&record.lid, record.occ_version, chrono::Utc::now())
            .await
            .is_err());
        assert_eq!(
            cache.get_key(&record.lid).await.unwrap().state,
            KeyState::PendingDeletion
        );
        let claim = cache
            .claim_destruction(&record.lid, pending.occ_version, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            cache.get_key(&record.lid).await.unwrap().occ_version,
            claim.record().occ_version
        );
        let mut cancelled = cache.get_key(&record.lid).await.unwrap();
        cancelled.transition_to(KeyState::Disabled).unwrap();
        assert!(cache.update_key(&cancelled).await.is_err());
        cache.complete_destruction(claim).await.unwrap();
        assert_eq!(
            cache.get_key(&record.lid).await.unwrap().state,
            KeyState::Destroyed
        );
        assert!(cache
            .claim_destruction(&record.lid, pending.occ_version, chrono::Utc::now())
            .await
            .unwrap()
            .is_none());
    }
}
