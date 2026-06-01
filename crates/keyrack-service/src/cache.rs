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
/// For HYOK deployments, the cache TTL functions as a security property:
/// after a tenant disconnects their HSM, cached key records will expire
/// within at most one TTL window, providing a bounded lockout guarantee.
pub struct CachingStorage {
    inner: Arc<dyn StorageBackend>,
    key_cache: Cache<Lid, KeyRecord>,
}

impl CachingStorage {
    /// Create a new caching storage wrapper.
    ///
    /// - `max_capacity`: Maximum number of key records to cache.
    /// - `ttl`: Time-to-live for cached entries. Also serves as the
    ///   upper bound on time-to-lockout for HYOK disconnect scenarios.
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
    pub async fn invalidate_all(&self) {
        self.key_cache.invalidate_all();
    }

    /// Number of entries currently in the cache.
    pub fn entry_count(&self) -> u64 {
        self.key_cache.entry_count()
    }
}

#[async_trait::async_trait]
impl StorageBackend for CachingStorage {
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
