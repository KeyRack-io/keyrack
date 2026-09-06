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

//! `PostgreSQL` storage backend for `KeyRack` multi-node deployments.
//!
//! Uses `sqlx` with the `postgres` feature for async database access.
//! Records are stored as JSONB. Creation identities, parent dependencies and
//! recovery cursors have separate scalar indexes.
//!
//! Optimistic concurrency is enforced via `WHERE occ_version = $expected`
//! on key metadata updates. Creation journal transitions additionally validate
//! owner/revision fencing. Key/journal writes and schema initialization share a
//! transaction advisory lock in this first correctness-focused profile; this
//! serialization is not a cloud-scale write-throughput claim.

#![forbid(unsafe_code)]

mod creation;

use async_trait::async_trait;
use keyrack_core::creation::{
    CreationJournal, CreationOwner, CreationPage, CreationRequest, VerifiedA2Closure,
};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::hsm::HsmConnection;
use keyrack_core::key::KeyRecord;
use keyrack_core::lid::Lid;
use keyrack_core::rotation::{RotationJob, RotationJobState};
use keyrack_core::storage::{AliasRecord, KeyFilter, Page, StorageBackend};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool, Row};
use uuid::Uuid;

const CREATE_TABLES: &str = "
CREATE TABLE IF NOT EXISTS kr_keys (
    lid          TEXT PRIMARY KEY,
    record_json  JSONB NOT NULL,
    occ_version  BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS kr_aliases (
    alias_name   TEXT PRIMARY KEY,
    target_lid   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS kr_hsm_connections (
    connection_id TEXT PRIMARY KEY,
    record_json   JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS kr_rotation_jobs (
    job_id       TEXT PRIMARY KEY,
    record_json  JSONB NOT NULL,
    state        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kr_rotation_jobs_state ON kr_rotation_jobs(state);
CREATE TABLE IF NOT EXISTS kr_creation_journal (
    operation_id   TEXT COLLATE \"C\" PRIMARY KEY,
    child_lid      TEXT NOT NULL,
    child_version  TEXT NOT NULL,
    parent_lid     TEXT NOT NULL,
    parent_version TEXT NOT NULL,
    envelope_ref   TEXT NOT NULL UNIQUE,
    phase          TEXT NOT NULL CHECK (phase IN ('reserved', 'staged', 'resolved', 'committed')),
    journal_json   JSONB NOT NULL,
    envelope       BYTEA CHECK (envelope IS NULL OR octet_length(envelope) BETWEEN 1 AND 65536),
    UNIQUE (child_lid, child_version)
);
CREATE INDEX IF NOT EXISTS idx_kr_creation_parent
    ON kr_creation_journal(parent_lid, parent_version);
CREATE INDEX IF NOT EXISTS idx_kr_creation_recovery
    ON kr_creation_journal(phase, operation_id);
CREATE INDEX IF NOT EXISTS idx_kr_creation_pending_operation
    ON kr_creation_journal(operation_id) WHERE phase != 'committed';
";

/// `PostgreSQL`-backed storage.
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    /// Connect to `PostgreSQL` using a connection URL and run migrations.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|e| KeyRackError::Storage(format!("connect: {e}")))?;

        initialize_schema(&pool).await?;

        tracing::info!("PostgreSQL storage initialized");
        Ok(Self { pool })
    }

    /// Create from an existing pool (useful for testing).
    pub async fn from_pool(pool: PgPool) -> Result<Self> {
        initialize_schema(&pool).await?;
        Ok(Self { pool })
    }
}

async fn initialize_schema(pool: &PgPool) -> Result<()> {
    // IF NOT EXISTS does not serialize concurrent catalog/type creation. The
    // same lock also coordinates migrations with key/journal writes from peers.
    let mut transaction = creation::write_transaction(pool).await?;
    // Multiple DDL statements require the unprepared simple-query path.
    (&mut *transaction)
        .execute(CREATE_TABLES)
        .await
        .map_err(|e| KeyRackError::Storage(format!("schema: {e}")))?;
    transaction
        .commit()
        .await
        .map_err(|e| KeyRackError::Storage(format!("schema commit: {e}")))
}

fn state_str(state: RotationJobState) -> Result<String> {
    Ok(serde_json::to_value(state)
        .map_err(|e| KeyRackError::Storage(format!("serialize state: {e}")))?
        .as_str()
        .unwrap_or("unknown")
        .to_owned())
}

#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
#[async_trait]
impl StorageBackend for PostgresStorage {
    async fn reserve_creation(&self, request: &CreationRequest) -> Result<CreationJournal> {
        self.creation_reserve(request).await
    }

    async fn get_creation(&self, operation: Uuid) -> Result<CreationJournal> {
        self.creation_get(operation).await
    }

    async fn stage_creation(
        &self,
        operation: Uuid,
        owner: CreationOwner,
        revision: u64,
        envelope: &[u8],
    ) -> Result<CreationJournal> {
        self.creation_stage(operation, owner, revision, envelope)
            .await
    }

    async fn resolve_creation(
        &self,
        operation: Uuid,
        owner: CreationOwner,
        revision: u64,
        closure: &VerifiedA2Closure,
    ) -> Result<CreationJournal> {
        self.creation_resolve(operation, owner, revision, closure)
            .await
    }

    async fn publish_creation(
        &self,
        operation: Uuid,
        owner: CreationOwner,
        revision: u64,
    ) -> Result<KeyRecord> {
        self.creation_publish(operation, owner, revision).await
    }

    async fn read_creation_envelope(&self, operation: Uuid) -> Result<Vec<u8>> {
        self.creation_read_envelope(operation).await
    }

    async fn recoverable_creations(&self, after: Option<Uuid>, limit: u32) -> Result<CreationPage> {
        self.creation_recoverable(after, limit).await
    }

    async fn create_key(&self, record: &KeyRecord) -> Result<()> {
        self.create_key_guarded(record).await
    }

    async fn get_key(&self, lid: &Lid) -> Result<KeyRecord> {
        let lid_str = lid.to_string();
        let row = sqlx::query("SELECT record_json FROM kr_keys WHERE lid = $1")
            .bind(&lid_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("get_key: {e}")))?
            .ok_or(KeyRackError::KeyNotFound(*lid))?;

        let json: serde_json::Value = row
            .try_get("record_json")
            .map_err(|e| KeyRackError::Storage(format!("column: {e}")))?;
        serde_json::from_value(json).map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))
    }

    async fn update_key(&self, record: &KeyRecord) -> Result<()> {
        self.update_key_guarded(record).await
    }

    async fn list_keys(&self, filter: &KeyFilter) -> Result<Page<KeyRecord>> {
        let limit = i64::from(filter.limit.unwrap_or(100));
        let rows = sqlx::query("SELECT record_json FROM kr_keys LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("list_keys: {e}")))?;

        let mut items = Vec::new();
        for row in &rows {
            let json: serde_json::Value = row
                .try_get("record_json")
                .map_err(|e| KeyRackError::Storage(format!("column: {e}")))?;
            let record: KeyRecord = serde_json::from_value(json)
                .map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))?;
            if filter.state.is_some_and(|s| s != record.state) {
                continue;
            }
            let owner_ok = filter.owner_principal_id.is_none()
                || record.owner_principal_id.is_none()
                || record.owner_principal_id.as_deref() == filter.owner_principal_id.as_deref();
            if owner_ok
                && filter
                    .user_tags
                    .iter()
                    .all(|(k, v)| record.user_tags.get(k).is_some_and(|tv| tv == v))
            {
                items.push(record);
            }
        }
        Ok(Page {
            items,
            next_cursor: None,
        })
    }

    async fn list_children(&self, parent: &Lid) -> Result<Vec<KeyRecord>> {
        let rows = sqlx::query("SELECT record_json FROM kr_keys")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("list_children: {e}")))?;

        let parent_str = parent.to_string();
        let mut children = Vec::new();
        for row in &rows {
            let json: serde_json::Value = row
                .try_get("record_json")
                .map_err(|e| KeyRackError::Storage(format!("column: {e}")))?;
            let record: KeyRecord = serde_json::from_value(json)
                .map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))?;
            if record
                .parent_lid
                .as_ref()
                .is_some_and(|p| p.to_string() == parent_str)
            {
                children.push(record);
            }
        }
        Ok(children)
    }

    async fn create_alias(&self, alias: &AliasRecord) -> Result<()> {
        let lid_str = alias.target_lid.to_string();
        sqlx::query(
            "INSERT INTO kr_aliases (alias_name, target_lid, created_at) VALUES ($1, $2, $3)",
        )
        .bind(&alias.alias_name)
        .bind(&lid_str)
        .bind(alias.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                KeyRackError::Other("alias already exists".into())
            } else {
                KeyRackError::Storage(format!("create_alias: {e}"))
            }
        })?;
        Ok(())
    }

    async fn resolve_alias(&self, alias_name: &str) -> Result<Lid> {
        let row = sqlx::query("SELECT target_lid FROM kr_aliases WHERE alias_name = $1")
            .bind(alias_name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("resolve_alias: {e}")))?
            .ok_or_else(|| KeyRackError::Other(format!("alias not found: {alias_name}")))?;

        let lid_str: String = row
            .try_get("target_lid")
            .map_err(|e| KeyRackError::Storage(format!("column: {e}")))?;
        lid_str
            .parse::<Lid>()
            .map_err(|e| KeyRackError::Storage(format!("parse lid: {e}")))
    }

    async fn delete_alias(&self, alias_name: &str) -> Result<()> {
        sqlx::query("DELETE FROM kr_aliases WHERE alias_name = $1")
            .bind(alias_name)
            .execute(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("delete_alias: {e}")))?;
        Ok(())
    }

    async fn list_aliases(&self) -> Result<Vec<AliasRecord>> {
        let rows = sqlx::query("SELECT alias_name, target_lid, created_at FROM kr_aliases")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("list_aliases: {e}")))?;

        let mut items = Vec::new();
        for row in &rows {
            let name: String = row
                .try_get("alias_name")
                .map_err(|e| KeyRackError::Storage(format!("column: {e}")))?;
            let lid_str: String = row
                .try_get("target_lid")
                .map_err(|e| KeyRackError::Storage(format!("column: {e}")))?;
            let created_at: chrono::DateTime<chrono::Utc> = row
                .try_get("created_at")
                .map_err(|e| KeyRackError::Storage(format!("column: {e}")))?;
            let lid = lid_str
                .parse::<Lid>()
                .map_err(|e| KeyRackError::Storage(format!("parse lid: {e}")))?;
            items.push(AliasRecord {
                alias_name: name,
                target_lid: lid,
                created_at,
            });
        }
        Ok(items)
    }

    async fn create_hsm_connection(&self, conn_rec: &HsmConnection) -> Result<()> {
        let json = serde_json::to_value(conn_rec)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        sqlx::query(
            "INSERT INTO kr_hsm_connections (connection_id, record_json) VALUES ($1, $2) \
             ON CONFLICT (connection_id) DO UPDATE SET record_json = EXCLUDED.record_json",
        )
        .bind(&conn_rec.connection_id)
        .bind(&json)
        .execute(&self.pool)
        .await
        .map_err(|e| KeyRackError::Storage(format!("create_hsm: {e}")))?;
        Ok(())
    }

    async fn get_hsm_connection(&self, connection_id: &str) -> Result<HsmConnection> {
        let row =
            sqlx::query("SELECT record_json FROM kr_hsm_connections WHERE connection_id = $1")
                .bind(connection_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| KeyRackError::Storage(format!("get_hsm: {e}")))?
                .ok_or_else(|| {
                    KeyRackError::Other(format!("hsm connection not found: {connection_id}"))
                })?;

        let json: serde_json::Value = row
            .try_get("record_json")
            .map_err(|e| KeyRackError::Storage(format!("column: {e}")))?;
        serde_json::from_value(json).map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))
    }

    async fn update_hsm_connection(&self, conn_rec: &HsmConnection) -> Result<()> {
        let json = serde_json::to_value(conn_rec)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        sqlx::query("UPDATE kr_hsm_connections SET record_json = $1 WHERE connection_id = $2")
            .bind(&json)
            .bind(&conn_rec.connection_id)
            .execute(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("update_hsm: {e}")))?;
        Ok(())
    }

    async fn list_hsm_connections(&self) -> Result<Vec<HsmConnection>> {
        let rows = sqlx::query("SELECT record_json FROM kr_hsm_connections")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("list_hsm: {e}")))?;

        let mut items = Vec::new();
        for row in &rows {
            let json: serde_json::Value = row
                .try_get("record_json")
                .map_err(|e| KeyRackError::Storage(format!("column: {e}")))?;
            let rec: HsmConnection = serde_json::from_value(json)
                .map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))?;
            items.push(rec);
        }
        Ok(items)
    }

    async fn delete_hsm_connection(&self, connection_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM kr_hsm_connections WHERE connection_id = $1")
            .bind(connection_id)
            .execute(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("delete_hsm: {e}")))?;
        Ok(())
    }

    async fn create_rotation_job(&self, job: &RotationJob) -> Result<()> {
        let json = serde_json::to_value(job)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        let s = state_str(job.state)?;
        sqlx::query(
            "INSERT INTO kr_rotation_jobs (job_id, record_json, state) VALUES ($1, $2, $3) \
             ON CONFLICT (job_id) DO UPDATE SET record_json = EXCLUDED.record_json, state = EXCLUDED.state",
        )
        .bind(&job.job_id)
        .bind(&json)
        .bind(&s)
        .execute(&self.pool)
        .await
        .map_err(|e| KeyRackError::Storage(format!("create_job: {e}")))?;
        Ok(())
    }

    async fn get_rotation_job(&self, job_id: &str) -> Result<RotationJob> {
        let row = sqlx::query("SELECT record_json FROM kr_rotation_jobs WHERE job_id = $1")
            .bind(job_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("get_job: {e}")))?
            .ok_or_else(|| KeyRackError::Other(format!("rotation job not found: {job_id}")))?;

        let json: serde_json::Value = row
            .try_get("record_json")
            .map_err(|e| KeyRackError::Storage(format!("column: {e}")))?;
        serde_json::from_value(json).map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))
    }

    async fn update_rotation_job(&self, job: &RotationJob) -> Result<()> {
        let json = serde_json::to_value(job)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        let s = state_str(job.state)?;
        sqlx::query("UPDATE kr_rotation_jobs SET record_json = $1, state = $2 WHERE job_id = $3")
            .bind(&json)
            .bind(&s)
            .bind(&job.job_id)
            .execute(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("update_job: {e}")))?;
        Ok(())
    }

    async fn list_rotation_jobs(
        &self,
        state_filter: Option<RotationJobState>,
    ) -> Result<Vec<RotationJob>> {
        let rows = match state_filter {
            Some(state) => {
                let s = state_str(state)?;
                sqlx::query("SELECT record_json FROM kr_rotation_jobs WHERE state = $1")
                    .bind(&s)
                    .fetch_all(&self.pool)
                    .await
            }
            None => {
                sqlx::query("SELECT record_json FROM kr_rotation_jobs")
                    .fetch_all(&self.pool)
                    .await
            }
        }
        .map_err(|e| KeyRackError::Storage(format!("list_jobs: {e}")))?;

        let mut items = Vec::new();
        for row in &rows {
            let json: serde_json::Value = row
                .try_get("record_json")
                .map_err(|e| KeyRackError::Storage(format!("column: {e}")))?;
            let rec: RotationJob = serde_json::from_value(json)
                .map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))?;
            items.push(rec);
        }
        Ok(items)
    }

    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| KeyRackError::Storage(format!("ping: {e}")))?;
        Ok(())
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(ref db_err) = e {
        db_err.code().as_deref() == Some("23505")
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn compiles() {
        // The conformance tests require a live PostgreSQL instance.
        // Run via docker-compose: docker compose run e2e
    }
}
