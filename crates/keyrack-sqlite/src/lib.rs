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

//! `SQLite` storage backend for single-node `KeyRack` deployments.
//!
//! Uses `rusqlite` with the `bundled` feature (zero system dependencies).
//! `rusqlite` is synchronous; operations acquire a `Mutex`-guarded
//! connection. For high-concurrency deployments, use `PostgreSQL`.

#![forbid(unsafe_code)]

mod creation;
mod destruction;

use async_trait::async_trait;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::hsm::HsmConnection;
use keyrack_core::key::KeyRecord;
use keyrack_core::lid::Lid;
use keyrack_core::rotation::{RotationJob, RotationJobState};
use keyrack_core::storage::{AliasRecord, KeyFilter, Page, StorageBackend};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS keys (
    lid          TEXT PRIMARY KEY,
    record_json  TEXT NOT NULL,
    occ_version  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS aliases (
    alias_name   TEXT PRIMARY KEY,
    target_lid   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hsm_connections (
    connection_id TEXT PRIMARY KEY,
    record_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rotation_jobs (
    job_id       TEXT PRIMARY KEY,
    record_json  TEXT NOT NULL,
    state        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rotation_jobs_state ON rotation_jobs(state);
CREATE TABLE IF NOT EXISTS destruction_journal (
    lid TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    completed INTEGER NOT NULL CHECK(completed IN (0,1))
);
";

/// `SQLite`-backed storage.
pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    /// Open (or create) a database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn =
            Connection::open(path).map_err(|e| KeyRackError::Storage(format!("open: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| KeyRackError::Storage(format!("schema: {e}")))?;
        conn.execute_batch(creation::SCHEMA)
            .map_err(|e| map_sql(&e))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory database (tests / ephemeral use).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| KeyRackError::Storage(format!("open in-memory: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| KeyRackError::Storage(format!("schema: {e}")))?;
        conn.execute_batch(creation::SCHEMA)
            .map_err(|e| map_sql(&e))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn with_conn<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Connection) -> Result<R>,
    {
        let conn = self
            .conn
            .lock()
            .map_err(|e| KeyRackError::Storage(format!("lock poisoned: {e}")))?;
        f(&conn)
    }
}

fn map_sql(e: &rusqlite::Error) -> KeyRackError {
    KeyRackError::Storage(format!("sqlite: {e}"))
}

fn state_to_string(state: RotationJobState) -> Result<String> {
    Ok(serde_json::to_value(state)
        .map_err(|e| KeyRackError::Storage(format!("serialize state: {e}")))?
        .as_str()
        .unwrap_or("unknown")
        .to_owned())
}

#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
#[async_trait]
impl StorageBackend for SqliteStorage {
    async fn claim_destruction(
        &self,
        lid: &Lid,
        expected_occ: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<keyrack_core::destruction::DestructionClaim>> {
        self.destruction_claim(lid, expected_occ, now)
    }

    async fn complete_destruction(
        &self,
        claim: keyrack_core::destruction::DestructionClaim,
    ) -> Result<KeyRecord> {
        self.destruction_complete(claim)
    }

    async fn reserve_creation(
        &self,
        request: &keyrack_core::creation::CreationRequest,
    ) -> Result<keyrack_core::creation::CreationJournal> {
        self.reserve_a2(request)
    }
    async fn get_creation(
        &self,
        operation: uuid::Uuid,
    ) -> Result<keyrack_core::creation::CreationJournal> {
        self.get_a2(operation)
    }
    async fn stage_creation(
        &self,
        operation: uuid::Uuid,
        owner: keyrack_core::creation::CreationOwner,
        revision: u64,
        envelope: &[u8],
    ) -> Result<keyrack_core::creation::CreationJournal> {
        self.stage_a2(operation, owner, revision, envelope)
    }
    async fn resolve_creation(
        &self,
        operation: uuid::Uuid,
        owner: keyrack_core::creation::CreationOwner,
        revision: u64,
        closure: &keyrack_core::creation::VerifiedA2Closure,
    ) -> Result<keyrack_core::creation::CreationJournal> {
        self.resolve_a2(operation, owner, revision, closure)
    }
    async fn publish_creation(
        &self,
        operation: uuid::Uuid,
        owner: keyrack_core::creation::CreationOwner,
        revision: u64,
    ) -> Result<KeyRecord> {
        self.publish_a2(operation, owner, revision)
    }
    async fn read_creation_envelope(&self, operation: uuid::Uuid) -> Result<Vec<u8>> {
        self.read_a2_envelope(operation)
    }
    async fn claim_creation_dispatch(
        &self,
        operation: uuid::Uuid,
        owner: keyrack_core::creation::CreationOwner,
    ) -> Result<keyrack_core::creation::CreationDispatch> {
        self.claim_a2_dispatch(operation, owner)
    }
    async fn creation_snapshot(
        &self,
        operation: uuid::Uuid,
        owner: keyrack_core::creation::CreationOwner,
    ) -> Result<keyrack_core::creation::CreationSnapshot> {
        self.snapshot_a2(operation, owner)
    }
    async fn recoverable_creations(
        &self,
        after: Option<uuid::Uuid>,
        limit: u32,
    ) -> Result<keyrack_core::creation::CreationPage> {
        self.recover_a2(after, limit)
    }

    async fn create_key(&self, record: &KeyRecord) -> Result<()> {
        let lid_str = record.lid.to_string();
        let mut persisted = record.clone();
        persisted.was_compromised = record.has_compromise_history();
        let json = serde_json::to_string(&persisted)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        let occ = i64::try_from(record.occ_version)
            .map_err(|_| keyrack_core::creation::invalid("key OCC out of range"))?;

        self.creation_tx(|conn| {
            creation::guard_create(conn, &record.lid)?;
            destruction::guard_write(conn, record)?;
            conn.execute(
                "INSERT INTO keys (lid, record_json, occ_version) VALUES (?1, ?2, ?3)",
                rusqlite::params![lid_str, json, occ],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(ref err, _)
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    KeyRackError::Other("key already exists".into())
                }
                ref other => map_sql(other),
            })?;
            Ok(())
        })
    }

    async fn get_key(&self, lid: &Lid) -> Result<KeyRecord> {
        let lid_str = lid.to_string();
        self.with_conn(|conn| {
            let json: String = conn
                .query_row(
                    "SELECT record_json FROM keys WHERE lid = ?1",
                    rusqlite::params![lid_str],
                    |row| row.get(0),
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => KeyRackError::KeyNotFound(*lid),
                    ref other => map_sql(other),
                })?;
            serde_json::from_str(&json)
                .map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))
        })
    }

    async fn update_key(&self, record: &KeyRecord) -> Result<()> {
        if record.occ_version == 0 {
            return Err(KeyRackError::Other(
                "occ_version must be > 0 for updates".into(),
            ));
        }
        let lid_str = record.lid.to_string();
        let mut persisted = record.clone();
        persisted.was_compromised = record.has_compromise_history();
        let json = serde_json::to_string(&persisted)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        let new_occ = i64::try_from(record.occ_version)
            .map_err(|_| keyrack_core::creation::invalid("key OCC out of range"))?;
        let expected_occ = new_occ - 1;

        self.creation_tx(|conn| {
            let previous = creation::key(conn, &record.lid)?.ok_or(KeyRackError::KeyNotFound(record.lid))?;
            if previous.occ_version != record.occ_version - 1 {
                return Err(KeyRackError::OptimisticConcurrencyConflict {
                    lid: record.lid, expected: record.occ_version - 1, actual: previous.occ_version,
                });
            }
            if previous.has_compromise_history() && !record.has_compromise_history() {
                return Err(KeyRackError::Other(
                    "cannot clear a key's compromise history".into(),
                ));
            }
            creation::guard_update(conn, &previous, record)?;
            destruction::guard_update(conn, record)?;
            let rows = conn
                .execute(
                    "UPDATE keys SET record_json = ?1, occ_version = ?2 WHERE lid = ?3 AND occ_version = ?4",
                    rusqlite::params![json, new_occ, lid_str, expected_occ],
                )
                .map_err(|e| map_sql(&e))?;

            if rows == 0 {
                let actual: std::result::Result<i64, _> = conn.query_row(
                    "SELECT occ_version FROM keys WHERE lid = ?1",
                    rusqlite::params![lid_str],
                    |row| row.get(0),
                );
                match actual {
                    Ok(v) => Err(KeyRackError::OptimisticConcurrencyConflict {
                        lid: record.lid,
                        expected: record.occ_version - 1,
                        actual: v as u64,
                    }),
                    Err(_) => Err(KeyRackError::KeyNotFound(record.lid)),
                }
            } else {
                Ok(())
            }
        })
    }

    async fn list_keys(&self, filter: &KeyFilter) -> Result<Page<KeyRecord>> {
        self.with_conn(|conn| {
            let limit = i64::from(filter.limit.unwrap_or(100));
            let mut stmt = conn
                .prepare("SELECT record_json FROM keys LIMIT ?1")
                .map_err(|e| map_sql(&e))?;
            let rows = stmt
                .query_map(rusqlite::params![limit], |row| {
                    let json: String = row.get(0)?;
                    Ok(json)
                })
                .map_err(|e| map_sql(&e))?;

            let mut items = Vec::new();
            for row in rows {
                let json = row.map_err(|e| map_sql(&e))?;
                let record: KeyRecord = serde_json::from_str(&json)
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
        })
    }

    async fn list_children(&self, parent: &Lid) -> Result<Vec<KeyRecord>> {
        let parent_str = parent.to_string();
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT record_json FROM keys")
                .map_err(|e| map_sql(&e))?;
            let rows = stmt
                .query_map([], |row| {
                    let json: String = row.get(0)?;
                    Ok(json)
                })
                .map_err(|e| map_sql(&e))?;

            let mut children = Vec::new();
            for row in rows {
                let json = row.map_err(|e| map_sql(&e))?;
                let record: KeyRecord = serde_json::from_str(&json)
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
        })
    }

    async fn create_alias(&self, alias: &AliasRecord) -> Result<()> {
        let created = alias.created_at.to_rfc3339();
        let lid_str = alias.target_lid.to_string();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO aliases (alias_name, target_lid, created_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![alias.alias_name, lid_str, created],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(ref err, _)
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    KeyRackError::Other("alias already exists".into())
                }
                ref other => map_sql(other),
            })?;
            Ok(())
        })
    }

    async fn resolve_alias(&self, alias_name: &str) -> Result<Lid> {
        let name = alias_name.to_owned();
        self.with_conn(|conn| {
            let lid_str: String = conn
                .query_row(
                    "SELECT target_lid FROM aliases WHERE alias_name = ?1",
                    rusqlite::params![name],
                    |row| row.get(0),
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => {
                        KeyRackError::Other(format!("alias not found: {name}"))
                    }
                    ref other => map_sql(other),
                })?;
            lid_str
                .parse::<Lid>()
                .map_err(|e| KeyRackError::Storage(format!("parse lid: {e}")))
        })
    }

    async fn delete_alias(&self, alias_name: &str) -> Result<()> {
        let name = alias_name.to_owned();
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM aliases WHERE alias_name = ?1",
                rusqlite::params![name],
            )
            .map_err(|e| map_sql(&e))?;
            Ok(())
        })
    }

    async fn list_aliases(&self) -> Result<Vec<AliasRecord>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT alias_name, target_lid, created_at FROM aliases")
                .map_err(|e| map_sql(&e))?;
            let rows = stmt
                .query_map([], |row| {
                    let name: String = row.get(0)?;
                    let lid_str: String = row.get(1)?;
                    let created_str: String = row.get(2)?;
                    Ok((name, lid_str, created_str))
                })
                .map_err(|e| map_sql(&e))?;

            let mut items = Vec::new();
            for row in rows {
                let (name, lid_str, created_str) = row.map_err(|e| map_sql(&e))?;
                let lid = lid_str
                    .parse::<Lid>()
                    .map_err(|e| KeyRackError::Storage(format!("parse lid: {e}")))?;
                let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
                    .map(|dt: chrono::DateTime<chrono::FixedOffset>| dt.with_timezone(&chrono::Utc))
                    .map_err(|e| KeyRackError::Storage(format!("parse date: {e}")))?;
                items.push(AliasRecord {
                    alias_name: name,
                    target_lid: lid,
                    created_at,
                });
            }
            Ok(items)
        })
    }

    async fn create_hsm_connection(&self, conn_rec: &HsmConnection) -> Result<()> {
        let json = serde_json::to_string(conn_rec)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO hsm_connections (connection_id, record_json) VALUES (?1, ?2)",
                rusqlite::params![conn_rec.connection_id, json],
            )
            .map_err(|e| map_sql(&e))?;
            Ok(())
        })
    }

    async fn get_hsm_connection(&self, connection_id: &str) -> Result<HsmConnection> {
        let id = connection_id.to_owned();
        self.with_conn(|conn| {
            let json: String = conn
                .query_row(
                    "SELECT record_json FROM hsm_connections WHERE connection_id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => {
                        KeyRackError::Other(format!("hsm connection not found: {id}"))
                    }
                    ref other => map_sql(other),
                })?;
            serde_json::from_str(&json)
                .map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))
        })
    }

    async fn update_hsm_connection(&self, conn_rec: &HsmConnection) -> Result<()> {
        let json = serde_json::to_string(conn_rec)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE hsm_connections SET record_json = ?1 WHERE connection_id = ?2",
                rusqlite::params![json, conn_rec.connection_id],
            )
            .map_err(|e| map_sql(&e))?;
            Ok(())
        })
    }

    async fn list_hsm_connections(&self) -> Result<Vec<HsmConnection>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT record_json FROM hsm_connections")
                .map_err(|e| map_sql(&e))?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| map_sql(&e))?;

            let mut items = Vec::new();
            for row in rows {
                let json = row.map_err(|e| map_sql(&e))?;
                let rec: HsmConnection = serde_json::from_str(&json)
                    .map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))?;
                items.push(rec);
            }
            Ok(items)
        })
    }

    async fn delete_hsm_connection(&self, connection_id: &str) -> Result<()> {
        let id = connection_id.to_owned();
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM hsm_connections WHERE connection_id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| map_sql(&e))?;
            Ok(())
        })
    }

    async fn create_rotation_job(&self, job: &RotationJob) -> Result<()> {
        let json = serde_json::to_string(job)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        let state_str = state_to_string(job.state)?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO rotation_jobs (job_id, record_json, state) VALUES (?1, ?2, ?3)",
                rusqlite::params![job.job_id, json, state_str],
            )
            .map_err(|e| map_sql(&e))?;
            Ok(())
        })
    }

    async fn get_rotation_job(&self, job_id: &str) -> Result<RotationJob> {
        let id = job_id.to_owned();
        self.with_conn(|conn| {
            let json: String = conn
                .query_row(
                    "SELECT record_json FROM rotation_jobs WHERE job_id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => {
                        KeyRackError::Other(format!("rotation job not found: {id}"))
                    }
                    ref other => map_sql(other),
                })?;
            serde_json::from_str(&json)
                .map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))
        })
    }

    async fn update_rotation_job(&self, job: &RotationJob) -> Result<()> {
        let json = serde_json::to_string(job)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        let state_str = state_to_string(job.state)?;
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE rotation_jobs SET record_json = ?1, state = ?2 WHERE job_id = ?3",
                rusqlite::params![json, state_str, job.job_id],
            )
            .map_err(|e| map_sql(&e))?;
            Ok(())
        })
    }

    async fn list_rotation_jobs(
        &self,
        state_filter: Option<RotationJobState>,
    ) -> Result<Vec<RotationJob>> {
        self.with_conn(|conn| {
            let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match state_filter {
                Some(state) => {
                    let state_str = state_to_string(state)?;
                    (
                        "SELECT record_json FROM rotation_jobs WHERE state = ?1",
                        vec![Box::new(state_str)],
                    )
                }
                None => ("SELECT record_json FROM rotation_jobs", vec![]),
            };

            let mut stmt = conn.prepare(sql).map_err(|e| map_sql(&e))?;
            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(AsRef::as_ref).collect();
            let rows = stmt
                .query_map(param_refs.as_slice(), |row| row.get::<_, String>(0))
                .map_err(|e| map_sql(&e))?;

            let mut items = Vec::new();
            for row in rows {
                let json = row.map_err(|e| map_sql(&e))?;
                let rec: RotationJob = serde_json::from_str(&json)
                    .map_err(|e| KeyRackError::Storage(format!("deserialize: {e}")))?;
                items.push(rec);
            }
            Ok(items)
        })
    }

    async fn ping(&self) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute_batch("SELECT 1").map_err(|e| map_sql(&e))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyrack_core::key::KeyState;
    use keyrack_test_support::fixtures::test_key_record;

    #[tokio::test]
    async fn open_in_memory() {
        let store = SqliteStorage::in_memory().unwrap();
        store.ping().await.unwrap();
    }

    #[tokio::test]
    async fn mixed_material_survives_database_reopen_and_stale_update() {
        use keyrack_core::key::{KeyMaterial, KeyState};
        use keyrack_test_support::fixtures::mixed_material_key_record;

        let record = mixed_material_key_record(KeyState::Enabled);
        let path = std::env::temp_dir().join(format!("keyrack-material-{}.sqlite", record.lid));
        // Reserve only our unique fixture path; never overwrite an existing DB.
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap(),
        );

        let store = SqliteStorage::open(&path).unwrap();
        store.create_key(&record).await.unwrap();
        let json = store
            .with_conn(|connection| {
                connection
                    .query_row(
                        "SELECT record_json FROM keys WHERE lid = ?1",
                        [record.lid.to_string()],
                        |row| row.get::<_, String>(0),
                    )
                    .map_err(|error| map_sql(&error))
            })
            .unwrap();
        let wire: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(wire["key_versions"][0].get("key_handle").is_some());
        assert!(wire["key_versions"][1].get("key_handle").is_none());
        let parent = record.parent_lid.unwrap();
        assert_eq!(
            wire["key_versions"][1]["material"]["parent_lid"],
            serde_json::to_value(parent.as_bytes()).unwrap()
        );
        drop(store);

        let reopened = SqliteStorage::open(&path).unwrap();
        let fetched = reopened.get_key(&record.lid).await.unwrap();
        assert_eq!(
            serde_json::to_value(&fetched).unwrap(),
            serde_json::to_value(&record).unwrap()
        );
        assert!(matches!(
            fetched.key_versions[1].material,
            KeyMaterial::ParentWrapped(_)
        ));
        assert!(fetched.key_versions[1].resident_handle().is_err());
        let mut updated = fetched;
        updated.occ_version += 1;
        updated.description = "updated after reopening".into();
        reopened.update_key(&updated).await.unwrap();
        drop(reopened);

        let reopened_again = SqliteStorage::open(&path).unwrap();
        let mut stale = record.clone();
        stale.occ_version += 1;
        stale.key_versions.truncate(1);
        stale.current_key_version = 1;
        assert!(matches!(
            reopened_again.update_key(&stale).await,
            Err(KeyRackError::OptimisticConcurrencyConflict { .. })
        ));
        let actual = reopened_again.get_key(&record.lid).await.unwrap();
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&updated).unwrap()
        );
        drop(reopened_again);
        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn compromise_history_survives_database_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compromise.sqlite");
        let mut record = test_key_record(KeyState::Enabled);
        {
            let store = SqliteStorage::open(&path).unwrap();
            store.create_key(&record).await.unwrap();
            record.transition_to(KeyState::Compromised).unwrap();
            store.update_key(&record).await.unwrap();
            record.transition_to(KeyState::PendingDeletion).unwrap();
            store.update_key(&record).await.unwrap();
        }

        let store = SqliteStorage::open(&path).unwrap();
        let mut reloaded = store.get_key_for_use(&record.lid).await.unwrap();
        assert_eq!(reloaded.state, KeyState::PendingDeletion);
        assert!(reloaded.was_compromised);
        reloaded.transition_to(KeyState::Disabled).unwrap();
        store.update_key(&reloaded).await.unwrap();
        assert!(reloaded.transition_to(KeyState::Enabled).is_err());
        assert!(!reloaded.permits_decrypt());
        assert!(!reloaded.permits_export());
    }

    #[tokio::test]
    async fn legacy_compromised_json_cannot_lose_history_on_update() {
        let store = SqliteStorage::in_memory().unwrap();
        let record = test_key_record(KeyState::Compromised);
        let mut value = serde_json::to_value(&record).unwrap();
        value.as_object_mut().unwrap().remove("was_compromised");
        store
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO keys (lid, record_json, occ_version) VALUES (?1, ?2, ?3)",
                    rusqlite::params![record.lid.to_string(), value.to_string(), 1_i64],
                )
                .map_err(|e| map_sql(&e))?;
                Ok(())
            })
            .unwrap();

        let mut legacy = store.get_key_for_use(&record.lid).await.unwrap();
        assert!(!legacy.was_compromised);
        assert!(legacy.has_compromise_history());
        let mut cleared = legacy.clone();
        cleared.state = KeyState::PendingDeletion;
        cleared.occ_version += 1;
        assert!(store.update_key(&cleared).await.is_err());

        legacy.description = "legacy metadata update".into();
        legacy.occ_version += 1;
        store.update_key(&legacy).await.unwrap();
        let updated = store.get_key_for_use(&record.lid).await.unwrap();
        assert!(updated.was_compromised);
        assert_eq!(updated.description, legacy.description);
    }

    #[tokio::test]
    async fn stale_pre_compromise_write_keeps_occ_conflict_semantics() {
        let store = SqliteStorage::in_memory().unwrap();
        let mut record = test_key_record(KeyState::Enabled);
        store.create_key(&record).await.unwrap();
        let mut stale = record.clone();
        record.transition_to(KeyState::Compromised).unwrap();
        store.update_key(&record).await.unwrap();

        stale.description = "write obtained before compromise".into();
        stale.occ_version += 1;
        assert!(matches!(
            store.update_key(&stale).await,
            Err(KeyRackError::OptimisticConcurrencyConflict { .. })
        ));
        assert!(store.get_key(&record.lid).await.unwrap().was_compromised);
    }

    #[tokio::test]
    async fn legacy_identity_version_is_rejected_without_relabeling_or_writing() {
        let store = SqliteStorage::in_memory().unwrap();
        let record = test_key_record(KeyState::Enabled);
        let mut value = serde_json::to_value(&record).unwrap();
        value["canonicalization_version"] = serde_json::json!("V1");
        let original = value.to_string();
        store
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO keys (lid, record_json, occ_version) VALUES (?1, ?2, ?3)",
                    rusqlite::params![record.lid.to_string(), original, 1_i64],
                )
                .map_err(|e| map_sql(&e))?;
                Ok(())
            })
            .unwrap();
        let error = store.get_key(&record.lid).await.unwrap_err();
        assert!(error.to_string().contains("unknown variant `V1`"));
        assert!(store.get_key_for_use(&record.lid).await.is_err());
        let unchanged: String = store
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT record_json FROM keys WHERE lid = ?1",
                    [record.lid.to_string()],
                    |row| row.get(0),
                )
                .map_err(|e| map_sql(&e))
            })
            .unwrap();
        assert_eq!(unchanged, original);
    }

    keyrack_test_support::storage_conformance_tests!(SqliteStorage::in_memory().unwrap());
    keyrack_test_support::creation_conformance_tests!(SqliteStorage::in_memory().unwrap());
    keyrack_test_support::destruction_conformance_tests!(SqliteStorage::in_memory().unwrap());
}
