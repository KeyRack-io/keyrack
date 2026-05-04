// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Change Date: 2030-01-01
// Change License: Apache License, Version 2.0

//! `SQLite` storage backend for single-node `KeyRack` deployments.
//!
//! Uses `rusqlite` with the `bundled` feature (zero system dependencies).
//! `rusqlite` is synchronous; operations acquire a `Mutex`-guarded
//! connection. For high-concurrency deployments, use `PostgreSQL`.

#![forbid(unsafe_code)]

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
";

/// `SQLite`-backed storage.
pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    /// Open (or create) a database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| KeyRackError::Storage(format!("open: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| KeyRackError::Storage(format!("schema: {e}")))?;
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
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn with_conn<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Connection) -> Result<R>,
    {
        let conn = self.conn.lock().map_err(|e| {
            KeyRackError::Storage(format!("lock poisoned: {e}"))
        })?;
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
    async fn create_key(&self, record: &KeyRecord) -> Result<()> {
        let lid_str = record.lid.to_string();
        let json = serde_json::to_string(record)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        let occ = record.occ_version as i64;

        self.with_conn(|conn| {
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
        let json = serde_json::to_string(record)
            .map_err(|e| KeyRackError::Storage(format!("serialize: {e}")))?;
        let new_occ = record.occ_version as i64;
        let expected_occ = (record.occ_version - 1) as i64;

        self.with_conn(|conn| {
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
                if filter.user_tags.iter().all(|(k, v)| {
                    record.user_tags.get(k).is_some_and(|tv| tv == v)
                }) {
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
                if record.parent_lid.as_ref().is_some_and(|p| p.to_string() == parent_str) {
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
                None => (
                    "SELECT record_json FROM rotation_jobs",
                    vec![],
                ),
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

    #[tokio::test]
    async fn open_in_memory() {
        let store = SqliteStorage::in_memory().unwrap();
        store.ping().await.unwrap();
    }

    keyrack_test_support::storage_conformance_tests!(
        SqliteStorage::in_memory().unwrap()
    );
}
