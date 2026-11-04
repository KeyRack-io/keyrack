// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{creation, map_sql, SqliteStorage};
use keyrack_core::destruction::{
    completed_record, invalid, prepare_claim, DestructionClaim, DestructionDependencies,
};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::{KeyMaterial, KeyRecord, KeyState};
use keyrack_core::lid::Lid;
use rusqlite::{params, Connection, OptionalExtension};

pub(super) fn guard(conn: &Connection, lid: &Lid) -> Result<()> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM destruction_journal WHERE lid=?1)",
            [lid.to_string()],
            |row| row.get(0),
        )
        .map_err(|e| map_sql(&e))?;
    if exists {
        return Err(KeyRackError::KeyDestructionFenced(*lid));
    }
    Ok(())
}

pub(super) fn guard_write(conn: &Connection, record: &KeyRecord) -> Result<()> {
    guard(conn, &record.lid)?;
    for version in &record.key_versions {
        if let KeyMaterial::ParentWrapped(material) = &version.material {
            guard(conn, &material.parent().lid)?;
        }
    }
    Ok(())
}

fn save_key(conn: &Connection, record: &KeyRecord, expected: u64) -> Result<()> {
    let json = serde_json::to_string(record).map_err(|_| invalid("key serialization"))?;
    let occ = i64::try_from(record.occ_version).map_err(|_| invalid("OCC out of range"))?;
    let expected = i64::try_from(expected).map_err(|_| invalid("OCC out of range"))?;
    let rows = conn
        .execute(
            "UPDATE keys SET record_json=?1,occ_version=?2 WHERE lid=?3 AND occ_version=?4",
            params![json, occ, record.lid.to_string(), expected],
        )
        .map_err(|e| map_sql(&e))?;
    if rows != 1 {
        return Err(invalid("key changed during destruction transaction"));
    }
    Ok(())
}

/// Caller holds the same writer transaction as creation and destruction claims.
fn dependencies(conn: &Connection, lid: &Lid) -> Result<DestructionDependencies> {
    creation::key(conn, lid)?.ok_or(KeyRackError::KeyNotFound(*lid))?;
    let journals: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM creation_journal WHERE parent_lid=?1 OR child_lid=?1",
            [lid.to_string()],
            |row| row.get(0),
        )
        .map_err(|e| map_sql(&e))?;
    let migrations: i64 = conn.query_row(
        "SELECT COUNT(*) FROM migration_journal WHERE committed=0 AND (child_lid=?1 OR old_parent_lid=?1 OR new_parent_lid=?1)",
        [lid.to_string()], |row| row.get(0),
    ).map_err(|e| map_sql(&e))?;
    let mut counts = DestructionDependencies {
        migration_journal_rows: u64::try_from(migrations)
            .map_err(|_| invalid("dependency count out of range"))?,
        creation_journal_rows: u64::try_from(journals)
            .map_err(|_| invalid("dependency count out of range"))?,
        ..DestructionDependencies::default()
    };
    // Include imported/legacy material without requiring a creation journal.
    let mut statement = conn
        .prepare("SELECT lid,record_json,occ_version FROM keys")
        .map_err(|e| map_sql(&e))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|e| map_sql(&e))?;
    for row in rows {
        let (indexed_lid, json, occ) = row.map_err(|e| map_sql(&e))?;
        let record: KeyRecord =
            serde_json::from_str(&json).map_err(|_| invalid("invalid persisted key"))?;
        if record.lid.to_string() != indexed_lid
            || u64::try_from(occ).ok() != Some(record.occ_version)
        {
            return Err(invalid("key row binding mismatch"));
        }
        counts.include_record(lid, &record)?;
    }
    Ok(counts)
}

impl SqliteStorage {
    pub(super) fn destruction_dependency_counts(
        &self,
        lid: &Lid,
    ) -> Result<DestructionDependencies> {
        self.creation_tx(|conn| dependencies(conn, lid))
    }

    pub(super) fn destruction_claim(
        &self,
        lid: &Lid,
        expected: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<DestructionClaim>> {
        let operation = uuid::Uuid::new_v4();
        let record = self.creation_tx(|conn| {
            let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM destruction_journal WHERE lid=?1)",
                [lid.to_string()], |row| row.get(0)).map_err(|e| map_sql(&e))?;
            if exists { return Ok(None); }
            let record = creation::key(conn, lid)?.ok_or(KeyRackError::KeyNotFound(*lid))?;
            let counts = dependencies(conn, lid)?;
            if counts.migration_journal_rows != 0 { return Err(KeyRackError::ProviderUnavailable(format!("key participates in an in-flight migration; retry the operation: {}", counts.summary()))); }
            if !counts.is_empty() { return Err(invalid(&counts.summary())); }
            let record = prepare_claim(record, expected, now)?;
            let json = serde_json::to_string(&record).map_err(|_| invalid("claim serialization"))?;
            conn.execute("INSERT INTO destruction_journal(lid,operation_id,record_json,completed) VALUES(?1,?2,?3,0)",
                params![lid.to_string(), operation.to_string(), json]).map_err(|e| map_sql(&e))?;
            save_key(conn, &record, expected)?;
            Ok(Some(record))
        })?;
        // Never return a ticket on failed or ambiguous commit.
        record
            .map(|record| DestructionClaim::committed(operation, record))
            .transpose()
    }

    pub(super) fn destruction_complete(&self, claim: DestructionClaim) -> Result<KeyRecord> {
        let result = self.creation_tx(|conn| {
            let lid = claim.record().lid;
            let stored: Option<(String, String, bool)> = conn.query_row(
                "SELECT operation_id,record_json,completed FROM destruction_journal WHERE lid=?1",
                [lid.to_string()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .optional().map_err(|e| map_sql(&e))?;
            let (operation, json, completed) = stored.ok_or(invalid("claim missing"))?;
            let snapshot: KeyRecord =
                serde_json::from_str(&json).map_err(|_| invalid("invalid claim snapshot"))?;
            if completed
                || operation != claim.operation().to_string()
                || !keyrack_core::creation::same_json(&snapshot, claim.record())?
            {
                return Err(invalid("claim mismatch or already completed"));
            }
            let current = creation::key(conn, &lid)?.ok_or(KeyRackError::KeyNotFound(lid))?;
            let record = completed_record(&claim, &current)?;
            save_key(conn, &record, current.occ_version)?;
            conn.execute(
                "UPDATE destruction_journal SET completed=1 WHERE lid=?1",
                [lid.to_string()],
            )
            .map_err(|e| map_sql(&e))?;
            Ok(record)
        });
        // Consume the one-shot ticket on success AND failure.
        drop(claim);
        result
    }
}

pub(super) fn guard_update(conn: &Connection, record: &KeyRecord) -> Result<()> {
    guard_write(conn, record)?;
    if record.state == KeyState::Destroyed {
        return Err(invalid("Destroyed requires fenced completion"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyrack_core::storage::StorageBackend;
    use keyrack_test_support::destruction_conformance::due;
    use keyrack_test_support::fixtures::unique_test_key_record;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn independent_connections_and_restart_do_not_reissue_claims() {
        let path = std::env::temp_dir().join(format!(
            "keyrack-destruction-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let first = SqliteStorage::open(&path).unwrap();
        let second = SqliteStorage::open(&path).unwrap();
        let record = due(unique_test_key_record(KeyState::Enabled));
        first.create_key(&record).await.unwrap();
        let barrier = std::sync::Barrier::new(2);
        let (a, b) = std::thread::scope(|scope| {
            let attempt = scope.spawn(|| {
                barrier.wait();
                first.destruction_claim(&record.lid, record.occ_version, chrono::Utc::now())
            });
            barrier.wait();
            let other =
                second.destruction_claim(&record.lid, record.occ_version, chrono::Utc::now());
            (attempt.join().unwrap().unwrap(), other.unwrap())
        });
        assert_eq!(usize::from(a.is_some()) + usize::from(b.is_some()), 1);
        drop((a, b));
        drop(first);
        drop(second);
        let reopened = SqliteStorage::open(&path).unwrap();
        assert!(reopened
            .claim_destruction(&record.lid, record.occ_version + 1, chrono::Utc::now())
            .await
            .unwrap()
            .is_none());
        let mut cancelled = reopened.get_key(&record.lid).await.unwrap();
        cancelled.transition_to(KeyState::Disabled).unwrap();
        assert!(reopened.update_key(&cancelled).await.is_err());
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn claim_and_completion_roll_back_atomically() {
        let store = SqliteStorage::in_memory().unwrap();
        let record = due(unique_test_key_record(KeyState::Enabled));
        store.create_key(&record).await.unwrap();
        store.with_conn(|conn| {
            conn.execute_batch("CREATE TRIGGER reject_key_write BEFORE UPDATE ON keys BEGIN SELECT RAISE(ABORT,'injected key write failure'); END;")
                .map_err(|e| map_sql(&e))
        }).unwrap();
        assert!(store
            .claim_destruction(&record.lid, record.occ_version, chrono::Utc::now())
            .await
            .is_err());
        assert_eq!(
            store.get_key(&record.lid).await.unwrap().occ_version,
            record.occ_version
        );
        store
            .with_conn(|conn| {
                let count: i64 = conn
                    .query_row("SELECT count(*) FROM destruction_journal", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(count, 0);
                conn.execute_batch("DROP TRIGGER reject_key_write;")
                    .map_err(|e| map_sql(&e))
            })
            .unwrap();
        let claim = store
            .claim_destruction(&record.lid, record.occ_version, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        store.with_conn(|conn| {
            conn.execute_batch("CREATE TRIGGER reject_completion BEFORE UPDATE ON destruction_journal BEGIN SELECT RAISE(ABORT,'injected completion failure'); END;")
                .map_err(|e| map_sql(&e))
        }).unwrap();
        assert!(store.complete_destruction(claim).await.is_err());
        assert_eq!(
            store.get_key(&record.lid).await.unwrap().state,
            KeyState::PendingDeletion
        );
        assert!(store
            .claim_destruction(&record.lid, record.occ_version + 1, chrono::Utc::now())
            .await
            .unwrap()
            .is_none());
        let mut cancelled = store.get_key(&record.lid).await.unwrap();
        cancelled.transition_to(KeyState::Disabled).unwrap();
        assert!(store.update_key(&cancelled).await.is_err());
    }
}
