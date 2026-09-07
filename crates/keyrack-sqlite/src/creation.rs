// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transactional A2 creation persistence. All key writes share `SQLite`'s writer
//! transaction, including reservations for child records which do not exist yet.

use super::{map_sql, SqliteStorage};
use keyrack_core::creation::{
    guard_referenced_parent, invalid, same_json, validate_envelope, validate_page_size,
    CreationDispatch, CreationJournal, CreationOwner, CreationPage, CreationPhase, CreationRequest,
    CreationSnapshot, VerifiedA2Closure,
};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::KeyRecord;
use keyrack_core::lid::Lid;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use uuid::Uuid;

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS creation_journal (
    operation_id TEXT PRIMARY KEY,
    child_lid TEXT NOT NULL,
    child_version TEXT NOT NULL,
    parent_lid TEXT NOT NULL,
    parent_version TEXT NOT NULL,
    envelope_ref TEXT NOT NULL UNIQUE,
    phase TEXT NOT NULL CHECK (phase IN ('reserved','staged','resolved','committed')),
    journal_json TEXT NOT NULL,
    envelope BLOB CHECK (envelope IS NULL OR length(envelope) BETWEEN 1 AND 65536),
    UNIQUE(child_lid, child_version)
);
CREATE INDEX IF NOT EXISTS idx_creation_parent ON creation_journal(parent_lid, parent_version);
CREATE INDEX IF NOT EXISTS idx_creation_recovery ON creation_journal(phase, operation_id);
CREATE INDEX IF NOT EXISTS idx_creation_recoverable ON creation_journal(operation_id) WHERE phase!='committed';
";

pub(super) fn key(conn: &Connection, lid: &Lid) -> Result<Option<KeyRecord>> {
    let row: Option<(String, i64)> = conn
        .query_row(
            "SELECT record_json,occ_version FROM keys WHERE lid=?1",
            [lid.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| map_sql(&e))?;
    row.map(|(json, occ)| {
        let record: KeyRecord =
            serde_json::from_str(&json).map_err(|_| invalid("invalid key record"))?;
        let occ = u64::try_from(occ).map_err(|_| invalid("negative persisted key OCC"))?;
        if record.lid != *lid || record.occ_version != occ {
            return Err(invalid("key row binding mismatch"));
        }
        Ok(record)
    })
    .transpose()
}

fn journal(conn: &Connection, operation: Uuid) -> Result<Option<CreationJournal>> {
    stored_journal(conn, operation)?
        .as_ref()
        .map(decode)
        .transpose()
}

fn stored_journal(conn: &Connection, operation: Uuid) -> Result<Option<StoredJournal>> {
    conn.query_row("SELECT operation_id,child_lid,child_version,parent_lid,parent_version,envelope_ref,phase,journal_json,envelope
        FROM creation_journal WHERE operation_id=?1", [operation.to_string()], stored_row)
        .optional().map_err(|e| map_sql(&e))
}

struct StoredJournal {
    fields: [String; 8],
    envelope: Option<Vec<u8>>,
}

fn stored_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredJournal> {
    Ok(StoredJournal {
        fields: [
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
        ],
        envelope: row.get(8)?,
    })
}

fn decode(row: &StoredJournal) -> Result<CreationJournal> {
    let value: CreationJournal =
        serde_json::from_str(&row.fields[7]).map_err(|_| invalid("invalid journal encoding"))?;
    value.validate()?;
    let request = &value.request;
    let material = request.material()?;
    let expected = [
        request.operation.to_string(),
        request.record.lid.to_string(),
        request.record.current_key_version.to_string(),
        material.parent().lid.to_string(),
        material.parent().version.to_string(),
        material.wrapped_material_ref().as_str().to_owned(),
        value.phase.as_str().to_owned(),
    ];
    if row.fields[..7] != expected {
        return Err(invalid("journal index binding mismatch"));
    }
    match (&row.envelope, value.phase) {
        (None, CreationPhase::Reserved) => {}
        (Some(bytes), phase) if phase != CreationPhase::Reserved => {
            validate_envelope(&value, bytes)?;
        }
        _ => return Err(invalid("journal envelope phase mismatch")),
    }
    Ok(value)
}

fn required_journal(conn: &Connection, operation: Uuid) -> Result<CreationJournal> {
    journal(conn, operation)?.ok_or(invalid("creation not found"))
}

fn encode(value: &CreationJournal) -> Result<String> {
    value.validate()?;
    serde_json::to_string(value).map_err(|_| invalid("journal serialization failed"))
}

fn save(conn: &Connection, value: &CreationJournal) -> Result<()> {
    let changed = conn
        .execute(
            "UPDATE creation_journal SET journal_json=?1, phase=?2 WHERE operation_id=?3",
            params![
                encode(value)?,
                value.phase.as_str(),
                value.request.operation.to_string()
            ],
        )
        .map_err(|e| map_sql(&e))?;
    if changed != 1 {
        return Err(invalid("creation disappeared"));
    }
    Ok(())
}

fn envelope(conn: &Connection, operation: Uuid) -> Result<Vec<u8>> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT envelope FROM creation_journal WHERE operation_id=?1",
            [operation.to_string()],
            |row| row.get(0),
        )
        .map_err(|e| map_sql(&e))?;
    bytes.ok_or(invalid("envelope not staged"))
}

pub(super) fn guard_create(conn: &Connection, lid: &Lid) -> Result<()> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM creation_journal WHERE child_lid=?1)",
            [lid.to_string()],
            |row| row.get(0),
        )
        .map_err(|e| map_sql(&e))?;
    if exists {
        return Err(invalid("child identity is reserved"));
    }
    Ok(())
}

pub(super) fn guard_update(
    conn: &Connection,
    previous: &KeyRecord,
    next: &KeyRecord,
) -> Result<()> {
    let pending: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM creation_journal WHERE child_lid=?1)",
            [next.lid.to_string()],
            |row| row.get(0),
        )
        .map_err(|e| map_sql(&e))?;
    if pending
        && (previous.current_key_version != next.current_key_version
            || !same_json(&previous.key_versions, &next.key_versions)?)
    {
        return Err(invalid(
            "version history is managed by the creation journal",
        ));
    }
    let referenced: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM creation_journal WHERE parent_lid=?1 OR (child_lid=?1 AND phase='committed'))",
        [next.lid.to_string()], |row| row.get(0)).map_err(|e| map_sql(&e))?;
    if referenced {
        guard_referenced_parent(previous, next)?;
    }
    Ok(())
}

impl SqliteStorage {
    pub(super) fn creation_tx<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        self.with_conn(|conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                .map_err(|e| map_sql(&e))?;
            let result = operation(&tx)?;
            tx.commit().map_err(|e| map_sql(&e))?;
            Ok(result)
        })
    }

    pub(super) fn reserve_a2(&self, request: &CreationRequest) -> Result<CreationJournal> {
        request.validate()?;
        self.creation_tx(|conn| {
            crate::destruction::guard_write(conn, &request.record)?;
            if let Some(existing) = journal(conn, request.operation)? {
                if existing.request.fingerprint()? != request.fingerprint()? { return Err(invalid("operation intent conflict")); }
                return Ok(existing);
            }
            let material = request.material()?;
            let parent = key(conn, &material.parent().lid)?.ok_or(KeyRackError::KeyNotFound(material.parent().lid))?;
            let current = key(conn, &request.record.lid)?;
            request.validate_records(current.as_ref(), &parent)?;
            let value = CreationJournal::reserved(request.clone())?;
            conn.execute("INSERT INTO creation_journal(operation_id,child_lid,child_version,parent_lid,parent_version,envelope_ref,phase,journal_json)
                VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", params![request.operation.to_string(), request.record.lid.to_string(),
                request.record.current_key_version.to_string(), material.parent().lid.to_string(), material.parent().version.to_string(),
                material.wrapped_material_ref().as_str(), value.phase.as_str(), encode(&value)?]).map_err(|e| map_sql(&e))?;
            Ok(value)
        })
    }

    pub(super) fn get_a2(&self, operation: Uuid) -> Result<CreationJournal> {
        self.with_conn(|conn| required_journal(conn, operation))
    }

    pub(super) fn claim_a2_dispatch(
        &self,
        operation: Uuid,
        owner: CreationOwner,
    ) -> Result<CreationDispatch> {
        self.creation_tx(|conn| {
            let mut value = required_journal(conn, operation)?;
            if !value.claim_dispatch(owner)? {
                return Ok(CreationDispatch::Existing(value));
            }
            let current = key(conn, &value.request.record.lid)?;
            let parent_lid = value.request.material()?.parent().lid;
            let parent = key(conn, &parent_lid)?.ok_or(KeyRackError::KeyNotFound(parent_lid))?;
            value.request.validate_records(current.as_ref(), &parent)?;
            save(conn, &value)?;
            // creation_tx commits before returning this one-shot permission.
            // A lost response remains consumed; a retry is only Existing.
            Ok(CreationDispatch::Started(value))
        })
    }

    pub(super) fn snapshot_a2(
        &self,
        operation: Uuid,
        owner: CreationOwner,
    ) -> Result<CreationSnapshot> {
        self.with_conn(|conn| {
            // Read the journal and envelope from one row in one SQL snapshot.
            let row = stored_journal(conn, operation)?.ok_or(invalid("creation not found"))?;
            let value = decode(&row)?;
            CreationSnapshot::new(value, row.envelope, owner)
        })
    }

    pub(super) fn stage_a2(
        &self,
        operation: Uuid,
        owner: CreationOwner,
        revision: u64,
        bytes: &[u8],
    ) -> Result<CreationJournal> {
        self.creation_tx(|conn| {
            let mut value = required_journal(conn, operation)?;
            let prior = value.phase;
            value.stage(owner, revision, bytes)?;
            if prior == CreationPhase::Reserved {
                conn.execute(
                    "UPDATE creation_journal SET envelope=?1 WHERE operation_id=?2",
                    params![bytes, operation.to_string()],
                )
                .map_err(|e| map_sql(&e))?;
            } else if envelope(conn, operation)? != bytes {
                return Err(invalid("immutable envelope conflict"));
            }
            save(conn, &value)?;
            Ok(value)
        })
    }

    pub(super) fn resolve_a2(
        &self,
        operation: Uuid,
        owner: CreationOwner,
        revision: u64,
        closure: &VerifiedA2Closure,
    ) -> Result<CreationJournal> {
        self.creation_tx(|conn| {
            let mut value = required_journal(conn, operation)?;
            validate_envelope(&value, &envelope(conn, operation)?)?;
            value.resolve(owner, revision, closure)?;
            save(conn, &value)?;
            Ok(value)
        })
    }

    pub(super) fn publish_a2(
        &self,
        operation: Uuid,
        owner: CreationOwner,
        revision: u64,
    ) -> Result<KeyRecord> {
        self.creation_tx(|conn| {
            let mut value = required_journal(conn, operation)?;
            if let Some(record) = value.committed_retry(owner, revision)? {
                return Ok(record);
            }
            validate_envelope(&value, &envelope(conn, operation)?)?;
            let request = &value.request;
            let current = key(conn, &request.record.lid)?;
            let parent_lid = request.material()?.parent().lid;
            let parent = key(conn, &parent_lid)?.ok_or(KeyRackError::KeyNotFound(parent_lid))?;
            let record = value.publication(owner, revision, current.as_ref(), &parent)?;
            let json = serde_json::to_string(&record)
                .map_err(|_| invalid("record serialization failed"))?;
            let occ = i64::try_from(record.occ_version).map_err(|_| invalid("OCC overflow"))?;
            if current.is_some() {
                conn.execute(
                    "UPDATE keys SET record_json=?1,occ_version=?2 WHERE lid=?3",
                    params![json, occ, record.lid.to_string()],
                )
                .map_err(|e| map_sql(&e))?;
            } else {
                conn.execute(
                    "INSERT INTO keys(lid,record_json,occ_version) VALUES(?1,?2,?3)",
                    params![record.lid.to_string(), json, occ],
                )
                .map_err(|e| map_sql(&e))?;
            }
            // Envelope and exact parent dependency are already reserved in this
            // row. Publication makes both live with the key and terminal result.
            save(conn, &value)?;
            Ok(record)
        })
    }

    pub(super) fn read_a2_envelope(&self, operation: Uuid) -> Result<Vec<u8>> {
        self.with_conn(|conn| {
            let value = required_journal(conn, operation)?;
            if value.phase != CreationPhase::Committed {
                return Err(invalid("staged material is unavailable"));
            }
            let bytes = envelope(conn, operation)?;
            validate_envelope(&value, &bytes)?;
            Ok(bytes)
        })
    }

    pub(super) fn recover_a2(&self, after: Option<Uuid>, limit: u32) -> Result<CreationPage> {
        validate_page_size(limit)?;
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT operation_id,child_lid,child_version,parent_lid,parent_version,envelope_ref,phase,journal_json,envelope
                FROM creation_journal WHERE phase!='committed'
                AND operation_id>?1 ORDER BY operation_id LIMIT ?2").map_err(|e| map_sql(&e))?;
            let rows = stmt.query_map(params![after.map(|v| v.to_string()).unwrap_or_default(), i64::from(limit) + 1],
                stored_row).map_err(|e| map_sql(&e))?;
            let mut items = Vec::new();
            for row in rows {
                items.push(decode(&row.map_err(|e| map_sql(&e))?)?);
            }
            let next_after = if items.len() > limit as usize {
                items.pop(); items.last().map(|v| v.request.operation)
            } else { None };
            Ok(CreationPage { items, next_after })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyrack_core::storage::StorageBackend;
    use keyrack_test_support::creation_conformance::{closure, fixture, resolved, TEST_ENVELOPE};

    fn database_path() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("keyrack-creation-{}.sqlite", Uuid::new_v4()));
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap(),
        );
        path
    }

    #[tokio::test]
    async fn every_durable_cut_survives_reopen_without_early_publication() {
        let path = database_path();
        let (parent, request) = fixture();
        let store = SqliteStorage::open(&path).unwrap();
        store.create_key(&parent).await.unwrap();
        store.reserve_creation(&request).await.unwrap();
        drop(store);
        let store = SqliteStorage::open(&path).unwrap();
        assert_eq!(
            store.get_creation(request.operation).await.unwrap().phase,
            CreationPhase::Reserved
        );
        assert!(store.get_key(&request.record.lid).await.is_err());
        assert!(matches!(
            store
                .claim_creation_dispatch(request.operation, request.owner)
                .await
                .unwrap(),
            CreationDispatch::Started(_)
        ));
        drop(store);
        let store = SqliteStorage::open(&path).unwrap();
        assert!(matches!(
            store
                .claim_creation_dispatch(request.operation, request.owner)
                .await
                .unwrap(),
            CreationDispatch::Existing(_)
        ));
        store
            .stage_creation(request.operation, request.owner, 1, TEST_ENVELOPE)
            .await
            .unwrap();
        drop(store);
        let store = SqliteStorage::open(&path).unwrap();
        assert_eq!(
            store.get_creation(request.operation).await.unwrap().phase,
            CreationPhase::Staged
        );
        assert!(store
            .read_creation_envelope(request.operation)
            .await
            .is_err());
        store
            .resolve_creation(request.operation, request.owner, 2, &closure(&request))
            .await
            .unwrap();
        drop(store);
        let store = SqliteStorage::open(&path).unwrap();
        assert_eq!(
            store.get_creation(request.operation).await.unwrap().phase,
            CreationPhase::Resolved
        );
        assert!(store.get_key(&request.record.lid).await.is_err());
        store
            .publish_creation(request.operation, request.owner, 3)
            .await
            .unwrap();
        drop(store);
        let store = SqliteStorage::open(&path).unwrap();
        assert_eq!(
            store.get_creation(request.operation).await.unwrap().phase,
            CreationPhase::Committed
        );
        assert!(same_json(
            &store.get_key(&request.record.lid).await.unwrap(),
            &request.record
        )
        .unwrap());
        assert_eq!(
            store
                .read_creation_envelope(request.operation)
                .await
                .unwrap(),
            TEST_ENVELOPE
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn failure_after_key_insert_rolls_back_key_and_terminal_journal_together() {
        let store = SqliteStorage::in_memory().unwrap();
        let (parent, request) = fixture();
        store.create_key(&parent).await.unwrap();
        resolved(&store, &request).await;
        store.with_conn(|conn| conn.execute_batch("CREATE TEMP TRIGGER fail_publication BEFORE UPDATE OF phase ON creation_journal
            WHEN NEW.phase='committed' BEGIN SELECT RAISE(ABORT, 'injected publication failure'); END;")
            .map_err(|e| map_sql(&e))).unwrap();
        assert!(store
            .publish_creation(request.operation, request.owner, 3)
            .await
            .is_err());
        assert!(store.get_key(&request.record.lid).await.is_err());
        let journal = store.get_creation(request.operation).await.unwrap();
        assert_eq!(journal.phase, CreationPhase::Resolved);
        assert!(journal.committed_record.is_none());
        store
            .with_conn(|conn| {
                conn.execute_batch("DROP TRIGGER fail_publication")
                    .map_err(|e| map_sql(&e))
            })
            .unwrap();
        store
            .publish_creation(request.operation, request.owner, 3)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn failure_after_envelope_write_does_not_leave_half_staged_state() {
        let store = SqliteStorage::in_memory().unwrap();
        let (parent, request) = fixture();
        store.create_key(&parent).await.unwrap();
        store.reserve_creation(&request).await.unwrap();
        assert!(matches!(
            store
                .claim_creation_dispatch(request.operation, request.owner)
                .await
                .unwrap(),
            CreationDispatch::Started(_)
        ));
        store
            .with_conn(|conn| {
                conn.execute_batch(
                    "CREATE TEMP TRIGGER fail_staging BEFORE UPDATE OF phase ON creation_journal
            WHEN NEW.phase='staged' BEGIN SELECT RAISE(ABORT, 'injected staging failure'); END;",
                )
                .map_err(|e| map_sql(&e))
            })
            .unwrap();
        assert!(store
            .stage_creation(request.operation, request.owner, 1, TEST_ENVELOPE)
            .await
            .is_err());
        assert_eq!(
            store.get_creation(request.operation).await.unwrap().phase,
            CreationPhase::Reserved
        );
        assert!(store
            .with_conn(|conn| envelope(conn, request.operation))
            .is_err());
        store
            .with_conn(|conn| {
                conn.execute_batch("DROP TRIGGER fail_staging")
                    .map_err(|e| map_sql(&e))
            })
            .unwrap();
        store
            .stage_creation(request.operation, request.owner, 1, TEST_ENVELOPE)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn corrupted_envelope_and_index_bindings_fail_closed() {
        let store = SqliteStorage::in_memory().unwrap();
        let (parent, request) = fixture();
        store.create_key(&parent).await.unwrap();
        resolved(&store, &request).await;
        store
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE creation_journal SET envelope=?1 WHERE operation_id=?2",
                    params![b"wrong".as_slice(), request.operation.to_string()],
                )
                .map(|_| ())
                .map_err(|e| map_sql(&e))
            })
            .unwrap();
        assert!(store.get_creation(request.operation).await.is_err());
        assert!(store
            .creation_snapshot(request.operation, request.owner)
            .await
            .is_err());
        assert!(store
            .publish_creation(request.operation, request.owner, 3)
            .await
            .is_err());
        store.with_conn(|conn| conn.execute("UPDATE creation_journal SET envelope=?1,parent_version='9000' WHERE operation_id=?2",
            params![TEST_ENVELOPE, request.operation.to_string()]).map(|_| ()).map_err(|e| map_sql(&e))).unwrap();
        assert!(store.get_creation(request.operation).await.is_err());
        assert!(store
            .creation_snapshot(request.operation, request.owner)
            .await
            .is_err());
        assert!(store
            .publish_creation(request.operation, request.owner, 3)
            .await
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn competing_connections_cannot_reserve_the_same_child_version() {
        let path = database_path();
        let (parent, request) = fixture();
        let first = SqliteStorage::open(&path).unwrap();
        let second = SqliteStorage::open(&path).unwrap();
        first.create_key(&parent).await.unwrap();
        let mut other = request.clone();
        other.operation = Uuid::new_v4();
        other.attempt = Uuid::new_v4();
        other.correlation =
            keyrack_core::creation::creation_correlation(other.operation, other.attempt);
        let reference = format!("envelope-{}", other.operation);
        keyrack_test_support::creation_conformance::replace_envelope_ref(&mut other, reference);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let other_barrier = barrier.clone();
        let one = tokio::spawn(async move {
            barrier.wait();
            first.reserve_creation(&request).await
        });
        let two = tokio::spawn(async move {
            other_barrier.wait();
            second.reserve_creation(&other).await
        });
        let (one, two) = tokio::join!(one, two);
        assert_ne!(one.unwrap().is_ok(), two.unwrap().is_ok());
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn competing_connections_issue_only_one_dispatch_and_snapshot_is_owner_fenced() {
        let path = database_path();
        let first = SqliteStorage::open(&path).unwrap();
        let second = SqliteStorage::open(&path).unwrap();
        let (parent, request) = fixture();
        first.create_key(&parent).await.unwrap();
        first.reserve_creation(&request).await.unwrap();
        let initial = first
            .creation_snapshot(request.operation, request.owner)
            .await
            .unwrap();
        assert!(!initial.journal.dispatch_started);
        assert!(initial.envelope.is_none());
        let operation = request.operation;
        let owner = request.owner;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let other_barrier = barrier.clone();
        let one = tokio::spawn(async move {
            barrier.wait();
            first.claim_creation_dispatch(operation, owner).await
        });
        let two = tokio::spawn(async move {
            other_barrier.wait();
            second.claim_creation_dispatch(operation, owner).await
        });
        let (one, two) = tokio::join!(one, two);
        let results = [one.unwrap().unwrap(), two.unwrap().unwrap()];
        assert_eq!(
            results
                .iter()
                .filter(|value| matches!(value, CreationDispatch::Started(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|value| matches!(value, CreationDispatch::Existing(_)))
                .count(),
            1
        );

        let store = SqliteStorage::open(&path).unwrap();
        assert!(matches!(
            store
                .claim_creation_dispatch(operation, owner)
                .await
                .unwrap(),
            CreationDispatch::Existing(_)
        ));
        let mut wrong_owner = owner;
        wrong_owner.generation += 1;
        assert!(store
            .claim_creation_dispatch(operation, wrong_owner)
            .await
            .is_err());
        assert!(store
            .creation_snapshot(operation, wrong_owner)
            .await
            .is_err());
        store
            .stage_creation(operation, owner, 1, TEST_ENVELOPE)
            .await
            .unwrap();
        let snapshot = store.creation_snapshot(operation, owner).await.unwrap();
        assert_eq!(snapshot.journal.phase, CreationPhase::Staged);
        assert!(snapshot.journal.dispatch_started);
        assert_eq!(snapshot.envelope.as_deref(), Some(TEST_ENVELOPE));
        assert!(store.read_creation_envelope(operation).await.is_err());
        assert!(store.get_key(&request.record.lid).await.is_err());
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn first_dispatch_rechecks_parent_and_failed_claim_does_not_consume_marker() {
        let store = SqliteStorage::in_memory().unwrap();
        let (mut parent, request) = fixture();
        store.create_key(&parent).await.unwrap();
        store.reserve_creation(&request).await.unwrap();
        parent.state = keyrack_core::key::KeyState::Disabled;
        parent.occ_version += 1;
        store.update_key(&parent).await.unwrap();
        assert!(store
            .claim_creation_dispatch(request.operation, request.owner)
            .await
            .is_err());
        assert!(
            !store
                .creation_snapshot(request.operation, request.owner)
                .await
                .unwrap()
                .journal
                .dispatch_started
        );
    }

    #[tokio::test]
    async fn dispatch_write_failure_is_not_a_started_decision() {
        let store = SqliteStorage::in_memory().unwrap();
        let (parent, request) = fixture();
        store.create_key(&parent).await.unwrap();
        store.reserve_creation(&request).await.unwrap();
        store
            .with_conn(|conn| {
                conn.execute_batch(
            "CREATE TEMP TRIGGER fail_dispatch BEFORE UPDATE OF journal_json ON creation_journal \
             BEGIN SELECT RAISE(ABORT, 'injected dispatch failure'); END;",
        ).map_err(|e| map_sql(&e))
            })
            .unwrap();
        let result = store
            .claim_creation_dispatch(request.operation, request.owner)
            .await;
        store
            .with_conn(|conn| {
                conn.execute_batch("DROP TRIGGER fail_dispatch")
                    .map_err(|e| map_sql(&e))
            })
            .unwrap();
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("injected dispatch failure"));
        assert!(
            !store
                .creation_snapshot(request.operation, request.owner)
                .await
                .unwrap()
                .journal
                .dispatch_started
        );
        assert!(matches!(
            store
                .claim_creation_dispatch(request.operation, request.owner)
                .await
                .unwrap(),
            CreationDispatch::Started(_)
        ));
    }

    #[tokio::test]
    async fn legacy_unknown_dispatch_status_is_not_treated_as_fresh() {
        let store = SqliteStorage::in_memory().unwrap();
        let (parent, request) = fixture();
        store.create_key(&parent).await.unwrap();
        let journal = store.reserve_creation(&request).await.unwrap();
        let mut legacy = serde_json::to_value(journal).unwrap();
        assert!(legacy
            .as_object_mut()
            .unwrap()
            .remove("dispatch_started")
            .is_some());
        store
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE creation_journal SET journal_json=?1 WHERE operation_id=?2",
                    params![legacy.to_string(), request.operation.to_string()],
                )
                .map(|_| ())
                .map_err(|e| map_sql(&e))
            })
            .unwrap();
        assert!(store.get_creation(request.operation).await.is_err());
        assert!(store
            .creation_snapshot(request.operation, request.owner)
            .await
            .is_err());
        assert!(store
            .claim_creation_dispatch(request.operation, request.owner)
            .await
            .is_err());
    }
}
