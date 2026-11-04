// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{creation, map_sql, SqliteStorage};
use keyrack_core::destruction::{
    completed_record, invalid, prepare_claim, DeletionIntent, DestroyedWrappingParent,
    DestructionClaim, DestructionDependencies, DestructionDependent, ScheduledDeletion,
};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::{KeyMaterial, KeyRecord, KeyState};
use keyrack_core::lid::Lid;
use rusqlite::{params, Connection, OptionalExtension};

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS deletion_schedules (
    lid TEXT PRIMARY KEY, scheduled_at TEXT NOT NULL, intent_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS destroyed_wrapping_parents (
    child_lid TEXT NOT NULL, child_version TEXT NOT NULL,
    parent_lid TEXT NOT NULL, parent_version TEXT NOT NULL,
    PRIMARY KEY(child_lid,child_version,parent_lid,parent_version)
);
";

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

fn parse_version(value: &str) -> Result<u64> {
    let version = value
        .parse::<u64>()
        .map_err(|_| invalid("invalid version index"))?;
    if version == 0 || version.to_string() != value {
        return Err(invalid("invalid version index"));
    }
    Ok(version)
}

fn count(conn: &Connection, sql: &str, lid: &Lid) -> Result<u64> {
    let n: i64 = conn
        .query_row(sql, [lid.to_string()], |r| r.get(0))
        .map_err(|e| map_sql(&e))?;
    u64::try_from(n).map_err(|_| invalid("dependency count out of range"))
}

/// Caller holds the same writer transaction as creation and destruction claims.
fn dependencies(conn: &Connection, lid: &Lid) -> Result<DestructionDependencies> {
    creation::key(conn, lid)?.ok_or(KeyRackError::KeyNotFound(*lid))?;
    let mut counts = DestructionDependencies {
        creation_journal_rows: count(conn, "SELECT COUNT(*) FROM creation_journal WHERE parent_lid=?1 OR child_lid=?1", lid)?,
        in_flight_creation_journal_rows: count(conn, "SELECT COUNT(*) FROM creation_journal WHERE phase!='committed' AND (parent_lid=?1 OR child_lid=?1)", lid)?,
        migration_journal_rows: count(conn, "SELECT COUNT(*) FROM migration_journal WHERE committed=0 AND (child_lid=?1 OR old_parent_lid=?1 OR new_parent_lid=?1)", lid)?,
        ..DestructionDependencies::default()
    };
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
    // Live envelopes remain dependencies even if a descriptor was lost or
    // imported metadata no longer points at them. Receipts without bytes do not.
    let mut statement = conn.prepare("SELECT child_lid,child_version,parent_version,envelope_ref FROM creation_journal WHERE parent_lid=?1 AND child_lid!=?1 AND phase='committed' AND envelope IS NOT NULL").map_err(|e|map_sql(&e))?;
    let rows = statement
        .query_map([lid.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|e| map_sql(&e))?;
    for row in rows {
        let (child, version, parent_version, envelope_ref) = row.map_err(|e| map_sql(&e))?;
        counts.dependents.push(DestructionDependent {
            lid: child.parse().map_err(|_| invalid("invalid child index"))?,
            version: parse_version(&version)?,
            parent_version: parse_version(&parent_version)?,
            envelope_ref,
        });
    }
    let mut statement=conn.prepare("SELECT j.operation_id,j.child_lid,j.journal_json,e.version FROM migration_journal j JOIN migration_envelopes e ON e.operation_id=j.operation_id WHERE j.new_parent_lid=?1 AND j.child_lid!=?1 AND j.committed=1").map_err(|e|map_sql(&e))?;
    let rows = statement
        .query_map([lid.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|e| map_sql(&e))?;
    for row in rows {
        let (operation, child, json, version) = row.map_err(|e| map_sql(&e))?;
        let journal: keyrack_core::migration::MigrationJournal =
            serde_json::from_str(&json).map_err(|_| invalid("invalid migration journal"))?;
        journal.validate()?;
        let version = parse_version(&version)?;
        let bound = journal
            .request
            .proposed
            .get_version(version)
            .ok_or(invalid("migration envelope version mismatch"))?;
        let KeyMaterial::ParentWrapped(material) = &bound.material else {
            return Err(invalid("migration envelope material mismatch"));
        };
        if journal.request.operation.to_string() != operation
            || journal.request.child.lid.to_string() != child
            || journal.phase != keyrack_core::migration::MigrationPhase::Committed
            || material.parent().lid != *lid
        {
            return Err(invalid("migration envelope index mismatch"));
        }
        counts.dependents.push(DestructionDependent {
            lid: journal.request.child.lid,
            version,
            parent_version: material.parent().version.get(),
            envelope_ref: material.wrapped_material_ref().as_str().to_owned(),
        });
    }
    counts.dependents.sort();
    counts.dependents.dedup();
    counts.dependent_wrapping_edges =
        u64::try_from(counts.dependents.len()).map_err(|_| invalid("dependency count overflow"))?;
    Ok(counts)
}

fn intent(conn: &Connection, record: &KeyRecord) -> Result<Option<DeletionIntent>> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT scheduled_at,intent_json FROM deletion_schedules WHERE lid=?1",
            [record.lid.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| map_sql(&e))?;
    row.map(|(at, json)| {
        if record.state != KeyState::PendingDeletion
            || record
                .scheduled_deletion_at
                .map(|v| v.to_rfc3339())
                .as_deref()
                != Some(&at)
        {
            return Err(invalid("deletion intent schedule mismatch"));
        }
        serde_json::from_str(&json).map_err(|_| invalid("invalid deletion intent"))
    })
    .transpose()
}

fn checked_record(conn: &Connection, lid: &Lid, expected: u64) -> Result<KeyRecord> {
    let record = creation::key(conn, lid)?.ok_or(KeyRackError::KeyNotFound(*lid))?;
    if record.occ_version != expected {
        return Err(KeyRackError::OptimisticConcurrencyConflict {
            lid: *lid,
            expected,
            actual: record.occ_version,
        });
    }
    if expected == 0 || expected >= i64::MAX as u64 {
        return Err(invalid("OCC out of range"));
    }
    Ok(record)
}

/// Require every owned wrapped descriptor to resolve to the exact persisted
/// envelope that this lifecycle will erase, rather than silently claiming success.
fn validate_owned_envelopes(conn: &Connection, record: &KeyRecord) -> Result<()> {
    for version in &record.key_versions {
        let KeyMaterial::ParentWrapped(material) = &version.material else {
            continue;
        };
        let reference = material.wrapped_material_ref().as_str();
        let creation: Option<(String,String,String,String,String,bool)> = conn.query_row(
            "SELECT child_lid,child_version,parent_lid,parent_version,phase,envelope IS NOT NULL FROM creation_journal WHERE envelope_ref=?1", [reference],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
        ).optional().map_err(|e|map_sql(&e))?;
        if let Some((child, number, parent, parent_version, phase, bytes)) = creation {
            if child != record.lid.to_string()
                || parse_version(&number)? != version.version_number
                || parent != material.parent().lid.to_string()
                || parse_version(&parent_version)? != material.parent().version.get()
                || phase != "committed"
                || !bytes
            {
                return Err(invalid("owned creation envelope binding mismatch"));
            }
        } else if let Some(tail) = reference.strip_prefix("migration:") {
            let (operation, number) = tail
                .rsplit_once(':')
                .ok_or(invalid("invalid migration envelope reference"))?;
            if parse_version(number)? != version.version_number {
                return Err(invalid("migration envelope version mismatch"));
            }
            let row:Option<(String,bool)>=conn.query_row("SELECT j.journal_json,j.committed FROM migration_journal j JOIN migration_envelopes e ON e.operation_id=j.operation_id WHERE j.operation_id=?1 AND e.version=?2",params![operation,number],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|map_sql(&e))?;
            let Some((json, committed)) = row else {
                return Err(invalid("owned migration envelope missing"));
            };
            let journal: keyrack_core::migration::MigrationJournal =
                serde_json::from_str(&json).map_err(|_| invalid("invalid migration journal"))?;
            journal.validate()?;
            if !committed
                || journal.phase != keyrack_core::migration::MigrationPhase::Committed
                || journal.request.child.lid != record.lid
                || journal
                    .request
                    .proposed
                    .get_version(version.version_number)
                    .map(|v| &v.material)
                    != Some(&version.material)
            {
                return Err(invalid("owned migration envelope binding mismatch"));
            }
        } else {
            return Err(invalid("unsupported wrapped envelope lifecycle"));
        }
    }
    Ok(())
}

impl SqliteStorage {
    pub(super) fn destruction_dependency_counts(
        &self,
        lid: &Lid,
    ) -> Result<DestructionDependencies> {
        self.creation_tx(|conn| dependencies(conn, lid))
    }
    pub(super) fn destruction_intent(&self, lid: &Lid) -> Result<Option<DeletionIntent>> {
        self.with_conn(|conn| {
            let record = creation::key(conn, lid)?.ok_or(KeyRackError::KeyNotFound(*lid))?;
            intent(conn, &record)
        })
    }
    pub(super) fn destruction_parent_markers(
        &self,
        lid: &Lid,
    ) -> Result<Vec<DestroyedWrappingParent>> {
        self.creation_tx(|conn| {
            creation::key(conn, lid)?.ok_or(KeyRackError::KeyNotFound(*lid))?;
            let mut statement=conn.prepare("SELECT child_version,parent_lid,parent_version FROM destroyed_wrapping_parents WHERE child_lid=?1").map_err(|e|map_sql(&e))?;
            let rows=statement.query_map([lid.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).map_err(|e|map_sql(&e))?;
            let mut markers = rows.map(|row| {let(version,parent,parent_version)=row.map_err(|e|map_sql(&e))?;Ok(DestroyedWrappingParent {version:parse_version(&version)?,parent_lid:parent.parse().map_err(|_|invalid("invalid destroyed parent index"))?,parent_version:parse_version(&parent_version)?})}).collect::<Result<Vec<_>>>()?;
            markers.sort_by_key(|marker| (marker.version, marker.parent_lid, marker.parent_version));
            Ok(markers)
        })
    }
    pub(super) fn destruction_schedule(
        &self,
        lid: &Lid,
        expected: u64,
        at: chrono::DateTime<chrono::Utc>,
        allow: bool,
    ) -> Result<ScheduledDeletion> {
        self.creation_tx(|conn| {
            guard(conn,lid)?;
            let mut record=checked_record(conn,lid,expected)?;
            let observed=dependencies(conn,lid)?;
            let approval=observed.approval(allow)?;
            keyrack_core::destruction::validate_destruction_history(&record)?;
            validate_owned_envelopes(conn,&record)?;
            record.transition_to(KeyState::PendingDeletion).map_err(|(from,to)|KeyRackError::InvalidStateTransition {lid:*lid,from,to})?;
            record.scheduled_deletion_at=Some(at);
            save_key(conn,&record,expected)?;
            conn.execute("INSERT INTO deletion_schedules(lid,scheduled_at,intent_json) VALUES(?1,?2,?3) ON CONFLICT(lid) DO UPDATE SET scheduled_at=excluded.scheduled_at,intent_json=excluded.intent_json",params![lid.to_string(),at.to_rfc3339(),serde_json::to_string(&approval).map_err(|_|invalid("intent serialization"))?]).map_err(|e|map_sql(&e))?;
            Ok(ScheduledDeletion { record, logical_only_children: observed.logical_only_children, approved_dependents: approval.approved_dependents })
        })
    }
    pub(super) fn destruction_cancel(&self, lid: &Lid, expected: u64) -> Result<KeyRecord> {
        self.creation_tx(|conn| {
            guard(conn, lid)?;
            crate::migration::guard(conn, lid)?;
            let mut record = checked_record(conn, lid, expected)?;
            if record.state != KeyState::PendingDeletion {
                return Err(invalid("key is not pending deletion"));
            }
            record
                .transition_to(KeyState::Disabled)
                .map_err(|(from, to)| KeyRackError::InvalidStateTransition {
                    lid: *lid,
                    from,
                    to,
                })?;
            record.scheduled_deletion_at = None;
            save_key(conn, &record, expected)?;
            conn.execute(
                "DELETE FROM deletion_schedules WHERE lid=?1",
                [lid.to_string()],
            )
            .map_err(|e| map_sql(&e))?;
            Ok(record)
        })
    }
    pub(super) fn destruction_claim(
        &self,
        lid: &Lid,
        expected: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<DestructionClaim>> {
        let claimed = self.creation_tx(|conn| {
            let journal: Option<(String, String, bool)> = conn.query_row(
                "SELECT operation_id,record_json,completed FROM destruction_journal WHERE lid=?1",
                [lid.to_string()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            ).optional().map_err(|e| map_sql(&e))?;
            if let Some((operation, json, completed)) = journal {
                if completed { return Ok(None); }
                let snapshot: KeyRecord = serde_json::from_str(&json)
                    .map_err(|_| invalid("invalid claim snapshot"))?;
                let operation = operation.parse::<uuid::Uuid>()
                    .map_err(|_| invalid("invalid claim operation"))?;
                if operation.is_nil() || snapshot.lid != *lid || snapshot.state != KeyState::PendingDeletion {
                    return Err(invalid("claim binding mismatch"));
                }
                let current = creation::key(conn, lid)?.ok_or(KeyRackError::KeyNotFound(*lid))?;
                if !keyrack_core::creation::same_json(&snapshot, &current)? {
                    return Err(invalid("claimed snapshot changed"));
                }
                if expected != snapshot.occ_version { return Ok(None); }
                keyrack_core::destruction::validate_destruction_history(&snapshot)?;
                // Also backfill claims written before loss markers were part of admission.
                record_loss_markers(conn, lid)?;
                return Ok(Some((operation, snapshot, true)));
            }
            let record = creation::key(conn, lid)?.ok_or(KeyRackError::KeyNotFound(*lid))?;
            let counts = dependencies(conn, lid)?;
            counts.validate_intent(&intent(conn, &record)?.unwrap_or_default())?;
            validate_owned_envelopes(conn, &record)?;
            let record = prepare_claim(record, expected, now)?;
            let operation = uuid::Uuid::new_v4();
            let json = serde_json::to_string(&record).map_err(|_| invalid("claim serialization"))?;
            conn.execute("INSERT INTO destruction_journal(lid,operation_id,record_json,completed) VALUES(?1,?2,?3,0)",
                params![lid.to_string(), operation.to_string(), json]).map_err(|e| map_sql(&e))?;
            record_loss_markers(conn, lid)?;
            save_key(conn, &record, expected)?;
            Ok(Some((operation, record, false)))
        })?;
        claimed
            .map(|(operation, record, recovered)| {
                if recovered {
                    DestructionClaim::recovered(operation, record)
                } else {
                    DestructionClaim::committed(operation, record)
                }
            })
            .transpose()
    }
    pub(super) fn destruction_complete(&self, claim: DestructionClaim) -> Result<KeyRecord> {
        let result=self.creation_tx(|conn| {
            let lid=claim.record().lid;
            let stored:Option<(String,String,bool)>=conn.query_row("SELECT operation_id,record_json,completed FROM destruction_journal WHERE lid=?1",[lid.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional().map_err(|e|map_sql(&e))?;
            let(operation,json,completed)=stored.ok_or(invalid("claim missing"))?;
            let snapshot:KeyRecord=serde_json::from_str(&json).map_err(|_|invalid("invalid claim snapshot"))?;
            if operation!=claim.operation().to_string() || !keyrack_core::creation::same_json(&snapshot,claim.record())? {return Err(invalid("claim mismatch"));}
            let current=creation::key(conn,&lid)?.ok_or(KeyRackError::KeyNotFound(lid))?;
            if completed {
                keyrack_core::destruction::validate_completed_record(&claim, &current)?;
                return Ok(current);
            }
            let record=completed_record(&claim,&current)?;
            conn.execute("INSERT INTO retired_creation_journal(operation_id,journal_json) SELECT operation_id,journal_json FROM creation_journal WHERE child_lid=?1 AND phase='committed' ON CONFLICT(operation_id) DO NOTHING",[lid.to_string()]).map_err(|e|map_sql(&e))?;
            conn.execute("DELETE FROM creation_journal WHERE child_lid=?1 AND phase='committed'",[lid.to_string()]).map_err(|e|map_sql(&e))?;
            conn.execute("DELETE FROM migration_envelopes WHERE operation_id IN (SELECT operation_id FROM migration_journal WHERE child_lid=?1 AND committed=1)",[lid.to_string()]).map_err(|e|map_sql(&e))?;
            save_key(conn,&record,current.occ_version)?;
            conn.execute("UPDATE destruction_journal SET completed=1 WHERE lid=?1",[lid.to_string()]).map_err(|e|map_sql(&e))?;
            conn.execute("DELETE FROM deletion_schedules WHERE lid=?1",[lid.to_string()]).map_err(|e|map_sql(&e))?;
            Ok(record)
        });
        drop(claim);
        result
    }
}

// Persist loss before provider effects; inspect current descriptors rather than
// marking retired envelopes or a child version rewrapped to another parent.
fn record_loss_markers(conn: &Connection, lid: &Lid) -> Result<()> {
    let observed = dependencies(conn, lid)?;
    for edge in observed.dependents {
        if let Some(child) = creation::key(conn, &edge.lid)? {
            if child.state == KeyState::Destroyed {
                continue;
            }
            if let Some(version) = child.get_version(edge.version) {
                if let KeyMaterial::ParentWrapped(material) = &version.material {
                    if material.parent().lid == *lid
                        && material.parent().version.get() == edge.parent_version
                        && material.wrapped_material_ref().as_str() == edge.envelope_ref
                    {
                        conn.execute("INSERT OR IGNORE INTO destroyed_wrapping_parents(child_lid,child_version,parent_lid,parent_version) VALUES(?1,?2,?3,?4)",params![edge.lid.to_string(),edge.version.to_string(),lid.to_string(),edge.parent_version.to_string()]).map_err(|e|map_sql(&e))?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn guard_update(conn: &Connection, record: &KeyRecord) -> Result<()> {
    guard_write(conn, record)?;
    if record.state == KeyState::Destroyed {
        return Err(invalid("Destroyed requires fenced completion"));
    }
    let previous =
        creation::key(conn, &record.lid)?.ok_or(KeyRackError::KeyNotFound(record.lid))?;
    if previous.state != record.state
        || previous.scheduled_deletion_at != record.scheduled_deletion_at
    {
        conn.execute(
            "DELETE FROM deletion_schedules WHERE lid=?1",
            [record.lid.to_string()],
        )
        .map_err(|e| map_sql(&e))?;
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
    async fn independent_connections_and_restart_resume_the_same_claim() {
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
        let operation = a.as_ref().or(b.as_ref()).unwrap().operation();
        drop((a, b));
        drop(first);
        drop(second);
        let reopened = SqliteStorage::open(&path).unwrap();
        let recovered = reopened
            .claim_destruction(&record.lid, record.occ_version + 1, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        assert!(recovered.is_recovered());
        assert_eq!(recovered.operation(), operation);
        assert_eq!(recovered.record().occ_version, record.occ_version + 1);
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
        let recovered = store
            .claim_destruction(&record.lid, record.occ_version + 1, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        assert!(recovered.is_recovered());
        let mut cancelled = store.get_key(&record.lid).await.unwrap();
        cancelled.transition_to(KeyState::Disabled).unwrap();
        assert!(store.update_key(&cancelled).await.is_err());
        store
            .with_conn(|conn| {
                conn.execute_batch("DROP TRIGGER reject_completion;")
                    .map_err(|e| map_sql(&e))
            })
            .unwrap();
        assert_eq!(
            store.complete_destruction(recovered).await.unwrap().state,
            KeyState::Destroyed
        );
    }
    async fn published(
        store: &SqliteStorage,
    ) -> (KeyRecord, keyrack_core::creation::CreationRequest) {
        let (parent, request) = keyrack_test_support::creation_conformance::fixture();
        store.create_key(&parent).await.unwrap();
        keyrack_test_support::creation_conformance::resolved(store, &request).await;
        store
            .publish_creation(request.operation, request.owner, 3)
            .await
            .unwrap();
        (parent, request)
    }

    #[tokio::test]
    async fn deletion_schema_upgrade_restart_and_cancel_preserve_approval_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.sqlite");
        let old = SqliteStorage::open(&path).unwrap();
        let record = unique_test_key_record(KeyState::Enabled);
        old.create_key(&record).await.unwrap();
        old.with_conn(|conn| {
            conn.execute_batch(
                "DROP TABLE deletion_schedules; DROP TABLE destroyed_wrapping_parents;",
            )
            .map_err(|e| map_sql(&e))
        })
        .unwrap();
        drop(old);
        let upgraded = SqliteStorage::open(&path).unwrap();
        assert!(upgraded
            .deletion_intent(&record.lid)
            .await
            .unwrap()
            .is_none());
        let scheduled = upgraded
            .schedule_destruction(&record.lid, record.occ_version, chrono::Utc::now(), true)
            .await
            .unwrap()
            .record;
        let approved = upgraded
            .deletion_intent(&record.lid)
            .await
            .unwrap()
            .unwrap();
        assert!(approved.allow_dependent_data_loss);
        drop(upgraded);
        let reopened = SqliteStorage::open(&path).unwrap();
        assert_eq!(
            reopened.deletion_intent(&record.lid).await.unwrap(),
            Some(approved)
        );
        let cancelled = reopened
            .cancel_destruction(&record.lid, scheduled.occ_version)
            .await
            .unwrap();
        assert_eq!(cancelled.state, KeyState::Disabled);
        assert!(cancelled.scheduled_deletion_at.is_none());
        drop(reopened);
        let reopened = SqliteStorage::open(&path).unwrap();
        assert!(reopened
            .deletion_intent(&record.lid)
            .await
            .unwrap()
            .is_none());
        reopened
            .schedule_destruction(
                &record.lid,
                cancelled.occ_version,
                chrono::Utc::now(),
                false,
            )
            .await
            .unwrap();
        assert!(
            !reopened
                .deletion_intent(&record.lid)
                .await
                .unwrap()
                .unwrap()
                .allow_dependent_data_loss
        );
    }

    #[tokio::test]
    async fn existing_pending_row_without_schedule_has_no_loss_approval() {
        for wrapped in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("legacy.sqlite");
            let old = SqliteStorage::open(&path).unwrap();
            let mut parent = if wrapped {
                published(&old).await.0
            } else {
                let key = unique_test_key_record(KeyState::Enabled);
                old.create_key(&key).await.unwrap();
                key
            };
            parent = due(parent);
            old.with_conn(|conn| {
                conn.execute(
                    "UPDATE keys SET record_json=?1 WHERE lid=?2",
                    params![
                        serde_json::to_string(&parent).unwrap(),
                        parent.lid.to_string()
                    ],
                )
                .map_err(|error| map_sql(&error))?;
                conn.execute_batch(
                    "DROP TABLE deletion_schedules; DROP TABLE destroyed_wrapping_parents;",
                )
                .map_err(|error| map_sql(&error))
            })
            .unwrap();
            drop(old);
            let upgraded = SqliteStorage::open(&path).unwrap();
            assert!(upgraded
                .deletion_intent(&parent.lid)
                .await
                .unwrap()
                .is_none());
            let result = upgraded
                .claim_destruction(&parent.lid, parent.occ_version, chrono::Utc::now())
                .await;
            if wrapped {
                assert!(
                    matches!(result, Err(KeyRackError::DeletionDependencyRefused { ref reason, .. }) if reason == "dependent_data_loss_not_approved")
                );
                assert_eq!(
                    upgraded.get_key(&parent.lid).await.unwrap().state,
                    KeyState::PendingDeletion
                );
            } else {
                assert!(result.unwrap().is_some());
            }
        }
    }

    #[tokio::test]
    async fn claimed_loss_survives_completion_failure_and_storage_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("restart.sqlite");
        let store = SqliteStorage::open(&path).unwrap();
        let (parent, request) = published(&store).await;
        let pending = store
            .schedule_destruction(&parent.lid, parent.occ_version, chrono::Utc::now(), true)
            .await
            .unwrap()
            .record;
        // Marker insertion and the initial claim must roll back together.
        store.with_conn(|conn| conn.execute_batch("CREATE TRIGGER reject_initial_claim BEFORE UPDATE ON keys BEGIN SELECT RAISE(ABORT,'injected claim failure'); END;").map_err(|e| map_sql(&e))).unwrap();
        assert!(store
            .claim_destruction(&parent.lid, pending.occ_version, chrono::Utc::now())
            .await
            .is_err());
        assert!(store
            .destroyed_wrapping_parents(&request.record.lid)
            .await
            .unwrap()
            .is_empty());
        store
            .with_conn(|conn| {
                conn.execute_batch("DROP TRIGGER reject_initial_claim;")
                    .map_err(|e| map_sql(&e))
            })
            .unwrap();
        let claim = store
            .claim_destruction(&parent.lid, pending.occ_version, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        let operation = claim.operation();
        store.with_conn(|conn| conn.execute_batch("CREATE TRIGGER reject_completion BEFORE UPDATE ON destruction_journal BEGIN SELECT RAISE(ABORT,'injected completion failure'); END;").map_err(|e| map_sql(&e))).unwrap();
        assert!(store.complete_destruction(claim).await.is_err());
        drop(store);
        let reopened = SqliteStorage::open(&path).unwrap();
        let markers = reopened
            .destroyed_wrapping_parents(&request.record.lid)
            .await
            .unwrap();
        assert_eq!(
            markers,
            vec![DestroyedWrappingParent {
                version: 1,
                parent_lid: parent.lid,
                parent_version: 1
            }]
        );
        assert!(matches!(
            reopened.wrapped_key_snapshot(&request.record.lid, 1).await,
            Err(KeyRackError::WrappingParentDestroyed)
        ));
        let current = reopened.get_key(&parent.lid).await.unwrap();
        assert_eq!(current.state, KeyState::PendingDeletion);
        let recovered = reopened
            .claim_destruction(&parent.lid, current.occ_version, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        assert!(recovered.is_recovered());
        assert_eq!(recovered.operation(), operation);
        reopened
            .with_conn(|conn| {
                conn.execute_batch("DROP TRIGGER reject_completion;")
                    .map_err(|e| map_sql(&e))
            })
            .unwrap();
        assert_eq!(
            reopened
                .complete_destruction(recovered)
                .await
                .unwrap()
                .state,
            KeyState::Destroyed
        );
    }

    #[tokio::test]
    async fn schedule_returns_logical_children_from_admission_snapshot() {
        for children in [0, 2] {
            let store = SqliteStorage::in_memory().unwrap();
            let parent = unique_test_key_record(KeyState::Enabled);
            store.create_key(&parent).await.unwrap();
            for _ in 0..children {
                let mut child = unique_test_key_record(KeyState::Enabled);
                child.parent_lid = Some(parent.lid);
                let mut historical = child.key_versions[0].clone();
                historical.version_number = 2;
                historical.is_primary = false;
                child.key_versions.push(historical);
                store.create_key(&child).await.unwrap();
            }
            let result = store
                .schedule_destruction(&parent.lid, parent.occ_version, chrono::Utc::now(), false)
                .await
                .unwrap();
            assert_eq!(result.logical_only_children, children);
            assert_eq!(result.record.state, KeyState::PendingDeletion);
            assert!(keyrack_core::creation::same_json(
                &result.record,
                &store.get_key(&parent.lid).await.unwrap()
            )
            .unwrap());
            let intent = store.deletion_intent(&parent.lid).await.unwrap().unwrap();
            assert!(!intent.allow_dependent_data_loss);
            assert!(intent.approved_dependents.is_empty());
        }
    }

    #[tokio::test]
    async fn generic_schedule_changes_cannot_reuse_approval() {
        let store = SqliteStorage::in_memory().unwrap();
        let key = unique_test_key_record(KeyState::Enabled);
        store.create_key(&key).await.unwrap();
        let mut scheduled = store
            .schedule_destruction(&key.lid, key.occ_version, chrono::Utc::now(), true)
            .await
            .unwrap()
            .record;
        scheduled.description = "ordinary metadata update".into();
        scheduled.occ_version += 1;
        store.update_key(&scheduled).await.unwrap();
        assert!(
            store
                .deletion_intent(&key.lid)
                .await
                .unwrap()
                .unwrap()
                .allow_dependent_data_loss
        );
        scheduled.scheduled_deletion_at = Some(chrono::Utc::now() + chrono::Duration::days(1));
        scheduled.occ_version += 1;
        store.update_key(&scheduled).await.unwrap();
        assert!(store.deletion_intent(&key.lid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn approved_parent_destruction_preserves_child_and_envelope_with_marker() {
        let store = SqliteStorage::in_memory().unwrap();
        let (parent, request) = published(&store).await;
        assert!(store
            .schedule_destruction(&parent.lid, parent.occ_version, chrono::Utc::now(), false)
            .await
            .is_err());
        let before = store.get_key(&request.record.lid).await.unwrap();
        let bytes = store
            .read_creation_envelope(request.operation)
            .await
            .unwrap();
        let pending = store
            .schedule_destruction(&parent.lid, parent.occ_version, chrono::Utc::now(), true)
            .await
            .unwrap()
            .record;
        let intent = store.deletion_intent(&parent.lid).await.unwrap().unwrap();
        assert_eq!(intent.approved_dependents.len(), 1);
        let claim = store
            .claim_destruction(&parent.lid, pending.occ_version, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        // The durable decision is visible before provider deletion or completion.
        assert_eq!(
            store.destroyed_wrapping_parents(&before.lid).await.unwrap(),
            vec![DestroyedWrappingParent {
                version: 1,
                parent_lid: parent.lid,
                parent_version: 1
            }]
        );
        assert!(matches!(
            store.wrapped_key_snapshot(&before.lid, 1).await,
            Err(KeyRackError::WrappingParentDestroyed)
        ));
        assert_eq!(
            store.complete_destruction(claim).await.unwrap().state,
            KeyState::Destroyed
        );
        assert!(keyrack_core::creation::same_json(
            &before,
            &store.get_key(&before.lid).await.unwrap()
        )
        .unwrap());
        assert_eq!(
            store
                .read_creation_envelope(request.operation)
                .await
                .unwrap(),
            bytes
        );
        assert_eq!(
            store.destroyed_wrapping_parents(&before.lid).await.unwrap(),
            vec![DestroyedWrappingParent {
                version: 1,
                parent_lid: parent.lid,
                parent_version: 1
            }]
        );
        // A lost parent does not strand the child's independently authorized
        // envelope-erasure lifecycle behind the parent's permanent fence.
        let pending_child = store
            .schedule_destruction(&before.lid, before.occ_version, chrono::Utc::now(), false)
            .await
            .unwrap()
            .record;
        let child_claim = store
            .claim_destruction(&before.lid, pending_child.occ_version, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        store.complete_destruction(child_claim).await.unwrap();
        assert!(store
            .read_creation_envelope(request.operation)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn new_dependent_or_new_version_is_outside_approved_snapshot() {
        for new_key in [false, true] {
            let store = SqliteStorage::in_memory().unwrap();
            let (parent, request) = published(&store).await;
            let pending = store
                .schedule_destruction(&parent.lid, parent.occ_version, chrono::Utc::now(), true)
                .await
                .unwrap()
                .record;
            let mut child = store.get_key(&request.record.lid).await.unwrap();
            if new_key {
                child.lid = unique_test_key_record(KeyState::Enabled).lid;
                store.create_key(&child).await.unwrap();
            } else {
                // Simulate a newly published version in a competing writer; the
                // claim must detect it even when the dependent LID is unchanged.
                let mut version = child.key_versions[0].clone();
                version.version_number = 2;
                version.is_primary = false;
                child.key_versions.push(version);
                child.occ_version += 1;
                store
                    .creation_tx(|conn| save_key(conn, &child, child.occ_version - 1))
                    .unwrap();
            }
            let error = store
                .claim_destruction(&parent.lid, pending.occ_version, chrono::Utc::now())
                .await
                .unwrap_err();
            assert!(
                matches!(error,KeyRackError::DeletionDependencyRefused {ref reason,..} if reason=="dependent_outside_approved_snapshot")
            );
            assert_eq!(
                store.get_key(&parent.lid).await.unwrap().state,
                KeyState::PendingDeletion
            );
            assert_eq!(
                store
                    .with_conn(|c| c
                        .query_row("SELECT COUNT(*) FROM destruction_journal", [], |r| r
                            .get::<_, i64>(0))
                        .map_err(|e| map_sql(&e)))
                    .unwrap(),
                0
            );
        }
    }

    #[tokio::test]
    async fn live_envelope_index_remains_dependency_without_child_descriptor() {
        let store = SqliteStorage::in_memory().unwrap();
        let (parent, request) = published(&store).await;
        store
            .creation_tx(|c| {
                c.execute(
                    "DELETE FROM keys WHERE lid=?1",
                    [request.record.lid.to_string()],
                )
                .map(|_| ())
                .map_err(|e| map_sql(&e))
            })
            .unwrap();
        assert_eq!(
            store
                .destruction_dependencies(&parent.lid)
                .await
                .unwrap()
                .dependents
                .len(),
            1
        );
        assert!(store
            .schedule_destruction(&parent.lid, parent.occ_version, chrono::Utc::now(), false)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn wrapped_child_erasure_is_atomic_with_terminal_metadata() {
        for rollback in [false, true] {
            let store = SqliteStorage::in_memory().unwrap();
            let (parent, request) = published(&store).await;
            let child = store.get_key(&request.record.lid).await.unwrap();
            let pending = store
                .schedule_destruction(&child.lid, child.occ_version, chrono::Utc::now(), false)
                .await
                .unwrap()
                .record;
            let claim = store
                .claim_destruction(&child.lid, pending.occ_version, chrono::Utc::now())
                .await
                .unwrap()
                .unwrap();
            if rollback {
                store.with_conn(|c|c.execute_batch("CREATE TRIGGER refuse_terminal_write BEFORE UPDATE ON destruction_journal BEGIN SELECT RAISE(ABORT,'injected failure'); END;").map_err(|e|map_sql(&e))).unwrap();
                assert!(store.complete_destruction(claim).await.is_err());
                assert!(store
                    .read_creation_envelope(request.operation)
                    .await
                    .is_ok());
                assert_eq!(
                    store.get_key(&child.lid).await.unwrap().state,
                    KeyState::PendingDeletion
                );
            } else {
                assert_eq!(
                    store.complete_destruction(claim).await.unwrap().state,
                    KeyState::Destroyed
                );
                assert!(store
                    .read_creation_envelope(request.operation)
                    .await
                    .is_err());
                assert_eq!(
                    store.get_creation(request.operation).await.unwrap().phase,
                    keyrack_core::creation::CreationPhase::Committed
                );
                assert!(store
                    .destruction_dependencies(&parent.lid)
                    .await
                    .unwrap()
                    .is_empty());
            }
        }
    }

    #[tokio::test]
    async fn migrated_child_erasure_removes_all_version_envelopes() {
        let store = SqliteStorage::in_memory().unwrap();
        let (request, creations) =
            keyrack_test_support::migration_conformance::seeded(&store).await;
        store.reserve_migration(&request).await.unwrap();
        store
            .stage_migration(
                request.operation,
                keyrack_test_support::migration_conformance::test_owner(&store, request.operation)
                    .await,
                &keyrack_test_support::migration_conformance::envelopes(),
            )
            .await
            .unwrap();
        let child = store
            .commit_migration(
                request.operation,
                keyrack_test_support::migration_conformance::test_owner(&store, request.operation)
                    .await,
            )
            .await
            .unwrap();
        let pending = store
            .schedule_destruction(&child.lid, child.occ_version, chrono::Utc::now(), false)
            .await
            .unwrap()
            .record;
        let claim = store
            .claim_destruction(&child.lid, pending.occ_version, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        store.complete_destruction(claim).await.unwrap();
        for creation in creations {
            assert!(store
                .read_creation_envelope(creation.operation)
                .await
                .is_err());
        }
        for version in [1, 2] {
            assert!(store
                .read_migration_envelope(request.operation, version)
                .await
                .is_err());
        }
        assert!(store
            .destruction_dependencies(&request.new_parent.lid)
            .await
            .unwrap()
            .is_empty());
        assert!(store
            .destruction_dependencies(&request.old_parent.lid)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn migrated_child_deletion_refuses_phase_index_mismatch() {
        for corrupt_after_schedule in [false, true] {
            let store = SqliteStorage::in_memory().unwrap();
            let (request, _) = keyrack_test_support::migration_conformance::seeded(&store).await;
            store.reserve_migration(&request).await.unwrap();
            let staged = store
                .stage_migration(
                    request.operation,
                    keyrack_test_support::migration_conformance::test_owner(
                        &store,
                        request.operation,
                    )
                    .await,
                    &keyrack_test_support::migration_conformance::envelopes(),
                )
                .await
                .unwrap();
            let mut child = store
                .commit_migration(
                    request.operation,
                    keyrack_test_support::migration_conformance::test_owner(
                        &store,
                        request.operation,
                    )
                    .await,
                )
                .await
                .unwrap();
            if corrupt_after_schedule {
                child = store
                    .schedule_destruction(&child.lid, child.occ_version, chrono::Utc::now(), false)
                    .await
                    .unwrap()
                    .record;
            }
            // Leave the SQL index committed while restoring valid staged JSON.
            // Neither the digest count nor material binding alone detects this.
            store
                .with_conn(|conn| {
                    conn.execute(
                        "UPDATE migration_journal SET journal_json=?1 WHERE operation_id=?2",
                        params![
                            serde_json::to_string(&staged).unwrap(),
                            request.operation.to_string()
                        ],
                    )
                    .map_err(|error| map_sql(&error))?;
                    Ok(())
                })
                .unwrap();
            let error = if corrupt_after_schedule {
                store
                    .claim_destruction(&child.lid, child.occ_version, chrono::Utc::now())
                    .await
                    .unwrap_err()
            } else {
                store
                    .schedule_destruction(&child.lid, child.occ_version, chrono::Utc::now(), false)
                    .await
                    .unwrap_err()
            };
            assert!(error
                .to_string()
                .contains("owned migration envelope binding mismatch"));
            assert!(keyrack_core::creation::same_json(
                &child,
                &store.get_key(&child.lid).await.unwrap()
            )
            .unwrap());
            assert!(!store
                .with_conn(|conn| conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM destruction_journal WHERE lid=?1)",
                        [child.lid.to_string()],
                        |row| row.get::<_, bool>(0)
                    )
                    .map_err(|error| map_sql(&error)))
                .unwrap());
        }
    }

    #[tokio::test]
    async fn claim_refuses_in_flight_journals_despite_persisted_approval() {
        for migration in [false, true] {
            let store = SqliteStorage::in_memory().unwrap();
            let mut target = if migration {
                let (request, _) =
                    keyrack_test_support::migration_conformance::seeded(&store).await;
                store.reserve_migration(&request).await.unwrap();
                request.old_parent
            } else {
                let (parent, request) = keyrack_test_support::creation_conformance::fixture();
                store.create_key(&parent).await.unwrap();
                store.reserve_creation(&request).await.unwrap();
                parent
            };
            let observed = store.destruction_dependencies(&target.lid).await.unwrap();
            let approved = DeletionIntent {
                allow_dependent_data_loss: true,
                approved_dependents: observed.dependents,
            };
            let at = chrono::Utc::now();
            let prior_occ = target.occ_version;
            target.state = KeyState::PendingDeletion;
            target.scheduled_deletion_at = Some(at);
            target.occ_version += 1;
            // Install a coherent legacy/racing schedule directly: normal admission
            // refuses the active journal. This isolates the fenced claim recheck.
            store.creation_tx(|conn| {
                save_key(conn, &target, prior_occ)?;
                conn.execute(
                    "INSERT INTO deletion_schedules(lid,scheduled_at,intent_json) VALUES(?1,?2,?3)",
                    params![target.lid.to_string(), at.to_rfc3339(), serde_json::to_string(&approved).unwrap()],
                ).map_err(|error| map_sql(&error))?;
                Ok(())
            }).unwrap();
            assert_eq!(
                store.deletion_intent(&target.lid).await.unwrap(),
                Some(approved)
            );
            let error = store
                .claim_destruction(&target.lid, target.occ_version, at)
                .await
                .unwrap_err();
            assert!(
                matches!(error, KeyRackError::DeletionDependencyRefused { ref reason, .. } if reason == "in_flight_journal")
            );
            assert!(keyrack_core::creation::same_json(
                &target,
                &store.get_key(&target.lid).await.unwrap()
            )
            .unwrap());
            assert!(!store
                .with_conn(|conn| conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM destruction_journal WHERE lid=?1)",
                        [target.lid.to_string()],
                        |row| row.get::<_, bool>(0)
                    )
                    .map_err(|error| map_sql(&error)))
                .unwrap());
        }
    }

    #[tokio::test]
    async fn nonterminal_migration_roles_refuse_even_with_override() {
        for staged in [false, true] {
            let store = SqliteStorage::in_memory().unwrap();
            let (request, _) = keyrack_test_support::migration_conformance::seeded(&store).await;
            store.reserve_migration(&request).await.unwrap();
            if staged {
                store
                    .stage_migration(
                        request.operation,
                        keyrack_test_support::migration_conformance::test_owner(
                            &store,
                            request.operation,
                        )
                        .await,
                        &keyrack_test_support::migration_conformance::envelopes(),
                    )
                    .await
                    .unwrap();
            }
            for key in [&request.child, &request.old_parent, &request.new_parent] {
                assert_eq!(
                    store
                        .destruction_dependencies(&key.lid)
                        .await
                        .unwrap()
                        .migration_journal_rows,
                    1
                );
                let error = store
                    .schedule_destruction(&key.lid, key.occ_version, chrono::Utc::now(), true)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error,KeyRackError::DeletionDependencyRefused {ref reason,..} if reason=="in_flight_journal")
                );
            }
        }
    }
}
