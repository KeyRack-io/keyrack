// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{creation, destruction, map_sql, SqliteStorage};
use keyrack_core::creation::same_json;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::{KeyMaterial, KeyRecord};
use keyrack_core::lid::Lid;
use keyrack_core::migration::{
    migration_busy, migration_invalid as invalid, MigrationJournal, MigrationOwnership,
    MigrationPhase, MigrationRequest, WrappedKeySnapshot,
};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS migration_journal (
 operation_id TEXT PRIMARY KEY, child_lid TEXT NOT NULL, old_parent_lid TEXT NOT NULL,
 new_parent_lid TEXT NOT NULL, committed INTEGER NOT NULL CHECK(committed IN (0,1)), journal_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_migration_child ON migration_journal(child_lid,committed);
CREATE INDEX IF NOT EXISTS idx_migration_old_parent ON migration_journal(old_parent_lid,committed);
CREATE INDEX IF NOT EXISTS idx_migration_new_parent ON migration_journal(new_parent_lid,committed);
CREATE TABLE IF NOT EXISTS migration_envelopes (
 operation_id TEXT NOT NULL, version TEXT NOT NULL, envelope BLOB NOT NULL CHECK(length(envelope) BETWEEN 1 AND 65536),
 PRIMARY KEY(operation_id,version)
);
CREATE TABLE IF NOT EXISTS retired_creation_journal (operation_id TEXT PRIMARY KEY, journal_json TEXT NOT NULL);
";

pub(super) fn guard(conn: &Connection, lid: &Lid) -> Result<()> {
    let active: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM migration_journal WHERE committed=0 AND (child_lid=?1 OR old_parent_lid=?1 OR new_parent_lid=?1))",
        [lid.to_string()], |row| row.get(0)).map_err(|e| map_sql(&e))?;
    if active {
        return Err(migration_busy());
    }
    Ok(())
}

pub(super) fn guard_record(conn: &Connection, record: &KeyRecord) -> Result<()> {
    guard(conn, &record.lid)?;
    if let Some(parent) = record.parent_lid {
        guard(conn, &parent)?;
    }
    for version in &record.key_versions {
        if let KeyMaterial::ParentWrapped(material) = &version.material {
            guard(conn, &material.parent().lid)?;
        }
    }
    Ok(())
}

pub(super) fn guard_update(
    conn: &Connection,
    previous: &KeyRecord,
    next: &KeyRecord,
) -> Result<()> {
    guard_record(conn, previous)?;
    guard_record(conn, next)?;
    if previous.parent_lid != next.parent_lid {
        return Err(invalid("parent_lid may change only through migration"));
    }
    if previous
        .key_versions
        .iter()
        .any(|version| matches!(version.material, KeyMaterial::ParentWrapped(_)))
    {
        keyrack_core::creation::guard_referenced_parent(previous, next)?;
        if !same_json(&previous.key_versions, &next.key_versions)? {
            return Err(invalid(
                "wrapped history may change only through journal publication",
            ));
        }
    }

    let referenced: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM migration_journal j JOIN migration_envelopes e ON e.operation_id=j.operation_id WHERE j.new_parent_lid=?1)", [next.lid.to_string()], |row|row.get(0)).map_err(|e|map_sql(&e))?;
    if referenced {
        keyrack_core::creation::guard_referenced_parent(previous, next)?;
    }
    Ok(())
}

fn load(conn: &Connection, operation: Uuid) -> Result<Option<MigrationJournal>> {
    let row: Option<(String,String,String,String,bool)> = conn.query_row(
        "SELECT journal_json,child_lid,old_parent_lid,new_parent_lid,committed FROM migration_journal WHERE operation_id=?1",
        [operation.to_string()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))
        .optional().map_err(|e| map_sql(&e))?;
    row.map(|(json, child, old, new, committed)| {
        let value: MigrationJournal =
            serde_json::from_str(&json).map_err(|_| invalid("invalid journal"))?;
        value.validate()?;
        if value.request.operation != operation
            || child != value.request.child.lid.to_string()
            || old != value.request.old_parent.lid.to_string()
            || new != value.request.new_parent.lid.to_string()
            || committed != (value.phase == MigrationPhase::Committed)
        {
            return Err(invalid("journal index mismatch"));
        }
        Ok(value)
    })
    .transpose()
}

fn required(conn: &Connection, operation: Uuid) -> Result<MigrationJournal> {
    load(conn, operation)?.ok_or_else(|| invalid("migration not found"))
}

fn save(conn: &Connection, value: &MigrationJournal) -> Result<()> {
    value.validate()?;
    conn.execute(
        "UPDATE migration_journal SET journal_json=?1,committed=?2 WHERE operation_id=?3",
        params![
            serde_json::to_string(value).map_err(|_| invalid("journal encoding"))?,
            value.phase == MigrationPhase::Committed,
            value.request.operation.to_string()
        ],
    )
    .map_err(|e| map_sql(&e))?;
    Ok(())
}

fn snapshots(conn: &Connection, request: &MigrationRequest) -> Result<()> {
    let child = creation::key(conn, &request.child.lid)?
        .ok_or(KeyRackError::KeyNotFound(request.child.lid))?;
    let old = creation::key(conn, &request.old_parent.lid)?
        .ok_or(KeyRackError::KeyNotFound(request.old_parent.lid))?;
    let new = creation::key(conn, &request.new_parent.lid)?
        .ok_or(KeyRackError::KeyNotFound(request.new_parent.lid))?;
    for record in [&child, &old, &new] {
        destruction::guard(conn, &record.lid)?;
    }
    request.validate_snapshots(&child, &old, &new)
}

fn envelope_ref(conn: &Connection, reference: &str) -> Result<Vec<u8>> {
    if let Some(operation) = reference.strip_prefix("creation:") {
        let operation: Uuid = operation
            .parse()
            .map_err(|_| invalid("invalid creation envelope reference"))?;
        return creation::committed_envelope(conn, operation);
    }
    if let Some((operation, version)) = reference
        .strip_prefix("migration:")
        .and_then(|v| v.split_once(':'))
    {
        let operation: Uuid = operation
            .parse()
            .map_err(|_| invalid("invalid migration envelope reference"))?;
        let version: u64 = version
            .parse()
            .map_err(|_| invalid("invalid migration version"))?;
        let value = required(conn, operation)?;
        if value.phase != MigrationPhase::Committed {
            return Err(invalid("migration envelope is not committed"));
        }
        let bytes: Vec<u8> = conn
            .query_row(
                "SELECT envelope FROM migration_envelopes WHERE operation_id=?1 AND version=?2",
                params![operation.to_string(), version.to_string()],
                |row| row.get(0),
            )
            .map_err(|e| map_sql(&e))?;
        value.verify_envelope(version, &bytes)?;
        return Ok(bytes);
    }
    Err(invalid("unknown wrapped envelope reference"))
}

impl SqliteStorage {
    pub(super) fn migration_reserve(&self, request: &MigrationRequest) -> Result<MigrationJournal> {
        request.validate()?;
        self.creation_tx(|conn| {
            if let Some(existing) = load(conn, request.operation)? {
                if !existing.request.same_intent(request)? { return Err(KeyRackError::MigrationIntentConflict { operation: request.operation }); }
                return Ok(existing);
            }
            snapshots(conn, request)?;
            for record in [&request.child,&request.old_parent,&request.new_parent] {
                guard(conn, &record.lid)?;
                let pending: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM creation_journal WHERE phase!='committed' AND (child_lid=?1 OR parent_lid=?1))",
                    [record.lid.to_string()], |row| row.get(0)).map_err(|e| map_sql(&e))?;
                if pending { return Err(migration_busy()); }
            }
            let value = MigrationJournal::reserved(request.clone());
            conn.execute("INSERT INTO migration_journal(operation_id,child_lid,old_parent_lid,new_parent_lid,committed,journal_json) VALUES(?1,?2,?3,?4,0,?5)",
                params![request.operation.to_string(),request.child.lid.to_string(),request.old_parent.lid.to_string(),request.new_parent.lid.to_string(),
                serde_json::to_string(&value).map_err(|_| invalid("journal encoding"))?]).map_err(|e| map_sql(&e))?;
            Ok(value)
        })
    }

    pub(super) fn migration_get(&self, operation: Uuid) -> Result<Option<MigrationJournal>> {
        self.with_conn(|conn| load(conn, operation))
    }

    pub(super) fn migration_claim(
        &self,
        operation: Uuid,
        owner: Uuid,
        expected_epoch: u64,
    ) -> Result<MigrationJournal> {
        self.creation_tx(|conn| {
            let mut value = required(conn, operation)?;
            value.claim(owner, expected_epoch)?;
            save(conn, &value)?;
            Ok(value)
        })
    }

    pub(super) fn migration_dispatch(
        &self,
        operation: Uuid,
        ownership: MigrationOwnership,
        retry_safe: bool,
    ) -> Result<MigrationJournal> {
        self.creation_tx(|conn| {
            let mut value = required(conn, operation)?;
            value.begin_dispatch(ownership, retry_safe)?;
            save(conn, &value)?;
            Ok(value)
        })
    }

    pub(super) fn migration_snapshot(&self, lid: &Lid, version: u64) -> Result<WrappedKeySnapshot> {
        self.creation_tx(|conn| {
            let record = creation::key(conn, lid)?.ok_or(KeyRackError::KeyNotFound(*lid))?;
            let entry = record
                .get_version(version)
                .ok_or_else(|| invalid("wrapped version absent"))?;
            let KeyMaterial::ParentWrapped(material) = &entry.material else {
                return Err(invalid("version is not wrapped"));
            };
            let loss_decided: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM destruction_journal WHERE lid=?1) OR EXISTS(SELECT 1 FROM destroyed_wrapping_parents WHERE parent_lid=?1 AND parent_version=?2 AND child_lid=?3 AND child_version=?4)",
                    rusqlite::params![material.parent().lid.to_string(), material.parent().version.get().to_string(), lid.to_string(), version.to_string()],
                    |row| row.get(0),
                )
                .map_err(|e| map_sql(&e))?;
            if loss_decided {
                return Err(KeyRackError::WrappingParentDestroyed);
            }
            let envelope = envelope_ref(conn, material.wrapped_material_ref().as_str())?;
            let parent = creation::key(conn, &material.parent().lid)?
                .ok_or(KeyRackError::WrappingParentDestroyed)?;
            if parent.state == keyrack_core::key::KeyState::Destroyed {
                return Err(KeyRackError::WrappingParentDestroyed);
            }
            Ok(WrappedKeySnapshot {
                record,
                parent,
                envelope,
            })
        })
    }

    pub(super) fn migration_stage(
        &self,
        operation: Uuid,
        ownership: MigrationOwnership,
        envelopes: &[Vec<u8>],
    ) -> Result<MigrationJournal> {
        self.creation_tx(|conn| {
            let mut value = required(conn,operation)?;
            value.require_owner(ownership)?;
            value.validate_envelopes(envelopes)?;
            if value.phase != MigrationPhase::Reserved { return Ok(value); }
            if value.dispatch.as_ref().map(|d| d.epoch) != Some(ownership.epoch) { return Err(invalid("provider dispatch belongs to another ownership epoch")); }
            snapshots(conn,&value.request)?;
            for (version,envelope) in value.request.proposed.key_versions.iter().zip(envelopes) {
                conn.execute("INSERT INTO migration_envelopes(operation_id,version,envelope) VALUES(?1,?2,?3)",
                    params![operation.to_string(),version.version_number.to_string(),envelope]).map_err(|e| map_sql(&e))?;
            }
            value.record_envelope_digests(envelopes);
            value.phase = MigrationPhase::Staged;
            save(conn,&value)?;
            Ok(value)
        })
    }

    pub(super) fn migration_commit(
        &self,
        operation: Uuid,
        ownership: MigrationOwnership,
    ) -> Result<KeyRecord> {
        self.creation_tx(|conn| {
            let mut value = required(conn,operation)?;
            value.require_owner(ownership)?;
            if value.phase == MigrationPhase::Committed { return Ok(value.request.proposed); }
            if value.phase != MigrationPhase::Staged { return Err(invalid("envelopes not staged")); }
            snapshots(conn,&value.request)?;
            let count: i64 = conn.query_row("SELECT count(*) FROM migration_envelopes WHERE operation_id=?1",[operation.to_string()],|r|r.get(0)).map_err(|e|map_sql(&e))?;
            if usize::try_from(count).ok()!=Some(value.request.child.key_versions.len()) { return Err(invalid("incomplete staged envelopes")); }
            for version in &value.request.proposed.key_versions {
                let bytes: Vec<u8> = conn.query_row("SELECT envelope FROM migration_envelopes WHERE operation_id=?1 AND version=?2",
                    params![operation.to_string(),version.version_number.to_string()],|row|row.get(0)).map_err(|e|map_sql(&e))?;
                value.verify_envelope(version.version_number,&bytes)?;
            }
            let mut old_envelopes = Vec::new();
            for version in &value.request.child.key_versions {
                let KeyMaterial::ParentWrapped(material) = &version.material else { return Err(invalid("resident child version")); };
                old_envelopes.push(envelope_ref(conn, material.wrapped_material_ref().as_str())?);
            }
            value.result = Some(value.terminal_result(&old_envelopes)?);
            // Retain only idempotency metadata. Old live dependencies and bytes disappear in this transaction.
            conn.execute("INSERT INTO retired_creation_journal(operation_id,journal_json) SELECT operation_id,journal_json FROM creation_journal WHERE child_lid=?1 AND phase='committed'",[value.request.child.lid.to_string()]).map_err(|e|map_sql(&e))?;
            conn.execute("DELETE FROM creation_journal WHERE child_lid=?1 AND phase='committed'",[value.request.child.lid.to_string()]).map_err(|e|map_sql(&e))?;
            conn.execute("DELETE FROM migration_envelopes WHERE operation_id IN (SELECT operation_id FROM migration_journal WHERE child_lid=?1 AND committed=1)",[value.request.child.lid.to_string()]).map_err(|e|map_sql(&e))?;
            let proposed = &value.request.proposed;
            let rows = conn.execute("UPDATE keys SET record_json=?1,occ_version=?2 WHERE lid=?3 AND occ_version=?4",
                params![serde_json::to_string(proposed).map_err(|_|invalid("record encoding"))?,i64::try_from(proposed.occ_version).map_err(|_|invalid("OCC overflow"))?,proposed.lid.to_string(),i64::try_from(value.request.child.occ_version).map_err(|_|invalid("OCC overflow"))?]).map_err(|e|map_sql(&e))?;
            if rows!=1 { return Err(migration_busy()); }
            value.phase=MigrationPhase::Committed;
            save(conn,&value)?;
            Ok(value.request.proposed)
        })
    }

    pub(super) fn migration_read(&self, operation: Uuid, version: u64) -> Result<Vec<u8>> {
        self.with_conn(|conn| {
            let value = required(conn, operation)?;
            if value.phase != MigrationPhase::Committed {
                return Err(invalid("migration is not committed"));
            }
            let bytes: Vec<u8> = conn
                .query_row(
                    "SELECT envelope FROM migration_envelopes WHERE operation_id=?1 AND version=?2",
                    params![operation.to_string(), version.to_string()],
                    |row| row.get(0),
                )
                .map_err(|e| map_sql(&e))?;
            value.verify_envelope(version, &bytes)?;
            Ok(bytes)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyrack_core::storage::StorageBackend;
    use keyrack_test_support::migration_conformance::{envelopes, seeded, test_owner};

    #[tokio::test]
    async fn migration_reopens_at_every_durable_phase() {
        let path =
            std::env::temp_dir().join(format!("keyrack-migration-{}.sqlite", Uuid::new_v4()));
        let store = SqliteStorage::open(&path).unwrap();
        let (request, creations) = seeded(&store).await;
        store.reserve_migration(&request).await.unwrap();
        drop(store);
        let store = SqliteStorage::open(&path).unwrap();
        assert_eq!(
            store
                .get_migration(request.operation)
                .await
                .unwrap()
                .unwrap()
                .phase,
            MigrationPhase::Reserved
        );
        assert!(same_json(
            &store.get_key(&request.child.lid).await.unwrap(),
            &request.child
        )
        .unwrap());
        store
            .stage_migration(
                request.operation,
                test_owner(&store, request.operation).await,
                &envelopes(),
            )
            .await
            .unwrap();
        drop(store);
        let store = SqliteStorage::open(&path).unwrap();
        assert_eq!(
            store
                .get_migration(request.operation)
                .await
                .unwrap()
                .unwrap()
                .phase,
            MigrationPhase::Staged
        );
        assert!(same_json(
            &store.get_key(&request.child.lid).await.unwrap(),
            &request.child
        )
        .unwrap());
        store
            .commit_migration(
                request.operation,
                test_owner(&store, request.operation).await,
            )
            .await
            .unwrap();
        drop(store);
        let store = SqliteStorage::open(&path).unwrap();
        assert_eq!(
            store
                .get_migration(request.operation)
                .await
                .unwrap()
                .unwrap()
                .phase,
            MigrationPhase::Committed
        );
        assert!(same_json(
            &store
                .commit_migration(
                    request.operation,
                    test_owner(&store, request.operation).await
                )
                .await
                .unwrap(),
            &request.proposed
        )
        .unwrap());
        for creation in creations {
            assert!(store
                .read_creation_envelope(creation.operation)
                .await
                .is_err());
        }
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn migration_commit_rollback_restores_old_envelopes_and_fence() {
        let store = SqliteStorage::in_memory().unwrap();
        let (request, creations) = seeded(&store).await;
        store.reserve_migration(&request).await.unwrap();
        store
            .stage_migration(
                request.operation,
                test_owner(&store, request.operation).await,
                &envelopes(),
            )
            .await
            .unwrap();
        store.with_conn(|conn| {
            conn.execute_batch("CREATE TRIGGER reject_migration_commit BEFORE UPDATE ON keys BEGIN SELECT RAISE(ABORT,'injected commit failure'); END;").map_err(|e|map_sql(&e))
        }).unwrap();
        assert!(store
            .commit_migration(
                request.operation,
                test_owner(&store, request.operation).await
            )
            .await
            .is_err());
        assert_eq!(
            store
                .get_migration(request.operation)
                .await
                .unwrap()
                .unwrap()
                .phase,
            MigrationPhase::Staged
        );
        assert!(same_json(
            &store.get_key(&request.child.lid).await.unwrap(),
            &request.child
        )
        .unwrap());
        for creation in creations {
            assert!(store
                .read_creation_envelope(creation.operation)
                .await
                .is_ok());
        }
        assert!(matches!(
            store.check_migration_fence(&request.old_parent.lid).await,
            Err(KeyRackError::ProviderUnavailable(_))
        ));
        store
            .with_conn(|conn| {
                conn.execute_batch("DROP TRIGGER reject_migration_commit;")
                    .map_err(|e| map_sql(&e))
            })
            .unwrap();
        store
            .commit_migration(
                request.operation,
                test_owner(&store, request.operation).await,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn migration_commit_rechecks_every_occ() {
        for subject in 0..3 {
            let store = SqliteStorage::in_memory().unwrap();
            let (request, _) = seeded(&store).await;
            store.reserve_migration(&request).await.unwrap();
            store
                .stage_migration(
                    request.operation,
                    test_owner(&store, request.operation).await,
                    &envelopes(),
                )
                .await
                .unwrap();
            let mut tampered = match subject {
                0 => request.child.clone(),
                1 => request.old_parent.clone(),
                _ => request.new_parent.clone(),
            };
            tampered.occ_version += 1;
            store
                .with_conn(|conn| {
                    conn.execute(
                        "UPDATE keys SET record_json=?1,occ_version=?2 WHERE lid=?3",
                        params![
                            serde_json::to_string(&tampered).unwrap(),
                            i64::try_from(tampered.occ_version).unwrap(),
                            tampered.lid.to_string()
                        ],
                    )
                    .map_err(|e| map_sql(&e))?;
                    Ok(())
                })
                .unwrap();
            assert!(
                store
                    .commit_migration(
                        request.operation,
                        test_owner(&store, request.operation).await
                    )
                    .await
                    .is_err(),
                "commit must recheck each snapshot OCC"
            );
            assert_eq!(
                store
                    .get_migration(request.operation)
                    .await
                    .unwrap()
                    .unwrap()
                    .phase,
                MigrationPhase::Staged
            );
        }
    }

    #[tokio::test]
    async fn migration_reservation_checks_destruction_fence_independently() {
        let store = SqliteStorage::in_memory().unwrap();
        let (request, _) = seeded(&store).await;
        // Synthetic persisted fence with unchanged eligible metadata isolates the fence
        // check from the state and OCC checks, which normal destruction also changes.
        store.with_conn(|conn| {
            conn.execute("INSERT INTO destruction_journal(lid,operation_id,record_json,completed) VALUES(?1,?2,?3,0)",
                params![request.new_parent.lid.to_string(),Uuid::new_v4().to_string(),serde_json::to_string(&request.new_parent).unwrap()]).map_err(|e|map_sql(&e))?;
            Ok(())
        }).unwrap();
        assert!(
            matches!(
                store.reserve_migration(&request).await,
                Err(KeyRackError::KeyDestructionFenced(_))
            ),
            "target destruction fence must reject reservation independently"
        );
    }
    #[tokio::test]
    async fn migration_blocks_due_unreferenced_target_destruction() {
        let store = SqliteStorage::in_memory().unwrap();
        let (request, _) = seeded(&store).await;
        store.reserve_migration(&request).await.unwrap();
        let mut due = request.new_parent.clone();
        due.state = keyrack_core::key::KeyState::PendingDeletion;
        due.scheduled_deletion_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        due.occ_version += 1;
        // Bypass the update guard to isolate destruction's own dependency query.
        store
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE keys SET record_json=?1,occ_version=?2 WHERE lid=?3",
                    params![
                        serde_json::to_string(&due).unwrap(),
                        i64::try_from(due.occ_version).unwrap(),
                        due.lid.to_string()
                    ],
                )
                .map_err(|e| map_sql(&e))?;
                Ok(())
            })
            .unwrap();
        assert!(
            matches!(
                store
                    .claim_destruction(&due.lid, due.occ_version, chrono::Utc::now())
                    .await,
                Err(KeyRackError::DeletionDependencyRefused { ref reason, .. })
                    if reason == "in_flight_journal"
            ),
            "migration journal alone must block target destruction"
        );
    }
    #[tokio::test]
    async fn migration_commit_rejects_corrupt_envelopes_and_version_bindings() {
        for change_version in [false, true] {
            let store = SqliteStorage::in_memory().unwrap();
            let (request, creations) = seeded(&store).await;
            store.reserve_migration(&request).await.unwrap();
            store
                .stage_migration(
                    request.operation,
                    test_owner(&store, request.operation).await,
                    &envelopes(),
                )
                .await
                .unwrap();
            store.with_conn(|conn| {
                let query=if change_version { "UPDATE migration_envelopes SET version='99' WHERE operation_id=?1 AND version='1'" }
                    else { "UPDATE migration_envelopes SET envelope=x'010203' WHERE operation_id=?1 AND version='1'" };
                conn.execute(query,[request.operation.to_string()]).map_err(|e|map_sql(&e))?;
                Ok(())
            }).unwrap();
            assert!(
                store
                    .commit_migration(
                        request.operation,
                        test_owner(&store, request.operation).await
                    )
                    .await
                    .is_err(),
                "commit requires exact staged envelope version and digest"
            );
            assert!(same_json(
                &store.get_key(&request.child.lid).await.unwrap(),
                &request.child
            )
            .unwrap());
            for creation in creations {
                assert!(store
                    .read_creation_envelope(creation.operation)
                    .await
                    .is_ok());
            }
        }
    }
}
