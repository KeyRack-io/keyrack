// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::creation::{database_error, load_key, replace_key, write_transaction};
use crate::PostgresStorage;
use keyrack_core::destruction::{
    completed_record, invalid, prepare_claim, DeletionIntent, DestroyedWrappingParent,
    DestructionClaim, DestructionDependencies, DestructionDependent, ScheduledDeletion,
};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::{KeyMaterial, KeyRecord, KeyState};
use keyrack_core::lid::Lid;
use sqlx::{PgConnection, Row};
use std::str::FromStr;

/// Idempotent migration for databases created before deletion approvals existed.
/// Initialization runs this under the same advisory lock as all key writers.
pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS kr_deletion_schedules (
    lid TEXT PRIMARY KEY,
    scheduled_at TIMESTAMPTZ NOT NULL,
    allow_dependent_data_loss BOOLEAN NOT NULL,
    approved_dependents JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS kr_destroyed_wrapping_parents (
    child_lid TEXT NOT NULL,
    child_version TEXT NOT NULL,
    parent_lid TEXT NOT NULL,
    parent_version TEXT NOT NULL,
    PRIMARY KEY(child_lid,child_version,parent_lid,parent_version)
);
";

pub(super) async fn guard(connection: &mut PgConnection, lid: &Lid) -> Result<()> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kr_destruction_journal WHERE lid=$1)")
            .bind(lid.to_string())
            .fetch_one(connection)
            .await
            .map_err(database_error)?;
    if exists {
        return Err(KeyRackError::KeyDestructionFenced(*lid));
    }
    Ok(())
}

pub(super) async fn guard_write(connection: &mut PgConnection, record: &KeyRecord) -> Result<()> {
    guard(connection, &record.lid).await?;
    for version in &record.key_versions {
        if let KeyMaterial::ParentWrapped(material) = &version.material {
            guard(connection, &material.parent().lid).await?;
        }
    }
    // Generic record updates cannot move an approval to a new schedule. This
    // deletion rolls back together with any later failed update in the caller.
    if let Some(previous) = load_key(&mut *connection, &record.lid).await? {
        if previous.state != record.state
            || previous.scheduled_deletion_at != record.scheduled_deletion_at
        {
            sqlx::query("DELETE FROM kr_deletion_schedules WHERE lid=$1")
                .bind(record.lid.to_string())
                .execute(&mut *connection)
                .await
                .map_err(database_error)?;
        }
    }
    Ok(())
}

/// Caller holds the shared creation/CRUD/destruction writer fence.
async fn dependencies(connection: &mut PgConnection, lid: &Lid) -> Result<DestructionDependencies> {
    load_key(&mut *connection, lid)
        .await?
        .ok_or(KeyRackError::KeyNotFound(*lid))?;
    let journals: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kr_creation_journal WHERE parent_lid=$1 OR child_lid=$1",
    )
    .bind(lid.to_string())
    .fetch_one(&mut *connection)
    .await
    .map_err(database_error)?;
    let in_flight: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kr_creation_journal WHERE phase!='committed' AND (parent_lid=$1 OR child_lid=$1)")
        .bind(lid.to_string()).fetch_one(&mut *connection).await.map_err(database_error)?;
    let migrations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kr_migration_journal WHERE NOT committed AND (child_lid=$1 OR old_parent_lid=$1 OR new_parent_lid=$1)")
        .bind(lid.to_string()).fetch_one(&mut *connection).await.map_err(database_error)?;
    let mut counts = DestructionDependencies {
        creation_journal_rows: count(journals)?,
        in_flight_creation_journal_rows: count(in_flight)?,
        migration_journal_rows: count(migrations)?,
        ..DestructionDependencies::default()
    };
    let rows = sqlx::query("SELECT lid,record_json,occ_version FROM kr_keys")
        .fetch_all(&mut *connection)
        .await
        .map_err(database_error)?;
    for row in rows {
        let indexed_lid: String = row.try_get("lid").map_err(database_error)?;
        let json: serde_json::Value = row.try_get("record_json").map_err(database_error)?;
        let occ: i64 = row.try_get("occ_version").map_err(database_error)?;
        let record: KeyRecord =
            serde_json::from_value(json).map_err(|_| invalid("invalid persisted key"))?;
        if record.lid.to_string() != indexed_lid
            || u64::try_from(occ).ok() != Some(record.occ_version)
        {
            return Err(invalid("key row binding mismatch"));
        }
        counts.include_record(lid, &record)?;
    }
    // Live indexed envelopes remain dependencies even if an imported or old
    // record no longer names them. Terminal receipts without bytes do not.
    let rows = sqlx::query("SELECT child_lid,child_version,parent_version,envelope_ref FROM kr_creation_journal WHERE parent_lid=$1 AND child_lid!=$1 AND phase='committed' AND envelope IS NOT NULL")
        .bind(lid.to_string()).fetch_all(&mut *connection).await.map_err(database_error)?;
    for row in rows {
        counts.dependents.push(DestructionDependent {
            lid: parse_lid(
                row.try_get::<&str, _>("child_lid")
                    .map_err(database_error)?,
            )?,
            version: parse_version(
                row.try_get::<&str, _>("child_version")
                    .map_err(database_error)?,
            )?,
            parent_version: parse_version(
                row.try_get::<&str, _>("parent_version")
                    .map_err(database_error)?,
            )?,
            envelope_ref: row.try_get("envelope_ref").map_err(database_error)?,
        });
    }
    let rows = sqlx::query("SELECT j.operation_id,j.child_lid,j.new_parent_lid,j.journal_json,e.version FROM kr_migration_journal j JOIN kr_migration_envelopes e ON e.operation_id=j.operation_id WHERE j.committed AND j.new_parent_lid=$1 AND j.child_lid!=$1")
        .bind(lid.to_string()).fetch_all(&mut *connection).await.map_err(database_error)?;
    for row in rows {
        let journal = decode_migration(&row)?;
        let version = parse_version(row.try_get::<&str, _>("version").map_err(database_error)?)?;
        let descriptor = journal
            .request
            .proposed
            .get_version(version)
            .ok_or(invalid("migration envelope has no descriptor"))?;
        let KeyMaterial::ParentWrapped(material) = &descriptor.material else {
            return Err(invalid("migration envelope has resident descriptor"));
        };
        counts.dependents.push(DestructionDependent {
            lid: journal.request.child.lid,
            version,
            parent_version: material.parent().version.get(),
            envelope_ref: material.wrapped_material_ref().as_str().to_owned(),
        });
    }
    counts.dependents.sort();
    counts.dependents.dedup();
    counts.dependent_parent_wrapped_versions =
        u64::try_from(counts.dependents.len()).map_err(|_| invalid("dependency count overflow"))?;
    Ok(counts)
}

fn count(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| invalid("dependency count out of range"))
}
fn parse_version(value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|v| *v > 0 && v.to_string() == value)
        .ok_or(invalid("invalid indexed version"))
}
fn parse_lid(value: &str) -> Result<Lid> {
    Lid::from_str(value).map_err(|_| invalid("invalid indexed lid"))
}
fn decode_migration(
    row: &sqlx::postgres::PgRow,
) -> Result<keyrack_core::migration::MigrationJournal> {
    let json: serde_json::Value = row.try_get("journal_json").map_err(database_error)?;
    let journal: keyrack_core::migration::MigrationJournal =
        serde_json::from_value(json).map_err(|_| invalid("invalid migration journal"))?;
    journal.validate()?;
    let operation: String = row.try_get("operation_id").map_err(database_error)?;
    let child: String = row.try_get("child_lid").map_err(database_error)?;
    let parent: String = row.try_get("new_parent_lid").map_err(database_error)?;
    if journal.request.operation.to_string() != operation
        || journal.request.child.lid.to_string() != child
        || journal.request.new_parent.lid.to_string() != parent
        || journal.phase != keyrack_core::migration::MigrationPhase::Committed
    {
        return Err(invalid("migration index binding mismatch"));
    }
    Ok(journal)
}
async fn intent(
    connection: &mut PgConnection,
    record: &KeyRecord,
) -> Result<Option<DeletionIntent>> {
    let row = sqlx::query("SELECT scheduled_at,allow_dependent_data_loss,approved_dependents FROM kr_deletion_schedules WHERE lid=$1")
        .bind(record.lid.to_string()).fetch_optional(connection).await.map_err(database_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let at: chrono::DateTime<chrono::Utc> = row.try_get("scheduled_at").map_err(database_error)?;
    if record.state != KeyState::PendingDeletion || record.scheduled_deletion_at != Some(at) {
        return Err(invalid("deletion approval schedule binding mismatch"));
    }
    let json: serde_json::Value = row.try_get("approved_dependents").map_err(database_error)?;
    Ok(Some(DeletionIntent {
        allow_dependent_data_loss: row
            .try_get("allow_dependent_data_loss")
            .map_err(database_error)?,
        approved_dependents: serde_json::from_value(json)
            .map_err(|_| invalid("invalid approved dependency snapshot"))?,
    }))
}
fn expected_occ(record: &KeyRecord, expected: u64) -> Result<()> {
    if record.occ_version != expected {
        return Err(KeyRackError::OptimisticConcurrencyConflict {
            lid: record.lid,
            expected,
            actual: record.occ_version,
        });
    }
    if expected == 0 || expected >= i64::MAX as u64 {
        return Err(invalid("OCC out of range"));
    }
    Ok(())
}

/// A wrapped version may be erased only through an authoritative owned envelope.
async fn validate_owned_envelopes(connection: &mut PgConnection, record: &KeyRecord) -> Result<()> {
    for version in &record.key_versions {
        let KeyMaterial::ParentWrapped(material) = &version.material else {
            continue;
        };
        let found: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kr_creation_journal WHERE child_lid=$1 AND child_version=$2 AND parent_lid=$3 AND parent_version=$4 AND envelope_ref=$5 AND phase='committed' AND envelope IS NOT NULL)")
            .bind(record.lid.to_string()).bind(version.version_number.to_string())
            .bind(material.parent().lid.to_string()).bind(material.parent().version.get().to_string())
            .bind(material.wrapped_material_ref().as_str()).fetch_one(&mut *connection).await.map_err(database_error)?;
        if found {
            continue;
        }
        // A creation reference that exists with different ownership/bindings
        // is ambiguous, not permission to fall through to a migration record.
        let conflicting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kr_creation_journal WHERE envelope_ref=$1)",
        )
        .bind(material.wrapped_material_ref().as_str())
        .fetch_one(&mut *connection)
        .await
        .map_err(database_error)?;
        if conflicting {
            return Err(invalid("owned creation envelope binding mismatch"));
        }
        let rows=sqlx::query("SELECT j.operation_id,j.child_lid,j.new_parent_lid,j.journal_json,e.version FROM kr_migration_journal j JOIN kr_migration_envelopes e ON e.operation_id=j.operation_id WHERE j.committed AND j.child_lid=$1 AND e.version=$2")
            .bind(record.lid.to_string()).bind(version.version_number.to_string()).fetch_all(&mut *connection).await.map_err(database_error)?;
        let mut found = false;
        for row in rows {
            let journal = decode_migration(&row)?;
            if let Some(candidate) = journal.request.proposed.get_version(version.version_number) {
                if matches!(&candidate.material, KeyMaterial::ParentWrapped(proposed) if proposed == material)
                {
                    found = true;
                }
            }
        }
        if !found {
            return Err(invalid(
                "wrapped destruction requires an authoritative owned envelope",
            ));
        }
    }
    Ok(())
}

impl PostgresStorage {
    pub(super) async fn destruction_schedule(
        &self,
        lid: &Lid,
        expected: u64,
        at: chrono::DateTime<chrono::Utc>,
        allow: bool,
    ) -> Result<ScheduledDeletion> {
        let mut tx = write_transaction(&self.pool).await?;
        guard(&mut tx, lid).await?;
        let mut record = load_key(&mut tx, lid)
            .await?
            .ok_or(KeyRackError::KeyNotFound(*lid))?;
        expected_occ(&record, expected)?;
        keyrack_core::destruction::validate_destruction_history(&record)?;
        validate_owned_envelopes(&mut tx, &record).await?;
        let dependencies = dependencies(&mut tx, lid).await?;
        let approved = dependencies.approval(allow)?;
        record
            .transition_to(KeyState::PendingDeletion)
            .map_err(|(from, to)| KeyRackError::InvalidStateTransition {
                lid: *lid,
                from,
                to,
            })?;
        // PostgreSQL timestamps have microsecond precision; persist the identical
        // value in JSON and the approval row so binding survives reconnect.
        let at = chrono::DateTime::from_timestamp_micros(at.timestamp_micros())
            .ok_or(invalid("deletion timestamp out of range"))?;
        record.scheduled_deletion_at = Some(at);
        replace_key(&mut tx, &record, expected).await?;
        sqlx::query("INSERT INTO kr_deletion_schedules(lid,scheduled_at,allow_dependent_data_loss,approved_dependents) VALUES($1,$2,$3,$4) ON CONFLICT(lid) DO UPDATE SET scheduled_at=EXCLUDED.scheduled_at,allow_dependent_data_loss=EXCLUDED.allow_dependent_data_loss,approved_dependents=EXCLUDED.approved_dependents")
            .bind(lid.to_string()).bind(at).bind(approved.allow_dependent_data_loss)
            .bind(serde_json::to_value(approved.approved_dependents).map_err(|_|invalid("snapshot serialization"))?)
            .execute(&mut *tx).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(ScheduledDeletion {
            record,
            logical_only_children: dependencies.logical_only_children,
        })
    }

    pub(super) async fn destruction_cancel(&self, lid: &Lid, expected: u64) -> Result<KeyRecord> {
        let mut tx = write_transaction(&self.pool).await?;
        guard(&mut tx, lid).await?;
        let mut record = load_key(&mut tx, lid)
            .await?
            .ok_or(KeyRackError::KeyNotFound(*lid))?;
        expected_occ(&record, expected)?;
        if record.state != KeyState::PendingDeletion {
            return Err(invalid("only pending deletion may be cancelled"));
        }
        record
            .transition_to(KeyState::Disabled)
            .map_err(|(from, to)| KeyRackError::InvalidStateTransition {
                lid: *lid,
                from,
                to,
            })?;
        record.scheduled_deletion_at = None;
        replace_key(&mut tx, &record, expected).await?;
        sqlx::query("DELETE FROM kr_deletion_schedules WHERE lid=$1")
            .bind(lid.to_string())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(record)
    }

    pub(super) async fn destruction_intent(&self, lid: &Lid) -> Result<Option<DeletionIntent>> {
        let mut tx = write_transaction(&self.pool).await?;
        let record = load_key(&mut tx, lid)
            .await?
            .ok_or(KeyRackError::KeyNotFound(*lid))?;
        let result = intent(&mut tx, &record).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }

    pub(super) async fn destruction_parent_status(
        &self,
        lid: &Lid,
    ) -> Result<Vec<DestroyedWrappingParent>> {
        let mut tx = write_transaction(&self.pool).await?;
        load_key(&mut tx, lid)
            .await?
            .ok_or(KeyRackError::KeyNotFound(*lid))?;
        let rows=sqlx::query("SELECT child_version,parent_lid,parent_version FROM kr_destroyed_wrapping_parents WHERE child_lid=$1 ORDER BY child_version,parent_lid,parent_version")
            .bind(lid.to_string()).fetch_all(&mut *tx).await.map_err(database_error)?;
        let mut result = Vec::new();
        for row in rows {
            result.push(DestroyedWrappingParent {
                version: parse_version(
                    row.try_get::<&str, _>("child_version")
                        .map_err(database_error)?,
                )?,
                parent_lid: parse_lid(
                    row.try_get::<&str, _>("parent_lid")
                        .map_err(database_error)?,
                )?,
                parent_version: parse_version(
                    row.try_get::<&str, _>("parent_version")
                        .map_err(database_error)?,
                )?,
            });
        }
        result.sort_by_key(|entry| entry.version);
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }

    pub(super) async fn destruction_dependency_counts(
        &self,
        lid: &Lid,
    ) -> Result<DestructionDependencies> {
        let mut tx = write_transaction(&self.pool).await?;
        let counts = dependencies(&mut tx, lid).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(counts)
    }

    pub(super) async fn destruction_claim(
        &self,
        lid: &Lid,
        expected: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<DestructionClaim>> {
        let mut tx = write_transaction(&self.pool).await?;
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kr_destruction_journal WHERE lid=$1)")
                .bind(lid.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(database_error)?;
        if exists {
            tx.commit().await.map_err(database_error)?;
            return Ok(None);
        }
        let record = load_key(&mut tx, lid)
            .await?
            .ok_or(KeyRackError::KeyNotFound(*lid))?;
        let counts = dependencies(&mut tx, lid).await?;
        counts.validate_intent(&intent(&mut tx, &record).await?.unwrap_or_default())?;
        validate_owned_envelopes(&mut tx, &record).await?;
        let record = prepare_claim(record, expected, now)?;
        let operation = uuid::Uuid::new_v4();
        let json = serde_json::to_value(&record).map_err(|_| invalid("claim serialization"))?;
        sqlx::query("INSERT INTO kr_destruction_journal(lid,operation_id,record_json,completed) VALUES($1,$2,$3,false)")
            .bind(lid.to_string()).bind(operation.to_string()).bind(json)
            .execute(&mut *tx).await.map_err(database_error)?;
        replace_key(&mut tx, &record, expected).await?;
        tx.commit().await.map_err(database_error)?;
        // Only a successfully committed new claim may issue an execution ticket.
        Ok(Some(DestructionClaim::committed(operation, record)?))
    }

    pub(super) async fn destruction_complete(&self, claim: DestructionClaim) -> Result<KeyRecord> {
        let mut tx = write_transaction(&self.pool).await?;
        let lid = claim.record().lid;
        let row = sqlx::query(
            "SELECT operation_id,record_json,completed FROM kr_destruction_journal WHERE lid=$1",
        )
        .bind(lid.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?
        .ok_or(invalid("claim missing"))?;
        let operation: String = row.try_get("operation_id").map_err(database_error)?;
        let completed: bool = row.try_get("completed").map_err(database_error)?;
        let json: serde_json::Value = row.try_get("record_json").map_err(database_error)?;
        let snapshot: KeyRecord =
            serde_json::from_value(json).map_err(|_| invalid("invalid claim snapshot"))?;
        if completed
            || operation != claim.operation().to_string()
            || !keyrack_core::creation::same_json(&snapshot, claim.record())?
        {
            return Err(invalid("claim mismatch or already completed"));
        }
        let current = load_key(&mut tx, &lid)
            .await?
            .ok_or(KeyRackError::KeyNotFound(lid))?;
        let record = completed_record(&claim, &current)?;
        // Only actual live material descriptors get a parent-loss marker. Retain
        // their state, key versions and envelopes exactly as they were.
        let rows = sqlx::query("SELECT lid,record_json,occ_version FROM kr_keys WHERE lid!=$1")
            .bind(lid.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(database_error)?;
        for row in rows {
            let json: serde_json::Value = row.try_get("record_json").map_err(database_error)?;
            let child: KeyRecord =
                serde_json::from_value(json).map_err(|_| invalid("invalid dependent metadata"))?;
            let indexed_lid: String = row.try_get("lid").map_err(database_error)?;
            let occ: i64 = row.try_get("occ_version").map_err(database_error)?;
            if child.lid.to_string() != indexed_lid
                || u64::try_from(occ).ok() != Some(child.occ_version)
            {
                return Err(invalid("dependent row binding mismatch"));
            }
            if child.state == KeyState::Destroyed {
                continue;
            }
            for version in &child.key_versions {
                if let KeyMaterial::ParentWrapped(material) = &version.material {
                    if material.parent().lid == lid {
                        sqlx::query("INSERT INTO kr_destroyed_wrapping_parents(child_lid,child_version,parent_lid,parent_version) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                            .bind(child.lid.to_string()).bind(version.version_number.to_string())
                            .bind(lid.to_string()).bind(material.parent().version.get().to_string())
                            .execute(&mut *tx).await.map_err(database_error)?;
                    }
                }
            }
        }
        // Erase only envelopes owned by this logical key, never its dependents.
        sqlx::query("INSERT INTO kr_retired_creation_journal(operation_id,journal_json) SELECT operation_id,journal_json FROM kr_creation_journal WHERE child_lid=$1 AND phase='committed' ON CONFLICT(operation_id) DO NOTHING")
            .bind(lid.to_string()).execute(&mut *tx).await.map_err(database_error)?;
        sqlx::query("DELETE FROM kr_creation_journal WHERE child_lid=$1 AND phase='committed'")
            .bind(lid.to_string())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        sqlx::query("DELETE FROM kr_migration_envelopes WHERE operation_id IN (SELECT operation_id FROM kr_migration_journal WHERE child_lid=$1 AND committed)")
            .bind(lid.to_string()).execute(&mut *tx).await.map_err(database_error)?;
        sqlx::query("DELETE FROM kr_deletion_schedules WHERE lid=$1")
            .bind(lid.to_string())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;

        replace_key(&mut tx, &record, current.occ_version).await?;
        sqlx::query("UPDATE kr_destruction_journal SET completed=true WHERE lid=$1")
            .bind(lid.to_string())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(record)
    }
}
