// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::creation::{database_error, load_key, write_transaction};
use crate::PostgresStorage;
use keyrack_core::creation::same_json;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::{KeyMaterial, KeyRecord};
use keyrack_core::lid::Lid;
use keyrack_core::migration::{
    migration_busy, migration_invalid as invalid, MigrationJournal, MigrationOwnership,
    MigrationPhase, MigrationRequest, WrappedKeySnapshot,
};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS kr_migration_journal (
 operation_id TEXT PRIMARY KEY, child_lid TEXT NOT NULL, old_parent_lid TEXT NOT NULL,
 new_parent_lid TEXT NOT NULL, committed BOOLEAN NOT NULL, journal_json JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kr_migration_child ON kr_migration_journal(child_lid,committed);
CREATE INDEX IF NOT EXISTS idx_kr_migration_old_parent ON kr_migration_journal(old_parent_lid,committed);
CREATE INDEX IF NOT EXISTS idx_kr_migration_new_parent ON kr_migration_journal(new_parent_lid,committed);
CREATE TABLE IF NOT EXISTS kr_migration_envelopes (
 operation_id TEXT NOT NULL, version TEXT NOT NULL, envelope BYTEA NOT NULL CHECK(octet_length(envelope) BETWEEN 1 AND 65536),
 PRIMARY KEY(operation_id,version)
);
CREATE TABLE IF NOT EXISTS kr_retired_creation_journal (operation_id TEXT PRIMARY KEY, journal_json JSONB NOT NULL);
";

pub(super) async fn guard(conn: &mut PgConnection, lid: &Lid) -> Result<()> {
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kr_migration_journal WHERE NOT committed AND (child_lid=$1 OR old_parent_lid=$1 OR new_parent_lid=$1))")
        .bind(lid.to_string()).fetch_one(conn).await.map_err(database_error)?;
    if active {
        return Err(migration_busy());
    }
    Ok(())
}

pub(super) async fn guard_record(conn: &mut PgConnection, record: &KeyRecord) -> Result<()> {
    guard(conn, &record.lid).await?;
    if let Some(parent) = record.parent_lid {
        guard(conn, &parent).await?;
    }
    for version in &record.key_versions {
        if let KeyMaterial::ParentWrapped(material) = &version.material {
            guard(conn, &material.parent().lid).await?;
        }
    }
    Ok(())
}

pub(super) async fn guard_update(
    conn: &mut PgConnection,
    previous: &KeyRecord,
    next: &KeyRecord,
) -> Result<()> {
    guard_record(conn, previous).await?;
    guard_record(conn, next).await?;
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

    let referenced: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kr_migration_journal j JOIN kr_migration_envelopes e ON e.operation_id=j.operation_id WHERE j.new_parent_lid=$1)")
        .bind(next.lid.to_string()).fetch_one(&mut *conn).await.map_err(database_error)?;
    if referenced {
        keyrack_core::creation::guard_referenced_parent(previous, next)?;
    }
    Ok(())
}

async fn load(conn: &mut PgConnection, operation: Uuid) -> Result<Option<MigrationJournal>> {
    let row = sqlx::query("SELECT journal_json,child_lid,old_parent_lid,new_parent_lid,committed FROM kr_migration_journal WHERE operation_id=$1")
        .bind(operation.to_string()).fetch_optional(conn).await.map_err(database_error)?;
    row.map(|row| {
        let value: MigrationJournal =
            serde_json::from_value(row.try_get("journal_json").map_err(database_error)?)
                .map_err(|_| invalid("invalid journal"))?;
        value.validate()?;
        let child: String = row.try_get("child_lid").map_err(database_error)?;
        let old: String = row.try_get("old_parent_lid").map_err(database_error)?;
        let new: String = row.try_get("new_parent_lid").map_err(database_error)?;
        let committed: bool = row.try_get("committed").map_err(database_error)?;
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

async fn required(conn: &mut PgConnection, operation: Uuid) -> Result<MigrationJournal> {
    load(conn, operation)
        .await?
        .ok_or_else(|| invalid("migration not found"))
}

async fn save(conn: &mut PgConnection, value: &MigrationJournal) -> Result<()> {
    value.validate()?;
    sqlx::query(
        "UPDATE kr_migration_journal SET journal_json=$1,committed=$2 WHERE operation_id=$3",
    )
    .bind(serde_json::to_value(value).map_err(|_| invalid("journal encoding"))?)
    .bind(value.phase == MigrationPhase::Committed)
    .bind(value.request.operation.to_string())
    .execute(conn)
    .await
    .map_err(database_error)?;
    Ok(())
}

async fn snapshots(conn: &mut PgConnection, request: &MigrationRequest) -> Result<()> {
    let child = load_key(conn, &request.child.lid)
        .await?
        .ok_or(KeyRackError::KeyNotFound(request.child.lid))?;
    let old = load_key(conn, &request.old_parent.lid)
        .await?
        .ok_or(KeyRackError::KeyNotFound(request.old_parent.lid))?;
    let new = load_key(conn, &request.new_parent.lid)
        .await?
        .ok_or(KeyRackError::KeyNotFound(request.new_parent.lid))?;
    for record in [&child, &old, &new] {
        crate::destruction::guard(conn, &record.lid).await?;
    }
    request.validate_snapshots(&child, &old, &new)
}

async fn envelope_ref(conn: &mut PgConnection, reference: &str) -> Result<Vec<u8>> {
    if let Some(operation) = reference.strip_prefix("creation:") {
        let operation: Uuid = operation
            .parse()
            .map_err(|_| invalid("invalid creation envelope reference"))?;
        return crate::creation::committed_envelope(conn, operation).await;
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
        let value = required(conn, operation).await?;
        if value.phase != MigrationPhase::Committed {
            return Err(invalid("migration envelope is not committed"));
        }
        let bytes: Vec<u8> = sqlx::query_scalar(
            "SELECT envelope FROM kr_migration_envelopes WHERE operation_id=$1 AND version=$2",
        )
        .bind(operation.to_string())
        .bind(version.to_string())
        .fetch_one(conn)
        .await
        .map_err(database_error)?;
        value.verify_envelope(version, &bytes)?;
        return Ok(bytes);
    }
    Err(invalid("unknown wrapped envelope reference"))
}

impl PostgresStorage {
    pub(super) async fn migration_reserve(
        &self,
        request: &MigrationRequest,
    ) -> Result<MigrationJournal> {
        request.validate()?;
        let mut tx = write_transaction(&self.pool).await?;
        if let Some(existing) = load(&mut tx, request.operation).await? {
            if !existing.request.same_intent(request)? {
                return Err(KeyRackError::MigrationIntentConflict {
                    operation: request.operation,
                });
            }
            return Ok(existing);
        }
        snapshots(&mut tx, request).await?;
        for record in [&request.child, &request.old_parent, &request.new_parent] {
            guard(&mut tx, &record.lid).await?;
            let pending: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kr_creation_journal WHERE phase!='committed' AND (child_lid=$1 OR parent_lid=$1))")
                .bind(record.lid.to_string()).fetch_one(&mut *tx).await.map_err(database_error)?;
            if pending {
                return Err(migration_busy());
            }
        }
        let value = MigrationJournal::reserved(request.clone());
        sqlx::query("INSERT INTO kr_migration_journal(operation_id,child_lid,old_parent_lid,new_parent_lid,committed,journal_json) VALUES($1,$2,$3,$4,false,$5)")
            .bind(request.operation.to_string()).bind(request.child.lid.to_string()).bind(request.old_parent.lid.to_string()).bind(request.new_parent.lid.to_string())
            .bind(serde_json::to_value(&value).map_err(|_|invalid("journal encoding"))?).execute(&mut *tx).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(value)
    }

    pub(super) async fn migration_get(&self, operation: Uuid) -> Result<Option<MigrationJournal>> {
        let mut conn = self.pool.acquire().await.map_err(database_error)?;
        load(&mut conn, operation).await
    }

    pub(super) async fn migration_claim(
        &self,
        operation: Uuid,
        owner: Uuid,
        expected_epoch: u64,
    ) -> Result<MigrationJournal> {
        let mut tx = write_transaction(&self.pool).await?;
        let mut value = required(&mut tx, operation).await?;
        value.claim(owner, expected_epoch)?;
        save(&mut tx, &value).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(value)
    }

    pub(super) async fn migration_dispatch(
        &self,
        operation: Uuid,
        ownership: MigrationOwnership,
        retry_safe: bool,
    ) -> Result<MigrationJournal> {
        let mut tx = write_transaction(&self.pool).await?;
        let mut value = required(&mut tx, operation).await?;
        value.begin_dispatch(ownership, retry_safe)?;
        save(&mut tx, &value).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(value)
    }

    pub(super) async fn migration_snapshot(
        &self,
        lid: &Lid,
        version: u64,
    ) -> Result<WrappedKeySnapshot> {
        let mut tx = write_transaction(&self.pool).await?;
        let record = load_key(&mut tx, lid)
            .await?
            .ok_or(KeyRackError::KeyNotFound(*lid))?;
        let entry = record
            .get_version(version)
            .ok_or_else(|| invalid("wrapped version absent"))?;
        let KeyMaterial::ParentWrapped(material) = &entry.material else {
            return Err(invalid("version is not wrapped"));
        };
        // Read the loss decision live under the same writer fence as this
        // descriptor. A historical marker for a different parent must not block
        // a version that was rewrapped in place. The exact parent's durable
        // claim also covers a pre-upgrade journal before marker backfill.
        let lost: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kr_destroyed_wrapping_parents WHERE child_lid=$1 AND child_version=$2 AND parent_lid=$3 AND parent_version=$4) OR EXISTS(SELECT 1 FROM kr_destruction_journal WHERE lid=$3)")
            .bind(lid.to_string()).bind(version.to_string())
            .bind(material.parent().lid.to_string()).bind(material.parent().version.get().to_string())
            .fetch_one(&mut *tx).await.map_err(database_error)?;
        if lost {
            return Err(KeyRackError::WrappingParentDestroyed);
        }
        let envelope = envelope_ref(&mut tx, material.wrapped_material_ref().as_str()).await?;
        let parent = load_key(&mut tx, &material.parent().lid)
            .await?
            .ok_or(KeyRackError::WrappingParentDestroyed)?;
        if parent.state == keyrack_core::key::KeyState::Destroyed {
            return Err(KeyRackError::WrappingParentDestroyed);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(WrappedKeySnapshot {
            record,
            parent,
            envelope,
        })
    }

    pub(super) async fn migration_stage(
        &self,
        operation: Uuid,
        ownership: MigrationOwnership,
        envelopes: &[Vec<u8>],
    ) -> Result<MigrationJournal> {
        let mut tx = write_transaction(&self.pool).await?;
        let mut value = required(&mut tx, operation).await?;
        value.require_owner(ownership)?;
        value.validate_envelopes(envelopes)?;
        if value.phase != MigrationPhase::Reserved {
            return Ok(value);
        }
        if value.dispatch.as_ref().map(|d| d.epoch) != Some(ownership.epoch) {
            return Err(invalid(
                "provider dispatch belongs to another ownership epoch",
            ));
        }
        snapshots(&mut tx, &value.request).await?;
        for (version, envelope) in value.request.proposed.key_versions.iter().zip(envelopes) {
            sqlx::query("INSERT INTO kr_migration_envelopes(operation_id,version,envelope) VALUES($1,$2,$3)")
                .bind(operation.to_string()).bind(version.version_number.to_string()).bind(envelope).execute(&mut *tx).await.map_err(database_error)?;
        }
        value.record_envelope_digests(envelopes);
        value.phase = MigrationPhase::Staged;
        save(&mut tx, &value).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(value)
    }

    pub(super) async fn migration_commit(
        &self,
        operation: Uuid,
        ownership: MigrationOwnership,
    ) -> Result<KeyRecord> {
        let mut tx = write_transaction(&self.pool).await?;
        let mut value = required(&mut tx, operation).await?;
        value.require_owner(ownership)?;
        if value.phase == MigrationPhase::Committed {
            return Ok(value.request.proposed);
        }
        if value.phase != MigrationPhase::Staged {
            return Err(invalid("envelopes not staged"));
        }
        snapshots(&mut tx, &value.request).await?;
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM kr_migration_envelopes WHERE operation_id=$1")
                .bind(operation.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(database_error)?;
        if usize::try_from(count).ok() != Some(value.request.child.key_versions.len()) {
            return Err(invalid("incomplete staged envelopes"));
        }
        for version in &value.request.proposed.key_versions {
            let bytes: Vec<u8> = sqlx::query_scalar(
                "SELECT envelope FROM kr_migration_envelopes WHERE operation_id=$1 AND version=$2",
            )
            .bind(operation.to_string())
            .bind(version.version_number.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
            value.verify_envelope(version.version_number, &bytes)?;
        }
        let mut old_envelopes = Vec::new();
        for version in &value.request.child.key_versions {
            let KeyMaterial::ParentWrapped(material) = &version.material else {
                return Err(invalid("resident child version"));
            };
            old_envelopes
                .push(envelope_ref(&mut tx, material.wrapped_material_ref().as_str()).await?);
        }
        value.result = Some(value.terminal_result(&old_envelopes)?);
        sqlx::query("INSERT INTO kr_retired_creation_journal(operation_id,journal_json) SELECT operation_id,journal_json FROM kr_creation_journal WHERE child_lid=$1 AND phase='committed'")
            .bind(value.request.child.lid.to_string()).execute(&mut *tx).await.map_err(database_error)?;
        sqlx::query("DELETE FROM kr_creation_journal WHERE child_lid=$1 AND phase='committed'")
            .bind(value.request.child.lid.to_string())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        sqlx::query("DELETE FROM kr_migration_envelopes WHERE operation_id IN (SELECT operation_id FROM kr_migration_journal WHERE child_lid=$1 AND committed)")
            .bind(value.request.child.lid.to_string()).execute(&mut *tx).await.map_err(database_error)?;
        let proposed = &value.request.proposed;
        let rows = sqlx::query(
            "UPDATE kr_keys SET record_json=$1,occ_version=$2 WHERE lid=$3 AND occ_version=$4",
        )
        .bind(serde_json::to_value(proposed).map_err(|_| invalid("record encoding"))?)
        .bind(i64::try_from(proposed.occ_version).map_err(|_| invalid("OCC overflow"))?)
        .bind(proposed.lid.to_string())
        .bind(i64::try_from(value.request.child.occ_version).map_err(|_| invalid("OCC overflow"))?)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?
        .rows_affected();
        if rows != 1 {
            return Err(migration_busy());
        }
        value.phase = MigrationPhase::Committed;
        save(&mut tx, &value).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(value.request.proposed)
    }

    pub(super) async fn migration_read(&self, operation: Uuid, version: u64) -> Result<Vec<u8>> {
        let mut conn = self.pool.acquire().await.map_err(database_error)?;
        let value = required(&mut conn, operation).await?;
        if value.phase != MigrationPhase::Committed {
            return Err(invalid("migration is not committed"));
        }
        let bytes: Vec<u8> = sqlx::query_scalar(
            "SELECT envelope FROM kr_migration_envelopes WHERE operation_id=$1 AND version=$2",
        )
        .bind(operation.to_string())
        .bind(version.to_string())
        .fetch_one(&mut *conn)
        .await
        .map_err(database_error)?;
        value.verify_envelope(version, &bytes)?;
        Ok(bytes)
    }
}
