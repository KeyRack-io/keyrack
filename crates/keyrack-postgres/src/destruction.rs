// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::creation::{database_error, load_key, replace_key, write_transaction};
use crate::PostgresStorage;
use keyrack_core::destruction::{completed_record, invalid, prepare_claim, DestructionClaim};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::{KeyMaterial, KeyRecord};
use keyrack_core::lid::Lid;
use sqlx::{PgConnection, Row};

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
    Ok(())
}

impl PostgresStorage {
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
        let record = prepare_claim(record, expected, now)?;
        let referenced: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kr_creation_journal WHERE parent_lid=$1 OR child_lid=$1)",
        )
        .bind(lid.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?;
        if referenced {
            return Err(invalid("key is referenced by a creation or envelope"));
        }
        // Include imported/legacy wrapped material not tracked by a journal.
        // Correctness-first scan, not a scale/throughput claim.
        let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT record_json FROM kr_keys")
            .fetch_all(&mut *tx)
            .await
            .map_err(database_error)?;
        for json in rows {
            let other: KeyRecord =
                serde_json::from_value(json).map_err(|_| invalid("invalid persisted key"))?;
            if other.key_versions.iter().any(|v| {
                matches!(&v.material,
                KeyMaterial::ParentWrapped(m) if m.parent().lid == *lid)
            }) {
                return Err(invalid("key is referenced by wrapped material"));
            }
        }
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
