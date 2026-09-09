// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Atomic creation publication, not provider activation or a custody proof.
//!
//! A transaction-scoped advisory lock serializes key/journal writes in this
//! first profile. Reads remain unlocked. This is a correctness tradeoff, not a
//! cloud-scale write-throughput claim. All writers must use this protocol;
//! out-of-band SQL administrators remain outside the storage trust boundary.
//! No provider operation or closure verifier runs inside a transaction.

use keyrack_core::creation::{
    guard_referenced_parent, invalid, same_json, validate_envelope, validate_page_size,
    CreationDispatch, CreationJournal, CreationOwner, CreationPage, CreationPhase, CreationRequest,
    CreationSnapshot, VerifiedA2Closure,
};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::KeyRecord;
use keyrack_core::lid::Lid;
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{is_unique_violation, PostgresStorage};

const WRITE_LOCK: i64 = 1_263_682_386;
const JOURNAL_SELECT: &str = "SELECT operation_id, child_lid, child_version, parent_lid, \
    parent_version, envelope_ref, phase, journal_json, envelope FROM kr_creation_journal";

// Consume the database error so this adapter can be passed directly to map_err.
#[allow(clippy::needless_pass_by_value)]
pub(super) fn database_error(error: sqlx::Error) -> KeyRackError {
    KeyRackError::Storage(format!("creation storage: {error}"))
}

pub(super) async fn write_transaction(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    let mut transaction = pool.begin().await.map_err(database_error)?;
    // A caller-supplied pool may have changed the default isolation level.
    // Take fresh snapshots after waiting for the lock, not a pre-lock snapshot.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(WRITE_LOCK)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
    Ok(transaction)
}

struct StoredCreation {
    journal: CreationJournal,
    envelope: Option<Vec<u8>>,
}

/// Validate JSON, indexed identity, phase, and bytes together on every journal
/// read. Index fields are denormalized bindings, not an alternate source of truth.
fn decode_journal(row: &PgRow) -> Result<StoredCreation> {
    let json: serde_json::Value = row.try_get("journal_json").map_err(database_error)?;
    let journal: CreationJournal =
        serde_json::from_value(json).map_err(|_| invalid("invalid persisted journal JSON"))?;
    journal.validate()?;
    let material = journal.request.material()?;
    let child = journal.request.child()?;
    let scalar = |name| row.try_get::<String, _>(name).map_err(database_error);
    if scalar("operation_id")? != journal.request.operation.to_string()
        || scalar("child_lid")? != child.lid.to_string()
        || scalar("child_version")? != child.version.get().to_string()
        || scalar("parent_lid")? != material.parent().lid.to_string()
        || scalar("parent_version")? != material.parent().version.get().to_string()
        || scalar("envelope_ref")? != material.wrapped_material_ref().as_str()
        || scalar("phase")? != journal.phase.as_str()
    {
        return Err(invalid("journal index binding mismatch"));
    }
    let envelope: Option<Vec<u8>> = row.try_get("envelope").map_err(database_error)?;
    match (journal.phase, envelope.as_deref()) {
        (CreationPhase::Reserved, None) => {}
        (CreationPhase::Reserved, Some(_)) | (_, None) => {
            return Err(invalid("journal envelope presence mismatch"));
        }
        (_, Some(bytes)) => validate_envelope(&journal, bytes)?,
    }
    Ok(StoredCreation { journal, envelope })
}

async fn load_creation(
    connection: &mut PgConnection,
    operation: Uuid,
) -> Result<Option<StoredCreation>> {
    let query = format!("{JOURNAL_SELECT} WHERE operation_id = $1");
    sqlx::query(&query)
        .bind(operation.to_string())
        .fetch_optional(connection)
        .await
        .map_err(database_error)?
        .as_ref()
        .map(decode_journal)
        .transpose()
}

async fn require_creation(
    connection: &mut PgConnection,
    operation: Uuid,
) -> Result<StoredCreation> {
    load_creation(connection, operation)
        .await?
        .ok_or(invalid("creation not found"))
}

fn decode_key(row: &PgRow, lid: &Lid) -> Result<KeyRecord> {
    let actual: i64 = row.try_get("occ_version").map_err(database_error)?;
    let actual = u64::try_from(actual).map_err(|_| invalid("negative persisted key OCC"))?;
    let json: serde_json::Value = row.try_get("record_json").map_err(database_error)?;
    let record: KeyRecord =
        serde_json::from_value(json).map_err(|_| invalid("invalid persisted key JSON"))?;
    if record.lid != *lid || record.occ_version != actual {
        return Err(invalid("key row binding mismatch"));
    }
    Ok(record)
}

pub(super) async fn load_key(
    connection: &mut PgConnection,
    lid: &Lid,
) -> Result<Option<KeyRecord>> {
    sqlx::query("SELECT record_json, occ_version FROM kr_keys WHERE lid = $1")
        .bind(lid.to_string())
        .fetch_optional(connection)
        .await
        .map_err(database_error)?
        .as_ref()
        .map(|row| decode_key(row, lid))
        .transpose()
}

async fn persist_journal(
    connection: &mut PgConnection,
    journal: &CreationJournal,
    envelope: &[u8],
) -> Result<()> {
    validate_envelope(journal, envelope)?;
    let json =
        serde_json::to_value(journal).map_err(|_| invalid("journal serialization failed"))?;
    let result = sqlx::query(
        "UPDATE kr_creation_journal SET phase = $1, journal_json = $2, envelope = $3 \
         WHERE operation_id = $4",
    )
    .bind(journal.phase.as_str())
    .bind(json)
    .bind(envelope)
    .bind(journal.request.operation.to_string())
    .execute(connection)
    .await
    .map_err(database_error)?;
    if result.rows_affected() != 1 {
        return Err(invalid("creation disappeared during transaction"));
    }
    Ok(())
}

async fn insert_key(connection: &mut PgConnection, record: &KeyRecord) -> Result<()> {
    let json = serde_json::to_value(record).map_err(|_| invalid("key serialization failed"))?;
    let occ = i64::try_from(record.occ_version).map_err(|_| invalid("key OCC out of range"))?;
    sqlx::query("INSERT INTO kr_keys (lid, record_json, occ_version) VALUES ($1, $2, $3)")
        .bind(record.lid.to_string())
        .bind(json)
        .bind(occ)
        .execute(connection)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                KeyRackError::Other("key already exists".into())
            } else {
                database_error(error)
            }
        })?;
    Ok(())
}

pub(super) async fn replace_key(
    connection: &mut PgConnection,
    record: &KeyRecord,
    expected_occ: u64,
) -> Result<()> {
    let json = serde_json::to_value(record).map_err(|_| invalid("key serialization failed"))?;
    let occ = i64::try_from(record.occ_version).map_err(|_| invalid("key OCC out of range"))?;
    let expected = i64::try_from(expected_occ).map_err(|_| invalid("key OCC out of range"))?;
    let result = sqlx::query(
        "UPDATE kr_keys SET record_json = $1, occ_version = $2 \
         WHERE lid = $3 AND occ_version = $4",
    )
    .bind(json)
    .bind(occ)
    .bind(record.lid.to_string())
    .bind(expected)
    .execute(connection)
    .await
    .map_err(database_error)?;
    if result.rows_affected() != 1 {
        return Err(invalid("key changed during locked transaction"));
    }
    Ok(())
}

impl PostgresStorage {
    pub(super) async fn creation_reserve(
        &self,
        request: &CreationRequest,
    ) -> Result<CreationJournal> {
        request.validate()?;
        let mut transaction = write_transaction(&self.pool).await?;
        crate::destruction::guard_write(&mut transaction, &request.record).await?;
        if let Some(stored) = load_creation(&mut transaction, request.operation).await? {
            if !same_json(&stored.journal.request, request)? {
                return Err(invalid("operation already has different intent"));
            }
            // Historical retry evidence only: not fresh authorization or a
            // license to regenerate a provider object after an uncertain result.
            transaction.commit().await.map_err(database_error)?;
            return Ok(stored.journal);
        }
        let current = load_key(&mut transaction, &request.record.lid).await?;
        let parent = load_key(&mut transaction, &request.material()?.parent().lid)
            .await?
            .ok_or(invalid("parent key not found"))?;
        request.validate_records(current.as_ref(), &parent)?;
        let journal = CreationJournal::reserved(request.clone())?;
        let child = request.child()?;
        let material = request.material()?;
        let json =
            serde_json::to_value(&journal).map_err(|_| invalid("journal serialization failed"))?;
        sqlx::query(
            "INSERT INTO kr_creation_journal \
             (operation_id, child_lid, child_version, parent_lid, parent_version, \
              envelope_ref, phase, journal_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(request.operation.to_string())
        .bind(child.lid.to_string())
        .bind(child.version.get().to_string())
        .bind(material.parent().lid.to_string())
        .bind(material.parent().version.get().to_string())
        .bind(material.wrapped_material_ref().as_str())
        .bind(journal.phase.as_str())
        .bind(json)
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                invalid("creation identity or envelope reference already reserved")
            } else {
                database_error(error)
            }
        })?;
        transaction.commit().await.map_err(database_error)?;
        Ok(journal)
    }

    pub(super) async fn creation_get(&self, operation: Uuid) -> Result<CreationJournal> {
        let mut connection = self.pool.acquire().await.map_err(database_error)?;
        Ok(require_creation(&mut connection, operation).await?.journal)
    }

    pub(super) async fn creation_claim_dispatch(
        &self,
        operation: Uuid,
        owner: CreationOwner,
    ) -> Result<CreationDispatch> {
        let mut transaction = write_transaction(&self.pool).await?;
        let mut stored = require_creation(&mut transaction, operation).await?;
        let started = stored.journal.claim_dispatch(owner)?;
        if started {
            let current = load_key(&mut transaction, &stored.journal.request.record.lid).await?;
            let parent = load_key(
                &mut transaction,
                &stored.journal.request.material()?.parent().lid,
            )
            .await?
            .ok_or(invalid("parent key not found"))?;
            stored
                .journal
                .request
                .validate_records(current.as_ref(), &parent)?;
            stored.journal.validate()?;
            let json = serde_json::to_value(&stored.journal)
                .map_err(|_| invalid("journal serialization failed"))?;
            let changed = sqlx::query(
                "UPDATE kr_creation_journal SET journal_json = $1 WHERE operation_id = $2",
            )
            .bind(json)
            .bind(operation.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(database_error)?;
            if changed.rows_affected() != 1 {
                return Err(invalid("creation disappeared during dispatch claim"));
            }
        }
        // Only a successfully committed first claim can authorize dispatch.
        // Once committed, a lost response remains consumed: retries are Existing.
        transaction.commit().await.map_err(database_error)?;
        Ok(if started {
            CreationDispatch::Started(stored.journal)
        } else {
            CreationDispatch::Existing(stored.journal)
        })
    }

    pub(super) async fn creation_read_snapshot(
        &self,
        operation: Uuid,
        owner: CreationOwner,
    ) -> Result<CreationSnapshot> {
        let mut connection = self.pool.acquire().await.map_err(database_error)?;
        // require_creation reads and validates the entire row in one SQL read.
        let stored = require_creation(&mut connection, operation).await?;
        CreationSnapshot::new(stored.journal, stored.envelope, owner)
    }

    pub(super) async fn creation_stage(
        &self,
        operation: Uuid,
        owner: CreationOwner,
        revision: u64,
        envelope: &[u8],
    ) -> Result<CreationJournal> {
        let mut transaction = write_transaction(&self.pool).await?;
        let mut stored = require_creation(&mut transaction, operation).await?;
        stored.journal.stage(owner, revision, envelope)?;
        if let Some(previous) = stored.envelope.as_deref() {
            // Digest binding is validated on reads; retries also require exact
            // immutable bytes, not merely equality of their digest.
            if previous != envelope {
                return Err(invalid("envelope bytes are immutable"));
            }
        } else {
            persist_journal(&mut transaction, &stored.journal, envelope).await?;
        }
        transaction.commit().await.map_err(database_error)?;
        Ok(stored.journal)
    }

    pub(super) async fn creation_resolve(
        &self,
        operation: Uuid,
        owner: CreationOwner,
        revision: u64,
        closure: &VerifiedA2Closure,
    ) -> Result<CreationJournal> {
        let mut transaction = write_transaction(&self.pool).await?;
        let mut stored = require_creation(&mut transaction, operation).await?;
        let previous_revision = stored.journal.revision;
        stored.journal.resolve(owner, revision, closure)?;
        if previous_revision != stored.journal.revision {
            persist_journal(
                &mut transaction,
                &stored.journal,
                stored
                    .envelope
                    .as_deref()
                    .ok_or(invalid("missing staged envelope"))?,
            )
            .await?;
        }
        transaction.commit().await.map_err(database_error)?;
        Ok(stored.journal)
    }

    pub(super) async fn creation_publish(
        &self,
        operation: Uuid,
        owner: CreationOwner,
        revision: u64,
    ) -> Result<KeyRecord> {
        let mut transaction = write_transaction(&self.pool).await?;
        let mut stored = require_creation(&mut transaction, operation).await?;
        if let Some(record) = stored.journal.committed_retry(owner, revision)? {
            // Return the recorded result before checking current key/parent
            // availability, and never overwrite newer metadata on this path.
            transaction.commit().await.map_err(database_error)?;
            return Ok(record);
        }
        let current = load_key(&mut transaction, &stored.journal.request.record.lid).await?;
        let parent = load_key(
            &mut transaction,
            &stored.journal.request.material()?.parent().lid,
        )
        .await?
        .ok_or(invalid("parent key not found"))?;
        let record = stored
            .journal
            .publication(owner, revision, current.as_ref(), &parent)?;
        match stored.journal.request.expected_key_occ {
            None => insert_key(&mut transaction, &record).await?,
            Some(expected) => replace_key(&mut transaction, &record, expected).await?,
        }
        persist_journal(
            &mut transaction,
            &stored.journal,
            stored
                .envelope
                .as_deref()
                .ok_or(invalid("missing staged envelope"))?,
        )
        .await?;
        transaction.commit().await.map_err(database_error)?;
        Ok(record)
    }

    pub(super) async fn creation_read_envelope(&self, operation: Uuid) -> Result<Vec<u8>> {
        let mut connection = self.pool.acquire().await.map_err(database_error)?;
        let stored = require_creation(&mut connection, operation).await?;
        if stored.journal.phase != CreationPhase::Committed {
            return Err(invalid("creation envelope is not committed"));
        }
        stored.envelope.ok_or(invalid("missing committed envelope"))
    }

    pub(super) async fn creation_recoverable(
        &self,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<CreationPage> {
        validate_page_size(limit)?;
        let query = format!(
            "{JOURNAL_SELECT} WHERE phase != 'committed' AND operation_id > $1 \
             ORDER BY operation_id LIMIT $2"
        );
        let rows = sqlx::query(&query)
            .bind(
                after
                    .map(|operation| operation.to_string())
                    .unwrap_or_default(),
            )
            .bind(i64::from(limit) + 1)
            .fetch_all(&self.pool)
            .await
            .map_err(database_error)?;
        let mut items = rows
            .iter()
            .map(|row| decode_journal(row).map(|stored| stored.journal))
            .collect::<Result<Vec<_>>>()?;
        let next_after = if items.len() > limit as usize {
            items.pop();
            items.last().map(|journal| journal.request.operation)
        } else {
            None
        };
        Ok(CreationPage { items, next_after })
    }

    pub(super) async fn create_key_guarded(&self, record: &KeyRecord) -> Result<()> {
        let mut transaction = write_transaction(&self.pool).await?;
        crate::destruction::guard_write(&mut transaction, record).await?;
        let reserved: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM kr_creation_journal WHERE child_lid = $1)",
        )
        .bind(record.lid.to_string())
        .fetch_one(&mut *transaction)
        .await
        .map_err(database_error)?;
        if reserved {
            return Err(invalid("child identity is reserved by a creation"));
        }
        let mut persisted = record.clone();
        persisted.was_compromised = record.has_compromise_history();
        insert_key(&mut transaction, &persisted).await?;
        transaction.commit().await.map_err(database_error)
    }

    pub(super) async fn update_key_guarded(&self, record: &KeyRecord) -> Result<()> {
        let expected = record
            .occ_version
            .checked_sub(1)
            .ok_or_else(|| KeyRackError::Other("occ_version must be > 0 for updates".into()))?;
        let mut transaction = write_transaction(&self.pool).await?;
        let row = sqlx::query("SELECT record_json, occ_version FROM kr_keys WHERE lid = $1")
            .bind(record.lid.to_string())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(database_error)?
            .ok_or(KeyRackError::KeyNotFound(record.lid))?;
        let actual: i64 = row.try_get("occ_version").map_err(database_error)?;
        let actual = u64::try_from(actual).map_err(|_| invalid("negative persisted key OCC"))?;
        // Preserve ordinary OCC semantics: reject stale callers before decoding
        // prior material or evaluating creation-specific mutation guards.
        if actual != expected {
            return Err(KeyRackError::OptimisticConcurrencyConflict {
                lid: record.lid,
                expected,
                actual,
            });
        }
        let previous = decode_key(&row, &record.lid)?;
        if previous.has_compromise_history() && !record.has_compromise_history() {
            return Err(KeyRackError::Other(
                "cannot clear a key's compromise history".into(),
            ));
        }
        crate::destruction::guard_write(&mut transaction, record).await?;
        if record.state == keyrack_core::key::KeyState::Destroyed {
            return Err(keyrack_core::destruction::invalid(
                "Destroyed requires fenced completion",
            ));
        }
        let guards = sqlx::query(
            "SELECT \
             EXISTS (SELECT 1 FROM kr_creation_journal WHERE child_lid = $1) AS child_tracked, \
             EXISTS (SELECT 1 FROM kr_creation_journal WHERE parent_lid = $1 \
                 OR (child_lid = $1 AND phase = 'committed')) AS material_referenced",
        )
        .bind(record.lid.to_string())
        .fetch_one(&mut *transaction)
        .await
        .map_err(database_error)?;
        let child_tracked: bool = guards.try_get("child_tracked").map_err(database_error)?;
        let material_referenced: bool = guards
            .try_get("material_referenced")
            .map_err(database_error)?;
        if child_tracked
            && (previous.current_key_version != record.current_key_version
                || !same_json(&previous.key_versions, &record.key_versions)?)
        {
            return Err(invalid(
                "tracked child versions require creation publication",
            ));
        }
        if material_referenced {
            guard_referenced_parent(&previous, record)?;
        }
        let mut persisted = record.clone();
        persisted.was_compromised = record.has_compromise_history();
        replace_key(&mut transaction, &persisted, expected).await?;
        transaction.commit().await.map_err(database_error)
    }
}
