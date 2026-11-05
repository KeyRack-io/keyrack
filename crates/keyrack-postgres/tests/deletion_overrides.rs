// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

#![cfg(feature = "live-tests")]

use keyrack_core::creation::same_json;
use keyrack_core::error::KeyRackError;
use keyrack_core::key::KeyState;
use keyrack_core::storage::StorageBackend;
use keyrack_postgres::PostgresStorage;
use keyrack_test_support::creation_conformance::{fixture, resolved, TEST_ENVELOPE};
use keyrack_test_support::fixtures::unique_test_key_record;

async fn store() -> PostgresStorage {
    PostgresStorage::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap()
}

async fn published(
    store: &PostgresStorage,
) -> (
    keyrack_core::key::KeyRecord,
    keyrack_core::creation::CreationRequest,
) {
    let (parent, request) = fixture();
    store.create_key(&parent).await.unwrap();
    resolved(store, &request).await;
    store
        .publish_creation(request.operation, request.owner, 3)
        .await
        .unwrap();
    (parent, request)
}

#[tokio::test]
async fn override_snapshot_survives_reconnect_cancel_clears_it_and_parent_loss_preserves_child() {
    let first = store().await;
    let (parent, request) = published(&first).await;
    let child_before = first.get_key(&request.record.lid).await.unwrap();
    let at = chrono::Utc::now() + chrono::Duration::days(7);
    assert!(matches!(
        first
            .schedule_destruction(&parent.lid, parent.occ_version, at, false)
            .await,
        Err(KeyRackError::DeletionDependencyRefused { .. })
    ));
    let scheduled = first
        .schedule_destruction(&parent.lid, parent.occ_version, at, true)
        .await
        .unwrap()
        .record;
    let approved = first.deletion_intent(&parent.lid).await.unwrap().unwrap();
    assert!(approved.allow_dependent_data_loss);
    assert_eq!(approved.approved_dependents.len(), 1);
    drop(first);
    let reopened = store().await;
    assert_eq!(
        reopened.deletion_intent(&parent.lid).await.unwrap(),
        Some(approved)
    );
    let cancelled = reopened
        .cancel_destruction(&parent.lid, scheduled.occ_version)
        .await
        .unwrap();
    assert_eq!(cancelled.state, KeyState::Disabled);
    assert!(reopened
        .deletion_intent(&parent.lid)
        .await
        .unwrap()
        .is_none());
    let scheduled = reopened
        .schedule_destruction(&parent.lid, cancelled.occ_version, at, true)
        .await
        .unwrap()
        .record;
    let claim = reopened
        .claim_destruction(
            &parent.lid,
            scheduled.occ_version,
            at + chrono::Duration::seconds(1),
        )
        .await
        .unwrap()
        .unwrap();
    reopened.complete_destruction(claim).await.unwrap();
    let child_after = reopened.get_key(&request.record.lid).await.unwrap();
    assert!(same_json(&child_before, &child_after).unwrap());
    assert_eq!(
        reopened
            .read_creation_envelope(request.operation)
            .await
            .unwrap(),
        TEST_ENVELOPE
    );
    let lost = reopened
        .destroyed_wrapping_parents(&request.record.lid)
        .await
        .unwrap();
    assert_eq!(lost.len(), 1);
    assert_eq!(lost[0].version, 1);
    assert_eq!(lost[0].parent_lid, parent.lid);
    assert_eq!(lost[0].parent_version, 1);
}

#[tokio::test]
async fn dependent_appearing_after_approval_refuses_claim_without_changing_pending_state() {
    let store = store().await;
    let (parent, request) = published(&store).await;
    let at = chrono::Utc::now() - chrono::Duration::seconds(1);
    let scheduled = store
        .schedule_destruction(&parent.lid, parent.occ_version, at, true)
        .await
        .unwrap()
        .record;
    // Imported metadata is another writer path, not a new creation reservation.
    let mut newcomer = request.record.clone();
    newcomer.lid = unique_test_key_record(KeyState::Enabled).lid;
    store.create_key(&newcomer).await.unwrap();
    assert!(
        matches!(store.claim_destruction(&parent.lid, scheduled.occ_version, chrono::Utc::now()).await,
        Err(KeyRackError::DeletionDependencyRefused{reason,..}) if reason=="dependent_outside_approved_snapshot")
    );
    assert!(same_json(&store.get_key(&parent.lid).await.unwrap(), &scheduled).unwrap());
    assert_eq!(
        store.get_key(&parent.lid).await.unwrap().state,
        KeyState::PendingDeletion
    );
}

#[tokio::test]
async fn wrapped_child_destruction_erases_only_owned_envelopes() {
    let store = store().await;
    let (parent, request) = published(&store).await;
    let child = store.get_key(&request.record.lid).await.unwrap();
    let at = chrono::Utc::now() - chrono::Duration::seconds(1);
    let scheduled = store
        .schedule_destruction(&child.lid, child.occ_version, at, false)
        .await
        .unwrap()
        .record;
    let claim = store
        .claim_destruction(&child.lid, scheduled.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    store.complete_destruction(claim).await.unwrap();
    assert_eq!(
        store.get_key(&child.lid).await.unwrap().state,
        KeyState::Destroyed
    );
    assert!(store
        .read_creation_envelope(request.operation)
        .await
        .is_err());
    assert!(same_json(&store.get_key(&parent.lid).await.unwrap(), &parent).unwrap());
    assert!(store
        .destruction_dependencies(&parent.lid)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn generic_schedule_change_does_not_reuse_override_approval() {
    let store = store().await;
    let (parent, _) = published(&store).await;
    let at = chrono::Utc::now() - chrono::Duration::seconds(1);
    let mut scheduled = store
        .schedule_destruction(&parent.lid, parent.occ_version, at, true)
        .await
        .unwrap()
        .record;
    scheduled.occ_version += 1;
    scheduled.scheduled_deletion_at = Some(at - chrono::Duration::seconds(1));
    store.update_key(&scheduled).await.unwrap();
    assert!(store.deletion_intent(&parent.lid).await.unwrap().is_none());
    assert!(
        matches!(store.claim_destruction(&parent.lid, scheduled.occ_version, chrono::Utc::now()).await,
        Err(KeyRackError::DeletionDependencyRefused{reason,..}) if reason=="dependent_data_loss_not_approved")
    );
}

#[tokio::test]
async fn failed_completion_rolls_back_wrapped_envelope_erasure() {
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let store = PostgresStorage::from_pool(pool.clone()).await.unwrap();
    let (_, request) = published(&store).await;
    let child = store.get_key(&request.record.lid).await.unwrap();
    let at = chrono::Utc::now() - chrono::Duration::seconds(1);
    let scheduled = store
        .schedule_destruction(&child.lid, child.occ_version, at, false)
        .await
        .unwrap()
        .record;
    let claim = store
        .claim_destruction(&child.lid, scheduled.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    let trigger = format!("envelope_rollback_{}", uuid::Uuid::new_v4().simple());
    let function = format!("{trigger}_fn");
    sqlx::query(&format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected envelope erasure rollback'; END; $$")).execute(&pool).await.unwrap();
    sqlx::query(&format!("CREATE TRIGGER {trigger} BEFORE UPDATE OF completed ON kr_destruction_journal FOR EACH ROW WHEN (NEW.operation_id = '{}') EXECUTE FUNCTION {function}()", claim.operation())).execute(&pool).await.unwrap();
    let result = store.complete_destruction(claim).await;
    sqlx::query(&format!("DROP TRIGGER {trigger} ON kr_destruction_journal"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION {function}()"))
        .execute(&pool)
        .await
        .unwrap();
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("injected envelope erasure rollback"));
    assert_eq!(
        store.get_key(&child.lid).await.unwrap().state,
        KeyState::PendingDeletion
    );
    assert_eq!(
        store
            .read_creation_envelope(request.operation)
            .await
            .unwrap(),
        TEST_ENVELOPE
    );
    let recovered = store
        .claim_destruction(&child.lid, scheduled.occ_version + 1, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert!(recovered.is_recovered());
    store.complete_destruction(recovered).await.unwrap();
    assert!(store
        .read_creation_envelope(request.operation)
        .await
        .is_err());
}

#[tokio::test]
async fn migrated_child_erasure_removes_all_version_envelopes() {
    let store = store().await;
    let (request, creations) = keyrack_test_support::migration_conformance::seeded(&store).await;
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
    // A durable historical marker must not poison a version rewrapped in place.
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::query("INSERT INTO kr_destroyed_wrapping_parents(child_lid,child_version,parent_lid,parent_version) VALUES($1,'1',$2,'1')")
        .bind(child.lid.to_string()).bind(request.old_parent.lid.to_string())
        .execute(&pool).await.unwrap();
    let snapshot = store.wrapped_key_snapshot(&child.lid, 1).await.unwrap();
    assert_eq!(snapshot.parent.lid, request.new_parent.lid);
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
async fn nonterminal_migration_roles_refuse_even_with_override() {
    for staged in [false, true] {
        let store = store().await;
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
                matches!(error, KeyRackError::DeletionDependencyRefused { ref reason, .. } if reason == "in_flight_journal")
            );
        }
    }
}

#[tokio::test]
async fn schedule_reports_logical_children_from_its_admission_snapshot() {
    let store = store().await;
    let parent = unique_test_key_record(KeyState::Enabled);
    store.create_key(&parent).await.unwrap();
    let at = chrono::Utc::now() + chrono::Duration::days(7);
    let scheduled = store
        .schedule_destruction(&parent.lid, parent.occ_version, at, false)
        .await
        .unwrap();
    assert_eq!(scheduled.logical_only_children, 0);
    assert_eq!(scheduled.record.state, KeyState::PendingDeletion);
    let cancelled = store
        .cancel_destruction(&parent.lid, scheduled.record.occ_version)
        .await
        .unwrap();

    // Logical ancestry is informational even when a resident child is destroyed.
    for state in [KeyState::Enabled, KeyState::Destroyed] {
        let mut child = unique_test_key_record(state);
        child.parent_lid = Some(parent.lid);
        store.create_key(&child).await.unwrap();
    }
    let scheduled = store
        .schedule_destruction(&parent.lid, cancelled.occ_version, at, false)
        .await
        .unwrap();
    assert_eq!(scheduled.logical_only_children, 2);
    assert_eq!(scheduled.record.state, KeyState::PendingDeletion);
    let intent = store.deletion_intent(&parent.lid).await.unwrap().unwrap();
    assert!(!intent.allow_dependent_data_loss);
    assert!(intent.approved_dependents.is_empty());
}

#[tokio::test]
async fn claimed_parent_loss_survives_completion_failure_and_reconnect() {
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let first = PostgresStorage::from_pool(pool.clone()).await.unwrap();
    let (parent, request) = published(&first).await;
    let pending = first
        .schedule_destruction(&parent.lid, parent.occ_version, chrono::Utc::now(), true)
        .await
        .unwrap()
        .record;
    let claim = first
        .claim_destruction(&parent.lid, pending.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    let operation = claim.operation();
    let lost = first
        .destroyed_wrapping_parents(&request.record.lid)
        .await
        .unwrap();
    assert_eq!(
        lost.len(),
        1,
        "claim must commit the loss decision before provider dispatch"
    );
    assert_eq!(
        (lost[0].version, lost[0].parent_lid, lost[0].parent_version),
        (1, parent.lid, 1)
    );
    assert!(matches!(
        first.wrapped_key_snapshot(&request.record.lid, 1).await,
        Err(KeyRackError::WrappingParentDestroyed)
    ));
    let trigger = format!("parent_loss_{}", uuid::Uuid::new_v4().simple());
    let function = format!("{trigger}_fn");
    sqlx::query(&format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected parent completion failure'; END; $$")).execute(&pool).await.unwrap();
    sqlx::query(&format!("CREATE TRIGGER {trigger} BEFORE UPDATE OF completed ON kr_destruction_journal FOR EACH ROW WHEN (NEW.operation_id = '{operation}') EXECUTE FUNCTION {function}()")).execute(&pool).await.unwrap();
    let result = first.complete_destruction(claim).await;
    sqlx::query(&format!("DROP TRIGGER {trigger} ON kr_destruction_journal"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION {function}()"))
        .execute(&pool)
        .await
        .unwrap();
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("injected parent completion failure"));
    drop(first);
    let reopened = store().await;
    assert_eq!(
        reopened
            .destroyed_wrapping_parents(&request.record.lid)
            .await
            .unwrap(),
        lost
    );
    assert!(matches!(
        reopened.wrapped_key_snapshot(&request.record.lid, 1).await,
        Err(KeyRackError::WrappingParentDestroyed)
    ));
    // Simulate an incomplete journal from before loss-marker deployment. Its
    // retained fence is already authoritative before any worker backfills it.
    sqlx::query("DELETE FROM kr_destroyed_wrapping_parents WHERE parent_lid=$1")
        .bind(parent.lid.to_string())
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        reopened.wrapped_key_snapshot(&request.record.lid, 1).await,
        Err(KeyRackError::WrappingParentDestroyed)
    ));
    let parent = reopened.get_key(&parent.lid).await.unwrap();
    let recovered = reopened
        .claim_destruction(&parent.lid, parent.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert!(recovered.is_recovered());
    assert_eq!(recovered.operation(), operation);
    assert_eq!(
        reopened
            .destroyed_wrapping_parents(&request.record.lid)
            .await
            .unwrap(),
        lost
    );
    assert_eq!(
        reopened
            .complete_destruction(recovered)
            .await
            .unwrap()
            .state,
        KeyState::Destroyed
    );
    assert_eq!(
        reopened
            .read_creation_envelope(request.operation)
            .await
            .unwrap(),
        TEST_ENVELOPE
    );
}

#[tokio::test]
async fn existing_database_pending_deletion_without_schedule_has_no_implicit_approval() {
    use sqlx::postgres::PgPoolOptions;
    let url = std::env::var("DATABASE_URL").unwrap();
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("deletion_upgrade_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let search_path = format!("SET search_path TO {schema}");
    let pool = PgPoolOptions::new()
        .after_connect(move |connection, _| {
            let search_path = search_path.clone();
            Box::pin(async move {
                sqlx::query(&search_path).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    // A pre-upgrade database has key rows and no deletion approval tables.
    sqlx::query("CREATE TABLE kr_keys(lid TEXT PRIMARY KEY, record_json JSONB NOT NULL, occ_version BIGINT NOT NULL)")
        .execute(&pool).await.unwrap();
    let (mut parent, request) = fixture();
    parent.state = KeyState::PendingDeletion;
    parent.scheduled_deletion_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    let unreferenced = keyrack_test_support::destruction_conformance::due(unique_test_key_record(
        KeyState::Enabled,
    ));
    for record in [&parent, &request.record, &unreferenced] {
        sqlx::query("INSERT INTO kr_keys(lid,record_json,occ_version) VALUES($1,$2,$3)")
            .bind(record.lid.to_string())
            .bind(serde_json::to_value(record).unwrap())
            .bind(i64::try_from(record.occ_version).unwrap())
            .execute(&pool)
            .await
            .unwrap();
    }
    let upgraded = PostgresStorage::from_pool(pool.clone()).await.unwrap();
    assert!(upgraded
        .deletion_intent(&parent.lid)
        .await
        .unwrap()
        .is_none());
    assert!(
        matches!(upgraded.claim_destruction(&parent.lid, parent.occ_version, chrono::Utc::now()).await,
        Err(KeyRackError::DeletionDependencyRefused { reason, .. }) if reason == "dependent_data_loss_not_approved")
    );
    assert_eq!(
        upgraded.get_key(&parent.lid).await.unwrap().state,
        KeyState::PendingDeletion
    );
    let claim = upgraded
        .claim_destruction(
            &unreferenced.lid,
            unreferenced.occ_version,
            chrono::Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        upgraded.complete_destruction(claim).await.unwrap().state,
        KeyState::Destroyed
    );
    drop(upgraded);
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
}
