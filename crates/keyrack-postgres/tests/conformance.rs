// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of KeyRack.
//
// KeyRack is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// KeyRack is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with KeyRack. If not, see <https://www.gnu.org/licenses/>.
//
// Alternative commercial licensing is available; contact the Licensor.

//! `PostgreSQL` conformance tests — require a live database.
//!
//! Enable with: `cargo test -p keyrack-postgres --features live-tests`
//!
//! Env var: `DATABASE_URL=postgres://user:pass@host/db`

#![cfg(feature = "live-tests")]

use keyrack_postgres::PostgresStorage;

async fn make_store() -> PostgresStorage {
    let url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live PostgreSQL tests");
    PostgresStorage::connect(&url)
        .await
        .expect("failed to connect to PostgreSQL")
}

keyrack_test_support::storage_conformance_tests!(make_store().await);
keyrack_test_support::creation_conformance_tests!(make_store().await);

mod creation_postgres {
    use super::PostgresStorage;
    use keyrack_core::creation::{
        creation_correlation, same_json, CreationDispatch, CreationPhase,
    };
    use keyrack_core::error::KeyRackError;
    use keyrack_core::key::{KeyMaterial, ParentWrappedMaterial};
    use keyrack_core::storage::StorageBackend;
    use keyrack_core::wrapping::WrappingIdentifier;
    use keyrack_test_support::creation_conformance::{closure, fixture, resolved, TEST_ENVELOPE};
    use sqlx::postgres::PgPoolOptions;
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn pool_store() -> (PgPool, PostgresStorage) {
        let url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set for live PostgreSQL tests");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let store = PostgresStorage::from_pool(pool.clone()).await.unwrap();
        (pool, store)
    }

    #[tokio::test]
    async fn publication_sql_failure_rolls_back_key_and_journal_together() {
        let (pool, store) = pool_store().await;
        let (parent, request) = fixture();
        store.create_key(&parent).await.unwrap();
        resolved(&store, &request).await;

        // Generated UUIDs are the only interpolated values. The trigger affects
        // exactly this test's operation and cannot fail another test's writes.
        let trigger = format!("kr_test_fail_{}", Uuid::new_v4().simple());
        let function = format!("{trigger}_fn");
        let mut installation = pool.begin().await.unwrap();
        sqlx::query(&format!(
            "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'keyrack injected publication failure'; END; $$"
        ))
        .execute(&mut *installation)
        .await
        .unwrap();
        sqlx::query(&format!(
            "CREATE TRIGGER {trigger} BEFORE UPDATE OF phase ON kr_creation_journal \
             FOR EACH ROW WHEN (NEW.operation_id = '{}' AND NEW.phase = 'committed') \
             EXECUTE FUNCTION {function}()",
            request.operation
        ))
        .execute(&mut *installation)
        .await
        .unwrap();
        installation.commit().await.unwrap();

        let result = store
            .publish_creation(request.operation, request.owner, 3)
            .await;

        // Remove only owned test objects before asserting the captured result,
        // including when publication unexpectedly succeeds or fails elsewhere.
        let mut cleanup = pool.begin().await.unwrap();
        sqlx::query(&format!("DROP TRIGGER {trigger} ON kr_creation_journal"))
            .execute(&mut *cleanup)
            .await
            .unwrap();
        sqlx::query(&format!("DROP FUNCTION {function}()"))
            .execute(&mut *cleanup)
            .await
            .unwrap();
        cleanup.commit().await.unwrap();

        let error = result.expect_err("injected journal write failure must reject publication");
        assert!(error
            .to_string()
            .contains("keyrack injected publication failure"));
        assert!(matches!(
            store.get_key(&request.record.lid).await,
            Err(KeyRackError::KeyNotFound(lid)) if lid == request.record.lid
        ));
        let journal = store.get_creation(request.operation).await.unwrap();
        assert_eq!(journal.phase, CreationPhase::Resolved);
        assert_eq!(journal.revision, 3);
        assert!(journal.committed_record.is_none());
        assert!(store
            .read_creation_envelope(request.operation)
            .await
            .is_err());
        let published = store
            .publish_creation(request.operation, request.owner, 3)
            .await
            .unwrap();
        assert!(same_json(&published, &request.record).unwrap());
        drop(store);
        pool.close().await;
    }

    #[tokio::test]
    async fn independent_pools_cannot_reserve_the_same_child_version() {
        let (first_pool, first) = pool_store().await;
        let (second_pool, second) = pool_store().await;
        let (parent, request) = fixture();
        first.create_key(&parent).await.unwrap();
        let mut other = request.clone();
        other.operation = Uuid::new_v4();
        other.attempt = Uuid::new_v4();
        other.correlation = creation_correlation(other.operation, other.attempt);
        let material = other.material().unwrap().clone();
        // Use a different envelope reference: the negative control must exercise
        // child/version uniqueness, not the independent envelope-reference index.
        other.record.key_versions[0].material = KeyMaterial::ParentWrapped(
            ParentWrappedMaterial::new(
                material.provider_ref().clone(),
                material.security_domain().clone(),
                material.parent(),
                material.wrapping_context_version(),
                material.key_format().clone(),
                material.mechanism().clone(),
                WrappingIdentifier::new(format!("envelope-{}", other.operation)).unwrap(),
            )
            .unwrap(),
        );
        other.context_bytes = other.context().unwrap().canonical_bytes().unwrap();
        other.validate().unwrap();
        let (one, two) = tokio::join!(
            first.reserve_creation(&request),
            second.reserve_creation(&other)
        );
        assert_ne!(one.is_ok(), two.is_ok());
        let (winner, loser) = if one.is_ok() {
            (&request, &other)
        } else {
            (&other, &request)
        };
        assert_eq!(
            first.get_creation(winner.operation).await.unwrap().phase,
            CreationPhase::Reserved
        );
        assert!(second.get_creation(loser.operation).await.is_err());
        assert!(first.get_key(&request.record.lid).await.is_err());
        drop(first);
        drop(second);
        first_pool.close().await;
        second_pool.close().await;
    }

    #[tokio::test]
    async fn every_durable_phase_survives_pool_reconnect() {
        let (mut pool, mut store) = pool_store().await;
        let (parent, request) = fixture();
        store.create_key(&parent).await.unwrap();
        store.reserve_creation(&request).await.unwrap();
        for phase in [
            CreationPhase::Reserved,
            CreationPhase::Staged,
            CreationPhase::Resolved,
            CreationPhase::Committed,
        ] {
            drop(store);
            pool.close().await;
            (pool, store) = pool_store().await;
            assert_eq!(
                store.get_creation(request.operation).await.unwrap().phase,
                phase
            );
            if phase != CreationPhase::Committed {
                assert!(matches!(
                    store.get_key(&request.record.lid).await,
                    Err(KeyRackError::KeyNotFound(lid)) if lid == request.record.lid
                ));
                assert!(store
                    .read_creation_envelope(request.operation)
                    .await
                    .is_err());
            }
            match phase {
                CreationPhase::Reserved => {
                    assert!(matches!(
                        store
                            .claim_creation_dispatch(request.operation, request.owner)
                            .await
                            .unwrap(),
                        CreationDispatch::Started(_)
                    ));
                    store
                        .stage_creation(request.operation, request.owner, 1, TEST_ENVELOPE)
                        .await
                        .unwrap();
                }
                CreationPhase::Staged => {
                    store
                        .resolve_creation(request.operation, request.owner, 2, &closure(&request))
                        .await
                        .unwrap();
                }
                CreationPhase::Resolved => {
                    store
                        .publish_creation(request.operation, request.owner, 3)
                        .await
                        .unwrap();
                }
                CreationPhase::Committed => {
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
                    let retry = store
                        .publish_creation(request.operation, request.owner, 3)
                        .await
                        .unwrap();
                    assert!(same_json(&retry, &request.record).unwrap());
                }
            }
        }
        drop(store);
        pool.close().await;
    }

    #[tokio::test]
    async fn independent_pools_issue_one_dispatch_and_snapshot_is_owner_fenced() {
        let (first_pool, first) = pool_store().await;
        let (second_pool, second) = pool_store().await;
        let (parent, request) = fixture();
        first.create_key(&parent).await.unwrap();
        first.reserve_creation(&request).await.unwrap();
        let initial = first
            .creation_snapshot(request.operation, request.owner)
            .await
            .unwrap();
        assert!(!initial.journal.dispatch_started);
        assert!(initial.envelope.is_none());
        let (one, two) = tokio::join!(
            first.claim_creation_dispatch(request.operation, request.owner),
            second.claim_creation_dispatch(request.operation, request.owner)
        );
        let results = [one.unwrap(), two.unwrap()];
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
        drop(first);
        drop(second);
        first_pool.close().await;
        second_pool.close().await;

        let (pool, store) = pool_store().await;
        assert!(matches!(
            store
                .claim_creation_dispatch(request.operation, request.owner)
                .await
                .unwrap(),
            CreationDispatch::Existing(_)
        ));
        let mut wrong_owner = request.owner;
        wrong_owner.generation += 1;
        assert!(store
            .claim_creation_dispatch(request.operation, wrong_owner)
            .await
            .is_err());
        assert!(store
            .creation_snapshot(request.operation, wrong_owner)
            .await
            .is_err());
        store
            .stage_creation(request.operation, request.owner, 1, TEST_ENVELOPE)
            .await
            .unwrap();
        let snapshot = store
            .creation_snapshot(request.operation, request.owner)
            .await
            .unwrap();
        assert_eq!(snapshot.journal.phase, CreationPhase::Staged);
        assert!(snapshot.journal.dispatch_started);
        assert_eq!(snapshot.envelope.as_deref(), Some(TEST_ENVELOPE));
        assert!(store
            .read_creation_envelope(request.operation)
            .await
            .is_err());
        assert!(store.get_key(&request.record.lid).await.is_err());
        drop(store);
        pool.close().await;
    }
}
