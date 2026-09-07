// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Storage fencing tests, not proof of provider destruction or authorization.

use crate::creation_conformance::fixture;
use crate::fixtures::unique_test_key_record;
use keyrack_core::creation::same_json;
use keyrack_core::destruction::DestructionClaim;
use keyrack_core::key::{KeyRecord, KeyState, ProviderRef};
use keyrack_core::storage::StorageBackend;

pub fn due(mut record: KeyRecord) -> KeyRecord {
    record.state = KeyState::PendingDeletion;
    record.scheduled_deletion_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    record
}

pub async fn one_shot_and_terminal_fence(store: &dyn StorageBackend) {
    let record = due(unique_test_key_record(KeyState::Enabled));
    store.create_key(&record).await.unwrap();
    let claim = store
        .claim_destruction(&record.lid, record.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.record().occ_version, record.occ_version + 1);
    assert!(same_json(&claim.record().key_versions, &record.key_versions).unwrap());
    assert!(store
        .claim_destruction(&record.lid, claim.record().occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .is_none());
    let mut stale = record.clone();
    stale.transition_to(KeyState::Disabled).unwrap();
    assert!(store.update_key(&stale).await.is_err());
    for change in 0..7 {
        let mut next = claim.record().clone();
        next.occ_version += 1;
        match change {
            0 => next.state = KeyState::Disabled,
            1 => next.state = KeyState::Enabled,
            2 => next.description = "cannot mutate even with fresh OCC".into(),
            3 => next.key_versions.clear(),
            4 => next.provider_ref = Some(ProviderRef::new("replacement")),
            5 => next.scheduled_deletion_at = None,
            _ => next.state = KeyState::Destroyed,
        }
        assert!(store.update_key(&next).await.is_err());
    }
    let mut wrong = claim.record().clone();
    wrong.provider_ref = Some(ProviderRef::new("other-provider"));
    let forged = DestructionClaim::committed(claim.operation(), wrong).unwrap();
    assert!(store.complete_destruction(forged).await.is_err());
    let forged = DestructionClaim::committed(uuid::Uuid::new_v4(), claim.record().clone()).unwrap();
    assert!(store.complete_destruction(forged).await.is_err());
    // Simulate success from every provider at the trusted storage boundary.
    let completed = store.complete_destruction(claim).await.unwrap();
    assert_eq!(completed.state, KeyState::Destroyed);
    assert!(store
        .claim_destruction(&record.lid, completed.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .is_none());
    let mut resurrect = completed;
    resurrect.occ_version += 1;
    resurrect.state = KeyState::Enabled;
    assert!(store.update_key(&resurrect).await.is_err());
    assert!(store.create_key(&record).await.is_err());
}

pub async fn eligibility_and_cancel_first(store: &dyn StorageBackend) {
    for case in 0..9 {
        let mut record = due(unique_test_key_record(KeyState::Enabled));
        match case {
            0 => record.state = KeyState::Enabled,
            1 => record.scheduled_deletion_at = None,
            2 => {
                record.scheduled_deletion_at = Some(chrono::Utc::now() + chrono::Duration::days(1));
            }
            3 => record.key_versions.clear(),
            4 => record.key_versions.push(record.key_versions[0].clone()),
            5 => record.current_key_version = 99,
            6 => record.key_versions[0].version_number = 0,
            7 => {
                record.key_versions[0].material =
                    fixture().1.record.key_versions[0].material.clone();
            }
            _ => record.occ_version = i64::MAX as u64,
        }
        store.create_key(&record).await.unwrap();
        assert!(
            store
                .claim_destruction(&record.lid, record.occ_version, chrono::Utc::now())
                .await
                .is_err(),
            "case {case}"
        );
        assert!(same_json(&store.get_key(&record.lid).await.unwrap(), &record).unwrap());
    }
    let record = due(unique_test_key_record(KeyState::Enabled));
    store.create_key(&record).await.unwrap();
    assert!(store
        .claim_destruction(&record.lid, record.occ_version + 1, chrono::Utc::now())
        .await
        .is_err());
    let mut cancelled = record.clone();
    cancelled.transition_to(KeyState::Disabled).unwrap();
    cancelled.scheduled_deletion_at = None;
    store.update_key(&cancelled).await.unwrap();
    assert!(store
        .claim_destruction(&record.lid, record.occ_version, chrono::Utc::now())
        .await
        .is_err());
    assert!(store
        .claim_destruction(&record.lid, cancelled.occ_version, chrono::Utc::now())
        .await
        .is_err());
    // Denied claims did not leave a tombstone: a fresh authorized schedule works.
    let mut scheduled = due(cancelled);
    scheduled.occ_version += 1;
    store.update_key(&scheduled).await.unwrap();
    assert!(store
        .claim_destruction(&record.lid, scheduled.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .is_some());
}

pub async fn creation_references_fence_destruction(store: &dyn StorageBackend) {
    for phase in 0..4 {
        let (parent, request) = fixture();
        store.create_key(&parent).await.unwrap();
        if phase == 0 {
            store.reserve_creation(&request).await.unwrap();
        } else {
            store.reserve_creation(&request).await.unwrap();
            store
                .claim_creation_dispatch(request.operation, request.owner)
                .await
                .unwrap();
            store
                .stage_creation(
                    request.operation,
                    request.owner,
                    1,
                    crate::creation_conformance::TEST_ENVELOPE,
                )
                .await
                .unwrap();
            if phase >= 2 {
                store
                    .resolve_creation(
                        request.operation,
                        request.owner,
                        2,
                        &crate::creation_conformance::closure(&request),
                    )
                    .await
                    .unwrap();
            }
            if phase == 3 {
                store
                    .publish_creation(request.operation, request.owner, 3)
                    .await
                    .unwrap();
            }
        }
        let mut pending = due(parent);
        pending.occ_version += 1;
        store.update_key(&pending).await.unwrap();
        assert!(store
            .claim_destruction(&pending.lid, pending.occ_version, chrono::Utc::now())
            .await
            .is_err());
    }
    // Pending creation of a new child version also pins its old resident history.
    let (parent, mut request) = fixture();
    let mut child = unique_test_key_record(KeyState::Enabled);
    child.lid = request.record.lid;
    store.create_key(&parent).await.unwrap();
    store.create_key(&child).await.unwrap();
    let mut next = child.clone();
    next.occ_version += 1;
    next.current_key_version = 2;
    next.key_versions[0].is_primary = false;
    let mut wrapped = request.record.key_versions[0].clone();
    wrapped.version_number = 2;
    next.key_versions.push(wrapped);
    request.record = next;
    request.expected_key_occ = Some(child.occ_version);
    request.context_bytes = request.context().unwrap().canonical_bytes().unwrap();
    store.reserve_creation(&request).await.unwrap();
    let mut pending = due(child);
    pending.occ_version += 1;
    store.update_key(&pending).await.unwrap();
    assert!(store
        .claim_destruction(&pending.lid, pending.occ_version, chrono::Utc::now())
        .await
        .is_err());
}

pub async fn raw_wrapped_edges_and_new_references(store: &dyn StorageBackend) {
    let (parent, mut request) = fixture();
    store.create_key(&parent).await.unwrap();
    // Material, not the logical parent_lid, is authoritative for destruction.
    request.record.parent_lid = None;
    store.create_key(&request.record).await.unwrap();
    let mut pending = due(parent);
    pending.occ_version += 1;
    store.update_key(&pending).await.unwrap();
    assert!(store
        .claim_destruction(&pending.lid, pending.occ_version, chrono::Utc::now())
        .await
        .is_err());

    let (parent, request) = fixture();
    let pending = due(parent);
    store.create_key(&pending).await.unwrap();
    let claim = store
        .claim_destruction(&pending.lid, pending.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert!(store.reserve_creation(&request).await.is_err());
    assert!(store.create_key(&request.record).await.is_err());
    let mut unrelated = unique_test_key_record(KeyState::Enabled);
    store.create_key(&unrelated).await.unwrap();
    unrelated.occ_version += 1;
    let mut historical = request.record.key_versions[0].clone();
    historical.version_number = 2;
    historical.is_primary = false;
    unrelated.key_versions.push(historical);
    assert!(store.update_key(&unrelated).await.is_err());
    drop(claim); // Lost response/process death: no expiry-based second ticket.
    assert!(store
        .claim_destruction(&pending.lid, pending.occ_version + 1, chrono::Utc::now())
        .await
        .unwrap()
        .is_none());
}

// The two storage instances must share a database but use independent handles.
pub async fn competing_claims(first: &dyn StorageBackend, second: &dyn StorageBackend) {
    let record = due(unique_test_key_record(KeyState::Enabled));
    first.create_key(&record).await.unwrap();
    let (a, b) = tokio::join!(
        first.claim_destruction(&record.lid, record.occ_version, chrono::Utc::now()),
        second.claim_destruction(&record.lid, record.occ_version, chrono::Utc::now())
    );
    let tickets = [a.unwrap(), b.unwrap()];
    assert_eq!(tickets.iter().filter(|v| v.is_some()).count(), 1);
    drop(tickets);
    assert!(second
        .claim_destruction(&record.lid, record.occ_version + 1, chrono::Utc::now())
        .await
        .unwrap()
        .is_none());
}

#[macro_export]
macro_rules! destruction_conformance_tests {
    ($create:expr) => {
        mod destruction_conformance {
            use super::*;
            #[tokio::test]
            async fn one_shot_and_terminal_fence() {
                $crate::destruction_conformance::one_shot_and_terminal_fence(&$create).await;
            }
            #[tokio::test]
            async fn eligibility_and_cancel_first() {
                $crate::destruction_conformance::eligibility_and_cancel_first(&$create).await;
            }
            #[tokio::test]
            async fn creation_references_fence_destruction() {
                $crate::destruction_conformance::creation_references_fence_destruction(&$create)
                    .await;
            }
            #[tokio::test]
            async fn raw_wrapped_edges_and_new_references() {
                $crate::destruction_conformance::raw_wrapped_edges_and_new_references(&$create)
                    .await;
            }
        }
    };
}
