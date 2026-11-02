// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared storage proofs; envelope bytes are synthetic, not provider qualification.
use crate::creation_conformance::{fixture, replace_envelope_ref, resolved};
use keyrack_core::creation::{creation_correlation, same_json, CreationPhase, CreationRequest};
use keyrack_core::error::KeyRackError;
use keyrack_core::key::{KeyMaterial, KeyRecord, KeyState, ProviderRef};
use keyrack_core::migration::{MigrationPhase, MigrationRequest};
use keyrack_core::storage::StorageBackend;
use uuid::Uuid;

pub fn next_creation(current: &KeyRecord, previous: &CreationRequest) -> CreationRequest {
    let mut request = previous.clone();
    request.operation = Uuid::new_v4();
    request.attempt = Uuid::new_v4();
    request.correlation = creation_correlation(request.operation, request.attempt);
    request.expected_key_occ = Some(current.occ_version);
    request.record = current.clone();
    request.record.occ_version += 1;
    request.record.current_key_version += 1;
    request.record.updated_at = chrono::Utc::now();
    for version in &mut request.record.key_versions {
        version.is_primary = false;
    }
    let mut version = previous.record.primary_version().unwrap().clone();
    version.version_number = request.record.current_key_version;
    version.is_primary = true;
    request.record.key_versions.push(version);
    let operation = request.operation;
    replace_envelope_ref(&mut request, format!("creation:{operation}"));
    request
}

pub async fn seeded(store: &dyn StorageBackend) -> (MigrationRequest, Vec<CreationRequest>) {
    let (old, mut first) = fixture();
    let operation = first.operation;
    replace_envelope_ref(&mut first, format!("creation:{operation}"));
    store.create_key(&old).await.unwrap();
    resolved(store, &first).await;
    let child = store
        .publish_creation(first.operation, first.owner, 3)
        .await
        .unwrap();
    let second = next_creation(&child, &first);
    resolved(store, &second).await;
    let child = store
        .publish_creation(second.operation, second.owner, 3)
        .await
        .unwrap();
    let (new, _) = fixture();
    store.create_key(&new).await.unwrap();
    let request = MigrationRequest::new(Uuid::new_v4(), Some(new.lid), child, old, new).unwrap();
    (request, vec![first, second])
}

pub fn envelopes() -> Vec<Vec<u8>> {
    vec![
        b"new-version-one-envelope".to_vec(),
        b"new-version-two-envelope".to_vec(),
    ]
}

pub async fn atomic_publication_and_retirement(store: &dyn StorageBackend) {
    let (request, creations) = seeded(store).await;
    let operation = request.operation;
    assert_eq!(
        store.reserve_migration(&request).await.unwrap().phase,
        MigrationPhase::Reserved
    );
    let mut timestamp_retry = request.clone();
    timestamp_retry.proposed.updated_at += chrono::Duration::seconds(1);
    assert!(same_json(
        &store
            .reserve_migration(&timestamp_retry)
            .await
            .unwrap()
            .request,
        &request
    )
    .unwrap());
    assert!(store.commit_migration(operation).await.is_err());
    assert!(store
        .stage_migration(operation, &envelopes()[..1])
        .await
        .is_err());
    assert!(same_json(
        &store.get_key(&request.child.lid).await.unwrap(),
        &request.child
    )
    .unwrap());
    store
        .stage_migration(operation, &envelopes())
        .await
        .unwrap();
    assert!(store.read_migration_envelope(operation, 1).await.is_err());
    assert!(same_json(
        &store.get_key(&request.child.lid).await.unwrap(),
        &request.child
    )
    .unwrap());
    let published = store.commit_migration(operation).await.unwrap();
    assert!(same_json(&published, &request.proposed).unwrap());
    let mut changed_spec = published.clone();
    changed_spec.occ_version += 1;
    changed_spec.key_spec = keyrack_core::key::KeySpec::Aes128;
    assert!(
        store.update_key(&changed_spec).await.is_err(),
        "migrated child spec remains immutable"
    );
    let mut changed_provider = published.clone();
    changed_provider.occ_version += 1;
    changed_provider.provider_ref = Some(ProviderRef::new("replacement-provider"));
    assert!(
        store.update_key(&changed_provider).await.is_err(),
        "migrated child provider remains immutable"
    );
    let mut changed_parent_material = request.new_parent.clone();
    changed_parent_material.occ_version += 1;
    if let KeyMaterial::ProviderResident { key_handle, .. } =
        &mut changed_parent_material.key_versions[0].material
    {
        key_handle.key_id = "replacement-material".into();
    }
    assert!(
        store.update_key(&changed_parent_material).await.is_err(),
        "migrated envelope protects target parent material"
    );

    assert!(same_json(
        &store.commit_migration(operation).await.unwrap(),
        &published
    )
    .unwrap());
    for creation in &creations {
        assert!(store
            .read_creation_envelope(creation.operation)
            .await
            .is_err());
        assert_eq!(
            store.get_creation(creation.operation).await.unwrap().phase,
            CreationPhase::Committed
        );
        assert!(same_json(
            &store
                .publish_creation(creation.operation, creation.owner, 3)
                .await
                .unwrap(),
            &creation.record
        )
        .unwrap());
    }
    for version in 1..=2 {
        assert_eq!(
            store
                .read_migration_envelope(operation, version)
                .await
                .unwrap(),
            envelopes()[(version - 1) as usize]
        );
    }
    let mut old = request.old_parent.clone();
    old.state = KeyState::PendingDeletion;
    old.scheduled_deletion_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    old.occ_version += 1;
    store.update_key(&old).await.unwrap();
    assert!(store
        .claim_destruction(&old.lid, old.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .is_some());
    // A later migration retires the previous migration envelopes, without losing operation replay.
    let (third, _) = fixture();
    store.create_key(&third).await.unwrap();
    let next = MigrationRequest::new(
        Uuid::new_v4(),
        Some(third.lid),
        published,
        request.new_parent.clone(),
        third,
    )
    .unwrap();
    store.reserve_migration(&next).await.unwrap();
    store
        .stage_migration(next.operation, &envelopes())
        .await
        .unwrap();
    store.commit_migration(next.operation).await.unwrap();
    assert!(store.read_migration_envelope(operation, 1).await.is_err());
    assert!(same_json(
        &store.commit_migration(operation).await.unwrap(),
        &request.proposed
    )
    .unwrap());
}

fn retryable<T: std::fmt::Debug>(result: keyrack_core::error::Result<T>) {
    let error = result.expect_err("in-flight migration must refuse conflicting work");
    assert!(
        matches!(error, KeyRackError::ProviderUnavailable(_)),
        "expected retryable refusal, got {error:?}"
    );
}

pub async fn all_writer_fences(store: &dyn StorageBackend) {
    let (request, creations) = seeded(store).await;
    store.reserve_migration(&request).await.unwrap();
    for record in [&request.child, &request.old_parent, &request.new_parent] {
        retryable(store.check_migration_fence(&record.lid).await);
        let mut update = record.clone();
        update.occ_version += 1;
        update.updated_at += chrono::Duration::seconds(1);
        retryable(store.update_key(&update).await);
        // Generic rotation is an append with unchanged old material.
        update.current_key_version += 1;
        for version in &mut update.key_versions {
            version.is_primary = false;
        }
        let mut version = record.primary_version().unwrap().clone();
        version.version_number = update.current_key_version;
        version.is_primary = true;
        update.key_versions.push(version);
        retryable(store.update_key(&update).await);
        retryable(
            store
                .claim_destruction(&record.lid, record.occ_version, chrono::Utc::now())
                .await,
        );
    }
    let rotate = next_creation(&request.child, &creations[1]);
    retryable(store.reserve_creation(&rotate).await);
    // A second migration cannot share any of the reserved identities.
    let mut other = request.clone();
    other.operation = Uuid::new_v4();
    other = MigrationRequest::new(
        other.operation,
        other.requested_parent,
        other.child,
        other.old_parent,
        other.new_parent,
    )
    .unwrap();
    retryable(store.reserve_migration(&other).await);
    // New child creation under either parent conflicts under the same writer lock.
    for parent in [&request.old_parent, &request.new_parent] {
        let (_, mut create) = fixture();
        create.expected_parent_occ = parent.occ_version;
        create.record.parent_lid = Some(parent.lid);
        let KeyMaterial::ParentWrapped(material) = &create.record.key_versions[0].material else {
            panic!()
        };
        create.record.key_versions[0].material = KeyMaterial::ParentWrapped(
            keyrack_core::material::ParentWrappedMaterial::new(
                material.provider_ref().clone(),
                material.security_domain().clone(),
                keyrack_core::wrapping::VersionedKeyId::new(parent.lid, 1).unwrap(),
                material.wrapping_context_version(),
                material.key_format().clone(),
                material.mechanism().clone(),
                material.wrapped_material_ref().clone(),
            )
            .unwrap(),
        );
        create.context_bytes = create.context().unwrap().canonical_bytes().unwrap();
        retryable(store.reserve_creation(&create).await);
    }
}

pub async fn pending_creation_and_occ_preempt_migration(store: &dyn StorageBackend) {
    let (request, creations) = seeded(store).await;
    for slot in 0..3 {
        let mut stale = request.clone();
        match slot {
            0 => stale.child.occ_version += 1,
            1 => stale.old_parent.occ_version += 1,
            _ => stale.new_parent.occ_version += 1,
        }
        stale = MigrationRequest::new(
            Uuid::new_v4(),
            stale.requested_parent,
            stale.child,
            stale.old_parent,
            stale.new_parent,
        )
        .unwrap();
        assert!(store.reserve_migration(&stale).await.is_err());
    }
    let rotation = next_creation(&request.child, &creations[1]);
    store.reserve_creation(&rotation).await.unwrap();
    retryable(store.reserve_migration(&request).await);
    assert!(store
        .get_migration(request.operation)
        .await
        .unwrap()
        .is_none());
}

pub async fn deny_paths_and_parent_immutability(store: &dyn StorageBackend) {
    let (request, _) = seeded(store).await;
    let mut update = request.child.clone();
    update.occ_version += 1;
    update.parent_lid = Some(request.new_parent.lid);
    assert!(store.update_key(&update).await.is_err());
    let mut resident_reparent = request.new_parent.clone();
    resident_reparent.occ_version += 1;
    resident_reparent.parent_lid = Some(request.old_parent.lid);
    assert!(
        store.update_key(&resident_reparent).await.is_err(),
        "resident parent_lid changes also require migration"
    );
    let mut cross = request.new_parent.clone();
    if let KeyMaterial::ProviderResident { provider_ref, .. } = &mut cross.key_versions[0].material
    {
        *provider_ref = Some(ProviderRef::new("different-provider"));
    }
    assert!(MigrationRequest::new(
        Uuid::new_v4(),
        Some(cross.lid),
        request.child.clone(),
        request.old_parent.clone(),
        cross
    )
    .is_err());
    assert!(MigrationRequest::new(
        Uuid::new_v4(),
        Some(request.child.lid),
        request.child.clone(),
        request.old_parent.clone(),
        request.child.clone()
    )
    .is_err());
    let mut scheduled = request.new_parent.clone();
    scheduled.scheduled_deletion_at = Some(chrono::Utc::now());
    assert!(MigrationRequest::new(
        Uuid::new_v4(),
        Some(scheduled.lid),
        request.child.clone(),
        request.old_parent.clone(),
        scheduled
    )
    .is_err());
    // Fenced target wins even if the caller retained an eligible pre-claim snapshot.
    let mut due = request.new_parent.clone();
    due.state = KeyState::PendingDeletion;
    due.scheduled_deletion_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    due.occ_version += 1;
    store.update_key(&due).await.unwrap();
    store
        .claim_destruction(&due.lid, due.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert!(store.reserve_migration(&request).await.is_err());
}

#[macro_export]
macro_rules! migration_conformance_tests {
    ($store:expr) => {
        #[tokio::test]
        async fn migration_atomic_publication_and_retirement() {
            $crate::migration_conformance::atomic_publication_and_retirement(&$store).await;
        }
        #[tokio::test]
        async fn migration_all_writer_fences() {
            $crate::migration_conformance::all_writer_fences(&$store).await;
        }
        #[tokio::test]
        async fn migration_creation_and_occ_preempt() {
            $crate::migration_conformance::pending_creation_and_occ_preempt_migration(&$store)
                .await;
        }
        #[tokio::test]
        async fn migration_deny_paths() {
            $crate::migration_conformance::deny_paths_and_parent_immutability(&$store).await;
        }
    };
}
