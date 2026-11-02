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

/// Test-only ownership admission for fixtures that do not exercise takeover.
pub async fn test_owner(
    store: &dyn StorageBackend,
    operation: Uuid,
) -> keyrack_core::migration::MigrationOwnership {
    let journal = store.get_migration(operation).await.unwrap().unwrap();
    if journal.owner.is_some() {
        return journal.ownership().unwrap();
    }
    let journal = store
        .claim_migration(operation, Uuid::new_v4(), journal.epoch)
        .await
        .unwrap();
    let owner = journal.ownership().unwrap();
    store
        .begin_migration_dispatch(operation, owner, true)
        .await
        .unwrap();
    owner
}

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
    assert!(store
        .commit_migration(operation, test_owner(store, operation).await)
        .await
        .is_err());
    assert!(store
        .stage_migration(
            operation,
            test_owner(store, operation).await,
            &envelopes()[..1]
        )
        .await
        .is_err());
    assert!(same_json(
        &store.get_key(&request.child.lid).await.unwrap(),
        &request.child
    )
    .unwrap());
    store
        .stage_migration(operation, test_owner(store, operation).await, &envelopes())
        .await
        .unwrap();
    assert!(store.read_migration_envelope(operation, 1).await.is_err());
    assert!(same_json(
        &store.get_key(&request.child.lid).await.unwrap(),
        &request.child
    )
    .unwrap());
    let published = store
        .commit_migration(operation, test_owner(store, operation).await)
        .await
        .unwrap();
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
        &store
            .commit_migration(operation, test_owner(store, operation).await)
            .await
            .unwrap(),
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
        .stage_migration(
            next.operation,
            test_owner(store, next.operation).await,
            &envelopes(),
        )
        .await
        .unwrap();
    store
        .commit_migration(next.operation, test_owner(store, next.operation).await)
        .await
        .unwrap();
    assert!(store.read_migration_envelope(operation, 1).await.is_err());
    assert!(same_json(
        &store
            .commit_migration(operation, test_owner(store, operation).await)
            .await
            .unwrap(),
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

pub async fn intent_binds_every_condition(store: &dyn StorageBackend) {
    use keyrack_core::migration::MigrationConditions;
    let (request, _) = seeded(store).await;
    let conditions = MigrationConditions {
        expected_child_occ: Some(request.child.occ_version),
        expected_old_parent_occ: Some(request.old_parent.occ_version),
        expected_new_parent_occ: Some(request.new_parent.occ_version),
        expected_old_parent: Some(request.old_parent.lid),
        covered_versions: Some(vec![2, 1]),
    };
    let request = request.with_conditions(conditions).unwrap();
    store.reserve_migration(&request).await.unwrap();
    assert_eq!(request.conditions.covered_versions, Some(vec![1, 2]));
    assert!(store.reserve_migration(&request).await.is_ok());
    for field in 0..9 {
        let mut changed = request.clone();
        match field {
            0 => changed.conditions.expected_child_occ = None,
            1 => changed.conditions.expected_old_parent_occ = None,
            2 => changed.conditions.expected_new_parent_occ = None,
            3 => changed.conditions.expected_old_parent = None,
            4 => changed.conditions.covered_versions = None,
            5 => changed.conditions.covered_versions = Some(vec![1]),
            6 => changed.child.lid = keyrack_core::lid::Lid::from_bytes([7; 32]),
            7 => changed.old_parent.lid = keyrack_core::lid::Lid::from_bytes([8; 32]),
            _ => changed.new_parent.lid = keyrack_core::lid::Lid::from_bytes([9; 32]),
        }
        assert!(
            store.reserve_migration(&changed).await.is_err(),
            "intent field {field} must conflict"
        );
        assert!(same_json(
            &store
                .get_migration(request.operation)
                .await
                .unwrap()
                .unwrap()
                .request,
            &request
        )
        .unwrap());
    }
    for field in 0..7 {
        let mut wrong = request.conditions.clone();
        match field {
            0 => wrong.expected_child_occ = Some(request.child.occ_version + 1),
            1 => wrong.expected_old_parent_occ = Some(request.old_parent.occ_version + 1),
            2 => wrong.expected_new_parent_occ = Some(request.new_parent.occ_version + 1),
            3 => wrong.expected_old_parent = Some(request.new_parent.lid),
            4 => wrong.covered_versions = Some(vec![1, 1]),
            5 => wrong.covered_versions = Some(vec![1]),
            _ => wrong.covered_versions = Some(vec![1, 2, 3]),
        }
        assert!(
            request.clone().with_conditions(wrong).is_err(),
            "mismatched caller condition {field} must fail"
        );
    }
}

pub async fn ownership_epoch_and_unknown_outcome(store: &dyn StorageBackend) {
    let (request, creations) = seeded(store).await;
    store.reserve_migration(&request).await.unwrap();
    let first = store
        .claim_migration(request.operation, Uuid::new_v4(), 0)
        .await
        .unwrap()
        .ownership()
        .unwrap();
    store
        .begin_migration_dispatch(request.operation, first, true)
        .await
        .unwrap();
    let second = store
        .claim_migration(request.operation, Uuid::new_v4(), first.epoch)
        .await
        .unwrap()
        .ownership()
        .unwrap();
    assert!(
        store
            .claim_migration(request.operation, Uuid::new_v4(), first.epoch)
            .await
            .is_err(),
        "stale ownership CAS must fail"
    );
    assert!(
        store
            .begin_migration_dispatch(request.operation, first, true)
            .await
            .is_err(),
        "stale dispatch admission must fail after takeover"
    );
    assert!(
        store
            .stage_migration(request.operation, first, &envelopes())
            .await
            .is_err(),
        "stale stage must fail after takeover"
    );
    assert!(
        store
            .commit_migration(request.operation, first)
            .await
            .is_err(),
        "stale commit must fail after takeover"
    );
    store
        .begin_migration_dispatch(request.operation, second, true)
        .await
        .unwrap();
    store
        .stage_migration(request.operation, second, &envelopes())
        .await
        .unwrap();
    assert!(
        store
            .commit_migration(request.operation, first)
            .await
            .is_err(),
        "stale commit must not publish staged envelopes after takeover"
    );
    store
        .commit_migration(request.operation, second)
        .await
        .unwrap();
    assert!(
        store
            .stage_migration(request.operation, first, &envelopes())
            .await
            .is_err(),
        "stale stage must not replay a terminal result"
    );
    assert!(
        store
            .commit_migration(request.operation, first)
            .await
            .is_err(),
        "stale commit must not replay a terminal result"
    );
    assert!(store
        .commit_migration(request.operation, second)
        .await
        .is_ok());
    for creation in creations {
        assert!(store
            .read_creation_envelope(creation.operation)
            .await
            .is_err());
    }

    let (unknown, creations) = seeded(store).await;
    store.reserve_migration(&unknown).await.unwrap();
    let first = store
        .claim_migration(unknown.operation, Uuid::new_v4(), 0)
        .await
        .unwrap()
        .ownership()
        .unwrap();
    store
        .begin_migration_dispatch(unknown.operation, first, false)
        .await
        .unwrap();
    assert!(store
        .begin_migration_dispatch(unknown.operation, first, false)
        .await
        .is_err());
    let second = store
        .claim_migration(unknown.operation, Uuid::new_v4(), first.epoch)
        .await
        .unwrap()
        .ownership()
        .unwrap();
    assert!(
        store
            .begin_migration_dispatch(unknown.operation, second, true)
            .await
            .is_err(),
        "unknown native effect must never be replayed by changing advertised retry safety"
    );
    assert!(
        store
            .stage_migration(unknown.operation, second, &envelopes())
            .await
            .is_err(),
        "takeover cannot publish an unreconciled prior-epoch effect"
    );
    assert!(store
        .commit_migration(unknown.operation, second)
        .await
        .is_err());
    let journal = store
        .get_migration(unknown.operation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(journal.phase, MigrationPhase::Reserved);
    assert!(journal.result.is_none());
    retryable(store.check_migration_fence(&unknown.old_parent.lid).await);
    for creation in creations {
        assert!(store
            .read_creation_envelope(creation.operation)
            .await
            .is_ok());
    }
}

pub async fn terminal_result_and_reader_snapshots(store: &dyn StorageBackend) {
    let (request, creations) = seeded(store).await;
    let mut original = Vec::new();
    for version in 1..=2 {
        original.push(
            store
                .wrapped_key_snapshot(&request.child.lid, version)
                .await
                .unwrap()
                .envelope,
        );
    }
    store.reserve_migration(&request).await.unwrap();
    let owner = test_owner(store, request.operation).await;
    for version in 1..=2 {
        let snapshot = store
            .wrapped_key_snapshot(&request.child.lid, version)
            .await
            .unwrap();
        assert_eq!(snapshot.parent.lid, request.old_parent.lid);
        assert_eq!(snapshot.envelope, original[(version - 1) as usize]);
    }
    store
        .stage_migration(request.operation, owner, &envelopes())
        .await
        .unwrap();
    assert!(store
        .get_migration(request.operation)
        .await
        .unwrap()
        .unwrap()
        .result
        .is_none());
    for version in 1..=2 {
        assert_eq!(
            store
                .wrapped_key_snapshot(&request.child.lid, version)
                .await
                .unwrap()
                .envelope,
            original[(version - 1) as usize]
        );
    }
    retryable(store.check_migration_fence(&request.old_parent.lid).await);
    store
        .commit_migration(request.operation, owner)
        .await
        .unwrap();
    let terminal = store
        .get_migration(request.operation)
        .await
        .unwrap()
        .unwrap()
        .result
        .unwrap();
    assert_eq!(terminal.operation_id, request.operation);
    assert_eq!(terminal.child, request.child.lid);
    assert_eq!(terminal.old_parent, request.old_parent.lid);
    assert_eq!(terminal.new_parent, request.new_parent.lid);
    assert_eq!(terminal.digest_algorithm, "blake3");
    for (index, entry) in terminal.versions.iter().enumerate() {
        assert_eq!(
            entry.old_envelope_digest,
            blake3::hash(&original[index]).to_hex().to_string()
        );
        assert_eq!(
            entry.new_envelope_digest,
            blake3::hash(&envelopes()[index]).to_hex().to_string()
        );
        assert_eq!(
            entry.new_reference,
            format!("migration:{}:{}", request.operation, entry.version)
        );
        assert_eq!(
            entry.old_reference,
            format!("creation:{}", creations[index].operation)
        );
        let snapshot = store
            .wrapped_key_snapshot(&request.child.lid, entry.version)
            .await
            .unwrap();
        assert_eq!(snapshot.parent.lid, request.new_parent.lid);
        assert_eq!(snapshot.envelope, envelopes()[index]);
    }
    store
        .commit_migration(request.operation, owner)
        .await
        .unwrap();
    assert_eq!(
        store
            .get_migration(request.operation)
            .await
            .unwrap()
            .unwrap()
            .result,
        Some(terminal)
    );
    for change in 0..9 {
        let mut journal = store
            .get_migration(request.operation)
            .await
            .unwrap()
            .unwrap();
        let result = journal.result.as_mut().unwrap();
        match change {
            0 => result.old_parent_versions.push(99),
            1 => result.new_parent_version += 1,
            2 => result.digest_algorithm = "sha256".into(),
            3 => result.versions[0].version += 1,
            4 => result.versions[0].old_parent_version += 1,
            5 => result.versions[0].new_parent_version += 1,
            6 => result.versions[0].old_reference.push('x'),
            7 => result.versions[0].new_envelope_digest = "0".repeat(64),
            _ => result.versions[0].old_envelope_digest = "invalid".into(),
        }
        assert!(
            journal.validate().is_err(),
            "receipt field {change} must be bound"
        );
    }
    assert!(store
        .check_migration_fence(&request.old_parent.lid)
        .await
        .is_ok());
}

pub async fn ordinary_updates_and_aliases(store: &dyn StorageBackend) {
    let (request, _) = seeded(store).await;
    store.reserve_migration(&request).await.unwrap();
    for phase in 0..2 {
        if phase == 1 {
            store
                .stage_migration(
                    request.operation,
                    test_owner(store, request.operation).await,
                    &envelopes(),
                )
                .await
                .unwrap();
        }
        for record in [&request.child, &request.old_parent, &request.new_parent] {
            for mutation in 0..5 {
                let mut update = record.clone();
                update.occ_version += 1;
                match mutation {
                    0 => {
                        update.user_tags.set("review", "changed");
                    }
                    1 => update.state = KeyState::Disabled,
                    2 => update.state = KeyState::Enabled,
                    3 => {
                        update.state = KeyState::PendingDeletion;
                        update.scheduled_deletion_at = Some(chrono::Utc::now());
                    }
                    _ => {
                        update.state = KeyState::Disabled;
                        update.scheduled_deletion_at = None;
                    }
                }
                retryable(store.update_key(&update).await);
            }
            let alias = keyrack_core::storage::AliasRecord {
                alias_name: format!("migration-alias-{}", Uuid::new_v4()),
                target_lid: record.lid,
                created_at: chrono::Utc::now(),
            };
            store.create_alias(&alias).await.unwrap();
            assert_eq!(
                store.resolve_alias(&alias.alias_name).await.unwrap(),
                record.lid
            );
            store.delete_alias(&alias.alias_name).await.unwrap();
            assert!(store.resolve_alias(&alias.alias_name).await.is_err());
            assert!(same_json(&store.get_key(&record.lid).await.unwrap(), record).unwrap());
        }
    }
}

/// Readers use independent atomic transactions while publication changes references
/// and erases old bytes in one writer transaction. Synthetic envelopes isolate the
/// storage guarantee; service tests exercise provider decryption over this API.
pub async fn concurrent_reader_snapshots(store: &dyn StorageBackend) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (request, creations) = seeded(store).await;
    let original = [
        store
            .wrapped_key_snapshot(&request.child.lid, 1)
            .await
            .unwrap()
            .envelope,
        store
            .wrapped_key_snapshot(&request.child.lid, 2)
            .await
            .unwrap()
            .envelope,
    ];
    let completed = AtomicBool::new(false);
    let ready = tokio::sync::Notify::new();
    let reader = async {
        let mut snapshot_count = 0;
        loop {
            for version in 1..=2 {
                let snapshot = store
                    .wrapped_key_snapshot(&request.child.lid, version)
                    .await
                    .unwrap();
                let index = (version - 1) as usize;
                let key_version = snapshot
                    .record
                    .key_versions
                    .iter()
                    .find(|item| item.version_number == version)
                    .unwrap();
                let KeyMaterial::ParentWrapped(material) = &key_version.material else {
                    panic!("wrapped descriptor required")
                };
                if snapshot.parent.lid == request.old_parent.lid {
                    assert_eq!(snapshot.envelope, original[index]);
                    assert_eq!(
                        material.wrapped_material_ref().as_str(),
                        format!("creation:{}", creations[index].operation)
                    );
                } else {
                    assert_eq!(snapshot.parent.lid, request.new_parent.lid);
                    assert_eq!(snapshot.envelope, envelopes()[index]);
                    assert_eq!(
                        material.wrapped_material_ref().as_str(),
                        format!("migration:{}:{version}", request.operation)
                    );
                }
                snapshot_count += 1;
            }
            ready.notify_one();
            if completed.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(snapshot_count >= 4);
    };
    let writer = async {
        ready.notified().await;
        store.reserve_migration(&request).await.unwrap();
        ready.notified().await;
        let owner = test_owner(store, request.operation).await;
        store
            .stage_migration(request.operation, owner, &envelopes())
            .await
            .unwrap();
        ready.notified().await;
        store
            .commit_migration(request.operation, owner)
            .await
            .unwrap();
        completed.store(true, Ordering::SeqCst);
    };
    tokio::join!(reader, writer);
    for creation in creations {
        assert!(store
            .read_creation_envelope(creation.operation)
            .await
            .is_err());
    }
    for version in 1..=2 {
        let snapshot = store
            .wrapped_key_snapshot(&request.child.lid, version)
            .await
            .unwrap();
        assert_eq!(snapshot.parent.lid, request.new_parent.lid);
        assert_eq!(snapshot.envelope, envelopes()[(version - 1) as usize]);
    }
}

#[macro_export]
macro_rules! migration_conformance_tests {
    ($store:expr) => {
        #[tokio::test]
        async fn migration_concurrent_reader_snapshots() {
            $crate::migration_conformance::concurrent_reader_snapshots(&$store).await;
        }
        #[tokio::test]
        async fn migration_intent_binds_every_condition() {
            $crate::migration_conformance::intent_binds_every_condition(&$store).await;
        }
        #[tokio::test]
        async fn migration_ownership_epoch_and_unknown_outcome() {
            $crate::migration_conformance::ownership_epoch_and_unknown_outcome(&$store).await;
        }
        #[tokio::test]
        async fn migration_terminal_result_and_reader_snapshots() {
            $crate::migration_conformance::terminal_result_and_reader_snapshots(&$store).await;
        }
        #[tokio::test]
        async fn migration_ordinary_updates_and_aliases() {
            $crate::migration_conformance::ordinary_updates_and_aliases(&$store).await;
        }
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
