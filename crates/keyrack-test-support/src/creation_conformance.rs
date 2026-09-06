// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Storage-only fixtures. The byte strings are NOT cryptographic envelopes and
//! the test verifier is NOT a production provider qualification.

use crate::fixtures::unique_test_key_record;
use keyrack_core::creation::{
    creation_correlation, invalid, same_json, A2ClosureClaim, A2ClosureFact, A2ClosureVerifier,
    CreationOwner, CreationPhase, CreationRequest, VerifiedA2Closure, MAX_CREATION_ENVELOPE_BYTES,
};
use keyrack_core::error::Result;
use keyrack_core::key::{KeyMaterial, KeyRecord, KeyState, ParentWrappedMaterial, ProviderRef};
use keyrack_core::storage::StorageBackend;
use keyrack_core::wrapping::{
    VersionedKeyId, WrappedKeyFormat, WrappingContextVersion, WrappingIdentifier,
};
use uuid::Uuid;

pub const TEST_ENVELOPE: &[u8] = b"storage-only-test-envelope-not-a-crypto-proof";

pub fn replace_envelope_ref(request: &mut CreationRequest, reference: String) {
    let material = request.material().unwrap().clone();
    let version = request.record.current_key_version;
    request
        .record
        .key_versions
        .iter_mut()
        .find(|v| v.version_number == version)
        .unwrap()
        .material = KeyMaterial::ParentWrapped(
        ParentWrappedMaterial::new(
            material.provider_ref().clone(),
            material.security_domain().clone(),
            material.parent(),
            material.wrapping_context_version(),
            material.key_format().clone(),
            material.mechanism().clone(),
            WrappingIdentifier::new(reference).unwrap(),
        )
        .unwrap(),
    );
    request.context_bytes = request.context().unwrap().canonical_bytes().unwrap();
}

pub fn fixture() -> (KeyRecord, CreationRequest) {
    let mut parent = unique_test_key_record(KeyState::Enabled);
    let provider = ProviderRef::new("storage-test-provider");
    if let KeyMaterial::ProviderResident { provider_ref, .. } = &mut parent.key_versions[0].material
    {
        *provider_ref = Some(provider.clone());
    }
    let mut child = unique_test_key_record(KeyState::Enabled);
    child.parent_lid = Some(parent.lid);
    let operation = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    child.key_versions[0].material = KeyMaterial::ParentWrapped(
        ParentWrappedMaterial::new(
            provider,
            WrappingIdentifier::new("storage-test-domain").unwrap(),
            VersionedKeyId::new(parent.lid, 1).unwrap(),
            WrappingContextVersion::V1,
            WrappedKeyFormat::RawSecret,
            WrappingIdentifier::new("unqualified-storage-test").unwrap(),
            WrappingIdentifier::new(format!("envelope-{operation}")).unwrap(),
        )
        .unwrap(),
    );
    let mut request = CreationRequest {
        operation,
        attempt,
        owner: CreationOwner {
            instance: Uuid::new_v4(),
            generation: 1,
        },
        correlation: creation_correlation(operation, attempt),
        record: child,
        expected_key_occ: None,
        expected_parent_occ: parent.occ_version,
        parent_spec: parent.key_spec.clone(),
        context_bytes: Vec::new(),
    };
    request.context_bytes = request.context().unwrap().canonical_bytes().unwrap();
    request.validate().unwrap();
    (parent, request)
}

/// Simulates a trusted provider adapter's positive confirmation for tests only.
struct TestClosureVerifier;
impl A2ClosureVerifier for TestClosureVerifier {
    fn verify(&self, request: &CreationRequest, claim: &A2ClosureClaim) -> Result<()> {
        if claim.fact
            != (A2ClosureFact::SessionClosed {
                session: request.correlation.clone(),
            })
        {
            return Err(invalid("test closure not confirmed"));
        }
        Ok(())
    }
}

pub fn closure(request: &CreationRequest) -> VerifiedA2Closure {
    VerifiedA2Closure::verify(
        request,
        A2ClosureClaim {
            intent_fingerprint: request.fingerprint().unwrap(),
            fact: A2ClosureFact::SessionClosed {
                session: request.correlation.clone(),
            },
        },
        &TestClosureVerifier,
    )
    .unwrap()
}

pub async fn staged(store: &dyn StorageBackend, request: &CreationRequest) {
    store.reserve_creation(request).await.unwrap();
    store
        .stage_creation(request.operation, request.owner, 1, TEST_ENVELOPE)
        .await
        .unwrap();
}

pub async fn resolved(store: &dyn StorageBackend, request: &CreationRequest) {
    staged(store, request).await;
    store
        .resolve_creation(request.operation, request.owner, 2, &closure(request))
        .await
        .unwrap();
}

pub async fn publication_and_retry(store: &dyn StorageBackend) {
    let (parent, request) = fixture();
    store.create_key(&parent).await.unwrap();
    let journal = store.reserve_creation(&request).await.unwrap();
    assert_eq!(journal.phase, CreationPhase::Reserved);
    assert!(store.get_key(&request.record.lid).await.is_err());
    assert!(store
        .read_creation_envelope(request.operation)
        .await
        .is_err());
    assert!(store
        .publish_creation(request.operation, request.owner, 1)
        .await
        .is_err());
    assert!(store
        .resolve_creation(request.operation, request.owner, 1, &closure(&request))
        .await
        .is_err());
    let again = store.reserve_creation(&request).await.unwrap();
    assert_eq!(again.revision, 1);
    store
        .stage_creation(request.operation, request.owner, 1, TEST_ENVELOPE)
        .await
        .unwrap();
    assert!(store.get_key(&request.record.lid).await.is_err());
    assert!(store
        .read_creation_envelope(request.operation)
        .await
        .is_err());
    assert!(store
        .publish_creation(request.operation, request.owner, 2)
        .await
        .is_err());
    store
        .resolve_creation(request.operation, request.owner, 2, &closure(&request))
        .await
        .unwrap();
    let record = store
        .publish_creation(request.operation, request.owner, 3)
        .await
        .unwrap();
    assert!(same_json(&record, &request.record).unwrap());
    assert_eq!(
        store
            .read_creation_envelope(request.operation)
            .await
            .unwrap(),
        TEST_ENVELOPE
    );
    let journal = store.get_creation(request.operation).await.unwrap();
    assert_eq!(journal.phase, CreationPhase::Committed);
    assert!(same_json(journal.committed_record.as_ref().unwrap(), &record).unwrap());
    let mut updated = record.clone();
    updated.description = "newer metadata must survive old commit retries".into();
    updated.occ_version += 1;
    store.update_key(&updated).await.unwrap();
    let mut disabled_parent = parent.clone();
    disabled_parent.state = KeyState::Disabled;
    disabled_parent.occ_version += 1;
    store.update_key(&disabled_parent).await.unwrap();
    let old_result = store
        .publish_creation(request.operation, request.owner, 3)
        .await
        .unwrap();
    assert!(same_json(&old_result, &record).unwrap());
    assert!(same_json(&store.get_key(&record.lid).await.unwrap(), &updated).unwrap());
    assert!(store
        .recoverable_creations(None, 100)
        .await
        .unwrap()
        .items
        .iter()
        .all(|j| j.request.operation != request.operation));
}

pub async fn conflicts_and_fencing(store: &dyn StorageBackend) {
    let (parent, request) = fixture();
    store.create_key(&parent).await.unwrap();
    store.reserve_creation(&request).await.unwrap();
    let mut conflict = request.clone();
    conflict.attempt = Uuid::new_v4();
    conflict.correlation = creation_correlation(conflict.operation, conflict.attempt);
    assert!(store.reserve_creation(&conflict).await.is_err());
    conflict.operation = Uuid::new_v4();
    conflict.correlation = creation_correlation(conflict.operation, conflict.attempt);
    assert!(store.reserve_creation(&conflict).await.is_err());
    let reference = format!("unique-ref-{}", conflict.operation);
    replace_envelope_ref(&mut conflict, reference);
    assert!(store.reserve_creation(&conflict).await.is_err());
    let (another_parent, mut reused_ref) = fixture();
    store.create_key(&another_parent).await.unwrap();
    replace_envelope_ref(
        &mut reused_ref,
        request
            .material()
            .unwrap()
            .wrapped_material_ref()
            .as_str()
            .to_owned(),
    );
    assert!(store.reserve_creation(&reused_ref).await.is_err());
    assert!(store.create_key(&request.record).await.is_err());
    let mut stale_owner = request.owner;
    stale_owner.generation += 1;
    assert!(store
        .stage_creation(request.operation, stale_owner, 1, TEST_ENVELOPE)
        .await
        .is_err());
    assert!(store
        .stage_creation(request.operation, request.owner, 2, TEST_ENVELOPE)
        .await
        .is_err());
    assert!(store
        .stage_creation(request.operation, request.owner, 1, &[])
        .await
        .is_err());
    assert!(store
        .stage_creation(
            request.operation,
            request.owner,
            1,
            &vec![1; MAX_CREATION_ENVELOPE_BYTES + 1]
        )
        .await
        .is_err());
    let journal = store
        .stage_creation(request.operation, request.owner, 1, TEST_ENVELOPE)
        .await
        .unwrap();
    assert_eq!(journal.revision, 2);
    assert_eq!(
        store
            .stage_creation(request.operation, request.owner, 1, TEST_ENVELOPE)
            .await
            .unwrap()
            .revision,
        2
    );
    assert!(store
        .stage_creation(request.operation, request.owner, 2, b"replacement")
        .await
        .is_err());
    let (_, other_request) = fixture();
    assert!(store
        .resolve_creation(
            request.operation,
            request.owner,
            2,
            &closure(&other_request)
        )
        .await
        .is_err());
    assert!(store
        .resolve_creation(request.operation, stale_owner, 2, &closure(&request))
        .await
        .is_err());
    store
        .resolve_creation(request.operation, request.owner, 2, &closure(&request))
        .await
        .unwrap();
    assert_eq!(
        store
            .resolve_creation(request.operation, request.owner, 2, &closure(&request))
            .await
            .unwrap()
            .revision,
        3
    );
    assert!(store
        .publish_creation(request.operation, stale_owner, 3)
        .await
        .is_err());
    assert!(store.get_key(&request.record.lid).await.is_err());
}

pub async fn parent_state_and_retirement(store: &dyn StorageBackend) {
    let (parent, request) = fixture();
    store.create_key(&parent).await.unwrap();
    resolved(store, &request).await;
    let mut retired = parent.clone();
    retired.occ_version += 1;
    retired.key_versions.clear();
    assert!(store.update_key(&retired).await.is_err());
    let mut disabled = parent.clone();
    disabled.state = KeyState::Disabled;
    disabled.occ_version += 1;
    store.update_key(&disabled).await.unwrap();
    assert!(store
        .publish_creation(request.operation, request.owner, 3)
        .await
        .is_err());
    assert!(store.get_key(&request.record.lid).await.is_err());
    assert_eq!(
        store.get_creation(request.operation).await.unwrap().phase,
        CreationPhase::Resolved
    );
}

pub async fn committed_material_is_not_ordinary_crud(store: &dyn StorageBackend) {
    let (parent, request) = fixture();
    store.create_key(&parent).await.unwrap();
    resolved(store, &request).await;
    let record = store
        .publish_creation(request.operation, request.owner, 3)
        .await
        .unwrap();
    let mut overwritten = record.clone();
    overwritten.occ_version += 1;
    overwritten.key_versions[0].material = parent.key_versions[0].material.clone();
    assert!(store.update_key(&overwritten).await.is_err());
    let mut appended = record.clone();
    appended.occ_version += 1;
    let mut version = parent.key_versions[0].clone();
    version.version_number = 2;
    appended.key_versions.push(version);
    assert!(store.update_key(&appended).await.is_err());
    appended.key_versions[1].material = record.key_versions[0].material.clone();
    assert!(store.update_key(&appended).await.is_err());
    appended.key_versions[1].version_number = 1;
    assert!(store.update_key(&appended).await.is_err());
    let mut switched = record.clone();
    switched.occ_version += 1;
    switched.current_key_version = 17;
    assert!(store.update_key(&switched).await.is_err());
    let mut destroyed_parent = parent.clone();
    destroyed_parent.state = KeyState::Destroyed;
    destroyed_parent.occ_version += 1;
    assert!(store.update_key(&destroyed_parent).await.is_err());
    assert!(same_json(&store.get_key(&record.lid).await.unwrap(), &record).unwrap());
}

pub async fn recovery_pages(store: &dyn StorageBackend) {
    let (parent, request) = fixture();
    store.create_key(&parent).await.unwrap();
    store.reserve_creation(&request).await.unwrap();
    assert!(store.recoverable_creations(None, 0).await.is_err());
    assert!(store.recoverable_creations(None, 101).await.is_err());
    let mut after = None;
    let mut found = false;
    let mut seen = std::collections::HashSet::new();
    loop {
        let page = store.recoverable_creations(after, 1).await.unwrap();
        assert!(page.items.len() <= 1);
        for item in page.items {
            assert!(seen.insert(item.request.operation));
            if item.request.operation == request.operation {
                found = true;
            }
            assert_ne!(item.phase, CreationPhase::Committed);
        }
        if let Some(next) = page.next_after {
            after = Some(next);
        } else {
            break;
        }
    }
    assert!(found);
}

pub async fn rotation_and_occ(store: &dyn StorageBackend) {
    let (parent, mut request) = fixture();
    store.create_key(&parent).await.unwrap();
    let mut old_child = request.record.clone();
    old_child.key_versions[0].material = parent.key_versions[0].material.clone();
    store.create_key(&old_child).await.unwrap();
    let mut new_version = request.record.key_versions[0].clone();
    new_version.version_number = 2;
    request.record = old_child.clone();
    request.record.key_versions[0].is_primary = false;
    request.record.key_versions.push(new_version);
    request.record.current_key_version = 2;
    request.record.occ_version += 1;
    request.expected_key_occ = Some(old_child.occ_version);
    request.context_bytes = request.context().unwrap().canonical_bytes().unwrap();
    resolved(store, &request).await;
    let mut racing_rotation = old_child.clone();
    racing_rotation.occ_version += 1;
    racing_rotation.current_key_version = 2;
    assert!(store.update_key(&racing_rotation).await.is_err());
    let published = store
        .publish_creation(request.operation, request.owner, 3)
        .await
        .unwrap();
    assert_eq!(published.key_versions.len(), 2);
    assert_eq!(
        published.key_versions[0].material,
        old_child.key_versions[0].material
    );
    assert_eq!(published.current_key_version, 2);

    let (parent, mut request) = fixture();
    store.create_key(&parent).await.unwrap();
    let mut current = request.record.clone();
    current.key_versions[0].material = parent.key_versions[0].material.clone();
    store.create_key(&current).await.unwrap();
    let mut next = request.record.key_versions[0].clone();
    next.version_number = 2;
    request.record = current.clone();
    request.record.key_versions[0].is_primary = false;
    request.record.key_versions.push(next);
    request.record.current_key_version = 2;
    request.record.occ_version += 1;
    request.expected_key_occ = Some(current.occ_version);
    request.context_bytes = request.context().unwrap().canonical_bytes().unwrap();
    resolved(store, &request).await;
    current.occ_version += 1;
    current.state = KeyState::Disabled;
    store.update_key(&current).await.unwrap();
    assert!(store
        .publish_creation(request.operation, request.owner, 3)
        .await
        .is_err());
    assert_eq!(
        store
            .get_key(&current.lid)
            .await
            .unwrap()
            .current_key_version,
        1
    );
}

#[macro_export]
macro_rules! creation_conformance_tests {
    ($store:expr) => {
        #[tokio::test]
        async fn a2_publication_and_retry() {
            $crate::creation_conformance::publication_and_retry(&$store).await;
        }
        #[tokio::test]
        async fn a2_conflicts_and_fencing() {
            $crate::creation_conformance::conflicts_and_fencing(&$store).await;
        }
        #[tokio::test]
        async fn a2_parent_state_and_retirement() {
            $crate::creation_conformance::parent_state_and_retirement(&$store).await;
        }
        #[tokio::test]
        async fn a2_committed_material_is_not_ordinary_crud() {
            $crate::creation_conformance::committed_material_is_not_ordinary_crud(&$store).await;
        }
        #[tokio::test]
        async fn a2_recovery_pages() {
            $crate::creation_conformance::recovery_pages(&$store).await;
        }
        #[tokio::test]
        async fn a2_rotation_and_occ() {
            $crate::creation_conformance::rotation_and_occ(&$store).await;
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyrack_core::creation::CreationJournal;
    use proptest::prelude::*;

    struct DenyVerifier;
    impl A2ClosureVerifier for DenyVerifier {
        fn verify(&self, _: &CreationRequest, _: &A2ClosureClaim) -> Result<()> {
            Err(invalid("provider did not confirm closure"))
        }
    }

    #[test]
    fn closure_claim_needs_verifier_and_exact_attempt_binding() {
        let (_, request) = fixture();
        let claim = A2ClosureClaim {
            intent_fingerprint: request.fingerprint().unwrap(),
            fact: A2ClosureFact::SessionClosed {
                session: request.correlation.clone(),
            },
        };
        assert!(VerifiedA2Closure::verify(&request, claim.clone(), &DenyVerifier).is_err());
        let mut wrong = claim.clone();
        wrong.fact = A2ClosureFact::SessionClosed {
            session: "different-session".into(),
        };
        assert!(VerifiedA2Closure::verify(&request, wrong, &TestClosureVerifier).is_err());
        let (_, different) = fixture();
        assert!(VerifiedA2Closure::verify(&different, claim, &TestClosureVerifier).is_err());
    }

    #[test]
    fn malformed_intent_and_history_are_not_reservations() {
        let (parent, request) = fixture();
        let mut wrong = request.clone();
        wrong.owner.generation = 0;
        assert!(CreationJournal::reserved(wrong).is_err());
        let mut wrong = request.clone();
        wrong.correlation = "ambiguous-reused-label".into();
        assert!(CreationJournal::reserved(wrong).is_err());
        let mut wrong = request.clone();
        wrong
            .record
            .key_versions
            .push(wrong.record.key_versions[0].clone());
        assert!(CreationJournal::reserved(wrong).is_err());
        let mut wrong = request.clone();
        wrong.record.exportability = keyrack_core::key::Exportability::Exportable;
        assert!(CreationJournal::reserved(wrong).is_err());
        let mut wrong_parent = parent.clone();
        if let KeyMaterial::ProviderResident { provider_ref, .. } =
            &mut wrong_parent.key_versions[0].material
        {
            *provider_ref = None;
        }
        assert!(request.validate_records(None, &wrong_parent).is_err());
    }

    proptest! {
        #[test]
        fn context_perturbation_never_becomes_a_valid_intent(index in any::<usize>(), delta in 1_u8..=255) {
            let (_, mut request) = fixture();
            let position = index % request.context_bytes.len();
            request.context_bytes[position] ^= delta;
            prop_assert!(request.validate().is_err());
        }

        #[test]
        fn rejected_journal_transitions_are_atomic(steps in prop::collection::vec(0_u8..6, 0..80)) {
            let (parent, request) = fixture();
            let proof = closure(&request);
            let mut journal = CreationJournal::reserved(request.clone()).unwrap();
            for step in steps {
                let before = journal.clone();
                let result = match step {
                    0 => journal.stage(request.owner, 1, TEST_ENVELOPE),
                    1 => journal.stage(request.owner, journal.revision, b"conflicting-envelope"),
                    2 => journal.resolve(request.owner, 2, &proof),
                    3 => journal.publication(request.owner, 3, None, &parent).map(|_| ()),
                    4 => journal.stage(CreationOwner { instance: Uuid::nil(), generation: 1 }, journal.revision, TEST_ENVELOPE),
                    _ => journal.resolve(request.owner, 999, &proof),
                };
                if result.is_err() { prop_assert!(same_json(&before, &journal).unwrap()); }
                prop_assert!(journal.validate().is_ok());
                prop_assert!(journal.revision >= before.revision);
                prop_assert!(journal.committed_record.is_some() == (journal.phase == CreationPhase::Committed));
            }
        }
    }
}
