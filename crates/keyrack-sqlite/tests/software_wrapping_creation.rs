// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Journaled A2 creation driven by a real provider's wrapping operations,
//! against real `SQLite` transactions.
//!
//! This qualifies the path, not a custody boundary: the provider here is the
//! software one, so parent, envelope and unwrapped child are all in this
//! process's heap. A wrapped child created this way is not provider-contained.

use async_trait::async_trait;
use keyrack_core::creation::{
    creation_correlation, A2ClosureClaim, A2ClosureFact, CreationBinding, CreationOwner,
    CreationPhase, CreationRequest,
};
use keyrack_core::creation_driver::{
    A2CreationDriver, CreationPendingReason as Pending, CreationProgress, WrappingCreationProvider,
};
use keyrack_core::error::Result;
use keyrack_core::key::{KeyRecord, KeySpec, KeyState, ProviderRef};
use keyrack_core::material::{KeyMaterial, ParentWrappedMaterial};
use keyrack_core::provider::software::{SoftwareProvider, SOFTWARE_WRAPPING_MECHANISM};
use keyrack_core::provider::{
    inmem::InMemoryProvider, CryptoProvider, EncryptOutput, GeneratedWrappedKey, KeyHandle,
    ProviderCapabilities, WrappedKeyClosure, WrappedKeyLease,
};
use keyrack_core::sensitive::Sensitive;
use keyrack_core::storage::StorageBackend;
use keyrack_core::wrapping::{
    VersionedKeyId, WrappedKeyFormat, WrappedKeyLifecycle, WrappingCapabilities, WrappingContext,
    WrappingContextVersion, WrappingIdentifier, WrappingOperation,
};
use keyrack_sqlite::SqliteStorage;
use keyrack_test_support::fixtures::unique_test_key_record;
use std::sync::Arc;
use uuid::Uuid;

const PROVIDER: &str = "software-a2-test";
const DOMAIN: &str = "software-a2-test-domain";

#[tokio::test]
async fn review_one_attempt_adapter_must_not_replace_cleanup_owner() {
    use keyrack_core::creation_driver::A2CreationProvider;
    let (_, provider, parent, original) = setup().await;
    let adapter =
        WrappingCreationProvider::new(provider, parent, WrappedKeyLifecycle::SessionObject)
            .unwrap();
    adapter.generate_and_wrap(&original).await.unwrap();
    let mut other = original.clone();
    other.operation = Uuid::new_v4();
    other.attempt = Uuid::new_v4();
    other.correlation = creation_correlation(other.operation, other.attempt);
    other.record.lid = keyrack_core::lid::Lid::from_bytes([0x71; 32]);
    other.context_bytes = other.context().unwrap().canonical_bytes().unwrap();
    other.validate().unwrap();
    assert_ne!(original.context_bytes, other.context_bytes);
    assert!(
        adapter.generate_and_wrap(&other).await.is_err(),
        "a second attempt replaced the original cleanup owner"
    );
}

#[tokio::test]
async fn review_creation_closure_must_not_rebind_owner() {
    use keyrack_core::creation_driver::A2CreationProvider;
    let (_, provider, parent, original) = setup().await;
    let adapter =
        WrappingCreationProvider::new(provider, parent, WrappedKeyLifecycle::SessionObject)
            .unwrap();
    adapter.generate_and_wrap(&original).await.unwrap();
    let mut other = original.clone();
    other.owner.generation += 1;
    other.validate().unwrap();
    assert_eq!(original.context_bytes, other.context_bytes);
    assert_ne!(
        original.fingerprint().unwrap(),
        other.fingerprint().unwrap()
    );
    assert!(
        adapter.close_creation(&other).await.is_err(),
        "the original creation closure was accepted for a different owner"
    );
}

#[tokio::test]
async fn review_creation_closure_must_not_rebind_operation_and_attempt() {
    use keyrack_core::creation_driver::A2CreationProvider;
    let (_, provider, parent, original) = setup().await;
    let adapter =
        WrappingCreationProvider::new(provider, parent, WrappedKeyLifecycle::SessionObject)
            .unwrap();
    adapter.generate_and_wrap(&original).await.unwrap();
    let mut other = original.clone();
    other.operation = Uuid::new_v4();
    other.attempt = Uuid::new_v4();
    other.correlation = creation_correlation(other.operation, other.attempt);
    other.validate().unwrap();
    assert_eq!(original.context_bytes, other.context_bytes);
    assert_ne!(
        original.fingerprint().unwrap(),
        other.fingerprint().unwrap()
    );
    assert!(
        adapter.close_creation(&other).await.is_err(),
        "the original creation closure was accepted for another operation/attempt"
    );
}

fn name(value: &str) -> WrappingIdentifier {
    WrappingIdentifier::new(value).unwrap()
}

/// A parent key record bound to a real software-provider object, and a creation
/// request for a wrapped child under it.
fn fixture(parent_handle: &KeyHandle) -> (KeyRecord, CreationRequest) {
    let mut parent = unique_test_key_record(KeyState::Enabled);
    parent.key_versions[0].material = KeyMaterial::ProviderResident {
        key_handle: parent_handle.clone(),
        provider_ref: Some(ProviderRef::new(PROVIDER)),
    };

    let mut child = unique_test_key_record(KeyState::Enabled);
    child.parent_lid = Some(parent.lid);
    let operation = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    child.key_versions[0].material = KeyMaterial::ParentWrapped(
        ParentWrappedMaterial::new(
            ProviderRef::new(PROVIDER),
            name(DOMAIN),
            VersionedKeyId::new(parent.lid, 1).unwrap(),
            WrappingContextVersion::V1,
            WrappedKeyFormat::RawSecret,
            name(SOFTWARE_WRAPPING_MECHANISM),
            name(&format!("kr-a2-envelope-{operation}")),
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

async fn setup() -> (
    Arc<SqliteStorage>,
    Arc<SoftwareProvider>,
    KeyHandle,
    CreationRequest,
) {
    let store = Arc::new(SqliteStorage::in_memory().unwrap());
    let provider = Arc::new(SoftwareProvider::scoped(
        ProviderRef::new(PROVIDER),
        name(DOMAIN),
    ));
    let parent_handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let (parent, request) = fixture(&parent_handle);
    store.create_key(&parent).await.unwrap();
    (store, provider, parent_handle, request)
}

fn driver(
    store: Arc<SqliteStorage>,
    provider: Arc<dyn CryptoProvider>,
    parent: KeyHandle,
) -> A2CreationDriver {
    let adapter =
        WrappingCreationProvider::new(provider, parent, WrappedKeyLifecycle::SessionObject)
            .unwrap();
    A2CreationDriver::new(store, Arc::new(adapter))
}

fn committed(progress: CreationProgress) -> KeyRecord {
    match progress {
        CreationProgress::Committed(record) => *record,
        other @ CreationProgress::Pending(_) => {
            panic!("expected a committed creation, got {other:?}")
        }
    }
}

#[tokio::test]
async fn a_journaled_creation_publishes_a_wrapped_child_that_still_opens() {
    let (store, provider, parent_handle, request) = setup().await;
    let record = committed(
        driver(store.clone(), provider.clone(), parent_handle.clone())
            .run(request.clone())
            .await
            .unwrap(),
    );

    // The published version is wrapped material, not a resident handle.
    let version = record.primary_version().unwrap();
    let KeyMaterial::ParentWrapped(material) = &version.material else {
        panic!("published child is not wrapped: {version:?}");
    };
    assert_eq!(material.mechanism().as_str(), SOFTWARE_WRAPPING_MECHANISM);
    assert!(version.resident_handle().is_err());
    assert_eq!(
        store.get_creation(request.operation).await.unwrap().phase,
        CreationPhase::Committed
    );

    // The envelope the journal kept is the one that opens the child, which is
    // what makes the published key usable rather than merely recorded.
    let envelope = store
        .read_creation_envelope(request.operation)
        .await
        .unwrap();
    let context = request.context().unwrap();
    let lease = provider
        .open_wrapped_key(&context, &parent_handle, &envelope)
        .await
        .unwrap();
    let sealed = provider
        .encrypt(lease.handle(), b"data under the child", b"aad")
        .await
        .unwrap();
    provider.close_wrapped_key(&lease).await.unwrap();

    let reopened = provider
        .open_wrapped_key(&context, &parent_handle, &envelope)
        .await
        .unwrap();
    let plaintext = provider
        .decrypt(reopened.handle(), &sealed.ciphertext, b"aad")
        .await
        .unwrap();
    assert_eq!(plaintext.expose(), b"data under the child");
    provider.close_wrapped_key(&reopened).await.unwrap();
}

#[tokio::test]
async fn a_provider_that_cannot_evidence_closure_cannot_be_installed() {
    let (_, _, parent_handle, _) = setup().await;
    let error = WrappingCreationProvider::new(
        Arc::new(InMemoryProvider::new()),
        parent_handle,
        WrappedKeyLifecycle::SessionObject,
    )
    .map(|_| ())
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("cannot evidence wrapped-key closure"),
        "{error}"
    );
}

/// One deviation from a fully working software provider, so that what a test
/// observes is attributable to that deviation and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Deviation {
    /// Declares generation but not opening, while still implementing both.
    UndeclaredOpen,
    /// Generates correctly but returns a lease bound to another context.
    MisboundLease,
    /// Closes the right object but reports it under another context.
    MisreportedClosure,
    /// Generates the object, then fails: the caller learns nothing about what
    /// exists, which is what a lost response looks like from here.
    LostGeneration,
    /// Never answers, so the caller can only give up on a call that may have
    /// had an effect.
    SilentGeneration,
}

struct DeviantProvider(Arc<SoftwareProvider>, Deviation);

#[async_trait]
impl CryptoProvider for DeviantProvider {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        self.0.generate_key(spec).await
    }
    async fn encrypt(&self, h: &KeyHandle, p: &[u8], aad: &[u8]) -> Result<EncryptOutput> {
        self.0.encrypt(h, p, aad).await
    }
    async fn decrypt(&self, h: &KeyHandle, c: &[u8], aad: &[u8]) -> Result<Sensitive<Vec<u8>>> {
        self.0.decrypt(h, c, aad).await
    }
    async fn sign(
        &self,
        h: &KeyHandle,
        a: keyrack_core::provider::SigningAlgorithm,
        m: &[u8],
    ) -> Result<Vec<u8>> {
        self.0.sign(h, a, m).await
    }
    async fn verify(
        &self,
        h: &KeyHandle,
        a: keyrack_core::provider::SigningAlgorithm,
        m: &[u8],
        s: &[u8],
    ) -> Result<bool> {
        self.0.verify(h, a, m, s).await
    }
    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        self.0.generate_random(length).await
    }
    async fn destroy_key(&self, h: &KeyHandle) -> Result<()> {
        self.0.destroy_key(h).await
    }
    fn capabilities(&self) -> ProviderCapabilities {
        self.0.capabilities()
    }
    fn wrapping_capabilities(&self) -> WrappingCapabilities {
        let tuples = self
            .0
            .wrapping_capabilities()
            .tuples()
            .iter()
            .filter(|tuple| {
                self.1 != Deviation::UndeclaredOpen || tuple.operation != WrappingOperation::Open
            })
            .cloned()
            .collect();
        WrappingCapabilities::new(tuples).unwrap()
    }
    async fn generate_wrapped_key(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        creation: &CreationBinding,
    ) -> Result<GeneratedWrappedKey> {
        if self.1 == Deviation::SilentGeneration {
            std::future::pending::<()>().await;
        }
        let generated = self
            .0
            .generate_wrapped_key(context, parent, creation)
            .await?;
        if self.1 == Deviation::LostGeneration {
            return Err(keyrack_core::error::KeyRackError::Provider(
                "generation response lost".into(),
            ));
        }
        if self.1 != Deviation::MisboundLease {
            return Ok(generated);
        }
        let mut other = context.clone();
        other.child = VersionedKeyId::new(other.child.lid, other.child.version.get() + 1).unwrap();
        Ok(GeneratedWrappedKey {
            envelope: generated.envelope,
            lease: WrappedKeyLease::new(
                generated.lease.handle().clone(),
                generated.lease.object().clone(),
                &other,
            )
            .unwrap(),
        })
    }
    async fn open_wrapped_key(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        envelope: &[u8],
    ) -> Result<WrappedKeyLease> {
        self.0.open_wrapped_key(context, parent, envelope).await
    }
    async fn close_wrapped_key(&self, lease: &WrappedKeyLease) -> Result<WrappedKeyClosure> {
        let mut closure = self.0.close_wrapped_key(lease).await?;
        if self.1 == Deviation::MisreportedClosure {
            closure.context_sha256[0] ^= 1;
        }
        Ok(closure)
    }
    fn wrapping_closure_verifier(
        &self,
    ) -> Option<Arc<dyn keyrack_core::creation::A2ClosureVerifier>> {
        self.0.wrapping_closure_verifier()
    }
}

#[tokio::test]
async fn a_child_that_could_not_be_opened_again_is_never_created() {
    let (store, provider, parent_handle, request) = setup().await;
    let generate_only = Arc::new(DeviantProvider(provider, Deviation::UndeclaredOpen));
    let error = driver(store.clone(), generate_only, parent_handle)
        .run(request.clone())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("Open"), "{error}");

    // Refused before any provider effect: no dispatch, no child, no envelope.
    let journal = store.get_creation(request.operation).await.unwrap();
    assert!(!journal.dispatch_started);
    assert_eq!(journal.phase, CreationPhase::Reserved);
    assert!(store.get_key(&request.record.lid).await.is_err());
}

#[tokio::test]
async fn a_lease_bound_to_another_context_never_reaches_publication() {
    let (store, provider, parent_handle, request) = setup().await;
    let misbinding = Arc::new(DeviantProvider(provider, Deviation::MisboundLease));
    let progress = driver(store.clone(), misbinding, parent_handle)
        .run(request.clone())
        .await
        .unwrap();
    // The generation is treated as an uncertain effect with cleanup owed, which
    // is the correct reading: an object exists and its lease cannot be trusted.
    assert!(
        matches!(
            progress,
            CreationProgress::Pending(Pending::CleanupUnconfirmed)
        ),
        "{progress:?}"
    );
    assert!(store.get_key(&request.record.lid).await.is_err());
    assert_eq!(
        store.get_creation(request.operation).await.unwrap().phase,
        CreationPhase::Reserved
    );
}

#[tokio::test]
async fn a_closure_reported_under_another_context_never_reaches_publication() {
    let (store, provider, parent_handle, request) = setup().await;
    let misreporting = Arc::new(DeviantProvider(provider, Deviation::MisreportedClosure));
    let progress = driver(store.clone(), misreporting, parent_handle)
        .run(request.clone())
        .await
        .unwrap();
    assert!(
        matches!(
            progress,
            CreationProgress::Pending(Pending::CleanupUnconfirmed)
        ),
        "{progress:?}"
    );
    assert!(store.get_key(&request.record.lid).await.is_err());
    // Staged rather than Reserved: generation and staging did happen here, and
    // only the closure was unusable, so cleanup stays owed on the stored bytes.
    assert_eq!(
        store.get_creation(request.operation).await.unwrap().phase,
        CreationPhase::Staged
    );
}

#[tokio::test]
async fn a_restart_leaves_an_interrupted_creation_to_reconciliation() {
    let (store, provider, parent_handle, request) = setup().await;
    // Stage the attempt, then drive it from an adapter that never generated it,
    // which is what a fresh process holds after a crash.
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
            b"envelope from a lost process",
        )
        .await
        .unwrap();

    let progress = driver(store.clone(), provider, parent_handle)
        .run(request.clone())
        .await
        .unwrap();
    assert!(
        matches!(
            progress,
            CreationProgress::Pending(Pending::CleanupUnconfirmed)
        ),
        "{progress:?}"
    );
    // Nothing was published, and nothing claimed the object was cleaned up.
    assert!(store.get_key(&request.record.lid).await.is_err());
    assert_eq!(
        store.get_creation(request.operation).await.unwrap().phase,
        CreationPhase::Staged
    );
}

#[tokio::test]
async fn closure_evidence_is_refused_for_anything_but_this_creation_object() {
    let (_, provider, parent_handle, request) = setup().await;
    let verifier = provider.wrapping_closure_verifier().unwrap();
    let context = request.context().unwrap();

    let claim = |object: &str, digest: [u8; 32]| A2ClosureClaim {
        intent_fingerprint: request.fingerprint().unwrap(),
        envelope_digest: digest,
        fact: A2ClosureFact::TemporaryObjectDestroyed {
            object: object.to_owned(),
        },
    };

    // An object no incarnation of this provider issued, and one this provider
    // never recorded destroying, are refused for distinguishable reasons. The
    // difference matters to whoever has to reconcile: the first claim is about
    // something else entirely, the second is about an object of ours that we
    // cannot speak for, which is what a claim from a previous process looks
    // like.
    let foreign = format!("kr-sw-a2-{}-1", Uuid::new_v4());
    let error = verifier
        .verify(&request, &claim(&foreign, [0; 32]))
        .unwrap_err()
        .to_string();
    assert!(error.contains("did not issue"), "{error}");

    // An object that was opened rather than generated: closing it is not
    // evidence that a creation attempt was cleaned up.
    let generated = provider
        .generate_wrapped_key(
            &context,
            &parent_handle,
            &CreationBinding::of(&request).unwrap(),
        )
        .await
        .unwrap();
    let opened = provider
        .open_wrapped_key(&context, &parent_handle, &generated.envelope)
        .await
        .unwrap();
    let opened_closure = provider.close_wrapped_key(&opened).await.unwrap();
    let digest = *blake3::hash(&generated.envelope).as_bytes();
    let A2ClosureFact::TemporaryObjectDestroyed { object } = &opened_closure.fact else {
        panic!("unexpected closure fact");
    };
    assert!(verifier.verify(&request, &claim(object, digest)).is_err());

    // The creation object itself, but bound to other bytes.
    let generation_closure = provider.close_wrapped_key(&generated.lease).await.unwrap();
    let A2ClosureFact::TemporaryObjectDestroyed { object } = &generation_closure.fact else {
        panic!("unexpected closure fact");
    };
    assert!(verifier.verify(&request, &claim(object, [1; 32])).is_err());

    // Issued here, but never recorded as destroyed.
    let (prefix, _) = object.rsplit_once('-').unwrap();
    let error = verifier
        .verify(&request, &claim(&format!("{prefix}-99999"), digest))
        .unwrap_err()
        .to_string();
    assert!(error.contains("no recorded destruction"), "{error}");

    // The right object and bytes, but presented for another child entirely.
    let (_, other_request) = fixture(&parent_handle);
    assert!(verifier
        .verify(&other_request, &claim(object, digest))
        .is_err());

    // The right object and bytes, presented for another attempt at the same
    // child. Context, envelope and origin are all equal here, so only the
    // creation recorded with the object distinguishes them.
    let mut second_attempt = request.clone();
    second_attempt.operation = Uuid::new_v4();
    second_attempt.attempt = Uuid::new_v4();
    second_attempt.correlation =
        creation_correlation(second_attempt.operation, second_attempt.attempt);
    second_attempt.validate().unwrap();
    assert_eq!(request.context_bytes, second_attempt.context_bytes);
    let error = verifier
        .verify(
            &second_attempt,
            &A2ClosureClaim {
                intent_fingerprint: second_attempt.fingerprint().unwrap(),
                envelope_digest: digest,
                fact: A2ClosureFact::TemporaryObjectDestroyed {
                    object: object.clone(),
                },
            },
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("another creation"), "{error}");

    // And the same object bound to the envelope it actually produced.
    assert!(verifier.verify(&request, &claim(object, digest)).is_ok());
}

/// The three ways a generation can leave an object with no usable answer, and
/// the one thing that must be true after each: this attempt still owns whatever
/// exists, and nothing else may generate over it.
///
/// Each case would pass trivially if the adapter simply refused everything, so
/// each also asserts the refusal names the state it is in.
#[tokio::test]
async fn a_generation_that_answers_badly_keeps_its_cleanup_ownership() {
    use keyrack_core::creation_driver::A2CreationProvider;
    for deviation in [
        Deviation::LostGeneration,
        Deviation::SilentGeneration,
        Deviation::MisboundLease,
    ] {
        let (_, provider, parent_handle, request) = setup().await;
        let adapter = WrappingCreationProvider::new(
            Arc::new(DeviantProvider(provider, deviation)),
            parent_handle,
            WrappedKeyLifecycle::SessionObject,
        )
        .unwrap();

        if deviation == Deviation::SilentGeneration {
            // A caller that gives up on a call that may already have had an
            // effect. The reservation is what survives the cancellation.
            assert!(tokio::time::timeout(
                std::time::Duration::from_millis(50),
                adapter.generate_and_wrap(&request),
            )
            .await
            .is_err());
        } else {
            assert!(adapter.generate_and_wrap(&request).await.is_err());
        }

        let again = adapter
            .generate_and_wrap(&request)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            again.contains("cannot generate again"),
            "{deviation:?}: {again}"
        );

        let error = adapter
            .close_creation(&request)
            .await
            .unwrap_err()
            .to_string();
        if deviation == Deviation::MisboundLease {
            // A lease came back, so there is something to close: the object is
            // still owned and the provider is asked about it. Refusing as
            // unresolved here would mean the adapter had thrown the lease away
            // with the refusal, leaving the object unreachable.
            assert!(
                !error.contains("unresolved"),
                "the only lease for a live object was discarded: {error}"
            );
        } else {
            // No lease came back. The attempt is unresolved, and saying so is
            // the whole answer: a closure must not be manufactured from the
            // absence of one.
            assert!(error.contains("unresolved"), "{deviation:?}: {error}");
        }
    }
}
