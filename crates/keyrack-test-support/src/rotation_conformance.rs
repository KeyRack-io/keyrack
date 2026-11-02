// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wrapped-child rotation and creation-journal recovery across storage backends.

use crate::creation_conformance::{closure, staged};
use crate::migration_conformance::seeded;
use keyrack_core::audit::FanoutSink;
use keyrack_core::creation::{creation_correlation, CreationOwner, CreationPhase, CreationRequest};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::{
    Exportability, KeyMaterial, KeyRecord, KeySpec, KeyVersionRecord, ProviderClass, ProviderRef,
};
use keyrack_core::material::ParentWrappedMaterial;
use keyrack_core::provider::software::{SoftwareProvider, SOFTWARE_WRAPPING_MECHANISM};
use keyrack_core::provider::{
    CryptoProvider, EncryptOutput, GeneratedWrappedKey, KeyHandle, ProviderCapabilities,
    SigningAlgorithm, WrappedKeyClosure, WrappedKeyLease,
};
use keyrack_core::registry::{ProviderEntry, StaticProviderRegistry};
use keyrack_core::sensitive::Sensitive;
use keyrack_core::storage::StorageBackend;
use keyrack_core::wrapping::{
    VersionedKeyId, WrappedKeyFormat, WrappingCapabilities, WrappingContext,
    WrappingContextVersion, WrappingIdentifier,
};
use keyrack_service::domain::{self, CreateKeyInput, DomainError};
use keyrack_service::hierarchy::{WrappingProfile, WrappingProfiles};
use keyrack_service::migration::{prepare_migration, rewrap_key};
use keyrack_service::routing::ProviderRouter;
use keyrack_service::state::ServiceState;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

const DOMAIN: &str = "rotation-conformance-domain";
const PROVIDER: &str = "default";

fn name(value: &str) -> WrappingIdentifier {
    WrappingIdentifier::new(value).unwrap()
}

struct CountingProvider {
    inner: SoftwareProvider,
    wrapped_generations: AtomicUsize,
}

impl CountingProvider {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: SoftwareProvider::scoped(ProviderRef::new(PROVIDER), name(DOMAIN)),
            wrapped_generations: AtomicUsize::new(0),
        })
    }

    fn generations(&self) -> usize {
        self.wrapped_generations.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl CryptoProvider for CountingProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        self.inner.capabilities()
    }
    fn wrapping_capabilities(&self) -> WrappingCapabilities {
        self.inner.wrapping_capabilities()
    }
    fn wrapping_closure_verifier(
        &self,
    ) -> Option<Arc<dyn keyrack_core::creation::A2ClosureVerifier>> {
        self.inner.wrapping_closure_verifier()
    }
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        self.inner.generate_key(spec).await
    }
    async fn encrypt(
        &self,
        handle: &KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        self.inner.encrypt(handle, plaintext, aad).await
    }
    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        self.inner.decrypt(handle, ciphertext, aad).await
    }
    async fn sign(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.inner.sign(handle, algorithm, message).await
    }
    async fn verify(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.inner
            .verify(handle, algorithm, message, signature)
            .await
    }
    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        self.inner.generate_random(length).await
    }
    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()> {
        self.inner.destroy_key(handle).await
    }
    async fn generate_wrapped_key(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        creation: &keyrack_core::creation::CreationBinding,
    ) -> Result<GeneratedWrappedKey> {
        self.wrapped_generations.fetch_add(1, Ordering::SeqCst);
        self.inner
            .generate_wrapped_key(context, parent, creation)
            .await
    }
    async fn open_wrapped_key(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        envelope: &[u8],
    ) -> Result<WrappedKeyLease> {
        self.inner.open_wrapped_key(context, parent, envelope).await
    }
    async fn close_wrapped_key(&self, lease: &WrappedKeyLease) -> Result<WrappedKeyClosure> {
        self.inner.close_wrapped_key(lease).await
    }
    async fn rewrap_wrapped_key(
        &self,
        old: &WrappingContext,
        old_parent: &KeyHandle,
        envelope: &[u8],
        new: &WrappingContext,
        new_parent: &KeyHandle,
    ) -> Result<Vec<u8>> {
        self.inner
            .rewrap_wrapped_key(old, old_parent, envelope, new, new_parent)
            .await
    }
}

fn service_state(
    storage: Arc<dyn StorageBackend>,
    provider: Arc<CountingProvider>,
) -> Arc<ServiceState> {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    Arc::new(ServiceState {
        storage,
        providers: Arc::new(
            StaticProviderRegistry::new(
                [(
                    ProviderRef::new(PROVIDER),
                    ProviderEntry {
                        provider,
                        class: ProviderClass::Software,
                    },
                )],
                ProviderRef::new(PROVIDER),
            )
            .unwrap(),
        ),
        provider_router: ProviderRouter::new(vec![], ProviderRef::new(PROVIDER)).unwrap(),
        pdp: Arc::new(keyrack_core::pdp::AlwaysAllow),
        audit: Arc::new(FanoutSink::new(vec![])),
        authn: Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
            Box::new(keyrack_core::authn::InsecureAuthenticator),
        ])),
        metrics_handle: recorder.handle(),
        max_plaintext_bytes: 4096,
        legacy_compromised_key_decrypt: false,
        nats_publisher: None,
        lease_cleanup: keyrack_service::lease::LeaseCleanup::default(),
        wrapping: WrappingProfiles::new([(
            ProviderRef::new(PROVIDER),
            WrappingProfile {
                mechanism: name(SOFTWARE_WRAPPING_MECHANISM),
                security_domain: name(DOMAIN),
            },
        )]),
    })
}

fn create_input(parent: Option<&KeyRecord>) -> CreateKeyInput {
    CreateKeyInput {
        key_spec: KeySpec::Aes256,
        attributes: BTreeMap::new(),
        namespace: String::new(),
        description: None,
        exportable: Exportability::NonExportable,
        parent_key_id: parent.map(|p| p.lid.to_string()),
        hsm_connection_id: None,
        backend_id: None,
    }
}

async fn parent_and_child(
    store: Arc<dyn StorageBackend>,
) -> (Arc<ServiceState>, KeyRecord, KeyRecord) {
    let provider = CountingProvider::new();
    let state = service_state(store, provider);
    let parent = domain::create_key(&state, create_input(None))
        .await
        .unwrap();
    let child = domain::create_key(&state, create_input(Some(&parent)))
        .await
        .unwrap();
    (state, parent, child)
}

fn rotation_request(
    child: &KeyRecord,
    parent: &KeyRecord,
    owner: CreationOwner,
) -> CreationRequest {
    let operation = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let mut record = child.clone();
    record.occ_version += 1;
    record.current_key_version += 1;
    record.updated_at = chrono::Utc::now();
    for version in &mut record.key_versions {
        version.is_primary = false;
    }
    record.key_versions.push(KeyVersionRecord {
        version_number: record.current_key_version,
        material: KeyMaterial::ParentWrapped(
            ParentWrappedMaterial::new(
                ProviderRef::new(PROVIDER),
                name(DOMAIN),
                VersionedKeyId::new(parent.lid, parent.current_key_version).unwrap(),
                WrappingContextVersion::V1,
                WrappedKeyFormat::RawSecret,
                name(SOFTWARE_WRAPPING_MECHANISM),
                name(&format!("creation:{operation}")),
            )
            .unwrap(),
        ),
        created_at: chrono::Utc::now(),
        is_primary: true,
    });
    let mut request = CreationRequest {
        operation,
        attempt,
        owner,
        correlation: creation_correlation(operation, attempt),
        record,
        expected_key_occ: Some(child.occ_version),
        expected_parent_occ: parent.occ_version,
        parent_spec: parent.key_spec.clone(),
        context_bytes: vec![],
    };
    request.context_bytes = request.context().unwrap().canonical_bytes().unwrap();
    request
}

fn stale_owner() -> CreationOwner {
    CreationOwner {
        instance: Uuid::new_v4(),
        generation: 1,
    }
}

fn wrapped_material(version: &KeyVersionRecord) -> &ParentWrappedMaterial {
    let KeyMaterial::ParentWrapped(material) = &version.material else {
        panic!("expected parent-wrapped version")
    };
    material
}

fn parent_version_number(version: &KeyVersionRecord) -> u64 {
    wrapped_material(version).parent().version.get()
}

async fn encrypt_under_primary(state: &Arc<ServiceState>, child: &KeyRecord) -> Vec<u8> {
    let provider = state
        .providers
        .resolve(&ProviderRef::new(PROVIDER))
        .unwrap()
        .provider;
    let version = child.primary_version().unwrap();
    domain::with_usable_handle(state, child, version, &provider, {
        let provider = provider.clone();
        move |handle| async move {
            provider
                .encrypt(&handle, b"rotation payload", b"aad")
                .await
                .map(|output| output.ciphertext)
                .map_err(DomainError::from)
        }
    })
    .await
    .unwrap()
}

async fn assert_decrypts(
    state: &Arc<ServiceState>,
    child: &KeyRecord,
    version_number: u64,
    ciphertext: &[u8],
) {
    let provider = state
        .providers
        .resolve(&ProviderRef::new(PROVIDER))
        .unwrap()
        .provider;
    let version = child.get_version(version_number).unwrap();
    let ciphertext = ciphertext.to_vec();
    let plaintext = domain::with_usable_handle(state, child, version, &provider, {
        let provider = provider.clone();
        move |handle| async move {
            provider
                .decrypt(&handle, &ciphertext, b"aad")
                .await
                .map(|value| value.expose().clone())
                .map_err(DomainError::from)
        }
    })
    .await
    .unwrap();
    assert_eq!(plaintext, b"rotation payload");
}

async fn assert_no_pending_creations(store: &dyn StorageBackend, child: &KeyRecord) {
    assert!(store
        .pending_creations(&child.lid)
        .await
        .unwrap()
        .is_empty());
}

fn version_material_unchanged(a: &KeyVersionRecord, b: &KeyVersionRecord) {
    assert_eq!(a.material, b.material);
    assert_eq!(a.created_at, b.created_at);
}

pub async fn old_versions_decrypt_and_new_version_names_parent_current(
    store: Arc<dyn StorageBackend>,
) {
    let (state, mut parent, child) = parent_and_child(store).await;
    let v1_snapshot = child.key_versions[0].clone();
    let initial_occ = child.occ_version;
    let ct_v1 = encrypt_under_primary(&state, &child).await;

    let rotated = domain::rotate_key(&state, &child.lid, &child.lid.to_string())
        .await
        .unwrap()
        .record;
    assert_eq!(rotated.current_key_version, 2);
    assert_eq!(rotated.occ_version, initial_occ + 1);
    assert_eq!(
        parent_version_number(rotated.primary_version().unwrap()),
        parent.current_key_version
    );
    version_material_unchanged(&rotated.key_versions[0], &v1_snapshot);
    assert_decrypts(&state, &rotated, 1, &ct_v1).await;
    let ct_v2 = encrypt_under_primary(&state, &rotated).await;
    assert_decrypts(&state, &rotated, 2, &ct_v2).await;
    assert_no_pending_creations(state.storage.as_ref(), &rotated).await;

    domain::rotate_key(&state, &parent.lid, &parent.lid.to_string())
        .await
        .unwrap();
    parent = state.storage.get_key(&parent.lid).await.unwrap();
    assert_eq!(parent.current_key_version, 2);
    let unchanged = state.storage.get_key(&child.lid).await.unwrap();
    assert_eq!(unchanged.current_key_version, 2);
    assert_eq!(unchanged.occ_version, rotated.occ_version);
    assert_eq!(parent_version_number(unchanged.get_version(1).unwrap()), 1);
    assert_eq!(parent_version_number(unchanged.get_version(2).unwrap()), 1);
    assert_decrypts(&state, &unchanged, 1, &ct_v1).await;
    assert_decrypts(&state, &unchanged, 2, &ct_v2).await;

    let third = domain::rotate_key(&state, &child.lid, &child.lid.to_string())
        .await
        .unwrap()
        .record;
    assert_eq!(third.current_key_version, 3);
    assert_eq!(third.occ_version, initial_occ + 2);
    assert_eq!(
        parent_version_number(third.primary_version().unwrap()),
        parent.current_key_version
    );
    assert_eq!(parent_version_number(third.get_version(1).unwrap()), 1);
    assert_eq!(parent_version_number(third.get_version(2).unwrap()), 1);
    version_material_unchanged(&third.key_versions[0], &v1_snapshot);
    assert_decrypts(&state, &third, 1, &ct_v1).await;
    assert_decrypts(&state, &third, 2, &ct_v2).await;
    let ct_v3 = encrypt_under_primary(&state, &third).await;
    assert_decrypts(&state, &third, 3, &ct_v3).await;
    assert_no_pending_creations(state.storage.as_ref(), &third).await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CrashPhase {
    ReservedUndispatched,
    ReservedDispatched,
    Staged,
    Resolved,
    Committed,
}

async fn plant_crash_entry(
    state: &Arc<ServiceState>,
    child: &KeyRecord,
    parent: &KeyRecord,
    phase: CrashPhase,
) -> CreationRequest {
    let owner = stale_owner();
    let request = rotation_request(child, parent, owner);
    let store = state.storage.as_ref();
    if phase == CrashPhase::Committed {
        use keyrack_core::creation_driver::{
            A2CreationDriver, CreationProgress, WrappingCreationProvider,
        };
        use keyrack_core::wrapping::WrappedKeyLifecycle;
        let provider = state
            .providers
            .resolve(&ProviderRef::new(PROVIDER))
            .unwrap()
            .provider;
        let parent_handle = parent
            .primary_version()
            .unwrap()
            .resident_handle()
            .unwrap()
            .clone();
        let adapter = WrappingCreationProvider::new(
            provider,
            parent_handle,
            WrappedKeyLifecycle::SessionObject,
        )
        .unwrap();
        match A2CreationDriver::new(state.storage.clone(), Arc::new(adapter))
            .run(request.clone())
            .await
            .unwrap()
        {
            CreationProgress::Committed(_) => {}
            CreationProgress::Pending(reason) => {
                panic!("committed plant left creation pending: {reason:?}")
            }
        }
    } else {
        store.reserve_creation(&request).await.unwrap();
        match phase {
            CrashPhase::ReservedUndispatched => {}
            CrashPhase::ReservedDispatched => {
                store
                    .claim_creation_dispatch(request.operation, request.owner)
                    .await
                    .unwrap();
            }
            CrashPhase::Staged => {
                staged(store, &request).await;
            }
            CrashPhase::Resolved => {
                staged(store, &request).await;
                store
                    .resolve_creation(request.operation, request.owner, 2, &closure(&request))
                    .await
                    .unwrap();
            }
            CrashPhase::Committed => unreachable!(),
        }
    }
    request
}

pub async fn crash_recovery_each_phase<F, FF, R, RF>(fresh_store: F, reconnect: R)
where
    F: Fn() -> FF,
    FF: Future<Output = Arc<dyn StorageBackend>>,
    R: Fn(Arc<dyn StorageBackend>) -> RF,
    RF: Future<Output = Arc<dyn StorageBackend>>,
{
    for phase in [
        CrashPhase::ReservedUndispatched,
        CrashPhase::ReservedDispatched,
        CrashPhase::Staged,
        CrashPhase::Resolved,
        CrashPhase::Committed,
    ] {
        let provider = CountingProvider::new();
        let store = fresh_store().await;
        let state = service_state(store.clone(), provider.clone());
        let parent = domain::create_key(&state, create_input(None))
            .await
            .unwrap();
        let child = domain::create_key(&state, create_input(Some(&parent)))
            .await
            .unwrap();
        let ct_v1 = encrypt_under_primary(&state, &child).await;
        let before = child.clone();
        let request = plant_crash_entry(&state, &child, &parent, phase).await;
        let store = reconnect(store).await;
        let state = service_state(store.clone(), provider);

        match phase {
            CrashPhase::ReservedUndispatched | CrashPhase::Resolved => {
                let after = domain::rotate_key(&state, &child.lid, &child.lid.to_string())
                    .await
                    .unwrap()
                    .record;
                assert!(store.get_creation(request.operation).await.is_err());
                assert_eq!(after.current_key_version, before.current_key_version + 1);
                assert_decrypts(&state, &after, 1, &ct_v1).await;
            }
            CrashPhase::ReservedDispatched | CrashPhase::Staged => {
                let outcome = domain::rotate_key(&state, &child.lid, &child.lid.to_string()).await;
                assert!(
                    matches!(
                        outcome,
                        Err(DomainError::ProviderUnavailable(ref msg))
                            if msg.contains("another instance") && msg.contains("reconcile")
                    ),
                    "expected a retryable refusal naming reconciliation, got success={}",
                    outcome.is_ok()
                );
                let unchanged = store.get_key(&child.lid).await.unwrap();
                assert_eq!(unchanged.occ_version, before.occ_version);
                assert_eq!(unchanged.current_key_version, before.current_key_version);
                assert_eq!(
                    store.get_creation(request.operation).await.unwrap().phase,
                    if phase == CrashPhase::Staged {
                        CreationPhase::Staged
                    } else {
                        CreationPhase::Reserved
                    }
                );
                assert_decrypts(&state, &unchanged, 1, &ct_v1).await;
            }
            CrashPhase::Committed => {
                let published = store.get_key(&child.lid).await.unwrap();
                assert_eq!(published.current_key_version, 2);
                assert_decrypts(&state, &published, 1, &ct_v1).await;
                let ct_v2 = encrypt_under_primary(&state, &published).await;
                let after = domain::rotate_key(&state, &child.lid, &child.lid.to_string())
                    .await
                    .unwrap()
                    .record;
                assert_eq!(after.current_key_version, 3);
                assert_decrypts(&state, &after, 2, &ct_v2).await;
            }
        }
    }
}

pub async fn withdraw_semantics(store: &dyn StorageBackend) {
    use crate::creation_conformance::fixture;

    let absent = Uuid::new_v4();
    store.withdraw_creation(absent).await.unwrap();

    let (parent, mut first) = fixture();
    store.create_key(&parent).await.unwrap();
    let operation = first.operation;
    crate::creation_conformance::replace_envelope_ref(&mut first, format!("creation:{operation}"));
    store.reserve_creation(&first).await.unwrap();
    store.withdraw_creation(operation).await.unwrap();
    assert!(store.get_creation(operation).await.is_err());
    store.reserve_creation(&first).await.unwrap();
    store.withdraw_creation(operation).await.unwrap();

    let (parent, mut resolved) = fixture();
    store.create_key(&parent).await.unwrap();
    let operation = resolved.operation;
    crate::creation_conformance::replace_envelope_ref(
        &mut resolved,
        format!("creation:{operation}"),
    );
    crate::creation_conformance::resolved(store, &resolved).await;
    store.withdraw_creation(operation).await.unwrap();
    assert!(store.get_creation(operation).await.is_err());
    let mut retry = resolved.clone();
    retry.operation = Uuid::new_v4();
    retry.attempt = Uuid::new_v4();
    retry.correlation = creation_correlation(retry.operation, retry.attempt);
    let retry_operation = retry.operation;
    crate::creation_conformance::replace_envelope_ref(
        &mut retry,
        format!("creation:{retry_operation}"),
    );
    store.reserve_creation(&retry).await.unwrap();
    store.withdraw_creation(retry.operation).await.unwrap();

    let (parent, request) = fixture();
    store.create_key(&parent).await.unwrap();
    store.reserve_creation(&request).await.unwrap();
    store
        .claim_creation_dispatch(request.operation, request.owner)
        .await
        .unwrap();
    assert!(store.withdraw_creation(request.operation).await.is_err());
    assert_eq!(
        store.get_creation(request.operation).await.unwrap().phase,
        CreationPhase::Reserved
    );

    let (parent, request) = fixture();
    store.create_key(&parent).await.unwrap();
    staged(store, &request).await;
    assert!(store.withdraw_creation(request.operation).await.is_err());
    assert_eq!(
        store.get_creation(request.operation).await.unwrap().phase,
        CreationPhase::Staged
    );

    let (parent, request) = fixture();
    store.create_key(&parent).await.unwrap();
    crate::creation_conformance::resolved(store, &request).await;
    store
        .publish_creation(request.operation, request.owner, 3)
        .await
        .unwrap();
    assert!(store.withdraw_creation(request.operation).await.is_err());
    assert_eq!(
        store.get_creation(request.operation).await.unwrap().phase,
        CreationPhase::Committed
    );
}

pub async fn journal_pins_parent_current_version_and_lineage(store: Arc<dyn StorageBackend>) {
    let (state, parent, child) = parent_and_child(store).await;
    let other = domain::create_key(&state, create_input(None))
        .await
        .unwrap();
    domain::rotate_key(&state, &parent.lid, &parent.lid.to_string())
        .await
        .unwrap();
    let parent = state.storage.get_key(&parent.lid).await.unwrap();
    assert_eq!(parent.current_key_version, 2);

    let mut superseded = parent.clone();
    superseded.current_key_version = 1;
    let stale_version = rotation_request(&child, &superseded, stale_owner());
    assert!(state
        .storage
        .reserve_creation(&stale_version)
        .await
        .is_err());
    assert!(state
        .storage
        .get_creation(stale_version.operation)
        .await
        .is_err());

    let foreign = rotation_request(&child, &other, stale_owner());
    assert_eq!(foreign.record.parent_lid, Some(parent.lid));
    assert!(state.storage.reserve_creation(&foreign).await.is_err());
    assert!(state.storage.get_creation(foreign.operation).await.is_err());

    let current = rotation_request(&child, &parent, stale_owner());
    state.storage.reserve_creation(&current).await.unwrap();
    state
        .storage
        .withdraw_creation(current.operation)
        .await
        .unwrap();
    assert_no_pending_creations(state.storage.as_ref(), &child).await;
}

fn retryable<T: std::fmt::Debug>(result: Result<T>) {
    let error = result.expect_err("expected retryable storage refusal");
    assert!(
        matches!(error, KeyRackError::ProviderUnavailable(_)),
        "{error:?}"
    );
}

pub async fn rotation_and_migration_fences(
    migration_store: Arc<dyn StorageBackend>,
    interaction_store: Arc<dyn StorageBackend>,
) {
    let (request, _) = seeded(migration_store.as_ref()).await;
    migration_store.reserve_migration(&request).await.unwrap();
    let provider = CountingProvider::new();
    let before_generations = provider.generations();
    let state = service_state(migration_store.clone(), provider.clone());
    let child_before = state.storage.get_key(&request.child.lid).await.unwrap();
    let outcome =
        domain::rotate_key(&state, &request.child.lid, &request.child.lid.to_string()).await;
    assert!(
        matches!(outcome, Err(DomainError::ProviderUnavailable(_))),
        "expected migration fence, got success={}",
        outcome.is_ok()
    );
    assert_eq!(provider.generations(), before_generations);
    let child_after = state.storage.get_key(&request.child.lid).await.unwrap();
    assert_eq!(child_after.occ_version, child_before.occ_version);
    assert_eq!(
        child_after.current_key_version,
        child_before.current_key_version
    );
    assert!(state
        .storage
        .pending_creations(&request.child.lid)
        .await
        .unwrap()
        .is_empty());

    let (state, parent, child) = parent_and_child(interaction_store.clone()).await;
    let new_parent = domain::create_key(&state, create_input(None))
        .await
        .unwrap();
    let ct_v1 = encrypt_under_primary(&state, &child).await;
    let rotate = rotation_request(&child, &parent, stale_owner());
    interaction_store.reserve_creation(&rotate).await.unwrap();
    retryable(
        interaction_store
            .reserve_migration(
                &keyrack_core::migration::MigrationRequest::new(
                    Uuid::new_v4(),
                    Some(new_parent.lid),
                    child.clone(),
                    parent.clone(),
                    new_parent.clone(),
                )
                .unwrap(),
            )
            .await,
    );

    let rotated = domain::rotate_key(&state, &child.lid, &child.lid.to_string())
        .await
        .unwrap()
        .record;
    assert_decrypts(&state, &rotated, 1, &ct_v1).await;
    assert_no_pending_creations(interaction_store.as_ref(), &rotated).await;
    let ct_v2 = encrypt_under_primary(&state, &rotated).await;

    let migration = prepare_migration(&state, child.lid, Some(new_parent.lid), Uuid::new_v4())
        .await
        .unwrap();
    let migrated = rewrap_key(&state, migration).await.unwrap();
    assert_eq!(migrated.parent_lid, Some(new_parent.lid));
    for version in &migrated.key_versions {
        assert_eq!(
            parent_version_number(version),
            new_parent.current_key_version
        );
    }
    assert_decrypts(&state, &migrated, 1, &ct_v1).await;
    assert_decrypts(&state, &migrated, rotated.current_key_version, &ct_v2).await;
}
