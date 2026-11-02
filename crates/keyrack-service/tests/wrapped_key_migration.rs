// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Migration conformance using real SQLite journals and software cryptography.
use keyrack_core::creation::{
    creation_correlation, CreationBinding, CreationOwner, CreationRequest,
};
use keyrack_core::creation_driver::{A2CreationDriver, CreationProgress, WrappingCreationProvider};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::{
    Exportability, KeyMaterial, KeyRecord, KeySpec, KeyState, KeyVersionRecord, ProviderClass,
    ProviderRef,
};
use keyrack_core::material::ParentWrappedMaterial;
use keyrack_core::migration::{MigrationPhase, MigrationRequest};
use keyrack_core::provider::software::{SoftwareProvider, SOFTWARE_WRAPPING_MECHANISM};
use keyrack_core::provider::{
    CryptoProvider, EncryptOutput, GeneratedWrappedKey, KeyHandle, ProviderCapabilities,
    SigningAlgorithm, WrappedKeyClosure, WrappedKeyLease,
};
use keyrack_core::registry::{ProviderEntry, StaticProviderRegistry};
use keyrack_core::sensitive::Sensitive;
use keyrack_core::storage::StorageBackend;
use keyrack_core::wrapping::{
    VersionedKeyId, WrappedKeyFormat, WrappedKeyLifecycle, WrappingCapabilities, WrappingContext,
    WrappingContextVersion, WrappingIdentifier, WrappingKeyPurpose,
};
use keyrack_service::domain::{self, CreateKeyInput, DomainError};
use keyrack_service::hierarchy::{WrappingProfile, WrappingProfiles};
use keyrack_service::migration::{prepare_migration, rewrap_key};
use keyrack_service::routing::ProviderRouter;
use keyrack_service::state::ServiceState;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

const DOMAIN: &str = "migration-test-domain";

fn name(value: &str) -> WrappingIdentifier {
    WrappingIdentifier::new(value).unwrap()
}

struct SilentAudit;
#[async_trait::async_trait]
impl keyrack_core::audit::AuditSink for SilentAudit {
    async fn emit(&self, _: &keyrack_core::audit::AuditEvent) -> Result<()> {
        Ok(())
    }
}

/// Pauses before a real rewrap effect; cancellation cannot leave a child object.
struct ObservedProvider {
    inner: SoftwareProvider,
    rewraps: AtomicUsize,
    paused: AtomicBool,
    entered: Semaphore,
    release: Semaphore,
    retry_safe: AtomicBool,
    fail_at_call: AtomicUsize,
    open_paused: AtomicBool,
    open_entered: Semaphore,
    open_release: Semaphore,
    decrypts: AtomicUsize,
}
impl ObservedProvider {
    fn new() -> Self {
        Self {
            inner: SoftwareProvider::scoped(ProviderRef::new("default"), name(DOMAIN)),
            rewraps: AtomicUsize::new(0),
            paused: AtomicBool::new(false),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            retry_safe: AtomicBool::new(true),
            fail_at_call: AtomicUsize::new(0),
            open_paused: AtomicBool::new(false),
            open_entered: Semaphore::new(0),
            open_release: Semaphore::new(0),
            decrypts: AtomicUsize::new(0),
        }
    }
}
#[async_trait::async_trait]
impl CryptoProvider for ObservedProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        self.inner.capabilities()
    }
    fn wrapping_capabilities(&self) -> WrappingCapabilities {
        self.inner.wrapping_capabilities()
    }
    fn rewrap_is_retry_safe(&self) -> bool {
        self.retry_safe.load(Ordering::SeqCst)
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
        self.decrypts.fetch_add(1, Ordering::SeqCst);
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
        creation: &CreationBinding,
    ) -> Result<GeneratedWrappedKey> {
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
        if self.open_paused.swap(false, Ordering::SeqCst) {
            self.open_entered.add_permits(1);
            self.open_release.acquire().await.unwrap().forget();
        }
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
        let call = self.rewraps.fetch_add(1, Ordering::SeqCst) + 1;
        if self.paused.load(Ordering::SeqCst) {
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
        let envelope = self
            .inner
            .rewrap_wrapped_key(old, old_parent, envelope, new, new_parent)
            .await?;
        if self.fail_at_call.load(Ordering::SeqCst) == call {
            return Err(KeyRackError::ProviderUnavailable(
                "injected lost provider reply after effect".into(),
            ));
        }
        Ok(envelope)
    }
}

fn service_state(
    storage: Arc<dyn StorageBackend>,
    provider: Arc<ObservedProvider>,
) -> Arc<ServiceState> {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    Arc::new(ServiceState {
        storage,
        providers: Arc::new(
            StaticProviderRegistry::new(
                [(
                    ProviderRef::new("default"),
                    ProviderEntry {
                        provider,
                        class: ProviderClass::Software,
                    },
                )],
                ProviderRef::new("default"),
            )
            .unwrap(),
        ),
        provider_router: ProviderRouter::new(vec![], ProviderRef::new("default")).unwrap(),
        pdp: Arc::new(keyrack_core::pdp::AlwaysAllow),
        audit: Arc::new(SilentAudit),
        authn: Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
            Box::new(keyrack_core::authn::InsecureAuthenticator),
        ])),
        metrics_handle: recorder.handle(),
        max_plaintext_bytes: 4096,
        legacy_compromised_key_decrypt: false,
        nats_publisher: None,
        lease_cleanup: keyrack_service::lease::LeaseCleanup::default(),
        wrapping: WrappingProfiles::new([(
            ProviderRef::new("default"),
            WrappingProfile {
                mechanism: name(SOFTWARE_WRAPPING_MECHANISM),
                security_domain: name(DOMAIN),
            },
        )]),
    })
}

fn input(parent: Option<&KeyRecord>) -> CreateKeyInput {
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

async fn fixture() -> (
    Arc<ServiceState>,
    Arc<ObservedProvider>,
    KeyRecord,
    KeyRecord,
    KeyRecord,
) {
    let provider = Arc::new(ObservedProvider::new());
    let state = service_state(
        Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap()),
        provider.clone(),
    );
    let old = domain::create_key(&state, input(None)).await.unwrap();
    let new = domain::create_key(&state, input(None)).await.unwrap();
    let child = domain::create_key(&state, input(Some(&old))).await.unwrap();
    (state, provider, child, old, new)
}

fn rotation_request(child: &KeyRecord, parent: &KeyRecord) -> CreationRequest {
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
                ProviderRef::new("default"),
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
        owner: CreationOwner {
            instance: Uuid::new_v4(),
            generation: 1,
        },
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

async fn append_version(
    state: &Arc<ServiceState>,
    child: &KeyRecord,
    parent: &KeyRecord,
) -> KeyRecord {
    let provider = state
        .providers
        .resolve(&ProviderRef::new("default"))
        .unwrap()
        .provider;
    let adapter = WrappingCreationProvider::new(
        provider,
        parent
            .primary_version()
            .unwrap()
            .resident_handle()
            .unwrap()
            .clone(),
        WrappedKeyLifecycle::SessionObject,
    )
    .unwrap();
    match A2CreationDriver::new(state.storage.clone(), Arc::new(adapter))
        .run(rotation_request(child, parent))
        .await
        .unwrap()
    {
        CreationProgress::Committed(record) => *record,
        CreationProgress::Pending(reason) => panic!("creation unresolved: {reason:?}"),
    }
}

fn material(version: &KeyVersionRecord) -> &ParentWrappedMaterial {
    let KeyMaterial::ParentWrapped(material) = &version.material else {
        panic!("wrapped version")
    };
    material
}

fn context(child: &KeyRecord, version: &KeyVersionRecord, parent: &KeyRecord) -> WrappingContext {
    let material = material(version);
    WrappingContext {
        version: material.wrapping_context_version(),
        child: VersionedKeyId::new(child.lid, version.version_number).unwrap(),
        parent: material.parent(),
        parent_spec: parent.key_spec.clone(),
        child_spec: child.key_spec.clone(),
        key_format: material.key_format().clone(),
        purpose: WrappingKeyPurpose::EncryptDecrypt,
        provider_ref: material.provider_ref().clone(),
        security_domain: material.security_domain().clone(),
        mechanism: material.mechanism().clone(),
        public_material_sha256: None,
    }
}

async fn read_envelope(state: &ServiceState, version: &KeyVersionRecord) -> Result<Vec<u8>> {
    let reference = material(version).wrapped_material_ref().as_str();
    if let Some(operation) = reference.strip_prefix("creation:") {
        state
            .storage
            .read_creation_envelope(operation.parse().unwrap())
            .await
    } else {
        let (operation, version) = reference
            .strip_prefix("migration:")
            .unwrap()
            .split_once(':')
            .unwrap();
        state
            .storage
            .read_migration_envelope(operation.parse().unwrap(), version.parse().unwrap())
            .await
    }
}

async fn ciphertexts(state: &Arc<ServiceState>, child: &KeyRecord) -> Vec<Vec<u8>> {
    let provider = state
        .providers
        .resolve(&ProviderRef::new("default"))
        .unwrap()
        .provider;
    let mut result = Vec::new();
    for version in &child.key_versions {
        let crypto = provider.clone();
        result.push(
            domain::with_usable_handle(state, child, version, &provider, |handle| async move {
                crypto
                    .encrypt(&handle, b"original payload", b"aad")
                    .await
                    .map(|output| output.ciphertext)
                    .map_err(DomainError::from)
            })
            .await
            .unwrap(),
        );
    }
    result
}

async fn assert_decrypts(state: &Arc<ServiceState>, child: &KeyRecord, ciphertexts: &[Vec<u8>]) {
    let provider = state
        .providers
        .resolve(&ProviderRef::new("default"))
        .unwrap()
        .provider;
    for (version, ciphertext) in child.key_versions.iter().zip(ciphertexts) {
        let crypto = provider.clone();
        let ciphertext = ciphertext.clone();
        let plaintext =
            domain::with_usable_handle(state, child, version, &provider, |handle| async move {
                crypto
                    .decrypt(&handle, &ciphertext, b"aad")
                    .await
                    .map(|value| value.expose().clone())
                    .map_err(DomainError::from)
            })
            .await
            .unwrap();
        assert_eq!(plaintext, b"original payload");
    }
}

async fn envelopes(state: &Arc<ServiceState>, request: &MigrationRequest) -> Vec<Vec<u8>> {
    let provider = state
        .providers
        .resolve(&ProviderRef::new("default"))
        .unwrap()
        .provider;
    let mut result = Vec::new();
    for (old, new) in request
        .child
        .key_versions
        .iter()
        .zip(&request.proposed.key_versions)
    {
        result.push(
            provider
                .rewrap_wrapped_key(
                    &context(&request.child, old, &request.old_parent),
                    request
                        .old_parent
                        .get_version(material(old).parent().version.get())
                        .unwrap()
                        .resident_handle()
                        .unwrap(),
                    &read_envelope(state, old).await.unwrap(),
                    &context(&request.proposed, new, &request.new_parent),
                    request
                        .new_parent
                        .primary_version()
                        .unwrap()
                        .resident_handle()
                        .unwrap(),
                )
                .await
                .unwrap(),
        );
    }
    result
}

#[tokio::test]
async fn every_version_survives_rewrap_and_reparent_and_old_parent_is_destroyable() {
    let (state, provider, child, old, new) = fixture().await;
    let child = append_version(&state, &child, &old).await;
    let child = append_version(&state, &child, &old).await;
    let ciphertexts = ciphertexts(&state, &child).await;
    domain::rotate_key(&state, &old.lid, &old.lid.to_string())
        .await
        .unwrap();
    let request = prepare_migration(&state, child.lid, None, Uuid::new_v4())
        .await
        .unwrap();
    let rewrapped = rewrap_key(&state, request.clone()).await.unwrap();
    assert_eq!(rewrapped.parent_lid, Some(old.lid));
    assert!(rewrapped
        .key_versions
        .iter()
        .all(|v| material(v).parent().version.get() == 2));
    assert_decrypts(&state, &rewrapped, &ciphertexts).await;
    for (old_version, new_version) in child.key_versions.iter().zip(&rewrapped.key_versions) {
        assert!(
            read_envelope(&state, old_version).await.is_err(),
            "old envelope was not erased"
        );
        assert!(
            provider
                .open_wrapped_key(
                    &context(&child, old_version, &old),
                    request
                        .new_parent
                        .primary_version()
                        .unwrap()
                        .resident_handle()
                        .unwrap(),
                    &read_envelope(&state, new_version).await.unwrap()
                )
                .await
                .is_err(),
            "new envelope accepted old context"
        );
    }
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    let reparented = rewrap_key(&state, request).await.unwrap();
    assert_eq!(reparented.parent_lid, Some(new.lid));
    assert_decrypts(&state, &reparented, &ciphertexts).await;
    for version in &rewrapped.key_versions {
        assert!(read_envelope(&state, version).await.is_err());
    }
    let mut old = state.storage.get_key(&old.lid).await.unwrap();
    old.transition_to(KeyState::PendingDeletion).unwrap();
    old.scheduled_deletion_at = Some(chrono::Utc::now() - chrono::Duration::days(1));
    state.storage.update_key(&old).await.unwrap();
    let claim = state
        .storage
        .claim_destruction(&old.lid, old.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .expect("old parent has no live envelope dependencies");
    assert_eq!(claim.record().lid, old.lid);
}

#[tokio::test]
async fn recovery_resumes_each_phase_and_committed_replay_is_idempotent() {
    for phase in [
        MigrationPhase::Reserved,
        MigrationPhase::Staged,
        MigrationPhase::Committed,
    ] {
        let path = std::env::temp_dir().join(format!(
            "keyrack-migration-recovery-{}.sqlite",
            Uuid::new_v4()
        ));
        let provider = Arc::new(ObservedProvider::new());
        let state = service_state(
            Arc::new(keyrack_sqlite::SqliteStorage::open(&path).unwrap()),
            provider.clone(),
        );
        let old = domain::create_key(&state, input(None)).await.unwrap();
        let new = domain::create_key(&state, input(None)).await.unwrap();
        let child = domain::create_key(&state, input(Some(&old))).await.unwrap();
        let ciphertexts = ciphertexts(&state, &child).await;
        let operation = Uuid::new_v4();
        let request = prepare_migration(&state, child.lid, Some(new.lid), operation)
            .await
            .unwrap();
        let reserved = state.storage.reserve_migration(&request).await.unwrap();
        let ownership = state
            .storage
            .claim_migration(operation, Uuid::new_v4(), reserved.epoch)
            .await
            .unwrap()
            .ownership()
            .unwrap();
        if phase != MigrationPhase::Reserved {
            state
                .storage
                .begin_migration_dispatch(operation, ownership, true)
                .await
                .unwrap();
            let bytes = envelopes(&state, &request).await;
            state
                .storage
                .stage_migration(operation, ownership, &bytes)
                .await
                .unwrap();
        }
        if phase == MigrationPhase::Committed {
            state
                .storage
                .commit_migration(operation, ownership)
                .await
                .unwrap();
        }
        // Restart storage and the service, retaining the provider as an external
        // surviving backend. The software provider itself is not persistent.
        drop(state);
        let state = service_state(
            Arc::new(keyrack_sqlite::SqliteStorage::open(&path).unwrap()),
            provider.clone(),
        );
        let before = provider.rewraps.load(Ordering::SeqCst);
        let retry = prepare_migration(&state, child.lid, Some(new.lid), operation)
            .await
            .unwrap();
        let result = rewrap_key(&state, retry).await.unwrap();
        let expected_calls = usize::from(phase == MigrationPhase::Reserved);
        assert_eq!(
            provider.rewraps.load(Ordering::SeqCst) - before,
            expected_calls
        );
        assert_decrypts(&state, &result, &ciphertexts).await;
        assert_eq!(
            state
                .storage
                .get_migration(operation)
                .await
                .unwrap()
                .unwrap()
                .phase,
            MigrationPhase::Committed
        );
        assert!(
            prepare_migration(&state, child.lid, None, operation)
                .await
                .is_err(),
            "operation ID reused for another intent"
        );
        assert!(
            prepare_migration(&state, new.lid, Some(new.lid), operation)
                .await
                .is_err(),
            "operation ID reused for another child"
        );
        drop(state);
        std::fs::remove_file(path).unwrap();
    }
}

#[tokio::test]
async fn cancellation_retains_the_fence_and_retry_finishes_the_migration() {
    let (state, provider, child, old, new) = fixture().await;
    let ciphertexts = ciphertexts(&state, &child).await;
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    provider.paused.store(true, Ordering::SeqCst);
    let task = tokio::spawn({
        let state = state.clone();
        let request = request.clone();
        async move { rewrap_key(&state, request).await }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.entered.acquire(),
    )
    .await
    .unwrap()
    .unwrap()
    .forget();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        state
            .storage
            .get_migration(request.operation)
            .await
            .unwrap()
            .unwrap()
            .phase,
        MigrationPhase::Reserved
    );
    for record in [&child, &old, &new] {
        let error = domain::rotate_key(&state, &record.lid, &record.lid.to_string())
            .await
            .err()
            .expect("in-flight migration must fence rotation");
        assert!(
            matches!(error, DomainError::ProviderUnavailable(_)),
            "{error:?}"
        );
    }
    assert!(matches!(
        state
            .storage
            .reserve_creation(&rotation_request(&child, &old))
            .await
            .unwrap_err(),
        KeyRackError::ProviderUnavailable(_)
    ));
    let create_error = domain::create_key(&state, input(Some(&new)))
        .await
        .unwrap_err();
    assert!(
        matches!(create_error, DomainError::ProviderUnavailable(_)),
        "{create_error:?}"
    );
    for parent in [&old, &new] {
        assert!(matches!(
            state
                .storage
                .claim_destruction(&parent.lid, parent.occ_version, chrono::Utc::now())
                .await
                .unwrap_err(),
            KeyRackError::DeletionDependencyRefused { ref reason, .. }
                if reason == "in_flight_journal"
        ));
    }
    assert_eq!(
        state.storage.get_key(&child.lid).await.unwrap().parent_lid,
        Some(old.lid)
    );
    provider.paused.store(false, Ordering::SeqCst);
    let result = rewrap_key(&state, request).await.unwrap();
    assert_decrypts(&state, &result, &ciphertexts).await;
}

#[tokio::test]
async fn invalid_parent_and_stale_snapshot_paths_have_no_rewrap_effect() {
    let (state, provider, child, old, new) = fixture().await;
    assert!(
        prepare_migration(&state, child.lid, Some(child.lid), Uuid::new_v4())
            .await
            .is_err(),
        "self-cycle accepted"
    );
    let wrapped_parent = domain::create_key(&state, input(Some(&new))).await.unwrap();
    assert!(
        prepare_migration(&state, child.lid, Some(wrapped_parent.lid), Uuid::new_v4())
            .await
            .is_err(),
        "wrapped parent accepted"
    );
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    domain::rotate_key(&state, &new.lid, &new.lid.to_string())
        .await
        .unwrap();
    assert!(
        rewrap_key(&state, request).await.is_err(),
        "stale target OCC accepted"
    );
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    domain::rotate_key(&state, &old.lid, &old.lid.to_string())
        .await
        .unwrap();
    assert!(
        rewrap_key(&state, request).await.is_err(),
        "stale source OCC accepted"
    );
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    let mut changed_child = state.storage.get_key(&child.lid).await.unwrap();
    changed_child.occ_version += 1;
    changed_child.description = "changed while preparing".into();
    state.storage.update_key(&changed_child).await.unwrap();
    assert!(
        rewrap_key(&state, request).await.is_err(),
        "stale child OCC accepted"
    );
    let mut new = state.storage.get_key(&new.lid).await.unwrap();
    new.transition_to(KeyState::PendingDeletion).unwrap();
    new.scheduled_deletion_at = Some(chrono::Utc::now());
    state.storage.update_key(&new).await.unwrap();
    assert!(
        prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
            .await
            .is_err(),
        "scheduled parent accepted"
    );
    assert_eq!(provider.rewraps.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cross_provider_and_destruction_claim_refuse_before_rewrap() {
    let (state, provider, child, _, new) = fixture().await;
    let mut foreign = new.clone();
    foreign.occ_version += 1;
    foreign.provider_ref = Some(ProviderRef::new("foreign"));
    let KeyMaterial::ProviderResident { provider_ref, .. } = &mut foreign.key_versions[0].material
    else {
        panic!("resident parent")
    };
    *provider_ref = Some(ProviderRef::new("foreign"));
    state.storage.update_key(&foreign).await.unwrap();
    let error = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("cross-provider"), "{error}");
    assert_eq!(provider.rewraps.load(Ordering::SeqCst), 0);

    let (state, provider, child, _, new) = fixture().await;
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    let mut doomed = new.clone();
    doomed.transition_to(KeyState::PendingDeletion).unwrap();
    doomed.scheduled_deletion_at = Some(chrono::Utc::now() - chrono::Duration::days(1));
    state.storage.update_key(&doomed).await.unwrap();
    let _claim = state
        .storage
        .claim_destruction(&doomed.lid, doomed.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert!(
        rewrap_key(&state, request).await.is_err(),
        "destroy-claimed target accepted"
    );
    assert_eq!(provider.rewraps.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn simultaneous_same_operation_retries_share_the_committed_result() {
    let (state, provider, child, _, new) = fixture().await;
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    provider.paused.store(true, Ordering::SeqCst);
    let first = tokio::spawn({
        let state = state.clone();
        let request = request.clone();
        async move { rewrap_key(&state, request).await }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.entered.acquire(),
    )
    .await
    .unwrap()
    .unwrap()
    .forget();
    let mut retries = Vec::new();
    for _ in 0..4 {
        let state = state.clone();
        let request = request.clone();
        retries.push(tokio::spawn(
            async move { rewrap_key(&state, request).await },
        ));
    }
    provider.paused.store(false, Ordering::SeqCst);
    provider.release.add_permits(5);
    let original = first.await.unwrap().unwrap();
    for retry in retries {
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), retry)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(keyrack_core::creation::same_json(&original, &result).unwrap());
    }
    assert_eq!(
        provider.rewraps.load(Ordering::SeqCst),
        1,
        "same-process retries must not duplicate provider dispatch"
    );
}

#[tokio::test]
async fn independently_prepared_same_operation_keeps_the_first_reserved_intent() {
    let (state, provider, child, _, new) = fixture().await;
    let operation = Uuid::new_v4();
    let first = prepare_migration(&state, child.lid, Some(new.lid), operation)
        .await
        .unwrap();
    let second = prepare_migration(&state, child.lid, Some(new.lid), operation)
        .await
        .unwrap();
    let committed = rewrap_key(&state, first).await.unwrap();
    let retried = rewrap_key(&state, second)
        .await
        .expect("same client intent prepared before reservation is idempotent");
    assert!(keyrack_core::creation::same_json(&committed, &retried).unwrap());
    assert_eq!(provider.rewraps.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn archived_creation_replay_cannot_restore_old_parent_in_the_cache() {
    let provider = Arc::new(ObservedProvider::new());
    let storage = Arc::new(keyrack_service::cache::CachingStorage::new(
        Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap()),
        100,
        std::time::Duration::from_secs(3600),
    ));
    let state = service_state(storage, provider);
    let old = domain::create_key(&state, input(None)).await.unwrap();
    let new = domain::create_key(&state, input(None)).await.unwrap();
    let child = domain::create_key(&state, input(Some(&old))).await.unwrap();
    let ciphertexts = ciphertexts(&state, &child).await;
    let operation = material(child.primary_version().unwrap())
        .wrapped_material_ref()
        .as_str()
        .strip_prefix("creation:")
        .unwrap()
        .parse()
        .unwrap();
    let creation = state.storage.get_creation(operation).await.unwrap();
    let migration = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    rewrap_key(&state, migration).await.unwrap();
    assert_eq!(
        state.storage.get_key(&child.lid).await.unwrap().parent_lid,
        Some(new.lid)
    );

    // Publication retry returns its historical response, but it must not make
    // that response the authoritative cache entry after migration retired it.
    let historical = state
        .storage
        .publish_creation(operation, creation.request.owner, creation.revision)
        .await
        .unwrap();
    assert_eq!(historical.parent_lid, Some(old.lid));
    let current = state.storage.get_key(&child.lid).await.unwrap();
    assert_eq!(
        current.parent_lid,
        Some(new.lid),
        "archived publication poisoned the current cache entry"
    );
    assert_decrypts(&state, &current, &ciphertexts).await;
    assert!(state
        .storage
        .read_creation_envelope(operation)
        .await
        .is_err());
}

async fn destroy_resident_parent(state: &Arc<ServiceState>, parent: &KeyRecord) {
    let mut due = state.storage.get_key_for_use(&parent.lid).await.unwrap();
    due.transition_to(KeyState::PendingDeletion).unwrap();
    due.scheduled_deletion_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    state.storage.update_key(&due).await.unwrap();
    let claim = state
        .storage
        .claim_destruction(&due.lid, due.occ_version, chrono::Utc::now())
        .await
        .unwrap()
        .expect("all old envelope dependencies retired");
    let provider = state
        .providers
        .resolve(&ProviderRef::new("default"))
        .unwrap()
        .provider;
    for version in &claim.record().key_versions {
        provider
            .destroy_key(version.resident_handle().unwrap())
            .await
            .unwrap();
    }
    state.storage.complete_destruction(claim).await.unwrap();
}

async fn wait_for_reads(reads: &AtomicUsize, minimum: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while reads.load(Ordering::SeqCst) < minimum {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retained versions remain readable while phase is held");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_versions_decrypt_continuously_in_reserve_stage_commit_and_after_erasure() {
    let (state, provider, child, old, new) = fixture().await;
    let child = append_version(&state, &child, &old).await;
    let child = append_version(&state, &child, &old).await;
    let ciphertexts = ciphertexts(&state, &child).await;
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    let reserved = state.storage.reserve_migration(&request).await.unwrap();
    let ownership = state
        .storage
        .claim_migration(request.operation, Uuid::new_v4(), reserved.epoch)
        .await
        .unwrap()
        .ownership()
        .unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let stopped = Arc::new(AtomicBool::new(false));
    let reader = tokio::spawn({
        let state = state.clone();
        let child = child.clone();
        let ciphertexts = ciphertexts.clone();
        let reads = reads.clone();
        let stopped = stopped.clone();
        async move {
            while !stopped.load(Ordering::SeqCst) {
                // Deliberately retain the original descriptor throughout commit.
                assert_decrypts(&state, &child, &ciphertexts).await;
                reads.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
            }
        }
    });
    wait_for_reads(&reads, 8).await;
    state
        .storage
        .begin_migration_dispatch(request.operation, ownership, true)
        .await
        .unwrap();
    let replacement = envelopes(&state, &request).await;
    state
        .storage
        .stage_migration(request.operation, ownership, &replacement)
        .await
        .unwrap();
    let before = reads.load(Ordering::SeqCst);
    wait_for_reads(&reads, before + 8).await;
    state
        .storage
        .commit_migration(request.operation, ownership)
        .await
        .unwrap();
    destroy_resident_parent(&state, &old).await;
    let before = reads.load(Ordering::SeqCst);
    wait_for_reads(&reads, before + 8).await;
    stopped.store(true, Ordering::SeqCst);
    reader
        .await
        .expect("no read failed across publication or erasure");
    assert!(provider.decrypts.load(Ordering::SeqCst) >= 24 * 3);
    assert_decrypts(&state, &child, &ciphertexts).await;
    for version in &child.key_versions {
        assert!(read_envelope(&state, version).await.is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reader_paused_before_open_survives_commit_and_parent_destruction_on_both_paths() {
    for two_key in [false, true] {
        let (state, provider, child, old, new) = fixture().await;
        let ciphertexts = ciphertexts(&state, &child).await;
        provider.open_paused.store(true, Ordering::SeqCst);
        let before = provider.decrypts.load(Ordering::SeqCst);
        let reader = tokio::spawn({
            let state = state.clone();
            let child = child.clone();
            let ciphertext = ciphertexts[0].clone();
            async move {
                let crypto = state
                    .providers
                    .resolve(&ProviderRef::new("default"))
                    .unwrap()
                    .provider;
                let decrypt_provider = crypto.clone();
                let version = child.primary_version().unwrap();
                if two_key {
                    domain::with_usable_handles(
                        &state,
                        domain::VersionUse {
                            record: &child,
                            version,
                            provider: &crypto,
                        },
                        domain::VersionUse {
                            record: &child,
                            version,
                            provider: &crypto,
                        },
                        |handle| async move {
                            decrypt_provider
                                .decrypt(&handle, &ciphertext, b"aad")
                                .await
                                .map_err(DomainError::from)
                        },
                        |_handle, plaintext| async move { Ok(plaintext.expose().clone()) },
                    )
                    .await
                } else {
                    domain::with_usable_handle(
                        &state,
                        &child,
                        version,
                        &crypto,
                        |handle| async move {
                            decrypt_provider
                                .decrypt(&handle, &ciphertext, b"aad")
                                .await
                                .map(|v| v.expose().clone())
                                .map_err(DomainError::from)
                        },
                    )
                    .await
                }
            }
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            provider.open_entered.acquire(),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();
        let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
            .await
            .unwrap();
        rewrap_key(&state, request).await.unwrap();
        destroy_resident_parent(&state, &old).await;
        provider.open_release.add_permits(1);
        assert_eq!(reader.await.unwrap().unwrap(), b"original payload");
        assert_eq!(
            provider.decrypts.load(Ordering::SeqCst) - before,
            1,
            "the caller crypto operation must never be replayed"
        );
    }
}

#[tokio::test]
async fn restoring_pre_migration_database_after_parent_destruction_fails_explicitly() {
    let path = std::env::temp_dir().join(format!("keyrack-restore-{}.sqlite", Uuid::new_v4()));
    let backup = path.with_extension("backup.sqlite");
    let provider = Arc::new(ObservedProvider::new());
    let state = service_state(
        Arc::new(keyrack_sqlite::SqliteStorage::open(&path).unwrap()),
        provider.clone(),
    );
    let old = domain::create_key(&state, input(None)).await.unwrap();
    let new = domain::create_key(&state, input(None)).await.unwrap();
    let child = domain::create_key(&state, input(Some(&old))).await.unwrap();
    let child = append_version(&state, &child, &old).await;
    let ciphertexts = ciphertexts(&state, &child).await;
    drop(state);
    std::fs::copy(&path, &backup).unwrap();
    let state = service_state(
        Arc::new(keyrack_sqlite::SqliteStorage::open(&path).unwrap()),
        provider.clone(),
    );
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    rewrap_key(&state, request).await.unwrap();
    destroy_resident_parent(&state, &old).await;
    assert_decrypts(&state, &child, &ciphertexts).await;
    drop(state);
    // Restore only the database. The provider is deliberately retained, so its
    // completed destruction survives restore just as an external backend would.
    let restored = service_state(
        Arc::new(keyrack_sqlite::SqliteStorage::open(&backup).unwrap()),
        provider,
    );
    for (version, ciphertext) in child.key_versions.iter().zip(&ciphertexts) {
        let crypto = restored
            .providers
            .resolve(&ProviderRef::new("default"))
            .unwrap()
            .provider;
        let decrypt = crypto.clone();
        let error =
            domain::with_usable_handle(&restored, &child, version, &crypto, |handle| async move {
                decrypt
                    .decrypt(&handle, ciphertext, b"aad")
                    .await
                    .map_err(DomainError::from)
            })
            .await
            .unwrap_err();
        assert!(
            matches!(&error, DomainError::FailedPrecondition(message) if message == "wrapping parent destroyed"),
            "unexpected restore result: {error:?}"
        );
    }
    drop(restored);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_file(backup).unwrap();
}

#[tokio::test]
async fn unknown_nonrepeatable_provider_outcome_retains_reservation_without_redispatch() {
    let (state, provider, child, _old, new) = fixture().await;
    let ciphertexts = ciphertexts(&state, &child).await;
    provider.retry_safe.store(false, Ordering::SeqCst);
    provider.fail_at_call.store(1, Ordering::SeqCst);
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    assert!(rewrap_key(&state, request.clone()).await.is_err());
    assert_eq!(provider.rewraps.load(Ordering::SeqCst), 1);
    assert_decrypts(&state, &child, &ciphertexts).await;
    assert!(rewrap_key(&state, request.clone()).await.is_err());
    assert_eq!(
        provider.rewraps.load(Ordering::SeqCst),
        1,
        "unknown native effect must not be repeated blindly"
    );
    assert_eq!(
        state
            .storage
            .get_migration(request.operation)
            .await
            .unwrap()
            .unwrap()
            .phase,
        MigrationPhase::Reserved
    );
    assert!(matches!(
        state
            .storage
            .check_migration_fence(&request.old_parent.lid)
            .await,
        Err(KeyRackError::ProviderUnavailable(_))
    ));
}

#[tokio::test]
async fn partial_repeatable_provider_failure_preserves_every_reader_until_recovery() {
    let (state, provider, child, old, new) = fixture().await;
    let child = append_version(&state, &child, &old).await;
    let child = append_version(&state, &child, &old).await;
    let ciphertexts = ciphertexts(&state, &child).await;
    provider.fail_at_call.store(2, Ordering::SeqCst);
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    assert!(rewrap_key(&state, request.clone()).await.is_err());
    assert_eq!(provider.rewraps.load(Ordering::SeqCst), 2);
    assert_eq!(
        state
            .storage
            .get_key_for_use(&child.lid)
            .await
            .unwrap()
            .parent_lid,
        Some(old.lid)
    );
    assert_decrypts(&state, &child, &ciphertexts).await;
    provider.fail_at_call.store(0, Ordering::SeqCst);
    let committed = rewrap_key(&state, request).await.unwrap();
    assert_eq!(provider.rewraps.load(Ordering::SeqCst), 5);
    assert_decrypts(&state, &committed, &ciphertexts).await;
}

#[tokio::test]
async fn metadata_and_lifecycle_updates_are_fenced_but_aliases_are_safe_during_migration() {
    for staged in [false, true] {
        let (state, _provider, child, old, new) = fixture().await;
        let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
            .await
            .unwrap();
        let reserved = state.storage.reserve_migration(&request).await.unwrap();
        let ownership = state
            .storage
            .claim_migration(request.operation, Uuid::new_v4(), reserved.epoch)
            .await
            .unwrap()
            .ownership()
            .unwrap();
        if staged {
            state
                .storage
                .begin_migration_dispatch(request.operation, ownership, true)
                .await
                .unwrap();
            let replacement = envelopes(&state, &request).await;
            state
                .storage
                .stage_migration(request.operation, ownership, &replacement)
                .await
                .unwrap();
        }
        for record in [&child, &old, &new] {
            let mut metadata = record.clone();
            metadata.description = "ordinary update while migration pending".into();
            metadata.occ_version += 1;
            assert!(matches!(
                state.storage.update_key(&metadata).await,
                Err(KeyRackError::ProviderUnavailable(_))
            ));
            let key_id = record.lid.to_string();
            assert!(matches!(
                domain::enable_key(&state, &key_id).await,
                Err(DomainError::ProviderUnavailable(_))
            ));
            assert!(matches!(
                domain::disable_key(&state, &record.lid, &key_id).await,
                Err(KeyRackError::ProviderUnavailable(_))
            ));
            let scheduling_error = domain::schedule_key_deletion(&state, &key_id, 7)
                .await
                .unwrap_err();
            assert!(
                matches!(&scheduling_error, DomainError::FailedPrecondition(message)
                    if message.contains("migration_journal_rows=1")),
                "scheduling must report the shared migration dependency for {key_id}, staged={staged}: {scheduling_error}"
            );
            assert!(keyrack_core::creation::same_json(
                record,
                &state.storage.get_key(&record.lid).await.unwrap()
            )
            .unwrap());
            assert!(matches!(
                domain::cancel_key_deletion(&state, &key_id).await,
                Err(DomainError::ProviderUnavailable(_))
            ));
        }
        let alias_name = format!("alias/migration-{}", Uuid::new_v4());
        let mut alias = keyrack_core::storage::AliasRecord {
            alias_name: alias_name.clone(),
            target_lid: child.lid,
            created_at: chrono::Utc::now(),
        };
        state.storage.create_alias(&alias).await.unwrap();
        assert_eq!(
            state.storage.resolve_alias(&alias_name).await.unwrap(),
            child.lid
        );
        state.storage.delete_alias(&alias_name).await.unwrap();
        alias.target_lid = new.lid;
        state.storage.create_alias(&alias).await.unwrap();
        assert_eq!(
            state.storage.resolve_alias(&alias_name).await.unwrap(),
            new.lid
        );
        let pending = state
            .storage
            .get_migration(request.operation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.request.child.lid, child.lid,
            "alias retargeting cannot change a LID-addressed migration"
        );
        let result = rewrap_key(&state, request).await.unwrap();
        assert_eq!(result.lid, child.lid);
        assert_eq!(
            state.storage.resolve_alias(&alias_name).await.unwrap(),
            new.lid
        );
    }
}
