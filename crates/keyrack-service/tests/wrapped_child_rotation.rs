// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wrapped-child rotation through domain, gRPC, and REST with migration fences.

use async_trait::async_trait;
use axum::body::Body;
use keyrack_core::audit::{AuditAction, AuditSink};
use keyrack_core::creation::CreationRequest;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::hsm::HsmConnection;
use keyrack_core::key::{
    Exportability, KeyMaterial, KeyRecord, KeySpec, KeyState, KeyVersionRecord, ProviderClass,
    ProviderRef,
};
use keyrack_core::lid::Lid;
use keyrack_core::material::ParentWrappedMaterial;
use keyrack_core::migration::MigrationRequest;
use keyrack_core::pdp::{AlwaysAllow, AuthzRequest, AuthzResponse, Decision, PolicyDecisionPoint};
use keyrack_core::provider::software::{SoftwareProvider, SOFTWARE_WRAPPING_MECHANISM};
use keyrack_core::provider::{
    CryptoProvider, EncryptOutput, GeneratedWrappedKey, KeyHandle, ProviderCapabilities,
    SigningAlgorithm, WrappedKeyClosure, WrappedKeyLease,
};
use keyrack_core::registry::{ProviderEntry, StaticProviderRegistry};
use keyrack_core::rotation::{RotationJob, RotationJobState};
use keyrack_core::sensitive::Sensitive;
use keyrack_core::storage::{AliasRecord, KeyFilter, Page, StorageBackend};
use keyrack_core::wrapping::{WrappingCapabilities, WrappingContext, WrappingIdentifier};
use keyrack_service::domain::{self, CreateKeyInput, DomainError};
use keyrack_service::hierarchy::{WrappingProfile, WrappingProfiles};
use keyrack_service::migration::{prepare_migration, rewrap_key};
use keyrack_service::proto::{self, key_service_server::KeyService};
use keyrack_service::routing::ProviderRouter;
use keyrack_service::state::ServiceState;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use tonic::Request;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "wrapped-child-rotation";

fn name(value: &str) -> WrappingIdentifier {
    WrappingIdentifier::new(value).unwrap()
}

struct SilentAudit;

#[async_trait]
impl AuditSink for SilentAudit {
    async fn emit(&self, _: &keyrack_core::audit::AuditEvent) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct CaptureAudit(Mutex<Vec<keyrack_core::audit::AuditEvent>>);

#[async_trait]
impl AuditSink for CaptureAudit {
    async fn emit(&self, event: &keyrack_core::audit::AuditEvent) -> Result<()> {
        self.0.lock().unwrap().push(event.clone());
        Ok(())
    }
}

impl CaptureAudit {
    fn rotate_outcomes(&self, key_id: &str) -> Vec<keyrack_core::audit::AuditResult> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.action == AuditAction::RotateKey && event.resource.id == key_id)
            .map(|event| event.result)
            .collect()
    }
}

struct DenyRotatePdp;

#[async_trait]
impl PolicyDecisionPoint for DenyRotatePdp {
    async fn evaluate(&self, request: &AuthzRequest) -> Result<AuthzResponse> {
        let mut response = AlwaysAllow.evaluate(request).await?;
        if request.action == AuditAction::RotateKey {
            response.decision = Decision::Forbid;
        }
        Ok(response)
    }
}

/// Pauses inside provider work; counts wrapped-key generation.
struct ObservedProvider {
    inner: SoftwareProvider,
    generates: AtomicUsize,
    paused: AtomicBool,
    entered: Semaphore,
    release: Semaphore,
}

impl ObservedProvider {
    fn new() -> Self {
        Self {
            inner: SoftwareProvider::scoped(ProviderRef::new("default"), name(DOMAIN)),
            generates: AtomicUsize::new(0),
            paused: AtomicBool::new(false),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }

    async fn wait_entered(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(5), self.entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
    }

    fn release_blocked(&self, count: usize) {
        self.paused.store(false, Ordering::SeqCst);
        self.release.add_permits(count);
    }
}

#[async_trait]
impl CryptoProvider for ObservedProvider {
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
        self.generates.fetch_add(1, Ordering::SeqCst);
        if self.paused.load(Ordering::SeqCst) {
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
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
    provider: Arc<ObservedProvider>,
    pdp: Arc<dyn PolicyDecisionPoint>,
) -> Arc<ServiceState> {
    service_state_audited(storage, provider, pdp, Arc::new(SilentAudit))
}

fn service_state_audited(
    storage: Arc<dyn StorageBackend>,
    provider: Arc<ObservedProvider>,
    pdp: Arc<dyn PolicyDecisionPoint>,
    audit: Arc<dyn AuditSink>,
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
        pdp,
        audit,
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

fn service_state_no_wrapping(
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
        pdp: Arc::new(AlwaysAllow),
        audit: Arc::new(SilentAudit),
        authn: Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
            Box::new(keyrack_core::authn::InsecureAuthenticator),
        ])),
        metrics_handle: recorder.handle(),
        max_plaintext_bytes: 4096,
        legacy_compromised_key_decrypt: false,
        nats_publisher: None,
        lease_cleanup: keyrack_service::lease::LeaseCleanup::default(),
        wrapping: WrappingProfiles::new([]),
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
) {
    let provider = Arc::new(ObservedProvider::new());
    let state = service_state(
        Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap()),
        provider.clone(),
        Arc::new(AlwaysAllow),
    );
    let parent = domain::create_key(&state, input(None)).await.unwrap();
    let child = domain::create_key(&state, input(Some(&parent)))
        .await
        .unwrap();
    (state, provider, child, parent)
}

fn material(version: &KeyVersionRecord) -> &ParentWrappedMaterial {
    let KeyMaterial::ParentWrapped(material) = &version.material else {
        panic!("wrapped version")
    };
    material
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

async fn assert_no_pending_creation(state: &Arc<ServiceState>, child: &Lid) {
    assert!(
        state
            .storage
            .pending_creations(child)
            .await
            .unwrap()
            .is_empty(),
        "unexpected pending creation journal for {child}"
    );
}

fn assert_retryable_domain(error: &DomainError) {
    assert!(
        matches!(error, DomainError::ProviderUnavailable(_)),
        "expected retryable refusal, got {error}"
    );
}

fn assert_same_key_snapshot(stored: &KeyRecord, expected: &KeyRecord) {
    assert_eq!(stored.lid, expected.lid);
    assert_eq!(stored.occ_version, expected.occ_version);
    assert_eq!(stored.current_key_version, expected.current_key_version);
    assert_eq!(stored.key_versions.len(), expected.key_versions.len());
}

fn assert_v1_unchanged(rotated: &KeyRecord, v1: &KeyVersionRecord) {
    let stored = &rotated.key_versions[0];
    assert_eq!(stored.version_number, v1.version_number);
    assert_eq!(
        material(stored).wrapped_material_ref(),
        material(v1).wrapped_material_ref()
    );
    assert_eq!(material(stored).parent(), material(v1).parent());
}

fn expect_rotate_err(
    result: std::result::Result<domain::RotateKeyResult, DomainError>,
) -> DomainError {
    match result {
        Err(error) => error,
        Ok(outcome) => panic!(
            "expected rotation refusal, got version {}",
            outcome.new_version
        ),
    }
}

async fn rotate_grpc(state: &Arc<ServiceState>, key_id: &str) -> (tonic::Code, u32) {
    let response = keyrack_service::grpc::KeyServiceImpl::new(state.clone())
        .rotate_key(Request::new(proto::RotateKeyRequest {
            key_id: key_id.into(),
        }))
        .await;
    match response {
        Ok(ok) => {
            let inner = ok.into_inner();
            (tonic::Code::Ok, inner.new_version)
        }
        Err(status) => (status.code(), 0),
    }
}

async fn rotate_rest(state: &Arc<ServiceState>, key_id: &str) -> (u16, u64) {
    let (code, body) = rotate_rest_body(state, key_id).await;
    let version = if code == 200 {
        body["current_key_version"].as_u64().unwrap()
    } else {
        0
    };
    (code, version)
}

async fn rotate_rest_body(state: &Arc<ServiceState>, key_id: &str) -> (u16, serde_json::Value) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/keys/{key_id}/actions-rotate"))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let response = keyrack_service::rest::router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    let code = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    (code, serde_json::from_slice(&bytes).unwrap())
}

struct InterleaveHook {
    child: Mutex<Option<Lid>>,
    armed: AtomicBool,
    once: AtomicBool,
    reserve_only: AtomicBool,
    stale_every_reservation: AtomicBool,
    stale_reservations: AtomicUsize,
    migration: Mutex<Option<(Arc<ServiceState>, MigrationRequest)>>,
}

struct HookedStorage {
    inner: Arc<keyrack_sqlite::SqliteStorage>,
    hook: Arc<InterleaveHook>,
}

impl HookedStorage {
    fn new(inner: Arc<keyrack_sqlite::SqliteStorage>) -> Self {
        Self {
            inner,
            hook: Arc::new(InterleaveHook {
                child: Mutex::new(None),
                armed: AtomicBool::new(false),
                once: AtomicBool::new(false),
                reserve_only: AtomicBool::new(false),
                stale_every_reservation: AtomicBool::new(false),
                stale_reservations: AtomicUsize::new(0),
                migration: Mutex::new(None),
            }),
        }
    }

    fn watch_child(&self, lid: Lid) {
        *self.hook.child.lock().unwrap() = Some(lid);
    }

    fn interleave_migration(&self, state: Arc<ServiceState>, request: MigrationRequest) {
        *self.hook.migration.lock().unwrap() = Some((state, request));
    }

    fn interleave_reservation(&self, state: Arc<ServiceState>, request: MigrationRequest) {
        self.hook.reserve_only.store(true, Ordering::SeqCst);
        self.interleave_migration(state, request);
    }

    fn arm_interleave(&self) {
        self.hook.armed.store(true, Ordering::SeqCst);
    }

    /// Change the watched child's parent after each of its reservations, so
    /// every attempt's snapshot is stale by the time it publishes.
    fn stale_every_reservation(&self) {
        self.hook
            .stale_every_reservation
            .store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl StorageBackend for HookedStorage {
    async fn get_key_for_use(&self, lid: &Lid) -> Result<KeyRecord> {
        self.inner.get_key_for_use(lid).await
    }
    async fn reserve_creation(
        &self,
        request: &CreationRequest,
    ) -> Result<keyrack_core::creation::CreationJournal> {
        let watched = *self.hook.child.lock().unwrap();
        if self.hook.armed.load(Ordering::SeqCst)
            && watched == Some(request.record.lid)
            && self
                .hook
                .once
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            let migration = self.hook.migration.lock().unwrap().take();
            if let Some((state, migration)) = migration {
                if self.hook.reserve_only.load(Ordering::SeqCst) {
                    self.inner.reserve_migration(&migration).await?;
                } else {
                    rewrap_key(&state, migration)
                        .await
                        .map_err(|error| KeyRackError::Other(error.to_string()))?;
                }
            }
        }
        let journal = self.inner.reserve_creation(request).await?;
        if self.hook.stale_every_reservation.load(Ordering::SeqCst)
            && watched == Some(request.record.lid)
        {
            let mut parent = self
                .inner
                .get_key(
                    &request
                        .record
                        .parent_lid
                        .expect("wrapped child names a parent"),
                )
                .await?;
            parent.occ_version += 1;
            parent.updated_at = chrono::Utc::now();
            self.inner.update_key(&parent).await?;
            self.hook.stale_reservations.fetch_add(1, Ordering::SeqCst);
        }
        Ok(journal)
    }
    async fn get_creation(
        &self,
        operation: uuid::Uuid,
    ) -> Result<keyrack_core::creation::CreationJournal> {
        self.inner.get_creation(operation).await
    }
    async fn claim_creation_dispatch(
        &self,
        operation: uuid::Uuid,
        owner: keyrack_core::creation::CreationOwner,
    ) -> Result<keyrack_core::creation::CreationDispatch> {
        self.inner.claim_creation_dispatch(operation, owner).await
    }
    async fn creation_snapshot(
        &self,
        operation: uuid::Uuid,
        owner: keyrack_core::creation::CreationOwner,
    ) -> Result<keyrack_core::creation::CreationSnapshot> {
        self.inner.creation_snapshot(operation, owner).await
    }
    async fn stage_creation(
        &self,
        operation: uuid::Uuid,
        owner: keyrack_core::creation::CreationOwner,
        revision: u64,
        envelope: &[u8],
    ) -> Result<keyrack_core::creation::CreationJournal> {
        self.inner
            .stage_creation(operation, owner, revision, envelope)
            .await
    }
    async fn resolve_creation(
        &self,
        operation: uuid::Uuid,
        owner: keyrack_core::creation::CreationOwner,
        revision: u64,
        closure: &keyrack_core::creation::VerifiedA2Closure,
    ) -> Result<keyrack_core::creation::CreationJournal> {
        self.inner
            .resolve_creation(operation, owner, revision, closure)
            .await
    }
    async fn publish_creation(
        &self,
        operation: uuid::Uuid,
        owner: keyrack_core::creation::CreationOwner,
        revision: u64,
    ) -> Result<KeyRecord> {
        self.inner
            .publish_creation(operation, owner, revision)
            .await
    }
    async fn read_creation_envelope(&self, operation: uuid::Uuid) -> Result<Vec<u8>> {
        self.inner.read_creation_envelope(operation).await
    }
    async fn recoverable_creations(
        &self,
        after: Option<uuid::Uuid>,
        limit: u32,
    ) -> Result<keyrack_core::creation::CreationPage> {
        self.inner.recoverable_creations(after, limit).await
    }
    async fn withdraw_creation(&self, operation: uuid::Uuid) -> Result<()> {
        self.inner.withdraw_creation(operation).await
    }
    async fn reserve_migration(
        &self,
        request: &MigrationRequest,
    ) -> Result<keyrack_core::migration::MigrationJournal> {
        self.inner.reserve_migration(request).await
    }
    async fn get_migration(
        &self,
        operation: uuid::Uuid,
    ) -> Result<Option<keyrack_core::migration::MigrationJournal>> {
        self.inner.get_migration(operation).await
    }
    async fn claim_migration(
        &self,
        operation: uuid::Uuid,
        owner: uuid::Uuid,
        expected_epoch: u64,
    ) -> Result<keyrack_core::migration::MigrationJournal> {
        self.inner
            .claim_migration(operation, owner, expected_epoch)
            .await
    }
    async fn begin_migration_dispatch(
        &self,
        operation: uuid::Uuid,
        ownership: keyrack_core::migration::MigrationOwnership,
        retry_safe: bool,
    ) -> Result<keyrack_core::migration::MigrationJournal> {
        self.inner
            .begin_migration_dispatch(operation, ownership, retry_safe)
            .await
    }
    async fn wrapped_key_snapshot(
        &self,
        lid: &Lid,
        version: u64,
    ) -> Result<keyrack_core::migration::WrappedKeySnapshot> {
        self.inner.wrapped_key_snapshot(lid, version).await
    }
    async fn stage_migration(
        &self,
        operation: uuid::Uuid,
        ownership: keyrack_core::migration::MigrationOwnership,
        envelopes: &[Vec<u8>],
    ) -> Result<keyrack_core::migration::MigrationJournal> {
        self.inner
            .stage_migration(operation, ownership, envelopes)
            .await
    }
    async fn commit_migration(
        &self,
        operation: uuid::Uuid,
        ownership: keyrack_core::migration::MigrationOwnership,
    ) -> Result<KeyRecord> {
        self.inner.commit_migration(operation, ownership).await
    }
    async fn read_migration_envelope(
        &self,
        operation: uuid::Uuid,
        version: u64,
    ) -> Result<Vec<u8>> {
        self.inner.read_migration_envelope(operation, version).await
    }
    async fn check_migration_fence(&self, lid: &Lid) -> Result<()> {
        self.inner.check_migration_fence(lid).await
    }
    async fn claim_destruction(
        &self,
        lid: &Lid,
        expected_occ: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<keyrack_core::destruction::DestructionClaim>> {
        self.inner.claim_destruction(lid, expected_occ, now).await
    }
    async fn complete_destruction(
        &self,
        claim: keyrack_core::destruction::DestructionClaim,
    ) -> Result<KeyRecord> {
        self.inner.complete_destruction(claim).await
    }
    async fn create_key(&self, record: &KeyRecord) -> Result<()> {
        self.inner.create_key(record).await
    }
    async fn get_key(&self, lid: &Lid) -> Result<KeyRecord> {
        self.inner.get_key(lid).await
    }
    async fn update_key(&self, record: &KeyRecord) -> Result<()> {
        self.inner.update_key(record).await
    }
    async fn list_keys(&self, filter: &KeyFilter) -> Result<Page<KeyRecord>> {
        self.inner.list_keys(filter).await
    }
    async fn list_children(&self, parent: &Lid) -> Result<Vec<KeyRecord>> {
        self.inner.list_children(parent).await
    }
    async fn create_alias(&self, alias: &AliasRecord) -> Result<()> {
        self.inner.create_alias(alias).await
    }
    async fn resolve_alias(&self, alias_name: &str) -> Result<Lid> {
        self.inner.resolve_alias(alias_name).await
    }
    async fn delete_alias(&self, alias_name: &str) -> Result<()> {
        self.inner.delete_alias(alias_name).await
    }
    async fn list_aliases(&self) -> Result<Vec<AliasRecord>> {
        self.inner.list_aliases().await
    }
    async fn create_hsm_connection(&self, conn: &HsmConnection) -> Result<()> {
        self.inner.create_hsm_connection(conn).await
    }
    async fn get_hsm_connection(&self, connection_id: &str) -> Result<HsmConnection> {
        self.inner.get_hsm_connection(connection_id).await
    }
    async fn update_hsm_connection(&self, conn: &HsmConnection) -> Result<()> {
        self.inner.update_hsm_connection(conn).await
    }
    async fn list_hsm_connections(&self) -> Result<Vec<HsmConnection>> {
        self.inner.list_hsm_connections().await
    }
    async fn delete_hsm_connection(&self, connection_id: &str) -> Result<()> {
        self.inner.delete_hsm_connection(connection_id).await
    }
    async fn create_rotation_job(&self, job: &RotationJob) -> Result<()> {
        self.inner.create_rotation_job(job).await
    }
    async fn get_rotation_job(&self, job_id: &str) -> Result<RotationJob> {
        self.inner.get_rotation_job(job_id).await
    }
    async fn update_rotation_job(&self, job: &RotationJob) -> Result<()> {
        self.inner.update_rotation_job(job).await
    }
    async fn list_rotation_jobs(
        &self,
        state_filter: Option<RotationJobState>,
    ) -> Result<Vec<RotationJob>> {
        self.inner.list_rotation_jobs(state_filter).await
    }
    async fn ping(&self) -> Result<()> {
        self.inner.ping().await
    }
}

#[tokio::test]
async fn grpc_wrapped_child_rotation_preserves_v1_and_names_parent_version() {
    let (state, _, child, parent) = fixture().await;
    let v1 = child.key_versions[0].clone();
    let ciphertexts = ciphertexts(&state, &child).await;

    let (code, new_version) = rotate_grpc(&state, &child.lid.to_string()).await;
    assert_eq!(code, tonic::Code::Ok);
    assert_eq!(new_version, 2);

    let rotated = state.storage.get_key(&child.lid).await.unwrap();
    assert_eq!(rotated.key_versions.len(), 2);
    assert_v1_unchanged(&rotated, &v1);
    let primary = rotated.primary_version().unwrap();
    assert_eq!(primary.version_number, 2);
    assert_eq!(
        material(primary).parent().version.get(),
        parent.current_key_version
    );
    assert_decrypts(&state, &rotated, &ciphertexts).await;
}

#[tokio::test]
async fn rest_wrapped_child_rotation_preserves_v1_and_names_parent_version() {
    let (state, _, child, parent) = fixture().await;
    let v1 = child.key_versions[0].clone();
    let ciphertexts = ciphertexts(&state, &child).await;

    let (code, new_version) = rotate_rest(&state, &child.lid.to_string()).await;
    assert_eq!(code, 200);
    assert_eq!(new_version, 2);

    let rotated = state.storage.get_key(&child.lid).await.unwrap();
    assert_eq!(rotated.key_versions.len(), 2);
    assert_v1_unchanged(&rotated, &v1);
    let primary = rotated.primary_version().unwrap();
    assert_eq!(primary.version_number, 2);
    assert_eq!(
        material(primary).parent().version.get(),
        parent.current_key_version
    );
    assert_decrypts(&state, &rotated, &ciphertexts).await;
}

#[tokio::test]
async fn parent_rotation_queues_job_without_rewrapping_child_then_child_rotation_uses_new_parent_version(
) {
    let (state, _, child, parent) = fixture().await;
    let before = child.clone();

    domain::rotate_key(&state, &parent.lid, &parent.lid.to_string())
        .await
        .unwrap();
    let parent = state.storage.get_key(&parent.lid).await.unwrap();
    assert_eq!(parent.current_key_version, 2);

    let jobs = state
        .storage
        .list_rotation_jobs(Some(RotationJobState::Pending))
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].parent_lid, parent.lid);
    assert_eq!(jobs[0].dependent_lid, child.lid);
    assert_eq!(jobs[0].new_version, 2);

    let unchanged = state.storage.get_key(&child.lid).await.unwrap();
    assert_eq!(unchanged.key_versions.len(), before.key_versions.len());
    assert_eq!(unchanged.current_key_version, before.current_key_version);

    let outcome = domain::rotate_key(&state, &child.lid, &child.lid.to_string())
        .await
        .unwrap();
    assert_eq!(outcome.new_version, 2);
    let primary = outcome.record.primary_version().unwrap();
    assert_eq!(
        material(primary).parent().version.get(),
        parent.current_key_version
    );

    domain::acknowledge_rotation_job(&state, &jobs[0].job_id)
        .await
        .unwrap();
    domain::complete_rotation_job(&state, &jobs[0].job_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn grpc_and_rest_deny_rotate_key_before_side_effects() {
    for rest in [false, true] {
        let provider = Arc::new(ObservedProvider::new());
        let state = service_state(
            Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap()),
            provider.clone(),
            Arc::new(DenyRotatePdp),
        );
        let parent = domain::create_key(&state, input(None)).await.unwrap();
        let child = domain::create_key(&state, input(Some(&parent)))
            .await
            .unwrap();
        let before = state.storage.get_key(&child.lid).await.unwrap();

        if rest {
            let (code, _) = rotate_rest(&state, &child.lid.to_string()).await;
            assert_eq!(code, 403);
        } else {
            let (code, _) = rotate_grpc(&state, &child.lid.to_string()).await;
            assert_eq!(code, tonic::Code::PermissionDenied);
        }

        let after = state.storage.get_key(&child.lid).await.unwrap();
        assert_same_key_snapshot(&after, &before);
        assert_no_pending_creation(&state, &child.lid).await;
    }
}

#[tokio::test]
async fn wrapped_child_rotation_refuses_ineligible_keys_and_mixed_history() {
    let (state, _, child, _parent) = fixture().await;
    let key_id = child.lid.to_string();

    let mut disabled = state.storage.get_key(&child.lid).await.unwrap();
    disabled.transition_to(KeyState::Disabled).unwrap();
    state.storage.update_key(&disabled).await.unwrap();
    let error = expect_rotate_err(domain::rotate_key(&state, &child.lid, &key_id).await);
    assert!(matches!(error, DomainError::FailedPrecondition(_)));
    assert_no_pending_creation(&state, &child.lid).await;

    let (state, _, child, _parent) = fixture().await;
    let mut compromised = state.storage.get_key(&child.lid).await.unwrap();
    compromised.transition_to(KeyState::Compromised).unwrap();
    state.storage.update_key(&compromised).await.unwrap();
    let error = expect_rotate_err(domain::rotate_key(&state, &child.lid, &key_id).await);
    assert!(matches!(error, DomainError::FailedPrecondition(_)));
    assert_no_pending_creation(&state, &child.lid).await;

    for parent_state in [KeyState::Disabled, KeyState::Compromised] {
        let (state, _, child, parent) = fixture().await;
        let mut parent = state.storage.get_key(&parent.lid).await.unwrap();
        parent.transition_to(parent_state).unwrap();
        state.storage.update_key(&parent).await.unwrap();
        let error =
            expect_rotate_err(domain::rotate_key(&state, &child.lid, &child.lid.to_string()).await);
        assert!(matches!(error, DomainError::FailedPrecondition(_)));
        assert_no_pending_creation(&state, &child.lid).await;
    }

    let (state, _, child, parent) = fixture().await;
    let mut parent_record = state.storage.get_key(&parent.lid).await.unwrap();
    parent_record
        .transition_to(KeyState::PendingDeletion)
        .unwrap();
    parent_record.scheduled_deletion_at = Some(chrono::Utc::now());
    state.storage.update_key(&parent_record).await.unwrap();
    let error =
        expect_rotate_err(domain::rotate_key(&state, &child.lid, &child.lid.to_string()).await);
    assert!(matches!(error, DomainError::FailedPrecondition(_)));
    assert_no_pending_creation(&state, &child.lid).await;

    // Everything but the history itself is rotatable: a resident first version
    // and a wrapped second one under an eligible parent with a profile.
    let (state, provider, child, parent) = fixture().await;
    let mut mixed = child.clone();
    mixed.lid = keyrack_test_support::fixtures::test_lid(&format!("mixed-{}", Uuid::new_v4()));
    let mut resident = parent.primary_version().unwrap().clone();
    resident.is_primary = false;
    let mut wrapped = child.primary_version().unwrap().clone();
    wrapped.version_number = 2;
    mixed.key_versions = vec![resident, wrapped];
    mixed.current_key_version = 2;
    state.storage.create_key(&mixed).await.unwrap();
    let generated = provider.generates.load(Ordering::SeqCst);
    let error =
        expect_rotate_err(domain::rotate_key(&state, &mixed.lid, &mixed.lid.to_string()).await);
    assert!(matches!(error, DomainError::FailedPrecondition(_)));
    assert_eq!(provider.generates.load(Ordering::SeqCst), generated);
    assert_same_key_snapshot(&state.storage.get_key(&mixed.lid).await.unwrap(), &mixed);
    assert_no_pending_creation(&state, &mixed.lid).await;

    let provider = Arc::new(ObservedProvider::new());
    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap());
    let child = {
        let state = service_state(storage.clone(), provider.clone(), Arc::new(AlwaysAllow));
        let parent = domain::create_key(&state, input(None)).await.unwrap();
        domain::create_key(&state, input(Some(&parent)))
            .await
            .unwrap()
    };
    let state = service_state_no_wrapping(storage, provider);
    let error =
        expect_rotate_err(domain::rotate_key(&state, &child.lid, &child.lid.to_string()).await);
    assert!(matches!(error, DomainError::FailedPrecondition(_)));
    assert_no_pending_creation(&state, &child.lid).await;
}

#[tokio::test]
async fn migration_reserved_first_refuses_child_rotation_retryably() {
    let (state, provider, child, _) = fixture().await;
    let new = domain::create_key(&state, input(None)).await.unwrap();
    let ciphertexts = ciphertexts(&state, &child).await;
    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    state.storage.reserve_migration(&request).await.unwrap();
    let generated = provider.generates.load(Ordering::SeqCst);

    let error =
        expect_rotate_err(domain::rotate_key(&state, &child.lid, &child.lid.to_string()).await);
    assert_retryable_domain(&error);
    assert_eq!(provider.generates.load(Ordering::SeqCst), generated);
    assert_same_key_snapshot(&state.storage.get_key(&child.lid).await.unwrap(), &child);
    assert_no_pending_creation(&state, &child.lid).await;

    rewrap_key(&state, request).await.unwrap();
    let rotated = domain::rotate_key(&state, &child.lid, &child.lid.to_string())
        .await
        .unwrap()
        .record;
    assert_every_version_under(&rotated, &new);
    assert_decrypts(&state, &rotated, &ciphertexts).await;
}

#[tokio::test]
async fn migration_reserved_after_rotation_check_refuses_before_provider() {
    let provider = Arc::new(ObservedProvider::new());
    let hooked = Arc::new(HookedStorage::new(Arc::new(
        keyrack_sqlite::SqliteStorage::in_memory().unwrap(),
    )));
    let state = service_state(hooked.clone(), provider.clone(), Arc::new(AlwaysAllow));
    let old = domain::create_key(&state, input(None)).await.unwrap();
    let new = domain::create_key(&state, input(None)).await.unwrap();
    let child = domain::create_key(&state, input(Some(&old))).await.unwrap();
    hooked.watch_child(child.lid);
    let migration = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    hooked.interleave_reservation(state.clone(), migration.clone());
    hooked.arm_interleave();
    let generated = provider.generates.load(Ordering::SeqCst);

    let error =
        expect_rotate_err(domain::rotate_key(&state, &child.lid, &child.lid.to_string()).await);
    assert!(hooked.hook.once.load(Ordering::SeqCst));
    assert!(matches!(error, DomainError::ProviderUnavailable(_)));
    assert_eq!(provider.generates.load(Ordering::SeqCst), generated);
    assert_same_key_snapshot(&state.storage.get_key(&child.lid).await.unwrap(), &child);
    assert_no_pending_creation(&state, &child.lid).await;

    let migrated = rewrap_key(&state, migration).await.unwrap();
    assert_every_version_under(&migrated, &new);
}

#[tokio::test]
async fn rotation_reserved_first_refuses_rewrap_until_rotation_commits() {
    let (state, provider, child, _) = fixture().await;
    let new = domain::create_key(&state, input(None)).await.unwrap();
    let ciphertexts = ciphertexts(&state, &child).await;

    provider.paused.store(true, Ordering::SeqCst);
    let rotation = tokio::spawn({
        let state = state.clone();
        let child = child.lid;
        async move { domain::rotate_key(&state, &child, &child.to_string()).await }
    });
    provider.wait_entered().await;

    let request = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    let migration_error = rewrap_key(&state, request.clone()).await.unwrap_err();
    assert_retryable_domain(&migration_error);

    provider.release_blocked(1);
    let outcome = rotation.await.unwrap().expect("child rotation task");
    assert_eq!(outcome.new_version, 2);
    let ciphertexts = [
        ciphertexts,
        self::ciphertexts(&state, &outcome.record).await[1..].to_vec(),
    ]
    .concat();

    let retry = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    let rewrapped = rewrap_key(&state, retry).await.unwrap();
    assert_eq!(rewrapped.key_versions.len(), 2);
    assert_every_version_under(&rewrapped, &new);
    assert_decrypts(&state, &rewrapped, &ciphertexts).await;
}

fn assert_every_version_under(child: &KeyRecord, parent: &KeyRecord) {
    assert_eq!(child.parent_lid, Some(parent.lid));
    for version in &child.key_versions {
        assert_eq!(material(version).parent().lid, parent.lid);
        assert_eq!(
            material(version).parent().version.get(),
            parent.current_key_version
        );
    }
}

#[tokio::test]
async fn migration_commit_before_rotation_reservation_wraps_under_new_parent() {
    let provider = Arc::new(ObservedProvider::new());
    let hooked = Arc::new(HookedStorage::new(Arc::new(
        keyrack_sqlite::SqliteStorage::in_memory().unwrap(),
    )));
    let state = service_state(hooked.clone(), provider.clone(), Arc::new(AlwaysAllow));
    let old = domain::create_key(&state, input(None)).await.unwrap();
    let new = domain::create_key(&state, input(None)).await.unwrap();
    let child = domain::create_key(&state, input(Some(&old))).await.unwrap();
    hooked.watch_child(child.lid);

    let migration = prepare_migration(&state, child.lid, Some(new.lid), Uuid::new_v4())
        .await
        .unwrap();
    hooked.interleave_migration(state.clone(), migration);
    hooked.arm_interleave();
    let generated = provider.generates.load(Ordering::SeqCst);

    let outcome = domain::rotate_key(&state, &child.lid, &child.lid.to_string())
        .await
        .unwrap();
    assert!(hooked.hook.once.load(Ordering::SeqCst));
    assert_eq!(provider.generates.load(Ordering::SeqCst), generated + 1);
    let rotated = state.storage.get_key(&child.lid).await.unwrap();
    assert_eq!(outcome.record.occ_version, rotated.occ_version);
    assert_eq!(rotated.parent_lid, Some(new.lid));
    assert_eq!(rotated.key_versions.len(), 2);
    let new_parent = state.storage.get_key(&new.lid).await.unwrap();
    for version in &rotated.key_versions {
        assert_eq!(material(version).parent().lid, new.lid);
    }
    assert_eq!(
        material(rotated.primary_version().unwrap())
            .parent()
            .version
            .get(),
        new_parent.current_key_version
    );
    assert!(state
        .storage
        .pending_creations(&child.lid)
        .await
        .unwrap()
        .is_empty());
    let all = ciphertexts(&state, &rotated).await;
    assert_decrypts(&state, &rotated, &all).await;
}

#[tokio::test]
async fn parent_rotation_during_generate_retries_with_new_parent_version() {
    let (state, provider, child, parent) = fixture().await;
    let v1_ciphertext = ciphertexts(&state, &child).await;
    provider.paused.store(true, Ordering::SeqCst);
    let rotation = tokio::spawn({
        let state = state.clone();
        let child = child.lid;
        async move { domain::rotate_key(&state, &child, &child.to_string()).await }
    });
    provider.wait_entered().await;
    domain::rotate_key(&state, &parent.lid, &parent.lid.to_string())
        .await
        .unwrap();
    let parent = state.storage.get_key(&parent.lid).await.unwrap();
    provider.release_blocked(1);
    let outcome = rotation.await.unwrap().unwrap();
    assert_eq!(outcome.new_version, 2);
    let primary = outcome.record.primary_version().unwrap();
    assert_eq!(
        material(primary).parent().version.get(),
        parent.current_key_version
    );

    let rotated = state.storage.get_key(&child.lid).await.unwrap();
    let all = [
        v1_ciphertext,
        ciphertexts(&state, &rotated).await[1..].to_vec(),
    ]
    .concat();
    assert_decrypts(&state, &rotated, &all).await;
}

#[tokio::test]
async fn repeatedly_stale_rotation_is_refused_as_conflict_on_both_surfaces() {
    for rest in [false, true] {
        let provider = Arc::new(ObservedProvider::new());
        let hooked = Arc::new(HookedStorage::new(Arc::new(
            keyrack_sqlite::SqliteStorage::in_memory().unwrap(),
        )));
        let state = service_state(hooked.clone(), provider.clone(), Arc::new(AlwaysAllow));
        let parent = domain::create_key(&state, input(None)).await.unwrap();
        let child = domain::create_key(&state, input(Some(&parent)))
            .await
            .unwrap();
        hooked.watch_child(child.lid);
        hooked.stale_every_reservation();
        let generated = provider.generates.load(Ordering::SeqCst);
        let id = child.lid.to_string();

        if rest {
            let (code, body) = rotate_rest_body(&state, &id).await;
            assert_eq!(code, 409, "{body}");
            assert_eq!(body["error"], "OccConflict", "{body}");
        } else {
            assert_eq!(rotate_grpc(&state, &id).await, (tonic::Code::Aborted, 0));
        }
        assert_eq!(hooked.hook.stale_reservations.load(Ordering::SeqCst), 3);
        // Each stale reservation is caught before dispatch.
        assert_eq!(provider.generates.load(Ordering::SeqCst), generated);
        let stored = state.storage.get_key(&child.lid).await.unwrap();
        assert_same_key_snapshot(&stored, &child);
        assert_no_pending_creation(&state, &child.lid).await;
    }
}

#[tokio::test]
async fn concurrent_child_rotations_do_not_lose_versions() {
    let (state, _, child, _) = fixture().await;
    let attempts = 6usize;
    let mut tasks = Vec::new();
    for _ in 0..attempts {
        let state = state.clone();
        let id = child.lid.to_string();
        let lid = child.lid;
        tasks.push(tokio::spawn(async move {
            domain::rotate_key(&state, &lid, &id).await
        }));
    }
    let mut successes = 0usize;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => successes += 1,
            Err(error) => assert_retryable_domain(&error),
        }
    }
    assert!(successes >= 1);
    let final_record = state.storage.get_key(&child.lid).await.unwrap();
    assert_eq!(final_record.key_versions.len(), 1 + successes);
    let versions: Vec<u64> = final_record
        .key_versions
        .iter()
        .map(|v| v.version_number)
        .collect();
    assert_eq!(
        versions.len(),
        versions
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
    let all_ciphertexts = ciphertexts(&state, &final_record).await;
    assert_decrypts(&state, &final_record, &all_ciphertexts).await;
}

#[tokio::test]
async fn dropped_rotation_request_leaves_key_consistent() {
    for rest in [false, true] {
        let provider = Arc::new(ObservedProvider::new());
        let audit = Arc::new(CaptureAudit::default());
        let state = service_state_audited(
            Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap()),
            provider.clone(),
            Arc::new(AlwaysAllow),
            audit.clone(),
        );
        let parent = domain::create_key(&state, input(None)).await.unwrap();
        let child = domain::create_key(&state, input(Some(&parent)))
            .await
            .unwrap();
        let grandchild = seed_descendant(&state, &child).await;
        let id = child.lid.to_string();
        let ciphertexts = ciphertexts(&state, &child).await;
        let generated = provider.generates.load(Ordering::SeqCst);

        provider.paused.store(true, Ordering::SeqCst);
        let request = tokio::spawn({
            let state = state.clone();
            let id = id.clone();
            async move {
                if rest {
                    rotate_rest(&state, &id).await;
                } else {
                    rotate_grpc(&state, &id).await;
                }
            }
        });
        provider.wait_entered().await;
        request.abort();
        assert!(request.await.is_err_and(|join| join.is_cancelled()));

        // A second rotation running beside the detached one would block in the
        // paused provider instead of being refused.
        let second = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            if rest {
                rotate_rest(&state, &id).await == (503, 0)
            } else {
                rotate_grpc(&state, &id).await == (tonic::Code::Unavailable, 0)
            }
        })
        .await;
        assert!(
            second.is_ok_and(|refused| refused),
            "a second rotation must be refused as retryable while the first runs"
        );
        provider.release_blocked(1);

        // The outcome is audited last, after the version and its descendant jobs.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !audit
                .rotate_outcomes(&id)
                .contains(&keyrack_core::audit::AuditResult::Success)
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the dropped request's rotation is audited");
        assert_eq!(
            audit.rotate_outcomes(&id),
            [
                keyrack_core::audit::AuditResult::Error,
                keyrack_core::audit::AuditResult::Success
            ],
            "the refused second request and the dropped one's outcome"
        );

        let detached = state.storage.get_key_for_use(&child.lid).await.unwrap();
        assert_eq!(detached.current_key_version, 2);
        assert_no_pending_creation(&state, &child.lid).await;
        let jobs: Vec<RotationJob> = state
            .storage
            .list_rotation_jobs(Some(RotationJobState::Pending))
            .await
            .unwrap()
            .into_iter()
            .filter(|job| job.parent_lid == child.lid)
            .collect();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].dependent_lid, grandchild);
        assert_eq!(jobs[0].new_version, 2);
        let all = [
            ciphertexts.clone(),
            self::ciphertexts(&state, &detached).await[1..].to_vec(),
        ]
        .concat();
        assert_decrypts(&state, &detached, &all).await;

        // The slot is released before the outcome is audited.
        if rest {
            assert_eq!(rotate_rest(&state, &id).await, (200, 3));
        } else {
            assert_eq!(rotate_grpc(&state, &id).await, (tonic::Code::Ok, 3));
        }
        assert_eq!(provider.generates.load(Ordering::SeqCst), generated + 2);
    }
}

/// Seed a logical descendant of `parent`. Only the descendant walk reads it, so
/// its descriptor is shaped as a wrapped child but deliberately not openable.
async fn seed_descendant(state: &Arc<ServiceState>, parent: &KeyRecord) -> Lid {
    let mut record = keyrack_test_support::fixtures::unique_test_key_record(KeyState::Enabled);
    record.parent_lid = Some(parent.lid);
    record.key_versions[0].material = KeyMaterial::ParentWrapped(
        ParentWrappedMaterial::new(
            ProviderRef::new("default"),
            name(DOMAIN),
            keyrack_core::wrapping::VersionedKeyId::new(parent.lid, parent.current_key_version)
                .unwrap(),
            keyrack_core::wrapping::WrappingContextVersion::V1,
            keyrack_core::wrapping::WrappedKeyFormat::RawSecret,
            name(SOFTWARE_WRAPPING_MECHANISM),
            name("seeded-not-openable"),
        )
        .unwrap(),
    );
    state.storage.create_key(&record).await.unwrap();
    record.lid
}
