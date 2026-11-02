// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-token service coverage. Run serially on the disposable fixture used by
//! test-pkcs11-wrapping.sh. The fault adapter changes inputs only after storage
//! validates its journal; every cryptographic operation still reaches `SoftHSM`.

use base64::Engine;
use keyrack_core::error::Result as CoreResult;
use keyrack_core::key::{KeyMaterial, KeyRecord, KeySpec, ProviderClass, ProviderRef};
use keyrack_core::provider::{
    CryptoProvider, EncryptOutput, GeneratedWrappedKey, KeyHandle, ProviderCapabilities,
    SigningAlgorithm, WrappedKeyClosure, WrappedKeyLease,
};
use keyrack_core::registry::{ProviderEntry, StaticProviderRegistry};
use keyrack_core::sensitive::Sensitive;
use keyrack_core::storage::StorageBackend;
use keyrack_core::wrapping::{WrappingContext, WrappingIdentifier};
use keyrack_pkcs11::{Pkcs11Provider, Pkcs11ProviderConfig, CONTEXT_DERIVED_WRAPPING_MECHANISM};
use keyrack_service::hierarchy::{WrappingProfile, WrappingProfiles};
use keyrack_service::proto::{self, key_service_client::KeyServiceClient};
use keyrack_service::routing::ProviderRouter;
use keyrack_service::state::ServiceState;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const PROVIDER: &str = "token-wrapping";
const DOMAIN: &str = "service-token-tests";
const PATIENCE: Duration = Duration::from_secs(10);

fn identifier(value: &str) -> WrappingIdentifier {
    WrappingIdentifier::new(value).unwrap()
}

#[derive(Default)]
struct Controls {
    replacement: Mutex<Option<Vec<u8>>>,
    mutation: Mutex<Option<&'static str>>,
    errors: Mutex<Vec<String>>,
    opened: Mutex<Vec<KeyHandle>>,
    hold_open: AtomicBool,
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    changed: Condvar,
    closed: AtomicUsize,
    hold_migration_result: AtomicBool,
    migration_entered: tokio::sync::Notify,
    migration_calls: AtomicUsize,
    migration_native_closed: AtomicUsize,
}

impl Controls {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

// Always release test-only blocking gates on assertion failure as well as success.
struct ReleaseGate(Arc<Controls>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.hold_migration_result.store(false, Ordering::SeqCst);
        self.0.release();
    }
}

struct Instrumented {
    inner: Arc<Pkcs11Provider>,
    controls: Arc<Controls>,
}

#[async_trait::async_trait]
impl CryptoProvider for Instrumented {
    fn capabilities(&self) -> ProviderCapabilities {
        self.inner.capabilities()
    }
    fn wrapping_capabilities(&self) -> keyrack_core::wrapping::WrappingCapabilities {
        self.inner.wrapping_capabilities()
    }
    fn wrapping_closure_verifier(
        &self,
    ) -> Option<Arc<dyn keyrack_core::creation::A2ClosureVerifier>> {
        self.inner.wrapping_closure_verifier()
    }
    async fn generate_key(&self, spec: &KeySpec) -> CoreResult<KeyHandle> {
        self.inner.generate_key(spec).await
    }
    async fn encrypt(
        &self,
        handle: &KeyHandle,
        plain: &[u8],
        aad: &[u8],
    ) -> CoreResult<EncryptOutput> {
        self.inner.encrypt(handle, plain, aad).await
    }
    async fn decrypt(
        &self,
        handle: &KeyHandle,
        cipher: &[u8],
        aad: &[u8],
    ) -> CoreResult<Sensitive<Vec<u8>>> {
        self.inner.decrypt(handle, cipher, aad).await
    }
    async fn sign(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
    ) -> CoreResult<Vec<u8>> {
        self.inner.sign(handle, algorithm, message).await
    }
    async fn verify(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> CoreResult<bool> {
        self.inner
            .verify(handle, algorithm, message, signature)
            .await
    }
    async fn generate_random(&self, length: usize) -> CoreResult<Sensitive<Vec<u8>>> {
        self.inner.generate_random(length).await
    }
    async fn destroy_key(&self, handle: &KeyHandle) -> CoreResult<()> {
        self.inner.destroy_key(handle).await
    }
    async fn generate_wrapped_key(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        creation: &keyrack_core::creation::CreationBinding,
    ) -> CoreResult<GeneratedWrappedKey> {
        self.inner
            .generate_wrapped_key(context, parent, creation)
            .await
    }
    async fn open_wrapped_key(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        envelope: &[u8],
    ) -> CoreResult<WrappedKeyLease> {
        let mut context = context.clone();
        if let Some(field) = *self.controls.mutation.lock().unwrap() {
            mutate(&mut context, field);
            // These cases are legal canonical contexts, not parser rejection.
            context
                .canonical_bytes()
                .expect("mutation remains canonical");
        }
        let envelope = self
            .controls
            .replacement
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| envelope.to_vec());
        let (inner, controls, parent) = (self.inner.clone(), self.controls.clone(), parent.clone());
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let result = runtime.block_on(inner.open_wrapped_key(&context, &parent, &envelope));
            match &result {
                Ok(lease) => {
                    controls.opened.lock().unwrap().push(lease.handle().clone());
                    if controls.hold_open.load(Ordering::SeqCst) {
                        controls.entered.notify_one();
                        let mut released = controls.released.lock().unwrap();
                        while !*released {
                            released = controls.changed.wait(released).unwrap();
                        }
                    }
                }
                Err(error) => controls.errors.lock().unwrap().push(error.to_string()),
            }
            result
        })
        .await
        .expect("native open thread")
    }
    fn rewrap_is_retry_safe(&self) -> bool {
        self.inner.rewrap_is_retry_safe()
    }

    async fn rewrap_wrapped_key(
        &self,
        old: &WrappingContext,
        old_parent: &KeyHandle,
        envelope: &[u8],
        new: &WrappingContext,
        new_parent: &KeyHandle,
    ) -> CoreResult<Vec<u8>> {
        let (inner, controls) = (self.inner.clone(), self.controls.clone());
        let (old, old_parent, envelope, new, new_parent) = (
            old.clone(),
            old_parent.clone(),
            envelope.to_vec(),
            new.clone(),
            new_parent.clone(),
        );
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            controls.migration_calls.fetch_add(1, Ordering::SeqCst);
            let result = runtime.block_on(inner.rewrap_wrapped_key(
                &old,
                &old_parent,
                &envelope,
                &new,
                &new_parent,
            ));
            if result.is_ok() {
                // Native success requires explicit original-session cleanup.
                // Hold its response before the service can stage the journal.
                controls
                    .migration_native_closed
                    .fetch_add(1, Ordering::SeqCst);
                if controls.hold_migration_result.load(Ordering::SeqCst) {
                    controls.migration_entered.notify_one();
                    let mut released = controls.released.lock().unwrap();
                    while !*released {
                        released = controls.changed.wait(released).unwrap();
                    }
                }
            }
            result
        })
        .await
        .expect("native migration response thread")
    }

    async fn close_wrapped_key(&self, lease: &WrappedKeyLease) -> CoreResult<WrappedKeyClosure> {
        let result = self.inner.close_wrapped_key(lease).await;
        if result.is_ok() {
            self.controls.closed.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
}

// V1 is the sole representable encoding. A public digest cannot be added to an
// AES context: canonical validation forbids it. Both are parser/profile limits,
// not independently testable legal single-field substitutions in this profile.
fn mutate(context: &mut WrappingContext, field: &str) {
    use keyrack_core::lid::Lid;
    use keyrack_core::wrapping::{WrappedKeyFormat, WrappingKeyPurpose};
    match field {
        "child_lid" => context.child.lid = Lid::from_bytes([7; 32]),
        "child_version" => context.child.version = 2.try_into().unwrap(),
        "parent_lid" => context.parent.lid = Lid::from_bytes([8; 32]),
        "parent_version" => context.parent.version = 2.try_into().unwrap(),
        "parent_spec" => context.parent_spec = KeySpec::Aes128,
        "child_spec" => context.child_spec = KeySpec::Aes128,
        "key_format" => {
            context.key_format = WrappedKeyFormat::ProviderNative(identifier("other-format"));
        }
        "purpose" => context.purpose = WrappingKeyPurpose::WrapUnwrap,
        "provider_ref" => context.provider_ref = ProviderRef::new("other-provider"),
        "security_domain" => context.security_domain = identifier("other-domain"),
        "mechanism" => context.mechanism = identifier("other-mechanism"),
        _ => panic!("unknown context field"),
    }
}

struct Service {
    state: Arc<ServiceState>,
    native: Arc<Pkcs11Provider>,
    controls: Arc<Controls>,
    grpc: String,
    rest: String,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Service {
    fn drop(&mut self) {
        self.controls.release();
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Service {
    async fn start(storage: Arc<dyn StorageBackend>) -> Self {
        std::env::var("SOFTHSM2_CONF").expect("isolated SoftHSM configuration required");
        let config = Pkcs11ProviderConfig {
            lib_path: std::env::var("KMS_PKCS11_LIB").expect("SoftHSM module required"),
            token_label: std::env::var("KMS_PKCS11_TOKEN_LABEL")
                .expect("disposable token required"),
            pin: std::env::var("KMS_PKCS11_PIN").expect("disposable PIN required"),
        };
        let ordinary = Arc::new(Pkcs11Provider::new(&config).expect("ordinary token provider"));
        let native = Arc::new(
            Pkcs11Provider::new_with_wrapping(
                &config,
                ProviderRef::new(PROVIDER),
                identifier(CONTEXT_DERIVED_WRAPPING_MECHANISM),
                identifier(DOMAIN),
            )
            .expect("qualified context-derived provider"),
        );
        let controls = Arc::new(Controls::default());
        let provider: Arc<dyn CryptoProvider> = Arc::new(Instrumented {
            inner: native.clone(),
            controls: controls.clone(),
        });
        let registry = StaticProviderRegistry::new(
            [
                (
                    ProviderRef::new("ordinary"),
                    ProviderEntry {
                        provider: ordinary,
                        class: ProviderClass::Pkcs11,
                    },
                ),
                (
                    ProviderRef::new(PROVIDER),
                    ProviderEntry {
                        provider,
                        class: ProviderClass::Pkcs11,
                    },
                ),
            ],
            ProviderRef::new("ordinary"),
        )
        .unwrap();
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let state = Arc::new(ServiceState {
            storage,
            providers: Arc::new(registry),
            provider_router: ProviderRouter::new(vec![], ProviderRef::new("ordinary")).unwrap(),
            pdp: Arc::new(keyrack_core::pdp::AlwaysAllow),
            audit: Arc::new(keyrack_core::audit::FanoutSink::new(vec![])),
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
                    mechanism: identifier(CONTEXT_DERIVED_WRAPPING_MECHANISM),
                    security_domain: identifier(DOMAIN),
                },
            )]),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let grpc = format!("http://{}", listener.local_addr().unwrap());
        let server = proto::key_service_server::KeyServiceServer::new(
            keyrack_service::grpc::KeyServiceImpl::new(state.clone()),
        );
        let grpc_task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(server)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rest = format!("http://{}", listener.local_addr().unwrap());
        let router = keyrack_service::rest::router(state.clone());
        let rest_task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            state,
            native,
            controls,
            grpc,
            rest,
            tasks: vec![grpc_task, rest_task],
        }
    }
    async fn client(&self) -> KeyServiceClient<tonic::transport::Channel> {
        KeyServiceClient::connect(self.grpc.clone()).await.unwrap()
    }
    async fn create(&self, rest: bool, parent: Option<&str>, aes128: bool) -> String {
        if rest {
            let response = reqwest::Client::new()
                .post(format!("{}/v1/keys", self.rest))
                .json(&serde_json::json!({
                    "key_spec": if aes128 {"AES_128"} else {"AES_256"},
                    "backend_id": PROVIDER, "parent_key_id": parent,
                }))
                .send()
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = response.json().await.unwrap();
            assert!(status.is_success(), "REST create: {status} {body}");
            body["lid"].as_str().expect("REST key id").to_owned()
        } else {
            self.client()
                .await
                .create_key(proto::CreateKeyRequest {
                    key_spec: if aes128 {
                        proto::KeySpec::Aes128
                    } else {
                        proto::KeySpec::Aes256
                    }
                    .into(),
                    backend_id: Some(PROVIDER.into()),
                    parent_key_id: parent.map(str::to_owned),
                    ..Default::default()
                })
                .await
                .expect("gRPC create")
                .into_inner()
                .metadata
                .unwrap()
                .key_id
        }
    }
    async fn encrypt(&self, rest: bool, key: &str) -> Result<Vec<u8>, String> {
        if rest {
            let response = reqwest::Client::new().post(format!("{}/v1/keys/{key}/actions-encrypt", self.rest))
                .json(&serde_json::json!({"plaintext": base64::engine::general_purpose::STANDARD.encode(b"native service data")}))
                .send().await.unwrap();
            let status = response.status();
            let body: serde_json::Value = response.json().await.unwrap();
            if !status.is_success() {
                return Err(format!("{status}: {body}"));
            }
            Ok(base64::engine::general_purpose::STANDARD
                .decode(body["ciphertext_blob"].as_str().unwrap())
                .unwrap())
        } else {
            self.client()
                .await
                .encrypt(proto::EncryptRequest {
                    key_id: key.into(),
                    plaintext: b"native service data".to_vec(),
                    ..Default::default()
                })
                .await
                .map(|r| r.into_inner().ciphertext_blob)
                .map_err(|e| e.to_string())
        }
    }
    async fn decrypt(&self, rest: bool, key: &str, blob: &[u8]) {
        let plain = if rest {
            let response = reqwest::Client::new().post(format!("{}/v1/keys/{key}/actions-decrypt", self.rest))
                .json(&serde_json::json!({"ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(blob)}))
                .send().await.unwrap();
            let status = response.status();
            let body: serde_json::Value = response.json().await.unwrap();
            assert!(status.is_success(), "REST decrypt: {status} {body}");
            base64::engine::general_purpose::STANDARD
                .decode(body["plaintext"].as_str().unwrap())
                .unwrap()
        } else {
            self.client()
                .await
                .decrypt(proto::DecryptRequest {
                    key_id: key.into(),
                    ciphertext_blob: blob.to_vec(),
                    ..Default::default()
                })
                .await
                .expect("gRPC decrypt")
                .into_inner()
                .plaintext
        };
        assert_eq!(plain, b"native service data");
    }
    async fn record(&self, key: &str) -> KeyRecord {
        self.state
            .storage
            .get_key(&key.parse().unwrap())
            .await
            .unwrap()
    }
    async fn envelope(&self, key: &str) -> Vec<u8> {
        let record = self.record(key).await;
        let KeyMaterial::ParentWrapped(material) = &record.primary_version().unwrap().material
        else {
            panic!("wrapped child required")
        };
        self.envelope_reference(material.wrapped_material_ref().as_str())
            .await
            .unwrap()
    }
    async fn envelope_reference(&self, reference: &str) -> CoreResult<Vec<u8>> {
        if let Some(operation) = reference.strip_prefix("creation:") {
            self.state
                .storage
                .read_creation_envelope(operation.parse().unwrap())
                .await
        } else {
            let (operation, version) = reference
                .strip_prefix("migration:")
                .unwrap()
                .split_once(':')
                .unwrap();
            self.state
                .storage
                .read_migration_envelope(operation.parse().unwrap(), version.parse().unwrap())
                .await
        }
    }
    async fn rotate(&self, rest: bool, key: &str) -> KeyRecord {
        if rest {
            let response = reqwest::Client::new()
                .post(format!("{}/v1/keys/{key}/actions-rotate", self.rest))
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap();
            let status = response.status();
            let body = response.text().await.unwrap();
            assert!(status.is_success(), "root rotation: {status} {body}");
        } else {
            self.client()
                .await
                .rotate_key(proto::RotateKeyRequest { key_id: key.into() })
                .await
                .expect("root rotation");
        }
        self.record(key).await
    }
    async fn migrate(
        &self,
        rest: bool,
        key: &str,
        parent: Option<&str>,
        operation: uuid::Uuid,
    ) -> KeyRecord {
        let receipt = if rest {
            let response = reqwest::Client::new()
                .post(format!("{}/v1/keys/{key}/rewrap", self.rest))
                .json(&serde_json::json!({
                    "operation_id": operation.to_string(),
                    "new_parent_key_id": parent.unwrap_or(""),
                }))
                .send()
                .await
                .unwrap();
            let status = response.status();
            let text = response.text().await.unwrap();
            assert!(status.is_success(), "migration: {status} {text}");
            let body: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(body["operation_id"], operation.to_string());
            let mut encoded = body["result"].clone();
            // REST uses textual LIDs; the storage record serializes their bytes.
            for field in ["child", "old_parent", "new_parent"] {
                let lid: keyrack_core::lid::Lid = encoded[field].as_str().unwrap().parse().unwrap();
                encoded[field] = serde_json::to_value(lid).unwrap();
            }
            let receipt: keyrack_core::migration::MigrationResult =
                serde_json::from_value(encoded).expect("terminal migration receipt");
            assert_eq!(body["metadata"]["lid"], receipt.child.to_string());
            assert_eq!(
                body["metadata"]["parent_lid"],
                receipt.new_parent.to_string()
            );
            receipt
        } else {
            let response = self
                .client()
                .await
                .rewrap_key(proto::RewrapKeyRequest {
                    key_id: key.into(),
                    new_parent_key_id: parent.unwrap_or("").into(),
                    operation_id: operation.to_string(),
                    ..Default::default()
                })
                .await
                .expect("gRPC migration")
                .into_inner();
            assert_eq!(response.operation_id, operation.to_string());
            let metadata = response.metadata.expect("original committed metadata");
            let result = response.result.expect("terminal migration receipt");
            assert_eq!(metadata.key_id, result.child);
            assert_eq!(
                metadata.parent_key_id.as_deref(),
                Some(result.new_parent.as_str())
            );
            keyrack_core::migration::MigrationResult {
                operation_id: result.operation_id.parse().unwrap(),
                child: result.child.parse().unwrap(),
                old_parent: result.old_parent.parse().unwrap(),
                old_parent_versions: result.old_parent_versions,
                new_parent: result.new_parent.parse().unwrap(),
                new_parent_version: result.new_parent_version,
                digest_algorithm: result.digest_algorithm,
                versions: result
                    .versions
                    .into_iter()
                    .map(|v| keyrack_core::migration::MigrationVersionResult {
                        version: v.version,
                        old_parent_version: v.old_parent_version,
                        new_parent_version: v.new_parent_version,
                        old_envelope_digest: v.old_envelope_digest,
                        new_envelope_digest: v.new_envelope_digest,
                        old_reference: v.old_reference,
                        new_reference: v.new_reference,
                    })
                    .collect(),
            }
        };
        assert_eq!(receipt.operation_id, operation);
        assert_eq!(receipt.child.to_string(), key);
        let journal = self
            .state
            .storage
            .get_migration(operation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            journal.phase,
            keyrack_core::migration::MigrationPhase::Committed
        );
        assert_eq!(journal.result.as_ref(), Some(&receipt));
        journal.request.proposed
    }

    async fn refuse_changed_migration_assertion(
        &self,
        rest: bool,
        key: &str,
        parent: &str,
        operation: uuid::Uuid,
    ) {
        // Same logical destination but newly supplied optional assertion is a
        // different immutable intent, even after the original operation commits.
        if rest {
            let response = reqwest::Client::new()
                .post(format!("{}/v1/keys/{key}/rewrap", self.rest))
                .json(&serde_json::json!({
                    "operation_id": operation.to_string(),
                    "old_parent_key_id": parent,
                }))
                .send()
                .await
                .unwrap();
            let status = response.status();
            let body = response.text().await.unwrap();
            assert_eq!(status, reqwest::StatusCode::CONFLICT, "{body}");
            assert!(body.contains("different migration intent"), "{body}");
        } else {
            let error = self
                .client()
                .await
                .rewrap_key(proto::RewrapKeyRequest {
                    key_id: key.into(),
                    operation_id: operation.to_string(),
                    old_parent_key_id: parent.into(),
                    ..Default::default()
                })
                .await
                .expect_err("changed assertion presence must refuse");
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
            assert!(
                error.message().contains("different migration intent"),
                "{error}"
            );
        }
    }

    fn native_object_count() -> usize {
        // Observe the already initialized module without initializing/finalizing
        // it independently or changing the service's recovery state.
        let module =
            cryptoki::context::Pkcs11::new(std::env::var("KMS_PKCS11_LIB").unwrap()).unwrap();
        let label = std::env::var("KMS_PKCS11_TOKEN_LABEL").unwrap();
        let slot = module
            .get_slots_with_token()
            .unwrap()
            .into_iter()
            .find(|slot| module.get_token_info(*slot).unwrap().label() == label)
            .unwrap();
        let session = module.open_rw_session_no_drop(slot).unwrap();
        let pin = cryptoki::types::AuthPin::new(std::env::var("KMS_PKCS11_PIN").unwrap().into());
        match session.login(cryptoki::session::UserType::User, Some(&pin)) {
            Ok(())
            | Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::UserAlreadyLoggedIn,
                _,
            )) => (),
            Err(error) => panic!("native observer login: {error}"),
        }
        let count = session.find_objects(&[]).unwrap().len();
        session.close().unwrap();
        count
    }
    async fn roundtrip(&self, rest: bool, key: &str) {
        let blob = self.encrypt(rest, key).await.unwrap();
        self.decrypt(rest, key, &blob).await;
    }
}

fn storage() -> Arc<dyn StorageBackend> {
    Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the isolated native-token fixture; no mock fallback"]
async fn native_wrapped_grpc_rest_roundtrip_and_envelope_swap_refusal() {
    let service = Service::start(storage()).await;
    // The ordinary default entry shares the token but retains application-key
    // permissions. Its resident key remains usable through both surfaces.
    let ordinary = service
        .client()
        .await
        .create_key(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            ..Default::default()
        })
        .await
        .expect("ordinary default key creation")
        .into_inner()
        .metadata
        .unwrap()
        .key_id;
    service.roundtrip(false, &ordinary).await;
    service.roundtrip(true, &ordinary).await;
    for rest in [false, true] {
        let parent = service.create(rest, None, false).await;
        for aes128 in [false, true] {
            let first = service.create(rest, Some(&parent), aes128).await;
            let second = service.create(rest, Some(&parent), aes128).await;
            service.roundtrip(rest, &first).await;
            service.roundtrip(rest, &second).await;
            *service.controls.replacement.lock().unwrap() = Some(service.envelope(&second).await);
            let error = service
                .encrypt(rest, &first)
                .await
                .expect_err("swapped child must not open");
            let native = service
                .controls
                .errors
                .lock()
                .unwrap()
                .last()
                .cloned()
                .expect("native refusal reached");
            assert!(
                native.contains("context-derived child unwrap"),
                "native cause: {native}; service: {error}"
            );
            *service.controls.replacement.lock().unwrap() = None;
            service.roundtrip(rest, &first).await;
            service.roundtrip(rest, &second).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the isolated native-token fixture; no mock fallback"]
async fn native_wrapped_context_fields_and_parent_version_are_bound() {
    let service = Service::start(storage()).await;
    let parent = service.create(false, None, false).await;
    let child = service.create(false, Some(&parent), false).await;
    for rest in [false, true] {
        for field in [
            "child_lid",
            "child_version",
            "parent_lid",
            "parent_version",
            "parent_spec",
            "child_spec",
            "key_format",
            "purpose",
            "provider_ref",
            "security_domain",
            "mechanism",
        ] {
            service.roundtrip(rest, &child).await;
            *service.controls.mutation.lock().unwrap() = Some(field);
            let before = service.controls.errors.lock().unwrap().len();
            let error = service.encrypt(rest, &child).await.expect_err(field);
            let cause = {
                let errors = service.controls.errors.lock().unwrap();
                assert_eq!(
                    errors.len(),
                    before + 1,
                    "{field}: native provider must refuse, not storage: {error}"
                );
                errors.last().unwrap().clone()
            };
            if matches!(
                field,
                "child_lid" | "child_version" | "parent_lid" | "parent_version"
            ) {
                assert!(
                    cause.contains("context-derived child unwrap"),
                    "{field}: {cause}"
                );
            } else {
                assert!(
                    cause.contains("context-derived PKCS#11 wrapping"),
                    "{field}: {cause}"
                );
            }
            *service.controls.mutation.lock().unwrap() = None;
            service.roundtrip(rest, &child).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the isolated native-token fixture; no mock fallback"]
async fn native_wrapped_grpc_rest_cancellation_closes_original_lease() {
    let service = Service::start(storage()).await;
    let parent = service.create(false, None, false).await;
    let child = service.create(false, Some(&parent), false).await;
    for rest in [false, true] {
        service.roundtrip(rest, &child).await;
        let before = service.state.lease_cleanup.counts();
        *service.controls.released.lock().unwrap() = false;
        service.controls.hold_open.store(true, Ordering::SeqCst);
        let entered = service.controls.entered.notified();
        let request = if rest {
            let url = format!("{}/v1/keys/{child}/actions-encrypt", service.rest);
            tokio::spawn(async move {
                let error = reqwest::Client::builder()
                    .timeout(Duration::from_millis(500))
                    .build()
                    .unwrap()
                    .post(url)
                    .json(&serde_json::json!({"plaintext":"aGVsbG8="}))
                    .send()
                    .await
                    .expect_err("REST timeout");
                assert!(error.is_timeout(), "{error}");
            })
        } else {
            let mut client = service.client().await;
            let mut input = tonic::Request::new(proto::EncryptRequest {
                key_id: child.clone(),
                plaintext: b"hello".to_vec(),
                ..Default::default()
            });
            input.set_timeout(Duration::from_millis(500));
            tokio::spawn(async move {
                let error = client.encrypt(input).await.expect_err("gRPC deadline");
                assert!(
                    matches!(
                        error.code(),
                        tonic::Code::Cancelled | tonic::Code::DeadlineExceeded
                    ),
                    "{error}"
                );
            })
        };
        tokio::time::timeout(PATIENCE, entered)
            .await
            .expect("real native open must complete before cancellation");
        let handle = service
            .controls
            .opened
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert!(service
            .native
            .encrypt(&handle, b"before close", b"aad")
            .await
            .is_ok());
        let result = request.await;
        service.controls.release();
        service.controls.hold_open.store(false, Ordering::SeqCst);
        result.unwrap();
        tokio::time::timeout(PATIENCE, async {
            loop {
                let counts = service.state.lease_cleanup.counts();
                if counts.closed_after_return > before.closed_after_return {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cleanup owner must close cancelled native lease");
        assert!(
            service
                .native
                .encrypt(&handle, b"after close", b"aad")
                .await
                .is_err(),
            "closed native handle remains usable"
        );
        let counts = service.state.lease_cleanup.counts();
        assert_eq!(counts.close_failed, before.close_failed);
        assert_eq!(counts.abandoned, before.abandoned);
        service.roundtrip(rest, &child).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the isolated native-token fixture; no mock fallback"]
async fn native_wrapped_provider_reconstruction_retains_child_usability() {
    // Reconstruct the provider and both service frontends over retained SQLite
    // metadata. This is an in-process reconstruction, not a crash-recovery proof.
    let storage = storage();
    let service = Service::start(storage.clone()).await;
    let parent = service.create(false, None, false).await;
    let child = service.create(false, Some(&parent), false).await;
    let blob = service.encrypt(false, &child).await.unwrap();
    drop(service);
    tokio::task::yield_now().await;
    let service = Service::start(storage).await;
    service.decrypt(false, &child, &blob).await;
    service.decrypt(true, &child, &blob).await;
    service.roundtrip(false, &child).await;
    service.roundtrip(true, &child).await;
}

struct RestartDirectory(std::path::PathBuf);
impl Drop for RestartDirectory {
    fn drop(&mut self) {
        // This directory is created exclusively for this test invocation.
        std::fs::remove_dir_all(&self.0).expect("remove restart fixture directory");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the isolated native-token fixture; no mock fallback"]
async fn native_wrapped_process_restart_retains_child_usability() {
    const TEST: &str = "native_wrapped_process_restart_retains_child_usability";
    const PHASE: &str = "KEYRACK_NATIVE_RESTART_PHASE";
    const DIRECTORY: &str = "KEYRACK_NATIVE_RESTART_DIRECTORY";
    if let Ok(phase) = std::env::var(PHASE) {
        let directory =
            std::path::PathBuf::from(std::env::var_os(DIRECTORY).expect("restart directory"));
        let database =
            Arc::new(keyrack_sqlite::SqliteStorage::open(directory.join("keys.sqlite")).unwrap());
        let service = Service::start(database).await;
        match phase.as_str() {
            "create" => {
                let parent = service.create(false, None, false).await;
                let grpc_child = service.create(false, Some(&parent), false).await;
                let rest_child = service.create(true, Some(&parent), true).await;
                let grpc_ciphertext = service.encrypt(false, &grpc_child).await.unwrap();
                let rest_ciphertext = service.encrypt(true, &rest_child).await.unwrap();
                let record = serde_json::json!({
                    "grpc_child": grpc_child,
                    "rest_child": rest_child,
                    "grpc_ciphertext": grpc_ciphertext,
                    "rest_ciphertext": rest_ciphertext,
                });
                // Only identifiers and application ciphertext cross processes;
                // wrapped envelopes remain in the durable creation journal.
                std::fs::write(
                    directory.join("ciphertexts.json"),
                    serde_json::to_vec(&record).unwrap(),
                )
                .unwrap();
            }
            "read" => {
                let record: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(directory.join("ciphertexts.json")).unwrap(),
                )
                .unwrap();
                for (name, rest) in [("grpc", false), ("rest", true)] {
                    let child = record[format!("{name}_child")].as_str().unwrap();
                    let ciphertext: Vec<u8> =
                        serde_json::from_value(record[format!("{name}_ciphertext")].clone())
                            .unwrap();
                    service.decrypt(rest, child, &ciphertext).await;
                    service.roundtrip(rest, child).await;
                }
            }
            other => panic!("unexpected restart phase: {other}"),
        }
        drop(service);
        println!("NATIVE_PROCESS_RESTART_PHASE_COMPLETE:{phase}");
        return;
    }

    // Do not initialize a provider in this process: no SharedModule, native
    // session, provider registry or lease evidence can be shared by the phases.
    let directory = RestartDirectory(
        std::env::temp_dir().join(format!("keyrack-native-restart-{}", uuid::Uuid::new_v4())),
    );
    std::fs::create_dir(&directory.0).unwrap();
    for phase in ["create", "read"] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                TEST,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PHASE, phase)
            .env(DIRECTORY, &directory.0)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("start independent service process");
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut timed_out = false;
        while child.try_wait().expect("poll service process").is_none() {
            if std::time::Instant::now() >= deadline {
                child.kill().expect("kill timed-out service process");
                timed_out = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let output = child.wait_with_output().expect("collect service process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !timed_out && output.status.success(),
            "{phase} process failed (timed out: {timed_out}): {stdout} {stderr}"
        );
        assert_eq!(
            stdout
                .matches(&format!("NATIVE_PROCESS_RESTART_PHASE_COMPLETE:{phase}"))
                .count(),
            1,
            "{phase} helper did not complete exactly once: {stdout} {stderr}"
        );
        assert!(
            stdout.contains("1 passed; 0 failed; 0 ignored"),
            "{phase} helper was skipped or mis-selected: {stdout}"
        );
        // wait_with_output has waited for the first process to terminate before
        // the next phase opens the same persistent metadata and token.
    }
}

fn wrapped_material(
    version: &keyrack_core::key::KeyVersionRecord,
) -> &keyrack_core::material::ParentWrappedMaterial {
    let KeyMaterial::ParentWrapped(material) = &version.material else {
        panic!("wrapped version required")
    };
    material
}

fn wrapping_context(
    record: &KeyRecord,
    version: &keyrack_core::key::KeyVersionRecord,
    parent: &KeyRecord,
) -> WrappingContext {
    let material = wrapped_material(version);
    WrappingContext {
        version: material.wrapping_context_version(),
        child: keyrack_core::wrapping::VersionedKeyId::new(record.lid, version.version_number)
            .unwrap(),
        parent: material.parent(),
        parent_spec: parent.key_spec.clone(),
        child_spec: record.key_spec.clone(),
        key_format: material.key_format().clone(),
        purpose: keyrack_core::wrapping::WrappingKeyPurpose::EncryptDecrypt,
        provider_ref: material.provider_ref().clone(),
        security_domain: material.security_domain().clone(),
        mechanism: material.mechanism().clone(),
        public_material_sha256: None,
    }
}

async fn append_retained_version(
    service: &Service,
    child: &KeyRecord,
    parent: &KeyRecord,
) -> KeyRecord {
    // Seed retained-version coverage through the real creation driver and native
    // closure verifier. This does not expose wrapped-key rotation as an API.
    use keyrack_core::creation::{creation_correlation, CreationOwner, CreationRequest};
    use keyrack_core::creation_driver::{
        A2CreationDriver, CreationProgress, WrappingCreationProvider,
    };
    use keyrack_core::key::KeyVersionRecord;
    use keyrack_core::material::ParentWrappedMaterial;
    use keyrack_core::wrapping::{
        VersionedKeyId, WrappedKeyFormat, WrappedKeyLifecycle, WrappingContextVersion,
    };
    let operation = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
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
                identifier(DOMAIN),
                VersionedKeyId::new(parent.lid, parent.current_key_version).unwrap(),
                WrappingContextVersion::V1,
                WrappedKeyFormat::RawSecret,
                identifier(CONTEXT_DERIVED_WRAPPING_MECHANISM),
                identifier(&format!("creation:{operation}")),
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
            instance: uuid::Uuid::new_v4(),
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
    let provider = service
        .state
        .providers
        .resolve(&ProviderRef::new(PROVIDER))
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
    match A2CreationDriver::new(service.state.storage.clone(), Arc::new(adapter))
        .run(request)
        .await
        .unwrap()
    {
        CreationProgress::Committed(record) => *record,
        CreationProgress::Pending(reason) => {
            panic!("native retained-version creation pending: {reason:?}")
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the isolated native-token fixture; no mock fallback"]
async fn native_wrapped_grpc_rest_rewrap_and_reparent_retained_versions() {
    let service = Service::start(storage()).await;
    for rest in [false, true] {
        for aes128 in [false, true] {
            let parent = service.create(rest, None, false).await;
            let other = service.create(rest, None, false).await;
            let child = service.create(rest, Some(&parent), aes128).await;
            let sibling = service.create(rest, Some(&parent), aes128).await;
            let first_ciphertext = service.encrypt(rest, &child).await.unwrap();
            let old_parent = service.record(&parent).await;
            let original =
                append_retained_version(&service, &service.record(&child).await, &old_parent).await;
            let second_ciphertext = service.encrypt(rest, &child).await.unwrap();
            assert_eq!(original.key_versions.len(), 2);
            let original_reference = wrapped_material(original.primary_version().unwrap())
                .wrapped_material_ref()
                .as_str()
                .to_owned();
            let mut old_envelopes = Vec::new();
            for version in &original.key_versions {
                old_envelopes.push(
                    service
                        .envelope_reference(
                            wrapped_material(version).wrapped_material_ref().as_str(),
                        )
                        .await
                        .unwrap(),
                );
            }
            let old_ciphertext = service.envelope(&child).await;
            let parent_v2 = service.rotate(rest, &parent).await;
            assert_eq!(parent_v2.current_key_version, 2);
            // Rotation alone leaves child envelopes bound to the old version.
            assert!(service
                .record(&child)
                .await
                .key_versions
                .iter()
                .all(|v| wrapped_material(v).parent().version.get() == 1));
            service.decrypt(rest, &child, &first_ciphertext).await;
            service.decrypt(rest, &child, &second_ciphertext).await;
            let baseline = Service::native_object_count();
            let operation = uuid::Uuid::new_v4();
            let rewrapped = service.migrate(rest, &child, None, operation).await;
            assert_eq!(
                Service::native_object_count(),
                baseline,
                "migration leaked native session objects"
            );
            assert_eq!(rewrapped.parent_lid, Some(old_parent.lid));
            assert!(rewrapped.key_versions.iter().all(|v| wrapped_material(v)
                .parent()
                .version
                .get()
                == 2));
            service.decrypt(rest, &child, &first_ciphertext).await;
            service.decrypt(rest, &child, &second_ciphertext).await;
            let old_reference_error = service
                .envelope_reference(&original_reference)
                .await
                .unwrap_err();
            assert!(
                old_reference_error
                    .to_string()
                    .contains("Query returned no rows"),
                "{old_reference_error}"
            );
            let terminal = service
                .state
                .storage
                .get_migration(operation)
                .await
                .unwrap()
                .unwrap()
                .result
                .unwrap();
            assert_eq!(terminal.digest_algorithm, "blake3");
            assert_eq!(terminal.old_parent, old_parent.lid);
            assert_eq!(terminal.new_parent, parent_v2.lid);
            assert_eq!(terminal.old_parent_versions, vec![1]);
            assert_eq!(terminal.new_parent_version, 2);
            assert_eq!(terminal.versions.len(), original.key_versions.len());
            for (index, version) in terminal.versions.iter().enumerate() {
                assert_eq!(version.version, original.key_versions[index].version_number);
                assert_eq!(version.old_parent_version, 1);
                assert_eq!(version.new_parent_version, 2);
                assert_eq!(
                    version.old_reference,
                    wrapped_material(&original.key_versions[index])
                        .wrapped_material_ref()
                        .as_str()
                );
                assert_eq!(
                    version.new_reference,
                    wrapped_material(&rewrapped.key_versions[index])
                        .wrapped_material_ref()
                        .as_str()
                );
                assert_eq!(
                    version.old_envelope_digest,
                    blake3::hash(&old_envelopes[index]).to_hex().as_str()
                );
                let current = service
                    .envelope_reference(&version.new_reference)
                    .await
                    .unwrap();
                assert_eq!(
                    version.new_envelope_digest,
                    blake3::hash(&current).to_hex().as_str()
                );
            }
            let calls = service.controls.migration_calls.load(Ordering::SeqCst);
            service
                .refuse_changed_migration_assertion(rest, &child, &parent, operation)
                .await;
            let replayed = service.migrate(rest, &child, None, operation).await;
            assert_eq!(
                serde_json::to_value(&replayed).unwrap(),
                serde_json::to_value(&rewrapped).unwrap()
            );
            assert_eq!(
                service.controls.migration_calls.load(Ordering::SeqCst),
                calls,
                "committed replay repeated native effects"
            );
            let new_envelope = service.envelope(&child).await;
            let old_context =
                wrapping_context(&original, original.primary_version().unwrap(), &old_parent);
            let new_context =
                wrapping_context(&rewrapped, rewrapped.primary_version().unwrap(), &parent_v2);
            let old_handle = old_parent
                .primary_version()
                .unwrap()
                .resident_handle()
                .unwrap();
            let new_handle = parent_v2
                .primary_version()
                .unwrap()
                .resident_handle()
                .unwrap();
            let wrong = service
                .native
                .open_wrapped_key(&old_context, old_handle, &new_envelope)
                .await
                .unwrap_err();
            assert!(
                wrong.to_string().contains("child unwrap"),
                "new envelope accepted old parent/version: {wrong}"
            );
            let wrong = service
                .native
                .open_wrapped_key(&new_context, old_handle, &new_envelope)
                .await
                .unwrap_err();
            assert!(
                wrong.to_string().contains("child unwrap"),
                "new context accepted old parent key: {wrong}"
            );
            // An independently copied old envelope remains recoverable while
            // the old parent exists; database erasure cannot revoke that copy.
            let retained = service
                .native
                .open_wrapped_key(&old_context, old_handle, &old_ciphertext)
                .await
                .unwrap();
            service.native.close_wrapped_key(&retained).await.unwrap();
            let valid = service
                .native
                .open_wrapped_key(&new_context, new_handle, &new_envelope)
                .await
                .unwrap();
            service.native.close_wrapped_key(&valid).await.unwrap();
            service
                .migrate(rest, &sibling, None, uuid::Uuid::new_v4())
                .await;
            let sibling_envelope = service.envelope(&sibling).await;
            *service.controls.replacement.lock().unwrap() = Some(sibling_envelope);
            service
                .encrypt(rest, &child)
                .await
                .expect_err("migrated sibling envelope must be context-bound");
            assert!(service
                .controls
                .errors
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .contains("child unwrap"));
            *service.controls.replacement.lock().unwrap() = None;
            service.decrypt(rest, &child, &second_ciphertext).await;
            let other_v2 = service.rotate(rest, &other).await;
            let before_reparent = Service::native_object_count();
            let reparented = service
                .migrate(rest, &child, Some(&other), uuid::Uuid::new_v4())
                .await;
            assert_eq!(reparented.parent_lid, Some(other_v2.lid));
            assert!(reparented
                .key_versions
                .iter()
                .all(|v| wrapped_material(v).parent().lid == other_v2.lid
                    && wrapped_material(v).parent().version.get() == 2));
            assert_eq!(Service::native_object_count(), before_reparent);
            service.decrypt(rest, &child, &first_ciphertext).await;
            service.decrypt(rest, &child, &second_ciphertext).await;
            service.roundtrip(rest, &child).await;
            let calls = service.controls.migration_calls.load(Ordering::SeqCst);
            let old_result = service.migrate(rest, &child, None, operation).await;
            assert_eq!(old_result.parent_lid, Some(old_parent.lid));
            assert_eq!(
                service.controls.migration_calls.load(Ordering::SeqCst),
                calls
            );
            assert_eq!(
                service
                    .state
                    .storage
                    .get_migration(operation)
                    .await
                    .unwrap()
                    .unwrap()
                    .result,
                Some(terminal)
            );
            assert!(
                service
                    .envelope_reference(
                        wrapped_material(rewrapped.primary_version().unwrap())
                            .wrapped_material_ref()
                            .as_str()
                    )
                    .await
                    .is_err(),
                "superseded migration envelope retained"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the isolated native-token fixture; no mock fallback"]
async fn native_wrapped_grpc_rest_migration_cancellation_retains_journal() {
    use keyrack_core::migration::MigrationPhase;
    let service = Service::start(storage()).await;
    for rest in [false, true] {
        let parent = service.create(rest, None, false).await;
        let other = service.create(rest, None, false).await;
        let child = service.create(rest, Some(&parent), false).await;
        let original = service.record(&child).await;
        let ciphertext = service.encrypt(rest, &child).await.unwrap();
        let operation = uuid::Uuid::new_v4();
        let baseline = Service::native_object_count();
        let calls_before = service.controls.migration_calls.load(Ordering::SeqCst);
        let closed_before = service
            .controls
            .migration_native_closed
            .load(Ordering::SeqCst);
        service
            .controls
            .hold_migration_result
            .store(true, Ordering::SeqCst);
        *service.controls.released.lock().unwrap() = false;
        let _release_on_exit = ReleaseGate(service.controls.clone());
        let entered = service.controls.migration_entered.notified();
        let request = if rest {
            let url = format!("{}/v1/keys/{child}/rewrap", service.rest);
            let destination = other.clone();
            tokio::spawn(async move {
                let error = reqwest::Client::builder()
                    .timeout(Duration::from_secs(1))
                    .build()
                    .unwrap()
                    .post(url)
                    .json(&serde_json::json!({
                        "operation_id": operation.to_string(),
                        "new_parent_key_id": destination,
                    }))
                    .send()
                    .await
                    .expect_err("REST migration client timeout");
                assert!(error.is_timeout(), "{error}");
            })
        } else {
            let mut client = service.client().await;
            let mut input = tonic::Request::new(proto::RewrapKeyRequest {
                key_id: child.clone(),
                new_parent_key_id: other.clone(),
                operation_id: operation.to_string(),
                ..Default::default()
            });
            input.set_timeout(Duration::from_secs(1));
            tokio::spawn(async move {
                let error = client
                    .rewrap_key(input)
                    .await
                    .expect_err("gRPC migration deadline");
                assert!(
                    matches!(
                        error.code(),
                        tonic::Code::Cancelled | tonic::Code::DeadlineExceeded
                    ),
                    "{error}"
                );
            })
        };
        tokio::time::timeout(PATIENCE, entered)
            .await
            .expect("native cleanup completed before cancellation");
        assert_eq!(
            service
                .controls
                .migration_native_closed
                .load(Ordering::SeqCst),
            closed_before + 1
        );
        assert_eq!(
            Service::native_object_count(),
            baseline,
            "native temporaries survived returned rewrap result"
        );
        request.await.unwrap();
        let journal = service
            .state
            .storage
            .get_migration(operation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            journal.phase,
            MigrationPhase::Reserved,
            "held response must not have staged envelopes"
        );
        assert_eq!(service.record(&child).await.parent_lid, original.parent_lid);
        let old_parent = service.record(&parent).await;
        let fenced = keyrack_service::domain::rotate_key(&service.state, &old_parent.lid, &parent)
            .await
            .err()
            .expect("migration fences parent rotation");
        assert!(
            matches!(
                fenced,
                keyrack_service::domain::DomainError::ProviderUnavailable(_)
            ),
            "{fenced:?}"
        );
        service
            .controls
            .hold_migration_result
            .store(false, Ordering::SeqCst);
        service.controls.release();
        let committed = tokio::time::timeout(
            PATIENCE,
            service.migrate(rest, &child, Some(&other), operation),
        )
        .await
        .expect("same-intent retry resolves migration");
        assert_eq!(committed.parent_lid, Some(other.parse().unwrap()));
        assert_eq!(
            service
                .state
                .storage
                .get_migration(operation)
                .await
                .unwrap()
                .unwrap()
                .phase,
            MigrationPhase::Committed
        );
        assert_eq!(Service::native_object_count(), baseline);
        assert_eq!(
            service.controls.migration_calls.load(Ordering::SeqCst),
            calls_before + 1,
            "same-operation retry duplicated the admitted native effect"
        );
        service.decrypt(rest, &child, &ciphertext).await;
        service.roundtrip(rest, &child).await;
    }
}
