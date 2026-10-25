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

//! Wrapped-key use leases when the request does not run to completion.
//!
//! The servers run in-process over real sockets so that cancellation arrives
//! the way it does in production: a client `grpc-timeout` that tonic enforces,
//! a reset gRPC stream, a REST client that gives up and closes its connection,
//! and the shutdown drain. The provider wraps the software provider and runs
//! open and close as blocking work that cannot be cancelled once started,
//! which is the shape of a provider talking to a token.

use keyrack_core::key::{Exportability, KeyRecord, KeySpec, ProviderClass, ProviderRef};
use keyrack_core::provider::software::{SoftwareProvider, SOFTWARE_WRAPPING_MECHANISM};
use keyrack_core::provider::{
    CryptoProvider, EncryptOutput, GeneratedWrappedKey, KeyHandle, ProviderCapabilities,
    SigningAlgorithm, WrappedKeyClosure, WrappedKeyLease,
};
use keyrack_core::registry::{ProviderEntry, ProviderRegistry, StaticProviderRegistry};
use keyrack_core::sensitive::Sensitive;
use keyrack_core::wrapping::{WrappingContext, WrappingIdentifier};
use keyrack_service::domain::{self, CreateKeyInput};
use keyrack_service::hierarchy::{WrappingProfile, WrappingProfiles};
use keyrack_service::proto;
use keyrack_service::proto::key_service_client::KeyServiceClient;
use keyrack_service::proto::key_service_server::KeyServiceServer;
use keyrack_service::routing::ProviderRouter;
use keyrack_service::state::ServiceState;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const DOMAIN: &str = "test-single-process";
const PROVIDER: &str = "default";
const PATIENCE: Duration = Duration::from_secs(10);

type CoreResult<T> = keyrack_core::error::Result<T>;

/// What the provider saw, in order.
#[derive(Debug, Clone)]
enum Event {
    Opened {
        key_id: String,
        handle: KeyHandle,
        object: String,
    },
    Closed {
        object: String,
        ok: bool,
    },
}

/// A thread-blocking gate. Work that reaches it waits on a blocking thread,
/// so dropping the future that started the work does not stop it.
#[derive(Default)]
struct Gate {
    held: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn hold(&self) {
        *self.held.lock().unwrap() = true;
    }

    fn release(&self) {
        *self.held.lock().unwrap() = false;
        self.changed.notify_all();
    }

    fn pass(&self) {
        let mut held = self.held.lock().unwrap();
        while *held {
            held = self.changed.wait(held).unwrap();
        }
    }
}

#[derive(Default)]
struct Controls {
    events: Mutex<Vec<Event>>,
    use_objects: Mutex<HashSet<String>>,
    open_gate: Gate,
    close_gate: Gate,
    /// Decrypt waits (cancellably) while this is held.
    decrypt_held: AtomicBool,
    decrypt_entered: tokio::sync::Notify,
    decrypt_released: tokio::sync::Notify,
    opens_started: AtomicUsize,
    closes_started: AtomicUsize,
    /// Fail the use open with this 1-based ordinal.
    fail_open: AtomicUsize,
    /// Fail the next use close once, leaving the object open.
    fail_next_close: AtomicBool,
    /// Panic in every use close, leaving the object open.
    panic_close: AtomicBool,
}

impl Controls {
    fn record(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }

    fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    fn opened(&self) -> Vec<(String, KeyHandle, String)> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                Event::Opened {
                    key_id,
                    handle,
                    object,
                } => Some((key_id, handle, object)),
                Event::Closed { .. } => None,
            })
            .collect()
    }

    fn closed_ok(&self, object: &str) -> bool {
        self.events()
            .iter()
            .any(|e| matches!(e, Event::Closed { object: o, ok: true } if o == object))
    }
}

/// The software provider behind blocking, uncancellable open and close.
struct Pausable {
    inner: Arc<SoftwareProvider>,
    controls: Arc<Controls>,
}

#[async_trait::async_trait]
impl CryptoProvider for Pausable {
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
        plaintext: &[u8],
        aad: &[u8],
    ) -> CoreResult<EncryptOutput> {
        self.inner.encrypt(handle, plaintext, aad).await
    }

    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> CoreResult<Sensitive<Vec<u8>>> {
        if self.controls.decrypt_held.load(Ordering::SeqCst) {
            let released = self.controls.decrypt_released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            if self.controls.decrypt_held.load(Ordering::SeqCst) {
                self.controls.decrypt_entered.notify_one();
                released.await;
            }
        }
        self.inner.decrypt(handle, ciphertext, aad).await
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
        let ordinal = self.controls.opens_started.fetch_add(1, Ordering::SeqCst) + 1;
        let (inner, controls) = (Arc::clone(&self.inner), Arc::clone(&self.controls));
        let (context, parent, envelope) = (context.clone(), parent.clone(), envelope.to_vec());
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            controls.open_gate.pass();
            if controls.fail_open.load(Ordering::SeqCst) == ordinal {
                return Err(keyrack_core::error::KeyRackError::Provider(
                    "injected open failure".into(),
                ));
            }
            let lease = runtime.block_on(inner.open_wrapped_key(&context, &parent, &envelope))?;
            let object = lease.object().as_str().to_owned();
            controls.use_objects.lock().unwrap().insert(object.clone());
            controls.record(Event::Opened {
                key_id: context.child.lid.to_string(),
                handle: lease.handle().clone(),
                object,
            });
            Ok(lease)
        })
        .await
        .expect("open thread")
    }

    async fn close_wrapped_key(&self, lease: &WrappedKeyLease) -> CoreResult<WrappedKeyClosure> {
        let object = lease.object().as_str().to_owned();
        if !self.controls.use_objects.lock().unwrap().contains(&object) {
            return self.inner.close_wrapped_key(lease).await;
        }
        self.controls.closes_started.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.controls.panic_close.load(Ordering::SeqCst),
            "injected close panic"
        );
        let (inner, controls, lease) = (
            Arc::clone(&self.inner),
            Arc::clone(&self.controls),
            lease.clone(),
        );
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            controls.close_gate.pass();
            if controls.fail_next_close.swap(false, Ordering::SeqCst) {
                controls.record(Event::Closed { object, ok: false });
                return Err(keyrack_core::error::KeyRackError::Provider(
                    "injected close failure".into(),
                ));
            }
            let closed = runtime.block_on(inner.close_wrapped_key(&lease));
            controls.record(Event::Closed {
                object,
                ok: closed.is_ok(),
            });
            closed
        })
        .await
        .expect("close thread")
    }
}

struct Service {
    state: Arc<ServiceState>,
    controls: Arc<Controls>,
    inner: Arc<SoftwareProvider>,
    grpc: String,
    rest: String,
}

fn identifier(value: &str) -> WrappingIdentifier {
    WrappingIdentifier::new(value).expect("valid identifier")
}

struct SilentAudit;

#[async_trait::async_trait]
impl keyrack_core::audit::AuditSink for SilentAudit {
    async fn emit(&self, _event: &keyrack_core::audit::AuditEvent) -> CoreResult<()> {
        Ok(())
    }
}

/// One recorder for the whole test binary, so service metrics can be read.
/// Tests run concurrently, so values are shared: check presence, not counts.
fn metrics() -> metrics_exporter_prometheus::PrometheusHandle {
    static HANDLE: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> =
        std::sync::OnceLock::new();
    HANDLE
        .get_or_init(|| {
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .install_recorder()
                .expect("the only recorder in this test binary")
        })
        .clone()
}

impl Service {
    async fn start() -> Self {
        Self::start_with_limit(keyrack_service::lease::DEFAULT_CLEANUP_LIMIT).await
    }

    async fn start_with_limit(limit: usize) -> Self {
        let inner = Arc::new(SoftwareProvider::scoped(
            ProviderRef::new(PROVIDER),
            identifier(DOMAIN),
        ));
        let controls = Arc::new(Controls::default());
        let provider: Arc<dyn CryptoProvider> = Arc::new(Pausable {
            inner: Arc::clone(&inner),
            controls: Arc::clone(&controls),
        });
        let registry: Arc<dyn ProviderRegistry> = Arc::new(
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
            .expect("registry"),
        );
        let state = Arc::new(ServiceState {
            storage: Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("SQLite")),
            providers: registry,
            provider_router: ProviderRouter::new(vec![], ProviderRef::new(PROVIDER)).unwrap(),
            pdp: Arc::new(keyrack_core::pdp::AlwaysAllow),
            audit: Arc::new(SilentAudit),
            authn: Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
                Box::new(keyrack_core::authn::InsecureAuthenticator),
            ])),
            metrics_handle: metrics(),
            max_plaintext_bytes: 4096,
            legacy_compromised_key_decrypt: false,
            nats_publisher: None,
            lease_cleanup: keyrack_service::lease::LeaseCleanup::new(limit),
            wrapping: WrappingProfiles::new([(
                ProviderRef::new(PROVIDER),
                WrappingProfile {
                    mechanism: identifier(SOFTWARE_WRAPPING_MECHANISM),
                    security_domain: identifier(DOMAIN),
                },
            )]),
        });

        let grpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let grpc = format!("http://{}", grpc_listener.local_addr().unwrap());
        let service = KeyServiceServer::new(keyrack_service::grpc::KeyServiceImpl::new(
            Arc::clone(&state),
        ));
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(
                    grpc_listener,
                )),
        );

        let rest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rest = format!("http://{}", rest_listener.local_addr().unwrap());
        let router = keyrack_service::rest::router(Arc::clone(&state));
        tokio::spawn(async move { axum::serve(rest_listener, router).await });

        Self {
            state,
            controls,
            inner,
            grpc,
            rest,
        }
    }

    async fn client(&self) -> KeyServiceClient<tonic::transport::Channel> {
        KeyServiceClient::connect(self.grpc.clone()).await.unwrap()
    }

    async fn child(&self) -> KeyRecord {
        let create = |parent: Option<String>| CreateKeyInput {
            key_spec: KeySpec::Aes256,
            attributes: BTreeMap::new(),
            namespace: String::new(),
            description: None,
            exportable: Exportability::NonExportable,
            parent_key_id: parent,
            hsm_connection_id: None,
            backend_id: None,
        };
        let parent = domain::create_key(&self.state, create(None))
            .await
            .expect("parent");
        domain::create_key(&self.state, create(Some(parent.lid.to_string())))
            .await
            .expect("wrapped child")
    }

    async fn encrypt(&self, key: &KeyRecord) -> Vec<u8> {
        self.client()
            .await
            .encrypt(proto::EncryptRequest {
                key_id: key.lid.to_string(),
                plaintext: b"wrapped child data".to_vec(),
                ..Default::default()
            })
            .await
            .expect("encrypt through a lease")
            .into_inner()
            .ciphertext_blob
    }

    /// The single use lease the provider has opened for `key` since `from`.
    fn lease_for(&self, key: &KeyRecord, from: usize) -> (KeyHandle, String) {
        let opened = self.controls.opened();
        let mut matching = opened[from..]
            .iter()
            .filter(|(key_id, ..)| *key_id == key.lid.to_string());
        let (_, handle, object) = matching.next().expect("a lease was opened");
        assert!(matching.next().is_none(), "exactly one lease opened");
        (handle.clone(), object.clone())
    }

    /// Wait for the provider to report `object` closed and the owner to record
    /// it, then confirm the handle it issued no longer operates.
    async fn assert_settled(&self, handle: &KeyHandle, object: &str, case: &str) {
        let recorded = || self.state.lease_cleanup.counts().closed_after_return >= 1;
        let closed = tokio::time::timeout(PATIENCE, async {
            while !(self.controls.closed_ok(object) && recorded()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok();
        let closed = closed || self.controls.closed_ok(object);
        let operable = self.inner.encrypt(handle, b"after", b"aad").await.is_ok();
        let counts = self.state.lease_cleanup.counts();
        assert!(
            closed && !operable,
            "{case}: the lease must be closed by the cleanup owner after cancellation \
             (closed: {closed}, still operable: {operable}, cleanup records: {counts:?})"
        );
        assert!(
            counts.scheduled >= 1 && counts.closed_after_return >= 1,
            "{case}: a close outside the request is recorded as an unverified cleanup outcome: \
             {counts:?}"
        );
    }

    /// Hold decrypt, wait until a request is inside it, and return the lease
    /// that request opened.
    async fn hold_decrypt_until_entered(
        &self,
        key: &KeyRecord,
        from: usize,
        request: tokio::task::JoinHandle<()>,
    ) -> (tokio::task::JoinHandle<()>, KeyHandle, String) {
        tokio::time::timeout(PATIENCE, self.controls.decrypt_entered.notified())
            .await
            .expect("the request reached the provider operation");
        let (handle, object) = self.lease_for(key, from);
        assert!(
            self.inner.encrypt(&handle, b"open", b"aad").await.is_ok(),
            "the lease is open while the operation runs"
        );
        (request, handle, object)
    }
}

/// Blocked provider threads would keep the test runtime from shutting down,
/// so a failing test must not leave a gate held.
impl Drop for Service {
    fn drop(&mut self) {
        self.controls.open_gate.release();
        self.controls.close_gate.release();
        self.controls.decrypt_held.store(false, Ordering::SeqCst);
        self.controls.decrypt_released.notify_waiters();
    }
}

fn rest_decrypt_body(blob: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    serde_json::json!({
        "ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(blob),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_client_deadline_closes_the_lease() {
    let service = Service::start().await;
    let key = service.child().await;
    let blob = service.encrypt(&key).await;
    let from = service.controls.opened().len();
    service.controls.decrypt_held.store(true, Ordering::SeqCst);

    let mut client = service.client().await;
    let lid = key.lid.to_string();
    let request = tokio::spawn(async move {
        let mut request = tonic::Request::new(proto::DecryptRequest {
            key_id: lid,
            ciphertext_blob: blob,
            ..Default::default()
        });
        request.set_timeout(Duration::from_millis(300));
        let status = client.decrypt(request).await.expect_err("deadline");
        assert!(
            matches!(
                status.code(),
                tonic::Code::DeadlineExceeded | tonic::Code::Cancelled
            ),
            "{status:?}"
        );
    });
    let (request, handle, object) = service
        .hold_decrypt_until_entered(&key, from, request)
        .await;
    request.await.expect("the client saw its deadline");

    service
        .assert_settled(&handle, &object, "gRPC client deadline")
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_client_disconnect_closes_the_lease() {
    let service = Service::start().await;
    let key = service.child().await;
    let blob = service.encrypt(&key).await;
    let from = service.controls.opened().len();
    service.controls.decrypt_held.store(true, Ordering::SeqCst);

    let mut client = service.client().await;
    let lid = key.lid.to_string();
    let request = tokio::spawn(async move {
        let _ = client
            .decrypt(proto::DecryptRequest {
                key_id: lid,
                ciphertext_blob: blob,
                ..Default::default()
            })
            .await;
    });
    let (request, handle, object) = service
        .hold_decrypt_until_entered(&key, from, request)
        .await;
    request.abort();
    let _ = request.await;

    service
        .assert_settled(&handle, &object, "gRPC client disconnect")
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rest_client_timeout_closes_the_lease() {
    let service = Service::start().await;
    let key = service.child().await;
    let blob = service.encrypt(&key).await;
    let from = service.controls.opened().len();
    service.controls.decrypt_held.store(true, Ordering::SeqCst);

    let url = format!("{}/v1/keys/{}/actions-decrypt", service.rest, key.lid);
    let request = tokio::spawn(async move {
        let error = reqwest::Client::builder()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap()
            .post(url)
            .json(&rest_decrypt_body(&blob))
            .send()
            .await
            .expect_err("client timeout");
        assert!(error.is_timeout(), "{error}");
    });
    let (request, handle, object) = service
        .hold_decrypt_until_entered(&key, from, request)
        .await;
    request.await.expect("the client timed out");

    service
        .assert_settled(&handle, &object, "REST client timeout")
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rest_client_disconnect_closes_the_lease() {
    let service = Service::start().await;
    let key = service.child().await;
    let blob = service.encrypt(&key).await;
    let from = service.controls.opened().len();
    service.controls.decrypt_held.store(true, Ordering::SeqCst);

    let url = format!("{}/v1/keys/{}/actions-decrypt", service.rest, key.lid);
    let request = tokio::spawn(async move {
        let _ = reqwest::Client::new()
            .post(url)
            .json(&rest_decrypt_body(&blob))
            .send()
            .await;
    });
    let (request, handle, object) = service
        .hold_decrypt_until_entered(&key, from, request)
        .await;
    request.abort();
    let _ = request.await;

    service
        .assert_settled(&handle, &object, "REST client disconnect")
        .await;
}

/// A deadline that expires while the provider is still opening: the open
/// cannot be stopped, so the lease it produces must still be closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_during_a_blocking_open_closes_the_lease_it_produces() {
    let service = Service::start().await;
    let key = service.child().await;
    let blob = service.encrypt(&key).await;
    let from = service.controls.opened().len();
    let started = service.controls.opens_started.load(Ordering::SeqCst);
    service.controls.open_gate.hold();

    let mut client = service.client().await;
    let mut request = tonic::Request::new(proto::DecryptRequest {
        key_id: key.lid.to_string(),
        ciphertext_blob: blob,
        ..Default::default()
    });
    request.set_timeout(Duration::from_millis(300));
    let status = client.decrypt(request).await.expect_err("deadline");
    assert_eq!(
        service.controls.opens_started.load(Ordering::SeqCst),
        started + 1,
        "the deadline expired during the open: {status:?}"
    );
    service.controls.open_gate.release();

    let opened = tokio::time::timeout(PATIENCE, async {
        while service.controls.opened().len() == from {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(opened.is_ok(), "the provider finished the open");
    let (handle, object) = service.lease_for(&key, from);
    service
        .assert_settled(&handle, &object, "cancellation during open")
        .await;
}

/// Re-encrypt between two wrapped keys: the source lease is closed before the
/// destination lease is opened, so the two are never open together.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn re_encrypt_closes_the_source_lease_before_opening_the_destination() {
    let service = Service::start().await;
    let source = service.child().await;
    let destination = service.child().await;
    let blob = service.encrypt(&source).await;
    let from = service.controls.events().len();

    service
        .client()
        .await
        .re_encrypt(proto::ReEncryptRequest {
            source_key_id: source.lid.to_string(),
            destination_key_id: destination.lid.to_string(),
            ciphertext_blob: blob,
            ..Default::default()
        })
        .await
        .expect("re-encrypt between wrapped keys");

    let events = service.controls.events()[from..].to_vec();
    let position = |wanted: &dyn Fn(&Event) -> bool| events.iter().position(wanted);
    let source_object = events.iter().find_map(|e| match e {
        Event::Opened { key_id, object, .. } if *key_id == source.lid.to_string() => {
            Some(object.clone())
        }
        _ => None,
    });
    let source_object = source_object.expect("source opened");
    let source_closed =
        position(&|e| matches!(e, Event::Closed { object, ok: true } if *object == source_object));
    let destination_opened = position(
        &|e| matches!(e, Event::Opened { key_id, .. } if *key_id == destination.lid.to_string()),
    );
    assert!(
        matches!((source_closed, destination_opened), (Some(c), Some(o)) if c < o),
        "the source lease must be closed before the destination opens: {events:?}"
    );
}

/// The source close fails. The failure must reach the caller, not be
/// discarded or replaced by a later error, the destination must never be
/// opened, and the source lease is still owed a close, which the cleanup owner
/// retries. The destination's open is set to fail so that an implementation
/// that opens it anyway shows that error instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_source_close_is_reported_and_retried() {
    let service = Service::start().await;
    let source = service.child().await;
    let destination = service.child().await;
    let blob = service.encrypt(&source).await;
    let from = service.controls.opened().len();
    let opens = service.controls.opens_started.load(Ordering::SeqCst);
    service
        .controls
        .fail_open
        .store(opens + 2, Ordering::SeqCst);
    service
        .controls
        .fail_next_close
        .store(true, Ordering::SeqCst);

    let status = service
        .client()
        .await
        .re_encrypt(proto::ReEncryptRequest {
            source_key_id: source.lid.to_string(),
            destination_key_id: destination.lid.to_string(),
            ciphertext_blob: blob,
            ..Default::default()
        })
        .await
        .expect_err("re-encrypt must fail");
    let (handle, object) = service.lease_for(&source, from);
    assert!(
        status.message().contains("injected close failure"),
        "the failed source close must be returned, not discarded: {status:?}"
    );
    let destination_opens = service.controls.opened()[from..]
        .iter()
        .filter(|(key_id, ..)| *key_id == destination.lid.to_string())
        .count();
    assert_eq!(
        (
            service.controls.opens_started.load(Ordering::SeqCst) - opens,
            destination_opens
        ),
        (1, 0),
        "after a failed source close the destination lease is never opened"
    );
    service
        .assert_settled(&handle, &object, "failed source close")
        .await;
}

/// Cancellations are cheap for a client (a short `grpc-timeout`), so the
/// closes they leave behind are bounded: at the limit, new uses of wrapped
/// keys are refused as unavailable, without opening anything, until the
/// backlog drains.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrapped_use_is_refused_while_the_cleanup_backlog_is_full() {
    let service = Service::start_with_limit(1).await;
    let key = service.child().await;
    let blob = service.encrypt(&key).await;
    cancel_with_close_pending(&service).await;
    assert_eq!(
        service.state.lease_cleanup.pending(),
        1,
        "the backlog is full"
    );
    let opens = service.controls.opens_started.load(Ordering::SeqCst);

    let mut request = tonic::Request::new(proto::DecryptRequest {
        key_id: key.lid.to_string(),
        ciphertext_blob: blob.clone(),
        ..Default::default()
    });
    request.set_timeout(Duration::from_secs(2));
    let status = service
        .client()
        .await
        .decrypt(request)
        .await
        .expect_err("refused at the limit");
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status:?}");
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap()
        .post(format!(
            "{}/v1/keys/{}/actions-decrypt",
            service.rest, key.lid
        ))
        .json(&rest_decrypt_body(&blob))
        .send()
        .await
        .expect("REST answers at the limit");
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        service.controls.opens_started.load(Ordering::SeqCst),
        opens,
        "nothing is opened at the limit"
    );
    assert!(
        metrics()
            .render()
            .contains("keyrack_wrapped_lease_cleanup_pending"),
        "the backlog is exposed as a metric"
    );

    service.controls.close_gate.release();
    let drained = tokio::time::timeout(PATIENCE, async {
        while service.state.lease_cleanup.pending() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "the backlog drains once the close finishes"
    );
    service
        .client()
        .await
        .decrypt(proto::DecryptRequest {
            key_id: key.lid.to_string(),
            ciphertext_blob: blob,
            ..Default::default()
        })
        .await
        .expect("uses resume once the backlog is below the limit");
}

/// A close that panics in the provider still settles: it is recorded as a
/// failed cleanup, and nothing is left pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_panicking_detached_close_is_recorded_as_failed() {
    let service = Service::start().await;
    let key = service.child().await;
    let blob = service.encrypt(&key).await;
    let from = service.controls.opened().len();
    service.controls.decrypt_held.store(true, Ordering::SeqCst);
    service.controls.panic_close.store(true, Ordering::SeqCst);

    let mut client = service.client().await;
    let lid = key.lid.to_string();
    let request = tokio::spawn(async move {
        let mut request = tonic::Request::new(proto::DecryptRequest {
            key_id: lid,
            ciphertext_blob: blob,
            ..Default::default()
        });
        request.set_timeout(Duration::from_millis(300));
        let _ = client.decrypt(request).await;
    });
    let (request, ..) = service
        .hold_decrypt_until_entered(&key, from, request)
        .await;
    request.await.expect("the client saw its deadline");

    let owner = &service.state.lease_cleanup;
    let _ = tokio::time::timeout(PATIENCE, async {
        while owner.counts().close_failed == 0 || owner.pending() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let counts = owner.counts();
    assert_eq!(
        (
            counts.close_failed,
            counts.closed_after_return,
            owner.pending()
        ),
        (1, 0, 0),
        "a panicked close is recorded as failed, not left pending: {counts:?}"
    );
}

/// Cancel a decrypt while its close is blocked in the provider, so the close
/// is still pending when shutdown begins. Returns the lease object.
async fn cancel_with_close_pending(service: &Service) -> String {
    let key = service.child().await;
    let blob = service.encrypt(&key).await;
    let from = service.controls.opened().len();
    let closes = service.controls.closes_started.load(Ordering::SeqCst);
    service.controls.close_gate.hold();

    let mut client = service.client().await;
    let mut request = tonic::Request::new(proto::DecryptRequest {
        key_id: key.lid.to_string(),
        ciphertext_blob: blob,
        ..Default::default()
    });
    request.set_timeout(Duration::from_millis(300));
    let status = client.decrypt(request).await.expect_err("deadline");
    assert_eq!(
        service.controls.closes_started.load(Ordering::SeqCst),
        closes + 1,
        "the deadline expired during the close: {status:?}"
    );
    // The client gives up on its own deadline, a moment before the server
    // drops the request and hands its close to the owner.
    let handed_over = tokio::time::timeout(PATIENCE, async {
        while service.state.lease_cleanup.pending() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(handed_over.is_ok(), "the cancelled close reached the owner");
    service.lease_for(&key, from).1
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_abandons_a_close_still_pending_at_its_deadline() {
    let service = Service::start().await;
    let object = cancel_with_close_pending(&service).await;

    let budget = Duration::from_millis(500);
    let started = tokio::time::Instant::now();
    let report = keyrack_service::shutdown::drain(&service.state, async {}, budget).await;
    let took = started.elapsed();
    service.controls.close_gate.release();

    assert!(
        took < budget + Duration::from_millis(250),
        "the drain keeps its deadline: {took:?}"
    );
    assert_eq!(
        (report.cleanups_abandoned, service.state.lease_cleanup.counts().abandoned),
        (1, 1),
        "the close pending at the deadline is recorded as abandoned, not closed: {report:?} {object}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_waits_for_a_pending_close_within_its_deadline() {
    let service = Service::start().await;
    let object = cancel_with_close_pending(&service).await;

    let controls = Arc::clone(&service.controls);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        controls.close_gate.release();
    });
    let report =
        keyrack_service::shutdown::drain(&service.state, async {}, Duration::from_secs(5)).await;

    assert!(
        service.controls.closed_ok(&object),
        "the drain returned before the pending close finished: {report:?}"
    );
    let counts = service.state.lease_cleanup.counts();
    assert_eq!(
        (
            report.cleanups_abandoned,
            counts.abandoned,
            counts.closed_after_return
        ),
        (0, 0, 1),
        "a close that finishes inside the deadline is recorded once, as closed after return: \
         {counts:?}"
    );
}
