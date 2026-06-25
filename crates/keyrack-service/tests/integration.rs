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

//! Integration tests that validate the systemic fixes:
//!
//! 1. PDP authorization is enforced on every handler.
//! 2. Audit events are emitted for every operation.
//! 3. Each `CreateKey` produces a unique LID.
//! 4. Bootstrap token uses constant-time comparison.
//! 5. REST crypto handlers are concrete (not 501 stubs).

use keyrack_core::audit::{AuditEvent, AuditSink};
use keyrack_core::pdp::{
    AlwaysAllow, AlwaysDeny, AuthzRequest, AuthzResponse, PolicyDecisionPoint,
};
use keyrack_core::provider::inmem::InMemoryProvider;
use keyrack_core::provider::CryptoProvider as _;
use keyrack_service::proto;
use keyrack_service::proto::key_service_server::KeyService;
use keyrack_service::state::ServiceState;
use std::sync::{Arc, Mutex};
use tonic::Request;

use base64::Engine as _;

/// Audit sink that captures events for test assertions.
struct CapturingSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl CapturingSink {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().unwrap().clone()
    }

    fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl AuditSink for CapturingSink {
    async fn emit(&self, event: &AuditEvent) -> keyrack_core::error::Result<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}

/// PDP that tracks how many times `evaluate` was called.
struct CountingPdp {
    inner: AlwaysAllow,
    call_count: Mutex<usize>,
}

impl CountingPdp {
    fn new() -> Self {
        Self {
            inner: AlwaysAllow,
            call_count: Mutex::new(0),
        }
    }

    fn count(&self) -> usize {
        *self.call_count.lock().unwrap()
    }
}

#[async_trait::async_trait]
impl PolicyDecisionPoint for CountingPdp {
    async fn evaluate(&self, request: &AuthzRequest) -> keyrack_core::error::Result<AuthzResponse> {
        *self.call_count.lock().unwrap() += 1;
        self.inner.evaluate(request).await
    }
}

fn build_test_state_with(
    pdp: Arc<dyn PolicyDecisionPoint>,
    audit: Arc<dyn AuditSink>,
) -> Arc<ServiceState> {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::StaticProviderRegistry;
    use keyrack_service::routing::ProviderRouter;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let provider = Arc::new(InMemoryProvider::new());
    let providers = Arc::new(StaticProviderRegistry::single(
        provider,
        ProviderClass::InMemory,
    ));
    let provider_router = ProviderRouter::new(vec![], ProviderRef::new("default"));
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(keyrack_core::authn::InsecureAuthenticator),
    ]));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    Arc::new(ServiceState {
        storage,
        providers,
        provider_router,
        pdp,
        audit,
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    })
}

fn build_test_state() -> (Arc<ServiceState>, Arc<CountingPdp>, Arc<CapturingSink>) {
    let pdp = Arc::new(CountingPdp::new());
    let audit = Arc::new(CapturingSink::new());
    let state = build_test_state_with(pdp.clone(), audit.clone());
    (state, pdp, audit)
}

// ═══════════════════════════════════════════════════════════════════
// 1. PDP AUTHORIZATION IS ENFORCED
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn create_key_calls_pdp() {
    let (state, pdp, _audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let req = Request::new(proto::CreateKeyRequest {
        key_spec: proto::KeySpec::Aes256.into(),
        description: "test".into(),
        ..Default::default()
    });

    let resp = svc.create_key(req).await;
    assert!(
        resp.is_ok(),
        "create_key should succeed with AlwaysAllow PDP"
    );
    assert!(
        pdp.count() >= 1,
        "PDP must be called at least once for CreateKey"
    );
}

#[tokio::test]
async fn encrypt_calls_pdp() {
    let (state, pdp, _audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let key = create_aes_key(&svc).await;

    let req = Request::new(proto::EncryptRequest {
        key_id: key.clone(),
        plaintext: b"hello".to_vec(),
        ..Default::default()
    });
    let _ = svc.encrypt(req).await;
    assert!(
        pdp.count() >= 2,
        "PDP must be called for CreateKey + Encrypt (got {})",
        pdp.count()
    );
}

#[tokio::test]
async fn denied_pdp_blocks_create_key() {
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysDeny);
    let audit = Arc::new(CapturingSink::new());
    let state = build_test_state_with(pdp, audit.clone());
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let req = Request::new(proto::CreateKeyRequest {
        key_spec: proto::KeySpec::Aes256.into(),
        description: "denied".into(),
        ..Default::default()
    });

    let resp = svc.create_key(req).await;
    assert!(resp.is_err(), "create_key must fail when PDP denies");
    let status = resp.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    // Audit should still emit even for denied operations
    assert!(
        audit.event_count() >= 1,
        "audit event must still be emitted for denied ops"
    );
}

#[tokio::test]
async fn denied_pdp_blocks_encrypt() {
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysDeny);
    let audit = Arc::new(CapturingSink::new());
    let state = build_test_state_with(pdp, audit.clone());
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let req = Request::new(proto::EncryptRequest {
        key_id: "lid_".to_owned() + &"ab".repeat(32),
        plaintext: b"hello".to_vec(),
        ..Default::default()
    });

    let resp = svc.encrypt(req).await;
    assert!(resp.is_err());
    assert_eq!(resp.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn denied_pdp_blocks_get_key() {
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysDeny);
    let audit = Arc::new(CapturingSink::new());
    let state = build_test_state_with(pdp, audit);
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let req = Request::new(proto::GetKeyRequest {
        key_id: "lid_".to_owned() + &"ab".repeat(32),
    });
    let resp = svc.get_key(req).await;
    assert!(resp.is_err());
    assert_eq!(resp.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn denied_pdp_blocks_tag_resource() {
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysDeny);
    let audit = Arc::new(CapturingSink::new());
    let state = build_test_state_with(pdp, audit);
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let req = Request::new(proto::TagResourceRequest {
        key_id: "lid_".to_owned() + &"ab".repeat(32),
        tags: vec![proto::Tag {
            key: "env".into(),
            value: "test".into(),
        }],
    });
    let resp = svc.tag_resource(req).await;
    assert!(resp.is_err());
    assert_eq!(resp.unwrap_err().code(), tonic::Code::PermissionDenied);
}

// ═══════════════════════════════════════════════════════════════════
// 2. AUDIT EVENTS ARE EMITTED
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn create_key_emits_audit_event() {
    let (state, _pdp, audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let req = Request::new(proto::CreateKeyRequest {
        key_spec: proto::KeySpec::Aes256.into(),
        description: "audit test".into(),
        ..Default::default()
    });
    let _ = svc.create_key(req).await.expect("should succeed");
    assert_eq!(
        audit.event_count(),
        1,
        "exactly one audit event for one CreateKey"
    );

    let events = audit.events();
    assert_eq!(
        events[0].action,
        keyrack_core::audit::AuditAction::CreateKey,
        "event action must be CreateKey"
    );
    assert_eq!(events[0].result, keyrack_core::audit::AuditResult::Success);
}

#[tokio::test]
async fn encrypt_decrypt_emits_audit_events() {
    let (state, _pdp, audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let key = create_aes_key(&svc).await;
    let initial_count = audit.event_count();

    let enc_req = Request::new(proto::EncryptRequest {
        key_id: key.clone(),
        plaintext: b"test-data".to_vec(),
        ..Default::default()
    });
    let enc_resp = svc.encrypt(enc_req).await.expect("encrypt should succeed");
    assert_eq!(
        audit.event_count(),
        initial_count + 1,
        "encrypt must emit audit event"
    );

    let events = audit.events();
    let enc_event = events.last().unwrap();
    assert_eq!(enc_event.action, keyrack_core::audit::AuditAction::Encrypt);

    let dec_req = Request::new(proto::DecryptRequest {
        key_id: key,
        ciphertext_blob: enc_resp.into_inner().ciphertext_blob,
        ..Default::default()
    });
    let _ = svc.decrypt(dec_req).await.expect("decrypt should succeed");
    assert_eq!(
        audit.event_count(),
        initial_count + 2,
        "decrypt must emit audit event"
    );
}

#[tokio::test]
async fn multiple_operations_emit_correct_event_count() {
    let (state, pdp, audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let key = create_aes_key(&svc).await;
    let _ = svc
        .get_key(Request::new(proto::GetKeyRequest {
            key_id: key.clone(),
        }))
        .await;
    let _ = svc
        .describe_key(Request::new(proto::DescribeKeyRequest {
            key_id: key.clone(),
        }))
        .await;
    let _ = svc
        .disable_key(Request::new(proto::DisableKeyRequest { key_id: key }))
        .await;

    // CreateKey + GetKey + DescribeKey + DisableKey = 4
    assert_eq!(audit.event_count(), 4, "4 operations = 4 audit events");
    // PDP must also have been called 4 times
    assert_eq!(pdp.count(), 4, "4 operations = 4 PDP evaluations");
}

// ═══════════════════════════════════════════════════════════════════
// 3. EACH CREATE_KEY PRODUCES A UNIQUE LID
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn create_key_produces_unique_lids() {
    let (state, _pdp, _audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let mut lids = std::collections::HashSet::new();
    for i in 0..10 {
        let req = Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: format!("key-{i}"),
            ..Default::default()
        });
        let resp = svc.create_key(req).await.expect("create should succeed");
        let metadata = resp.into_inner().metadata.expect("metadata present");
        let key_id = metadata.key_id;
        assert!(
            lids.insert(key_id.clone()),
            "LID collision detected: {key_id} was already returned by a previous CreateKey"
        );
    }
    assert_eq!(lids.len(), 10, "10 creates must produce 10 distinct LIDs");
}

#[tokio::test]
async fn create_key_lid_not_empty_and_prefixed() {
    let (state, _pdp, _audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let req = Request::new(proto::CreateKeyRequest {
        key_spec: proto::KeySpec::Aes256.into(),
        description: "prefix check".into(),
        ..Default::default()
    });
    let resp = svc.create_key(req).await.expect("should succeed");
    let key_id = resp.into_inner().metadata.unwrap().key_id;
    assert!(key_id.starts_with("lid_"), "LID must start with 'lid_'");
    assert_eq!(key_id.len(), 68, "LID must be 4 + 64 hex chars = 68");
}

// ═══════════════════════════════════════════════════════════════════
// 4. FULL LIFECYCLE WITH PDP + AUDIT
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn full_lifecycle_pdp_and_audit() {
    let (state, pdp, audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    // Create
    let key = create_aes_key(&svc).await;
    assert_eq!(pdp.count(), 1);
    assert_eq!(audit.event_count(), 1);

    // Encrypt
    let enc = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: key.clone(),
            plaintext: b"secret".to_vec(),
            ..Default::default()
        }))
        .await
        .expect("encrypt");
    assert_eq!(pdp.count(), 2);
    assert_eq!(audit.event_count(), 2);

    // Decrypt
    let _ = svc
        .decrypt(Request::new(proto::DecryptRequest {
            key_id: key.clone(),
            ciphertext_blob: enc.into_inner().ciphertext_blob,
            ..Default::default()
        }))
        .await
        .expect("decrypt");
    assert_eq!(pdp.count(), 3);
    assert_eq!(audit.event_count(), 3);

    // Tag
    let _ = svc
        .tag_resource(Request::new(proto::TagResourceRequest {
            key_id: key.clone(),
            tags: vec![proto::Tag {
                key: "env".into(),
                value: "test".into(),
            }],
        }))
        .await
        .expect("tag");
    assert_eq!(pdp.count(), 4);
    assert_eq!(audit.event_count(), 4);

    // Disable
    let _ = svc
        .disable_key(Request::new(proto::DisableKeyRequest { key_id: key }))
        .await
        .expect("disable");
    assert_eq!(pdp.count(), 5);
    assert_eq!(audit.event_count(), 5);

    // Verify audit actions recorded correctly
    let events = audit.events();
    let actions: Vec<_> = events.iter().map(|e| &e.action).collect();
    assert_eq!(
        actions,
        vec![
            &keyrack_core::audit::AuditAction::CreateKey,
            &keyrack_core::audit::AuditAction::Encrypt,
            &keyrack_core::audit::AuditAction::Decrypt,
            &keyrack_core::audit::AuditAction::TagResource,
            &keyrack_core::audit::AuditAction::DisableKey,
        ]
    );
}

// ═══════════════════════════════════════════════════════════════════
// 5. SIGN / VERIFY LIFECYCLE
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sign_verify_with_pdp_and_audit() {
    let (state, pdp, audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let req = Request::new(proto::CreateKeyRequest {
        key_spec: proto::KeySpec::Ed25519.into(),
        description: "signing key".into(),
        ..Default::default()
    });
    let resp = svc.create_key(req).await.expect("create ed25519 key");
    let key_id = resp.into_inner().metadata.unwrap().key_id;

    let sign_resp = svc
        .sign(Request::new(proto::SignRequest {
            key_id: key_id.clone(),
            message: b"data-to-sign".to_vec(),
            signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
            message_type: proto::MessageType::Raw.into(),
        }))
        .await
        .expect("sign");

    let verify_resp = svc
        .verify(Request::new(proto::VerifyRequest {
            key_id: key_id.clone(),
            message: b"data-to-sign".to_vec(),
            signature: sign_resp.into_inner().signature,
            signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
            message_type: proto::MessageType::Raw.into(),
        }))
        .await
        .expect("verify");

    assert!(verify_resp.into_inner().signature_valid);
    assert_eq!(pdp.count(), 3, "Create + Sign + Verify = 3 PDP calls");
    assert_eq!(
        audit.event_count(),
        3,
        "Create + Sign + Verify = 3 audit events"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 6. ALIAS OPERATIONS WITH PDP + AUDIT
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn alias_operations_with_pdp_and_audit() {
    let (state, pdp, audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let key = create_aes_key(&svc).await;
    let initial_pdp = pdp.count();
    let initial_audit = audit.event_count();

    let _ = svc
        .create_alias(Request::new(proto::CreateAliasRequest {
            alias_name: "alias/test".into(),
            target_key_id: key,
        }))
        .await
        .expect("create alias");

    let _ = svc
        .list_aliases(Request::new(proto::ListAliasesRequest::default()))
        .await
        .expect("list aliases");

    let _ = svc
        .delete_alias(Request::new(proto::DeleteAliasRequest {
            alias_name: "alias/test".into(),
        }))
        .await
        .expect("delete alias");

    assert_eq!(pdp.count() - initial_pdp, 3, "3 alias ops = 3 PDP calls");
    assert_eq!(
        audit.event_count() - initial_audit,
        3,
        "3 alias ops = 3 audit events"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 7. ENCRYPT WITH ENCRYPTION CONTEXT → AUDIT HASH
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn encrypt_with_ec_emits_audit_with_hash() {
    let (state, _pdp, audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let key = create_aes_key(&svc).await;

    let mut ec = std::collections::HashMap::new();
    ec.insert("tenant".to_string(), "acme-corp".to_string());

    let _ = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: key,
            plaintext: b"hello".to_vec(),
            encryption_context: ec,
        }))
        .await
        .expect("encrypt with EC");

    let events = audit.events();
    let encrypt_event = events
        .iter()
        .find(|e| e.action == keyrack_core::audit::AuditAction::Encrypt);
    assert!(
        encrypt_event.is_some(),
        "should have an Encrypt audit event"
    );
    assert!(
        encrypt_event.unwrap().encryption_context_hash.is_some(),
        "Encrypt with EC must include encryption_context_hash in audit"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 8. KEY VERSIONS
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn list_key_versions() {
    let (state, _pdp, _audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let key = create_aes_key(&svc).await;

    let resp = svc
        .list_key_versions(Request::new(proto::ListKeyVersionsRequest {
            key_id: key,
            ..Default::default()
        }))
        .await
        .expect("list versions");

    let versions = resp.into_inner().versions;
    assert!(
        !versions.is_empty(),
        "new key should have at least one version"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 9. NAMESPACE OPERATIONS (PDP + Audit)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn namespace_operations_call_pdp_and_audit() {
    let (state, pdp, audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let _ = svc
        .register_namespace(Request::new(proto::RegisterNamespaceRequest {
            name: "test-ns".into(),
            yaml_config: "rules: []".into(),
        }))
        .await
        .expect("register namespace");

    assert!(pdp.count() >= 1, "PDP must be called for RegisterNamespace");
    assert!(
        audit.event_count() >= 1,
        "audit event must be emitted for RegisterNamespace"
    );

    let _ = svc
        .list_namespaces(Request::new(proto::ListNamespacesRequest::default()))
        .await
        .expect("list namespaces");

    assert!(pdp.count() >= 2, "PDP must be called for ListNamespaces");
}

// ═══════════════════════════════════════════════════════════════════
// 10. DESCRIBE KEY RETURNS METADATA
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn describe_key_returns_full_metadata() {
    let (state, _pdp, _audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let key = create_aes_key(&svc).await;

    let resp = svc
        .describe_key(Request::new(proto::DescribeKeyRequest {
            key_id: key.clone(),
        }))
        .await
        .expect("describe key");

    let meta = resp
        .into_inner()
        .metadata
        .expect("metadata must be present");
    assert_eq!(meta.key_id, key);
    assert_eq!(meta.description, "test key");
    assert_eq!(meta.key_spec, i32::from(proto::KeySpec::Aes256));
    assert!(meta.created_at.is_some());
}

// ═══════════════════════════════════════════════════════════════════
// 11. GENERATE DATA KEY
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn generate_data_key_returns_both_keys() {
    let (state, _pdp, _audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let key = create_aes_key(&svc).await;

    let resp = svc
        .generate_data_key(Request::new(proto::GenerateDataKeyRequest {
            key_id: key.clone(),
            ..Default::default()
        }))
        .await
        .expect("generate data key");

    let inner = resp.into_inner();
    assert!(
        !inner.plaintext_data_key.is_empty(),
        "plaintext key must be non-empty"
    );
    assert!(
        !inner.encrypted_data_key.is_empty(),
        "encrypted key must be non-empty"
    );
    assert_eq!(inner.key_id, key);
}

// ═══════════════════════════════════════════════════════════════════
// Provider Routing Tests
// ═══════════════════════════════════════════════════════════════════

/// Build a two-provider `ServiceState` with optional routing rules.
/// Provider "default" is an `InMemoryProvider`; "tenant-b" is another `InMemoryProvider`.
fn build_two_provider_state(
    routing_rules: Vec<(
        std::collections::BTreeMap<String, String>,
        keyrack_core::key::ProviderRef,
    )>,
) -> Arc<ServiceState> {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::{ProviderEntry, StaticProviderRegistry};
    use keyrack_service::routing::ProviderRouter;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let prov_default = Arc::new(InMemoryProvider::new());
    let prov_tenant_b = Arc::new(InMemoryProvider::new());

    let registry = Arc::new(
        StaticProviderRegistry::new(
            [
                (
                    ProviderRef::new("default"),
                    ProviderEntry {
                        provider: prov_default,
                        class: ProviderClass::InMemory,
                    },
                ),
                (
                    ProviderRef::new("tenant-b"),
                    ProviderEntry {
                        provider: prov_tenant_b,
                        class: ProviderClass::InMemory,
                    },
                ),
            ],
            ProviderRef::new("default"),
        )
        .expect("valid registry"),
    );

    let default_ref = ProviderRef::new("default");
    let provider_router = ProviderRouter::new(routing_rules, default_ref);

    let pdp: Arc<dyn keyrack_core::pdp::PolicyDecisionPoint> =
        Arc::new(keyrack_core::pdp::AlwaysAllow);
    let audit: Arc<dyn AuditSink> = Arc::new(CapturingSink::new());
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(keyrack_core::authn::InsecureAuthenticator),
    ]));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    Arc::new(ServiceState {
        storage,
        providers: registry,
        provider_router,
        pdp,
        audit,
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    })
}

/// 1. Key with no matching rule → default provider; encrypt/decrypt round-trips.
#[tokio::test]
async fn routing_no_match_uses_default_provider() {
    use keyrack_core::key::ProviderRef;
    let state = build_two_provider_state(vec![]);
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let key_id = create_aes_key(&svc).await;

    // The record should be bound to the "default" provider.
    let lid: keyrack_core::lid::Lid = key_id.parse().expect("valid lid");
    let record = state.storage.get_key(&lid).await.expect("key exists");
    assert_eq!(record.provider_ref, Some(ProviderRef::new("default")));
    assert_eq!(
        record.key_versions[0].provider_ref,
        Some(ProviderRef::new("default"))
    );

    // Encrypt/decrypt round-trip.
    let pt = b"hello routing";
    let enc = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: key_id.clone(),
            plaintext: pt.to_vec(),
            ..Default::default()
        }))
        .await
        .expect("encrypt ok")
        .into_inner();

    let dec = svc
        .decrypt(Request::new(proto::DecryptRequest {
            key_id: key_id.clone(),
            ciphertext_blob: enc.ciphertext_blob,
            ..Default::default()
        }))
        .await
        .expect("decrypt ok")
        .into_inner();

    assert_eq!(dec.plaintext, pt.to_vec());
}

/// 2. Key whose identity tags match a routing rule → bound to "tenant-b"; round-trips.
///
/// This exercises the router selection + provider binding directly through the
/// domain layer with controlled attrs. (The full create-handler path is covered
/// end-to-end by `routing_create_with_attributes_routes_to_tenant_b`.)
#[tokio::test]
async fn routing_matching_rule_selects_tenant_b() {
    use keyrack_core::key::ProviderRef;
    use std::collections::BTreeMap;

    // Rule: if identity tag `tenant` == `acme`, use "tenant-b".
    let mut match_tags = BTreeMap::new();
    match_tags.insert("tenant".into(), "acme".into());
    let state = build_two_provider_state(vec![(match_tags, ProviderRef::new("tenant-b"))]);

    // Build identity tags that match the rule.
    let mut attrs = keyrack_core::attr::AttributeSet::new();
    attrs.insert(
        "tenant",
        keyrack_core::attr::AttributeValue::String("acme".into()),
    );
    let identity_tags = keyrack_core::tags::IdentityTags::from_attribute_set(&attrs);

    let selected = state.provider_router.select(&identity_tags);
    assert_eq!(selected, ProviderRef::new("tenant-b"));

    // Resolve the provider and generate a key on it.
    let entry = state
        .providers
        .resolve(&selected)
        .expect("tenant-b resolves");
    let handle = entry
        .provider
        .generate_key(&keyrack_core::key::KeySpec::Aes256)
        .await
        .expect("generate_key ok");

    // Build a record manually with the correct provider binding.
    let now = chrono::Utc::now();
    let mut attrs2 = keyrack_core::attr::AttributeSet::new();
    attrs2.insert(
        "_keyrack_key_id",
        keyrack_core::attr::AttributeValue::String(uuid::Uuid::new_v4().to_string()),
    );
    attrs2.insert(
        "tenant",
        keyrack_core::attr::AttributeValue::String("acme".into()),
    );
    let canonical = keyrack_core::canon::canonicalize(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &attrs2,
    );
    let lid = keyrack_core::lid::Lid::derive(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &canonical,
    );
    let record = keyrack_core::key::KeyRecord {
        lid,
        canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
        parent_lid: None,
        occ_version: 1,
        current_key_version: 1,
        state: keyrack_core::key::KeyState::Enabled,
        key_usage: keyrack_core::key::KeyUsage::EncryptDecrypt,
        key_spec: keyrack_core::key::KeySpec::Aes256,
        origin: keyrack_core::key::KeyOrigin::KeyRack,
        provider_class: entry.class,
        provider_ref: Some(selected.clone()),
        identity_tags: identity_tags.clone(),
        user_tags: keyrack_core::tags::UserTags::new(),
        created_at: now,
        updated_at: now,
        scheduled_deletion_at: None,
        description: "routing test".into(),
        key_versions: vec![keyrack_core::key::KeyVersionRecord {
            version_number: 1,
            key_handle: handle,
            provider_ref: Some(selected.clone()),
            created_at: now,
            is_primary: true,
        }],
    };
    state.storage.create_key(&record).await.expect("created");

    // Verify the record is bound to tenant-b.
    let fetched = state.storage.get_key(&lid).await.expect("found");
    assert_eq!(fetched.provider_ref, Some(ProviderRef::new("tenant-b")));
    assert_eq!(
        fetched.key_versions[0].provider_ref,
        Some(ProviderRef::new("tenant-b"))
    );

    // Encrypt/decrypt via the domain layer.
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let pt = b"tenant-b secret";
    let enc = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: lid.to_string(),
            plaintext: pt.to_vec(),
            ..Default::default()
        }))
        .await
        .expect("encrypt ok")
        .into_inner();

    let dec = svc
        .decrypt(Request::new(proto::DecryptRequest {
            key_id: lid.to_string(),
            ciphertext_blob: enc.ciphertext_blob,
            ..Default::default()
        }))
        .await
        .expect("decrypt ok")
        .into_inner();

    assert_eq!(dec.plaintext, pt.to_vec());
}

/// 2b. End-to-end: creating a key through the gRPC handler with caller-supplied
/// `attributes` that match a routing rule binds the new key to the routed
/// provider. Proves identity enrichment makes routing reachable via the API.
#[tokio::test]
async fn routing_create_with_attributes_routes_to_tenant_b() {
    use keyrack_core::key::ProviderRef;
    use std::collections::BTreeMap;

    let mut match_tags = BTreeMap::new();
    match_tags.insert("tenant".into(), "acme".into());
    let state = build_two_provider_state(vec![(match_tags, ProviderRef::new("tenant-b"))]);
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let mut attributes = std::collections::HashMap::new();
    attributes.insert("tenant".to_string(), "acme".to_string());

    let key_id = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "routed key".into(),
            attributes,
            ..Default::default()
        }))
        .await
        .expect("create_key ok")
        .into_inner()
        .metadata
        .expect("metadata")
        .key_id;

    let lid: keyrack_core::lid::Lid = key_id.parse().expect("valid lid");
    let record = state.storage.get_key(&lid).await.expect("key exists");
    assert_eq!(record.provider_ref, Some(ProviderRef::new("tenant-b")));
    assert_eq!(
        record.key_versions[0].provider_ref,
        Some(ProviderRef::new("tenant-b"))
    );
}

/// 2c. The optional `keyrack.provider` assertion is fail-closed: if the caller
/// asserts a provider that does not match what routing policy selects, the
/// create call is rejected (the assertion never overrides policy).
#[tokio::test]
async fn routing_provider_assertion_mismatch_fails() {
    // No routing rules → everything routes to "default".
    let state = build_two_provider_state(vec![]);
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let mut attributes = std::collections::HashMap::new();
    // Assert "tenant-b" while policy will select "default" → must fail.
    attributes.insert("keyrack.provider".to_string(), "tenant-b".to_string());

    let result = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "asserted key".into(),
            attributes,
            ..Default::default()
        }))
        .await;

    let err = result.expect_err("assertion mismatch must fail");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

/// 3. A version whose `provider_ref` names an unknown provider → `ProviderUnavailable`.
#[tokio::test]
async fn routing_unknown_provider_yields_unavailable() {
    use keyrack_core::key::ProviderRef;
    let state = build_two_provider_state(vec![]);
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let key_id = create_aes_key(&svc).await;
    let lid: keyrack_core::lid::Lid = key_id.parse().expect("valid lid");

    // Corrupt the record to reference a nonexistent provider.
    let mut record = state.storage.get_key(&lid).await.expect("found");
    record.provider_ref = Some(ProviderRef::new("ghost-provider"));
    record.key_versions[0].provider_ref = Some(ProviderRef::new("ghost-provider"));
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state.storage.update_key(&record).await.expect("updated");

    // Encrypt should yield an error because ghost-provider doesn't exist.
    let result = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: key_id.clone(),
            plaintext: b"test".to_vec(),
            ..Default::default()
        }))
        .await;

    assert!(result.is_err(), "should fail with ProviderUnavailable");
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unavailable,
        "expected Unavailable status, got: {status:?}"
    );
}

/// 4. Legacy record (`provider_ref`: None) resolves to default and round-trips.
#[tokio::test]
async fn routing_legacy_record_none_provider_ref_uses_default() {
    let state = build_two_provider_state(vec![]);

    // Create a record with no provider_ref (simulating old stored data).
    let default_entry = state.providers.default_entry();
    let handle = default_entry
        .provider
        .generate_key(&keyrack_core::key::KeySpec::Aes256)
        .await
        .expect("generate_key");

    let now = chrono::Utc::now();
    let mut attrs = keyrack_core::attr::AttributeSet::new();
    attrs.insert(
        "_keyrack_key_id",
        keyrack_core::attr::AttributeValue::String(uuid::Uuid::new_v4().to_string()),
    );
    let canonical =
        keyrack_core::canon::canonicalize(keyrack_core::canon::CanonicalizationVersion::V1, &attrs);
    let lid = keyrack_core::lid::Lid::derive(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &canonical,
    );

    // provider_ref: None on both record and version (legacy format).
    let record = keyrack_core::key::KeyRecord {
        lid,
        canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
        parent_lid: None,
        occ_version: 1,
        current_key_version: 1,
        state: keyrack_core::key::KeyState::Enabled,
        key_usage: keyrack_core::key::KeyUsage::EncryptDecrypt,
        key_spec: keyrack_core::key::KeySpec::Aes256,
        origin: keyrack_core::key::KeyOrigin::KeyRack,
        provider_class: keyrack_core::key::ProviderClass::InMemory,
        provider_ref: None,
        identity_tags: keyrack_core::tags::IdentityTags::from_attribute_set(&attrs),
        user_tags: keyrack_core::tags::UserTags::new(),
        created_at: now,
        updated_at: now,
        scheduled_deletion_at: None,
        description: "legacy".into(),
        key_versions: vec![keyrack_core::key::KeyVersionRecord {
            version_number: 1,
            key_handle: handle,
            provider_ref: None,
            created_at: now,
            is_primary: true,
        }],
    };
    state.storage.create_key(&record).await.expect("created");

    // Verify: effective_provider_ref returns None (uses registry default).
    let fetched = state.storage.get_key(&lid).await.expect("found");
    assert_eq!(fetched.provider_ref, None);
    assert_eq!(fetched.key_versions[0].provider_ref, None);
    assert_eq!(fetched.effective_provider_ref(1), None);

    // Encrypt/decrypt should still work via the default provider.
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let pt = b"legacy record test";
    let enc = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: lid.to_string(),
            plaintext: pt.to_vec(),
            ..Default::default()
        }))
        .await
        .expect("encrypt ok")
        .into_inner();
    let dec = svc
        .decrypt(Request::new(proto::DecryptRequest {
            key_id: lid.to_string(),
            ciphertext_blob: enc.ciphertext_blob,
            ..Default::default()
        }))
        .await
        .expect("decrypt ok")
        .into_inner();
    assert_eq!(dec.plaintext, pt.to_vec());
}

/// 5. Migration: create key on "default", add new version on "tenant-b",
///    verify old ciphertext (pinned to v1 on default) still decrypts,
///    and new encrypt uses v2 on tenant-b.
#[tokio::test]
async fn routing_cross_version_migration() {
    use keyrack_core::key::ProviderRef;
    let state = build_two_provider_state(vec![]);
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    // Step 1: create on default provider.
    let key_id = create_aes_key(&svc).await;
    let lid: keyrack_core::lid::Lid = key_id.parse().expect("valid lid");

    // Step 2: encrypt with v1 (on default).
    let pt_v1 = b"v1 plaintext";
    let enc_v1 = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: key_id.clone(),
            plaintext: pt_v1.to_vec(),
            ..Default::default()
        }))
        .await
        .expect("encrypt v1")
        .into_inner();

    // Step 3: generate v2 material on "tenant-b" and make it primary.
    let tenant_b_entry = state
        .providers
        .resolve(&ProviderRef::new("tenant-b"))
        .expect("resolve tenant-b");
    let v2_handle = tenant_b_entry
        .provider
        .generate_key(&keyrack_core::key::KeySpec::Aes256)
        .await
        .expect("generate v2");

    let mut record = state.storage.get_key(&lid).await.expect("found");
    for v in &mut record.key_versions {
        v.is_primary = false;
    }
    let v2_num = record.current_key_version + 1;
    record
        .key_versions
        .push(keyrack_core::key::KeyVersionRecord {
            version_number: v2_num,
            key_handle: v2_handle,
            provider_ref: Some(ProviderRef::new("tenant-b")),
            created_at: chrono::Utc::now(),
            is_primary: true,
        });
    record.current_key_version = v2_num;
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state.storage.update_key(&record).await.expect("updated");

    // Step 4: new encrypt uses v2 (tenant-b).
    let pt_v2 = b"v2 plaintext";
    let enc_v2 = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: key_id.clone(),
            plaintext: pt_v2.to_vec(),
            ..Default::default()
        }))
        .await
        .expect("encrypt v2")
        .into_inner();
    assert_eq!(enc_v2.key_version, v2_num as u32);

    // Step 5: old v1 ciphertext still decrypts on default provider.
    let dec_v1 = svc
        .decrypt(Request::new(proto::DecryptRequest {
            key_id: key_id.clone(),
            ciphertext_blob: enc_v1.ciphertext_blob,
            ..Default::default()
        }))
        .await
        .expect("decrypt v1")
        .into_inner();
    assert_eq!(dec_v1.plaintext, pt_v1.to_vec());

    // Step 6: new v2 ciphertext decrypts on tenant-b provider.
    let dec_v2 = svc
        .decrypt(Request::new(proto::DecryptRequest {
            key_id: key_id.clone(),
            ciphertext_blob: enc_v2.ciphertext_blob,
            ..Default::default()
        }))
        .await
        .expect("decrypt v2")
        .into_inner();
    assert_eq!(dec_v2.plaintext, pt_v2.to_vec());
}

// ═══════════════════════════════════════════════════════════════════
// Helper
// ═══════════════════════════════════════════════════════════════════

async fn create_aes_key(svc: &keyrack_service::grpc::KeyServiceImpl) -> String {
    let req = Request::new(proto::CreateKeyRequest {
        key_spec: proto::KeySpec::Aes256.into(),
        description: "test key".into(),
        ..Default::default()
    });
    svc.create_key(req)
        .await
        .expect("create_key must succeed")
        .into_inner()
        .metadata
        .expect("metadata")
        .key_id
}

// ═══════════════════════════════════════════════════════════════════
// 0.3.0 DENY-PATH TESTS
// ═══════════════════════════════════════════════════════════════════

/// Build a state with routing rules configured (`has_rules` = true) and two providers.
fn build_routed_state() -> (Arc<ServiceState>, Arc<CapturingSink>) {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::{DynamicProviderRegistry, ProviderEntry};
    use keyrack_core::routing::{ProviderRouter, RoutingRule, RuleAction};
    use std::collections::BTreeMap;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let prov_default = Arc::new(InMemoryProvider::new());
    let prov_tenant = Arc::new(InMemoryProvider::new());

    let entries = vec![
        (
            ProviderRef::new("default"),
            ProviderEntry {
                provider: prov_default,
                class: ProviderClass::InMemory,
            },
        ),
        (
            ProviderRef::new("tenant-hsm"),
            ProviderEntry {
                provider: prov_tenant,
                class: ProviderClass::InMemory,
            },
        ),
    ];
    let registry = Arc::new(
        DynamicProviderRegistry::new(entries, ProviderRef::new("default")).expect("valid registry"),
    );

    let mut match_tags = BTreeMap::new();
    match_tags.insert("tenant".to_string(), "acme".to_string());
    let rules = vec![RoutingRule {
        match_tags,
        action: RuleAction::Route(ProviderRef::new("tenant-hsm")),
    }];
    let provider_router = ProviderRouter::with_rules(rules, ProviderRef::new("default"));

    let pdp: Arc<dyn keyrack_core::pdp::PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit = Arc::new(CapturingSink::new());
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(keyrack_core::authn::InsecureAuthenticator),
    ]));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    let state = Arc::new(ServiceState {
        storage,
        providers: registry,
        provider_router,
        pdp,
        audit: audit.clone(),
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });
    (state, audit)
}

/// Build a state with delegate rules for deny-path testing.
fn build_delegate_state() -> (Arc<ServiceState>, Arc<CapturingSink>) {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::{DynamicProviderRegistry, ProviderEntry};
    use keyrack_core::routing::{ProviderRouter, RoutingRule, RuleAction};
    use std::collections::{BTreeMap, BTreeSet};

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let prov_default = Arc::new(InMemoryProvider::new());
    let prov_a = Arc::new(InMemoryProvider::new());
    let prov_b = Arc::new(InMemoryProvider::new());

    let entries = vec![
        (
            ProviderRef::new("default"),
            ProviderEntry {
                provider: prov_default,
                class: ProviderClass::InMemory,
            },
        ),
        (
            ProviderRef::new("prov-a"),
            ProviderEntry {
                provider: prov_a,
                class: ProviderClass::InMemory,
            },
        ),
        (
            ProviderRef::new("prov-b"),
            ProviderEntry {
                provider: prov_b,
                class: ProviderClass::InMemory,
            },
        ),
    ];
    let registry = Arc::new(
        DynamicProviderRegistry::new(entries, ProviderRef::new("default")).expect("valid registry"),
    );

    let mut match_tags = BTreeMap::new();
    match_tags.insert("tier".to_string(), "premium".to_string());
    let allowed: BTreeSet<ProviderRef> = [ProviderRef::new("prov-a"), ProviderRef::new("prov-b")]
        .into_iter()
        .collect();
    let rules = vec![RoutingRule {
        match_tags,
        action: RuleAction::Delegate(allowed),
    }];
    let provider_router = ProviderRouter::with_rules(rules, ProviderRef::new("default"));

    let pdp: Arc<dyn keyrack_core::pdp::PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit = Arc::new(CapturingSink::new());
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(keyrack_core::authn::InsecureAuthenticator),
    ]));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    let state = Arc::new(ServiceState {
        storage,
        providers: registry,
        provider_router,
        pdp,
        audit: audit.clone(),
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });
    (state, audit)
}

// ── backend_id deny paths ──────────────────────────────────────────

#[tokio::test]
async fn backend_id_unregistered_fails_with_failed_precondition() {
    let (state, _audit) = build_routed_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let result = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "test".into(),
            backend_id: Some("nonexistent-provider".into()),
            ..Default::default()
        }))
        .await;

    let err = result.expect_err("unregistered backend_id must fail");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("not a registered provider"));
}

#[tokio::test]
async fn backend_id_default_deny_when_policy_configured() {
    let (state, _audit) = build_routed_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    // Request backend_id "tenant-hsm" without matching any routing rule
    // (no tags match the rule). With routing rules configured, this is
    // denied because no delegate authorizes it.
    let result = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "test".into(),
            backend_id: Some("tenant-hsm".into()),
            ..Default::default()
        }))
        .await;

    let err = result.expect_err("default-deny must reject unauthorized backend_id");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(err.message().contains("not authorized"));
}

#[tokio::test]
async fn backend_id_alias_disagree_fails() {
    let (state, _audit) = build_routed_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let result = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "test".into(),
            backend_id: Some("default".into()),
            hsm_connection_id: Some("tenant-hsm".into()),
            ..Default::default()
        }))
        .await;

    let err = result.expect_err("disagree must fail");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("disagree"));
}

// ── delegate deny paths ────────────────────────────────────────────

#[tokio::test]
async fn delegate_bounded_select_honored() {
    let (state, _audit) = build_delegate_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let mut attributes = std::collections::HashMap::new();
    attributes.insert("tier".to_string(), "premium".to_string());

    let result = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "delegated".into(),
            backend_id: Some("prov-a".into()),
            attributes,
            ..Default::default()
        }))
        .await;

    assert!(result.is_ok(), "delegate allows prov-a: {result:?}");
    let lid: keyrack_core::lid::Lid = result
        .unwrap()
        .into_inner()
        .metadata
        .unwrap()
        .key_id
        .parse()
        .unwrap();
    let record = state.storage.get_key(&lid).await.unwrap();
    assert_eq!(
        record.provider_ref,
        Some(keyrack_core::key::ProviderRef::new("prov-a"))
    );
}

#[tokio::test]
async fn delegate_outside_set_rejected_permission_denied() {
    let (state, _audit) = build_delegate_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let mut attributes = std::collections::HashMap::new();
    attributes.insert("tier".to_string(), "premium".to_string());

    // "default" is registered but not in the delegate's allowed set.
    let result = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "blocked".into(),
            backend_id: Some("default".into()),
            attributes,
            ..Default::default()
        }))
        .await;

    let err = result.expect_err("outside delegate set must be rejected");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(err.message().contains("not permitted by the delegate rule"));
}

#[tokio::test]
async fn route_pin_conflict_fails_precondition_names_both() {
    let (state, _audit) = build_routed_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let mut attributes = std::collections::HashMap::new();
    attributes.insert("tenant".to_string(), "acme".to_string());

    // Route pins to "tenant-hsm" but caller requests "default".
    let result = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "conflict".into(),
            backend_id: Some("default".into()),
            attributes,
            ..Default::default()
        }))
        .await;

    let err = result.expect_err("pin conflict must fail");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("tenant-hsm"));
    assert!(err.message().contains("default"));
}

// ── scope_owner deny paths ─────────────────────────────────────────

#[tokio::test]
async fn scope_owner_mismatch_denied_on_encrypt() {
    let (state, audit) = build_routed_state();

    // Register a dynamic HSM connection with scope_owner.
    let conn = keyrack_core::hsm::HsmConnection::new(
        "scoped-conn",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "scoped connection",
    )
    .with_scope_owner("tenant:acme");
    state
        .storage
        .create_hsm_connection(&conn)
        .await
        .expect("save conn");

    // Create a key bound to this connection by inserting directly.
    let default_entry = state.providers.default_entry();
    let handle = default_entry
        .provider
        .generate_key(&keyrack_core::key::KeySpec::Aes256)
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let mut attrs = keyrack_core::attr::AttributeSet::new();
    attrs.insert(
        "_keyrack_key_id",
        keyrack_core::attr::AttributeValue::String(uuid::Uuid::new_v4().to_string()),
    );
    let canonical =
        keyrack_core::canon::canonicalize(keyrack_core::canon::CanonicalizationVersion::V1, &attrs);
    let lid = keyrack_core::lid::Lid::derive(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &canonical,
    );
    let record = keyrack_core::key::KeyRecord {
        lid,
        canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
        parent_lid: None,
        occ_version: 1,
        current_key_version: 1,
        state: keyrack_core::key::KeyState::Enabled,
        key_usage: keyrack_core::key::KeyUsage::EncryptDecrypt,
        key_spec: keyrack_core::key::KeySpec::Aes256,
        origin: keyrack_core::key::KeyOrigin::KeyRack,
        provider_class: keyrack_core::key::ProviderClass::InMemory,
        provider_ref: Some(keyrack_core::key::ProviderRef::new("scoped-conn")),
        identity_tags: keyrack_core::tags::IdentityTags::from_attribute_set(&attrs),
        user_tags: keyrack_core::tags::UserTags::new(),
        created_at: now,
        updated_at: now,
        scheduled_deletion_at: None,
        description: "scope test".into(),
        key_versions: vec![keyrack_core::key::KeyVersionRecord {
            version_number: 1,
            key_handle: handle,
            provider_ref: Some(keyrack_core::key::ProviderRef::new("scoped-conn")),
            created_at: now,
            is_primary: true,
        }],
    };
    state.storage.create_key(&record).await.unwrap();

    // The InsecureAuthenticator principal has no scope claim → must be denied.
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let result = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: lid.to_string(),
            plaintext: b"test".to_vec(),
            ..Default::default()
        }))
        .await;

    let err = result.expect_err("missing scope claim must deny");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // Verify audit event was emitted with the correct envelope.
    let events = audit.events();
    let scope_event = events
        .iter()
        .find(|e| e.event_type == keyrack_core::audit::EventType::ScopeOwnerCheck);
    assert!(
        scope_event.is_some(),
        "scope_owner_check event must be emitted"
    );
    let ev = scope_event.unwrap();
    assert_eq!(ev.result, keyrack_core::audit::AuditResult::Denied);
    assert_eq!(ev.resource.resource_type, "HsmConnection");
    assert_eq!(ev.resource.id, "scoped-conn");
    assert!(ev.metadata.contains_key("scope"));
    assert!(ev.metadata.contains_key("connection_scope_owner"));
    assert_eq!(
        ev.metadata["connection_scope_owner"],
        serde_json::Value::String("tenant:acme".into())
    );
}

#[tokio::test]
async fn scope_owner_unset_passes_without_check() {
    // When scope_owner is not set on the connection, no check is performed
    // and the operation succeeds.
    let (state, audit) = build_routed_state();

    // Register a connection WITHOUT scope_owner and add it as a provider.
    let conn = keyrack_core::hsm::HsmConnection::new(
        "unscoped-conn",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "no scope",
    );
    state
        .storage
        .create_hsm_connection(&conn)
        .await
        .expect("save conn");
    let prov = Arc::new(InMemoryProvider::new());
    let entry = keyrack_core::registry::ProviderEntry {
        provider: prov,
        class: keyrack_core::key::ProviderClass::InMemory,
    };
    let _ = state
        .providers
        .register(keyrack_core::key::ProviderRef::new("unscoped-conn"), entry);

    // Create a key bound to it.
    let unscoped_entry = state
        .providers
        .resolve(&keyrack_core::key::ProviderRef::new("unscoped-conn"))
        .unwrap();
    let handle = unscoped_entry
        .provider
        .generate_key(&keyrack_core::key::KeySpec::Aes256)
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let mut attrs = keyrack_core::attr::AttributeSet::new();
    attrs.insert(
        "_keyrack_key_id",
        keyrack_core::attr::AttributeValue::String(uuid::Uuid::new_v4().to_string()),
    );
    let canonical =
        keyrack_core::canon::canonicalize(keyrack_core::canon::CanonicalizationVersion::V1, &attrs);
    let lid = keyrack_core::lid::Lid::derive(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &canonical,
    );
    let record = keyrack_core::key::KeyRecord {
        lid,
        canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
        parent_lid: None,
        occ_version: 1,
        current_key_version: 1,
        state: keyrack_core::key::KeyState::Enabled,
        key_usage: keyrack_core::key::KeyUsage::EncryptDecrypt,
        key_spec: keyrack_core::key::KeySpec::Aes256,
        origin: keyrack_core::key::KeyOrigin::KeyRack,
        provider_class: keyrack_core::key::ProviderClass::InMemory,
        provider_ref: Some(keyrack_core::key::ProviderRef::new("unscoped-conn")),
        identity_tags: keyrack_core::tags::IdentityTags::from_attribute_set(&attrs),
        user_tags: keyrack_core::tags::UserTags::new(),
        created_at: now,
        updated_at: now,
        scheduled_deletion_at: None,
        description: "unscoped test".into(),
        key_versions: vec![keyrack_core::key::KeyVersionRecord {
            version_number: 1,
            key_handle: handle,
            provider_ref: Some(keyrack_core::key::ProviderRef::new("unscoped-conn")),
            created_at: now,
            is_primary: true,
        }],
    };
    state.storage.create_key(&record).await.unwrap();

    // Should succeed — no scope check because connection has no scope_owner.
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let result = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: lid.to_string(),
            plaintext: b"test".to_vec(),
            ..Default::default()
        }))
        .await;

    assert!(
        result.is_ok(),
        "unscoped connection should allow: {result:?}"
    );

    // No scope_owner_check events should be emitted.
    let scope_events: Vec<_> = audit
        .events()
        .iter()
        .filter(|e| e.event_type == keyrack_core::audit::EventType::ScopeOwnerCheck)
        .cloned()
        .collect();
    assert!(
        scope_events.is_empty(),
        "no scope_owner_check event when scope_owner is unset"
    );
}

// ── DeleteHsmConnection deregisters ────────────────────────────────

#[tokio::test]
async fn delete_hsm_connection_deregisters_from_registry() {
    let (state, _audit) = build_routed_state();

    // Register a connection directly in storage (bypassing the PKCS#11
    // provider initialization which requires a real library + secret root).
    let conn = keyrack_core::hsm::HsmConnection::new(
        "temp-conn",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "temporary",
    );
    state
        .storage
        .create_hsm_connection(&conn)
        .await
        .expect("save conn");
    // Add it to the live registry as well.
    let prov = Arc::new(InMemoryProvider::new());
    let entry = keyrack_core::registry::ProviderEntry {
        provider: prov,
        class: keyrack_core::key::ProviderClass::InMemory,
    };
    let _ = state
        .providers
        .register(keyrack_core::key::ProviderRef::new("temp-conn"), entry);

    assert!(state
        .providers
        .contains(&keyrack_core::key::ProviderRef::new("temp-conn")));

    // Delete it via the gRPC handler.
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let _ = svc
        .delete_hsm_connection(Request::new(proto::DeleteHsmConnectionRequest {
            connection_id: "temp-conn".into(),
        }))
        .await
        .expect("delete");

    // A subsequent contains check must be false.
    assert!(
        !state
            .providers
            .contains(&keyrack_core::key::ProviderRef::new("temp-conn")),
        "provider must be removed from live registry after delete"
    );
}

// ── read echo of backend_id ────────────────────────────────────────

#[tokio::test]
async fn get_key_echoes_backend_id() {
    let (state, _audit) = build_routed_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    // Create a key that routes to tenant-hsm via matching attributes.
    let mut attributes = std::collections::HashMap::new();
    attributes.insert("tenant".to_string(), "acme".to_string());

    let resp = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "echo test".into(),
            attributes,
            ..Default::default()
        }))
        .await
        .expect("create");
    let key_id = resp.into_inner().metadata.unwrap().key_id;

    let get_resp = svc
        .get_key(Request::new(proto::GetKeyRequest {
            key_id: key_id.clone(),
        }))
        .await
        .expect("get_key");
    let meta = get_resp.into_inner().metadata.unwrap();
    assert_eq!(
        meta.backend_id.as_deref(),
        Some("tenant-hsm"),
        "backend_id should echo the bound provider"
    );
    // Deprecated hsm_connection_id should also echo.
    assert_eq!(
        meta.hsm_connection_id.as_deref(),
        Some("tenant-hsm"),
        "hsm_connection_id alias should echo"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SURFACE × OP SCOPE ENFORCEMENT MATRIX
// ═══════════════════════════════════════════════════════════════════

/// Helper: create a scoped connection + key bound to it for scope enforcement tests.
async fn setup_scoped_key(state: &Arc<ServiceState>) -> keyrack_core::lid::Lid {
    let conn = keyrack_core::hsm::HsmConnection::new(
        "scoped-conn",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "scoped",
    )
    .with_scope_owner("tenant:acme");
    state
        .storage
        .create_hsm_connection(&conn)
        .await
        .expect("save conn");

    let default_entry = state.providers.default_entry();
    let handle = default_entry
        .provider
        .generate_key(&keyrack_core::key::KeySpec::Aes256)
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let mut attrs = keyrack_core::attr::AttributeSet::new();
    attrs.insert(
        "_keyrack_key_id",
        keyrack_core::attr::AttributeValue::String(uuid::Uuid::new_v4().to_string()),
    );
    let canonical =
        keyrack_core::canon::canonicalize(keyrack_core::canon::CanonicalizationVersion::V1, &attrs);
    let lid = keyrack_core::lid::Lid::derive(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &canonical,
    );
    let record = keyrack_core::key::KeyRecord {
        lid,
        canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
        parent_lid: None,
        occ_version: 1,
        current_key_version: 1,
        state: keyrack_core::key::KeyState::Enabled,
        key_usage: keyrack_core::key::KeyUsage::EncryptDecrypt,
        key_spec: keyrack_core::key::KeySpec::Aes256,
        origin: keyrack_core::key::KeyOrigin::KeyRack,
        provider_class: keyrack_core::key::ProviderClass::InMemory,
        provider_ref: Some(keyrack_core::key::ProviderRef::new("scoped-conn")),
        identity_tags: keyrack_core::tags::IdentityTags::from_attribute_set(&attrs),
        user_tags: keyrack_core::tags::UserTags::new(),
        created_at: now,
        updated_at: now,
        scheduled_deletion_at: None,
        description: "scope matrix test".into(),
        key_versions: vec![keyrack_core::key::KeyVersionRecord {
            version_number: 1,
            key_handle: handle,
            provider_ref: Some(keyrack_core::key::ProviderRef::new("scoped-conn")),
            created_at: now,
            is_primary: true,
        }],
    };
    state.storage.create_key(&record).await.unwrap();
    lid
}

/// Helper: create the same setup but for a signing key.
async fn setup_scoped_signing_key(state: &Arc<ServiceState>) -> keyrack_core::lid::Lid {
    let conn_id = "scoped-sign-conn";
    if state.storage.get_hsm_connection(conn_id).await.is_err() {
        let conn = keyrack_core::hsm::HsmConnection::new(
            conn_id,
            keyrack_core::hsm::HsmProviderType::Hsm,
            "/lib.so",
            "scoped signing",
        )
        .with_scope_owner("tenant:acme");
        state.storage.create_hsm_connection(&conn).await.unwrap();
    }

    let default_entry = state.providers.default_entry();
    let handle = default_entry
        .provider
        .generate_key(&keyrack_core::key::KeySpec::Ed25519)
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let mut attrs = keyrack_core::attr::AttributeSet::new();
    attrs.insert(
        "_keyrack_key_id",
        keyrack_core::attr::AttributeValue::String(uuid::Uuid::new_v4().to_string()),
    );
    let canonical =
        keyrack_core::canon::canonicalize(keyrack_core::canon::CanonicalizationVersion::V1, &attrs);
    let lid = keyrack_core::lid::Lid::derive(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &canonical,
    );
    let record = keyrack_core::key::KeyRecord {
        lid,
        canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
        parent_lid: None,
        occ_version: 1,
        current_key_version: 1,
        state: keyrack_core::key::KeyState::Enabled,
        key_usage: keyrack_core::key::KeyUsage::SignVerify,
        key_spec: keyrack_core::key::KeySpec::Ed25519,
        origin: keyrack_core::key::KeyOrigin::KeyRack,
        provider_class: keyrack_core::key::ProviderClass::InMemory,
        provider_ref: Some(keyrack_core::key::ProviderRef::new(conn_id)),
        identity_tags: keyrack_core::tags::IdentityTags::from_attribute_set(&attrs),
        user_tags: keyrack_core::tags::UserTags::new(),
        created_at: now,
        updated_at: now,
        scheduled_deletion_at: None,
        description: "scope sign test".into(),
        key_versions: vec![keyrack_core::key::KeyVersionRecord {
            version_number: 1,
            key_handle: handle,
            provider_ref: Some(keyrack_core::key::ProviderRef::new(conn_id)),
            created_at: now,
            is_primary: true,
        }],
    };
    state.storage.create_key(&record).await.unwrap();
    lid
}

// ── gRPC surface: all scoped ops deny on missing scope claim ──────

#[tokio::test]
async fn grpc_scope_deny_encrypt() {
    let (state, _) = build_routed_state();
    let lid = setup_scoped_key(&state).await;
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let err = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: lid.to_string(),
            plaintext: b"x".to_vec(),
            ..Default::default()
        }))
        .await
        .expect_err("scope must deny");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn grpc_scope_deny_decrypt() {
    let (state, _) = build_routed_state();
    let lid = setup_scoped_key(&state).await;
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    // Build a valid ciphertext header so the scope check fires before decryption.
    let header = keyrack_core::header::CiphertextHeader::new(lid, 1, [0u8; 32]);
    let ciphertext_blob = header.wrap_payload(&[0u8; 32]);

    let err = svc
        .decrypt(Request::new(proto::DecryptRequest {
            key_id: lid.to_string(),
            ciphertext_blob,
            ..Default::default()
        }))
        .await
        .expect_err("scope must deny");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn grpc_scope_deny_sign() {
    let (state, _) = build_routed_state();
    let lid = setup_scoped_signing_key(&state).await;
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let err = svc
        .sign(Request::new(proto::SignRequest {
            key_id: lid.to_string(),
            message: b"msg".to_vec(),
            signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
            ..Default::default()
        }))
        .await
        .expect_err("scope must deny");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn grpc_scope_deny_verify() {
    let (state, _) = build_routed_state();
    let lid = setup_scoped_signing_key(&state).await;
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let err = svc
        .verify(Request::new(proto::VerifyRequest {
            key_id: lid.to_string(),
            message: b"msg".to_vec(),
            signature: vec![0u8; 64],
            signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
            ..Default::default()
        }))
        .await
        .expect_err("scope must deny");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn grpc_scope_deny_generate_mac() {
    let (state, _) = build_routed_state();
    let lid = setup_scoped_key(&state).await;
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let err = svc
        .generate_mac(Request::new(proto::GenerateMacRequest {
            key_id: lid.to_string(),
            message: b"x".to_vec(),
            mac_algorithm: proto::MacAlgorithm::HmacSha256.into(),
        }))
        .await
        .expect_err("scope must deny");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn grpc_scope_deny_verify_mac() {
    let (state, _) = build_routed_state();
    let lid = setup_scoped_key(&state).await;
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let err = svc
        .verify_mac(Request::new(proto::VerifyMacRequest {
            key_id: lid.to_string(),
            message: b"x".to_vec(),
            mac: vec![0u8; 32],
            mac_algorithm: proto::MacAlgorithm::HmacSha256.into(),
        }))
        .await
        .expect_err("scope must deny");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn grpc_scope_deny_create_key_with_scoped_backend() {
    let (state, _) = build_routed_state();
    let conn = keyrack_core::hsm::HsmConnection::new(
        "create-scoped",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "test",
    )
    .with_scope_owner("tenant:acme");
    state.storage.create_hsm_connection(&conn).await.unwrap();
    let prov = Arc::new(InMemoryProvider::new());
    state
        .providers
        .register(
            keyrack_core::key::ProviderRef::new("create-scoped"),
            keyrack_core::registry::ProviderEntry {
                provider: prov,
                class: keyrack_core::key::ProviderClass::InMemory,
            },
        )
        .unwrap();

    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let err = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "scope create test".into(),
            backend_id: Some("create-scoped".into()),
            ..Default::default()
        }))
        .await
        .expect_err("scope must deny create");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

// ── REST surface: scope enforcement via tower ─────────────────────

#[tokio::test]
async fn rest_scope_deny_encrypt() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_routed_state();
    let lid = setup_scoped_key(&state).await;
    let app = keyrack_service::rest::router(state);

    let body = serde_json::json!({
        "plaintext": base64::engine::general_purpose::STANDARD.encode(b"hello"),
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/keys/{lid}/actions-encrypt"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rest_scope_deny_decrypt() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_routed_state();
    let lid = setup_scoped_key(&state).await;
    let app = keyrack_service::rest::router(state);

    // Build a valid ciphertext header so the scope check fires.
    let header = keyrack_core::header::CiphertextHeader::new(lid, 1, [0u8; 32]);
    let ciphertext_blob = header.wrap_payload(&[0u8; 32]);

    let body = serde_json::json!({
        "ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(&ciphertext_blob),
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/keys/{lid}/actions-decrypt"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rest_scope_deny_sign() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_routed_state();
    let lid = setup_scoped_signing_key(&state).await;
    let app = keyrack_service::rest::router(state);

    let body = serde_json::json!({
        "message": base64::engine::general_purpose::STANDARD.encode(b"msg"),
        "signing_algorithm": "ED25519",
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/keys/{lid}/actions-sign"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rest_scope_deny_verify() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_routed_state();
    let lid = setup_scoped_signing_key(&state).await;
    let app = keyrack_service::rest::router(state);

    let body = serde_json::json!({
        "message": base64::engine::general_purpose::STANDARD.encode(b"msg"),
        "signature": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
        "signing_algorithm": "ED25519",
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/keys/{lid}/actions-verify"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rest_scope_deny_generate_mac() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_routed_state();
    let lid = setup_scoped_key(&state).await;
    let app = keyrack_service::rest::router(state);

    let body = serde_json::json!({
        "message": base64::engine::general_purpose::STANDARD.encode(b"msg"),
        "mac_algorithm": "HMAC_SHA_256",
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/keys/{lid}/actions-generate-mac"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rest_scope_deny_verify_mac() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_routed_state();
    let lid = setup_scoped_key(&state).await;
    let app = keyrack_service::rest::router(state);

    let body = serde_json::json!({
        "message": base64::engine::general_purpose::STANDARD.encode(b"msg"),
        "mac": base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
        "mac_algorithm": "HMAC_SHA_256",
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/keys/{lid}/actions-verify-mac"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

// ── Registration rejects invalid scope_owner ──────────────────────

#[tokio::test]
async fn create_hsm_connection_rejects_org_scope_owner() {
    let (state, _) = build_routed_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let err = svc
        .create_hsm_connection(Request::new(proto::CreateHsmConnectionRequest {
            endpoint: "kmip://host:5696".into(),
            provider_type: proto::HsmProviderType::Hyok.into(),
            scope_owner: Some("org:globex".into()),
            ..Default::default()
        }))
        .await
        .expect_err("org scope must be rejected for 0.3.0");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("scope_owner"));
}

#[tokio::test]
async fn create_hsm_connection_rejects_empty_tenant() {
    let (state, _) = build_routed_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let err = svc
        .create_hsm_connection(Request::new(proto::CreateHsmConnectionRequest {
            endpoint: "kmip://host:5696".into(),
            provider_type: proto::HsmProviderType::Hyok.into(),
            scope_owner: Some("tenant:".into()),
            ..Default::default()
        }))
        .await
        .expect_err("empty tenant: must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn create_hsm_connection_rejects_arbitrary_scope() {
    let (state, _) = build_routed_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let err = svc
        .create_hsm_connection(Request::new(proto::CreateHsmConnectionRequest {
            endpoint: "kmip://host:5696".into(),
            provider_type: proto::HsmProviderType::Hyok.into(),
            scope_owner: Some("foobar".into()),
            ..Default::default()
        }))
        .await
        .expect_err("arbitrary scope must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn create_hsm_connection_accepts_valid_scope_owners() {
    let (state, _) = build_routed_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let resp = svc
        .create_hsm_connection(Request::new(proto::CreateHsmConnectionRequest {
            connection_id: "valid-platform".into(),
            endpoint: "kmip://host:5696".into(),
            provider_type: proto::HsmProviderType::Hyok.into(),
            scope_owner: Some("platform".into()),
            ..Default::default()
        }))
        .await;
    assert!(resp.is_ok(), "platform scope_owner must be accepted");

    let resp = svc
        .create_hsm_connection(Request::new(proto::CreateHsmConnectionRequest {
            connection_id: "valid-tenant".into(),
            endpoint: "kmip://host:5696".into(),
            provider_type: proto::HsmProviderType::Hyok.into(),
            scope_owner: Some("tenant:globex".into()),
            ..Default::default()
        }))
        .await;
    assert!(resp.is_ok(), "tenant:<id> scope_owner must be accepted");
}

// ── scope_owner_check audit envelope on success ───────────────────

#[tokio::test]
async fn scope_audit_success_on_unscoped_connection() {
    let (state, audit) = build_routed_state();

    // Register connection in storage AND in provider registry.
    let conn = keyrack_core::hsm::HsmConnection::new(
        "scoped-conn",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "scoped",
    );
    state.storage.create_hsm_connection(&conn).await.unwrap();
    let prov = Arc::new(InMemoryProvider::new());
    state
        .providers
        .register(
            keyrack_core::key::ProviderRef::new("scoped-conn"),
            keyrack_core::registry::ProviderEntry {
                provider: prov.clone(),
                class: keyrack_core::key::ProviderClass::InMemory,
            },
        )
        .unwrap();

    // Create a key bound to this connection.
    let handle = prov
        .generate_key(&keyrack_core::key::KeySpec::Aes256)
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let mut attrs = keyrack_core::attr::AttributeSet::new();
    attrs.insert(
        "_keyrack_key_id",
        keyrack_core::attr::AttributeValue::String(uuid::Uuid::new_v4().to_string()),
    );
    let canonical =
        keyrack_core::canon::canonicalize(keyrack_core::canon::CanonicalizationVersion::V1, &attrs);
    let lid = keyrack_core::lid::Lid::derive(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &canonical,
    );
    let record = keyrack_core::key::KeyRecord {
        lid,
        canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
        parent_lid: None,
        occ_version: 1,
        current_key_version: 1,
        state: keyrack_core::key::KeyState::Enabled,
        key_usage: keyrack_core::key::KeyUsage::EncryptDecrypt,
        key_spec: keyrack_core::key::KeySpec::Aes256,
        origin: keyrack_core::key::KeyOrigin::KeyRack,
        provider_class: keyrack_core::key::ProviderClass::InMemory,
        provider_ref: Some(keyrack_core::key::ProviderRef::new("scoped-conn")),
        identity_tags: keyrack_core::tags::IdentityTags::from_attribute_set(&attrs),
        user_tags: keyrack_core::tags::UserTags::new(),
        created_at: now,
        updated_at: now,
        scheduled_deletion_at: None,
        description: "audit unscoped test".into(),
        key_versions: vec![keyrack_core::key::KeyVersionRecord {
            version_number: 1,
            key_handle: handle,
            provider_ref: Some(keyrack_core::key::ProviderRef::new("scoped-conn")),
            created_at: now,
            is_primary: true,
        }],
    };
    state.storage.create_key(&record).await.unwrap();

    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let result = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: lid.to_string(),
            plaintext: b"data".to_vec(),
            ..Default::default()
        }))
        .await;
    assert!(result.is_ok(), "unscoped connection must pass: {result:?}");

    let events = audit.events();
    let scope_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == keyrack_core::audit::EventType::ScopeOwnerCheck)
        .collect();
    assert!(
        scope_events.is_empty(),
        "no scope_owner_check event when scope_owner is unset"
    );
}

// ── Idempotency conflict on scope_owner change ────────────────────

#[tokio::test]
async fn scope_owner_change_is_conflict_not_idempotent() {
    use keyrack_service::hsm_registration::{classify_registration, RegistrationOutcome};

    let a = keyrack_core::hsm::HsmConnection::new(
        "conn-x",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "test",
    )
    .with_scope_owner("tenant:alpha");

    let b = keyrack_core::hsm::HsmConnection::new(
        "conn-x",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "test",
    )
    .with_scope_owner("tenant:beta");

    let outcome = classify_registration(Some(&a), &b);
    assert!(
        matches!(outcome, RegistrationOutcome::Conflict),
        "changing scope_owner must be a conflict, not idempotent: got {outcome:?}"
    );
}

#[tokio::test]
async fn same_scope_owner_re_register_is_idempotent() {
    use keyrack_service::hsm_registration::{classify_registration, RegistrationOutcome};

    let a = keyrack_core::hsm::HsmConnection::new(
        "conn-y",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "test",
    )
    .with_scope_owner("tenant:acme");

    let b = keyrack_core::hsm::HsmConnection::new(
        "conn-y",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "test",
    )
    .with_scope_owner("tenant:acme");

    let outcome = classify_registration(Some(&a), &b);
    assert!(
        matches!(outcome, RegistrationOutcome::Idempotent),
        "same scope_owner re-register must be idempotent: got {outcome:?}"
    );
}

// ── No-policy backward-compat ─────────────────────────────────────

fn build_no_policy_state() -> (Arc<ServiceState>, Arc<CapturingSink>) {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::{DynamicProviderRegistry, ProviderEntry};
    use keyrack_core::routing::ProviderRouter;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let prov_default = Arc::new(InMemoryProvider::new());
    let prov_custom = Arc::new(InMemoryProvider::new());

    let entries = vec![
        (
            ProviderRef::new("default"),
            ProviderEntry {
                provider: prov_default,
                class: ProviderClass::InMemory,
            },
        ),
        (
            ProviderRef::new("custom-hsm"),
            ProviderEntry {
                provider: prov_custom,
                class: ProviderClass::InMemory,
            },
        ),
    ];
    let registry = Arc::new(
        DynamicProviderRegistry::new(entries, ProviderRef::new("default")).expect("valid registry"),
    );

    let provider_router = ProviderRouter::new(vec![], ProviderRef::new("default"));

    let pdp: Arc<dyn keyrack_core::pdp::PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit = Arc::new(CapturingSink::new());
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(keyrack_core::authn::InsecureAuthenticator),
    ]));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    let state = Arc::new(ServiceState {
        storage,
        providers: registry,
        provider_router,
        pdp,
        audit: audit.clone(),
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });
    (state, audit)
}

#[tokio::test]
async fn no_policy_backend_id_free_select() {
    let (state, _) = build_no_policy_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let resp = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "no-policy select".into(),
            backend_id: Some("custom-hsm".into()),
            ..Default::default()
        }))
        .await;
    assert!(
        resp.is_ok(),
        "no-policy mode must allow backend_id free-select: {resp:?}"
    );
    let meta = resp.unwrap().into_inner().metadata.unwrap();
    assert_eq!(
        meta.backend_id.as_deref(),
        Some("custom-hsm"),
        "selected backend must be custom-hsm"
    );
}

#[tokio::test]
async fn no_policy_default_provider_used_without_backend_id() {
    let (state, _) = build_no_policy_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let resp = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "no-policy default".into(),
            ..Default::default()
        }))
        .await;
    assert!(resp.is_ok(), "no-policy default must work: {resp:?}");
    let meta = resp.unwrap().into_inner().metadata.unwrap();
    assert_eq!(
        meta.backend_id.as_deref(),
        Some("default"),
        "should route to default provider"
    );
}

// ── REST CreateKey scope deny ─────────────────────────────────────

#[tokio::test]
async fn rest_scope_deny_create_key() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_routed_state();
    let conn = keyrack_core::hsm::HsmConnection::new(
        "rest-create-scoped",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "test",
    )
    .with_scope_owner("tenant:acme");
    state.storage.create_hsm_connection(&conn).await.unwrap();
    let prov = Arc::new(InMemoryProvider::new());
    state
        .providers
        .register(
            keyrack_core::key::ProviderRef::new("rest-create-scoped"),
            keyrack_core::registry::ProviderEntry {
                provider: prov,
                class: keyrack_core::key::ProviderClass::InMemory,
            },
        )
        .unwrap();

    let app = keyrack_service::rest::router(state);
    let body = serde_json::json!({
        "key_spec": "AES_256",
        "description": "scope test",
        "backend_id": "rest-create-scoped",
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/keys")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

// ═══════════════════════════════════════════════════════════════════
// SCOPED PRINCIPAL: MATCH → ALLOW + MISMATCH → DENY
// ═══════════════════════════════════════════════════════════════════

/// Test authenticator that returns a principal carrying a configurable `scope`
/// attribute. Mirrors what the JWT authenticator does in production (lifts the
/// namespaced claim into `principal.attributes["scope"]`).
struct ScopedAuthenticator {
    scope: String,
}

impl ScopedAuthenticator {
    fn new(scope: &str) -> Self {
        Self {
            scope: scope.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl keyrack_core::authn::Authenticator for ScopedAuthenticator {
    async fn authenticate(
        &self,
        _metadata: &keyrack_core::authn::RequestMetadata,
    ) -> Result<Option<keyrack_core::authn::AuthnResult>, keyrack_core::authn::AuthnError> {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert(
            "scope".to_string(),
            keyrack_core::pdp::AttributeValue::String(self.scope.clone()),
        );
        Ok(Some(keyrack_core::authn::AuthnResult {
            principal: keyrack_core::pdp::Principal {
                id: "test:scoped-user".into(),
                principal_type: "Service".into(),
                attributes: attrs,
            },
            method: "test-scoped".into(),
        }))
    }
}

/// Build a state using a `ScopedAuthenticator` with the given scope value.
fn build_scoped_state(scope: &str) -> (Arc<ServiceState>, Arc<CapturingSink>) {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::{DynamicProviderRegistry, ProviderEntry};
    use keyrack_core::routing::{ProviderRouter, RoutingRule, RuleAction};
    use std::collections::BTreeMap;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let prov_default = Arc::new(InMemoryProvider::new());
    let prov_tenant = Arc::new(InMemoryProvider::new());

    let entries = vec![
        (
            ProviderRef::new("default"),
            ProviderEntry {
                provider: prov_default,
                class: ProviderClass::InMemory,
            },
        ),
        (
            ProviderRef::new("tenant-hsm"),
            ProviderEntry {
                provider: prov_tenant,
                class: ProviderClass::InMemory,
            },
        ),
    ];
    let registry = Arc::new(
        DynamicProviderRegistry::new(entries, ProviderRef::new("default")).expect("valid registry"),
    );

    let mut match_tags = BTreeMap::new();
    match_tags.insert("tenant".to_string(), "acme".to_string());
    let rules = vec![RoutingRule {
        match_tags,
        action: RuleAction::Route(ProviderRef::new("tenant-hsm")),
    }];
    let provider_router = ProviderRouter::with_rules(rules, ProviderRef::new("default"));

    let pdp: Arc<dyn keyrack_core::pdp::PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit = Arc::new(CapturingSink::new());
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(ScopedAuthenticator::new(scope)),
    ]));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    let state = Arc::new(ServiceState {
        storage,
        providers: registry,
        provider_router,
        pdp,
        audit: audit.clone(),
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });
    (state, audit)
}

/// Build a state with `ScopedAuthenticator` but NO routing rules (no-policy mode).
fn build_scoped_state_no_rules(scope: &str) -> (Arc<ServiceState>, Arc<CapturingSink>) {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::{DynamicProviderRegistry, ProviderEntry};
    use keyrack_core::routing::ProviderRouter;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let prov_default = Arc::new(InMemoryProvider::new());

    let entries = vec![(
        ProviderRef::new("default"),
        ProviderEntry {
            provider: prov_default,
            class: ProviderClass::InMemory,
        },
    )];
    let registry = Arc::new(
        DynamicProviderRegistry::new(entries, ProviderRef::new("default")).expect("valid registry"),
    );

    let provider_router = ProviderRouter::new(vec![], ProviderRef::new("default"));

    let pdp: Arc<dyn keyrack_core::pdp::PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit = Arc::new(CapturingSink::new());
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(ScopedAuthenticator::new(scope)),
    ]));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    let state = Arc::new(ServiceState {
        storage,
        providers: registry,
        provider_router,
        pdp,
        audit: audit.clone(),
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });
    (state, audit)
}

/// Helper: register a scoped connection + provider, create a key bound to it.
async fn setup_scoped_key_in(state: &Arc<ServiceState>, conn_id: &str) -> keyrack_core::lid::Lid {
    let conn = keyrack_core::hsm::HsmConnection::new(
        conn_id,
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "scoped",
    )
    .with_scope_owner("tenant:acme");
    state.storage.create_hsm_connection(&conn).await.unwrap();

    let prov = Arc::new(InMemoryProvider::new());
    state
        .providers
        .register(
            keyrack_core::key::ProviderRef::new(conn_id),
            keyrack_core::registry::ProviderEntry {
                provider: prov.clone(),
                class: keyrack_core::key::ProviderClass::InMemory,
            },
        )
        .unwrap();

    let handle = prov
        .generate_key(&keyrack_core::key::KeySpec::Aes256)
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let mut attrs = keyrack_core::attr::AttributeSet::new();
    attrs.insert(
        "_keyrack_key_id",
        keyrack_core::attr::AttributeValue::String(uuid::Uuid::new_v4().to_string()),
    );
    let canonical =
        keyrack_core::canon::canonicalize(keyrack_core::canon::CanonicalizationVersion::V1, &attrs);
    let lid = keyrack_core::lid::Lid::derive(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &canonical,
    );
    let record = keyrack_core::key::KeyRecord {
        lid,
        canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
        parent_lid: None,
        occ_version: 1,
        current_key_version: 1,
        state: keyrack_core::key::KeyState::Enabled,
        key_usage: keyrack_core::key::KeyUsage::EncryptDecrypt,
        key_spec: keyrack_core::key::KeySpec::Aes256,
        origin: keyrack_core::key::KeyOrigin::KeyRack,
        provider_class: keyrack_core::key::ProviderClass::InMemory,
        provider_ref: Some(keyrack_core::key::ProviderRef::new(conn_id)),
        identity_tags: keyrack_core::tags::IdentityTags::from_attribute_set(&attrs),
        user_tags: keyrack_core::tags::UserTags::new(),
        created_at: now,
        updated_at: now,
        scheduled_deletion_at: None,
        description: "scoped key".into(),
        key_versions: vec![keyrack_core::key::KeyVersionRecord {
            version_number: 1,
            key_handle: handle,
            provider_ref: Some(keyrack_core::key::ProviderRef::new(conn_id)),
            created_at: now,
            is_primary: true,
        }],
    };
    state.storage.create_key(&record).await.unwrap();
    lid
}

// ── gRPC: MATCH → ALLOW (positive control) ───────────────────────

#[tokio::test]
async fn grpc_scope_match_allows_encrypt() {
    let (state, audit) = build_scoped_state("tenant:acme");
    let lid = setup_scoped_key_in(&state, "scoped-enc").await;
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let result = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: lid.to_string(),
            plaintext: b"hello".to_vec(),
            ..Default::default()
        }))
        .await;
    assert!(result.is_ok(), "matching scope must allow: {result:?}");

    let events = audit.events();
    let scope_event = events
        .iter()
        .find(|e| e.event_type == keyrack_core::audit::EventType::ScopeOwnerCheck);
    assert!(
        scope_event.is_some(),
        "scope_owner_check must be emitted on success"
    );
    let ev = scope_event.unwrap();
    assert_eq!(ev.result, keyrack_core::audit::AuditResult::Success);
    assert_eq!(ev.resource.id, "scoped-enc");
    assert_eq!(ev.resource.resource_type, "HsmConnection");
    assert_eq!(
        ev.metadata["scope"],
        serde_json::Value::String("tenant:acme".into())
    );
    assert_eq!(
        ev.metadata["connection_scope_owner"],
        serde_json::Value::String("tenant:acme".into())
    );
}

#[tokio::test]
async fn grpc_scope_match_allows_create_key() {
    let (state, _audit) = build_scoped_state("tenant:acme");

    let conn = keyrack_core::hsm::HsmConnection::new(
        "create-match",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "test",
    )
    .with_scope_owner("tenant:acme");
    state.storage.create_hsm_connection(&conn).await.unwrap();
    let prov = Arc::new(InMemoryProvider::new());
    state
        .providers
        .register(
            keyrack_core::key::ProviderRef::new("create-match"),
            keyrack_core::registry::ProviderEntry {
                provider: prov,
                class: keyrack_core::key::ProviderClass::InMemory,
            },
        )
        .unwrap();

    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    // Use attributes that match the routing rule → routes to tenant-hsm (no scope_owner).
    // Instead, test scope on Encrypt with a key already bound to the scoped conn.
    // For CreateKey, we need a delegate rule. Use the no-policy trick: create with
    // attributes matching the rule so routing selects tenant-hsm, then override is not needed.
    // Actually just test CreateKey using the already-delegated setup: select backend_id
    // matching a DelegateAny rule. We'll use a fresh state without routing rules.
    let result = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "scope match create".into(),
            // Don't select the scoped backend directly; let routing pick tenant-hsm
            // (which has no scope_owner) and test scope enforcement on a directly-bound key.
            ..Default::default()
        }))
        .await;
    assert!(
        result.is_ok(),
        "create without scoped backend must work: {result:?}"
    );

    // Now test CreateKey with a scoped backend in no-policy mode:
    drop(svc);
    drop(state);
    let (state2, audit2) = build_scoped_state_no_rules("tenant:acme");
    let conn2 = keyrack_core::hsm::HsmConnection::new(
        "create-match2",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "test",
    )
    .with_scope_owner("tenant:acme");
    state2.storage.create_hsm_connection(&conn2).await.unwrap();
    let prov2 = Arc::new(InMemoryProvider::new());
    state2
        .providers
        .register(
            keyrack_core::key::ProviderRef::new("create-match2"),
            keyrack_core::registry::ProviderEntry {
                provider: prov2,
                class: keyrack_core::key::ProviderClass::InMemory,
            },
        )
        .unwrap();

    let svc2 = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state2));
    let result = svc2
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "scope match create".into(),
            backend_id: Some("create-match2".into()),
            ..Default::default()
        }))
        .await;
    assert!(
        result.is_ok(),
        "matching scope must allow create: {result:?}"
    );

    let events = audit2.events();
    let scope_event = events
        .iter()
        .find(|e| e.event_type == keyrack_core::audit::EventType::ScopeOwnerCheck);
    assert!(
        scope_event.is_some(),
        "scope_owner_check event on create success"
    );
    assert_eq!(
        scope_event.unwrap().result,
        keyrack_core::audit::AuditResult::Success
    );
}

// ── gRPC: MISMATCH → DENY ────────────────────────────────────────

#[tokio::test]
async fn grpc_scope_mismatch_denies_encrypt() {
    let (state, audit) = build_scoped_state("tenant:other");
    let lid = setup_scoped_key_in(&state, "scoped-mm-enc").await;
    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let err = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: lid.to_string(),
            plaintext: b"hello".to_vec(),
            ..Default::default()
        }))
        .await
        .expect_err("mismatched scope must deny");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let events = audit.events();
    let scope_event = events
        .iter()
        .find(|e| e.event_type == keyrack_core::audit::EventType::ScopeOwnerCheck);
    assert!(
        scope_event.is_some(),
        "scope_owner_check must be emitted on mismatch"
    );
    let ev = scope_event.unwrap();
    assert_eq!(ev.result, keyrack_core::audit::AuditResult::Denied);
    assert_eq!(
        ev.metadata["scope"],
        serde_json::Value::String("tenant:other".into())
    );
    assert_eq!(
        ev.metadata["connection_scope_owner"],
        serde_json::Value::String("tenant:acme".into())
    );
}

#[tokio::test]
async fn grpc_scope_mismatch_denies_create_key() {
    let (state, _) = build_scoped_state_no_rules("tenant:other");
    let conn = keyrack_core::hsm::HsmConnection::new(
        "create-mismatch",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "test",
    )
    .with_scope_owner("tenant:acme");
    state.storage.create_hsm_connection(&conn).await.unwrap();
    let prov = Arc::new(InMemoryProvider::new());
    state
        .providers
        .register(
            keyrack_core::key::ProviderRef::new("create-mismatch"),
            keyrack_core::registry::ProviderEntry {
                provider: prov,
                class: keyrack_core::key::ProviderClass::InMemory,
            },
        )
        .unwrap();

    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let err = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            description: "scope mismatch create".into(),
            backend_id: Some("create-mismatch".into()),
            ..Default::default()
        }))
        .await
        .expect_err("mismatched scope must deny create");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

// ── REST: MATCH → ALLOW ──────────────────────────────────────────

#[tokio::test]
async fn rest_scope_match_allows_encrypt() {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let (state, audit) = build_scoped_state("tenant:acme");
    let lid = setup_scoped_key_in(&state, "rest-match-enc").await;
    let app = keyrack_service::rest::router(state);

    let body = serde_json::json!({
        "plaintext": base64::engine::general_purpose::STANDARD.encode(b"data"),
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/keys/{lid}/actions-encrypt"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::OK,
        "REST encrypt must succeed with matching scope"
    );

    let resp_body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(
        parsed.get("ciphertext_blob").is_some(),
        "response must contain ciphertext_blob"
    );

    let events = audit.events();
    let scope_event = events
        .iter()
        .find(|e| e.event_type == keyrack_core::audit::EventType::ScopeOwnerCheck);
    assert!(
        scope_event.is_some(),
        "scope_owner_check emitted on REST success"
    );
    assert_eq!(
        scope_event.unwrap().result,
        keyrack_core::audit::AuditResult::Success
    );
}

#[tokio::test]
async fn rest_scope_match_allows_create_key() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_scoped_state_no_rules("tenant:acme");
    let conn = keyrack_core::hsm::HsmConnection::new(
        "rest-create-match",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "test",
    )
    .with_scope_owner("tenant:acme");
    state.storage.create_hsm_connection(&conn).await.unwrap();
    let prov = Arc::new(InMemoryProvider::new());
    state
        .providers
        .register(
            keyrack_core::key::ProviderRef::new("rest-create-match"),
            keyrack_core::registry::ProviderEntry {
                provider: prov,
                class: keyrack_core::key::ProviderClass::InMemory,
            },
        )
        .unwrap();

    let app = keyrack_service::rest::router(state);
    let body = serde_json::json!({
        "key_spec": "AES_256",
        "description": "rest scope match create",
        "backend_id": "rest-create-match",
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/keys")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::CREATED,
        "REST create with matching scope must succeed"
    );
}

// ── REST: MISMATCH → DENY ────────────────────────────────────────

#[tokio::test]
async fn rest_scope_mismatch_denies_encrypt() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, audit) = build_scoped_state("tenant:other");
    let lid = setup_scoped_key_in(&state, "rest-mm-enc").await;
    let app = keyrack_service::rest::router(state);

    let body = serde_json::json!({
        "plaintext": base64::engine::general_purpose::STANDARD.encode(b"data"),
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/keys/{lid}/actions-encrypt"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);

    let events = audit.events();
    let scope_event = events
        .iter()
        .find(|e| e.event_type == keyrack_core::audit::EventType::ScopeOwnerCheck);
    assert!(scope_event.is_some(), "scope_owner_check on REST mismatch");
    assert_eq!(
        scope_event.unwrap().result,
        keyrack_core::audit::AuditResult::Denied
    );
}

#[tokio::test]
async fn rest_scope_mismatch_denies_create_key() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_scoped_state_no_rules("tenant:other");
    let conn = keyrack_core::hsm::HsmConnection::new(
        "rest-create-mm",
        keyrack_core::hsm::HsmProviderType::Hsm,
        "/lib.so",
        "test",
    )
    .with_scope_owner("tenant:acme");
    state.storage.create_hsm_connection(&conn).await.unwrap();
    let prov = Arc::new(InMemoryProvider::new());
    state
        .providers
        .register(
            keyrack_core::key::ProviderRef::new("rest-create-mm"),
            keyrack_core::registry::ProviderEntry {
                provider: prov,
                class: keyrack_core::key::ProviderClass::InMemory,
            },
        )
        .unwrap();

    let app = keyrack_service::rest::router(state);
    let body = serde_json::json!({
        "key_spec": "AES_256",
        "description": "rest scope mismatch create",
        "backend_id": "rest-create-mm",
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/keys")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

// ═══════════════════════════════════════════════════════════════════
// REST AUTHN FAIL-CLOSED TESTS
// ═══════════════════════════════════════════════════════════════════
//
// These tests prove that REST handlers reject (401) when authn is
// configured and the caller presents missing/invalid credentials,
// rather than silently downgrading to `keyrack:anonymous`.

/// Authenticator that always rejects — simulates a configured authn
/// (JWT/bootstrap-token) that finds no valid credential.
struct RejectingAuthenticator;

#[async_trait::async_trait]
impl keyrack_core::authn::Authenticator for RejectingAuthenticator {
    async fn authenticate(
        &self,
        _metadata: &keyrack_core::authn::RequestMetadata,
    ) -> Result<Option<keyrack_core::authn::AuthnResult>, keyrack_core::authn::AuthnError> {
        Err(keyrack_core::authn::AuthnError::NoCredential)
    }
}

/// Authenticator that rejects with `InvalidCredential` — simulates a
/// bad/expired token.
struct InvalidCredentialAuthenticator;

#[async_trait::async_trait]
impl keyrack_core::authn::Authenticator for InvalidCredentialAuthenticator {
    async fn authenticate(
        &self,
        _metadata: &keyrack_core::authn::RequestMetadata,
    ) -> Result<Option<keyrack_core::authn::AuthnResult>, keyrack_core::authn::AuthnError> {
        Err(keyrack_core::authn::AuthnError::InvalidCredential(
            "expired token".into(),
        ))
    }
}

/// Build a `ServiceState` wired to a `RejectingAuthenticator`.
fn build_rejecting_authn_state() -> (Arc<ServiceState>, Arc<CapturingSink>) {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::StaticProviderRegistry;
    use keyrack_service::routing::ProviderRouter;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let provider = Arc::new(InMemoryProvider::new());
    let providers = Arc::new(StaticProviderRegistry::single(
        provider,
        ProviderClass::InMemory,
    ));
    let provider_router = ProviderRouter::new(vec![], ProviderRef::new("default"));
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(RejectingAuthenticator),
    ]));
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit = Arc::new(CapturingSink::new());
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    let state = Arc::new(ServiceState {
        storage,
        providers,
        provider_router,
        pdp,
        audit: audit.clone(),
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });
    (state, audit)
}

/// Build a `ServiceState` wired to an `InvalidCredentialAuthenticator`.
fn build_invalid_cred_authn_state() -> Arc<ServiceState> {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::StaticProviderRegistry;
    use keyrack_service::routing::ProviderRouter;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let provider = Arc::new(InMemoryProvider::new());
    let providers = Arc::new(StaticProviderRegistry::single(
        provider,
        ProviderClass::InMemory,
    ));
    let provider_router = ProviderRouter::new(vec![], ProviderRef::new("default"));
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(InvalidCredentialAuthenticator),
    ]));
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit: Arc<dyn AuditSink> = Arc::new(CapturingSink::new());
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    Arc::new(ServiceState {
        storage,
        providers,
        provider_router,
        pdp,
        audit,
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    })
}

/// REST: missing credential → 401 on `CreateKey`.
#[tokio::test]
async fn rest_authn_reject_no_credential_create_key() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, audit) = build_rejecting_authn_state();
    let app = keyrack_service::rest::router(state);
    let body = serde_json::json!({ "key_spec": "AES_256" });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/keys")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(audit.event_count(), 0, "no audit event on authn rejection");
}

/// REST: invalid credential → 401 on `CreateKey`.
#[tokio::test]
async fn rest_authn_reject_invalid_credential_create_key() {
    use axum::body::Body;
    use tower::ServiceExt;

    let state = build_invalid_cred_authn_state();
    let app = keyrack_service::rest::router(state);
    let body = serde_json::json!({ "key_spec": "AES_256" });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/keys")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

/// REST: missing credential → 401 on `ListKeys`.
#[tokio::test]
async fn rest_authn_reject_no_credential_list_keys() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_rejecting_authn_state();
    let app = keyrack_service::rest::router(state);
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/keys")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

/// REST: missing credential → 401 on `GetKey`.
#[tokio::test]
async fn rest_authn_reject_no_credential_get_key() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_rejecting_authn_state();
    let app = keyrack_service::rest::router(state);
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/keys/some-key-id")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

/// REST: missing credential → 401 on `Encrypt`.
#[tokio::test]
async fn rest_authn_reject_no_credential_encrypt() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_rejecting_authn_state();
    let app = keyrack_service::rest::router(state);
    let body = serde_json::json!({
        "plaintext": base64::engine::general_purpose::STANDARD.encode(b"secret"),
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/keys/some-key/actions-encrypt")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

/// REST: missing credential → 401 on `Decrypt`.
#[tokio::test]
async fn rest_authn_reject_no_credential_decrypt() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_rejecting_authn_state();
    let app = keyrack_service::rest::router(state);
    let body = serde_json::json!({
        "ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(b"fake"),
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/keys/some-key/actions-decrypt")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

/// REST: missing credential → 401 on `RotateKey`.
#[tokio::test]
async fn rest_authn_reject_no_credential_rotate_key() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_rejecting_authn_state();
    let app = keyrack_service::rest::router(state);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/keys/some-key/actions-rotate")
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

/// REST: missing credential → 401 on `Sign`.
#[tokio::test]
async fn rest_authn_reject_no_credential_sign() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_rejecting_authn_state();
    let app = keyrack_service::rest::router(state);
    let body = serde_json::json!({
        "message": base64::engine::general_purpose::STANDARD.encode(b"msg"),
        "signing_algorithm": "ED25519",
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/keys/some-key/actions-sign")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

/// REST: missing credential → 401 on aliases.
#[tokio::test]
async fn rest_authn_reject_no_credential_create_alias() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, _) = build_rejecting_authn_state();
    let app = keyrack_service::rest::router(state);
    let body = serde_json::json!({
        "alias_name": "test-alias",
        "target_key_id": "some-key",
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/aliases")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

/// REST: valid credential (`InsecureAuthenticator`) → principal reaches
/// PDP + audit with correct identity (not anonymous-fallback).
#[tokio::test]
async fn rest_authn_valid_credential_reaches_pdp_and_audit() {
    use axum::body::Body;
    use tower::ServiceExt;

    let (state, pdp, audit) = build_test_state();
    let app = keyrack_service::rest::router(state);

    let body = serde_json::json!({ "key_spec": "AES_256", "description": "authn test" });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/keys")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::CREATED);

    assert!(pdp.count() >= 1, "PDP was consulted");
    let events = audit.events();
    assert!(!events.is_empty(), "audit events emitted");
    assert_eq!(
        events[0].principal.id, "keyrack:anonymous",
        "InsecureAuthenticator principal reaches audit"
    );
}

/// REST: 401 response body includes structured error JSON.
#[tokio::test]
async fn rest_authn_reject_response_body_is_json() {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let (state, _) = build_rejecting_authn_state();
    let app = keyrack_service::rest::router(state);
    let body = serde_json::json!({ "key_spec": "AES_256" });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/keys")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "Unauthenticated");
    assert!(body_json["message"]
        .as_str()
        .unwrap()
        .contains("authentication failed"),);
}

/// gRPC: missing credential → Unauthenticated (confirms gRPC was
/// already fail-closed, for parity).
#[tokio::test]
async fn grpc_authn_reject_no_credential() {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::StaticProviderRegistry;
    use keyrack_service::routing::ProviderRouter;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let provider = Arc::new(InMemoryProvider::new());
    let providers = Arc::new(StaticProviderRegistry::single(
        provider,
        ProviderClass::InMemory,
    ));
    let provider_router = ProviderRouter::new(vec![], ProviderRef::new("default"));
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(RejectingAuthenticator),
    ]));
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit: Arc<dyn AuditSink> = Arc::new(CapturingSink::new());
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    let state = Arc::new(ServiceState {
        storage,
        providers,
        provider_router,
        pdp,
        audit,
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });

    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));
    let result = svc
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256 as i32,
            ..Default::default()
        }))
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

// ═══════════════════════════════════════════════════════════════════
// IN-PROCESS mTLS IDENTITY TESTS (docker-free, deterministic)
// ═══════════════════════════════════════════════════════════════════
//
// Mirrors demo 10 (10-mtls-identity) as an in-process CI gate:
//   1. Valid client cert  → principal extracted, reaches PDP/audit
//   2. No client cert     → rejected (Unauthenticated)
//   3. Untrusted CA cert  → TLS-layer rejection

/// Bundle of a generated certificate + its key pair.
struct TestCertBundle {
    params: rcgen::CertificateParams,
    cert: rcgen::Certificate,
    key_pair: rcgen::KeyPair,
}

/// Generate a self-signed CA certificate + key pair using `rcgen`.
fn generate_ca(cn: &str) -> TestCertBundle {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    TestCertBundle {
        params,
        cert,
        key_pair,
    }
}

/// Generate a leaf certificate signed by the given CA.
fn generate_leaf(cn: &str, san_dns: &[&str], ca: &TestCertBundle) -> TestCertBundle {
    let sans: Vec<String> = san_dns.iter().map(|s| (*s).to_string()).collect();
    let mut params = rcgen::CertificateParams::new(sans).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.is_ca = rcgen::IsCa::NoCa;
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key_pair);
    let cert = params.signed_by(&key_pair, &issuer).unwrap();
    TestCertBundle {
        params,
        cert,
        key_pair,
    }
}

/// mTLS case 1: valid client cert → principal extracted, reaches PDP/audit.
///
/// Uses extension injection (no real TLS): injects the DER-encoded client
/// cert as `PeerCertificates`, wired through `MtlsAuthenticator`.
#[tokio::test]
async fn mtls_valid_cert_principal_reaches_pdp_audit() {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::StaticProviderRegistry;
    use keyrack_service::ops::PeerCertificates;
    use keyrack_service::routing::ProviderRouter;

    let ca = generate_ca("Test CA");
    let client = generate_leaf("alice", &[], &ca);
    let client_der = client.cert.der().to_vec();

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let provider = Arc::new(InMemoryProvider::new());
    let providers = Arc::new(StaticProviderRegistry::single(
        provider,
        ProviderClass::InMemory,
    ));
    let provider_router = ProviderRouter::new(vec![], ProviderRef::new("default"));
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(keyrack_core::authn::MtlsAuthenticator),
    ]));
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit = Arc::new(CapturingSink::new());
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    let state = Arc::new(ServiceState {
        storage,
        providers,
        provider_router,
        pdp,
        audit: audit.clone(),
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });

    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let mut req = Request::new(proto::CreateKeyRequest {
        key_spec: proto::KeySpec::Aes256 as i32,
        ..Default::default()
    });
    req.extensions_mut()
        .insert(PeerCertificates(vec![client_der]));

    let result = svc.create_key(req).await;
    assert!(result.is_ok(), "valid mTLS cert should be accepted");

    let events = audit.events();
    assert!(!events.is_empty(), "audit events emitted");
    assert_eq!(
        events[0].principal.id, "alice",
        "principal extracted from cert CN"
    );
}

/// mTLS case 2: no client cert → rejected (Unauthenticated).
///
/// With `MtlsAuthenticator` as the sole authenticator and no peer certs,
/// the chain returns `NoCredential` → gRPC `Unauthenticated`.
#[tokio::test]
async fn mtls_no_cert_rejected() {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::StaticProviderRegistry;
    use keyrack_service::routing::ProviderRouter;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let provider = Arc::new(InMemoryProvider::new());
    let providers = Arc::new(StaticProviderRegistry::single(
        provider,
        ProviderClass::InMemory,
    ));
    let provider_router = ProviderRouter::new(vec![], ProviderRef::new("default"));
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(keyrack_core::authn::MtlsAuthenticator),
    ]));
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit: Arc<dyn AuditSink> = Arc::new(CapturingSink::new());
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    let state = Arc::new(ServiceState {
        storage,
        providers,
        provider_router,
        pdp,
        audit,
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });

    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    let req = Request::new(proto::CreateKeyRequest {
        key_spec: proto::KeySpec::Aes256 as i32,
        ..Default::default()
    });

    let result = svc.create_key(req).await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().code(),
        tonic::Code::Unauthenticated,
        "no client cert → Unauthenticated"
    );
}

/// mTLS case 3: untrusted CA → TLS-layer rejection.
///
/// Starts a real gRPC server with TLS + client CA verification on a
/// localhost port, then connects with a client cert signed by a different
/// (rogue) CA. The TLS handshake itself fails — no application-level
/// response is produced.
#[tokio::test]
async fn mtls_untrusted_ca_tls_rejected() {
    use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let trusted_ca = generate_ca("Trusted CA");
    let rogue_ca = generate_ca("Rogue CA");
    let server_leaf = generate_leaf("localhost", &["localhost"], &trusted_ca);
    let rogue_client = generate_leaf("rogue-alice", &[], &rogue_ca);

    let server_cert_pem = server_leaf.cert.pem();
    let server_key_pem = server_leaf.key_pair.serialize_pem();
    let trusted_ca_pem = trusted_ca.cert.pem();

    let identity = Identity::from_pem(server_cert_pem, server_key_pem);
    let tls = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(Certificate::from_pem(trusted_ca_pem));

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let provider = Arc::new(InMemoryProvider::new());
    let providers: Arc<dyn keyrack_core::registry::ProviderRegistry> =
        Arc::new(keyrack_core::registry::StaticProviderRegistry::single(
            provider,
            keyrack_core::key::ProviderClass::InMemory,
        ));
    let provider_router = keyrack_service::routing::ProviderRouter::new(
        vec![],
        keyrack_core::key::ProviderRef::new("default"),
    );
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(keyrack_core::authn::MtlsAuthenticator),
    ]));
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit: Arc<dyn AuditSink> = Arc::new(CapturingSink::new());
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();

    let state = Arc::new(ServiceState {
        storage,
        providers,
        provider_router,
        pdp,
        audit,
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);
    let server_handle = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .tls_config(tls)
            .expect("TLS config")
            .add_service(keyrack_service::proto::key_service_server::KeyServiceServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .ok();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let rogue_client_cert_pem = rogue_client.cert.pem();
    let rogue_client_key_pem = rogue_client.key_pair.serialize_pem();

    let client_identity = Identity::from_pem(rogue_client_cert_pem, rogue_client_key_pem);
    let ca_cert = Certificate::from_pem(trusted_ca.cert.pem());

    let channel =
        tonic::transport::Channel::from_shared(format!("https://localhost:{}", addr.port()))
            .unwrap()
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .domain_name("localhost")
                    .ca_certificate(ca_cert)
                    .identity(client_identity),
            )
            .unwrap()
            .connect()
            .await;

    match channel {
        Err(_) => {
            // TLS handshake failed — expected (rogue CA not trusted by server).
        }
        Ok(channel) => {
            let mut client =
                keyrack_service::proto::key_service_client::KeyServiceClient::new(channel);
            let result = client
                .create_key(proto::CreateKeyRequest {
                    key_spec: proto::KeySpec::Aes256 as i32,
                    ..Default::default()
                })
                .await;
            assert!(
                result.is_err(),
                "rogue-CA client should be rejected at TLS layer"
            );
        }
    }

    server_handle.abort();
}

// ═══════════════════════════════════════════════════════════════════
// ROUTING EXPLAIN (read-only dry-run)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn explain_routing_returns_routed_for_matching_attributes() {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::{DynamicProviderRegistry, ProviderEntry};
    use keyrack_service::routing::ProviderRouter;
    use std::collections::BTreeMap;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let prov_default = Arc::new(InMemoryProvider::new());
    let prov_acme = Arc::new(InMemoryProvider::new());
    let entries = vec![
        (
            ProviderRef::new("default"),
            ProviderEntry {
                provider: prov_default,
                class: ProviderClass::InMemory,
            },
        ),
        (
            ProviderRef::new("acme-hsm"),
            ProviderEntry {
                provider: prov_acme,
                class: ProviderClass::InMemory,
            },
        ),
    ];
    let registry =
        Arc::new(DynamicProviderRegistry::new(entries, ProviderRef::new("default")).unwrap());
    let provider_router = ProviderRouter::new(
        vec![(
            BTreeMap::from([("tenant".to_string(), "acme".to_string())]),
            ProviderRef::new("acme-hsm"),
        )],
        ProviderRef::new("default"),
    );
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit: Arc<dyn keyrack_core::audit::AuditSink> = Arc::new(CapturingSink::new());
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(keyrack_core::authn::InsecureAuthenticator),
    ]));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let state = Arc::new(ServiceState {
        storage: storage.clone(),
        providers: registry,
        provider_router,
        pdp,
        audit,
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });

    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    // Call ExplainRouting with matching tenant=acme.
    let resp = svc
        .explain_routing(Request::new(proto::ExplainRoutingRequest {
            attributes: [("tenant".to_string(), "acme".to_string())]
                .into_iter()
                .collect(),
            namespace: None,
            backend_id: None,
            hsm_connection_id: None,
        }))
        .await
        .expect("ExplainRouting should succeed");

    let inner = resp.into_inner();
    assert_eq!(inner.outcome, proto::RoutingOutcome::Routed as i32);
    assert_eq!(inner.selected_backend_id, "acme-hsm");
    assert_eq!(inner.matched_rule_index, 0);
    assert!(inner.deny_reason.is_empty());
    assert!(inner.policy_configured);

    // CRITICAL: verify that NO key was created (the store is empty).
    use keyrack_core::storage::StorageBackend;
    let page = storage
        .list_keys(&keyrack_core::storage::KeyFilter::default())
        .await
        .expect("list_keys");
    assert!(
        page.items.is_empty(),
        "ExplainRouting must not create any keys; found {} key(s)",
        page.items.len()
    );
}

#[tokio::test]
async fn explain_routing_returns_deny_and_creates_no_key() {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::{DynamicProviderRegistry, ProviderEntry};
    use keyrack_service::routing::ProviderRouter;
    use std::collections::BTreeMap;

    let storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let prov_default = Arc::new(InMemoryProvider::new());
    let entries = vec![(
        ProviderRef::new("default"),
        ProviderEntry {
            provider: prov_default,
            class: ProviderClass::InMemory,
        },
    )];
    let registry =
        Arc::new(DynamicProviderRegistry::new(entries, ProviderRef::new("default")).unwrap());
    let provider_router = ProviderRouter::new(
        vec![(
            BTreeMap::from([("tenant".to_string(), "acme".to_string())]),
            ProviderRef::new("default"),
        )],
        ProviderRef::new("default"),
    );
    let pdp: Arc<dyn PolicyDecisionPoint> = Arc::new(AlwaysAllow);
    let audit: Arc<dyn keyrack_core::audit::AuditSink> = Arc::new(CapturingSink::new());
    let authn = Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
        Box::new(keyrack_core::authn::InsecureAuthenticator),
    ]));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let state = Arc::new(ServiceState {
        storage: storage.clone(),
        providers: registry,
        provider_router,
        pdp,
        audit,
        authn,
        metrics_handle,
        max_plaintext_bytes: 4096,
        nats_publisher: None,
    });

    let svc = keyrack_service::grpc::KeyServiceImpl::new(Arc::clone(&state));

    // Call ExplainRouting requesting a non-existent backend (default-deny).
    let resp = svc
        .explain_routing(Request::new(proto::ExplainRoutingRequest {
            attributes: std::collections::HashMap::new(),
            namespace: None,
            backend_id: Some("nonexistent".to_string()),
            hsm_connection_id: None,
        }))
        .await
        .expect("ExplainRouting should succeed even for denials");

    let inner = resp.into_inner();
    assert_eq!(inner.outcome, proto::RoutingOutcome::Denied as i32);
    assert!(inner.selected_backend_id.is_empty());
    assert!(!inner.deny_reason.is_empty());

    // CRITICAL: no key created.
    use keyrack_core::storage::StorageBackend;
    let page = storage
        .list_keys(&keyrack_core::storage::KeyFilter::default())
        .await
        .expect("list_keys");
    assert!(
        page.items.is_empty(),
        "ExplainRouting DENY must not create any keys"
    );
}
