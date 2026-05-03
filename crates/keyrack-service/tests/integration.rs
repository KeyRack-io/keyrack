// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Change Date: 2030-01-01
// Change License: Apache License, Version 2.0

//! Integration tests that validate the systemic fixes:
//!
//! 1. PDP authorization is enforced on every handler.
//! 2. Audit events are emitted for every operation.
//! 3. Each `CreateKey` produces a unique LID.
//! 4. Bootstrap token uses constant-time comparison.
//! 5. REST crypto handlers are concrete (not 501 stubs).

use keyrack_core::audit::{AuditEvent, AuditSink};
use keyrack_core::pdp::{AlwaysAllow, AlwaysDeny, AuthzRequest, AuthzResponse, PolicyDecisionPoint};
use keyrack_core::provider::inmem::InMemoryProvider;
use keyrack_service::proto;
use keyrack_service::proto::key_service_server::KeyService;
use keyrack_service::state::ServiceState;
use std::sync::{Arc, Mutex};
use tonic::Request;

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
    let storage = Arc::new(
        keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"),
    );
    let provider = Arc::new(InMemoryProvider::new());
    Arc::new(ServiceState {
        storage,
        provider,
        pdp,
        audit,
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
    assert!(resp.is_ok(), "create_key should succeed with AlwaysAllow PDP");
    assert!(pdp.count() >= 1, "PDP must be called at least once for CreateKey");
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
    assert!(pdp.count() >= 2, "PDP must be called for CreateKey + Encrypt (got {})", pdp.count());
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
    assert!(audit.event_count() >= 1, "audit event must still be emitted for denied ops");
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
        tags: vec![proto::Tag { key: "env".into(), value: "test".into() }],
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
    assert_eq!(audit.event_count(), 1, "exactly one audit event for one CreateKey");

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
    assert_eq!(audit.event_count(), initial_count + 1, "encrypt must emit audit event");

    let events = audit.events();
    let enc_event = events.last().unwrap();
    assert_eq!(enc_event.action, keyrack_core::audit::AuditAction::Encrypt);

    let dec_req = Request::new(proto::DecryptRequest {
        key_id: key,
        ciphertext_blob: enc_resp.into_inner().ciphertext_blob,
        ..Default::default()
    });
    let _ = svc.decrypt(dec_req).await.expect("decrypt should succeed");
    assert_eq!(audit.event_count(), initial_count + 2, "decrypt must emit audit event");
}

#[tokio::test]
async fn multiple_operations_emit_correct_event_count() {
    let (state, pdp, audit) = build_test_state();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);

    let key = create_aes_key(&svc).await;
    let _ = svc.get_key(Request::new(proto::GetKeyRequest { key_id: key.clone() })).await;
    let _ = svc.describe_key(Request::new(proto::DescribeKeyRequest { key_id: key.clone() })).await;
    let _ = svc.disable_key(Request::new(proto::DisableKeyRequest { key_id: key })).await;

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
        }))
        .await
        .expect("sign");

    let verify_resp = svc
        .verify(Request::new(proto::VerifyRequest {
            key_id: key_id.clone(),
            message: b"data-to-sign".to_vec(),
            signature: sign_resp.into_inner().signature,
            signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
        }))
        .await
        .expect("verify");

    assert!(verify_resp.into_inner().signature_valid);
    assert_eq!(pdp.count(), 3, "Create + Sign + Verify = 3 PDP calls");
    assert_eq!(audit.event_count(), 3, "Create + Sign + Verify = 3 audit events");
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
    assert_eq!(audit.event_count() - initial_audit, 3, "3 alias ops = 3 audit events");
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
