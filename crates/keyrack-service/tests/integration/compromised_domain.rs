// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Supplemental coverage of the caller-authorized domain helpers and unchanged
//! mathematical verification semantics. The baseline-proven binary acceptance
//! suite is separate; these tests exercise the new domain audit-context API.

use super::*;
use keyrack_core::audit::AuditAction;
use keyrack_core::pdp::Principal;
use keyrack_core::provider::software::SoftwareProvider;
use keyrack_service::domain::{crypto, DomainError};
use keyrack_service::ops::OpContext;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const MARKER: &str = "legacy_compromised_key_decrypt";
const MESSAGE: &[u8] = b"supplemental compromise tests";

fn fixture(legacy: bool) -> (Arc<ServiceState>, Arc<CapturingSink>) {
    let audit = Arc::new(CapturingSink::new());
    let mut state = build_test_state_with_provider(
        Arc::new(SoftwareProvider::new()),
        Arc::new(AlwaysAllow),
        audit.clone(),
    );
    Arc::get_mut(&mut state)
        .unwrap()
        .legacy_compromised_key_decrypt = legacy;
    (state, audit)
}

fn context(key: &str, action: AuditAction) -> OpContext {
    OpContext::key(action, Principal::system(), key)
}

fn decrypt_input(key: &str, blob: &[u8]) -> crypto::DecryptInput {
    crypto::DecryptInput {
        key_id: key.into(),
        ciphertext_blob: blob.into(),
        encryption_context: None,
        audit_context: context(key, AuditAction::Decrypt),
    }
}

fn reencrypt_input(source: &str, destination: &str, blob: &[u8]) -> crypto::ReEncryptInput {
    crypto::ReEncryptInput {
        source_key_id: source.into(),
        destination_key_id: destination.into(),
        ciphertext_blob: blob.into(),
        source_encryption_context: None,
        destination_encryption_context: None,
        principal_scope: None,
        principal_id: Principal::system().id,
        audit_context: context(source, AuditAction::ReEncryptFrom),
    }
}

async fn encrypt_blob(service: &keyrack_service::grpc::KeyServiceImpl, key: &str) -> Vec<u8> {
    service
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: key.into(),
            plaintext: MESSAGE.into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .ciphertext_blob
}

async fn compromise(service: &keyrack_service::grpc::KeyServiceImpl, key: &str) {
    service
        .report_key_compromise(Request::new(proto::ReportKeyCompromiseRequest {
            key_id: key.into(),
        }))
        .await
        .unwrap();
}

fn assert_domain_denial<T>(result: Result<T, DomainError>) {
    match result {
        Err(DomainError::FailedPrecondition(_)) => {}
        Err(error) => panic!("expected lifecycle denial, not {error:?}"),
        Ok(_) => panic!("compromised key reached successful domain crypto"),
    }
}

async fn rest_action(
    state: &Arc<ServiceState>,
    key: &str,
    action: &str,
    body: Value,
) -> (u16, Value) {
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    let response = keyrack_service::rest::router(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/v1/keys/{key}/actions-{action}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn dormant_domain_decrypt_obeys_default_denial() {
    let (state, audit) = fixture(false);
    let service = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    let key = create_aes_key(&service).await;
    let blob = encrypt_blob(&service, &key).await;
    assert_eq!(
        crypto::decrypt(&state, decrypt_input(&key, &blob))
            .await
            .unwrap()
            .plaintext,
        MESSAGE
    );
    compromise(&service, &key).await;
    assert_domain_denial(crypto::decrypt(&state, decrypt_input(&key, &blob)).await);
    assert!(audit
        .events()
        .iter()
        .all(|event| !event.metadata.contains_key(MARKER)));
}

#[tokio::test]
async fn dormant_domain_reencrypt_obeys_source_default_denial() {
    let (state, audit) = fixture(false);
    let service = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    let source = create_aes_key(&service).await;
    let destination = create_aes_key(&service).await;
    let blob = encrypt_blob(&service, &source).await;
    let positive = crypto::re_encrypt(&state, reencrypt_input(&source, &destination, &blob))
        .await
        .unwrap();
    assert_eq!(
        crypto::decrypt(
            &state,
            decrypt_input(&destination, &positive.ciphertext_blob)
        )
        .await
        .unwrap()
        .plaintext,
        MESSAGE
    );
    compromise(&service, &source).await;
    assert_domain_denial(
        crypto::re_encrypt(&state, reencrypt_input(&source, &destination, &blob)).await,
    );
    assert!(audit
        .events()
        .iter()
        .all(|event| !event.metadata.contains_key(MARKER)));
}

#[tokio::test]
async fn dormant_domain_legacy_uses_emit_correlated_structured_markers() {
    let (state, audit) = fixture(true);
    let service = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    let source = create_aes_key(&service).await;
    let destination = create_aes_key(&service).await;
    let blob = encrypt_blob(&service, &source).await;
    compromise(&service, &source).await;
    let decrypt = decrypt_input(&source, &blob);
    let decrypt_request_id = decrypt.audit_context.request_id.clone();
    assert_eq!(
        crypto::decrypt(&state, decrypt).await.unwrap().plaintext,
        MESSAGE
    );
    let reencrypt = reencrypt_input(&source, &destination, &blob);
    let reencrypt_request_id = reencrypt.audit_context.request_id.clone();
    let output = crypto::re_encrypt(&state, reencrypt).await.unwrap();
    assert_eq!(
        crypto::decrypt(&state, decrypt_input(&destination, &output.ciphertext_blob))
            .await
            .unwrap()
            .plaintext,
        MESSAGE
    );
    let events = audit.events();
    let marked: Vec<_> = events
        .iter()
        .filter(|event| event.metadata.contains_key(MARKER))
        .collect();
    assert_eq!(
        marked.len(),
        2,
        "ordinary destination decrypt adds no override marker"
    );
    for (event, (action, request_id)) in marked.iter().zip([
        (AuditAction::Decrypt, decrypt_request_id),
        (AuditAction::ReEncryptFrom, reencrypt_request_id),
    ]) {
        assert_eq!(event.action, action);
        assert_eq!(event.request_id.as_deref(), Some(request_id.as_str()));
        assert_eq!(event.principal.id, Principal::system().id);
        assert_eq!(event.resource.id, source);
        assert_eq!(event.metadata[MARKER], json!("true"));
        assert_eq!(event.metadata["key_state"], json!("compromised"));
        assert_eq!(event.metadata["phase"], json!("provider_dispatch"));
    }
}

async fn signing_fixture(
    service: &keyrack_service::grpc::KeyServiceImpl,
) -> (String, Vec<u8>, String, Vec<u8>) {
    let signing = service
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Ed25519.into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .metadata
        .unwrap()
        .key_id;
    let hmac = create_hmac_key(service).await;
    let signature = service
        .sign(Request::new(proto::SignRequest {
            key_id: signing.clone(),
            message: MESSAGE.into(),
            signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .signature;
    let mac = service
        .generate_mac(Request::new(proto::GenerateMacRequest {
            key_id: hmac.clone(),
            message: MESSAGE.into(),
            mac_algorithm: proto::MacAlgorithm::HmacSha256.into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .mac;
    (signing, signature, hmac, mac)
}

async fn verification_state(
    service: &keyrack_service::grpc::KeyServiceImpl,
    keys: &[&str],
    step: u8,
) {
    for key in keys {
        match step {
            0 => {}
            1 => {
                service
                    .disable_key(Request::new(proto::DisableKeyRequest {
                        key_id: (*key).into(),
                    }))
                    .await
                    .unwrap();
            }
            2 => compromise(service, key).await,
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn grpc_verify_and_verify_mac_retain_all_three_existing_states() {
    let (state, audit) = fixture(false);
    let service = keyrack_service::grpc::KeyServiceImpl::new(state);
    let (signing, signature, hmac, mac) = signing_fixture(&service).await;
    for step in 0..=2 {
        verification_state(&service, &[&signing, &hmac], step).await;
        let verified = service
            .verify(Request::new(proto::VerifyRequest {
                key_id: signing.clone(),
                message: MESSAGE.into(),
                signature: signature.clone(),
                signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            verified.signature_valid,
            "mathematical Verify in state step {step}"
        );
        let verified_mac = service
            .verify_mac(Request::new(proto::VerifyMacRequest {
                key_id: hmac.clone(),
                message: MESSAGE.into(),
                mac: mac.clone(),
                mac_algorithm: proto::MacAlgorithm::HmacSha256.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            verified_mac.mac_valid,
            "mathematical VerifyMac in state step {step}"
        );
    }
    assert!(audit
        .events()
        .iter()
        .all(|event| !event.metadata.contains_key(MARKER)));
}

#[tokio::test]
async fn rest_verify_and_verify_mac_retain_all_three_existing_states() {
    let (state, audit) = fixture(false);
    let service = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    let (signing, signature, hmac, mac) = signing_fixture(&service).await;
    for step in 0..=2 {
        verification_state(&service, &[&signing, &hmac], step).await;
        let (status, body) = rest_action(
            &state,
            &signing,
            "verify",
            json!({
                "message": base64::engine::general_purpose::STANDARD.encode(MESSAGE),
                "signature": base64::engine::general_purpose::STANDARD.encode(&signature),
                "signing_algorithm": "ED25519",
            }),
        )
        .await;
        assert_eq!(status, 200, "REST Verify state step {step}: {body}");
        assert_eq!(body["signature_valid"], json!(true));
        let (status, body) = rest_action(
            &state,
            &hmac,
            "verify-mac",
            json!({
                "message": base64::engine::general_purpose::STANDARD.encode(MESSAGE),
                "mac": base64::engine::general_purpose::STANDARD.encode(&mac),
                "mac_algorithm": "HMAC_SHA_256",
            }),
        )
        .await;
        assert_eq!(status, 200, "REST VerifyMac state step {step}: {body}");
        assert_eq!(body["mac_valid"], json!(true));
    }
    assert!(audit
        .events()
        .iter()
        .all(|event| !event.metadata.contains_key(MARKER)));
}

#[tokio::test]
async fn legacy_flag_does_not_permit_mac_or_either_data_key_generation() {
    let (state, audit) = fixture(true);
    let service = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    let aes = create_aes_key(&service).await;
    let hmac = create_hmac_key(&service).await;
    for key in [&aes, &hmac] {
        compromise(&service, key).await;
    }
    let mac = service
        .generate_mac(Request::new(proto::GenerateMacRequest {
            key_id: hmac.clone(),
            message: MESSAGE.into(),
            mac_algorithm: proto::MacAlgorithm::HmacSha256.into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(mac.code(), tonic::Code::FailedPrecondition);
    let data_key = service
        .generate_data_key(Request::new(proto::GenerateDataKeyRequest {
            key_id: aes.clone(),
            key_spec: proto::KeySpec::Aes256.into(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(data_key.code(), tonic::Code::FailedPrecondition);
    let ciphertext_only = service
        .generate_data_key_without_plaintext(Request::new(
            proto::GenerateDataKeyWithoutPlaintextRequest {
                key_id: aes.clone(),
                key_spec: proto::KeySpec::Aes256.into(),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(ciphertext_only.code(), tonic::Code::FailedPrecondition);
    let (status, body) = rest_action(&state, &hmac, "generate-mac", json!({
        "message": base64::engine::general_purpose::STANDARD.encode(MESSAGE), "mac_algorithm": "HMAC_SHA_256",
    })).await;
    assert_eq!(status, 409, "REST MAC generation: {body}");
    let (status, body) = rest_action(
        &state,
        &aes,
        "generate-data-key",
        json!({"key_spec": "AES_256"}),
    )
    .await;
    assert_eq!(status, 409, "REST data-key generation: {body}");
    assert!(audit
        .events()
        .iter()
        .all(|event| !event.metadata.contains_key(MARKER)));
}

#[tokio::test]
async fn legacy_flag_is_not_an_override_for_historically_compromised_disabled_keys() {
    let (state, audit) = fixture(true);
    let service = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    let key = create_aes_key(&service).await;
    let destination = create_aes_key(&service).await;
    let blob = encrypt_blob(&service, &key).await;
    compromise(&service, &key).await;
    service
        .schedule_key_deletion(Request::new(proto::ScheduleKeyDeletionRequest {
            key_id: key.clone(),
            grace_period_days: 30,
        }))
        .await
        .unwrap();
    let disabled = service
        .cancel_key_deletion(Request::new(proto::CancelKeyDeletionRequest {
            key_id: key.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .metadata
        .unwrap();
    assert_eq!(disabled.state, i32::from(proto::KeyState::Disabled));
    let error = service
        .decrypt(Request::new(proto::DecryptRequest {
            key_id: key.clone(),
            ciphertext_blob: blob.clone(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    let (status, body) = rest_action(
        &state,
        &key,
        "decrypt",
        json!({
            "ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(&blob),
        }),
    )
    .await;
    assert_eq!(status, 409, "legacy override is Compromised-only: {body}");
    assert_domain_denial(crypto::decrypt(&state, decrypt_input(&key, &blob)).await);
    assert_domain_denial(
        crypto::re_encrypt(&state, reencrypt_input(&key, &destination, &blob)).await,
    );
    assert!(audit
        .events()
        .iter()
        .all(|event| !event.metadata.contains_key(MARKER)));
}

struct ExportCountingProvider {
    inner: InMemoryProvider,
    exports: AtomicUsize,
}

#[async_trait::async_trait]
impl keyrack_core::provider::CryptoProvider for ExportCountingProvider {
    async fn generate_key(
        &self,
        spec: &keyrack_core::key::KeySpec,
    ) -> keyrack_core::error::Result<keyrack_core::provider::KeyHandle> {
        self.inner.generate_key(spec).await
    }

    async fn encrypt(
        &self,
        handle: &keyrack_core::provider::KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> keyrack_core::error::Result<keyrack_core::provider::EncryptOutput> {
        self.inner.encrypt(handle, plaintext, aad).await
    }

    async fn decrypt(
        &self,
        handle: &keyrack_core::provider::KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> keyrack_core::error::Result<keyrack_core::sensitive::Sensitive<Vec<u8>>> {
        self.inner.decrypt(handle, ciphertext, aad).await
    }

    async fn sign(
        &self,
        handle: &keyrack_core::provider::KeyHandle,
        algorithm: keyrack_core::provider::SigningAlgorithm,
        message: &[u8],
    ) -> keyrack_core::error::Result<Vec<u8>> {
        self.inner.sign(handle, algorithm, message).await
    }

    async fn verify(
        &self,
        handle: &keyrack_core::provider::KeyHandle,
        algorithm: keyrack_core::provider::SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> keyrack_core::error::Result<bool> {
        self.inner
            .verify(handle, algorithm, message, signature)
            .await
    }

    async fn generate_random(
        &self,
        length: usize,
    ) -> keyrack_core::error::Result<keyrack_core::sensitive::Sensitive<Vec<u8>>> {
        self.inner.generate_random(length).await
    }

    async fn destroy_key(
        &self,
        handle: &keyrack_core::provider::KeyHandle,
    ) -> keyrack_core::error::Result<()> {
        self.inner.destroy_key(handle).await
    }

    fn capabilities(&self) -> keyrack_core::provider::ProviderCapabilities {
        self.inner.capabilities()
    }

    async fn export_key_material(
        &self,
        handle: &keyrack_core::provider::KeyHandle,
    ) -> keyrack_core::error::Result<keyrack_core::sensitive::Sensitive<Vec<u8>>> {
        self.exports.fetch_add(1, Ordering::SeqCst);
        self.inner.export_key_material(handle).await
    }
}

struct PausingExportPdp {
    armed: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl PolicyDecisionPoint for PausingExportPdp {
    async fn evaluate(&self, request: &AuthzRequest) -> keyrack_core::error::Result<AuthzResponse> {
        if request.action == AuditAction::GetKeyMaterial && self.armed.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        AlwaysAllow.evaluate(request).await
    }
}

#[tokio::test]
async fn export_rechecks_compromise_after_waiting_for_pdp_before_provider_dispatch() {
    let provider = Arc::new(ExportCountingProvider {
        inner: InMemoryProvider::new(),
        exports: AtomicUsize::new(0),
    });
    let pdp = Arc::new(PausingExportPdp {
        armed: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let state = build_test_state_with_provider(
        provider.clone(),
        pdp.clone(),
        Arc::new(CapturingSink::new()),
    );
    let service = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    let key = service
        .create_key(Request::new(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            exportable: true,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .metadata
        .unwrap()
        .key_id;
    let request = proto::GetKeyMaterialRequest {
        key_id: key.clone(),
        ..Default::default()
    };
    let raw = service
        .get_key_material(Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(raw.key_material.len(), 32);
    assert_eq!(provider.exports.load(Ordering::SeqCst), 1);
    // A previous real export persists first_exported_at. The vulnerable second
    // export therefore has no OCC write whose failure could hide leaked bytes.
    let lid: keyrack_core::lid::Lid = key.parse().unwrap();
    assert!(state
        .storage
        .get_key(&lid)
        .await
        .unwrap()
        .first_exported_at
        .is_some());
    provider.exports.store(0, Ordering::SeqCst);
    pdp.armed.store(true, Ordering::SeqCst);
    let waiting_service = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    let pending_export = tokio::spawn(async move {
        waiting_service
            .get_key_material(Request::new(request))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), pdp.entered.notified())
        .await
        .expect("export reached the deliberately blocked PDP");
    compromise(&service, &key).await;
    pdp.release.notify_one();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), pending_export)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
    assert_eq!(provider.exports.load(Ordering::SeqCst), 0, "compromise during authorization must prevent provider export, not merely suppress its response");
}
