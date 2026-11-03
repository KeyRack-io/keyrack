// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Metadata is descriptive, never the source of operation eligibility.

use super::*;
use keyrack_core::key::KeyState;
use keyrack_core::provider::software::SoftwareProvider;
use serde_json::{json, Value};

const MESSAGE: &[u8] = b"lifecycle and history matrix";
const STATES: [KeyState; 6] = [
    KeyState::Creating,
    KeyState::Enabled,
    KeyState::Disabled,
    KeyState::Compromised,
    KeyState::PendingDeletion,
    KeyState::Destroyed,
];

fn fixture(legacy: bool) -> Arc<ServiceState> {
    let mut state = build_test_state_with_provider(
        Arc::new(SoftwareProvider::new()),
        Arc::new(AlwaysAllow),
        Arc::new(CapturingSink::new()),
    );
    Arc::get_mut(&mut state)
        .unwrap()
        .legacy_compromised_key_decrypt = legacy;
    state
}

async fn rest(state: &Arc<ServiceState>, method: &str, path: &str, body: Value) -> (u16, Value) {
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    let response = keyrack_service::rest::router(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn set_state(state: &Arc<ServiceState>, key: &str, live: KeyState, history: bool) {
    let mut record = state.storage.get_key(&key.parse().unwrap()).await.unwrap();
    // Include imported/legacy record combinations that normal API transitions
    // cannot create. Storage must normalize Compromised even with a false latch.
    // Destroyed requires fenced completion; never fabricate that terminal state.
    record.state = if live == KeyState::Destroyed {
        KeyState::Enabled
    } else {
        live
    };
    record.was_compromised = history;
    record.occ_version += 1;
    state.storage.update_key(&record).await.unwrap();
    if live == KeyState::Destroyed {
        let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
        svc.schedule_key_deletion(Request::new(proto::ScheduleKeyDeletionRequest {
            key_id: key.into(),
            grace_period_days: 7,
        }))
        .await
        .unwrap();
        backdate_scheduled_deletion(state, key).await;
        keyrack_service::workers::run_deletion_scan(state)
            .await
            .unwrap();
        assert_eq!(key_state(state, key).await, KeyState::Destroyed);
    }
}

async fn rotated_key(svc: &keyrack_service::grpc::KeyServiceImpl) -> (String, Vec<Vec<u8>>) {
    let key = create_exportable_key(svc).await;
    let mut blobs = Vec::new();
    for version in 1..=3 {
        if version > 1 {
            svc.rotate_key(Request::new(proto::RotateKeyRequest {
                key_id: key.clone(),
            }))
            .await
            .unwrap();
        }
        let encrypted = svc
            .encrypt(Request::new(proto::EncryptRequest {
                key_id: key.clone(),
                plaintext: MESSAGE.into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(encrypted.key_version, version);
        blobs.push(encrypted.ciphertext_blob);
    }
    (key, blobs)
}

#[allow(deprecated)] // Assert the retained wire contract, including after destruction.
async fn assert_metadata(state: &Arc<ServiceState>, key: &str, live: KeyState, history: bool) {
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    let wire_live = i32::from(keyrack_service::convert::key_state_to_proto(&live));
    let wire_legacy = if history {
        i32::from(proto::KeyState::Compromised)
    } else {
        wire_live
    };
    let metadata = svc
        .get_key(Request::new(proto::GetKeyRequest { key_id: key.into() }))
        .await
        .unwrap()
        .into_inner()
        .metadata
        .unwrap();
    assert_eq!(metadata.state, wire_live);
    assert_eq!(metadata.lifecycle_state, wire_live);
    assert_eq!(metadata.has_compromise_history, history);
    let described = svc
        .describe_key(Request::new(proto::DescribeKeyRequest {
            key_id: key.into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .metadata
        .unwrap();
    assert_eq!(described, metadata);
    let listed = svc
        .list_keys(Request::new(proto::ListKeysRequest::default()))
        .await
        .unwrap()
        .into_inner()
        .keys;
    assert_eq!(
        listed.iter().find(|item| item.key_id == key).unwrap(),
        &metadata
    );
    let versions = svc
        .list_key_versions(Request::new(proto::ListKeyVersionsRequest {
            key_id: key.into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .versions;
    assert_eq!(versions.len(), 3);
    assert_eq!(
        versions.iter().map(|v| v.version).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    for version in &versions {
        assert_eq!(version.lifecycle_state, wire_live);
        assert_eq!(version.has_compromise_history, history);
        assert_eq!(version.state, wire_legacy);
        assert_eq!(version.is_primary, version.version == 3);
        let fetched = svc
            .get_key_version(Request::new(proto::GetKeyVersionRequest {
                key_id: key.into(),
                version: version.version,
            }))
            .await
            .unwrap()
            .into_inner()
            .version
            .unwrap();
        assert_eq!(&fetched, version);
    }
    for path in [
        format!("/v1/keys/{key}"),
        format!("/v1/keys/{key}/describe"),
    ] {
        let (status, body) = rest(state, "GET", &path, Value::Null).await;
        assert_eq!(status, 200, "{path}: {body}");
        assert_rest_metadata(&body, live, history);
    }
    let (status, body) = rest(state, "GET", "/v1/keys", Value::Null).await;
    assert_eq!(status, 200);
    let listed = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["lid"] == key)
        .unwrap();
    assert_rest_metadata(listed, live, history);
}

fn assert_rest_metadata(body: &Value, live: KeyState, history: bool) {
    assert_eq!(body["state"], json!(live));
    assert_eq!(body["lifecycle_state"], json!(live));
    assert_eq!(body["has_compromise_history"], json!(history));
    let versions = body["key_versions"].as_array().unwrap();
    assert_eq!(versions.len(), 3);
    assert_eq!(
        versions
            .iter()
            .map(|v| v["version_number"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    for version in versions {
        assert!(
            version.get("state").is_none(),
            "REST never had a legacy version state"
        );
        assert_eq!(version["lifecycle_state"], json!(live));
        assert_eq!(version["has_compromise_history"], json!(history));
        assert_eq!(version["is_primary"], json!(version["version_number"] == 3));
    }
}

async fn assert_decrypt_export(
    state: &Arc<ServiceState>,
    key: &str,
    blobs: &[Vec<u8>],
    live: KeyState,
    history: bool,
) {
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    // Expectations are a table independent of production predicates.
    let decrypt_ok = (!history && matches!(live, KeyState::Enabled | KeyState::Disabled))
        || (state.legacy_compromised_key_decrypt && live == KeyState::Compromised);
    let export_ok = !history && live == KeyState::Enabled;
    let destination = create_aes_key(&svc).await;
    let stored = state.storage.get_key(&key.parse().unwrap()).await.unwrap();
    for action in [
        keyrack_core::audit::AuditAction::Encrypt,
        keyrack_core::audit::AuditAction::Sign,
        keyrack_core::audit::AuditAction::GenerateMac,
        keyrack_core::audit::AuditAction::GenerateDataKey,
        keyrack_core::audit::AuditAction::GenerateDataKeyWithoutPlaintext,
    ] {
        assert_eq!(
            keyrack_service::domain::enforce_state_for_key_op(&stored, &action).is_ok(),
            export_ok
        );
    }
    let encrypted = svc
        .encrypt(Request::new(proto::EncryptRequest {
            key_id: key.into(),
            plaintext: MESSAGE.into(),
            ..Default::default()
        }))
        .await;
    if export_ok {
        assert_eq!(encrypted.unwrap().into_inner().key_version, 3);
    } else {
        assert_eq!(
            encrypted.unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }
    let (status, body) = rest(
        state,
        "POST",
        &format!("/v1/keys/{key}/actions-encrypt"),
        json!({
            "plaintext": base64::engine::general_purpose::STANDARD.encode(MESSAGE),
        }),
    )
    .await;
    assert_eq!(
        status,
        if export_ok { 200 } else { 409 },
        "REST encrypt: {body}"
    );
    for (index, blob) in blobs.iter().enumerate() {
        let version = u32::try_from(index + 1).unwrap();
        let decrypted = svc
            .decrypt(Request::new(proto::DecryptRequest {
                key_id: key.into(),
                ciphertext_blob: blob.clone(),
                ..Default::default()
            }))
            .await;
        if decrypt_ok {
            assert_eq!(decrypted.unwrap().into_inner().plaintext, MESSAGE);
        } else {
            assert_eq!(
                decrypted.unwrap_err().code(),
                tonic::Code::FailedPrecondition,
                "decrypt version {version}, live={live}, history={history}"
            );
        }
        let (status, body) = rest(
            state,
            "POST",
            &format!("/v1/keys/{key}/actions-decrypt"),
            json!({
                "ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(blob),
            }),
        )
        .await;
        assert_eq!(
            status,
            if decrypt_ok { 200 } else { 409 },
            "REST decrypt: {body}"
        );
        if decrypt_ok {
            assert_eq!(
                body["plaintext"],
                json!(base64::engine::general_purpose::STANDARD.encode(MESSAGE))
            );
        }
        let reencrypted = svc
            .re_encrypt(Request::new(proto::ReEncryptRequest {
                source_key_id: key.into(),
                ciphertext_blob: blob.clone(),
                destination_key_id: destination.clone(),
                ..Default::default()
            }))
            .await;
        if decrypt_ok {
            let output = reencrypted.unwrap().into_inner();
            let plaintext = svc
                .decrypt(Request::new(proto::DecryptRequest {
                    key_id: destination.clone(),
                    ciphertext_blob: output.ciphertext_blob,
                    ..Default::default()
                }))
                .await
                .unwrap()
                .into_inner()
                .plaintext;
            assert_eq!(plaintext, MESSAGE);
        } else {
            assert_eq!(
                reencrypted.unwrap_err().code(),
                tonic::Code::FailedPrecondition
            );
        }
        let (status, body) = rest(
            state,
            "POST",
            &format!("/v1/keys/{key}/actions-re-encrypt"),
            json!({
                "ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(blob),
                "destination_key_id": destination,
            }),
        )
        .await;
        assert_eq!(
            status,
            if decrypt_ok { 200 } else { 409 },
            "REST re-encrypt: {body}"
        );
        // Export has no REST endpoint and is deliberately stricter than decrypt.
        let exported = svc
            .get_key_material(Request::new(proto::GetKeyMaterialRequest {
                key_id: key.into(),
                key_version: version,
                wrapping_key: None,
            }))
            .await;
        if export_ok {
            assert!(!exported.unwrap().into_inner().key_material.is_empty());
        } else {
            assert_eq!(
                exported.unwrap_err().code(),
                tonic::Code::FailedPrecondition,
                "export version {version}, live={live}, history={history}"
            );
        }
    }
}

#[tokio::test]
async fn lifecycle_history_legacy_matrix_metadata_and_decrypt_export() {
    for legacy in [false, true] {
        for history in [false, true] {
            for live in STATES {
                let state = fixture(legacy);
                let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
                let (key, blobs) = rotated_key(&svc).await;
                set_state(&state, &key, live, history).await;
                let effective_history = history || live == KeyState::Compromised;
                assert_metadata(&state, &key, live, effective_history).await;
                assert_decrypt_export(&state, &key, &blobs, live, effective_history).await;
            }
        }
    }
}

// This is a metadata-service restart: close/reopen the actual SQLite file and
// recreate handlers with fresh uncached storage, retaining the test provider. It does not
// claim that the software provider persists material across a process restart.
fn reopen(state: Arc<ServiceState>, path: &std::path::Path) -> Arc<ServiceState> {
    let mut state = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("service still holds state"));
    state.storage = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap());
    state.storage = Arc::new(keyrack_sqlite::SqliteStorage::open(path).unwrap());
    Arc::new(state)
}

#[tokio::test]
async fn lifecycle_metadata_survives_cancel_restart_and_completed_destruction() {
    for legacy in [false, true] {
        for history in [false, true] {
            let dir =
                std::env::temp_dir().join(format!("keyrack-lifecycle-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("keys.sqlite");
            let mut state = fixture(legacy);
            Arc::get_mut(&mut state).unwrap().storage =
                Arc::new(keyrack_sqlite::SqliteStorage::open(&path).unwrap());
            let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
            let (key, blobs) = rotated_key(&svc).await;
            if history {
                svc.report_key_compromise(Request::new(proto::ReportKeyCompromiseRequest {
                    key_id: key.clone(),
                }))
                .await
                .unwrap();
            }
            let initial = if history {
                KeyState::Compromised
            } else {
                KeyState::Enabled
            };
            assert_metadata(&state, &key, initial, history).await;
            assert_decrypt_export(&state, &key, &blobs, initial, history).await;
            svc.schedule_key_deletion(Request::new(proto::ScheduleKeyDeletionRequest {
                key_id: key.clone(),
                grace_period_days: 7,
            }))
            .await
            .unwrap();
            drop(svc);
            state = reopen(state, &path);
            assert_metadata(&state, &key, KeyState::PendingDeletion, history).await;
            assert_decrypt_export(&state, &key, &blobs, KeyState::PendingDeletion, history).await;
            let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
            svc.cancel_key_deletion(Request::new(proto::CancelKeyDeletionRequest {
                key_id: key.clone(),
            }))
            .await
            .unwrap();
            drop(svc);
            state = reopen(state, &path);
            assert_metadata(&state, &key, KeyState::Disabled, history).await;
            assert_decrypt_export(&state, &key, &blobs, KeyState::Disabled, history).await;
            let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
            svc.schedule_key_deletion(Request::new(proto::ScheduleKeyDeletionRequest {
                key_id: key.clone(),
                grace_period_days: 7,
            }))
            .await
            .unwrap();
            drop(svc);
            backdate_scheduled_deletion(&state, &key).await;
            let before = state.storage.get_key(&key.parse().unwrap()).await.unwrap();
            keyrack_service::workers::run_deletion_scan(&state)
                .await
                .unwrap();
            for version in &before.key_versions {
                let provider = state
                    .providers
                    .resolve_for_version(&before, version.version_number)
                    .unwrap();
                assert!(
                    provider
                        .provider
                        .export_key_material(version.resident_handle().unwrap())
                        .await
                        .is_err(),
                    "completed destruction must erase every version's material"
                );
            }
            assert_metadata(&state, &key, KeyState::Destroyed, history).await;
            assert_decrypt_export(&state, &key, &blobs, KeyState::Destroyed, history).await;
            state = reopen(state, &path);
            assert_metadata(&state, &key, KeyState::Destroyed, history).await;
            assert_decrypt_export(&state, &key, &blobs, KeyState::Destroyed, history).await;
            drop(state);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[tokio::test]
async fn lifecycle_history_legacy_matrix_verification_is_separate() {
    for legacy in [false, true] {
        for history in [false, true] {
            for live in STATES {
                let state = fixture(legacy);
                let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
                let signing = svc
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
                let hmac = create_hmac_key(&svc).await;
                let signature = svc
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
                let mac = svc
                    .generate_mac(Request::new(proto::GenerateMacRequest {
                        key_id: hmac.clone(),
                        message: MESSAGE.into(),
                        mac_algorithm: proto::MacAlgorithm::HmacSha256.into(),
                    }))
                    .await
                    .unwrap()
                    .into_inner()
                    .mac;
                for key in [&signing, &hmac] {
                    set_state(&state, key, live, history).await;
                }
                // Mathematical verification ignores history and the decrypt override.
                // Native Verify/VerifyMac select the primary; neither accepts a version.
                let allowed = matches!(
                    live,
                    KeyState::Enabled | KeyState::Disabled | KeyState::Compromised
                );
                let verified = svc
                    .verify(Request::new(proto::VerifyRequest {
                        key_id: signing.clone(),
                        message: MESSAGE.into(),
                        signature: signature.clone(),
                        signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
                        ..Default::default()
                    }))
                    .await;
                let verified_mac = svc
                    .verify_mac(Request::new(proto::VerifyMacRequest {
                        key_id: hmac.clone(),
                        message: MESSAGE.into(),
                        mac: mac.clone(),
                        mac_algorithm: proto::MacAlgorithm::HmacSha256.into(),
                    }))
                    .await;
                if allowed {
                    assert!(verified.unwrap().into_inner().signature_valid);
                    assert!(verified_mac.unwrap().into_inner().mac_valid);
                } else {
                    assert_eq!(
                        verified.unwrap_err().code(),
                        tonic::Code::FailedPrecondition
                    );
                    assert_eq!(
                        verified_mac.unwrap_err().code(),
                        tonic::Code::FailedPrecondition
                    );
                }
                for (key, action, body, result_field) in [
                    (
                        &signing,
                        "verify",
                        json!({"message": base64::engine::general_purpose::STANDARD.encode(MESSAGE),
                        "signature": base64::engine::general_purpose::STANDARD.encode(&signature), "signing_algorithm": "ED25519"}),
                        "signature_valid",
                    ),
                    (
                        &hmac,
                        "verify-mac",
                        json!({"message": base64::engine::general_purpose::STANDARD.encode(MESSAGE),
                        "mac": base64::engine::general_purpose::STANDARD.encode(&mac), "mac_algorithm": "HMAC_SHA_256"}),
                        "mac_valid",
                    ),
                ] {
                    let (status, body) = rest(
                        &state,
                        "POST",
                        &format!("/v1/keys/{key}/actions-{action}"),
                        body,
                    )
                    .await;
                    assert_eq!(status, if allowed { 200 } else { 409 }, "{action}: {body}");
                    if allowed {
                        assert_eq!(body[result_field], json!(true));
                    }
                }
            }
        }
    }
}
