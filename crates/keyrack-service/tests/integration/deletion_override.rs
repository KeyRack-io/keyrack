// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use keyrack_core::key::{
    Exportability, KeyMaterial, KeyRecord, KeySpec, KeyState, ParentWrappedMaterial, ProviderRef,
};
use keyrack_core::provider::software::{SoftwareProvider, SOFTWARE_WRAPPING_MECHANISM};
use keyrack_core::wrapping::{VersionedKeyId, WrappingIdentifier};
use keyrack_service::domain::{self, CreateKeyInput};
use keyrack_service::hierarchy::{WrappingProfile, WrappingProfiles};
use keyrack_test_support::creation_conformance;
use std::collections::BTreeMap;

// Mutation controls run each surface separately so one panic cannot mask the other.
fn surfaces() -> Vec<&'static str> {
    match std::env::var("KEYRACK_DELETION_TEST_SURFACE").as_deref() {
        Ok("grpc") => vec!["grpc"],
        Ok("rest") => vec!["rest"],
        Err(_) => vec!["grpc", "rest"],
        Ok(other) => panic!("invalid deletion test surface: {other}"),
    }
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
fn state_at(
    path: &std::path::Path,
    pdp: Arc<dyn PolicyDecisionPoint>,
    audit: Arc<CapturingSink>,
) -> Arc<ServiceState> {
    let provider = Arc::new(SoftwareProvider::scoped(
        ProviderRef::new("default"),
        WrappingIdentifier::new("deletion-test").unwrap(),
    ));
    let mut state = build_test_state_with_provider(provider, pdp, audit);
    let state_mut = Arc::get_mut(&mut state).unwrap();
    state_mut.storage = Arc::new(keyrack_sqlite::SqliteStorage::open(path).unwrap());
    state_mut.wrapping = WrappingProfiles::new([(
        ProviderRef::new("default"),
        WrappingProfile {
            mechanism: WrappingIdentifier::new(SOFTWARE_WRAPPING_MECHANISM).unwrap(),
            security_domain: WrappingIdentifier::new("deletion-test").unwrap(),
        },
    )]);
    state
}
fn path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "keyrack-deletion-matrix-{}.sqlite",
        uuid::Uuid::new_v4()
    ))
}

async fn request(
    state: Arc<ServiceState>,
    surface: &str,
    key: &str,
    action: &str,
    allow: bool,
) -> (u16, String) {
    if surface == "grpc" {
        let svc = keyrack_service::grpc::KeyServiceImpl::new(state);
        let result = if action == "schedule" {
            svc.schedule_key_deletion(Request::new(proto::ScheduleKeyDeletionRequest {
                key_id: key.into(),
                grace_period_days: 7,
                allow_dependent_data_loss: allow,
            }))
            .await
            .map(|_| ())
        } else {
            svc.cancel_key_deletion(Request::new(proto::CancelKeyDeletionRequest {
                key_id: key.into(),
            }))
            .await
            .map(|_| ())
        };
        match result {
            Ok(()) => (200, String::new()),
            Err(e) => (
                match e.code() {
                    tonic::Code::PermissionDenied => 403,
                    tonic::Code::FailedPrecondition => 409,
                    _ => 500,
                },
                e.to_string(),
            ),
        }
    } else {
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;
        let route = if action == "schedule" {
            "actions-schedule-deletion"
        } else {
            "actions-cancel-deletion"
        };
        let response=keyrack_service::rest::router(state).oneshot(axum::http::Request::builder().method("POST")
            .uri(format!("/v1/keys/{key}/{route}")).header("content-type","application/json")
            .body(axum::body::Body::from(serde_json::json!({"grace_period_days":7,"allow_dependent_data_loss":allow}).to_string())).unwrap()).await.unwrap();
        let status = response.status().as_u16();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }
}

fn pending_request(parent: &KeyRecord) -> keyrack_core::creation::CreationRequest {
    let (_, mut request) = creation_conformance::fixture();
    let old = request.material().unwrap().clone();
    request.record.parent_lid = Some(parent.lid);
    request.record.key_versions[0].material = KeyMaterial::ParentWrapped(
        ParentWrappedMaterial::new(
            ProviderRef::new("default"),
            WrappingIdentifier::new("deletion-test").unwrap(),
            VersionedKeyId::new(parent.lid, parent.current_key_version).unwrap(),
            old.wrapping_context_version(),
            old.key_format().clone(),
            WrappingIdentifier::new(SOFTWARE_WRAPPING_MECHANISM).unwrap(),
            old.wrapped_material_ref().clone(),
        )
        .unwrap(),
    );
    request.expected_parent_occ = parent.occ_version;
    request.parent_spec = parent.key_spec.clone();
    request.context_bytes = request.context().unwrap().canonical_bytes().unwrap();
    request
}

async fn seed(state: &Arc<ServiceState>, parent: &KeyRecord, kind: &str) -> Option<KeyRecord> {
    match kind {
        "none" => None,
        "logical" => {
            let mut child = creation_conformance::fixture().1.record;
            child.parent_lid = Some(parent.lid);
            let provider = state
                .providers
                .resolve_for_primary(parent)
                .unwrap()
                .provider;
            child.key_versions[0].material = KeyMaterial::ProviderResident {
                key_handle: provider.generate_key(&KeySpec::Aes256).await.unwrap(),
                provider_ref: None,
            };
            state.storage.create_key(&child).await.unwrap();
            Some(child)
        }
        "wrapped" => Some(
            domain::create_key(state, input(Some(parent)))
                .await
                .unwrap(),
        ),
        "journal" => {
            state
                .storage
                .reserve_creation(&pending_request(parent))
                .await
                .unwrap();
            None
        }
        _ => unreachable!(),
    }
}

// The three requested events are crossed with both authorization intents and
// both surfaces. Blocked admission leaves no schedule or persisted approval.
#[tokio::test]
async fn dependency_override_event_surface_matrix() {
    for surface in surfaces() {
        for kind in ["none", "logical", "wrapped", "journal"] {
            for allow in [false, true] {
                for event in ["appears", "cancel", "restart"] {
                    let file = path();
                    let audit = Arc::new(CapturingSink::new());
                    let mut state = state_at(&file, Arc::new(AlwaysAllow), audit.clone());
                    let parent = domain::create_key(&state, input(None)).await.unwrap();
                    let dependent = seed(&state, &parent, kind).await;
                    let key = parent.lid.to_string();
                    let before = state.storage.get_key(&parent.lid).await.unwrap();
                    let (status, body) =
                        request(state.clone(), surface, &key, "schedule", allow).await;
                    let blocked = kind == "journal" || (kind == "wrapped" && !allow);
                    assert_eq!(
                        status,
                        if blocked { 409 } else { 200 },
                        "{surface}/{kind}/{allow}/{event}: {body}"
                    );
                    if blocked {
                        assert!(keyrack_core::creation::same_json(
                            &before,
                            &state.storage.get_key(&parent.lid).await.unwrap()
                        )
                        .unwrap());
                        assert!(state
                            .storage
                            .deletion_intent(&parent.lid)
                            .await
                            .unwrap()
                            .is_none());
                    } else {
                        let intent = state
                            .storage
                            .deletion_intent(&parent.lid)
                            .await
                            .unwrap()
                            .unwrap();
                        assert_eq!(intent.allow_dependent_data_loss, allow);
                        if event == "cancel" {
                            assert_eq!(
                                request(state.clone(), surface, &key, "cancel", false)
                                    .await
                                    .0,
                                200
                            );
                            assert!(state
                                .storage
                                .deletion_intent(&parent.lid)
                                .await
                                .unwrap()
                                .is_none());
                        } else if event == "appears" {
                            // Import an additional edge after approval, including on an already
                            // approved parent. Claim must reject before any provider effect.
                            state
                                .storage
                                .create_key(&pending_request(&parent).record)
                                .await
                                .unwrap();
                        } else {
                            Arc::get_mut(&mut state).unwrap().storage =
                                Arc::new(keyrack_sqlite::SqliteStorage::open(&file).unwrap());
                            assert_eq!(
                                state.storage.deletion_intent(&parent.lid).await.unwrap(),
                                Some(intent)
                            );
                        }
                        keyrack_service::workers::run_deletion_scan_at(
                            &state,
                            chrono::Utc::now() + chrono::Duration::days(8),
                        )
                        .await
                        .unwrap();
                        let actual = state.storage.get_key(&parent.lid).await.unwrap();
                        let expected = match event {
                            "cancel" => KeyState::Disabled,
                            "appears" => KeyState::PendingDeletion,
                            _ => KeyState::Destroyed,
                        };
                        assert_eq!(actual.state, expected, "{surface}/{kind}/{allow}/{event}");
                        if event == "appears" {
                            assert!(audit.events().iter().any(|e| e.action
                                == keyrack_core::audit::AuditAction::KeyDestructionRefused));
                            assert!(!audit.events().iter().any(|e| e.action
                                == keyrack_core::audit::AuditAction::ProviderDestroyKey));
                        }
                        if let Some(child) = dependent {
                            assert!(keyrack_core::creation::same_json(
                                &child,
                                &state.storage.get_key(&child.lid).await.unwrap()
                            )
                            .unwrap());
                            let lost = state
                                .storage
                                .destroyed_wrapping_parents(&child.lid)
                                .await
                                .unwrap();
                            assert_eq!(!lost.is_empty(), kind == "wrapped" && event == "restart");
                        }
                    }
                    drop(state);
                    std::fs::remove_file(file).unwrap();
                }
            }
        }
    }
}

struct OverrideDeny {
    calls: Mutex<Vec<AuthzRequest>>,
}
#[async_trait::async_trait]
impl PolicyDecisionPoint for OverrideDeny {
    async fn evaluate(&self, r: &AuthzRequest) -> keyrack_core::error::Result<AuthzResponse> {
        self.calls.lock().unwrap().push(r.clone());
        let mut answer = AlwaysAllow.evaluate(r).await?;
        if r.action == keyrack_core::audit::AuditAction::ScheduleKeyDeletionWithDependentDataLoss {
            answer.decision = keyrack_core::pdp::Decision::Forbid;
        }
        Ok(answer)
    }
}
#[tokio::test]
async fn override_requires_its_own_permission_on_both_surfaces() {
    for surface in surfaces() {
        let file = path();
        let pdp = Arc::new(OverrideDeny {
            calls: Mutex::new(Vec::new()),
        });
        let audit = Arc::new(CapturingSink::new());
        let state = state_at(&file, pdp.clone(), audit.clone());
        let parent = domain::create_key(&state, input(None)).await.unwrap();
        seed(&state, &parent, "wrapped").await;
        let (status, body) = request(
            state.clone(),
            surface,
            &parent.lid.to_string(),
            "schedule",
            true,
        )
        .await;
        assert_eq!(status, 403, "override permission must refuse: {body}");
        assert_eq!(
            state.storage.get_key(&parent.lid).await.unwrap().state,
            KeyState::Enabled
        );
        assert!(state
            .storage
            .deletion_intent(&parent.lid)
            .await
            .unwrap()
            .is_none());
        let calls = pdp.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_ne!(calls[0].request_id, calls[1].request_id);
        assert_eq!(
            calls[1].action,
            keyrack_core::audit::AuditAction::ScheduleKeyDeletionWithDependentDataLoss
        );
        assert!(audit
            .events()
            .iter()
            .any(|e| e.action == calls[1].action
                && e.result == keyrack_core::audit::AuditResult::Denied));
        drop(calls);
        drop(state);
        std::fs::remove_file(file).unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn refusal_is_audited_and_counted_without_destroying_material() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let file = path();
    let audit = Arc::new(CapturingSink::new());
    let state = state_at(&file, Arc::new(AlwaysAllow), audit.clone());
    let parent = domain::create_key(&state, input(None)).await.unwrap();
    assert_eq!(
        request(
            state.clone(),
            "grpc",
            &parent.lid.to_string(),
            "schedule",
            true
        )
        .await
        .0,
        200
    );
    state
        .storage
        .create_key(&pending_request(&parent).record)
        .await
        .unwrap();
    keyrack_service::workers::run_deletion_scan_at(
        &state,
        chrono::Utc::now() + chrono::Duration::days(8),
    )
    .await
    .unwrap();
    assert!(handle.render().contains(
        "keyrack_deletion_claim_refusals_total{reason=\"dependent_outside_approved_snapshot\"} 1"
    ));
    assert!(audit
        .events()
        .iter()
        .any(|e| e.action == keyrack_core::audit::AuditAction::KeyDestructionRefused));
    assert!(!audit
        .events()
        .iter()
        .any(|e| e.action == keyrack_core::audit::AuditAction::ProviderDestroyKey));
    drop(state);
    std::fs::remove_file(file).unwrap();
}

async fn rest_json(
    state: Arc<ServiceState>,
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    let response = keyrack_service::rest::router(state)
        .oneshot(
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
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

#[tokio::test]
async fn destroyed_parent_is_explicit_and_child_envelopes_can_be_erased_on_both_surfaces() {
    for surface in surfaces() {
        for destroy_parent in [false, true] {
            let file = path();
            let audit = Arc::new(CapturingSink::new());
            let state = state_at(&file, Arc::new(AlwaysAllow), audit.clone());
            let parent = domain::create_key(&state, input(None)).await.unwrap();
            let child = domain::create_key(&state, input(Some(&parent)))
                .await
                .unwrap();
            let key = child.lid.to_string();
            let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
            let blob = svc
                .encrypt(Request::new(proto::EncryptRequest {
                    key_id: key.clone(),
                    plaintext: b"preserved data".to_vec(),
                    ..Default::default()
                }))
                .await
                .unwrap()
                .into_inner()
                .ciphertext_blob;
            let KeyMaterial::ParentWrapped(material) = &child.primary_version().unwrap().material
            else {
                panic!("wrapped fixture")
            };
            let operation = uuid::Uuid::parse_str(
                material
                    .wrapped_material_ref()
                    .as_str()
                    .strip_prefix("creation:")
                    .unwrap(),
            )
            .unwrap();
            let envelope = state
                .storage
                .read_creation_envelope(operation)
                .await
                .unwrap();
            if destroy_parent {
                assert_eq!(
                    request(
                        state.clone(),
                        surface,
                        &parent.lid.to_string(),
                        "schedule",
                        true
                    )
                    .await
                    .0,
                    200
                );
                keyrack_service::workers::run_deletion_scan_at(
                    &state,
                    chrono::Utc::now() + chrono::Duration::days(8),
                )
                .await
                .unwrap();
                assert_eq!(
                    state.storage.get_key(&parent.lid).await.unwrap().state,
                    KeyState::Destroyed
                );
                assert_eq!(
                    state
                        .storage
                        .read_creation_envelope(operation)
                        .await
                        .unwrap(),
                    envelope,
                    "parent deletion must leave dependent envelope alone"
                );
                if surface == "grpc" {
                    let err = svc
                        .decrypt(Request::new(proto::DecryptRequest {
                            key_id: key.clone(),
                            ciphertext_blob: blob,
                            ..Default::default()
                        }))
                        .await
                        .unwrap_err();
                    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
                    assert!(err.message().contains("wrapping parent destroyed"), "{err}");
                    let metadata = svc
                        .describe_key(Request::new(proto::DescribeKeyRequest {
                            key_id: key.clone(),
                        }))
                        .await
                        .unwrap()
                        .into_inner()
                        .metadata
                        .unwrap();
                    assert_eq!(
                        metadata.wrapping_parent_destroyed_versions,
                        vec![1],
                        "destroyed parent version must be reported"
                    );
                } else {
                    let (status,body)=rest_json(state.clone(),"POST",&format!("/v1/keys/{key}/actions-decrypt"),serde_json::json!({"ciphertext_blob":base64::engine::general_purpose::STANDARD.encode(blob)})).await;
                    assert_eq!(status, 409);
                    assert!(
                        body.to_string().contains("wrapping parent destroyed"),
                        "{body}"
                    );
                    let (status, body) = rest_json(
                        state.clone(),
                        "GET",
                        &format!("/v1/keys/{key}/describe"),
                        serde_json::json!({}),
                    )
                    .await;
                    assert_eq!(status, 200);
                    let versions: Vec<u64> = body["wrapping_parent_destroyed_versions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| value.as_u64().unwrap())
                        .collect();
                    assert_eq!(
                        versions,
                        vec![1],
                        "destroyed parent version must be reported"
                    );
                }
            }
            let parent_before = state.storage.get_key(&parent.lid).await.unwrap();
            let destroys_before = audit
                .events()
                .iter()
                .filter(|e| e.action == keyrack_core::audit::AuditAction::ProviderDestroyKey)
                .count();
            let (status, body) = request(state.clone(), surface, &key, "schedule", false).await;
            assert_eq!(status, 200, "wrapped child scheduling: {body}");
            keyrack_service::workers::run_deletion_scan_at(
                &state,
                chrono::Utc::now() + chrono::Duration::days(8),
            )
            .await
            .unwrap();
            assert_eq!(
                state.storage.get_key(&child.lid).await.unwrap().state,
                KeyState::Destroyed,
                "wrapped child must complete destruction"
            );
            assert!(
                state
                    .storage
                    .read_creation_envelope(operation)
                    .await
                    .is_err(),
                "wrapped child envelope must be erased"
            );
            assert!(keyrack_core::creation::same_json(
                &parent_before,
                &state.storage.get_key(&parent.lid).await.unwrap()
            )
            .unwrap());
            assert_eq!(
                audit
                    .events()
                    .iter()
                    .filter(|e| e.action == keyrack_core::audit::AuditAction::ProviderDestroyKey)
                    .count(),
                destroys_before,
                "wrapped child destruction must not destroy a parent handle"
            );
            drop(svc);
            drop(state);
            std::fs::remove_file(file).unwrap();
        }
    }
}

#[tokio::test]
async fn migration_journals_refuse_all_roles_and_overrides_on_both_surfaces() {
    for surface in surfaces() {
        for staged in [false, true] {
            for allow in [false, true] {
                let file = path();
                let state = state_at(&file, Arc::new(AlwaysAllow), Arc::new(CapturingSink::new()));
                let (migration, _) =
                    keyrack_test_support::migration_conformance::seeded(state.storage.as_ref())
                        .await;
                state.storage.reserve_migration(&migration).await.unwrap();
                if staged {
                    state
                        .storage
                        .stage_migration(
                            migration.operation,
                            &keyrack_test_support::migration_conformance::envelopes(),
                        )
                        .await
                        .unwrap();
                }
                for lid in [
                    migration.child.lid,
                    migration.old_parent.lid,
                    migration.new_parent.lid,
                ] {
                    let (status, body) =
                        request(state.clone(), surface, &lid.to_string(), "schedule", allow).await;
                    assert_eq!(
                        status, 409,
                        "{surface}/{staged}/{allow}: migration journal must refuse: {body}"
                    );
                    assert!(body.contains("in_flight_journal"), "{body}");
                    assert_eq!(
                        state.storage.get_key(&lid).await.unwrap().state,
                        KeyState::Enabled
                    );
                    assert!(state.storage.deletion_intent(&lid).await.unwrap().is_none());
                }
                drop(state);
                std::fs::remove_file(file).unwrap();
            }
        }
    }
}

#[tokio::test]
async fn rest_rejects_non_boolean_data_loss_intent() {
    let file = path();
    let state = state_at(&file, Arc::new(AlwaysAllow), Arc::new(CapturingSink::new()));
    let parent = domain::create_key(&state, input(None)).await.unwrap();
    for invalid in [
        serde_json::json!("true"),
        serde_json::json!(1),
        serde_json::json!(null),
    ] {
        let (status, body) = rest_json(
            state.clone(),
            "POST",
            &format!("/v1/keys/{}/actions-schedule-deletion", parent.lid),
            serde_json::json!({"grace_period_days":7,"allow_dependent_data_loss":invalid}),
        )
        .await;
        assert_eq!(status, 400, "non-boolean approval must refuse: {body}");
        assert!(state
            .storage
            .deletion_intent(&parent.lid)
            .await
            .unwrap()
            .is_none());
    }
    drop(state);
    std::fs::remove_file(file).unwrap();
}
