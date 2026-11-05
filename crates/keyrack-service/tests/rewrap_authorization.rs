// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real transport handlers share three independent migration grants and audit.
use async_trait::async_trait;
use axum::body::Body;
use keyrack_core::audit::{AuditAction, AuditEvent, AuditResult, AuditSink};
use keyrack_core::key::{Exportability, KeyRecord, KeySpec, ProviderClass, ProviderRef};
use keyrack_core::pdp::{
    AlwaysAllow, AttributeValue, AuthzRequest, AuthzResponse, Decision, PolicyDecisionPoint,
};
use keyrack_core::provider::software::{SoftwareProvider, SOFTWARE_WRAPPING_MECHANISM};
use keyrack_core::registry::{ProviderEntry, StaticProviderRegistry};
use keyrack_core::wrapping::WrappingIdentifier;
use keyrack_service::domain::{self, CreateKeyInput};
use keyrack_service::hierarchy::{WrappingProfile, WrappingProfiles};
use keyrack_service::proto::{self, key_service_server::KeyService};
use keyrack_service::routing::ProviderRouter;
use keyrack_service::state::ServiceState;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

#[derive(Default)]
struct Audit(Mutex<Vec<AuditEvent>>);
#[async_trait]
impl AuditSink for Audit {
    async fn emit(&self, event: &AuditEvent) -> keyrack_core::error::Result<()> {
        self.0.lock().unwrap().push(event.clone());
        Ok(())
    }
}
struct Pdp {
    deny: Option<&'static str>,
    replay: bool,
    requests: Mutex<Vec<AuthzRequest>>,
}
#[async_trait]
impl PolicyDecisionPoint for Pdp {
    async fn evaluate(&self, request: &AuthzRequest) -> keyrack_core::error::Result<AuthzResponse> {
        let mut response = AlwaysAllow.evaluate(request).await?;
        if request.action == AuditAction::RewrapKey {
            let mut requests = self.requests.lock().unwrap();
            let role = match request.context.entries.get("migration_role") {
                Some(AttributeValue::String(role)) => role.as_str(),
                _ => panic!("missing role"),
            };
            if Some(role) == self.deny
                || request.resource.attributes.get("owner_principal_id")
                    == Some(&AttributeValue::String("revoked-owner".into()))
            {
                response.decision = Decision::Forbid;
            }
            if self.replay && role == "new_parent" {
                response
                    .request_id
                    .clone_from(&requests.first().unwrap().request_id);
            }
            requests.push(request.clone());
        }
        Ok(response)
    }
}
fn identifier(value: &str) -> WrappingIdentifier {
    WrappingIdentifier::new(value).unwrap()
}
fn state(deny: Option<&'static str>, replay: bool) -> (Arc<ServiceState>, Arc<Pdp>, Arc<Audit>) {
    let pdp = Arc::new(Pdp {
        deny,
        replay,
        requests: Mutex::new(Vec::new()),
    });
    let audit = Arc::new(Audit::default());
    let name = ProviderRef::new("default");
    let provider = Arc::new(SoftwareProvider::scoped(
        name.clone(),
        identifier("migration-api"),
    ));
    let registry = StaticProviderRegistry::new(
        [(
            name.clone(),
            ProviderEntry {
                provider,
                class: ProviderClass::Software,
            },
        )],
        name.clone(),
    )
    .unwrap();
    let metrics = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    (
        Arc::new(ServiceState {
            storage: Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap()),
            providers: Arc::new(registry),
            provider_router: ProviderRouter::new(vec![], name.clone()).unwrap(),
            pdp: pdp.clone(),
            audit: audit.clone(),
            authn: Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
                Box::new(keyrack_core::authn::InsecureAuthenticator),
            ])),
            metrics_handle: metrics.handle(),
            max_plaintext_bytes: 4096,
            legacy_compromised_key_decrypt: false,
            nats_publisher: None,
            lease_cleanup: keyrack_service::lease::LeaseCleanup::default(),
            wrapping: WrappingProfiles::new([(
                name,
                WrappingProfile {
                    mechanism: identifier(SOFTWARE_WRAPPING_MECHANISM),
                    security_domain: identifier("migration-api"),
                },
            )]),
        }),
        pdp,
        audit,
    )
}
async fn create(state: &Arc<ServiceState>, parent: Option<&KeyRecord>) -> KeyRecord {
    domain::create_key(
        state,
        CreateKeyInput {
            key_spec: KeySpec::Aes256,
            attributes: BTreeMap::new(),
            namespace: String::new(),
            description: None,
            exportable: Exportability::NonExportable,
            parent_key_id: parent.map(|record| record.lid.to_string()),
            hsm_connection_id: None,
            backend_id: None,
        },
    )
    .await
    .unwrap()
}
async fn request(
    state: &Arc<ServiceState>,
    child: &KeyRecord,
    parent: Option<&KeyRecord>,
    operation: &str,
    rest: bool,
) -> (u16, serde_json::Value) {
    let target = parent
        .map(|record| record.lid.to_string())
        .unwrap_or_default();
    request_body(
        state,
        &child.lid.to_string(),
        serde_json::json!({"operation_id": operation, "new_parent_key_id": target}),
        rest,
    )
    .await
}

async fn request_body(
    state: &Arc<ServiceState>,
    child_id: &str,
    body: serde_json::Value,
    rest: bool,
) -> (u16, serde_json::Value) {
    if rest {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/v1/keys/{child_id}/rewrap"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = keyrack_service::rest::router(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        let code = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        (
            code,
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| serde_json::json!({"error":String::from_utf8_lossy(&bytes)})),
        )
    } else {
        let string = |name: &str| body[name].as_str().unwrap_or_default().to_owned();
        let response = keyrack_service::grpc::KeyServiceImpl::new(state.clone())
            .rewrap_key(tonic::Request::new(proto::RewrapKeyRequest {
                key_id: child_id.into(),
                new_parent_key_id: string("new_parent_key_id"),
                operation_id: string("operation_id"),
                old_parent_key_id: string("old_parent_key_id"),
                expected_child_revision: body["expected_child_revision"].as_u64(),
                expected_old_parent_revision: body["expected_old_parent_revision"].as_u64(),
                expected_new_parent_revision: body["expected_new_parent_revision"].as_u64(),
                covered_versions: body["covered_versions"]
                    .as_array()
                    .map(|values| values.iter().map(|v| v.as_u64().unwrap()).collect())
                    .unwrap_or_default(),
            }))
            .await;
        match response {
            Ok(response) => {
                let response = response.into_inner();
                let result = response
                    .result
                    .expect("successful response carries terminal receipt");
                (
                    200,
                    serde_json::json!({
                        "operation_id":response.operation_id,
                        "parent":response.metadata.unwrap().parent_key_id,
                        "result": {
                            "operation_id":result.operation_id,
                            "child":result.child,
                            "old_parent":result.old_parent,
                            "old_parent_versions":result.old_parent_versions,
                            "new_parent":result.new_parent,
                            "new_parent_version":result.new_parent_version,
                            "digest_algorithm":result.digest_algorithm,
                            "versions":result.versions.into_iter().map(|v| serde_json::json!({
                                "version":v.version, "old_parent_version":v.old_parent_version,
                                "new_parent_version":v.new_parent_version,
                                "old_envelope_digest":v.old_envelope_digest,
                                "new_envelope_digest":v.new_envelope_digest,
                                "old_reference":v.old_reference,"new_reference":v.new_reference,
                            })).collect::<Vec<_>>()
                        }
                    }),
                )
            }
            Err(error) => (
                match error.code() {
                    tonic::Code::PermissionDenied => 403,
                    tonic::Code::InvalidArgument => 400,
                    tonic::Code::FailedPrecondition
                    | tonic::Code::Aborted
                    | tonic::Code::AlreadyExists => 409,
                    tonic::Code::Unavailable => 503,
                    _ => 500,
                },
                serde_json::json!({"error":error.message()}),
            ),
        }
    }
}

#[tokio::test]
async fn both_surfaces_deny_missing_permission_on_either_parent_before_reservation() {
    for rest in [false, true] {
        for role in ["old_parent", "new_parent"] {
            let (state, pdp, audit) = state(Some(role), false);
            let old = create(&state, None).await;
            let new = create(&state, None).await;
            let child = create(&state, Some(&old)).await;
            let operation = uuid::Uuid::new_v4();
            let (code, body) =
                request(&state, &child, Some(&new), &operation.to_string(), rest).await;
            assert_eq!(code, 403, "{role} rest={rest}: {body}");
            assert_eq!(
                state.storage.get_key(&child.lid).await.unwrap().parent_lid,
                Some(old.lid)
            );
            assert!(state
                .storage
                .get_migration(operation)
                .await
                .unwrap()
                .is_none());
            let requests = pdp.requests.lock().unwrap();
            assert!(requests.iter().all(|r| r.action == AuditAction::RewrapKey));
            let events = audit.0.lock().unwrap();
            let outcomes: Vec<_> = events
                .iter()
                .filter(|e| e.action == AuditAction::RewrapKey)
                .map(|e| e.result)
                .collect();
            assert_eq!(outcomes, [AuditResult::Attempt, AuditResult::Denied]);
        }
    }
}
#[tokio::test]
async fn both_surfaces_use_three_distinct_grants_and_idempotent_operation_ids() {
    for rest in [false, true] {
        let (state, pdp, audit) = state(None, false);
        let old = create(&state, None).await;
        let new = create(&state, None).await;
        let child = create(&state, Some(&old)).await;
        let operation = uuid::Uuid::new_v4().to_string();
        for _ in 0..2 {
            let (code, body) = request(&state, &child, Some(&new), &operation, rest).await;
            assert_eq!(code, 200, "rest={rest}: {body}");
            assert_eq!(body["operation_id"], operation);
        }
        let requests = pdp.requests.lock().unwrap();
        assert_eq!(requests.len(), 6);
        assert_eq!(
            requests
                .iter()
                .map(|r| &r.request_id)
                .collect::<BTreeSet<_>>()
                .len(),
            6
        );
        for group in requests.chunks(3) {
            assert_eq!(
                group
                    .iter()
                    .map(|r| r.resource.id.clone())
                    .collect::<Vec<_>>(),
                [
                    child.lid.to_string(),
                    old.lid.to_string(),
                    new.lid.to_string()
                ]
            );
        }
        let events = audit.0.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|e| e.action == AuditAction::RewrapKey)
                .map(|e| e.result)
                .collect::<Vec<_>>(),
            [
                AuditResult::Attempt,
                AuditResult::Success,
                AuditResult::Attempt,
                AuditResult::Success
            ]
        );
    }
}
#[tokio::test]
async fn same_parent_still_has_two_parent_grants_and_replayed_permit_is_refused() {
    for replay in [false, true] {
        let (state, pdp, _) = state(None, replay);
        let parent = create(&state, None).await;
        let child = create(&state, Some(&parent)).await;
        let operation = uuid::Uuid::new_v4();
        let (code, _) = request(&state, &child, None, &operation.to_string(), false).await;
        assert_eq!(code, if replay { 500 } else { 200 });
        {
            let requests = pdp.requests.lock().unwrap();
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[1].resource.id, requests[2].resource.id);
            assert_ne!(requests[1].request_id, requests[2].request_id);
        }
        if replay {
            assert!(state
                .storage
                .get_migration(operation)
                .await
                .unwrap()
                .is_none());
        }
    }
}
#[tokio::test]
async fn invalid_operation_id_is_audited_on_both_surfaces() {
    for rest in [false, true] {
        let (state, pdp, audit) = state(None, false);
        let parent = create(&state, None).await;
        let child = create(&state, Some(&parent)).await;
        assert_eq!(
            request(&state, &child, None, "not-a-uuid", rest).await.0,
            400
        );
        assert!(pdp.requests.lock().unwrap().is_empty());
        assert_eq!(
            audit
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| e.action == AuditAction::RewrapKey)
                .map(|e| e.result)
                .collect::<Vec<_>>(),
            [AuditResult::Attempt, AuditResult::Error]
        );
    }
}

struct PausedPdp {
    inner: Arc<Pdp>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait]
impl PolicyDecisionPoint for PausedPdp {
    async fn evaluate(&self, request: &AuthzRequest) -> keyrack_core::error::Result<AuthzResponse> {
        if request.action == AuditAction::RewrapKey
            && request.context.entries.get("migration_role")
                == Some(&AttributeValue::String("child".into()))
        {
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.inner.evaluate(request).await
    }
}

struct PanickingPdp;
#[async_trait]
impl PolicyDecisionPoint for PanickingPdp {
    async fn evaluate(&self, request: &AuthzRequest) -> keyrack_core::error::Result<AuthzResponse> {
        assert!(
            request.action != AuditAction::RewrapKey,
            "policy evaluation panicked"
        );
        AlwaysAllow.evaluate(request).await
    }
}

#[tokio::test]
async fn a_panicking_rewrap_is_audited_as_an_error() {
    for surface in ["grpc", "rest", "execute_rewrap"] {
        let (mut state, _, audit) = state(None, false);
        let old = create(&state, None).await;
        let new = create(&state, None).await;
        let child = create(&state, Some(&old)).await;
        Arc::get_mut(&mut state).unwrap().pdp = Arc::new(PanickingPdp);
        let operation = uuid::Uuid::new_v4();
        if surface == "execute_rewrap" {
            let error = keyrack_service::ops::execute_rewrap(
                &state,
                keyrack_service::ops::default_principal(),
                "panicking-rewrap".into(),
                child.lid.to_string(),
                new.lid.to_string(),
                operation.to_string(),
            )
            .await
            .expect_err("a panicking rewrap fails");
            assert!(matches!(error, domain::DomainError::Internal(_)), "{error}");
        } else {
            let (code, body) = request(
                &state,
                &child,
                Some(&new),
                &operation.to_string(),
                surface == "rest",
            )
            .await;
            assert_eq!(code, 500, "{surface}: {body}");
        }
        assert_eq!(
            audit
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| e.action == AuditAction::RewrapKey)
                .map(|e| e.result)
                .collect::<Vec<_>>(),
            [AuditResult::Attempt, AuditResult::Error],
            "{surface}"
        );
        assert!(state
            .storage
            .get_migration(operation)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            state.storage.get_key(&child.lid).await.unwrap().parent_lid,
            Some(old.lid)
        );
    }
}

#[tokio::test]
async fn a_cancelled_request_retains_its_migration_outcome() {
    let (mut state, pdp, audit) = state(None, false);
    let gate = Arc::new(PausedPdp {
        inner: pdp,
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    Arc::get_mut(&mut state).unwrap().pdp = gate.clone();
    let old = create(&state, None).await;
    let new = create(&state, None).await;
    let child = create(&state, Some(&old)).await;
    let operation = uuid::Uuid::new_v4().to_string();
    let task_state = state.clone();
    let task_child = child.clone();
    let task = tokio::spawn(async move {
        request(&task_state, &task_child, Some(&new), &operation, false).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), gate.entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    gate.release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if audit.0.lock().unwrap().iter().any(|event| {
                event.action == AuditAction::RewrapKey && event.result == AuditResult::Success
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the detached operation records its outcome");
    assert_ne!(
        state.storage.get_key(&child.lid).await.unwrap().parent_lid,
        Some(old.lid)
    );
}

#[tokio::test]
async fn committed_replay_authorizes_fresh_parent_metadata_beyond_cache_ttl() {
    let (mut state, _, _) = state(None, false);
    let underlying = state.storage.clone();
    Arc::get_mut(&mut state).unwrap().storage =
        Arc::new(keyrack_service::cache::CachingStorage::new(
            underlying.clone(),
            64,
            std::time::Duration::from_secs(3600),
        ));
    let old = create(&state, None).await;
    let new = create(&state, None).await;
    let child = create(&state, Some(&old)).await;
    let operation = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        request(&state, &child, Some(&new), &operation, false)
            .await
            .0,
        200
    );
    let cached = state.storage.get_key(&old.lid).await.unwrap();
    let mut revoked = underlying.get_key(&old.lid).await.unwrap();
    revoked.owner_principal_id = Some("revoked-owner".into());
    revoked.occ_version += 1;
    underlying.update_key(&revoked).await.unwrap();
    // Simulate a different replica changing policy-relevant metadata. Ordinary
    // metadata reads remain stale; authorization must explicitly bypass them.
    assert_eq!(
        state
            .storage
            .get_key(&old.lid)
            .await
            .unwrap()
            .owner_principal_id,
        cached.owner_principal_id
    );
    assert_eq!(
        request(&state, &child, Some(&new), &operation, false)
            .await
            .0,
        403
    );
}

fn intent_body(
    child: &KeyRecord,
    old: &KeyRecord,
    new: &KeyRecord,
    operation: uuid::Uuid,
) -> serde_json::Value {
    serde_json::json!({
        "operation_id":operation.to_string(),
        "old_parent_key_id":old.lid.to_string(),
        "new_parent_key_id":new.lid.to_string(),
        "expected_child_revision":child.occ_version,
        "expected_old_parent_revision":old.occ_version,
        "expected_new_parent_revision":new.occ_version,
        "covered_versions":[1],
    })
}

#[tokio::test]
async fn every_caller_intent_field_is_bound_on_both_surfaces() {
    for rest in [false, true] {
        let (state, _, _) = state(None, false);
        let old = create(&state, None).await;
        let new = create(&state, None).await;
        let other = create(&state, None).await;
        let child = create(&state, Some(&old)).await;
        let other_child = create(&state, Some(&old)).await;
        let operation = uuid::Uuid::new_v4();
        let original = intent_body(&child, &old, &new, operation);
        let first = request_body(&state, &child.lid.to_string(), original.clone(), rest).await;
        assert_eq!(first.0, 200, "rest={rest}: {}", first.1);
        // A caller that lost the first reply receives exactly the same receipt.
        let retry = request_body(&state, &child.lid.to_string(), original.clone(), rest).await;
        assert_eq!(retry.0, 200);
        assert_eq!(retry.1["result"], first.1["result"]);
        assert_eq!(
            request_body(&state, &other_child.lid.to_string(), original.clone(), rest)
                .await
                .0,
            409,
            "child must bind intent"
        );
        for (field, value) in [
            (
                "old_parent_key_id",
                serde_json::json!(other.lid.to_string()),
            ),
            (
                "new_parent_key_id",
                serde_json::json!(other.lid.to_string()),
            ),
            (
                "expected_child_revision",
                serde_json::json!(child.occ_version + 1),
            ),
            (
                "expected_old_parent_revision",
                serde_json::json!(old.occ_version + 1),
            ),
            (
                "expected_new_parent_revision",
                serde_json::json!(new.occ_version + 1),
            ),
            ("covered_versions", serde_json::json!([1, 2])),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            let result = request_body(&state, &child.lid.to_string(), changed, rest).await;
            assert_eq!(result.0, 409, "{field} rest={rest}: {}", result.1);
        }
        for field in [
            "old_parent_key_id",
            "new_parent_key_id",
            "expected_child_revision",
            "expected_old_parent_revision",
            "expected_new_parent_revision",
            "covered_versions",
        ] {
            let mut changed = original.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert_eq!(
                request_body(&state, &child.lid.to_string(), changed, rest)
                    .await
                    .0,
                409,
                "presence of {field} binds intent"
            );
        }
        assert_eq!(
            request_body(&state, &child.lid.to_string(), original, rest)
                .await
                .1["result"],
            first.1["result"]
        );
    }
}

#[tokio::test]
async fn initial_occ_and_covered_version_assertions_refuse_without_reservation() {
    for rest in [false, true] {
        let (state, _, _) = state(None, false);
        let old = create(&state, None).await;
        let new = create(&state, None).await;
        let child = create(&state, Some(&old)).await;
        for (field, value) in [
            ("old_parent_key_id", serde_json::json!(new.lid.to_string())),
            (
                "expected_child_revision",
                serde_json::json!(child.occ_version + 1),
            ),
            (
                "expected_old_parent_revision",
                serde_json::json!(old.occ_version + 1),
            ),
            (
                "expected_new_parent_revision",
                serde_json::json!(new.occ_version + 1),
            ),
            ("covered_versions", serde_json::json!([2])),
            ("covered_versions", serde_json::json!([1, 1])),
        ] {
            let operation = uuid::Uuid::new_v4();
            let mut body = intent_body(&child, &old, &new, operation);
            let expected_status = if value == serde_json::json!([1, 1]) {
                400
            } else {
                409
            };
            body[field] = value;
            let result = request_body(&state, &child.lid.to_string(), body, rest).await;
            assert_eq!(
                result.0, expected_status,
                "{field} rest={rest}: {}",
                result.1
            );
            assert!(state
                .storage
                .get_migration(operation)
                .await
                .unwrap()
                .is_none());
        }
    }
}

#[tokio::test]
async fn terminal_receipt_binds_envelopes_and_survives_lost_reply_and_later_changes() {
    for rest in [false, true] {
        let (state, _, _) = state(None, false);
        let old = create(&state, None).await;
        let new = create(&state, None).await;
        let child = create(&state, Some(&old)).await;
        let keyrack_core::key::KeyMaterial::ParentWrapped(material) =
            &child.key_versions[0].material
        else {
            panic!("wrapped fixture")
        };
        let old_reference = material.wrapped_material_ref().as_str().to_owned();
        let creation: uuid::Uuid = old_reference
            .strip_prefix("creation:")
            .unwrap()
            .parse()
            .unwrap();
        let original_bytes = state
            .storage
            .read_creation_envelope(creation)
            .await
            .unwrap();
        let operation = uuid::Uuid::new_v4();
        let body = intent_body(&child, &old, &new, operation);
        let (code, response) =
            request_body(&state, &child.lid.to_string(), body.clone(), rest).await;
        assert_eq!(code, 200, "{response}");
        let result = response["result"].clone();
        assert_eq!(result["operation_id"], operation.to_string());
        assert_eq!(result["child"], child.lid.to_string());
        assert_eq!(result["old_parent"], old.lid.to_string());
        assert_eq!(result["old_parent_versions"], serde_json::json!([1]));
        assert_eq!(result["new_parent"], new.lid.to_string());
        assert_eq!(result["new_parent_version"], 1);
        assert_eq!(result["digest_algorithm"], "blake3");
        assert_eq!(result["versions"].as_array().unwrap().len(), 1);
        let entry = &result["versions"][0];
        assert_eq!(entry["version"], 1);
        assert_eq!(entry["old_parent_version"], 1);
        assert_eq!(entry["new_parent_version"], 1);
        assert_eq!(entry["old_reference"], old_reference);
        assert_eq!(entry["new_reference"], format!("migration:{operation}:1"));
        assert_eq!(
            entry["old_envelope_digest"],
            blake3::hash(&original_bytes).to_hex().as_str()
        );
        let new_bytes = state
            .storage
            .read_migration_envelope(operation, 1)
            .await
            .unwrap();
        assert_eq!(
            entry["new_envelope_digest"],
            blake3::hash(&new_bytes).to_hex().as_str()
        );
        assert!(state
            .storage
            .read_creation_envelope(creation)
            .await
            .is_err());
        // Drop the first response, change ordinary metadata, then recover by ID.
        drop(response);
        let mut updated = state.storage.get_key(&child.lid).await.unwrap();
        updated.description = "changed after commit".into();
        updated.occ_version += 1;
        state.storage.update_key(&updated).await.unwrap();
        let replay = request_body(&state, &child.lid.to_string(), body, rest).await;
        assert_eq!(replay.0, 200, "{}", replay.1);
        assert_eq!(replay.1["result"], result);
    }
}

#[tokio::test]
async fn lifecycle_updates_are_fenced_on_both_surfaces_before_state_validation() {
    for rest in [false, true] {
        let (state, _, _) = state(None, false);
        let old_parent = create(&state, None).await;
        let new_parent = create(&state, None).await;
        let child = create(&state, Some(&old_parent)).await;
        let operation = uuid::Uuid::new_v4();
        let migration = keyrack_service::migration::prepare_migration(
            &state,
            child.lid,
            Some(new_parent.lid),
            operation,
        )
        .await
        .unwrap();
        state.storage.reserve_migration(&migration).await.unwrap();
        for record in [&child, &old_parent, &new_parent] {
            let domain_error = domain::schedule_key_deletion(&state, &record.lid.to_string(), 7)
                .await
                .unwrap_err();
            assert!(matches!(
                domain_error,
                domain::DomainError::FailedPrecondition(_)
            ));
            assert!(domain_error
                .to_string()
                .contains("migration_journal_rows=1"));
            for action in ["enable", "disable", "schedule-deletion", "cancel-deletion"] {
                if rest {
                    let request = axum::http::Request::builder()
                        .method("POST")
                        .uri(format!("/v1/keys/{}/actions-{action}", record.lid))
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap();
                    let response = keyrack_service::rest::router(state.clone())
                        .oneshot(request)
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        if action == "schedule-deletion" {
                            409
                        } else {
                            503
                        },
                        "{action} on {}",
                        record.lid
                    );
                    if action == "schedule-deletion" {
                        let body = axum::body::to_bytes(response.into_body(), 65536)
                            .await
                            .unwrap();
                        let body = String::from_utf8(body.to_vec()).unwrap();
                        assert!(
                            body.contains("in_flight_journal")
                                && body.contains("migration_journal_rows=1"),
                            "schedule refusal must identify the migration dependency: {body}"
                        );
                    }
                } else {
                    let service = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
                    let key_id = record.lid.to_string();
                    let response = match action {
                        "enable" => service
                            .enable_key(tonic::Request::new(proto::EnableKeyRequest { key_id }))
                            .await
                            .map(|_| ()),
                        "disable" => service
                            .disable_key(tonic::Request::new(proto::DisableKeyRequest { key_id }))
                            .await
                            .map(|_| ()),
                        "schedule-deletion" => service
                            .schedule_key_deletion(tonic::Request::new(
                                proto::ScheduleKeyDeletionRequest {
                                    key_id,
                                    grace_period_days: 7,
                                    allow_dependent_data_loss: false,
                                },
                            ))
                            .await
                            .map(|_| ()),
                        "cancel-deletion" => service
                            .cancel_key_deletion(tonic::Request::new(
                                proto::CancelKeyDeletionRequest { key_id },
                            ))
                            .await
                            .map(|_| ()),
                        _ => unreachable!(),
                    };
                    let error = response.unwrap_err();
                    let expected = if action == "schedule-deletion" {
                        assert!(error.message().contains("migration_journal_rows=1"));
                        assert!(error.message().contains("in_flight_journal"));
                        tonic::Code::FailedPrecondition
                    } else {
                        tonic::Code::Unavailable
                    };
                    assert_eq!(error.code(), expected, "{action} on {}", record.lid);
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn competing_replica_intents_return_conflict_from_reservation_on_both_surfaces() {
    use keyrack_core::error::KeyRackError;
    use keyrack_core::migration::MigrationConditions;
    use keyrack_core::storage::StorageBackend;
    use keyrack_service::domain::DomainError;

    let path =
        std::env::temp_dir().join(format!("migration-intent-{}.sqlite", uuid::Uuid::new_v4()));
    let first = Arc::new(keyrack_sqlite::SqliteStorage::open(&path).unwrap());
    let second = Arc::new(keyrack_sqlite::SqliteStorage::open(&path).unwrap());
    let (request, _) = keyrack_test_support::migration_conformance::seeded(first.as_ref()).await;
    let operation = request.operation;
    // Both replicas prepared valid requests before either reserved the ID. The
    // only difference is presence of a caller OCC assertion, which binds intent.
    let competing = request
        .clone()
        .with_conditions(MigrationConditions {
            expected_child_occ: Some(request.child.occ_version),
            ..MigrationConditions::default()
        })
        .unwrap();
    assert!(first.get_migration(operation).await.unwrap().is_none());
    assert!(second.get_migration(operation).await.unwrap().is_none());
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let reserve = |store: Arc<keyrack_sqlite::SqliteStorage>, intent| {
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            store.reserve_migration(&intent).await
        })
    };
    let (one, two) = tokio::join!(
        reserve(first.clone(), request),
        reserve(second.clone(), competing)
    );
    let (winner, error) = match (one.unwrap(), two.unwrap()) {
        (Ok(winner), Err(error)) | (Err(error), Ok(winner)) => (winner, error),
        outcomes => panic!("exactly one reservation must win: {outcomes:?}"),
    };
    assert!(
        matches!(error, KeyRackError::MigrationIntentConflict { operation: id } if id == operation)
    );
    let domain = DomainError::from(error);
    assert_eq!(
        domain.to_grpc_status().code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(domain.to_rest_error().0, axum::http::StatusCode::CONFLICT);
    // Direct core-error adapters must agree with the shared operation executor.
    assert_eq!(
        keyrack_service::convert::error_to_status(KeyRackError::MigrationIntentConflict {
            operation
        })
        .code(),
        tonic::Code::FailedPrecondition,
    );
    let core = DomainError::Core(KeyRackError::MigrationIntentConflict { operation });
    assert_eq!(
        core.to_grpc_status().code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(core.to_rest_error().0, axum::http::StatusCode::CONFLICT);
    let saved = first.get_migration(operation).await.unwrap().unwrap();
    assert!(saved.request.same_intent(&winner.request).unwrap());
    assert!(saved.result.is_none());
    assert_eq!(saved.epoch, 0, "a losing intent must not take ownership");
    drop(first);
    drop(second);
    std::fs::remove_file(path).unwrap();
}
