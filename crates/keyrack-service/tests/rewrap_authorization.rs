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
    if rest {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/v1/keys/{}/rewrap", child.lid))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"operation_id": operation, "new_parent_key_id": target})
                    .to_string(),
            ))
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
    } else {
        let response = keyrack_service::grpc::KeyServiceImpl::new(state.clone())
            .rewrap_key(tonic::Request::new(proto::RewrapKeyRequest {
                key_id: child.lid.to_string(),
                new_parent_key_id: target,
                operation_id: operation.into(),
            }))
            .await;
        match response {
            Ok(response) => {
                let result = response.into_inner();
                (
                    200,
                    serde_json::json!({"operation_id":result.operation_id, "parent":result.metadata.unwrap().parent_key_id}),
                )
            }
            Err(error) => (
                match error.code() {
                    tonic::Code::PermissionDenied => 403,
                    tonic::Code::InvalidArgument => 400,
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
