// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity normalization at the actual JSON and REST boundaries.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use keyrack_core::audit::FanoutSink;
use keyrack_core::authn::{AuthenticatorChain, InsecureAuthenticator};
use keyrack_core::key::{ProviderClass, ProviderRef};
use keyrack_core::pdp::{AlwaysAllow, AuthzRequest, AuthzResponse, PolicyDecisionPoint};
use keyrack_core::provider::inmem::InMemoryProvider;
use keyrack_core::provider::software::SoftwareProvider;
use keyrack_core::registry::{ProviderEntry, StaticProviderRegistry};
use keyrack_core::routing::{ProviderRouter, RoutingRule, RuleAction};
use keyrack_core::storage::KeyFilter;
use keyrack_service::identity_input::IdentityRequest;
use keyrack_service::state::ServiceState;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt as _;

#[test]
fn raw_json_duplicate_fields_and_attributes_are_rejected_before_map_collection() {
    for raw in [
        r#"{"attributes":{"tenant":"a","tenant":"b"}}"#,
        r#"{"attributes":{"tenant":"same","tenant":"same"}}"#,
        r#"{"attributes":{"é":"a","e\u0301":"b"}}"#,
        r#"{"attributes":{"é":"same","e\u0301":"same"}}"#,
        r#"{"attributes":{},"attributes":{}}"#,
        r#"{"key_spec":"AES_256","key_spec":"AES_128"}"#,
        r#"{"attributes":{"keyrack.provider":"e\u0301","keyrack.provider":"é"}}"#,
        r#"{"namespace":"one","namespace":"two"}"#,
    ] {
        assert!(
            serde_json::from_str::<IdentityRequest>(raw).is_err(),
            "{raw}"
        );
    }
}

#[test]
fn supplied_attributes_must_be_a_map_of_strings() {
    for value in [
        "null",
        "false",
        "123",
        "[]",
        r#""tenant""#,
        r#"{"x":null}"#,
        r#"{"x":1}"#,
        r#"{"x":true}"#,
        r#"{"x":[]}"#,
        r#"{"x":{}}"#,
    ] {
        let raw = format!(r#"{{"attributes":{value}}}"#);
        assert!(
            serde_json::from_str::<IdentityRequest>(&raw).is_err(),
            "{raw}"
        );
    }
    assert!(serde_json::from_str::<IdentityRequest>("null").is_err());
    assert!(serde_json::from_str::<IdentityRequest>("[]").is_err());
}

#[test]
fn normalized_attributes_preserve_other_request_fields_and_absence() {
    let decomposed: IdentityRequest = serde_json::from_str(
        r#"{"attributes":{"te\u0301nant":"e\u0301"},"description":"e\u0301","options":[null,2,true]}"#,
    ).unwrap();
    assert_eq!(
        decomposed.0,
        json!({"attributes":{"ténant":"é"},"description":"e\u{301}","options":[null,2,true]})
    );
    let composed: IdentityRequest =
        serde_json::from_str(r#"{"attributes":{"ténant":"é"}}"#).unwrap();
    assert_eq!(decomposed.0["attributes"], composed.0["attributes"]);
    let absent: IdentityRequest = serde_json::from_str(r#"{"key_spec":"AES_256"}"#).unwrap();
    assert!(absent.0.get("attributes").is_none());
}

#[derive(Default)]
struct CountingPdp(AtomicUsize);

#[async_trait::async_trait]
impl PolicyDecisionPoint for CountingPdp {
    async fn evaluate(&self, request: &AuthzRequest) -> keyrack_core::error::Result<AuthzResponse> {
        self.0.fetch_add(1, Ordering::Relaxed);
        AlwaysAllow.evaluate(request).await
    }
}

fn state() -> (Arc<ServiceState>, Arc<CountingPdp>) {
    let pdp = Arc::new(CountingPdp::default());
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let state = Arc::new(ServiceState {
        storage: Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap()),
        providers: Arc::new(StaticProviderRegistry::single(
            Arc::new(InMemoryProvider::new()),
            ProviderClass::InMemory,
        )),
        // A missed NFC match selects an unavailable provider and cannot create.
        provider_router: ProviderRouter::new(
            vec![(
                BTreeMap::from([("ténant".into(), "é".into())]),
                ProviderRef::new("default"),
            )],
            ProviderRef::new("unavailable"),
        )
        .unwrap(),
        pdp: pdp.clone(),
        audit: Arc::new(FanoutSink::new(vec![])),
        authn: Arc::new(AuthenticatorChain::new(vec![Box::new(
            InsecureAuthenticator,
        )])),
        metrics_handle: recorder.handle(),
        max_plaintext_bytes: 4096,
        nats_publisher: None,
        legacy_compromised_key_decrypt: false,
    });
    (state, pdp)
}

async fn post(state: Arc<ServiceState>, path: &str, raw: &str) -> axum::response::Response {
    keyrack_service::rest::router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(raw.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn all_identity_rest_handlers_reject_ambiguous_input_before_authorization_or_storage() {
    let (state, pdp) = state();
    for path in ["/v1/keys", "/v1/keys/import", "/v1/routing/explain"] {
        for raw in [
            r#"{"attributes":{"tenant":"same","tenant":"same"}}"#,
            r#"{"attributes":{"é":"same","e\u0301":"same"}}"#,
            r#"{"attributes":null}"#,
            r#"{"attributes":{"tenant":true}}"#,
            r#"{"attributes":{},"attributes":{}}"#,
            r#"{"namespace":null}"#,
            r#"{"namespace":true}"#,
            r#"{"namespace":123}"#,
            r#"{"namespace":[]}"#,
            r#"{"namespace":{}}"#,
        ] {
            let response = post(state.clone(), path, raw).await;
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{path}: {raw}"
            );
        }
    }
    assert_eq!(pdp.0.load(Ordering::Relaxed), 0);
    assert!(state
        .storage
        .list_keys(&KeyFilter::default())
        .await
        .unwrap()
        .items
        .is_empty());
}

#[tokio::test]
async fn create_routes_and_stores_equivalent_unicode_attributes_in_the_same_normal_form() {
    let (state, _) = state();
    for raw in [
        r#"{"attributes":{"ténant":"é"}}"#,
        r#"{"attributes":{"te\u0301nant":"e\u0301"}}"#,
    ] {
        let response = post(state.clone(), "/v1/keys", raw).await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert!(
            status.is_success(),
            "{}: {}",
            status,
            String::from_utf8_lossy(&bytes)
        );
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["provider_ref"], "default");
    }
    let records = state
        .storage
        .list_keys(&KeyFilter::default())
        .await
        .unwrap()
        .items;
    assert_eq!(records.len(), 2);
    for record in records {
        assert!(record
            .identity_tags
            .iter()
            .any(|(key, value)| key == "ténant" && value == "é"));
        assert!(record
            .identity_tags
            .iter()
            .all(|(key, _)| key != "te\u{301}nant"));
        assert_eq!(record.provider_ref, Some(ProviderRef::new("default")));
    }
}

#[test]
fn opaque_provider_selector_is_preserved_while_namespace_and_identity_are_normalized() {
    let request: IdentityRequest = serde_json::from_str(
        r#"{"attributes":{"keyrack.provider":"e\u0301","te\u0301nant":"e\u0301"},"namespace":"e\u0301"}"#,
    ).unwrap();
    assert_eq!(request.0["attributes"]["keyrack.provider"], "e\u{301}");
    assert_eq!(request.0["attributes"]["ténant"], "é");
    assert_eq!(request.0["namespace"], "é");
    let empty: IdentityRequest = serde_json::from_str(r#"{"namespace":""}"#).unwrap();
    assert_eq!(empty.0["namespace"], "");
}

#[tokio::test]
async fn create_import_and_explain_preserve_opaque_decomposed_provider_selection() {
    let (mut state, _) = state();
    let opaque = "e\u{301}";
    let config = Arc::get_mut(&mut state).unwrap();
    config.providers = Arc::new(
        StaticProviderRegistry::new(
            [(
                ProviderRef::new(opaque),
                ProviderEntry {
                    provider: Arc::new(SoftwareProvider::new()),
                    class: ProviderClass::Software,
                },
            )],
            ProviderRef::new(opaque),
        )
        .unwrap(),
    );
    config.provider_router = ProviderRouter::with_rules(
        vec![RoutingRule {
            match_tags: BTreeMap::new(),
            action: RuleAction::DelegateAny,
        }],
        ProviderRef::new(opaque),
    )
    .unwrap();
    let raw = json!({
        "attributes": {"keyrack.provider": opaque, "te\u{301}nant": "e\u{301}"},
        "namespace": "e\u{301}",
        "key_material": base64::engine::general_purpose::STANDARD.encode([7_u8; 32]),
    })
    .to_string();
    for path in ["/v1/keys", "/v1/keys/import", "/v1/routing/explain"] {
        let response = post(state.clone(), path, &raw).await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert!(
            status.is_success(),
            "{path}: {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        if path == "/v1/routing/explain" {
            assert_eq!(body["selected_backend_id"], opaque);
            assert_eq!(body["outcome"], "DELEGATED");
        } else {
            assert_eq!(body["provider_ref"], opaque);
        }
    }
    let records = state
        .storage
        .list_keys(&KeyFilter::default())
        .await
        .unwrap()
        .items;
    assert_eq!(records.len(), 2);
    for record in records {
        assert_eq!(record.provider_ref, Some(ProviderRef::new(opaque)));
        assert_eq!(record.identity_tags.get("namespace"), Some("é"));
        assert_eq!(record.identity_tags.get("ténant"), Some("é"));
        assert!(!record.identity_tags.contains_key("keyrack.provider"));
    }
}
