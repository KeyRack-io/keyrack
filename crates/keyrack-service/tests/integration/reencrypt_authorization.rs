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

//! The two-resource `ReEncrypt` delegation is independent of standalone
//! Encrypt/Decrypt grants and must be enforced before either provider runs.

use super::*;
use keyrack_core::audit::{AuditAction, AuditResult, EventType};
use keyrack_core::pdp::{AttributeValue, Decision, Obligation, Principal};
use keyrack_service::ops::{self, OpContext};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};

const OUTER_REQUEST_ID: &str = "reencrypt-caller-correlation-id";
const PLAINTEXT: &[u8] = b"independent two-key authorization";

#[derive(Clone, Copy, Debug)]
enum PdpMode {
    PermitBoth,
    FromOnly,
    ToOnly,
    SourceForbid,
    DestinationForbid,
    DestinationIndeterminate,
    DestinationError,
    DestinationWrongId,
    DestinationReplaySource,
    DestinationObligation,
    DestinationWrongVersion,
}

fn is_reencrypt(action: &AuditAction) -> bool {
    matches!(
        action,
        AuditAction::ReEncryptFrom | AuditAction::ReEncryptTo
    )
}

/// Deliberately returns raw responses: the service executor, not an HTTP PDP
/// adapter, must validate correlation and unsupported obligations here.
struct ReEncryptPdp {
    mode: PdpMode,
    requests: Mutex<Vec<AuthzRequest>>,
}

impl ReEncryptPdp {
    fn new(mode: PdpMode) -> Self {
        Self {
            mode,
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<AuthzRequest> {
        self.requests.lock().unwrap().clone()
    }

    fn clear(&self) {
        self.requests.lock().unwrap().clear();
    }
}

#[async_trait::async_trait]
impl PolicyDecisionPoint for ReEncryptPdp {
    async fn evaluate(&self, request: &AuthzRequest) -> keyrack_core::error::Result<AuthzResponse> {
        let (leg, first_id) = {
            let mut requests = self.requests.lock().unwrap();
            let prior_legs = requests.iter().filter(|r| is_reencrypt(&r.action)).count();
            let first_id = requests
                .iter()
                .find(|r| is_reencrypt(&r.action))
                .map(|r| r.request_id.clone());
            requests.push(request.clone());
            (prior_legs % 2, first_id)
        };
        let mut response = AlwaysAllow.evaluate(request).await?;
        if !is_reencrypt(&request.action) {
            return Ok(response);
        }
        // Match actual actions, not leg order or context: a one-direction grant
        // must never acquire its converse, even when both resources are identical.
        if (matches!(self.mode, PdpMode::FromOnly) && request.action != AuditAction::ReEncryptFrom)
            || (matches!(self.mode, PdpMode::ToOnly) && request.action != AuditAction::ReEncryptTo)
        {
            response.decision = Decision::Forbid;
            return Ok(response);
        }
        match (self.mode, leg) {
            (PdpMode::SourceForbid, 0) | (PdpMode::DestinationForbid, 1) => {
                response.decision = Decision::Forbid;
            }
            (PdpMode::DestinationIndeterminate, 1) => response.decision = Decision::Indeterminate,
            (PdpMode::DestinationError, 1) => {
                return Err(keyrack_core::error::KeyRackError::Other(
                    "synthetic PDP transport failure".into(),
                ));
            }
            (PdpMode::DestinationWrongId, 1) => response.request_id = "unrelated-response".into(),
            (PdpMode::DestinationReplaySource, 1) => {
                response.request_id = first_id.expect("source request precedes destination");
            }
            (PdpMode::DestinationObligation, 1) => response.obligations.push(Obligation {
                obligation_id: "test:unsupported-step-up".into(),
                parameters: BTreeMap::default(),
            }),
            (PdpMode::DestinationWrongVersion, 1) => {
                response.pdp_api_version = Some("unsupported-version".into());
            }
            _ => {}
        }
        Ok(response)
    }
}

#[derive(Clone, Copy, Debug)]
enum Wire {
    Grpc,
    Rest,
}

#[derive(Debug)]
enum Failure {
    Grpc(tonic::Code),
    Rest(axum::http::StatusCode),
}

impl Failure {
    fn assert_forbidden(&self) {
        match self {
            Self::Grpc(code) => assert_eq!(*code, tonic::Code::PermissionDenied),
            Self::Rest(status) => assert_eq!(*status, axum::http::StatusCode::FORBIDDEN),
        }
    }

    fn assert_internal(&self) {
        match self {
            Self::Grpc(code) => assert_eq!(*code, tonic::Code::Internal),
            Self::Rest(status) => {
                assert_eq!(*status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }
}

async fn re_encrypt(
    wire: Wire,
    state: &Arc<ServiceState>,
    source: &str,
    destination: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Failure> {
    match wire {
        Wire::Grpc => {
            let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
            let mut request = Request::new(proto::ReEncryptRequest {
                source_key_id: source.into(),
                destination_key_id: destination.into(),
                ciphertext_blob: ciphertext.to_vec(),
                ..Default::default()
            });
            request
                .metadata_mut()
                .insert("x-request-id", OUTER_REQUEST_ID.parse().unwrap());
            let response = svc
                .re_encrypt(request)
                .await
                .map_err(|error| Failure::Grpc(error.code()))?
                .into_inner();
            assert_eq!(response.source_key_id, source);
            assert_eq!(response.destination_key_id, destination);
            Ok(response.ciphertext_blob)
        }
        Wire::Rest => {
            use axum::body::Body;
            use tower::ServiceExt;

            let request = axum::http::Request::builder()
                .method("POST")
                .uri(format!("/v1/keys/{source}/actions-re-encrypt"))
                .header("content-type", "application/json")
                .header("x-request-id", OUTER_REQUEST_ID)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "destination_key_id": destination,
                        "ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(ciphertext),
                    }))
                    .unwrap(),
                ))
                .unwrap();
            let response = keyrack_service::rest::router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let status = response.status();
            if !status.is_success() {
                return Err(Failure::Rest(status));
            }
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["source_key_id"], source);
            assert_eq!(body["destination_key_id"], destination);
            Ok(base64::engine::general_purpose::STANDARD
                .decode(body["ciphertext_blob"].as_str().unwrap())
                .unwrap())
        }
    }
}

struct Fixture {
    state: Arc<ServiceState>,
    provider: Arc<RecordingProvider>,
    pdp: Arc<ReEncryptPdp>,
    audit: Arc<CapturingSink>,
    source: String,
    destination: String,
    ciphertext: Vec<u8>,
}

impl Fixture {
    async fn new(mode: PdpMode, same_key: bool) -> Self {
        let provider = Arc::new(RecordingProvider::new(false));
        let pdp = Arc::new(ReEncryptPdp::new(mode));
        let audit = Arc::new(CapturingSink::new());
        let state = build_test_state_with_provider(provider.clone(), pdp.clone(), audit.clone());
        let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
        let source = create_aes_key(&svc).await;
        let destination = if same_key {
            source.clone()
        } else {
            create_aes_key(&svc).await
        };
        let ciphertext = svc
            .encrypt(Request::new(proto::EncryptRequest {
                key_id: source.clone(),
                plaintext: PLAINTEXT.to_vec(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .ciphertext_blob;
        pdp.clear();
        Self {
            state,
            provider,
            pdp,
            audit,
            source,
            destination,
            ciphertext,
        }
    }

    async fn run(&self, wire: Wire) -> Result<Vec<u8>, Failure> {
        re_encrypt(
            wire,
            &self.state,
            &self.source,
            &self.destination,
            &self.ciphertext,
        )
        .await
    }

    async fn assert_plaintext(&self, ciphertext: Vec<u8>) {
        let svc = keyrack_service::grpc::KeyServiceImpl::new(self.state.clone());
        let plaintext = svc
            .decrypt(Request::new(proto::DecryptRequest {
                key_id: self.destination.clone(),
                ciphertext_blob: ciphertext,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .plaintext;
        assert_eq!(plaintext, PLAINTEXT);
    }

    fn assert_failed_audit(&self, destination_failed: bool, denied: bool) {
        let events: Vec<_> = self
            .audit
            .events()
            .into_iter()
            .filter(|event| is_reencrypt(&event.action))
            .collect();
        let resources: Vec<_> = events
            .iter()
            .map(|event| event.resource.id.as_str())
            .collect();
        let expected = if destination_failed {
            vec![self.destination.as_str(), self.source.as_str()]
        } else {
            vec![self.source.as_str()]
        };
        assert_eq!(resources, expected);
        for (index, event) in events.into_iter().enumerate() {
            assert_eq!(
                event.action,
                if destination_failed && index == 0 {
                    AuditAction::ReEncryptTo
                } else {
                    AuditAction::ReEncryptFrom
                }
            );
            if denied {
                assert_eq!(event.event_type, EventType::AuthorizationDenied);
                assert_eq!(event.result, AuditResult::Denied);
                assert_eq!(event.metadata["authorization_status"], "PermissionDenied");
            } else {
                assert_eq!(event.event_type, EventType::CryptoOperation);
                assert_eq!(event.result, AuditResult::Error);
                assert_eq!(event.metadata["authorization_status"], "Internal");
            }
            assert_eq!(event.metadata["failure_phase"], "authorization");
            assert_eq!(event.request_id.as_deref(), Some(OUTER_REQUEST_ID));
        }
    }
}

fn assert_requests(requests: &[AuthzRequest], source: &str, destination: &str) {
    assert!(!requests.is_empty());
    let ids: BTreeSet<_> = requests.iter().map(|request| &request.request_id).collect();
    assert_eq!(ids.len(), requests.len(), "every PDP question is fresh");
    for (index, request) in requests.iter().enumerate() {
        let (role, resource) = if index % 2 == 0 {
            ("source", source)
        } else {
            ("destination", destination)
        };
        assert_eq!(
            request.action,
            if index % 2 == 0 {
                AuditAction::ReEncryptFrom
            } else {
                AuditAction::ReEncryptTo
            }
        );
        assert_eq!(request.resource.id, resource);
        assert_eq!(request.resource.resource_type, "Key");
        assert_ne!(request.request_id, OUTER_REQUEST_ID);
        for (name, value) in [
            ("operation_request_id", OUTER_REQUEST_ID),
            ("re_encrypt_role", role),
            ("source_key_id", source),
            ("destination_key_id", destination),
        ] {
            assert_eq!(
                request.context.entries.get(name),
                Some(&AttributeValue::String(value.into())),
                "missing or incorrect {name} on {role} decision"
            );
        }
    }
}

#[tokio::test]
async fn a_one_direction_grant_cannot_authorize_the_other_leg_even_on_the_same_key() {
    for wire in [Wire::Grpc, Wire::Rest] {
        for same_key in [false, true] {
            for mode in [PdpMode::FromOnly, PdpMode::ToOnly] {
                let fixture = Fixture::new(mode, same_key).await;
                let before = fixture.provider.calls();
                fixture.run(wire).await.unwrap_err().assert_forbidden();
                assert_eq!(fixture.provider.calls(), before);
                let requests = fixture.pdp.requests();
                let destination_failed = matches!(mode, PdpMode::FromOnly);
                assert_eq!(requests.len(), if destination_failed { 2 } else { 1 });
                assert_requests(&requests, &fixture.source, &fixture.destination);
                fixture.assert_failed_audit(destination_failed, true);
            }
        }
    }
}

#[tokio::test]
async fn source_permit_destination_forbid_blocks_both_transports_before_provider() {
    for wire in [Wire::Grpc, Wire::Rest] {
        let fixture = Fixture::new(PdpMode::DestinationForbid, false).await;
        let calls_before = fixture.provider.calls();
        fixture.run(wire).await.unwrap_err().assert_forbidden();
        assert_eq!(fixture.provider.calls(), calls_before);
        let requests = fixture.pdp.requests();
        assert_eq!(requests.len(), 2, "{wire:?}");
        assert_requests(&requests, &fixture.source, &fixture.destination);
        fixture.assert_failed_audit(true, true);
    }
}

#[tokio::test]
async fn source_forbid_short_circuits_destination_and_provider_on_both_transports() {
    for wire in [Wire::Grpc, Wire::Rest] {
        let fixture = Fixture::new(PdpMode::SourceForbid, false).await;
        let calls_before = fixture.provider.calls();
        fixture.run(wire).await.unwrap_err().assert_forbidden();
        assert_eq!(fixture.provider.calls(), calls_before);
        let requests = fixture.pdp.requests();
        assert_eq!(requests.len(), 1, "{wire:?}");
        assert_requests(&requests, &fixture.source, &fixture.destination);
        fixture.assert_failed_audit(false, true);
    }
}

#[tokio::test]
async fn both_permits_roundtrip_with_independent_ids_even_when_caller_reuses_request_id() {
    for wire in [Wire::Grpc, Wire::Rest] {
        let fixture = Fixture::new(PdpMode::PermitBoth, false).await;
        let first = fixture.run(wire).await.unwrap();
        let second = fixture.run(wire).await.unwrap();
        let requests = fixture.pdp.requests();
        assert_eq!(requests.len(), 4);
        assert_requests(&requests, &fixture.source, &fixture.destination);
        let events: Vec<_> = fixture
            .audit
            .events()
            .into_iter()
            .filter(|event| is_reencrypt(&event.action))
            .collect();
        assert_eq!(events.len(), 2);
        for event in events {
            assert_eq!(event.action, AuditAction::ReEncryptFrom);
            assert_eq!(event.result, AuditResult::Success);
            assert_eq!(event.resource.id, fixture.source);
            assert_eq!(event.request_id.as_deref(), Some(OUTER_REQUEST_ID));
        }
        fixture.assert_plaintext(first).await;
        fixture.assert_plaintext(second).await;
    }
}

#[tokio::test]
async fn same_key_still_requires_two_distinct_decisions_on_both_transports() {
    for wire in [Wire::Grpc, Wire::Rest] {
        let fixture = Fixture::new(PdpMode::PermitBoth, true).await;
        let result = fixture.run(wire).await.unwrap();
        let requests = fixture.pdp.requests();
        assert_eq!(requests.len(), 2);
        assert_requests(&requests, &fixture.source, &fixture.destination);
        fixture.assert_plaintext(result).await;
    }
}

#[tokio::test]
async fn destination_nonpermit_and_raw_protocol_failures_never_reach_provider() {
    for wire in [Wire::Grpc, Wire::Rest] {
        for mode in [
            PdpMode::DestinationIndeterminate,
            PdpMode::DestinationError,
            PdpMode::DestinationWrongId,
            PdpMode::DestinationReplaySource,
            PdpMode::DestinationObligation,
            PdpMode::DestinationWrongVersion,
        ] {
            let fixture = Fixture::new(mode, false).await;
            let calls_before = fixture.provider.calls();
            let error = fixture
                .run(wire)
                .await
                .expect_err("destination must fail closed");
            let denied = matches!(
                mode,
                PdpMode::DestinationIndeterminate | PdpMode::DestinationObligation
            );
            if denied {
                error.assert_forbidden();
            } else {
                error.assert_internal();
            }
            assert_eq!(fixture.provider.calls(), calls_before, "{wire:?} {mode:?}");
            let requests = fixture.pdp.requests();
            assert_eq!(requests.len(), 2, "{wire:?} {mode:?}");
            assert_requests(&requests, &fixture.source, &fixture.destination);
            fixture.assert_failed_audit(true, denied);
        }
    }
}

#[tokio::test]
async fn denied_destination_precedes_storage_lookup_and_ciphertext_parsing() {
    for wire in [Wire::Grpc, Wire::Rest] {
        let fixture = Fixture::new(PdpMode::DestinationForbid, false).await;
        // These are deliberately not valid LIDs or a valid ciphertext. A storage
        // lookup/parse before authorization would return a different error.
        re_encrypt(
            wire,
            &fixture.state,
            "missing-source",
            "missing-destination",
            &[],
        )
        .await
        .unwrap_err()
        .assert_forbidden();
        let requests = fixture.pdp.requests();
        assert_eq!(requests.len(), 2);
        assert_requests(&requests, "missing-source", "missing-destination");
    }
}

#[tokio::test]
async fn generic_single_key_reencrypt_context_cannot_enter_either_executor_closure() {
    let fixture = Fixture::new(PdpMode::PermitBoth, false).await;
    for action in [AuditAction::ReEncryptFrom, AuditAction::ReEncryptTo] {
        let executed = Arc::new(AtomicBool::new(false));
        let observed = executed.clone();
        let result = ops::execute(
            &fixture.state,
            OpContext::key(action.clone(), Principal::system(), &fixture.source),
            move |_| async move {
                observed.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(result.is_err());
        assert!(!executed.load(Ordering::SeqCst));
        let observed = executed.clone();
        let result = ops::execute_rest(
            &fixture.state,
            OpContext::key(action, Principal::system(), &fixture.source),
            move |_| async move {
                observed.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(result.is_err());
        assert!(!executed.load(Ordering::SeqCst));
        assert!(fixture.pdp.requests().is_empty());
    }
}

#[tokio::test]
async fn single_resource_attribute_helper_cannot_authorize_reencrypt() {
    let fixture = Fixture::new(PdpMode::PermitBoth, false).await;
    for ctx in [
        OpContext::key(
            AuditAction::ReEncryptFrom,
            Principal::system(),
            &fixture.source,
        ),
        OpContext::key(
            AuditAction::ReEncryptTo,
            Principal::system(),
            &fixture.source,
        ),
        OpContext::re_encrypt(Principal::system(), &fixture.source, &fixture.destination),
    ] {
        assert!(
            ops::authorize_with_resource_attrs(&fixture.state, &ctx, BTreeMap::default())
                .await
                .is_err()
        );
    }
    assert!(fixture.pdp.requests().is_empty());
}

fn install_alternate_provider(fixture: &mut Fixture) -> Arc<RecordingProvider> {
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::registry::{ProviderEntry, StaticProviderRegistry};

    let alternate = Arc::new(RecordingProvider::new(false));
    Arc::get_mut(&mut fixture.state).unwrap().providers = Arc::new(
        StaticProviderRegistry::new(
            [
                (
                    ProviderRef::new("default"),
                    ProviderEntry {
                        provider: fixture.provider.clone(),
                        class: ProviderClass::InMemory,
                    },
                ),
                (
                    ProviderRef::new("alternate"),
                    ProviderEntry {
                        provider: alternate.clone(),
                        class: ProviderClass::InMemory,
                    },
                ),
            ],
            ProviderRef::new("default"),
        )
        .unwrap(),
    );
    alternate
}

/// Construct a resident-version fixture, not a custody-preserving migration.
/// The new destination material is generated on the second in-memory backend.
async fn bind_destination_to_alternate(fixture: &Fixture, alternate: &RecordingProvider) {
    use keyrack_core::key::{KeySpec, ProviderRef};

    let mut destination = fixture
        .state
        .storage
        .get_key(&fixture.destination.parse().unwrap())
        .await
        .unwrap();
    destination.key_versions[0].key_handle =
        alternate.generate_key(&KeySpec::Aes256).await.unwrap();
    destination.key_versions[0].provider_ref = Some(ProviderRef::new("alternate"));
    destination.occ_version += 1;
    fixture
        .state
        .storage
        .update_key(&destination)
        .await
        .unwrap();
}

#[tokio::test]
async fn dual_permits_cover_cross_provider_resident_reencrypt_on_both_transports() {
    for wire in [Wire::Grpc, Wire::Rest] {
        let mut fixture = Fixture::new(PdpMode::PermitBoth, false).await;
        let alternate = install_alternate_provider(&mut fixture);
        bind_destination_to_alternate(&fixture, &alternate).await;
        let source_calls_before = fixture.provider.calls().len();
        let destination_calls_before = alternate.calls().len();
        let output = fixture.run(wire).await.unwrap();
        assert_eq!(
            &fixture.provider.calls()[source_calls_before..],
            &["decrypt"]
        );
        assert_eq!(&alternate.calls()[destination_calls_before..], &["encrypt"]);
        let requests = fixture.pdp.requests();
        assert_eq!(requests.len(), 2);
        assert_requests(&requests, &fixture.source, &fixture.destination);
        fixture.assert_plaintext(output).await;
    }
}

#[tokio::test]
async fn source_scope_follows_ciphertext_version_not_current_primary_on_both_transports() {
    use keyrack_core::key::{KeySpec, KeyVersionRecord, ProviderRef};

    for wire in [Wire::Grpc, Wire::Rest] {
        for historical_protected in [true, false] {
            let mut fixture = Fixture::new(PdpMode::PermitBoth, false).await;
            let alternate = install_alternate_provider(&mut fixture);
            if historical_protected {
                // Destination stays accessible when the source's historical
                // provider is forbidden, so it cannot mask a source bypass.
                bind_destination_to_alternate(&fixture, &alternate).await;
            }
            let mut source = fixture
                .state
                .storage
                .get_key(&fixture.source.parse().unwrap())
                .await
                .unwrap();
            source.key_versions[0].is_primary = false;
            source.key_versions.push(KeyVersionRecord {
                version_number: 2,
                key_handle: alternate.generate_key(&KeySpec::Aes256).await.unwrap(),
                provider_ref: Some(ProviderRef::new("alternate")),
                created_at: chrono::Utc::now(),
                is_primary: true,
            });
            source.current_key_version = 2;
            source.occ_version += 1;
            fixture.state.storage.update_key(&source).await.unwrap();
            let protected_provider = if historical_protected {
                "default"
            } else {
                "alternate"
            };
            let connection = keyrack_core::hsm::HsmConnection::new(
                protected_provider,
                keyrack_core::hsm::HsmProviderType::Hsm,
                "/test-only-provider.so",
                "historical scope regression",
            )
            .with_scope_owner("tenant:unrelated");
            fixture
                .state
                .storage
                .create_hsm_connection(&connection)
                .await
                .unwrap();
            let source_before = fixture.provider.calls();
            let alternate_before = alternate.calls();
            let output = fixture.run(wire).await;
            let requests = fixture.pdp.requests();
            assert_eq!(requests.len(), 2);
            assert_requests(&requests, &fixture.source, &fixture.destination);
            if historical_protected {
                output.unwrap_err().assert_forbidden();
                assert_eq!(fixture.provider.calls(), source_before);
                assert_eq!(alternate.calls(), alternate_before);
                assert!(fixture.audit.events().iter().any(|event| {
                    event.event_type == EventType::ScopeOwnerCheck
                        && event.result == AuditResult::Denied
                        && event.resource.id == protected_provider
                }));
            } else {
                // An inaccessible new primary must not prevent access to an
                // authorized historical version selected by authenticated CT.
                fixture.assert_plaintext(output.unwrap()).await;
                assert_eq!(alternate.calls(), alternate_before);
            }
        }
    }
}
