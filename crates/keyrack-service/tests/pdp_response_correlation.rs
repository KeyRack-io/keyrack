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

//! A PDP response must answer the request it is applied to.
//!
//! Both PDP clients used to return whatever the endpoint sent as long as it
//! parsed, so a well-formed `Permit` belonging to a *different* authorization
//! request was accepted as the decision for the operation in hand. The
//! exploit shape is response substitution or a confused proxy rather than an
//! unauthenticated allow — the status-error and parse-error paths were already
//! closed — but the decision applied is then unrelated to the request.
//!
//! Each transport is tested against a real server rather than a stubbed
//! client, because the gap was in the client's handling of a genuinely
//! well-formed response. The happy-path cases are here to show the check
//! refuses only uncorrelated responses.

use keyrack_core::audit::AuditAction;
use keyrack_core::pdp::{
    AuthzRequest, Decision, PolicyDecisionPoint, Principal, RequestContext, Resource,
    PDP_API_VERSION,
};
use keyrack_service::pdp_grpc::GrpcPdpClient;
use keyrack_service::pdp_http::HttpPdpClient;
use keyrack_service::proto;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

const TIMEOUT: Duration = Duration::from_secs(5);

fn request_with_id(id: &str) -> AuthzRequest {
    AuthzRequest {
        pdp_api_version: PDP_API_VERSION.into(),
        request_id: id.into(),
        action: AuditAction::Decrypt,
        principal: Principal {
            id: "user:alice".into(),
            principal_type: "User".into(),
            attributes: BTreeMap::new(),
        },
        resource: Resource {
            id: "lid_abc".into(),
            resource_type: "Key".into(),
            attributes: BTreeMap::new(),
        },
        context: RequestContext::default(),
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/// Serves one fixed JSON body to every request, so the response is well-formed
/// and successful and differs from the request only in `request_id`.
async fn spawn_http_pdp(body: serde_json::Value) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let app = axum::Router::new().route(
        "/authorize",
        axum::routing::post(move || {
            let body = body.clone();
            async move { axum::Json(body) }
        }),
    );

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    addr
}

fn permit_body(request_id: &str) -> serde_json::Value {
    serde_json::json!({
        "request_id": request_id,
        "decision": "Permit",
        "reasons": [],
        "obligations": [],
    })
}

#[tokio::test]
async fn http_pdp_refuses_permit_for_a_different_request() {
    // A complete, successful, parseable Permit — for someone else's request.
    let addr = spawn_http_pdp(permit_body("req-SOMEONE-ELSE")).await;
    let client = HttpPdpClient::new(
        format!("http://{addr}/authorize"),
        TIMEOUT,
        None,
        None,
        None,
    )
    .expect("client");

    let err = client
        .evaluate(&request_with_id("req-MINE"))
        .await
        .expect_err(
            "a Permit carrying another request's id must be refused, not applied to this request",
        );

    let msg = err.to_string();
    assert!(
        msg.contains("PDP protocol violation"),
        "expected a protocol violation, got: {msg}"
    );
    assert!(
        msg.contains("req-SOMEONE-ELSE") && msg.contains("req-MINE"),
        "the error should name both ids so an operator can see the mismatch, got: {msg}"
    );
}

#[tokio::test]
async fn http_pdp_accepts_a_correlated_permit() {
    let addr = spawn_http_pdp(permit_body("req-MINE")).await;
    let client = HttpPdpClient::new(
        format!("http://{addr}/authorize"),
        TIMEOUT,
        None,
        None,
        None,
    )
    .expect("client");

    let resp = client
        .evaluate(&request_with_id("req-MINE"))
        .await
        .expect("a correlated Permit must still be accepted");
    assert_eq!(resp.decision, Decision::Permit);
}

// ---------------------------------------------------------------------------
// gRPC
// ---------------------------------------------------------------------------

/// Answers every `Authorize` with a Permit built from these fields, regardless
/// of what was asked.
#[derive(Clone, Default)]
struct FixedIdPdp {
    reply_id: String,
    api_version: String,
    obligation_ids: Vec<String>,
}

#[tonic::async_trait]
impl proto::pdp_service_server::PdpService for FixedIdPdp {
    async fn authorize(
        &self,
        _request: tonic::Request<proto::PdpAuthorizeRequest>,
    ) -> Result<tonic::Response<proto::PdpAuthorizeResponse>, tonic::Status> {
        Ok(tonic::Response::new(proto::PdpAuthorizeResponse {
            request_id: self.reply_id.clone(),
            decision: proto::PdpDecision::Permit as i32,
            reasons: vec![],
            obligations: self
                .obligation_ids
                .iter()
                .map(|id| proto::PdpObligation {
                    obligation_id: id.clone(),
                    parameters: std::collections::HashMap::new(),
                })
                .collect(),
            policy_version: String::new(),
            pdp_api_version: self.api_version.clone(),
        }))
    }

    async fn batch_authorize(
        &self,
        _request: tonic::Request<proto::PdpBatchAuthorizeRequest>,
    ) -> Result<tonic::Response<proto::PdpBatchAuthorizeResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not used by this test"))
    }

    async fn explain_authorization(
        &self,
        _request: tonic::Request<proto::PdpExplainRequest>,
    ) -> Result<tonic::Response<proto::PdpExplainResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not used by this test"))
    }
}

async fn spawn_grpc_pdp(reply_id: &str) -> SocketAddr {
    spawn_grpc_pdp_with(FixedIdPdp {
        reply_id: reply_id.to_string(),
        ..FixedIdPdp::default()
    })
    .await
}

async fn spawn_grpc_pdp_with(svc: FixedIdPdp) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(proto::pdp_service_server::PdpServiceServer::new(svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await;
    });

    addr
}

#[tokio::test]
async fn grpc_pdp_refuses_permit_for_a_different_request() {
    let addr = spawn_grpc_pdp("req-SOMEONE-ELSE").await;
    let client =
        GrpcPdpClient::new(format!("http://{addr}"), TIMEOUT, None, None, None).expect("client");

    let err = client
        .evaluate(&request_with_id("req-MINE"))
        .await
        .expect_err("a Permit carrying another request's id must be refused");

    assert!(
        err.to_string().contains("PDP protocol violation"),
        "expected a protocol violation, got: {err}"
    );
}

/// proto3 has no absent-vs-empty distinction, so a gRPC PDP that never sets
/// `request_id` sends `""` and the response still looks well-formed. That is
/// the likeliest real-world form of an uncorrelated response, so it gets its
/// own case and its own diagnostic.
#[tokio::test]
async fn grpc_pdp_refuses_a_response_with_no_request_id() {
    let addr = spawn_grpc_pdp("").await;
    let client =
        GrpcPdpClient::new(format!("http://{addr}"), TIMEOUT, None, None, None).expect("client");

    let err = client
        .evaluate(&request_with_id("req-MINE"))
        .await
        .expect_err("a response that echoes no request_id must be refused");

    let msg = err.to_string();
    assert!(
        msg.contains("carries no request_id"),
        "the error should explain the proto3 empty-field case, got: {msg}"
    );
}

#[tokio::test]
async fn grpc_pdp_accepts_a_correlated_permit() {
    let addr = spawn_grpc_pdp("req-MINE").await;
    let client =
        GrpcPdpClient::new(format!("http://{addr}"), TIMEOUT, None, None, None).expect("client");

    let resp = client
        .evaluate(&request_with_id("req-MINE"))
        .await
        .expect("a correlated Permit must still be accepted");
    assert_eq!(resp.decision, Decision::Permit);
}

// ---------------------------------------------------------------------------
// Obligations: a permit conditional on something nothing discharges
// ---------------------------------------------------------------------------

/// Ignoring an obligation turns a conditional permit into an unconditional
/// one, granting more than the policy author wrote. Nothing here implements
/// any obligation handler, so the decision is denied rather than honoured.
///
/// This denies rather than erroring: the PDP behaved correctly and its
/// decision parsed, so a protocol error would misdescribe what happened.
#[tokio::test]
async fn http_pdp_denies_a_permit_carrying_an_obligation() {
    let body = serde_json::json!({
        "request_id": "req-MINE",
        "decision": "Permit",
        "obligations": [{ "obligation_id": "rate_limit_class",
                          "parameters": { "class": "burst" } }],
    });
    let addr = spawn_http_pdp(body).await;
    let client = HttpPdpClient::new(
        format!("http://{addr}/authorize"),
        TIMEOUT,
        None,
        None,
        None,
    )
    .expect("client");

    let resp = client
        .evaluate(&request_with_id("req-MINE"))
        .await
        .expect("an obligation is a policy condition, not a protocol failure");

    assert_eq!(
        resp.decision,
        Decision::Forbid,
        "a conditional permit must not be honoured as an unconditional one"
    );
    assert!(
        resp.reasons.iter().any(|r| r.policy_id == "keyrack:pep"),
        "the refusal must be attributed to the enforcement point rather than the policy, \
         so an audit reader can tell who denied: {:?}",
        resp.reasons
    );
}

#[tokio::test]
async fn grpc_pdp_denies_a_permit_carrying_an_obligation() {
    let addr = spawn_grpc_pdp_with(FixedIdPdp {
        reply_id: "req-MINE".into(),
        obligation_ids: vec!["rate_limit_class".into()],
        ..FixedIdPdp::default()
    })
    .await;
    let client =
        GrpcPdpClient::new(format!("http://{addr}"), TIMEOUT, None, None, None).expect("client");

    let resp = client
        .evaluate(&request_with_id("req-MINE"))
        .await
        .expect("an obligation is a policy condition, not a protocol failure");
    assert_eq!(resp.decision, Decision::Forbid);
    assert!(resp.reasons.iter().any(|r| r.policy_id == "keyrack:pep"));
}

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// A response that states a version this build cannot read must not have its
/// remaining fields trusted. Refused as a protocol failure, matching the
/// correlation case: no policy decision can be attributed to it.
#[tokio::test]
async fn grpc_pdp_refuses_an_unreadable_schema_version() {
    let addr = spawn_grpc_pdp_with(FixedIdPdp {
        reply_id: "req-MINE".into(),
        api_version: "2.0".into(),
        ..FixedIdPdp::default()
    })
    .await;
    let client =
        GrpcPdpClient::new(format!("http://{addr}"), TIMEOUT, None, None, None).expect("client");

    let err = client
        .evaluate(&request_with_id("req-MINE"))
        .await
        .expect_err("a Permit under an unreadable schema version must not be applied");
    assert!(
        err.to_string().contains("PDP protocol violation"),
        "got: {err}"
    );
}

/// proto3 sends `""` for an unset field, and PDPs written before the field
/// existed do not set it, so absent must stay acceptable.
#[tokio::test]
async fn grpc_pdp_accepts_a_response_that_states_no_schema_version() {
    let addr = spawn_grpc_pdp("req-MINE").await;
    let client =
        GrpcPdpClient::new(format!("http://{addr}"), TIMEOUT, None, None, None).expect("client");

    let resp = client
        .evaluate(&request_with_id("req-MINE"))
        .await
        .expect("a PDP predating the field is well-formed");
    assert_eq!(resp.decision, Decision::Permit);
}

#[tokio::test]
async fn http_pdp_refuses_an_unreadable_schema_version() {
    let body = serde_json::json!({
        "request_id": "req-MINE",
        "decision": "Permit",
        "pdp_api_version": "2.0",
    });
    let addr = spawn_http_pdp(body).await;
    let client = HttpPdpClient::new(
        format!("http://{addr}/authorize"),
        TIMEOUT,
        None,
        None,
        None,
    )
    .expect("client");

    let err = client
        .evaluate(&request_with_id("req-MINE"))
        .await
        .expect_err("a Permit under an unreadable schema version must not be applied");
    assert!(
        err.to_string().contains("PDP protocol violation"),
        "got: {err}"
    );
}
