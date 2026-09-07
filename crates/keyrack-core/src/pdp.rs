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

//! Policy Decision Point (PDP) trait and request/response types.
//!
//! `KeyRack`'s PDP is **architecturally external by default** — the
//! service calls out to a separate process (Cedar, OPA, or any
//! HTTP/gRPC-shaped PDP).
//!
//! This module defines the stable, versioned request schema that all
//! PDP implementations must accept. The schema shape is locked in
//! `SPEC.md` §8; field details evolve with the PDP team.
//!
//! See `PDP_WIRE_FORMAT_REQS.md` for the full constraint set.

use crate::audit::AuditAction;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// PDP wire format API version (R-V1).
pub const PDP_API_VERSION: &str = "1.0";

/// Typed attribute value for PDP attribute maps.
///
/// Uses an explicit `oneof AttributeValue` to avoid `serde_json::Value`
/// ambiguity for the boolean/integer distinction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    String(String),
    Bool(bool),
    Integer(i64),
    StringList(Vec<String>),
    Record(BTreeMap<String, AttributeValue>),
    RecordList(Vec<BTreeMap<String, AttributeValue>>),
}

/// Authorization request sent to the PDP.
///
/// Top-level shape is stable (§8.1):
/// `{ pdp_api_version, request_id, action, principal, resource, context }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzRequest {
    pub pdp_api_version: String,
    pub request_id: String,
    pub action: AuditAction,
    pub principal: Principal,
    pub resource: Resource,
    pub context: RequestContext,
}

/// The authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Opaque principal identifier (e.g. SRN, service account name).
    pub id: String,
    /// Principal kind (e.g. `"User"`, `"Service"`, `"Admin"`).
    #[serde(rename = "type")]
    pub principal_type: String,
    /// Caller-specific attributes visible to the PDP (roles, tenant, etc.).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, AttributeValue>,
}

/// Well-known system principal for internal operations.
pub const SYSTEM_PRINCIPAL_ID: &str = "keyrack:system";

impl Principal {
    /// The system principal used for `KeyRack`-internal operations
    /// (cascade-disable, rotation-job expiry, etc.).
    #[must_use]
    pub fn system() -> Self {
        Self {
            id: SYSTEM_PRINCIPAL_ID.into(),
            principal_type: "System".into(),
            attributes: BTreeMap::new(),
        }
    }
}

/// Resource targeted by the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    /// Resource identifier (LID string for keys, connection id for
    /// HSM connections, etc.).
    pub id: String,
    /// Resource kind (e.g. `"Key"`, `"Alias"`, `"HsmConnection"`).
    #[serde(rename = "type")]
    pub resource_type: String,
    /// Additional attributes visible to the PDP (e.g. identity tags,
    /// user tags, key state). Content varies by resource type.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, AttributeValue>,
}

/// Request-scoped context (non-resource, non-principal data).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestContext {
    /// Free-form context pairs visible to the PDP.
    #[serde(flatten)]
    pub entries: BTreeMap<String, AttributeValue>,
}

/// Structured policy reason from the PDP (two-tier: machine + human).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReason {
    pub policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_message: Option<String>,
}

/// Obligation the caller must fulfill after a Permit decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obligation {
    pub obligation_id: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, AttributeValue>,
}

/// Authorization response from the PDP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzResponse {
    pub request_id: String,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<PolicyReason>,
    /// Conditions the enforcement point must discharge before acting on a
    /// `Permit`. Core implements no obligation handlers, so a `Permit`
    /// carrying any of these is refused — see [`AuthzResponse::into_enforceable`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<Obligation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    /// Schema version of this response, when the PDP states one. Absent is
    /// accepted; a stated version that is not [`PDP_API_VERSION`] is refused,
    /// because the fields cannot be read with confidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdp_api_version: Option<String>,
}

/// Reason source for a refusal decided by the enforcement point rather than
/// by policy, so an audit reader can tell the two apart.
const PEP_POLICY_ID: &str = "keyrack:pep";

impl AuthzResponse {
    /// Reduce this response to what the enforcement point can actually act on,
    /// or refuse it.
    ///
    /// Three conditions, applied at the point the response crosses the trust
    /// boundary. Both the HTTP and gRPC clients call this one function, so the
    /// two transports cannot drift apart in what they accept — the correlation
    /// gap this replaced was present in both, and a per-transport check is how
    /// they got there.
    ///
    /// 1. **Correlation.** A decision is only meaningful for the request it was
    ///    computed for, so a response whose `request_id` does not echo the one
    ///    sent is refused. Without this, a response substituted in transit or
    ///    misrouted by a shared proxy or a connection-pooling bug is acted on
    ///    as though it described the operation being authorized.
    /// 2. **Schema version.** A stated `pdp_api_version` other than
    ///    [`PDP_API_VERSION`] is refused, because the remaining fields cannot
    ///    be read with confidence. An absent version is accepted: the field is
    ///    an addition, and PDPs that predate it are well-formed.
    /// 3. **Obligations.** No obligation handlers are implemented, so a
    ///    `Permit` carrying one cannot be discharged and is downgraded to
    ///    `Forbid`. An obligation is a *condition* on a permit; ignoring it
    ///    turns a conditional permit into an unconditional one, which grants
    ///    more than the policy author wrote.
    ///
    /// The first two are protocol failures and return `Err` — no policy
    /// decided anything, so nothing should be recorded as though it had. The
    /// third is a decision this crate understands but cannot honour safely, so
    /// it denies and says who denied it via [`PEP_POLICY_ID`], leaving the
    /// PDP's own reasons in place.
    ///
    /// Obligations on a non-`Permit` decision are left alone: the operation is
    /// refused regardless, so there is no condition to discharge and nothing
    /// is granted on an undischarged one.
    ///
    /// The bundled implementations (`AlwaysAllow`, `AlwaysDeny`, the Cedar
    /// engine) echo the id and emit no obligations, so they pass unchanged.
    pub fn into_enforceable(mut self, request: &AuthzRequest) -> crate::error::Result<Self> {
        if self.request_id != request.request_id {
            // Called out separately because it is the shape a gRPC PDP that
            // never sets the field produces: proto3 yields "" rather than an
            // absent value, so the response still looks well-formed.
            let detail = if self.request_id.is_empty() {
                "response carries no request_id (a gRPC PDP must echo the field; \
                 proto3 leaves it empty when unset)"
                    .to_string()
            } else {
                format!(
                    "response request_id {:?} does not match request {:?}",
                    self.request_id, request.request_id
                )
            };
            return Err(crate::error::KeyRackError::Other(format!(
                "PDP protocol violation: {detail}"
            )));
        }

        if let Some(version) = self.pdp_api_version.as_deref() {
            if version != PDP_API_VERSION {
                return Err(crate::error::KeyRackError::Other(format!(
                    "PDP protocol violation: response states pdp_api_version {version:?}, \
                     which this build cannot read (expected {PDP_API_VERSION:?})"
                )));
            }
        }

        if self.decision.is_permit() && !self.obligations.is_empty() {
            let ids: Vec<&str> = self
                .obligations
                .iter()
                .map(|o| o.obligation_id.as_str())
                .collect();
            let ids = ids.join(", ");

            tracing::warn!(
                request_id = %self.request_id,
                obligations = %ids,
                "PDP permitted subject to obligations that cannot be discharged; denying"
            );

            self.decision = Decision::Forbid;
            self.reasons.push(PolicyReason {
                policy_id: PEP_POLICY_ID.into(),
                reason_code: Some("obligation_not_dischargeable".into()),
                human_message: Some(format!(
                    "permit was conditional on obligations with no handler ({ids}); \
                     denied rather than granted unconditionally"
                )),
            });
        }

        Ok(self)
    }
}

/// PDP decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Decision {
    Permit,
    Forbid,
    Indeterminate,
}

impl Decision {
    #[must_use]
    pub fn is_permit(&self) -> bool {
        matches!(self, Self::Permit)
    }
}

/// Trait for policy decision points.
///
/// All PDP implementations (HTTP, gRPC, embedded Cedar, test fixtures)
/// implement this trait.
#[async_trait]
pub trait PolicyDecisionPoint: Send + Sync {
    /// Evaluate an authorization request.
    async fn evaluate(&self, request: &AuthzRequest) -> crate::error::Result<AuthzResponse>;
}

/// Test fixture: always permits.
pub struct AlwaysAllow;

#[async_trait]
impl PolicyDecisionPoint for AlwaysAllow {
    async fn evaluate(&self, request: &AuthzRequest) -> crate::error::Result<AuthzResponse> {
        Ok(AuthzResponse {
            request_id: request.request_id.clone(),
            decision: Decision::Permit,
            reasons: vec![],
            obligations: vec![],
            policy_version: None,
            pdp_api_version: Some(PDP_API_VERSION.into()),
        })
    }
}

/// Test fixture: always denies.
pub struct AlwaysDeny;

#[async_trait]
impl PolicyDecisionPoint for AlwaysDeny {
    async fn evaluate(&self, request: &AuthzRequest) -> crate::error::Result<AuthzResponse> {
        Ok(AuthzResponse {
            request_id: request.request_id.clone(),
            decision: Decision::Forbid,
            reasons: vec![PolicyReason {
                policy_id: "builtin:always_deny".into(),
                reason_code: Some("always_deny".into()),
                human_message: Some("policy: always deny".into()),
            }],
            obligations: vec![],
            policy_version: None,
            pdp_api_version: Some(PDP_API_VERSION.into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_request(action: AuditAction) -> AuthzRequest {
        AuthzRequest {
            pdp_api_version: PDP_API_VERSION.into(),
            request_id: "req-001".into(),
            action,
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

    #[test]
    fn authz_request_serialization() {
        let req = make_test_request(AuditAction::Encrypt);
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AuthzRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.request_id, "req-001");
        assert_eq!(parsed.action, AuditAction::Encrypt);
        assert_eq!(parsed.pdp_api_version, "1.0");
    }

    #[test]
    fn system_principal() {
        let p = Principal::system();
        assert_eq!(p.id, "keyrack:system");
        assert_eq!(p.principal_type, "System");
        assert!(p.attributes.is_empty());
    }

    #[test]
    fn decision_variants() {
        assert!(Decision::Permit.is_permit());
        assert!(!Decision::Forbid.is_permit());
        assert!(!Decision::Indeterminate.is_permit());
    }

    #[tokio::test]
    async fn always_allow_permits() {
        let pdp = AlwaysAllow;
        let req = make_test_request(AuditAction::Decrypt);
        let resp = pdp.evaluate(&req).await.unwrap();
        assert!(resp.decision.is_permit());
    }

    #[tokio::test]
    async fn always_deny_forbids() {
        let pdp = AlwaysDeny;
        let req = make_test_request(AuditAction::CreateKey);
        let resp = pdp.evaluate(&req).await.unwrap();
        assert_eq!(resp.decision, Decision::Forbid);
        assert!(!resp.reasons.is_empty());
    }

    fn response_with_id(id: &str) -> AuthzResponse {
        AuthzResponse {
            request_id: id.into(),
            decision: Decision::Permit,
            reasons: vec![],
            obligations: vec![],
            policy_version: None,
            pdp_api_version: None,
        }
    }

    fn obligation(id: &str) -> Obligation {
        Obligation {
            obligation_id: id.into(),
            parameters: BTreeMap::new(),
        }
    }

    #[test]
    fn correlated_response_is_accepted() {
        let req = make_test_request(AuditAction::Decrypt);
        assert!(response_with_id("req-001").into_enforceable(&req).is_ok());
    }

    #[test]
    fn response_for_another_request_is_refused() {
        let req = make_test_request(AuditAction::Decrypt);
        let err = response_with_id("req-999")
            .into_enforceable(&req)
            .expect_err("a Permit for a different request must not be applied to this one");
        let msg = err.to_string();
        assert!(msg.contains("PDP protocol violation"), "got: {msg}");
        assert!(
            msg.contains("req-999") && msg.contains("req-001"),
            "both ids belong in the error so the mismatch is diagnosable: {msg}"
        );
    }

    #[test]
    fn response_without_a_request_id_is_refused() {
        let req = make_test_request(AuditAction::Decrypt);
        let err = response_with_id("")
            .into_enforceable(&req)
            .expect_err("an empty request_id does not correlate");
        assert!(
            err.to_string().contains("carries no request_id"),
            "the proto3 empty-field case gets its own message: {err}"
        );
    }

    #[test]
    fn absent_schema_version_is_accepted() {
        // The field is an addition; PDPs predating it are well-formed.
        let req = make_test_request(AuditAction::Decrypt);
        let mut resp = response_with_id("req-001");
        resp.pdp_api_version = None;
        assert!(resp.into_enforceable(&req).is_ok());
    }

    #[test]
    fn unreadable_schema_version_is_refused() {
        let req = make_test_request(AuditAction::Decrypt);
        let mut resp = response_with_id("req-001");
        resp.pdp_api_version = Some("2.0".into());
        let err = resp
            .into_enforceable(&req)
            .expect_err("a version this build cannot read must not be parsed as though it could");
        let msg = err.to_string();
        assert!(msg.contains("PDP protocol violation"), "got: {msg}");
        assert!(msg.contains("2.0") && msg.contains("1.0"), "got: {msg}");
    }

    #[test]
    fn permit_with_an_obligation_is_denied_not_granted() {
        let req = make_test_request(AuditAction::Decrypt);
        let mut resp = response_with_id("req-001");
        resp.obligations = vec![obligation("rate_limit_class")];

        let enforced = resp
            .into_enforceable(&req)
            .expect("an obligation is a policy condition, not a protocol failure");

        assert_eq!(
            enforced.decision,
            Decision::Forbid,
            "a permit conditional on something nothing discharges must not be honoured \
             as an unconditional permit"
        );
        let pep = enforced
            .reasons
            .iter()
            .find(|r| r.policy_id == PEP_POLICY_ID)
            .expect("the refusal must name the enforcement point, not the policy");
        assert_eq!(
            pep.reason_code.as_deref(),
            Some("obligation_not_dischargeable")
        );
        assert!(
            pep.human_message
                .as_deref()
                .is_some_and(|m| m.contains("rate_limit_class")),
            "the unhandled obligation should be named: {:?}",
            pep.human_message
        );
    }

    #[test]
    fn obligations_on_a_denial_are_left_alone() {
        // Nothing is granted, so there is no condition to discharge; the
        // decision and the PDP's own reasons pass through untouched.
        let req = make_test_request(AuditAction::Decrypt);
        let mut resp = response_with_id("req-001");
        resp.decision = Decision::Forbid;
        resp.obligations = vec![obligation("log_denial")];

        let enforced = resp.into_enforceable(&req).expect("still a valid response");
        assert_eq!(enforced.decision, Decision::Forbid);
        assert!(
            enforced.reasons.is_empty(),
            "no PEP reason should be synthesised for an already-denied request"
        );
    }

    #[test]
    fn bundled_pdps_pass_unchanged() {
        // The fixtures and the Cedar engine echo the id and emit no
        // obligations, so none of the three rules is load-bearing for them.
        // Asserted here so a refactor that breaks the echo, or starts emitting
        // an obligation, is caught in this crate rather than in a deployment.
        let req = make_test_request(AuditAction::CreateKey);
        let permit = tokio_test_block(AlwaysAllow.evaluate(&req)).expect("permit");
        let deny = tokio_test_block(AlwaysDeny.evaluate(&req)).expect("deny");

        assert_eq!(
            permit
                .into_enforceable(&req)
                .expect("fixture must pass")
                .decision,
            Decision::Permit
        );
        assert_eq!(
            deny.into_enforceable(&req)
                .expect("fixture must pass")
                .decision,
            Decision::Forbid
        );
    }

    fn tokio_test_block<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(fut)
    }

    #[test]
    fn resource_attributes_included() {
        let mut attrs = BTreeMap::new();
        attrs.insert("tenant".into(), AttributeValue::String("globex".into()));

        let resource = Resource {
            id: "lid_z".into(),
            resource_type: "Key".into(),
            attributes: attrs,
        };

        let json = serde_json::to_string(&resource).unwrap();
        assert!(json.contains("globex"));
    }

    #[test]
    fn attribute_value_serde() {
        let av = AttributeValue::Integer(42);
        let json = serde_json::to_string(&av).unwrap();
        assert_eq!(json, "42");

        let av2 = AttributeValue::StringList(vec!["a".into(), "b".into()]);
        let json2 = serde_json::to_string(&av2).unwrap();
        assert!(json2.contains("\"a\""));
    }
}
