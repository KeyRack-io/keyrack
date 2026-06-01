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
/// Matches the partner's `oneof AttributeValue` proposal. Avoids
/// `serde_json::Value` ambiguity for boolean/integer distinction.
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
///
/// `rate_limit_class` is expressed as an obligation
/// (`obligation_id = "rate_limit_class"`), not a top-level field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzResponse {
    pub request_id: String,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<PolicyReason>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<Obligation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
}

impl AuthzResponse {
    /// Extract `rate_limit_class` from the obligations array, if present.
    pub fn rate_limit_class(&self) -> Option<&str> {
        self.obligations.iter()
            .find(|o| o.obligation_id == "rate_limit_class")
            .and_then(|o| o.parameters.get("class"))
            .and_then(|v| match v {
                AttributeValue::String(s) => Some(s.as_str()),
                _ => None,
            })
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
