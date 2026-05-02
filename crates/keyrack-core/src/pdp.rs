// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Change Date: 2030-01-01
// Change License: Apache License, Version 2.0

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

/// Authorization request sent to the PDP.
///
/// Top-level shape is stable (§8.1):
/// `{ request_id, action, principal, resource, context }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzRequest {
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
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// Request-scoped context (non-resource, non-principal data).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestContext {
    /// Free-form context pairs visible to the PDP.
    #[serde(flatten)]
    pub entries: BTreeMap<String, serde_json::Value>,
}

/// Authorization response from the PDP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzResponse {
    pub request_id: String,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
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
            reasons: vec!["policy: always deny".into()],
            policy_version: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authz_request_serialization() {
        let req = AuthzRequest {
            request_id: "req-001".into(),
            action: AuditAction::Encrypt,
            principal: Principal {
                id: "user:alice".into(),
                principal_type: "User".into(),
            },
            resource: Resource {
                id: "lid_abc".into(),
                resource_type: "Key".into(),
                attributes: BTreeMap::new(),
            },
            context: RequestContext::default(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let parsed: AuthzRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.request_id, "req-001");
        assert_eq!(parsed.action, AuditAction::Encrypt);
    }

    #[test]
    fn system_principal() {
        let p = Principal::system();
        assert_eq!(p.id, "keyrack:system");
        assert_eq!(p.principal_type, "System");
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
        let req = AuthzRequest {
            request_id: "r1".into(),
            action: AuditAction::Decrypt,
            principal: Principal::system(),
            resource: Resource {
                id: "lid_x".into(),
                resource_type: "Key".into(),
                attributes: BTreeMap::new(),
            },
            context: RequestContext::default(),
        };
        let resp = pdp.evaluate(&req).await.unwrap();
        assert!(resp.decision.is_permit());
    }

    #[tokio::test]
    async fn always_deny_forbids() {
        let pdp = AlwaysDeny;
        let req = AuthzRequest {
            request_id: "r2".into(),
            action: AuditAction::CreateKey,
            principal: Principal {
                id: "user:bob".into(),
                principal_type: "User".into(),
            },
            resource: Resource {
                id: "lid_y".into(),
                resource_type: "Key".into(),
                attributes: BTreeMap::new(),
            },
            context: RequestContext::default(),
        };
        let resp = pdp.evaluate(&req).await.unwrap();
        assert_eq!(resp.decision, Decision::Forbid);
        assert!(!resp.reasons.is_empty());
    }

    #[test]
    fn resource_attributes_included() {
        let mut attrs = BTreeMap::new();
        attrs.insert("tenant".into(), serde_json::Value::String("globex".into()));

        let resource = Resource {
            id: "lid_z".into(),
            resource_type: "Key".into(),
            attributes: attrs,
        };

        let json = serde_json::to_string(&resource).unwrap();
        assert!(json.contains("globex"));
    }
}
