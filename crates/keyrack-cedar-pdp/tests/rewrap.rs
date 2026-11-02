// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use keyrack_cedar_pdp::engine::CedarEngine;
use keyrack_core::audit::AuditAction;
use keyrack_core::pdp::{
    AuthzRequest, Decision, Principal, RequestContext, Resource, PDP_API_VERSION,
};
use std::collections::BTreeMap;

#[tokio::test]
async fn rewrap_is_an_explicit_grant_on_each_resource() {
    let engine =
        CedarEngine::new(include_str!("../../../docs/examples/rewrap.cedar"), None).unwrap();
    for (action, key, expected) in [
        (AuditAction::RewrapKey, "child-key", Decision::Permit),
        (AuditAction::RewrapKey, "old-parent", Decision::Permit),
        (AuditAction::RewrapKey, "new-parent", Decision::Permit),
        (AuditAction::RewrapKey, "other-parent", Decision::Forbid),
        (AuditAction::RotateKey, "child-key", Decision::Forbid),
        (AuditAction::Decrypt, "child-key", Decision::Forbid),
    ] {
        let request = AuthzRequest {
            pdp_api_version: PDP_API_VERSION.into(),
            request_id: "rewrap-policy".into(),
            action,
            principal: Principal::system(),
            resource: Resource {
                id: key.into(),
                resource_type: "Key".into(),
                attributes: BTreeMap::new(),
            },
            context: RequestContext::default(),
        };
        assert_eq!(
            engine
                .evaluate(&request)
                .await
                .unwrap()
                .into_enforceable(&request)
                .unwrap()
                .decision,
            expected
        );
    }
}
