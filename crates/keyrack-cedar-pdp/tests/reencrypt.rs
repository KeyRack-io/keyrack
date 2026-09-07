// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use keyrack_cedar_pdp::engine::CedarEngine;
use keyrack_core::audit::AuditAction;
use keyrack_core::pdp::{
    AuthzRequest, Decision, Principal, RequestContext, Resource, PDP_API_VERSION,
};
use std::collections::BTreeMap;

fn request(action: AuditAction, key: &str) -> AuthzRequest {
    AuthzRequest {
        pdp_api_version: PDP_API_VERSION.into(),
        request_id: "directional-policy-test".into(),
        action,
        principal: Principal::system(),
        resource: Resource {
            id: key.into(),
            resource_type: "Key".into(),
            attributes: BTreeMap::new(),
        },
        context: RequestContext::default(),
    }
}

#[tokio::test]
async fn real_cedar_distinguishes_direction_and_exact_resource() {
    let engine =
        CedarEngine::new(include_str!("../../../docs/examples/reencrypt.cedar"), None).unwrap();
    for (action, key, expected) in [
        (AuditAction::ReEncryptFrom, "source-key", Decision::Permit),
        (
            AuditAction::ReEncryptTo,
            "destination-key",
            Decision::Permit,
        ),
        (AuditAction::ReEncryptTo, "source-key", Decision::Forbid),
        (
            AuditAction::ReEncryptFrom,
            "destination-key",
            Decision::Forbid,
        ),
        (
            AuditAction::ReEncryptTo,
            "other-tenant-key",
            Decision::Forbid,
        ),
        (AuditAction::Decrypt, "source-key", Decision::Forbid),
        (AuditAction::Encrypt, "destination-key", Decision::Forbid),
    ] {
        let req = request(action, key);
        assert_eq!(
            engine
                .evaluate(&req)
                .await
                .unwrap()
                .into_enforceable(&req)
                .unwrap()
                .decision,
            expected
        );
    }
}

#[tokio::test]
async fn same_key_requires_both_actions_without_legacy_or_standalone_aliases() {
    for (name, from, to) in [
        ("kms:ReEncryptFrom", Decision::Permit, Decision::Forbid),
        ("kms:ReEncryptTo", Decision::Forbid, Decision::Permit),
        ("kms:ReEncrypt", Decision::Forbid, Decision::Forbid),
        ("kms:ReEncrypt*", Decision::Forbid, Decision::Forbid),
        ("kms:Decrypt", Decision::Forbid, Decision::Forbid),
        ("kms:Encrypt", Decision::Forbid, Decision::Forbid),
    ] {
        let policy = format!("permit(principal, action == KeyRack::Action::\"{name}\", resource);");
        let engine = CedarEngine::new(&policy, None).unwrap();
        for (action, expected) in [
            (AuditAction::ReEncryptFrom, from),
            (AuditAction::ReEncryptTo, to),
        ] {
            assert_eq!(
                engine
                    .evaluate(&request(action, "same-key"))
                    .await
                    .unwrap()
                    .decision,
                expected,
                "{name}"
            );
        }
    }
    let engine = CedarEngine::new(
        "permit(principal, action in [KeyRack::Action::\"kms:ReEncryptFrom\", KeyRack::Action::\"kms:ReEncryptTo\"], resource);",
        None,
    ).unwrap();
    for action in [AuditAction::ReEncryptFrom, AuditAction::ReEncryptTo] {
        assert_eq!(
            engine
                .evaluate(&request(action, "same-key"))
                .await
                .unwrap()
                .decision,
            Decision::Permit
        );
    }
}

#[tokio::test]
async fn explicit_destination_forbid_overrides_a_broad_permit() {
    let engine = CedarEngine::new(
        "permit(principal, action, resource);
         forbid(principal, action == KeyRack::Action::\"kms:ReEncryptTo\", resource == KeyRack::Resource::\"destination-key\");",
        None,
    ).unwrap();
    assert_eq!(
        engine
            .evaluate(&request(AuditAction::ReEncryptFrom, "source-key"))
            .await
            .unwrap()
            .decision,
        Decision::Permit
    );
    assert_eq!(
        engine
            .evaluate(&request(AuditAction::ReEncryptTo, "destination-key"))
            .await
            .unwrap()
            .decision,
        Decision::Forbid
    );
}
