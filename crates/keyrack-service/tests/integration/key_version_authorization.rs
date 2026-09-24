// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact native-version authorization uses the decoded request, not headers.

use super::*;
use keyrack_core::audit::AuditAction;
use keyrack_core::pdp::{AttributeValue, Decision, Principal};
use keyrack_service::ops::{self, OpContext};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

struct VersionPdp {
    permitted: AtomicU32,
    requests: Mutex<Vec<AuthzRequest>>,
}

impl VersionPdp {
    fn new(permitted: u32) -> Self {
        Self {
            permitted: AtomicU32::new(permitted),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<AuthzRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl PolicyDecisionPoint for VersionPdp {
    async fn evaluate(&self, request: &AuthzRequest) -> keyrack_core::error::Result<AuthzResponse> {
        self.requests.lock().unwrap().push(request.clone());
        let mut response = AlwaysAllow.evaluate(request).await?;
        if request.action == AuditAction::GetKeyVersion
            && request.context.entries.get("key_version")
                != Some(&AttributeValue::Integer(i64::from(
                    self.permitted.load(Ordering::SeqCst),
                )))
        {
            response.decision = Decision::Forbid;
        }
        Ok(response)
    }
}

fn fixture() -> (Arc<ServiceState>, Arc<VersionPdp>, Arc<CapturingSink>) {
    let pdp = Arc::new(VersionPdp::new(1));
    let audit = Arc::new(CapturingSink::new());
    let state = build_test_state_with(pdp.clone(), audit.clone());
    (state, pdp, audit)
}

fn request(key: &str, version: u32) -> Request<proto::GetKeyVersionRequest> {
    let mut request = Request::new(proto::GetKeyVersionRequest {
        key_id: key.into(),
        version,
    });
    request
        .metadata_mut()
        .insert("x-request-id", "version-correlation".parse().unwrap());
    // A caller cannot replace the decoded version with a permitted header value.
    request
        .metadata_mut()
        .insert("x-key-version", "1".parse().unwrap());
    request
        .metadata_mut()
        .insert("key-version", "1".parse().unwrap());
    request
}

#[tokio::test]
async fn grpc_versions_are_distinct_and_preserve_native_authorization_identity() {
    let (state, pdp, audit) = fixture();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    let key = create_aes_key(&svc).await;
    svc.rotate_key(Request::new(proto::RotateKeyRequest {
        key_id: key.clone(),
    }))
    .await
    .unwrap();
    pdp.requests.lock().unwrap().clear();
    let principal = ops::extract_principal_grpc(&state, &request(&key, 1))
        .await
        .unwrap();

    let first = svc.get_key_version(request(&key, 1)).await.unwrap();
    assert_eq!(first.into_inner().version.unwrap().version, 1);
    let denied = svc.get_key_version(request(&key, 2)).await.unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    pdp.permitted.store(2, Ordering::SeqCst);
    let second = svc.get_key_version(request(&key, 2)).await.unwrap();
    assert_eq!(second.into_inner().version.unwrap().version, 2);

    let requests = pdp.requests();
    assert_eq!(requests.len(), 3);
    for (request, version) in requests.iter().zip([1_i64, 2, 2]) {
        assert_eq!(request.action, AuditAction::GetKeyVersion);
        assert_eq!(request.action.to_string(), "kms:GetKeyVersion");
        assert_eq!(request.resource.id, key);
        assert_eq!(request.resource.resource_type, "Key");
        assert_eq!(request.principal, principal);
        assert_eq!(request.request_id, "version-correlation");
        assert_eq!(
            request.context.entries,
            BTreeMap::from([("key_version".into(), AttributeValue::Integer(version))])
        );
    }
    let events = audit.events();
    assert!(events.iter().rev().take(3).all(|event| {
        event.request_id.as_deref() == Some("version-correlation")
            && event.action == AuditAction::GetKeyVersion
    }));
}

#[tokio::test]
async fn wrong_version_is_denied_before_key_parsing_or_storage_lookup() {
    let (state, pdp, _) = fixture();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);
    // Parsing or reading this key first would produce a different failure.
    let error = svc
        .get_key_version(request("not-a-native-key-id", 2))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(pdp.requests().len(), 1);
    assert_eq!(
        pdp.requests()[0].context.entries["key_version"],
        AttributeValue::Integer(2)
    );
}

#[tokio::test]
async fn denied_version_cannot_execute_the_operation() {
    let (state, pdp, _) = fixture();
    let executed = Arc::new(AtomicBool::new(false));
    let observed = executed.clone();
    let error = ops::execute(
        &state,
        OpContext::key_version(Principal::system(), "key", 2),
        move |_| async move {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(pdp.requests().len(), 1);
    assert!(!executed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn zero_or_omitted_decoded_version_cannot_use_a_header_or_fallback() {
    let (state, pdp, _) = fixture();
    let svc = keyrack_service::grpc::KeyServiceImpl::new(state);
    // An omitted proto3 uint32 is zero too; neither is a valid native version.
    for request in [
        request("not-a-native-key-id", 0),
        Request::new(proto::GetKeyVersionRequest::default()),
    ] {
        let error = svc.get_key_version(request).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
    assert!(pdp.requests().is_empty());
}

#[tokio::test]
async fn missing_or_mismatched_context_cannot_enter_any_executor() {
    let (state, pdp, _) = fixture();
    let mut wrong_action = OpContext::key_version(Principal::system(), "key", 1);
    wrong_action.action = AuditAction::GetKey;
    let mut wrong_type = OpContext::key_version(Principal::system(), "key", 1);
    wrong_type.resource_type = "Alias".into();
    for ctx in [
        OpContext::key(AuditAction::GetKeyVersion, Principal::system(), "key"),
        OpContext::alias(AuditAction::GetKeyVersion, Principal::system(), "alias"),
        OpContext::resource(
            AuditAction::GetKeyVersion,
            Principal::system(),
            "key",
            "Key",
        ),
        OpContext::system(AuditAction::GetKeyVersion, "key", "Key"),
        OpContext::key_version(Principal::system(), "key", 0),
        wrong_action,
        wrong_type,
    ] {
        let executed = Arc::new(AtomicBool::new(false));
        let observed = executed.clone();
        assert!(ops::execute(&state, ctx.clone(), move |_| async move {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .is_err());
        let observed = executed.clone();
        assert!(ops::execute_with_resource_attrs(
            &state,
            ctx.clone(),
            BTreeMap::from([("key_version".into(), AttributeValue::Integer(1))]),
            move |_| async move {
                observed.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .is_err());
        let observed = executed.clone();
        assert!(ops::execute_rest(&state, ctx, move |_| async move {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .is_err());
        assert!(!executed.load(Ordering::SeqCst));
    }
    assert!(pdp.requests().is_empty());
}

#[tokio::test]
async fn resource_attribute_authorization_keeps_the_bound_version() {
    let (state, pdp, _) = fixture();
    ops::authorize_with_resource_attrs(
        &state,
        &OpContext::key_version(Principal::system(), "key", 1),
        BTreeMap::from([("key_version".into(), AttributeValue::Integer(2))]),
    )
    .await
    .unwrap();
    let requests = pdp.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].context.entries["key_version"],
        AttributeValue::Integer(1)
    );
    assert_eq!(
        requests[0].resource.attributes["key_version"],
        AttributeValue::Integer(2)
    );
}

#[tokio::test]
async fn unversioned_constructors_keep_their_original_empty_context() {
    let (state, pdp, _) = fixture();
    for ctx in [
        OpContext::key(AuditAction::GetKey, Principal::system(), "key"),
        OpContext::key(AuditAction::ListKeyVersions, Principal::system(), "key"),
        OpContext::alias(AuditAction::ListAliases, Principal::system(), "alias"),
        OpContext::resource(
            AuditAction::DescribeNamespace,
            Principal::system(),
            "ns",
            "Namespace",
        ),
        OpContext::system(AuditAction::ListKeys, "*", "Key"),
    ] {
        ops::execute(&state, ctx, |_| async { Ok(()) })
            .await
            .unwrap();
    }
    let requests = pdp.requests();
    assert_eq!(requests.len(), 5);
    assert!(requests
        .iter()
        .all(|request| request.context.entries.is_empty()));
}

#[tokio::test]
async fn full_uint32_version_is_preserved_as_a_typed_integer() {
    let (state, pdp, _) = fixture();
    pdp.permitted.store(u32::MAX, Ordering::SeqCst);
    ops::execute(
        &state,
        OpContext::key_version(Principal::system(), "key", u32::MAX),
        |_| async { Ok(()) },
    )
    .await
    .unwrap();
    assert_eq!(
        pdp.requests()[0].context.entries["key_version"],
        AttributeValue::Integer(i64::from(u32::MAX))
    );
}
