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

//! Operation executor: the single choke-point for PDP + audit.
//!
//! Every service handler calls [`OperationExecutor::run`] instead of
//! touching storage/provider directly.  This guarantees that:
//!
//! 1. PDP authorization is checked **before** the operation executes.
//! 2. An audit event is emitted **after** the operation completes
//!    (success or failure).
//!
//! Handlers that bypass this module will not compile against the
//! integration test suite (which asserts event counts).

use crate::state::ServiceState;
use keyrack_core::audit::{
    AuditAction, AuditEvent, AuditPrincipal, AuditResource, AuditResult,
};
use keyrack_core::pdp::{AuthzRequest, Decision, Principal, RequestContext, Resource, PDP_API_VERSION};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

/// Generate a new request ID (UUIDv7 for monotonic time-ordering).
pub fn new_request_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Extract x-request-id from gRPC metadata, falling back to a generated UUIDv7.
pub fn extract_request_id_grpc<T>(request: &tonic::Request<T>) -> String {
    request
        .metadata()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(new_request_id)
}

/// Extract x-request-id from HTTP headers, falling back to a generated UUIDv7.
pub fn extract_request_id_rest(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(new_request_id)
}

/// Extension type inserted into tonic requests by the TLS interceptor
/// when mTLS client certificates are available. Each entry is a DER-encoded cert.
#[derive(Debug, Clone)]
pub struct PeerCertificates(pub Vec<Vec<u8>>);

/// Describes a pending operation for PDP + audit purposes.
pub struct OpContext {
    pub action: AuditAction,
    pub principal: Principal,
    pub resource_id: String,
    pub resource_type: String,
    pub encryption_context_hash: Option<[u8; 32]>,
    /// Propagated x-request-id for end-to-end correlation (a partner contract).
    pub request_id: String,
}

impl OpContext {
    pub fn key(action: AuditAction, principal: Principal, key_id: &str) -> Self {
        Self {
            action,
            principal,
            resource_id: key_id.to_owned(),
            resource_type: "Key".into(),
            encryption_context_hash: None,
            request_id: new_request_id(),
        }
    }

    pub fn alias(action: AuditAction, principal: Principal, alias_name: &str) -> Self {
        Self {
            action,
            principal,
            resource_id: alias_name.to_owned(),
            resource_type: "Alias".into(),
            encryption_context_hash: None,
            request_id: new_request_id(),
        }
    }

    pub fn resource(action: AuditAction, principal: Principal, resource_id: &str, resource_type: &str) -> Self {
        Self {
            action,
            principal,
            resource_id: resource_id.to_owned(),
            resource_type: resource_type.to_owned(),
            encryption_context_hash: None,
            request_id: new_request_id(),
        }
    }

    pub fn system(action: AuditAction, resource_id: &str, resource_type: &str) -> Self {
        Self {
            action,
            principal: Principal::system(),
            resource_id: resource_id.to_owned(),
            resource_type: resource_type.to_owned(),
            encryption_context_hash: None,
            request_id: new_request_id(),
        }
    }
}

/// The single entry point for authorized + audited operations.
///
/// Usage in a handler:
/// ```ignore
/// let result = execute(
///     &state,
///     OpContext::key(AuditAction::Encrypt, principal, &key_id),
///     |state| async move { /* actual work */ },
/// ).await?;
/// ```
pub async fn execute<F, Fut, T>(
    state: &Arc<ServiceState>,
    ctx: OpContext,
    op: F,
) -> Result<T, tonic::Status>
where
    F: FnOnce(Arc<ServiceState>) -> Fut,
    Fut: std::future::Future<Output = Result<T, tonic::Status>>,
{
    let start = Instant::now();
    tracing::debug!(request_id = %ctx.request_id, action = %ctx.action, resource = %ctx.resource_id, "op.start");

    if let Err(denied) = authorize(state, &ctx).await {
        emit_audit(state, &ctx, AuditResult::Denied, Some(keyrack_core::audit::EventType::AuthorizationDenied)).await;
        crate::metrics::record_op(&ctx.action.to_string(), "denied", start.elapsed());
        return Err(denied);
    }

    let result = op(Arc::clone(state)).await;

    let (audit_result, result_str) = if result.is_ok() {
        (AuditResult::Success, "success")
    } else {
        (AuditResult::Error, "error")
    };
    emit_audit(state, &ctx, audit_result, None).await;
    crate::metrics::record_op(&ctx.action.to_string(), result_str, start.elapsed());

    result
}

async fn emit_audit(
    state: &Arc<ServiceState>,
    ctx: &OpContext,
    result: AuditResult,
    event_type_override: Option<keyrack_core::audit::EventType>,
) {
    let event_type = event_type_override.unwrap_or_else(|| event_type_for_action(&ctx.action));
    let mut event = AuditEvent::new(
        event_type,
        ctx.action.clone(),
        AuditPrincipal {
            id: ctx.principal.id.clone(),
            principal_type: ctx.principal.principal_type.clone(),
        },
        AuditResource {
            id: ctx.resource_id.clone(),
            resource_type: ctx.resource_type.clone(),
        },
        result,
    )
    .with_request_id(ctx.request_id.clone());
    if let Some(hash) = ctx.encryption_context_hash {
        event = event.with_encryption_context_hash(hash);
    }
    if let Err(e) = state.audit.emit(&event).await {
        tracing::error!(error = %e, event_id = %event.event_id, "failed to emit audit event");
        crate::metrics::record_audit_error();
    }
}

async fn authorize(state: &Arc<ServiceState>, ctx: &OpContext) -> Result<(), tonic::Status> {
    let pdp_start = Instant::now();

    let request = AuthzRequest {
        pdp_api_version: PDP_API_VERSION.into(),
        request_id: ctx.request_id.clone(),
        action: ctx.action.clone(),
        principal: ctx.principal.clone(),
        resource: Resource {
            id: ctx.resource_id.clone(),
            resource_type: ctx.resource_type.clone(),
            attributes: Default::default(),
        },
        context: RequestContext::default(),
    };

    let response = state.pdp.evaluate(&request).await.map_err(|e| {
        tracing::error!(error = %e, "PDP evaluation failed");
        crate::metrics::record_pdp(pdp_start.elapsed(), false);
        tonic::Status::internal("authorization service unavailable")
    })?;

    match response.decision {
        Decision::Permit => {
            crate::metrics::record_pdp(pdp_start.elapsed(), true);
            Ok(())
        }
        Decision::Forbid | Decision::Indeterminate => {
            crate::metrics::record_pdp(pdp_start.elapsed(), true);
            let reasons: String = response.reasons.iter()
                .map(|r| r.human_message.as_deref().or(r.reason_code.as_deref()).unwrap_or(&r.policy_id))
                .collect::<Vec<_>>()
                .join("; ");
            Err(tonic::Status::permission_denied(format!(
                "authorization denied: {reasons}"
            )))
        }
    }
}

/// REST-side execute: same PDP + audit guarantees but uses Axum's
/// error type instead of `tonic::Status`.
pub async fn execute_rest<F, Fut, T>(
    state: &Arc<ServiceState>,
    ctx: OpContext,
    op: F,
) -> Result<T, (axum::http::StatusCode, axum::Json<serde_json::Value>)>
where
    F: FnOnce(Arc<ServiceState>) -> Fut,
    Fut: std::future::Future<Output = Result<T, (axum::http::StatusCode, axum::Json<serde_json::Value>)>>,
{
    let start = Instant::now();
    tracing::debug!(request_id = %ctx.request_id, action = %ctx.action, resource = %ctx.resource_id, "op.start");

    if let Err(denied) = authorize_rest(state, &ctx).await {
        emit_audit(state, &ctx, AuditResult::Denied, Some(keyrack_core::audit::EventType::AuthorizationDenied)).await;
        crate::metrics::record_op(&ctx.action.to_string(), "denied", start.elapsed());
        return Err(denied);
    }

    let result = op(Arc::clone(state)).await;

    let (audit_result, result_str) = if result.is_ok() {
        (AuditResult::Success, "success")
    } else {
        (AuditResult::Error, "error")
    };
    emit_audit(state, &ctx, audit_result, None).await;
    crate::metrics::record_op(&ctx.action.to_string(), result_str, start.elapsed());

    result
}

async fn authorize_rest(
    state: &Arc<ServiceState>,
    ctx: &OpContext,
) -> Result<(), (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    let pdp_start = Instant::now();

    let request = AuthzRequest {
        pdp_api_version: PDP_API_VERSION.into(),
        request_id: ctx.request_id.clone(),
        action: ctx.action.clone(),
        principal: ctx.principal.clone(),
        resource: Resource {
            id: ctx.resource_id.clone(),
            resource_type: ctx.resource_type.clone(),
            attributes: Default::default(),
        },
        context: RequestContext::default(),
    };

    let response = state.pdp.evaluate(&request).await.map_err(|e| {
        tracing::error!(error = %e, "PDP evaluation failed");
        crate::metrics::record_pdp(pdp_start.elapsed(), false);
        rest_error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "PdpUnavailable",
            "authorization service unavailable",
        )
    })?;

    match response.decision {
        Decision::Permit => {
            crate::metrics::record_pdp(pdp_start.elapsed(), true);
            Ok(())
        }
        Decision::Forbid | Decision::Indeterminate => {
            crate::metrics::record_pdp(pdp_start.elapsed(), true);
            let reasons: String = response.reasons.iter()
                .map(|r| r.human_message.as_deref().or(r.reason_code.as_deref()).unwrap_or(&r.policy_id))
                .collect::<Vec<_>>()
                .join("; ");
            Err(rest_error(
                axum::http::StatusCode::FORBIDDEN,
                "AuthorizationDenied",
                &format!("authorization denied: {reasons}"),
            ))
        }
    }
}

pub fn rest_error(
    code: axum::http::StatusCode,
    error: &str,
    message: &str,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    (
        code,
        axum::Json(serde_json::json!({ "error": error, "message": message })),
    )
}

fn event_type_for_action(action: &AuditAction) -> keyrack_core::audit::EventType {
    use keyrack_core::audit::EventType;
    match action {
        AuditAction::CreateKey => EventType::KeyCreated,
        AuditAction::RotateKey => EventType::KeyRotated,
        AuditAction::EnableKey | AuditAction::DisableKey => EventType::KeyStateChanged,
        AuditAction::ScheduleKeyDeletion | AuditAction::CancelKeyDeletion => EventType::KeyStateChanged,
        AuditAction::UpdateKey => EventType::KeyStateChanged,

        AuditAction::GetKey | AuditAction::DescribeKey | AuditAction::ListKeys
        | AuditAction::ListKeyVersions | AuditAction::GetKeyVersion
        | AuditAction::GetKeyDependents | AuditAction::GetKeyAncestors
        | AuditAction::GetKeyRotationStatus | AuditAction::GetKeyRotationHistory
        | AuditAction::GetKeyRotationPolicy => EventType::KeyRead,

        AuditAction::Encrypt | AuditAction::Decrypt | AuditAction::Sign | AuditAction::Verify
        | AuditAction::GenerateRandom | AuditAction::GenerateDataKey
        | AuditAction::GenerateDataKeyWithoutPlaintext | AuditAction::ReEncrypt => EventType::CryptoOperation,

        AuditAction::TagResource | AuditAction::UntagResource | AuditAction::ListResourceTags => EventType::TagMutation,
        AuditAction::CreateAlias | AuditAction::DeleteAlias | AuditAction::ListAliases => EventType::AliasMutation,

        AuditAction::CreateHsmConnection | AuditAction::DeleteHsmConnection
        | AuditAction::GetHsmConnection | AuditAction::ListHsmConnections
        | AuditAction::GetHsmConnectionStatus => EventType::HsmConnectionMutation,

        AuditAction::EnableKeyRotation | AuditAction::DisableKeyRotation
        | AuditAction::SetKeyRotationPolicy => EventType::RotationPolicyChanged,

        AuditAction::ListRotationJobs | AuditAction::AcknowledgeRotationJob
        | AuditAction::CompleteRotationJob | AuditAction::FailRotationJob => EventType::RotationJobStateChanged,

        AuditAction::RegisterNamespace | AuditAction::ListNamespaces
        | AuditAction::DescribeNamespace => EventType::NamespaceOperation,

        AuditAction::CascadeDisable => EventType::CascadeDisable,
        AuditAction::RotationJobExpired => EventType::RotationJobStateChanged,
        AuditAction::KeyDestroyed => EventType::KeyDeleted,
    }
}

/// Convenience: the default principal used when authentication is not
/// configured or as a fallback.
pub fn default_principal() -> Principal {
    Principal {
        id: "keyrack:anonymous".into(),
        principal_type: "Service".into(),
        attributes: BTreeMap::new(),
    }
}

/// Extract the authenticated principal from a tonic gRPC request.
///
/// Reads standard headers (`authorization`, plus peer certs if available)
/// and runs them through the configured authenticator chain.
pub async fn extract_principal_grpc<T>(
    state: &Arc<ServiceState>,
    request: &tonic::Request<T>,
) -> Principal {
    use keyrack_core::authn::RequestMetadata;

    let mut meta = RequestMetadata::default();
    for key_and_value in request.metadata().iter() {
        if let tonic::metadata::KeyAndValueRef::Ascii(key, value) = key_and_value {
            if let Ok(v) = value.to_str() {
                meta.headers.insert(key.as_str().to_owned(), v.to_owned());
            }
        }
    }

    if let Some(certs) = request.extensions().get::<PeerCertificates>() {
        meta.peer_certificates.clone_from(&certs.0);
    }

    match state.authn.authenticate(&meta).await {
        Ok(result) => result.principal,
        Err(e) => {
            tracing::warn!(error = %e, "authentication failed, using default principal");
            default_principal()
        }
    }
}

/// Extract the authenticated principal from an axum REST request.
pub async fn extract_principal_rest(
    state: &Arc<ServiceState>,
    headers: &axum::http::HeaderMap,
) -> Principal {
    use keyrack_core::authn::RequestMetadata;

    let mut meta = RequestMetadata::default();
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            meta.headers.insert(key.as_str().to_owned(), v.to_owned());
        }
    }

    match state.authn.authenticate(&meta).await {
        Ok(result) => result.principal,
        Err(e) => {
            tracing::warn!(error = %e, "authentication failed, using default principal");
            default_principal()
        }
    }
}
