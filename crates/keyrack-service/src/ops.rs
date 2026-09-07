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
use keyrack_core::audit::{AuditAction, AuditEvent, AuditPrincipal, AuditResource, AuditResult};
use keyrack_core::pdp::{
    AuthzRequest, Decision, Principal, RequestContext, Resource, PDP_API_VERSION,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

/// Generate a new request ID (`UUIDv7` for monotonic time-ordering).
pub fn new_request_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Extract x-request-id from gRPC metadata, falling back to a generated `UUIDv7`.
pub fn extract_request_id_grpc<T>(request: &tonic::Request<T>) -> String {
    request
        .metadata()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map_or_else(new_request_id, ToOwned::to_owned)
}

/// Extract x-request-id from HTTP headers, falling back to a generated `UUIDv7`.
pub fn extract_request_id_rest(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map_or_else(new_request_id, ToOwned::to_owned)
}

/// Extension type inserted into tonic requests by the TLS interceptor
/// when mTLS client certificates are available. Each entry is a DER-encoded cert.
#[derive(Debug, Clone)]
pub struct PeerCertificates(pub Vec<Vec<u8>>);

/// Describes a pending operation for PDP + audit purposes.
#[derive(Clone)]
pub struct OpContext {
    pub action: AuditAction,
    pub principal: Principal,
    pub resource_id: String,
    pub resource_type: String,
    pub encryption_context_hash: Option<[u8; 32]>,
    /// Propagated x-request-id for end-to-end correlation across services.
    pub request_id: String,
    // A second key is mandatory for ReEncrypt. Keep the binding private so a
    // generic single-resource context cannot accidentally authorize the pair.
    re_encrypt_destination: Option<String>,
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
            re_encrypt_destination: None,
        }
    }

    /// Re-encryption-only delegation requires `kms:ReEncrypt` on BOTH keys;
    /// it does not imply permission to retrieve plaintext through `Decrypt`.
    pub fn re_encrypt(principal: Principal, source: &str, destination: &str) -> Self {
        let mut ctx = Self::key(AuditAction::ReEncrypt, principal, source);
        ctx.re_encrypt_destination = Some(destination.to_owned());
        ctx
    }

    pub fn alias(action: AuditAction, principal: Principal, alias_name: &str) -> Self {
        Self {
            action,
            principal,
            resource_id: alias_name.to_owned(),
            resource_type: "Alias".into(),
            encryption_context_hash: None,
            request_id: new_request_id(),
            re_encrypt_destination: None,
        }
    }

    pub fn resource(
        action: AuditAction,
        principal: Principal,
        resource_id: &str,
        resource_type: &str,
    ) -> Self {
        Self {
            action,
            principal,
            resource_id: resource_id.to_owned(),
            resource_type: resource_type.to_owned(),
            encryption_context_hash: None,
            request_id: new_request_id(),
            re_encrypt_destination: None,
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
            re_encrypt_destination: None,
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
// tonic::Status is the public gRPC error type; boxing it would only move the
// allocation into every call site.
#[allow(clippy::result_large_err)]
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
        emit_authorization_failure(state, &ctx, denied.code()).await;
        record_authorization_failure(&ctx, denied.code(), start);
        return Err(denied);
    }

    let result = op(Arc::clone(state)).await;

    let (audit_result, result_str) = if result.is_ok() {
        (AuditResult::Success, "success")
    } else {
        (AuditResult::Error, "error")
    };
    emit_audit(state, &ctx, audit_result, None, None).await;
    crate::metrics::record_op(&ctx.action.to_string(), result_str, start.elapsed());

    result
}

async fn emit_audit(
    state: &Arc<ServiceState>,
    ctx: &OpContext,
    result: AuditResult,
    event_type_override: Option<keyrack_core::audit::EventType>,
    authorization_status: Option<tonic::Code>,
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

    if let Some(code) = authorization_status {
        event.add_metadata("failure_phase", "authorization");
        event.add_metadata("authorization_status", format!("{code:?}"));
    }

    let tenant = ctx
        .principal
        .attributes
        .get("tenant_id")
        .or_else(|| ctx.principal.attributes.get("domain_id"))
        .and_then(|v| match v {
            keyrack_core::pdp::AttributeValue::String(s) => Some(s.clone()),
            _ => None,
        });
    let project = ctx
        .principal
        .attributes
        .get("project_id")
        .and_then(|v| match v {
            keyrack_core::pdp::AttributeValue::String(s) => Some(s.clone()),
            _ => None,
        });
    if tenant.is_some() || project.is_some() {
        event = event.with_context(tenant, project, None);
    }

    if let Some(hash) = ctx.encryption_context_hash {
        event = event.with_encryption_context_hash(hash);
    }
    if let Err(e) = state.audit.emit(&event).await {
        tracing::error!(error = %e, event_id = %event.event_id, "failed to emit audit event");
        crate::metrics::record_audit_error();
    }
}

#[allow(clippy::result_large_err)]
async fn authorize(state: &Arc<ServiceState>, ctx: &OpContext) -> Result<(), tonic::Status> {
    for (index, request) in authorization_requests(ctx)?.iter().enumerate() {
        if let Err(error) = authorize_request(state, request).await {
            if index == 1 {
                // The executor also records the overall source operation as
                // denied. Name the refused destination explicitly, without
                // inventing a successful standalone Encrypt operation.
                let mut denied = OpContext::key(
                    AuditAction::ReEncrypt,
                    ctx.principal.clone(),
                    &request.resource.id,
                );
                denied.request_id.clone_from(&ctx.request_id);
                denied.encryption_context_hash = ctx.encryption_context_hash;
                emit_authorization_failure(state, &denied, error.code()).await;
            }
            return Err(error);
        }
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn authorization_requests(ctx: &OpContext) -> Result<Vec<AuthzRequest>, tonic::Status> {
    let request = AuthzRequest {
        pdp_api_version: PDP_API_VERSION.into(),
        request_id: ctx.request_id.clone(),
        action: ctx.action.clone(),
        principal: ctx.principal.clone(),
        resource: Resource {
            id: ctx.resource_id.clone(),
            resource_type: ctx.resource_type.clone(),
            attributes: std::collections::BTreeMap::default(),
        },
        context: RequestContext::default(),
    };
    if ctx.action != AuditAction::ReEncrypt {
        if ctx.re_encrypt_destination.is_some() {
            return Err(tonic::Status::internal(
                "invalid two-key authorization context",
            ));
        }
        return Ok(vec![request]);
    }
    let destination = ctx.re_encrypt_destination.as_deref().ok_or_else(|| {
        tonic::Status::internal("ReEncrypt requires a bound destination authorization")
    })?;
    Ok([
        ("source", ctx.resource_id.as_str()),
        ("destination", destination),
    ]
    .into_iter()
    .map(|(role, key_id)| {
        let mut leg = request.clone();
        // These are different PDP questions, even for a same-key rewrap.
        // Reusing the operation ID would accept a source response for the
        // destination. Keep the outer ID solely as correlation context.
        leg.request_id = new_request_id();
        key_id.clone_into(&mut leg.resource.id);
        for (name, value) in [
            ("operation_request_id", ctx.request_id.as_str()),
            ("re_encrypt_role", role),
            ("source_key_id", ctx.resource_id.as_str()),
            ("destination_key_id", destination),
        ] {
            leg.context.entries.insert(
                name.into(),
                keyrack_core::pdp::AttributeValue::String(value.into()),
            );
        }
        leg
    })
    .collect())
}

#[allow(clippy::result_large_err)]
async fn authorize_request(
    state: &Arc<ServiceState>,
    request: &AuthzRequest,
) -> Result<(), tonic::Status> {
    let pdp_start = Instant::now();
    let response = state
        .pdp
        .evaluate(request)
        .await
        .and_then(|response| {
            // Enforce the response contract for injected/in-process PDPs too, not
            // only the HTTP/gRPC adapters. This operation must not accept a source
            // Permit substituted as its independently requested destination Permit.
            response.into_enforceable(request)
        })
        .map_err(|e| {
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
            let reasons: String = response
                .reasons
                .iter()
                .map(|r| {
                    r.human_message
                        .as_deref()
                        .or(r.reason_code.as_deref())
                        .unwrap_or(&r.policy_id)
                })
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
    Fut: std::future::Future<
        Output = Result<T, (axum::http::StatusCode, axum::Json<serde_json::Value>)>,
    >,
{
    let start = Instant::now();
    tracing::debug!(request_id = %ctx.request_id, action = %ctx.action, resource = %ctx.resource_id, "op.start");

    if let Err(denied) = authorize_rest(state, &ctx).await {
        let code = if denied.0 == axum::http::StatusCode::FORBIDDEN {
            tonic::Code::PermissionDenied
        } else {
            tonic::Code::Internal
        };
        emit_authorization_failure(state, &ctx, code).await;
        record_authorization_failure(&ctx, code, start);
        return Err(denied);
    }

    let result = op(Arc::clone(state)).await;

    let (audit_result, result_str) = if result.is_ok() {
        (AuditResult::Success, "success")
    } else {
        (AuditResult::Error, "error")
    };
    emit_audit(state, &ctx, audit_result, None, None).await;
    crate::metrics::record_op(&ctx.action.to_string(), result_str, start.elapsed());

    result
}

async fn authorize_rest(
    state: &Arc<ServiceState>,
    ctx: &OpContext,
) -> Result<(), (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    authorize(state, ctx).await.map_err(|error| {
        if error.code() == tonic::Code::PermissionDenied {
            rest_error(
                axum::http::StatusCode::FORBIDDEN,
                "AuthorizationDenied",
                error.message(),
            )
        } else {
            rest_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "PdpUnavailable",
                error.message(),
            )
        }
    })
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
        AuditAction::CreateKey | AuditAction::ImportKeyMaterial => EventType::KeyCreated,
        AuditAction::RotateKey => EventType::KeyRotated,
        AuditAction::EnableKey
        | AuditAction::DisableKey
        | AuditAction::ScheduleKeyDeletion
        | AuditAction::CancelKeyDeletion
        | AuditAction::UpdateKey => EventType::KeyStateChanged,
        AuditAction::ReportKeyCompromise => EventType::KeyCompromised,

        AuditAction::GetKey
        | AuditAction::DescribeKey
        | AuditAction::ListKeys
        | AuditAction::ListKeyVersions
        | AuditAction::GetKeyVersion
        | AuditAction::GetKeyDependents
        | AuditAction::GetKeyAncestors
        | AuditAction::GetKeyRotationStatus
        | AuditAction::GetKeyRotationHistory
        | AuditAction::GetKeyRotationPolicy => EventType::KeyRead,

        AuditAction::Encrypt
        | AuditAction::Decrypt
        | AuditAction::Sign
        | AuditAction::Verify
        | AuditAction::GenerateMac
        | AuditAction::VerifyMac
        | AuditAction::GenerateRandom
        | AuditAction::GenerateDataKey
        | AuditAction::GenerateDataKeyWithoutPlaintext
        | AuditAction::ReEncrypt => EventType::CryptoOperation,

        AuditAction::TagResource | AuditAction::UntagResource | AuditAction::ListResourceTags => {
            EventType::TagMutation
        }
        AuditAction::CreateAlias | AuditAction::DeleteAlias | AuditAction::ListAliases => {
            EventType::AliasMutation
        }

        AuditAction::CreateHsmConnection
        | AuditAction::DeleteHsmConnection
        | AuditAction::GetHsmConnection
        | AuditAction::ListHsmConnections
        | AuditAction::GetHsmConnectionStatus => EventType::HsmConnectionMutation,

        AuditAction::EnableKeyRotation
        | AuditAction::DisableKeyRotation
        | AuditAction::SetKeyRotationPolicy => EventType::RotationPolicyChanged,

        AuditAction::ListRotationJobs
        | AuditAction::AcknowledgeRotationJob
        | AuditAction::CompleteRotationJob
        | AuditAction::FailRotationJob
        | AuditAction::RotationJobExpired => EventType::RotationJobStateChanged,

        AuditAction::RegisterNamespace
        | AuditAction::ListNamespaces
        | AuditAction::DescribeNamespace => EventType::NamespaceOperation,

        AuditAction::CascadeDisable => EventType::CascadeDisable,
        AuditAction::KeyDestroyed | AuditAction::ProviderDestroyKey => EventType::KeyDeleted,
        AuditAction::AccessSecret | AuditAction::GetKeyMaterial => EventType::SecretAccess,
        AuditAction::ScopeOwnerCheck => EventType::ScopeOwnerCheck,
        AuditAction::MakeKeyExportable | AuditAction::RevokeKeyExportability => {
            EventType::KeyStateChanged
        }
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

/// Authorize with explicit resource attributes (for exportable-key operations
/// that populate `exportable`/`exported` on the PDP resource). Returns
/// `Err(tonic::Status)` on deny/indeterminate.
#[allow(clippy::result_large_err)]
pub async fn authorize_with_resource_attrs(
    state: &Arc<ServiceState>,
    ctx: &OpContext,
    resource_attrs: BTreeMap<String, keyrack_core::pdp::AttributeValue>,
) -> Result<(), tonic::Status> {
    // This helper authorizes one resource. ReEncrypt must go through the
    // two-key executor; neither a generic nor bound context can bypass it here.
    if ctx.action == AuditAction::ReEncrypt || ctx.re_encrypt_destination.is_some() {
        return Err(tonic::Status::internal(
            "ReEncrypt requires the two-key executor",
        ));
    }
    let request = AuthzRequest {
        pdp_api_version: PDP_API_VERSION.into(),
        request_id: ctx.request_id.clone(),
        action: ctx.action.clone(),
        principal: ctx.principal.clone(),
        resource: Resource {
            id: ctx.resource_id.clone(),
            resource_type: ctx.resource_type.clone(),
            attributes: resource_attrs,
        },
        context: RequestContext::default(),
    };
    authorize_request(state, &request).await
}

/// Emit an authorization-denied audit event (used by double-gate flows where
/// a secondary authorization check happens inside an already-authorized operation).
pub async fn emit_audit_denied(state: &Arc<ServiceState>, ctx: &OpContext) {
    emit_authorization_failure(state, ctx, tonic::Code::PermissionDenied).await;
}

fn record_authorization_failure(ctx: &OpContext, code: tonic::Code, start: Instant) {
    let outcome = if code == tonic::Code::PermissionDenied {
        "denied"
    } else {
        "error"
    };
    crate::metrics::record_op(&ctx.action.to_string(), outcome, start.elapsed());
}

async fn emit_authorization_failure(state: &Arc<ServiceState>, ctx: &OpContext, code: tonic::Code) {
    let (result, kind) = if code == tonic::Code::PermissionDenied {
        (
            AuditResult::Denied,
            Some(keyrack_core::audit::EventType::AuthorizationDenied),
        )
    } else {
        // An unavailable PDP or invalid response is not a policy decision.
        (AuditResult::Error, None)
    };
    emit_audit(state, ctx, result, kind, Some(code)).await;
}

/// PDP + audit envelope with resource-attribute enrichment. Used by
/// exportable-key operations that must populate `Resource.attributes`.
#[allow(clippy::result_large_err)]
pub async fn execute_with_resource_attrs<F, Fut, T>(
    state: &Arc<ServiceState>,
    ctx: OpContext,
    resource_attrs: BTreeMap<String, keyrack_core::pdp::AttributeValue>,
    op: F,
) -> Result<T, tonic::Status>
where
    F: FnOnce(Arc<ServiceState>) -> Fut,
    Fut: std::future::Future<Output = Result<T, tonic::Status>>,
{
    let start = Instant::now();
    tracing::debug!(request_id = %ctx.request_id, action = %ctx.action, resource = %ctx.resource_id, "op.start");

    if let Err(denied) = authorize_with_resource_attrs(state, &ctx, resource_attrs).await {
        emit_authorization_failure(state, &ctx, denied.code()).await;
        record_authorization_failure(&ctx, denied.code(), start);
        return Err(denied);
    }

    let result = op(Arc::clone(state)).await;

    let (audit_result, result_str) = if result.is_ok() {
        (AuditResult::Success, "success")
    } else {
        (AuditResult::Error, "error")
    };
    emit_audit(state, &ctx, audit_result, None, None).await;
    crate::metrics::record_op(&ctx.action.to_string(), result_str, start.elapsed());

    result
}

/// Extract the authenticated principal from a tonic gRPC request.
///
/// Reads standard headers (`authorization`) plus the mTLS peer certificate
/// chain, and runs them through the configured authenticator chain.
///
/// **Fails closed:** if the configured authenticators recognise no valid
/// credential, the request is rejected with `Unauthenticated` rather than
/// downgraded to an anonymous principal. The insecure authenticator never
/// errors, so dev/test deployments (no real authn) are unaffected.
#[allow(clippy::result_large_err)]
pub async fn extract_principal_grpc<T>(
    state: &Arc<ServiceState>,
    request: &tonic::Request<T>,
) -> Result<Principal, tonic::Status> {
    use keyrack_core::authn::RequestMetadata;

    let mut meta = RequestMetadata::default();
    for key_and_value in request.metadata().iter() {
        if let tonic::metadata::KeyAndValueRef::Ascii(key, value) = key_and_value {
            if let Ok(v) = value.to_str() {
                meta.headers.insert(key.as_str().to_owned(), v.to_owned());
            }
        }
    }

    // Peer certificates for mTLS identity. Tests may inject them directly via a
    // `PeerCertificates` request extension; in production they come from the TLS
    // connection (tonic populates peer certs when serving with a client CA).
    if let Some(certs) = request.extensions().get::<PeerCertificates>() {
        meta.peer_certificates.clone_from(&certs.0);
    } else if let Some(certs) = request.peer_certs() {
        meta.peer_certificates = certs.iter().map(|c| c.as_ref().to_vec()).collect();
    }

    match state.authn.authenticate(&meta).await {
        Ok(result) => Ok(result.principal),
        Err(e) => {
            tracing::warn!(error = %e, "authentication failed; rejecting request");
            Err(tonic::Status::unauthenticated(format!(
                "authentication failed: {e}"
            )))
        }
    }
}

/// Extract the authenticated principal from an axum REST request.
///
/// **Fails closed:** if the configured authenticators recognise no valid
/// credential, the request is rejected with `401 Unauthenticated` rather
/// than downgraded to an anonymous principal. The insecure authenticator
/// never errors, so dev/test deployments (no real authn) are unaffected.
pub async fn extract_principal_rest(
    state: &Arc<ServiceState>,
    headers: &axum::http::HeaderMap,
) -> Result<Principal, (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    use keyrack_core::authn::RequestMetadata;

    ensure_rest_authn_transport_supported(&state.authn)?;

    let mut meta = RequestMetadata::default();
    for (key, value) in headers {
        if let Ok(v) = value.to_str() {
            meta.headers.insert(key.as_str().to_owned(), v.to_owned());
        }
    }

    match state.authn.authenticate(&meta).await {
        Ok(result) => Ok(result.principal),
        Err(e) => {
            tracing::warn!(error = %e, "REST authentication failed; rejecting request");
            Err(rest_error(
                axum::http::StatusCode::UNAUTHORIZED,
                "Unauthenticated",
                &format!("authentication failed: {e}"),
            ))
        }
    }
}

fn ensure_rest_authn_transport_supported(
    authn: &keyrack_core::authn::AuthenticatorChain,
) -> Result<(), (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    if authn.supports_requests_without_peer_certificate() {
        return Ok(());
    }

    tracing::warn!(
        "REST authentication transport unsupported; configured authenticators require a peer certificate"
    );
    Err(rest_error(
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "AuthenticationTransportUnsupported",
        "the configured authentication profile requires a client certificate exposed by the gRPC transport; use gRPC or configure a REST-capable authenticator in the chain",
    ))
}

#[cfg(test)]
mod authn_transport_tests {
    use super::ensure_rest_authn_transport_supported;
    use keyrack_core::authn::{AuthenticatorChain, BootstrapTokenAuthenticator, MtlsAuthenticator};

    #[test]
    fn rest_rejects_peer_certificate_only_chain_explicitly() {
        let chain = AuthenticatorChain::new(vec![Box::new(MtlsAuthenticator)]);

        let (status, axum::Json(body)) = ensure_rest_authn_transport_supported(&chain).unwrap_err();
        assert_eq!(status, axum::http::StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            body["error"],
            serde_json::Value::String("AuthenticationTransportUnsupported".into())
        );
    }

    #[test]
    fn rest_accepts_chain_with_token_fallback() {
        let chain = AuthenticatorChain::new(vec![
            Box::new(MtlsAuthenticator),
            Box::new(BootstrapTokenAuthenticator::new(
                "fallback-token",
                std::time::Duration::from_secs(3600),
            )),
        ]);

        ensure_rest_authn_transport_supported(&chain).unwrap();
    }
}
