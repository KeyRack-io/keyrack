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

//! Domain service layer: protocol-agnostic business logic.
//!
//! Both gRPC and REST handlers delegate to functions in this module.
//! This eliminates behavioral divergence between the two API surfaces
//! (Issue 3 / Option A from the project conclusion plan).
//!
//! ## Provider resolution precedence (ADR-0001 Amendment 1)
//!
//! 1. Evaluate routing rules against identity tags (first match wins).
//! 2. Route pin — authoritative; caller `backend_id` must match or be absent.
//! 3. Delegate — caller may select within bounded set (or any with `delegate *`).
//! 4. Default (no rule matched): if routing rules configured → default-deny
//!    caller selection; if no rules → backward-compat (caller selects freely).
//!
//! ## Scope-owner enforcement
//!
//! `check_scope_owner` / `enforce_scope_for_key_op` enforce tenant isolation
//! on the shared path (both gRPC and REST). The check targets the effective
//! per-version binding so migrated keys are checked against the correct backend.
//!
//! Functions here are called *inside* [`ops::execute`] /
//! [`ops::execute_rest`] closures, so PDP authorization and audit
//! emission remain structurally guaranteed by the ops layer.

use crate::state::ServiceState;
use keyrack_core::key::{KeyRecord, KeySpec, KeyState, KeyUsage, KeyVersionRecord};
use keyrack_core::lid::Lid;
use keyrack_core::storage::{KeyFilter, Page};
use std::collections::HashSet;
use std::sync::Arc;

// ── Error type ──────────────────────────────────────────────────────

/// Protocol-agnostic error produced by domain functions.
///
/// Handlers map this to `tonic::Status` (gRPC) or
/// `(StatusCode, Json<Value>)` (REST) via the conversion methods.
#[derive(Debug)]
pub enum DomainError {
    NotFound(String),
    InvalidArgument(String),
    FailedPrecondition(String),
    PermissionDenied(String),
    ProviderUnavailable(String),
    Internal(String),
    Core(keyrack_core::error::KeyRackError),
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::FailedPrecondition(msg) => write!(f, "failed precondition: {msg}"),
            Self::PermissionDenied(msg) => write!(f, "permission denied: {msg}"),
            Self::ProviderUnavailable(msg) => write!(f, "provider unavailable: {msg}"),
            Self::Internal(msg) => write!(f, "internal: {msg}"),
            Self::Core(e) => write!(f, "{e}"),
        }
    }
}

impl From<keyrack_core::error::KeyRackError> for DomainError {
    fn from(e: keyrack_core::error::KeyRackError) -> Self {
        use keyrack_core::error::KeyRackError;
        match &e {
            KeyRackError::KeyNotFound(_) => Self::NotFound(e.to_string()),
            KeyRackError::Storage(msg) if msg.contains("not found") => {
                Self::NotFound(e.to_string())
            }
            KeyRackError::InvalidStateTransition { .. }
            | KeyRackError::OperationNotPermitted { .. } => Self::FailedPrecondition(e.to_string()),
            KeyRackError::ImmutableTag { .. }
            | KeyRackError::EncryptionContextMismatch
            | KeyRackError::DepthLimitExceeded { .. }
            | KeyRackError::CycleDetected { .. } => Self::InvalidArgument(e.to_string()),
            KeyRackError::ProviderUnavailable(_) => Self::ProviderUnavailable(e.to_string()),
            _ => Self::Internal(e.to_string()),
        }
    }
}

impl DomainError {
    pub fn to_grpc_status(&self) -> tonic::Status {
        match self {
            Self::NotFound(msg) => tonic::Status::not_found(msg),
            Self::InvalidArgument(msg) => tonic::Status::invalid_argument(msg),
            Self::FailedPrecondition(msg) => tonic::Status::failed_precondition(msg),
            Self::PermissionDenied(msg) => tonic::Status::permission_denied(msg),
            Self::ProviderUnavailable(msg) => tonic::Status::unavailable(msg),
            Self::Internal(msg) => tonic::Status::internal(msg),
            Self::Core(e) => {
                use keyrack_core::error::KeyRackError;
                let msg = e.to_string();
                match e {
                    KeyRackError::KeyNotFound(_) => tonic::Status::not_found(msg),
                    KeyRackError::OptimisticConcurrencyConflict { .. } => {
                        tonic::Status::aborted(msg)
                    }
                    KeyRackError::InvalidStateTransition { .. }
                    | KeyRackError::OperationNotPermitted { .. }
                    | KeyRackError::ImmutableTag { .. }
                    | KeyRackError::DepthLimitExceeded { .. }
                    | KeyRackError::CycleDetected { .. } => tonic::Status::failed_precondition(msg),
                    KeyRackError::EncryptionContextMismatch => tonic::Status::invalid_argument(msg),
                    KeyRackError::AuthorizationDenied { .. } => {
                        tonic::Status::permission_denied(msg)
                    }
                    KeyRackError::ProviderUnavailable(_) => tonic::Status::unavailable(msg),
                    _ => tonic::Status::internal(msg),
                }
            }
        }
    }

    pub fn to_rest_error(&self) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
        use axum::http::StatusCode;
        let (code, kind) = match self {
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "NotFound"),
            Self::InvalidArgument(_) => (StatusCode::BAD_REQUEST, "InvalidArgument"),
            Self::FailedPrecondition(_) => (StatusCode::CONFLICT, "FailedPrecondition"),
            Self::PermissionDenied(_) => (StatusCode::FORBIDDEN, "PermissionDenied"),
            Self::ProviderUnavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "ProviderUnavailable")
            }
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
            Self::Core(e) => {
                use keyrack_core::error::KeyRackError;
                match e {
                    KeyRackError::KeyNotFound(_) => (StatusCode::NOT_FOUND, "KeyNotFound"),
                    KeyRackError::OptimisticConcurrencyConflict { .. } => {
                        (StatusCode::CONFLICT, "OccConflict")
                    }
                    KeyRackError::InvalidStateTransition { .. } => {
                        (StatusCode::CONFLICT, "InvalidStateTransition")
                    }
                    KeyRackError::OperationNotPermitted { .. } => {
                        (StatusCode::FORBIDDEN, "OperationNotPermitted")
                    }
                    KeyRackError::ImmutableTag { .. } => (StatusCode::BAD_REQUEST, "ImmutableTag"),
                    KeyRackError::EncryptionContextMismatch => {
                        (StatusCode::BAD_REQUEST, "EncryptionContextMismatch")
                    }
                    KeyRackError::AuthorizationDenied { .. } => {
                        (StatusCode::FORBIDDEN, "AuthorizationDenied")
                    }
                    KeyRackError::ProviderUnavailable(_) => {
                        (StatusCode::SERVICE_UNAVAILABLE, "ProviderUnavailable")
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                }
            }
        };
        crate::ops::rest_error(code, kind, &self.to_string())
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn parse_lid(s: &str) -> Result<Lid, DomainError> {
    s.parse()
        .map_err(|_| DomainError::InvalidArgument(format!("invalid key_id: {s}")))
}

fn transition_err(from: KeyState, to: KeyState) -> DomainError {
    DomainError::FailedPrecondition(format!("cannot transition from {from} to {to}"))
}

/// Generate a unique LID seeded with caller-supplied identity attributes.
/// The random `_keyrack_key_id` guarantees a distinct LID per call even when
/// attributes repeat (keys stay unique/opaque); the caller attributes enrich
/// `identity_tags` so routing rules can match on them.
pub fn generate_key_lid_from_attrs(
    caller_attrs: std::collections::BTreeMap<String, String>,
) -> (Lid, keyrack_core::attr::AttributeSet) {
    let mut attrs = keyrack_core::attr::AttributeSet::new();
    for (k, v) in caller_attrs {
        attrs.insert(&k, keyrack_core::attr::AttributeValue::String(v));
    }
    attrs.insert(
        "_keyrack_key_id",
        keyrack_core::attr::AttributeValue::String(uuid::Uuid::new_v4().to_string()),
    );
    let canonical =
        keyrack_core::canon::canonicalize(keyrack_core::canon::CanonicalizationVersion::V1, &attrs);
    let lid = Lid::derive(keyrack_core::canon::CanonicalizationVersion::V1, &canonical);
    (lid, attrs)
}

/// Generate a unique LID for a new key.
///
/// Seeds the attribute set with a UUID so that every `CreateKey` call
/// produces a distinct LID even when the caller supplies no identity
/// attributes.
pub fn generate_key_lid() -> (Lid, keyrack_core::attr::AttributeSet) {
    generate_key_lid_from_attrs(std::collections::BTreeMap::new())
}

// ── Key lifecycle ───────────────────────────────────────────────────

pub struct CreateKeyInput {
    pub key_spec: KeySpec,
    pub description: Option<String>,
    pub parent_key_id: Option<String>,
    pub attributes: std::collections::BTreeMap<String, String>,
    pub namespace: String,
    /// Deprecated alias for `backend_id`. When set,
    /// it must be a registered connection; see [`resolve_create_provider`].
    pub hsm_connection_id: Option<String>,
    /// The crypto backend to bind this key to. Supersedes `hsm_connection_id`.
    pub backend_id: Option<String>,
    /// Whether the key is born exportable. Default `NonExportable`.
    pub exportable: keyrack_core::key::Exportability,
}

/// Resolve the provider a new key binds to — the single source of truth shared
/// by the gRPC, REST, and library (`create_key`) paths.
///
/// ## Precedence (ADR-0001 Amendment 1)
///
/// 1. Evaluate routing rules against identity tags (first match wins).
/// 2. **Route** pin — authoritative; caller `backend_id` must match or be absent.
/// 3. **Delegate** — caller may select within the bounded set (or any registered
///    with `DelegateAny`). If no caller selection → use default.
/// 4. **Default** (no rule matched):
///    - If routing rules ARE configured → DEFAULT-DENY: caller `backend_id` that
///      differs from default is rejected (no delegate authorized it).
///    - If NO routing rules configured → backward-compat: `backend_id` selects
///      any registered provider (≈ implicit `delegate *`).
///
/// ## Error mapping (A1.6 §3)
///
/// - Unknown backend id (not in registry) → `FailedPrecondition`
/// - Known but policy does not permit selection → `PermissionDenied`
/// - Route-pin conflict (pin ≠ requested) → `FailedPrecondition` naming both
///
/// `keyrack.provider` / `backend_id` assertion: mismatch is `FailedPrecondition`.
pub fn resolve_create_provider(
    router: &keyrack_core::routing::ProviderRouter,
    providers: &Arc<dyn keyrack_core::registry::ProviderRegistry>,
    identity_tags: &keyrack_core::tags::IdentityTags,
    requested_provider: Option<&str>,
    hsm_connection_id: Option<&str>,
    backend_id: Option<&str>,
) -> Result<keyrack_core::key::ProviderRef, DomainError> {
    use keyrack_core::routing::RouteOutcome;

    // Reconcile the deprecated hsm_connection_id alias with backend_id.
    let effective_backend = match (
        backend_id.filter(|s| !s.is_empty()),
        hsm_connection_id.filter(|s| !s.is_empty()),
    ) {
        (Some(bid), Some(hid)) => {
            if bid != hid {
                return Err(DomainError::FailedPrecondition(format!(
                    "backend_id '{bid}' and hsm_connection_id '{hid}' disagree; \
                     use backend_id only (hsm_connection_id is deprecated)"
                )));
            }
            Some(bid)
        }
        (Some(bid), None) => Some(bid),
        (None, Some(hid)) => Some(hid),
        (None, None) => None,
    };

    // Also fold in the deprecated keyrack.provider attribute as an assertion.
    let assertion = requested_provider.filter(|s| !s.is_empty());

    // Evaluate routing rules.
    let outcome = router.evaluate(identity_tags);

    let resolved = match outcome {
        RouteOutcome::Pinned(ref pinned) => {
            if let Some(caller_id) = effective_backend {
                if caller_id != pinned.as_str() {
                    return Err(DomainError::FailedPrecondition(format!(
                        "routing policy pins provider '{}' but backend_id '{}' was requested \
                         (route rules are authoritative)",
                        pinned.as_str(),
                        caller_id
                    )));
                }
            }
            pinned.clone()
        }
        RouteOutcome::Delegated(ref allowed_set) => match effective_backend {
            Some(caller_id) => {
                let pref = keyrack_core::key::ProviderRef::new(caller_id);
                if !providers.contains(&pref) {
                    return Err(DomainError::FailedPrecondition(format!(
                        "backend_id '{caller_id}' is not a registered provider"
                    )));
                }
                if !allowed_set.contains(&pref) {
                    return Err(DomainError::PermissionDenied(format!(
                        "backend_id '{caller_id}' is not permitted by the delegate rule \
                             (allowed: {:?})",
                        allowed_set
                            .iter()
                            .map(keyrack_core::key::ProviderRef::as_str)
                            .collect::<Vec<_>>()
                    )));
                }
                pref
            }
            None => router.default_ref().clone(),
        },
        RouteOutcome::DelegatedAny => match effective_backend {
            Some(caller_id) => {
                let pref = keyrack_core::key::ProviderRef::new(caller_id);
                if !providers.contains(&pref) {
                    return Err(DomainError::FailedPrecondition(format!(
                        "backend_id '{caller_id}' is not a registered provider"
                    )));
                }
                pref
            }
            None => router.default_ref().clone(),
        },
        RouteOutcome::Default(ref default_provider) => {
            match effective_backend {
                Some(caller_id) => {
                    let pref = keyrack_core::key::ProviderRef::new(caller_id);
                    if !providers.contains(&pref) {
                        return Err(DomainError::FailedPrecondition(format!(
                            "backend_id '{caller_id}' is not a registered provider"
                        )));
                    }
                    // DEFAULT-DENY when routing rules are configured:
                    // a caller backend_id that differs from the default is not
                    // authorized by any delegate rule.
                    if router.has_rules() && pref != *default_provider {
                        return Err(DomainError::PermissionDenied(format!(
                            "backend_id '{caller_id}' is not authorized: no routing rule \
                             matched and no delegate permits caller selection"
                        )));
                    }
                    pref
                }
                None => default_provider.clone(),
            }
        }
    };

    // Assertion overlay (keyrack.provider / deprecated).
    if let Some(req) = assertion {
        if req != resolved.as_str() {
            let via = match &outcome {
                RouteOutcome::Pinned(_) => "route pin",
                RouteOutcome::Delegated(_) | RouteOutcome::DelegatedAny => "delegate selection",
                RouteOutcome::Default(_) => {
                    if effective_backend.is_some() {
                        "backend_id"
                    } else {
                        "routing policy"
                    }
                }
            };
            return Err(DomainError::FailedPrecondition(format!(
                "requested provider '{req}' but {via} selected '{}'",
                resolved.as_str()
            )));
        }
    }
    Ok(resolved)
}

// ── Routing explain (read-only dry-run) ─────────────────────────────

/// The outcome of a routing explain (dry-run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainOutcome {
    /// A route rule pinned the provider.
    Routed,
    /// A delegate rule authorized caller selection.
    Delegated,
    /// No rule matched; the default provider was used.
    Default,
    /// Resolution would be denied (fail-closed).
    Denied,
    /// The inputs conflict (`backend_id` vs `hsm_connection_id`, or assertion mismatch).
    Clash,
}

/// Full result of a routing dry-run / explain.
#[derive(Debug, Clone)]
pub struct ExplainResult {
    pub outcome: ExplainOutcome,
    /// The selected `backend_id` (empty when denied or clash).
    pub selected_backend_id: String,
    /// 0-based index of the matched routing rule, or -1 when no rule matched.
    pub matched_rule_index: i32,
    /// Human-readable deny/clash reason (empty on success).
    pub deny_reason: String,
    /// Whether routing rules are configured.
    pub policy_configured: bool,
}

/// Read-only dry-run of provider resolution. Uses the SAME logic as
/// [`resolve_create_provider`] so the explanation cannot drift from reality.
/// Denials and clashes are reported as successful results (not errors).
pub fn explain_routing(
    router: &keyrack_core::routing::ProviderRouter,
    providers: &Arc<dyn keyrack_core::registry::ProviderRegistry>,
    identity_tags: &keyrack_core::tags::IdentityTags,
    requested_provider: Option<&str>,
    hsm_connection_id: Option<&str>,
    backend_id: Option<&str>,
) -> ExplainResult {
    let policy_configured = router.has_rules();

    // Try the real resolution. On success we know the outcome; on error
    // we inspect the error to classify as DENIED or CLASH.
    match resolve_create_provider(
        router,
        providers,
        identity_tags,
        requested_provider,
        hsm_connection_id,
        backend_id,
    ) {
        Ok(resolved) => {
            let (_, rule_index) = router.evaluate_with_index(identity_tags);
            let outcome = match rule_index {
                Some(_) => {
                    use keyrack_core::routing::RouteOutcome;
                    let (raw_outcome, _) = router.evaluate_with_index(identity_tags);
                    match raw_outcome {
                        RouteOutcome::Pinned(_) => ExplainOutcome::Routed,
                        RouteOutcome::Delegated(_) | RouteOutcome::DelegatedAny => {
                            ExplainOutcome::Delegated
                        }
                        RouteOutcome::Default(_) => ExplainOutcome::Default,
                    }
                }
                None => ExplainOutcome::Default,
            };
            ExplainResult {
                outcome,
                selected_backend_id: resolved.as_str().to_string(),
                matched_rule_index: rule_index.map_or(-1, |i| i as i32),
                deny_reason: String::new(),
                policy_configured,
            }
        }
        Err(e) => {
            let msg = e.to_string();
            let (_, rule_index) = router.evaluate_with_index(identity_tags);

            // Classify: clash vs deny.
            let is_clash = msg.contains("disagree")
                || msg.contains("but backend_id")
                || msg.contains("but route pin")
                || (msg.contains("requested provider") && msg.contains("selected"));

            let outcome = if is_clash {
                ExplainOutcome::Clash
            } else {
                ExplainOutcome::Denied
            };

            ExplainResult {
                outcome,
                selected_backend_id: String::new(),
                matched_rule_index: rule_index.map_or(-1, |i| i as i32),
                deny_reason: msg,
                policy_configured,
            }
        }
    }
}

/// Enforce `scope_owner` on a resolved backend (ADR-0001 A1.4).
///
/// If the resolved `provider_name` corresponds to a persisted HSM connection
/// with a `scope_owner` value, the caller's principal must carry a matching
/// `scope` attribute (exact string equality). Mismatch or absent scope claim
/// → `PermissionDenied` (fail-closed; the principal IS authenticated).
/// When the connection has no `scope_owner` → passes (platform-scoped).
///
/// Emits a `scope_owner_check` audit event on EVERY evaluation (success,
/// denied, error) per ADR §5.1.
///
/// Returns `Ok(())` on pass, `Err(DomainError::PermissionDenied)` on deny.
pub async fn check_scope_owner(
    storage: &Arc<dyn keyrack_core::storage::StorageBackend>,
    audit: &Arc<dyn keyrack_core::audit::AuditSink>,
    provider_name: &keyrack_core::key::ProviderRef,
    principal_scope: Option<&str>,
    principal_id: &str,
    action: &keyrack_core::audit::AuditAction,
) -> Result<(), DomainError> {
    let conn = match storage.get_hsm_connection(provider_name.as_str()).await {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") {
                // Not an HSM connection (static provider or legacy) → no scope check.
                return Ok(());
            }
            // Genuine storage error → emit result=error and propagate.
            emit_scope_audit(
                audit,
                provider_name,
                principal_scope,
                principal_id,
                action,
                keyrack_core::audit::AuditResult::Error,
                "",
            )
            .await;
            return Err(DomainError::FailedPrecondition(format!(
                "scope_owner check failed: storage error for connection '{}'",
                provider_name.as_str()
            )));
        }
    };
    let Some(ref required_scope) = conn.scope_owner else {
        // No scope_owner set → platform-scoped, no check.
        return Ok(());
    };

    let (result, err_msg) = match principal_scope {
        Some(scope) if scope == required_scope => (keyrack_core::audit::AuditResult::Success, None),
        Some(scope) => (
            keyrack_core::audit::AuditResult::Denied,
            Some(format!(
                "scope mismatch: principal scope '{scope}' does not match \
                 connection scope_owner '{required_scope}'"
            )),
        ),
        None => (
            keyrack_core::audit::AuditResult::Denied,
            Some(format!(
                "scope_owner '{required_scope}' is set on connection '{}' but \
                 the principal has no scope claim",
                provider_name.as_str()
            )),
        ),
    };

    emit_scope_audit(
        audit,
        provider_name,
        principal_scope,
        principal_id,
        action,
        result,
        required_scope,
    )
    .await;

    match err_msg {
        None => Ok(()),
        Some(msg) => Err(DomainError::PermissionDenied(msg)),
    }
}

async fn emit_scope_audit(
    audit: &Arc<dyn keyrack_core::audit::AuditSink>,
    provider_name: &keyrack_core::key::ProviderRef,
    principal_scope: Option<&str>,
    principal_id: &str,
    action: &keyrack_core::audit::AuditAction,
    result: keyrack_core::audit::AuditResult,
    connection_scope_owner: &str,
) {
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        "scope".into(),
        serde_json::Value::String(principal_scope.unwrap_or("").to_string()),
    );
    metadata.insert(
        "connection_scope_owner".into(),
        serde_json::Value::String(connection_scope_owner.to_string()),
    );

    let event = keyrack_core::audit::AuditEvent {
        schema_version: keyrack_core::audit::SCHEMA_VERSION,
        event_id: uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string(),
        timestamp: chrono::Utc::now(),
        event_type: keyrack_core::audit::EventType::ScopeOwnerCheck,
        action: action.clone(),
        principal: keyrack_core::audit::AuditPrincipal {
            id: principal_id.to_string(),
            principal_type: "authenticated".into(),
        },
        resource: keyrack_core::audit::AuditResource {
            id: provider_name.as_str().to_string(),
            resource_type: "HsmConnection".into(),
        },
        result,
        encryption_context_hash: None,
        tenant: None,
        project: None,
        srn: None,
        request_id: None,
        metadata,
        signature: None,
        previous_hash: None,
    };
    if let Err(e) = audit.emit(&event).await {
        tracing::warn!(error = %e, "failed to emit scope_owner_check audit event");
    }
}

/// Enforce `scope_owner` for a crypto operation on an existing key.
///
/// Checks the EFFECTIVE per-version binding (`key_version.provider_ref`, falling
/// back to `record.provider_ref`) so migrated keys that straddle backends are
/// checked against the correct connection.
///
/// For encrypt/sign/mac-generate: checks the primary version binding.
/// For decrypt/verify/mac-verify: checks the specific version binding.
pub async fn enforce_scope_for_key_op(
    state: &crate::state::ServiceState,
    record: &KeyRecord,
    version_number: Option<u64>,
    principal_scope: Option<&str>,
    principal_id: &str,
    action: &keyrack_core::audit::AuditAction,
) -> Result<(), DomainError> {
    let effective_pref = match version_number {
        Some(ver) => record
            .key_versions
            .iter()
            .find(|v| v.version_number == ver)
            .and_then(|v| v.provider_ref.as_ref())
            .or(record.provider_ref.as_ref()),
        None => {
            // Primary version.
            record
                .key_versions
                .iter()
                .find(|v| v.is_primary)
                .and_then(|v| v.provider_ref.as_ref())
                .or(record.provider_ref.as_ref())
        }
    };

    let Some(pref) = effective_pref else {
        return Ok(());
    };

    check_scope_owner(
        &state.storage,
        &state.audit,
        pref,
        principal_scope,
        principal_id,
        action,
    )
    .await
}

pub async fn create_key(
    state: &Arc<ServiceState>,
    input: CreateKeyInput,
) -> Result<KeyRecord, DomainError> {
    if matches!(
        &input.key_spec,
        KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 } | KeySpec::RsaPssSha256 { key_size: 2048 }
    ) {
        tracing::warn!(
            "RSA-2048 provides only 112-bit security and is deprecated per NIST guidance (2030 deadline). \
             Consider RSA-3072+ or ECDSA P-256 for new keys."
        );
    }

    let mut caller_attrs = input.attributes.clone();
    let namespace = input.namespace.clone();
    let requested_provider = caller_attrs.remove("keyrack.provider");
    if !namespace.is_empty() {
        caller_attrs.insert("namespace".to_string(), namespace);
    }
    let (lid, attrs) = generate_key_lid_from_attrs(caller_attrs);
    let identity_tags = keyrack_core::tags::IdentityTags::from_attribute_set(&attrs);

    // Resolve the binding (tag routing + explicit selectors) in one place.
    let provider_name = resolve_create_provider(
        &state.provider_router,
        &state.providers,
        &identity_tags,
        requested_provider.as_deref(),
        input.hsm_connection_id.as_deref(),
        input.backend_id.as_deref(),
    )?;
    let entry = state
        .providers
        .resolve(&provider_name)
        .map_err(DomainError::from)?;

    let handle = entry
        .provider
        .generate_key(&input.key_spec)
        .await
        .map_err(DomainError::from)?;

    let parent_lid = input
        .parent_key_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(parse_lid)
        .transpose()?;

    let now = chrono::Utc::now();
    let key_usage = match input.key_spec {
        KeySpec::Aes256 | KeySpec::Aes128 => KeyUsage::EncryptDecrypt,
        KeySpec::Hmac256 => KeyUsage::GenerateVerifyMac,
        _ => KeyUsage::SignVerify,
    };

    let record = KeyRecord {
        lid,
        canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
        parent_lid,
        occ_version: 1,
        current_key_version: 1,
        state: KeyState::Enabled,
        key_usage,
        key_spec: input.key_spec,
        origin: keyrack_core::key::KeyOrigin::KeyRack,
        provider_class: entry.class,
        provider_ref: Some(provider_name.clone()),
        exportability: input.exportable,
        first_exported_at: None,
        identity_tags,
        user_tags: keyrack_core::tags::UserTags::new(),
        created_at: now,
        updated_at: now,
        scheduled_deletion_at: None,
        description: input.description.unwrap_or_default(),
        key_versions: vec![KeyVersionRecord {
            version_number: 1,
            key_handle: handle,
            provider_ref: Some(provider_name.clone()),
            created_at: now,
            is_primary: true,
        }],
    };

    state
        .storage
        .create_key(&record)
        .await
        .map_err(DomainError::from)?;

    if let Some(nats) = &state.nats_publisher {
        if let Err(e) = nats.publish_key_created(&lid).await {
            tracing::warn!(lid = %lid, error = %e, "NATS key-created publish failed");
        }
    }

    Ok(record)
}

pub async fn get_key(state: &Arc<ServiceState>, key_id: &str) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    state.storage.get_key(&lid).await.map_err(DomainError::from)
}

pub struct UpdateKeyInput {
    pub key_id: String,
    pub description: Option<String>,
}

pub async fn update_key(
    state: &Arc<ServiceState>,
    input: UpdateKeyInput,
) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(&input.key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    if let Some(desc) = input.description {
        record.description = desc;
    }
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    Ok(record)
}

pub struct ListKeysInput {
    pub limit: u32,
    pub cursor: Option<String>,
}

pub async fn list_keys(
    state: &Arc<ServiceState>,
    input: ListKeysInput,
) -> Result<Page<KeyRecord>, DomainError> {
    let limit = if input.limit == 0 { 100 } else { input.limit };
    let filter = KeyFilter {
        user_tags: vec![],
        state: None,
        limit: Some(limit),
        cursor: input.cursor,
    };
    state
        .storage
        .list_keys(&filter)
        .await
        .map_err(DomainError::from)
}

pub async fn enable_key(state: &Arc<ServiceState>, key_id: &str) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    let old_state = record.state.to_string();
    record
        .transition_to(KeyState::Enabled)
        .map_err(|(f, t)| transition_err(f, t))?;
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    if let Some(nats) = &state.nats_publisher {
        if let Err(e) = nats
            .publish_state_changed(&lid, &old_state, "enabled")
            .await
        {
            tracing::warn!(lid = %lid, error = %e, "NATS state-changed publish failed");
        }
    }
    Ok(record)
}

pub struct DisableKeyResult {
    pub record: KeyRecord,
    pub cascade_count: u64,
}

pub async fn disable_key(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<DisableKeyResult, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    let old_state = record.state.to_string();
    record
        .transition_to(KeyState::Disabled)
        .map_err(|(f, t)| transition_err(f, t))?;
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;

    if let Some(nats) = &state.nats_publisher {
        if let Err(e) = nats
            .publish_state_changed(&lid, &old_state, "disabled")
            .await
        {
            tracing::warn!(lid = %lid, error = %e, "NATS state-changed publish failed");
        }
    }

    // Cascade: disable all descendant keys (BFS)
    let cascade_start = std::time::Instant::now();
    let mut cascade_count = 0u64;
    let mut queue = vec![lid];
    while let Some(parent) = queue.pop() {
        let children = state
            .storage
            .list_children(&parent)
            .await
            .map_err(DomainError::from)?;
        for mut child in children {
            if child.state == KeyState::Enabled && child.transition_to(KeyState::Disabled).is_ok() {
                if let Err(e) = state.storage.update_key(&child).await {
                    tracing::error!(
                        child_lid = %child.lid,
                        error = %e,
                        "failed to disable descendant key during cascade"
                    );
                    return Err(DomainError::Internal(format!(
                        "cascade disable failed on descendant {}: {e}",
                        child.lid
                    )));
                }
                cascade_count += 1;
                queue.push(child.lid);
            }
        }
    }

    if cascade_count > 0 {
        tracing::info!(
            root = %key_id,
            descendants_disabled = cascade_count,
            elapsed_ms = cascade_start.elapsed().as_millis(),
            "cascade disable completed"
        );
        state
            .emit_audit_event(key_id, &format!("disabled {cascade_count} descendant(s)"))
            .await;
    }

    Ok(DisableKeyResult {
        record,
        cascade_count,
    })
}

pub async fn schedule_key_deletion(
    state: &Arc<ServiceState>,
    key_id: &str,
    grace_period_days: u32,
) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    let days = if grace_period_days == 0 {
        7
    } else {
        grace_period_days
    };
    record
        .transition_to(KeyState::PendingDeletion)
        .map_err(|(f, t)| transition_err(f, t))?;
    record.scheduled_deletion_at =
        Some(chrono::Utc::now() + chrono::Duration::days(i64::from(days)));
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    Ok(record)
}

pub async fn cancel_key_deletion(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    if record.state != KeyState::PendingDeletion {
        return Err(DomainError::FailedPrecondition(
            "can only cancel deletion from PendingDeletion".into(),
        ));
    }
    record
        .transition_to(KeyState::Disabled)
        .map_err(|(f, t)| transition_err(f, t))?;
    record.scheduled_deletion_at = None;
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    Ok(record)
}

pub async fn report_key_compromise(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    let old_state = record.state.to_string();
    record
        .transition_to(KeyState::Compromised)
        .map_err(|(f, t)| transition_err(f, t))?;
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    if let Some(nats) = &state.nats_publisher {
        if let Err(e) = nats
            .publish_state_changed(&lid, &old_state, "compromised")
            .await
        {
            tracing::warn!(lid = %lid, error = %e, "NATS state-changed publish failed");
        }
    }
    Ok(record)
}

pub struct RotateKeyResult {
    pub record: KeyRecord,
    pub new_version: u64,
    pub jobs_created: usize,
}

pub async fn rotate_key(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<RotateKeyResult, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    if record.state != KeyState::Enabled {
        return Err(DomainError::FailedPrecondition(
            "key must be Enabled to rotate".into(),
        ));
    }

    // Resolve the provider for the current primary version BEFORE pushing
    // the new version, so resolution uses the existing binding.
    let entry = state
        .providers
        .resolve_for_primary(&record)
        .map_err(DomainError::from)?;

    let new_handle = entry
        .provider
        .generate_key(&record.key_spec)
        .await
        .map_err(DomainError::from)?;

    // The new version inherits the key's record-level provider binding.
    let new_version_provider_ref = record.provider_ref.clone();
    let new_version = record.current_key_version + 1;
    for v in &mut record.key_versions {
        v.is_primary = false;
    }
    record.key_versions.push(KeyVersionRecord {
        version_number: new_version,
        key_handle: new_handle,
        provider_ref: new_version_provider_ref,
        created_at: chrono::Utc::now(),
        is_primary: true,
    });
    record.current_key_version = new_version;
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;

    // Create rotation jobs for all descendant keys (BFS)
    let mut queue = vec![lid];
    let mut visited = HashSet::new();
    visited.insert(lid);
    let mut total_jobs = 0usize;
    while let Some(parent_lid) = queue.pop() {
        let children = state
            .storage
            .list_children(&parent_lid)
            .await
            .map_err(DomainError::from)?;
        for dep in &children {
            if !visited.insert(dep.lid) {
                continue;
            }
            let job = keyrack_core::rotation::RotationJob::new(
                uuid::Uuid::new_v4().to_string(),
                lid,
                dep.lid,
                new_version,
            );
            if let Err(e) = state.storage.create_rotation_job(&job).await {
                tracing::warn!(
                    parent = %lid,
                    dependent = %dep.lid,
                    error = %e,
                    "failed to create rotation job for dependent"
                );
            }
            total_jobs += 1;
            queue.push(dep.lid);
        }
    }
    if total_jobs > 0 {
        tracing::info!(
            key = %key_id,
            new_version,
            jobs_created = total_jobs,
            "rotation jobs created for descendants (recursive)"
        );
    }

    if let Some(nats) = &state.nats_publisher {
        if let Err(e) = nats.publish_rotation_started(&lid, new_version).await {
            tracing::warn!(lid = %lid, error = %e, "NATS rotation-started publish failed");
        }
    }

    Ok(RotateKeyResult {
        record,
        new_version,
        jobs_created: total_jobs,
    })
}

// ── Crypto operations ───────────────────────────────────────────────

#[cfg(feature = "crypto-endpoints")]
pub mod crypto {
    use super::{parse_lid, DomainError, ServiceState};
    use keyrack_core::encryption_context::EncryptionContext;
    use keyrack_core::header::CiphertextHeader;
    use keyrack_core::key::KeySpec;
    use keyrack_core::provider::SigningAlgorithm;
    use std::sync::Arc;

    pub struct EncryptInput {
        pub key_id: String,
        pub plaintext: Vec<u8>,
        pub encryption_context: Option<EncryptionContext>,
    }

    pub struct EncryptOutput {
        pub ciphertext_blob: Vec<u8>,
        pub key_id: String,
        pub key_version: u64,
    }

    pub async fn encrypt(
        state: &Arc<ServiceState>,
        input: EncryptInput,
    ) -> Result<EncryptOutput, DomainError> {
        let lid = parse_lid(&input.key_id)?;
        let record = state
            .storage
            .get_key(&lid)
            .await
            .map_err(DomainError::from)?;

        if !record.state.permits_encrypt() {
            return Err(DomainError::FailedPrecondition(format!(
                "key {} is in state {} — encrypt not permitted",
                input.key_id, record.state
            )));
        }

        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| DomainError::Internal("no primary key version".into()))?;

        let entry = state
            .providers
            .resolve_for_primary(&record)
            .map_err(DomainError::from)?;

        let ec_aad = input
            .encryption_context
            .as_ref()
            .map(EncryptionContext::to_aad_bytes)
            .unwrap_or_default();

        let ec_hash = input
            .encryption_context
            .as_ref()
            .map_or([0u8; 32], EncryptionContext::hash);

        let header = CiphertextHeader::new(record.lid, record.current_key_version, ec_hash);
        let aad = header.build_aad(&ec_aad);

        let output = entry
            .provider
            .encrypt(&primary.key_handle, &input.plaintext, &aad)
            .await
            .map_err(DomainError::from)?;

        let ciphertext_blob = header.wrap_payload(&output.ciphertext);

        Ok(EncryptOutput {
            ciphertext_blob,
            key_id: record.lid.to_string(),
            key_version: record.current_key_version,
        })
    }

    pub struct DecryptInput {
        pub key_id: String,
        pub ciphertext_blob: Vec<u8>,
        pub encryption_context: Option<EncryptionContext>,
    }

    pub struct DecryptOutput {
        pub plaintext: Vec<u8>,
        pub key_id: String,
    }

    pub async fn decrypt(
        state: &Arc<ServiceState>,
        input: DecryptInput,
    ) -> Result<DecryptOutput, DomainError> {
        let lid = parse_lid(&input.key_id)?;
        let record = state
            .storage
            .get_key(&lid)
            .await
            .map_err(DomainError::from)?;

        if !record.state.permits_decrypt() {
            return Err(DomainError::FailedPrecondition(format!(
                "key {} is in state {} — decrypt not permitted",
                input.key_id, record.state
            )));
        }

        let (header, ciphertext) = CiphertextHeader::unwrap_payload(&input.ciphertext_blob)
            .map_err(|e| DomainError::InvalidArgument(e.to_string()))?;

        let ec_hash = input
            .encryption_context
            .as_ref()
            .map_or([0u8; 32], EncryptionContext::hash);

        if ec_hash != header.encryption_context_hash {
            return Err(DomainError::InvalidArgument(
                "encryption context mismatch".into(),
            ));
        }

        let version_record = record
            .key_versions
            .iter()
            .find(|v| v.version_number == header.key_version)
            .ok_or_else(|| DomainError::NotFound("key version not found".into()))?;

        let entry = state
            .providers
            .resolve_for_version(&record, header.key_version)
            .map_err(DomainError::from)?;

        let ec_aad = input
            .encryption_context
            .as_ref()
            .map(EncryptionContext::to_aad_bytes)
            .unwrap_or_default();

        let aad = header.build_aad(&ec_aad);

        let plaintext = entry
            .provider
            .decrypt(&version_record.key_handle, ciphertext, &aad)
            .await
            .map_err(DomainError::from)?;

        Ok(DecryptOutput {
            plaintext: plaintext.expose().clone(),
            key_id: record.lid.to_string(),
        })
    }

    pub struct ReEncryptInput {
        pub source_key_id: String,
        pub destination_key_id: String,
        pub ciphertext_blob: Vec<u8>,
        pub source_encryption_context: Option<EncryptionContext>,
        pub destination_encryption_context: Option<EncryptionContext>,
    }

    pub struct ReEncryptOutput {
        pub ciphertext_blob: Vec<u8>,
        pub source_key_id: String,
        pub destination_key_id: String,
    }

    pub async fn re_encrypt(
        state: &Arc<ServiceState>,
        input: ReEncryptInput,
    ) -> Result<ReEncryptOutput, DomainError> {
        let src_lid = parse_lid(&input.source_key_id)?;
        let dst_lid = parse_lid(&input.destination_key_id)?;

        let src_record = state
            .storage
            .get_key(&src_lid)
            .await
            .map_err(DomainError::from)?;
        let dst_record = state
            .storage
            .get_key(&dst_lid)
            .await
            .map_err(DomainError::from)?;

        let (header, ciphertext) = CiphertextHeader::unwrap_payload(&input.ciphertext_blob)
            .map_err(|e| DomainError::InvalidArgument(e.to_string()))?;

        let src_version = src_record
            .key_versions
            .iter()
            .find(|v| v.version_number == header.key_version)
            .ok_or_else(|| DomainError::NotFound("source key version not found".into()))?;

        let src_entry = state
            .providers
            .resolve_for_version(&src_record, header.key_version)
            .map_err(DomainError::from)?;
        let dst_entry = state
            .providers
            .resolve_for_primary(&dst_record)
            .map_err(DomainError::from)?;

        let src_ec_aad = input
            .source_encryption_context
            .as_ref()
            .map(EncryptionContext::to_aad_bytes)
            .unwrap_or_default();
        let src_aad = header.build_aad(&src_ec_aad);

        let dst_primary = dst_record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| DomainError::Internal("destination has no primary version".into()))?;

        let dst_ec_hash = input
            .destination_encryption_context
            .as_ref()
            .map_or([0u8; 32], EncryptionContext::hash);

        let new_header =
            CiphertextHeader::new(dst_record.lid, dst_record.current_key_version, dst_ec_hash);

        let dst_ec_aad = input
            .destination_encryption_context
            .as_ref()
            .map(EncryptionContext::to_aad_bytes)
            .unwrap_or_default();
        let dst_aad = new_header.build_aad(&dst_ec_aad);

        // Same-provider path: calls `re_encrypt` on the shared provider.
        // NOTE: no in-tree provider currently overrides `re_encrypt`, so the
        // trait default fires and plaintext surfaces in coordinator memory
        // regardless of the Arc::ptr_eq check.
        // Cross-provider path: decrypt on source, re-encrypt on destination
        // (plaintext transits service memory).
        let output = if Arc::ptr_eq(&src_entry.provider, &dst_entry.provider) {
            src_entry
                .provider
                .re_encrypt(
                    &src_version.key_handle,
                    ciphertext,
                    &src_aad,
                    &dst_primary.key_handle,
                    &dst_aad,
                )
                .await
                .map_err(DomainError::from)?
        } else {
            let plaintext = src_entry
                .provider
                .decrypt(&src_version.key_handle, ciphertext, &src_aad)
                .await
                .map_err(DomainError::from)?;
            dst_entry
                .provider
                .encrypt(&dst_primary.key_handle, plaintext.expose(), &dst_aad)
                .await
                .map_err(DomainError::from)?
        };

        Ok(ReEncryptOutput {
            ciphertext_blob: new_header.wrap_payload(&output.ciphertext),
            source_key_id: src_record.lid.to_string(),
            destination_key_id: dst_record.lid.to_string(),
        })
    }

    pub struct SignInput {
        pub key_id: String,
        pub message: Vec<u8>,
        pub signing_algorithm: SigningAlgorithm,
    }

    pub struct SignOutput {
        pub signature: Vec<u8>,
        pub key_id: String,
        pub signing_algorithm: SigningAlgorithm,
    }

    pub async fn sign(
        state: &Arc<ServiceState>,
        input: SignInput,
    ) -> Result<SignOutput, DomainError> {
        let lid = parse_lid(&input.key_id)?;
        let record = state
            .storage
            .get_key(&lid)
            .await
            .map_err(DomainError::from)?;

        if !record.state.permits_encrypt() {
            return Err(DomainError::FailedPrecondition(format!(
                "key {} is in state {} — sign not permitted",
                input.key_id, record.state
            )));
        }

        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| DomainError::Internal("no primary key version".into()))?;

        let entry = state
            .providers
            .resolve_for_primary(&record)
            .map_err(DomainError::from)?;

        let signature = entry
            .provider
            .sign(&primary.key_handle, input.signing_algorithm, &input.message)
            .await
            .map_err(DomainError::from)?;

        Ok(SignOutput {
            signature,
            key_id: record.lid.to_string(),
            signing_algorithm: input.signing_algorithm,
        })
    }

    pub struct VerifyInput {
        pub key_id: String,
        pub message: Vec<u8>,
        pub signature: Vec<u8>,
        pub signing_algorithm: SigningAlgorithm,
    }

    pub struct VerifyOutput {
        pub signature_valid: bool,
        pub key_id: String,
        pub signing_algorithm: SigningAlgorithm,
    }

    pub async fn verify(
        state: &Arc<ServiceState>,
        input: VerifyInput,
    ) -> Result<VerifyOutput, DomainError> {
        let lid = parse_lid(&input.key_id)?;
        let record = state
            .storage
            .get_key(&lid)
            .await
            .map_err(DomainError::from)?;

        if !record.state.permits_decrypt() {
            return Err(DomainError::FailedPrecondition(format!(
                "key {} is in state {} — verify not permitted",
                input.key_id, record.state
            )));
        }

        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| DomainError::Internal("no primary key version".into()))?;

        let entry = state
            .providers
            .resolve_for_primary(&record)
            .map_err(DomainError::from)?;

        let valid = entry
            .provider
            .verify(
                &primary.key_handle,
                input.signing_algorithm,
                &input.message,
                &input.signature,
            )
            .await
            .map_err(DomainError::from)?;

        Ok(VerifyOutput {
            signature_valid: valid,
            key_id: record.lid.to_string(),
            signing_algorithm: input.signing_algorithm,
        })
    }

    pub struct GenerateDataKeyInput {
        pub key_id: String,
        pub key_spec: Option<KeySpec>,
        pub number_of_bytes: u32,
        pub encryption_context: Option<EncryptionContext>,
    }

    pub struct GenerateDataKeyOutput {
        pub plaintext: Vec<u8>,
        pub ciphertext_blob: Vec<u8>,
        pub key_id: String,
    }

    pub async fn generate_data_key(
        state: &Arc<ServiceState>,
        input: GenerateDataKeyInput,
    ) -> Result<GenerateDataKeyOutput, DomainError> {
        let lid = parse_lid(&input.key_id)?;
        let record = state
            .storage
            .get_key(&lid)
            .await
            .map_err(DomainError::from)?;

        if !record.state.permits_encrypt() {
            return Err(DomainError::FailedPrecondition(format!(
                "key {} is in state {} — generate data key not permitted",
                input.key_id, record.state
            )));
        }

        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| DomainError::Internal("no primary key version".into()))?;

        let entry = state
            .providers
            .resolve_for_primary(&record)
            .map_err(DomainError::from)?;

        let ec_aad = input
            .encryption_context
            .as_ref()
            .map(EncryptionContext::to_aad_bytes)
            .unwrap_or_default();

        let ec_hash = input
            .encryption_context
            .as_ref()
            .map_or([0u8; 32], EncryptionContext::hash);

        let header = CiphertextHeader::new(record.lid, record.current_key_version, ec_hash);
        let aad = header.build_aad(&ec_aad);

        let dek_len = dek_length(input.key_spec.as_ref(), input.number_of_bytes);

        let output = entry
            .provider
            .generate_data_key(&primary.key_handle, dek_len, &aad)
            .await
            .map_err(DomainError::from)?;

        Ok(GenerateDataKeyOutput {
            plaintext: output.plaintext_key.into_inner(),
            ciphertext_blob: header.wrap_payload(&output.encrypted_key),
            key_id: record.lid.to_string(),
        })
    }

    pub struct GenerateDataKeyWithoutPlaintextOutput {
        pub ciphertext_blob: Vec<u8>,
        pub key_id: String,
    }

    pub async fn generate_data_key_without_plaintext(
        state: &Arc<ServiceState>,
        input: GenerateDataKeyInput,
    ) -> Result<GenerateDataKeyWithoutPlaintextOutput, DomainError> {
        let out = generate_data_key(state, input).await?;
        Ok(GenerateDataKeyWithoutPlaintextOutput {
            ciphertext_blob: out.ciphertext_blob,
            key_id: out.key_id,
        })
    }

    pub async fn generate_random(
        state: &Arc<ServiceState>,
        length: usize,
    ) -> Result<Vec<u8>, DomainError> {
        let random = state
            .providers
            .default_entry()
            .provider
            .generate_random(length)
            .await
            .map_err(DomainError::from)?;
        Ok(random.into_inner())
    }

    /// Determine DEK length from an optional key spec or explicit byte count.
    fn dek_length(spec: Option<&KeySpec>, number_of_bytes: u32) -> usize {
        if number_of_bytes > 0 {
            return number_of_bytes as usize;
        }
        match spec {
            Some(
                KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 }
                | KeySpec::RsaPssSha256 { key_size: 2048 },
            ) => 256,
            Some(
                KeySpec::RsaPkcs1v15Sha256 { key_size: 3072 }
                | KeySpec::RsaPssSha256 { key_size: 3072 },
            ) => 384,
            Some(
                KeySpec::RsaPkcs1v15Sha256 { key_size: 4096 }
                | KeySpec::RsaPssSha256 { key_size: 4096 },
            ) => 512,
            _ => 32,
        }
    }
}

// ── Key versions ────────────────────────────────────────────────────

pub async fn list_key_versions(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<Vec<KeyVersionRecord>, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    Ok(record.key_versions)
}

pub async fn get_key_version(
    state: &Arc<ServiceState>,
    key_id: &str,
    version: u64,
) -> Result<KeyVersionRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    record
        .key_versions
        .into_iter()
        .find(|v| v.version_number == version)
        .ok_or_else(|| DomainError::NotFound(format!("version {version} not found")))
}

// ── Rotation policy ─────────────────────────────────────────────────

pub async fn enable_key_rotation(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<(), DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    record.user_tags.set("_keyrack_rotation_enabled", "true");
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    tracing::info!(key_id, "rotation enabled");
    Ok(())
}

pub async fn disable_key_rotation(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<(), DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    record.user_tags.set("_keyrack_rotation_enabled", "false");
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    tracing::info!(key_id, "rotation disabled");
    Ok(())
}

pub struct RotationStatus {
    pub rotation_enabled: bool,
    pub last_rotated_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn get_key_rotation_status(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<RotationStatus, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    let rotation_enabled = record.user_tags.get("_keyrack_rotation_enabled") == Some("true");
    let last_rotated_at = record
        .key_versions
        .iter()
        .filter(|v| !v.is_primary)
        .max_by_key(|v| v.version_number)
        .map(|v| v.created_at);
    Ok(RotationStatus {
        rotation_enabled,
        last_rotated_at,
    })
}

pub struct RotationHistoryEntry {
    pub from_version: u64,
    pub to_version: u64,
    pub rotated_at: chrono::DateTime<chrono::Utc>,
}

pub async fn get_key_rotation_history(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<Vec<RotationHistoryEntry>, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    let mut sorted = record.key_versions;
    sorted.sort_by_key(|v| v.version_number);
    let entries = sorted
        .windows(2)
        .map(|w| RotationHistoryEntry {
            from_version: w[0].version_number,
            to_version: w[1].version_number,
            rotated_at: w[1].created_at,
        })
        .collect();
    Ok(entries)
}

pub struct RotationPolicy {
    pub enabled: bool,
    pub rotation_interval_days: u32,
}

pub async fn get_key_rotation_policy(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<RotationPolicy, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    let enabled = record.user_tags.get("_keyrack_rotation_enabled") == Some("true");
    let rotation_interval_days = record
        .user_tags
        .get("_keyrack_rotation_interval_days")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    Ok(RotationPolicy {
        enabled,
        rotation_interval_days,
    })
}

pub async fn set_key_rotation_policy(
    state: &Arc<ServiceState>,
    key_id: &str,
    policy: RotationPolicy,
) -> Result<(), DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    let enabled_str = if policy.enabled { "true" } else { "false" };
    record
        .user_tags
        .set("_keyrack_rotation_enabled", enabled_str);
    record.user_tags.set(
        "_keyrack_rotation_interval_days",
        policy.rotation_interval_days.to_string(),
    );
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    tracing::info!(
        key_id,
        enabled = policy.enabled,
        interval_days = policy.rotation_interval_days,
        "rotation policy persisted"
    );
    Ok(())
}

// ── Hierarchy queries ───────────────────────────────────────────────

pub struct LineageEntry {
    pub id: String,
    pub resource_type: String,
    pub depth: u32,
    pub parent_id: Option<String>,
}

pub async fn get_key_dependents(
    state: &Arc<ServiceState>,
    key_id: &str,
    recursive: bool,
) -> Result<Vec<LineageEntry>, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut dependents = Vec::new();
    let mut queue = vec![(lid, 1u32)];
    let mut visited = HashSet::new();
    visited.insert(lid);

    while let Some((parent_lid, depth)) = queue.pop() {
        let children = state
            .storage
            .list_children(&parent_lid)
            .await
            .map_err(DomainError::from)?;
        for child in &children {
            if !visited.insert(child.lid) {
                continue;
            }
            dependents.push(LineageEntry {
                id: child.lid.to_string(),
                resource_type: "key".into(),
                depth,
                parent_id: Some(parent_lid.to_string()),
            });
            if recursive {
                queue.push((child.lid, depth + 1));
            }
        }
    }
    Ok(dependents)
}

pub async fn get_key_ancestors(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<Vec<LineageEntry>, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut ancestors = Vec::new();
    let mut current = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    let mut depth = 1u32;
    let mut visited = HashSet::new();
    visited.insert(lid);

    while let Some(parent_lid) = current.parent_lid {
        if !visited.insert(parent_lid) {
            break;
        }
        current = state
            .storage
            .get_key(&parent_lid)
            .await
            .map_err(DomainError::from)?;
        ancestors.push(LineageEntry {
            id: parent_lid.to_string(),
            resource_type: "key".into(),
            depth,
            parent_id: current.parent_lid.map(|l| l.to_string()),
        });
        depth += 1;
        if depth > 100 {
            break;
        }
    }
    Ok(ancestors)
}

// ── Aliases ─────────────────────────────────────────────────────────

pub async fn create_alias(
    state: &Arc<ServiceState>,
    alias_name: &str,
    target_key_id: &str,
) -> Result<keyrack_core::storage::AliasRecord, DomainError> {
    let lid = parse_lid(target_key_id)?;
    let alias = keyrack_core::storage::AliasRecord {
        alias_name: alias_name.to_owned(),
        target_lid: lid,
        created_at: chrono::Utc::now(),
    };
    state
        .storage
        .create_alias(&alias)
        .await
        .map_err(DomainError::from)?;
    Ok(alias)
}

pub async fn delete_alias(state: &Arc<ServiceState>, alias_name: &str) -> Result<(), DomainError> {
    state
        .storage
        .delete_alias(alias_name)
        .await
        .map_err(DomainError::from)
}

pub async fn list_aliases(
    state: &Arc<ServiceState>,
) -> Result<Vec<keyrack_core::storage::AliasRecord>, DomainError> {
    state
        .storage
        .list_aliases()
        .await
        .map_err(DomainError::from)
}

// ── Tags ────────────────────────────────────────────────────────────

pub async fn tag_resource(
    state: &Arc<ServiceState>,
    key_id: &str,
    tags: Vec<(String, String)>,
) -> Result<(), DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    for (k, v) in tags {
        record.user_tags.set(k, v);
    }
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)
}

pub async fn untag_resource(
    state: &Arc<ServiceState>,
    key_id: &str,
    tag_keys: Vec<String>,
) -> Result<(), DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    for key in &tag_keys {
        record.user_tags.remove(key);
    }
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)
}

pub async fn list_resource_tags(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<Vec<(String, String)>, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)?;
    Ok(record
        .user_tags
        .iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect())
}

// ── HSM connections ─────────────────────────────────────────────────

pub async fn create_hsm_connection(
    state: &Arc<ServiceState>,
    provider_type: keyrack_core::hsm::HsmProviderType,
    endpoint: &str,
) -> Result<keyrack_core::hsm::HsmConnection, DomainError> {
    let conn = keyrack_core::hsm::HsmConnection::new(
        uuid::Uuid::new_v4().to_string(),
        provider_type,
        endpoint,
        "",
    );
    state
        .storage
        .create_hsm_connection(&conn)
        .await
        .map_err(DomainError::from)?;
    Ok(conn)
}

pub async fn get_hsm_connection(
    state: &Arc<ServiceState>,
    connection_id: &str,
) -> Result<keyrack_core::hsm::HsmConnection, DomainError> {
    state
        .storage
        .get_hsm_connection(connection_id)
        .await
        .map_err(DomainError::from)
}

pub async fn list_hsm_connections(
    state: &Arc<ServiceState>,
) -> Result<Vec<keyrack_core::hsm::HsmConnection>, DomainError> {
    state
        .storage
        .list_hsm_connections()
        .await
        .map_err(DomainError::from)
}

pub async fn delete_hsm_connection(
    state: &Arc<ServiceState>,
    connection_id: &str,
) -> Result<(), DomainError> {
    state
        .storage
        .delete_hsm_connection(connection_id)
        .await
        .map_err(DomainError::from)?;
    let pref = keyrack_core::key::ProviderRef::new(connection_id);
    if let Err(e) = state.providers.remove(&pref) {
        tracing::debug!(
            connection_id = %connection_id,
            error = %e,
            "provider not in live registry on delete"
        );
    }
    Ok(())
}

pub async fn get_hsm_connection_status(
    state: &Arc<ServiceState>,
    connection_id: &str,
) -> Result<keyrack_core::hsm::HsmConnection, DomainError> {
    state
        .storage
        .get_hsm_connection(connection_id)
        .await
        .map_err(DomainError::from)
}

// ── Rotation jobs ───────────────────────────────────────────────────

pub async fn list_rotation_jobs(
    state: &Arc<ServiceState>,
    state_filter: Option<keyrack_core::rotation::RotationJobState>,
    key_id: Option<&str>,
) -> Result<Vec<keyrack_core::rotation::RotationJob>, DomainError> {
    let key_filter_lid = key_id.map(parse_lid).transpose()?;
    let mut jobs = state
        .storage
        .list_rotation_jobs(state_filter)
        .await
        .map_err(DomainError::from)?;
    if let Some(lid) = &key_filter_lid {
        jobs.retain(|j| j.parent_lid == *lid || j.dependent_lid == *lid);
    }
    Ok(jobs)
}

pub async fn acknowledge_rotation_job(
    state: &Arc<ServiceState>,
    job_id: &str,
) -> Result<keyrack_core::rotation::RotationJob, DomainError> {
    let mut job = state
        .storage
        .get_rotation_job(job_id)
        .await
        .map_err(DomainError::from)?;
    job.transition_to(keyrack_core::rotation::RotationJobState::Acknowledged)
        .map_err(|(from, to)| {
            DomainError::FailedPrecondition(format!("cannot transition from {from} to {to}"))
        })?;
    state
        .storage
        .update_rotation_job(&job)
        .await
        .map_err(DomainError::from)?;
    Ok(job)
}

pub async fn complete_rotation_job(
    state: &Arc<ServiceState>,
    job_id: &str,
) -> Result<keyrack_core::rotation::RotationJob, DomainError> {
    let mut job = state
        .storage
        .get_rotation_job(job_id)
        .await
        .map_err(DomainError::from)?;
    job.transition_to(keyrack_core::rotation::RotationJobState::Completed)
        .map_err(|(from, to)| {
            DomainError::FailedPrecondition(format!("cannot transition from {from} to {to}"))
        })?;
    state
        .storage
        .update_rotation_job(&job)
        .await
        .map_err(DomainError::from)?;
    Ok(job)
}

pub async fn fail_rotation_job(
    state: &Arc<ServiceState>,
    job_id: &str,
    reason: &str,
) -> Result<keyrack_core::rotation::RotationJob, DomainError> {
    let mut job = state
        .storage
        .get_rotation_job(job_id)
        .await
        .map_err(DomainError::from)?;
    job.fail(reason).map_err(|(from, to)| {
        DomainError::FailedPrecondition(format!("cannot transition from {from} to {to}"))
    })?;
    state
        .storage
        .update_rotation_job(&job)
        .await
        .map_err(DomainError::from)?;
    Ok(job)
}

#[cfg(test)]
mod resolve_tests {
    use super::*;
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::provider::inmem::InMemoryProvider;
    use keyrack_core::registry::{DynamicProviderRegistry, ProviderEntry, ProviderRegistry};
    use keyrack_core::routing::ProviderRouter;
    use keyrack_core::tags::IdentityTags;
    use std::collections::BTreeMap;

    fn entry() -> ProviderEntry {
        ProviderEntry {
            provider: Arc::new(InMemoryProvider::new()),
            class: ProviderClass::InMemory,
        }
    }

    /// Registry with a static default + a static tenant provider + one
    /// "dynamic" HSM connection (`conn-1`). `conn-unknown` is deliberately absent.
    fn registry() -> Arc<dyn ProviderRegistry> {
        Arc::new(
            DynamicProviderRegistry::new(
                [
                    (ProviderRef::new("shared"), entry()),
                    (ProviderRef::new("tenant-acme"), entry()),
                    (ProviderRef::new("conn-1"), entry()),
                ],
                ProviderRef::new("shared"),
            )
            .unwrap(),
        )
    }

    /// One rule: `tenant=acme -> tenant-acme`, default `shared`.
    fn router() -> ProviderRouter {
        ProviderRouter::new(
            vec![(
                BTreeMap::from([("tenant".to_string(), "acme".to_string())]),
                ProviderRef::new("tenant-acme"),
            )],
            ProviderRef::new("shared"),
        )
    }

    fn no_rules_router() -> ProviderRouter {
        ProviderRouter::new(vec![], ProviderRef::new("shared"))
    }

    fn tags(pairs: &[(&str, &str)]) -> IdentityTags {
        let attrs: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let (_, attr_set) = generate_key_lid_from_attrs(attrs);
        IdentityTags::from_attribute_set(&attr_set)
    }

    #[test]
    fn no_explicit_no_match_uses_default() {
        let r =
            resolve_create_provider(&router(), &registry(), &tags(&[]), None, None, None).unwrap();
        assert_eq!(r.as_str(), "shared");
    }

    #[test]
    fn no_explicit_tag_match_routes() {
        let r = resolve_create_provider(
            &router(),
            &registry(),
            &tags(&[("tenant", "acme")]),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(r.as_str(), "tenant-acme");
    }

    #[test]
    fn requested_provider_agrees_with_routing() {
        let r = resolve_create_provider(
            &router(),
            &registry(),
            &tags(&[("tenant", "acme")]),
            Some("tenant-acme"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(r.as_str(), "tenant-acme");
    }

    #[test]
    fn requested_provider_disagrees_with_routing() {
        let err = resolve_create_provider(
            &router(),
            &registry(),
            &tags(&[("tenant", "acme")]),
            Some("shared"),
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("route pin selected 'tenant-acme'"),
            "{err}"
        );
    }

    #[test]
    fn hsm_connection_id_selects_directly_no_policy() {
        // When no routing rules configured (backward compat), hsm_connection_id
        // selects any registered provider (≈ delegate *).
        let r = resolve_create_provider(
            &no_rules_router(),
            &registry(),
            &tags(&[]),
            None,
            Some("conn-1"),
            None,
        )
        .unwrap();
        assert_eq!(r.as_str(), "conn-1");
    }

    #[test]
    fn hsm_connection_id_denied_when_policy_configured() {
        // When routing rules ARE configured and no delegate matches,
        // caller backend_id that differs from default is rejected.
        let err = resolve_create_provider(
            &router(),
            &registry(),
            &tags(&[]),
            None,
            Some("conn-1"),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not authorized"), "{err}");
    }

    #[test]
    fn hsm_connection_id_unregistered_fails_closed() {
        let err = resolve_create_provider(
            &router(),
            &registry(),
            &tags(&[]),
            None,
            Some("conn-unknown"),
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not a registered provider"),
            "{err}"
        );
    }

    #[test]
    fn hsm_connection_id_with_matching_assertion() {
        let r = resolve_create_provider(
            &no_rules_router(),
            &registry(),
            &tags(&[]),
            Some("conn-1"),
            Some("conn-1"),
            None,
        )
        .unwrap();
        assert_eq!(r.as_str(), "conn-1");
    }

    #[test]
    fn hsm_connection_id_with_conflicting_assertion() {
        let err = resolve_create_provider(
            &no_rules_router(),
            &registry(),
            &tags(&[]),
            Some("shared"),
            Some("conn-1"),
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("backend_id selected 'conn-1'"),
            "{err}"
        );
    }

    #[test]
    fn empty_explicit_strings_treated_as_absent() {
        let r =
            resolve_create_provider(&router(), &registry(), &tags(&[]), Some(""), Some(""), None)
                .unwrap();
        assert_eq!(r.as_str(), "shared");
    }

    // ── backend_id tests (0.3.0 additive) ──────────────────────────────

    #[test]
    fn backend_id_selects_directly() {
        let r = resolve_create_provider(
            &no_rules_router(),
            &registry(),
            &tags(&[]),
            None,
            None,
            Some("conn-1"),
        )
        .unwrap();
        assert_eq!(r.as_str(), "conn-1");
    }

    #[test]
    fn backend_id_and_hsm_connection_id_agree() {
        let r = resolve_create_provider(
            &no_rules_router(),
            &registry(),
            &tags(&[]),
            None,
            Some("conn-1"),
            Some("conn-1"),
        )
        .unwrap();
        assert_eq!(r.as_str(), "conn-1");
    }

    #[test]
    fn backend_id_and_hsm_connection_id_disagree_fails() {
        let err = resolve_create_provider(
            &router(),
            &registry(),
            &tags(&[]),
            None,
            Some("conn-1"),
            Some("shared"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("disagree"), "{err}");
    }

    #[test]
    fn backend_id_unregistered_fails_closed() {
        let err = resolve_create_provider(
            &router(),
            &registry(),
            &tags(&[]),
            None,
            None,
            Some("nonexistent"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not a registered provider"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod explain_tests {
    use super::*;
    use keyrack_core::key::{ProviderClass, ProviderRef};
    use keyrack_core::provider::inmem::InMemoryProvider;
    use keyrack_core::registry::{DynamicProviderRegistry, ProviderEntry, ProviderRegistry};
    use keyrack_core::routing::ProviderRouter;
    use keyrack_core::tags::IdentityTags;
    use std::collections::BTreeMap;

    fn entry() -> ProviderEntry {
        ProviderEntry {
            provider: Arc::new(InMemoryProvider::new()),
            class: ProviderClass::InMemory,
        }
    }

    fn registry() -> Arc<dyn ProviderRegistry> {
        Arc::new(
            DynamicProviderRegistry::new(
                [
                    (ProviderRef::new("shared"), entry()),
                    (ProviderRef::new("tenant-acme"), entry()),
                    (ProviderRef::new("conn-1"), entry()),
                ],
                ProviderRef::new("shared"),
            )
            .unwrap(),
        )
    }

    fn router() -> ProviderRouter {
        ProviderRouter::new(
            vec![(
                BTreeMap::from([("tenant".to_string(), "acme".to_string())]),
                ProviderRef::new("tenant-acme"),
            )],
            ProviderRef::new("shared"),
        )
    }

    fn no_rules_router() -> ProviderRouter {
        ProviderRouter::new(vec![], ProviderRef::new("shared"))
    }

    fn tags(pairs: &[(&str, &str)]) -> IdentityTags {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        IdentityTags::from_map(map)
    }

    #[test]
    fn explain_returns_routed_for_matching_rule() {
        let result = explain_routing(
            &router(),
            &registry(),
            &tags(&[("tenant", "acme")]),
            None,
            None,
            None,
        );
        assert_eq!(result.outcome, ExplainOutcome::Routed);
        assert_eq!(result.selected_backend_id, "tenant-acme");
        assert_eq!(result.matched_rule_index, 0);
        assert!(result.deny_reason.is_empty());
        assert!(result.policy_configured);
    }

    #[test]
    fn explain_returns_default_when_no_rule_matches() {
        let result = explain_routing(
            &router(),
            &registry(),
            &tags(&[("env", "staging")]),
            None,
            None,
            None,
        );
        assert_eq!(result.outcome, ExplainOutcome::Default);
        assert_eq!(result.selected_backend_id, "shared");
        assert_eq!(result.matched_rule_index, -1);
        assert!(result.deny_reason.is_empty());
        assert!(result.policy_configured);
    }

    #[test]
    fn explain_returns_clash_when_backend_id_conflicts_with_hsm_connection_id() {
        let result = explain_routing(
            &router(),
            &registry(),
            &tags(&[]),
            None,
            Some("conn-1"),
            Some("shared"),
        );
        assert_eq!(result.outcome, ExplainOutcome::Clash);
        assert!(result.selected_backend_id.is_empty());
        assert!(result.deny_reason.contains("disagree"));
    }

    #[test]
    fn explain_returns_deny_under_default_deny() {
        let result = explain_routing(
            &router(),
            &registry(),
            &tags(&[]),
            None,
            Some("conn-1"),
            None,
        );
        assert_eq!(result.outcome, ExplainOutcome::Denied);
        assert!(result.selected_backend_id.is_empty());
        assert!(result.deny_reason.contains("not authorized"));
        assert!(result.policy_configured);
    }

    #[test]
    fn explain_returns_deny_for_unregistered_backend() {
        let result = explain_routing(
            &router(),
            &registry(),
            &tags(&[]),
            None,
            None,
            Some("nonexistent"),
        );
        assert_eq!(result.outcome, ExplainOutcome::Denied);
        assert!(result.selected_backend_id.is_empty());
        assert!(result.deny_reason.contains("not a registered provider"));
    }

    #[test]
    fn explain_returns_clash_when_assertion_disagrees_with_routing() {
        let result = explain_routing(
            &router(),
            &registry(),
            &tags(&[("tenant", "acme")]),
            Some("shared"),
            None,
            None,
        );
        assert_eq!(result.outcome, ExplainOutcome::Clash);
        assert!(result.selected_backend_id.is_empty());
        assert!(result
            .deny_reason
            .contains("route pin selected 'tenant-acme'"));
    }

    #[test]
    fn explain_no_policy_returns_default_without_deny() {
        let result = explain_routing(
            &no_rules_router(),
            &registry(),
            &tags(&[]),
            None,
            None,
            None,
        );
        assert_eq!(result.outcome, ExplainOutcome::Default);
        assert_eq!(result.selected_backend_id, "shared");
        assert_eq!(result.matched_rule_index, -1);
        assert!(!result.policy_configured);
    }

    #[test]
    fn explain_no_policy_backend_id_selects_freely() {
        let result = explain_routing(
            &no_rules_router(),
            &registry(),
            &tags(&[]),
            None,
            None,
            Some("conn-1"),
        );
        assert_eq!(result.outcome, ExplainOutcome::Default);
        assert_eq!(result.selected_backend_id, "conn-1");
        assert!(!result.policy_configured);
    }
}

/// Build PDP resource attributes for exportable-key operations.
/// Populates `exportable` and `exported` so Cedar can gate on them.
pub fn exportability_resource_attrs(
    record: &KeyRecord,
) -> std::collections::BTreeMap<String, keyrack_core::pdp::AttributeValue> {
    use keyrack_core::pdp::AttributeValue;
    let mut attrs = std::collections::BTreeMap::new();
    attrs.insert(
        "exportable".into(),
        AttributeValue::Bool(record.exportability == keyrack_core::key::Exportability::Exportable),
    );
    attrs.insert(
        "exported".into(),
        AttributeValue::Bool(record.first_exported_at.is_some()),
    );
    attrs
}
