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

//! REST gateway layer.
//!
//! Every handler uses [`ops::execute_rest`] to ensure PDP authorization
//! and audit emission are structurally impossible to skip.

use crate::ops::{self, OpContext};
use crate::state::ServiceState;
use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::Router;
use keyrack_core::audit::AuditAction;
use keyrack_core::key::KeyRecord;
use std::sync::Arc;

type AppState = Arc<ServiceState>;
type RestError = (StatusCode, Json<serde_json::Value>);

/// Tenant-safe key version — strips `key_handle` (provider-internal).
#[derive(serde::Serialize)]
struct KeyVersionResponse {
    version_number: u64,
    created_at: chrono::DateTime<chrono::Utc>,
    is_primary: bool,
}

/// Tenant-safe key response DTO.
///
/// Excludes `identity_tags`, `occ_version`, `canonicalization_version`,
/// and all `key_handle` internals that are provider-private.
#[derive(serde::Serialize)]
struct KeyResponse {
    lid: String,
    state: keyrack_core::key::KeyState,
    key_spec: keyrack_core::key::KeySpec,
    key_usage: keyrack_core::key::KeyUsage,
    origin: keyrack_core::key::KeyOrigin,
    provider_class: keyrack_core::key::ProviderClass,
    /// Name of the configured provider this key is bound to (routing target).
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_ref: Option<String>,
    description: String,
    user_tags: keyrack_core::tags::UserTags,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scheduled_deletion_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_lid: Option<String>,
    current_key_version: u64,
    key_versions: Vec<KeyVersionResponse>,
}

impl From<&KeyRecord> for KeyResponse {
    fn from(r: &KeyRecord) -> Self {
        Self {
            lid: r.lid.to_string(),
            state: r.state,
            key_spec: r.key_spec.clone(),
            key_usage: r.key_usage,
            origin: r.origin,
            provider_class: r.provider_class,
            provider_ref: r.provider_ref.as_ref().map(|p| p.as_str().to_string()),
            description: r.description.clone(),
            user_tags: r.user_tags.clone(),
            created_at: r.created_at,
            updated_at: r.updated_at,
            scheduled_deletion_at: r.scheduled_deletion_at,
            parent_lid: r.parent_lid.as_ref().map(ToString::to_string),
            current_key_version: r.current_key_version,
            key_versions: r
                .key_versions
                .iter()
                .map(|v| KeyVersionResponse {
                    version_number: v.version_number,
                    created_at: v.created_at,
                    is_primary: v.is_primary,
                })
                .collect(),
        }
    }
}

/// Tenant-safe list page response.
#[derive(serde::Serialize)]
struct KeyListResponse {
    items: Vec<KeyResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

fn key_json(record: &KeyRecord) -> Json<serde_json::Value> {
    Json(serde_json::to_value(KeyResponse::from(record)).unwrap_or_default())
}

pub fn router(state: AppState) -> Router {
    let r = Router::new()
        // ── Key lifecycle ───────────────────────────────────
        .route("/v1/keys", get(list_keys).post(create_key))
        .route("/v1/keys/:key_id", get(get_key).put(update_key))
        .route("/v1/keys/:key_id/describe", get(describe_key))
        .route("/v1/keys/:key_id/actions-enable", post(enable_key))
        .route("/v1/keys/:key_id/actions-disable", post(disable_key))
        .route(
            "/v1/keys/:key_id/actions-schedule-deletion",
            post(schedule_key_deletion),
        )
        .route(
            "/v1/keys/:key_id/actions-cancel-deletion",
            post(cancel_key_deletion),
        )
        .route(
            "/v1/keys/:key_id/actions-report-compromise",
            post(report_key_compromise),
        )
        .route("/v1/keys/:key_id/actions-rotate", post(rotate_key));

    // Crypto operation routes: gated behind the `crypto-endpoints` feature.
    #[cfg(feature = "crypto-endpoints")]
    let r = r
        .route("/v1/keys/:key_id/actions-encrypt", post(encrypt))
        .route("/v1/keys/:key_id/actions-decrypt", post(decrypt))
        .route("/v1/keys/:key_id/actions-sign", post(sign))
        .route("/v1/keys/:key_id/actions-verify", post(verify))
        .route("/v1/keys/:key_id/actions-generate-mac", post(generate_mac))
        .route("/v1/keys/:key_id/actions-verify-mac", post(verify_mac))
        .route(
            "/v1/keys/:key_id/actions-generate-data-key",
            post(generate_data_key),
        )
        .route("/v1/keys/:key_id/actions-re-encrypt", post(re_encrypt))
        .route("/v1/generate-random", post(generate_random));

    r
        // ── Tags ────────────────────────────────────────────
        .route(
            "/v1/keys/:key_id/tags",
            get(list_resource_tags)
                .post(tag_resource)
                .delete(untag_resource),
        )
        // ── Aliases ─────────────────────────────────────────
        .route("/v1/aliases", get(list_aliases).post(create_alias))
        .route("/v1/aliases/:alias_name", delete(delete_alias))
        // ── Health / ops ────────────────────────────────────
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .layer(middleware::from_fn(echo_request_id))
        .with_state(state)
}

async fn echo_request_id(req: axum::extract::Request, next: middleware::Next) -> impl IntoResponse {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map_or_else(ops::new_request_id, ToOwned::to_owned);

    let mut response = next.run(req).await;
    if let Ok(val) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", val);
    }
    response
}

#[allow(clippy::needless_pass_by_value)]
fn map_core_err(err: keyrack_core::error::KeyRackError) -> RestError {
    use keyrack_core::error::KeyRackError;
    let (code, kind) = match &err {
        KeyRackError::KeyNotFound(_) => (StatusCode::NOT_FOUND, "KeyNotFound"),
        KeyRackError::OptimisticConcurrencyConflict { .. } => (StatusCode::CONFLICT, "OccConflict"),
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
        KeyRackError::AuthorizationDenied { .. } => (StatusCode::FORBIDDEN, "AuthorizationDenied"),
        KeyRackError::DepthLimitExceeded { .. } => (StatusCode::BAD_REQUEST, "DepthLimitExceeded"),
        KeyRackError::CycleDetected { .. } => (StatusCode::BAD_REQUEST, "CycleDetected"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
    };
    ops::rest_error(code, kind, &err.to_string())
}

fn transition_err(from: keyrack_core::key::KeyState, to: keyrack_core::key::KeyState) -> RestError {
    ops::rest_error(
        StatusCode::CONFLICT,
        "InvalidStateTransition",
        &format!("cannot transition from {from} to {to}"),
    )
}

#[cfg(feature = "crypto-endpoints")]
fn build_ec(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Option<keyrack_core::encryption_context::EncryptionContext> {
    if map.is_empty() {
        return None;
    }
    let mut ec = keyrack_core::encryption_context::EncryptionContext::new();
    for (k, v) in map {
        if let Some(s) = v.as_str() {
            ec.insert(k, s);
        }
    }
    Some(ec)
}

// ── Handlers ────────────────────────────────────────────────────────

async fn create_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::CreateKey, principal, "(new)");
    op_ctx.request_id = request_id;
    ops::execute_rest(
        &state,
        op_ctx,
        |state| async move {
            let spec_str = body.get("key_spec").and_then(|v| v.as_str()).unwrap_or("AES_256");
            let spec = match spec_str {
                "AES_256" => keyrack_core::key::KeySpec::Aes256,
                "ED25519" => keyrack_core::key::KeySpec::Ed25519,
                "ECDSA_P256" => keyrack_core::key::KeySpec::EcdsaP256Sha256,
                "RSA_2048" => keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 },
                "RSA_3072" => keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size: 3072 },
                "RSA_4096" => keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size: 4096 },
                "RSA_PSS_2048" => keyrack_core::key::KeySpec::RsaPssSha256 { key_size: 2048 },
                "RSA_PSS_3072" => keyrack_core::key::KeySpec::RsaPssSha256 { key_size: 3072 },
                "RSA_PSS_4096" => keyrack_core::key::KeySpec::RsaPssSha256 { key_size: 4096 },
                "ECC_NIST_P384" => keyrack_core::key::KeySpec::EcdsaP384,
                "HMAC_256" => keyrack_core::key::KeySpec::Hmac256,
                "AES_128" => keyrack_core::key::KeySpec::Aes128,
                _ => return Err(ops::rest_error(StatusCode::BAD_REQUEST, "InvalidKeySpec", &format!("unknown key_spec: {spec_str}"))),
            };
            if matches!(&spec, keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 } | keyrack_core::key::KeySpec::RsaPssSha256 { key_size: 2048 }) {
                tracing::warn!(
                    "RSA-2048 provides only 112-bit security and is deprecated per NIST guidance (2030 deadline). \
                     Consider RSA-3072+ or ECDSA P-256 for new keys."
                );
            }
            let mut caller_attrs: std::collections::BTreeMap<String, String> = body
                .get("attributes")
                .and_then(|v| v.as_object())
                .map(|obj| {
                    obj.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            let namespace = body
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let requested_provider = caller_attrs.remove("keyrack.provider");
            if !namespace.is_empty() {
                caller_attrs.insert("namespace".to_string(), namespace);
            }
            let (lid, attrs) = crate::domain::generate_key_lid_from_attrs(caller_attrs);
            let identity_tags = keyrack_core::tags::IdentityTags::from_attribute_set(&attrs);

            // Route new key to the appropriate provider.
            let provider_name = state.provider_router.select(&identity_tags);
            if let Some(req_provider) = &requested_provider {
                if req_provider != provider_name.as_str() {
                    return Err(ops::rest_error(
                        StatusCode::CONFLICT,
                        "ProviderMismatch",
                        &format!(
                            "requested provider '{req_provider}' but routing policy selected '{}'",
                            provider_name.as_str()
                        ),
                    ));
                }
            }
            let entry = state.providers.resolve(&provider_name).map_err(map_core_err)?;

            let handle = entry.provider.generate_key(&spec).await.map_err(map_core_err)?;

            let parent_lid = body.get("parent_key_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(parse_lid_rest)
                .transpose()?;

            let now = chrono::Utc::now();
            let key_usage = match spec {
                keyrack_core::key::KeySpec::Aes256 | keyrack_core::key::KeySpec::Aes128 => {
                    keyrack_core::key::KeyUsage::EncryptDecrypt
                }
                keyrack_core::key::KeySpec::Hmac256 => {
                    keyrack_core::key::KeyUsage::GenerateVerifyMac
                }
                _ => keyrack_core::key::KeyUsage::SignVerify,
            };
            let desc = body.get("description").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let record = keyrack_core::key::KeyRecord {
                lid,
                canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
                parent_lid,
                occ_version: 1,
                current_key_version: 1,
                state: keyrack_core::key::KeyState::Enabled,
                key_usage,
                key_spec: spec,
                origin: keyrack_core::key::KeyOrigin::KeyRack,
                provider_class: entry.class,
                provider_ref: Some(provider_name.clone()),
                identity_tags,
                user_tags: keyrack_core::tags::UserTags::new(),
                created_at: now,
                updated_at: now,
                scheduled_deletion_at: None,
                description: desc,
                key_versions: vec![keyrack_core::key::KeyVersionRecord {
                    version_number: 1,
                    key_handle: handle,
                    provider_ref: Some(provider_name.clone()),
                    created_at: now,
                    is_primary: true,
                }],
            };
            state.storage.create_key(&record).await.map_err(map_core_err)?;
            Ok((StatusCode::CREATED, key_json(&record)))
        },
    ).await
}

async fn get_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::GetKey, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        Ok(key_json(&record))
    })
    .await
}

async fn describe_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::DescribeKey, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        Ok(key_json(&record))
    })
    .await
}

async fn update_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::UpdateKey, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let mut record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        if let Some(desc) = body.get("description").and_then(|v| v.as_str()) {
            desc.clone_into(&mut record.description);
        }
        record.occ_version += 1;
        record.updated_at = chrono::Utc::now();
        state
            .storage
            .update_key(&record)
            .await
            .map_err(map_core_err)?;
        Ok(key_json(&record))
    })
    .await
}

async fn list_keys(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::ListKeys, principal, "");
    op_ctx.resource_type = "Key".into();
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let filter = keyrack_core::storage::KeyFilter {
            user_tags: vec![],
            state: None,
            limit: Some(100),
            cursor: None,
        };
        let page = state
            .storage
            .list_keys(&filter)
            .await
            .map_err(map_core_err)?;
        let resp = KeyListResponse {
            items: page.items.iter().map(KeyResponse::from).collect(),
            next_cursor: page.next_cursor,
        };
        Ok(Json(serde_json::to_value(&resp).unwrap_or_default()))
    })
    .await
}

async fn enable_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::EnableKey, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let mut record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        record
            .transition_to(keyrack_core::key::KeyState::Enabled)
            .map_err(|(f, t)| transition_err(f, t))?;
        state
            .storage
            .update_key(&record)
            .await
            .map_err(map_core_err)?;
        Ok(key_json(&record))
    })
    .await
}

async fn disable_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::DisableKey, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let mut record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        record
            .transition_to(keyrack_core::key::KeyState::Disabled)
            .map_err(|(f, t)| transition_err(f, t))?;
        state
            .storage
            .update_key(&record)
            .await
            .map_err(map_core_err)?;
        Ok(key_json(&record))
    })
    .await
}

async fn schedule_key_deletion(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::ScheduleKeyDeletion, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let mut record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        let days = body
            .get("grace_period_days")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(7);
        record
            .transition_to(keyrack_core::key::KeyState::PendingDeletion)
            .map_err(|(f, t)| transition_err(f, t))?;
        #[allow(clippy::cast_possible_wrap)]
        {
            record.scheduled_deletion_at =
                Some(chrono::Utc::now() + chrono::Duration::days(days as i64));
        }
        state
            .storage
            .update_key(&record)
            .await
            .map_err(map_core_err)?;
        Ok(key_json(&record))
    })
    .await
}

async fn cancel_key_deletion(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::CancelKeyDeletion, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let mut record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        if record.state != keyrack_core::key::KeyState::PendingDeletion {
            return Err(ops::rest_error(
                StatusCode::CONFLICT,
                "InvalidStateTransition",
                "can only cancel deletion from PendingDeletion",
            ));
        }
        record
            .transition_to(keyrack_core::key::KeyState::Disabled)
            .map_err(|(f, t)| transition_err(f, t))?;
        record.scheduled_deletion_at = None;
        state
            .storage
            .update_key(&record)
            .await
            .map_err(map_core_err)?;
        Ok(key_json(&record))
    })
    .await
}

async fn report_key_compromise(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::ReportKeyCompromise, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let mut record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        let old_state = record.state.to_string();
        record
            .transition_to(keyrack_core::key::KeyState::Compromised)
            .map_err(|(f, t)| transition_err(f, t))?;
        state
            .storage
            .update_key(&record)
            .await
            .map_err(map_core_err)?;
        if let Some(nats) = &state.nats_publisher {
            if let Err(e) = nats
                .publish_state_changed(&lid, &old_state, "compromised")
                .await
            {
                tracing::warn!(lid = %lid, error = %e, "NATS state-changed publish failed");
            }
        }
        Ok(key_json(&record))
    })
    .await
}

async fn rotate_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::RotateKey, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let mut record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        if record.state != keyrack_core::key::KeyState::Enabled {
            return Err(ops::rest_error(
                StatusCode::CONFLICT,
                "InvalidState",
                "key must be Enabled to rotate",
            ));
        }
        let rot_entry = state
            .providers
            .resolve_for_primary(&record)
            .map_err(map_core_err)?;
        let handle = rot_entry
            .provider
            .generate_key(&record.key_spec)
            .await
            .map_err(map_core_err)?;
        let new_version_provider_ref = record.provider_ref.clone();
        let new_version = record.current_key_version + 1;
        for v in &mut record.key_versions {
            v.is_primary = false;
        }
        record
            .key_versions
            .push(keyrack_core::key::KeyVersionRecord {
                version_number: new_version,
                key_handle: handle,
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
            .map_err(map_core_err)?;
        Ok(key_json(&record))
    })
    .await
}

// ── Crypto action handlers ──────────────────────────────────────────
// Gated behind the `crypto-endpoints` Cargo feature (default-on).

#[cfg(feature = "crypto-endpoints")]
async fn encrypt(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let ec_hash = body
        .get("encryption_context")
        .and_then(|v| v.as_object())
        .and_then(build_ec)
        .as_ref()
        .map(keyrack_core::encryption_context::EncryptionContext::hash);
    let mut op_ctx = OpContext::key(AuditAction::Encrypt, principal, &key_id);
    op_ctx.encryption_context_hash = ec_hash;
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        if !record.state.permits_encrypt() {
            return Err(ops::rest_error(
                StatusCode::CONFLICT,
                "InvalidState",
                "key not in Enabled state",
            ));
        }
        let plaintext_b64 = body.get("plaintext").and_then(|v| v.as_str()).unwrap_or("");
        let plaintext = base64_decode(plaintext_b64)?;
        let ec = body
            .get("encryption_context")
            .and_then(|v| v.as_object())
            .and_then(build_ec);
        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| {
                ops::rest_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "NoVersion",
                    "no primary version",
                )
            })?;
        let ec_aad = ec
            .as_ref()
            .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
            .unwrap_or_default();
        let ec_hash = ec.as_ref().map_or(
            [0u8; 32],
            keyrack_core::encryption_context::EncryptionContext::hash,
        );
        let header = keyrack_core::header::CiphertextHeader::new(
            record.lid,
            record.current_key_version,
            ec_hash,
        );
        let aad = header.build_aad(&ec_aad);
        let enc_entry = state
            .providers
            .resolve_for_primary(&record)
            .map_err(map_core_err)?;
        let output = enc_entry
            .provider
            .encrypt(&primary.key_handle, &plaintext, &aad)
            .await
            .map_err(map_core_err)?;
        let blob = header.wrap_payload(&output.ciphertext);
        Ok(Json(serde_json::json!({
            "ciphertext_blob": base64_encode(&blob),
            "key_id": record.lid.to_string(),
        })))
    })
    .await
}

#[cfg(feature = "crypto-endpoints")]
async fn decrypt(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let ec_hash = body
        .get("encryption_context")
        .and_then(|v| v.as_object())
        .and_then(build_ec)
        .as_ref()
        .map(keyrack_core::encryption_context::EncryptionContext::hash);
    let mut op_ctx = OpContext::key(AuditAction::Decrypt, principal, &key_id);
    op_ctx.encryption_context_hash = ec_hash;
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        if !record.state.permits_decrypt() {
            return Err(ops::rest_error(
                StatusCode::CONFLICT,
                "InvalidState",
                "key not in state for decrypt",
            ));
        }
        let blob_b64 = body
            .get("ciphertext_blob")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let blob = base64_decode(blob_b64)?;
        let (header, ciphertext) = keyrack_core::header::CiphertextHeader::unwrap_payload(&blob)
            .map_err(|e| {
                ops::rest_error(StatusCode::BAD_REQUEST, "InvalidCiphertext", &e.to_string())
            })?;
        let ec = body
            .get("encryption_context")
            .and_then(|v| v.as_object())
            .and_then(build_ec);
        let ec_hash = ec.as_ref().map_or(
            [0u8; 32],
            keyrack_core::encryption_context::EncryptionContext::hash,
        );
        if ec_hash != header.encryption_context_hash {
            return Err(ops::rest_error(
                StatusCode::BAD_REQUEST,
                "EncryptionContextMismatch",
                "encryption context mismatch",
            ));
        }
        let version_record = record
            .key_versions
            .iter()
            .find(|v| v.version_number == header.key_version)
            .ok_or_else(|| {
                ops::rest_error(
                    StatusCode::NOT_FOUND,
                    "VersionNotFound",
                    "key version not found",
                )
            })?;
        let dec_entry = state
            .providers
            .resolve_for_version(&record, header.key_version)
            .map_err(map_core_err)?;
        let ec_aad = ec
            .as_ref()
            .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
            .unwrap_or_default();
        let aad = header.build_aad(&ec_aad);
        let plaintext = dec_entry
            .provider
            .decrypt(&version_record.key_handle, ciphertext, &aad)
            .await
            .map_err(map_core_err)?;
        Ok(Json(serde_json::json!({
            "plaintext": base64_encode(plaintext.expose()),
            "key_id": record.lid.to_string(),
        })))
    })
    .await
}

#[cfg(feature = "crypto-endpoints")]
async fn sign(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::Sign, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        let alg_str = body
            .get("signing_algorithm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let alg = parse_signing_algorithm(alg_str)?;
        let use_digest = parse_message_type_is_digest(&body)?;
        if use_digest && alg == keyrack_core::provider::SigningAlgorithm::Ed25519 {
            return Err(ops::rest_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "DIGEST message type is invalid for Ed25519",
            ));
        }
        let message_b64 = body.get("message").and_then(|v| v.as_str()).unwrap_or("");
        let message = base64_decode(message_b64)?;
        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| {
                ops::rest_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "NoVersion",
                    "no primary version",
                )
            })?;
        let sign_entry = state
            .providers
            .resolve_for_primary(&record)
            .map_err(map_core_err)?;
        let signature = if use_digest {
            sign_entry
                .provider
                .sign_digest(&primary.key_handle, alg, &message)
                .await
                .map_err(|e| {
                    ops::rest_error(StatusCode::BAD_REQUEST, "InvalidArgument", &e.to_string())
                })?
        } else {
            sign_entry
                .provider
                .sign(&primary.key_handle, alg, &message)
                .await
                .map_err(map_core_err)?
        };
        Ok(Json(serde_json::json!({
            "signature": base64_encode(&signature),
            "key_id": record.lid.to_string(),
            "signing_algorithm": alg_str,
        })))
    })
    .await
}

#[cfg(feature = "crypto-endpoints")]
async fn verify(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::Verify, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        let alg_str = body
            .get("signing_algorithm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let alg = parse_signing_algorithm(alg_str)?;
        let use_digest = parse_message_type_is_digest(&body)?;
        if use_digest && alg == keyrack_core::provider::SigningAlgorithm::Ed25519 {
            return Err(ops::rest_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "DIGEST message type is invalid for Ed25519",
            ));
        }
        let message = base64_decode(body.get("message").and_then(|v| v.as_str()).unwrap_or(""))?;
        let signature =
            base64_decode(body.get("signature").and_then(|v| v.as_str()).unwrap_or(""))?;
        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| {
                ops::rest_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "NoVersion",
                    "no primary version",
                )
            })?;
        let verify_entry = state
            .providers
            .resolve_for_primary(&record)
            .map_err(map_core_err)?;
        let valid = if use_digest {
            verify_entry
                .provider
                .verify_digest(&primary.key_handle, alg, &message, &signature)
                .await
                .map_err(|e| {
                    ops::rest_error(StatusCode::BAD_REQUEST, "InvalidArgument", &e.to_string())
                })?
        } else {
            verify_entry
                .provider
                .verify(&primary.key_handle, alg, &message, &signature)
                .await
                .map_err(map_core_err)?
        };
        Ok(Json(serde_json::json!({
            "signature_valid": valid,
            "key_id": record.lid.to_string(),
        })))
    })
    .await
}

#[cfg(feature = "crypto-endpoints")]
fn parse_signing_algorithm(s: &str) -> Result<keyrack_core::provider::SigningAlgorithm, RestError> {
    use keyrack_core::provider::SigningAlgorithm as A;
    Ok(match s {
        "ED25519" => A::Ed25519,
        "ECDSA_P256_SHA256" => A::EcdsaP256Sha256,
        "ECDSA_P256_SHA384" => A::EcdsaP256Sha384,
        "ECDSA_P384_SHA384" => A::EcdsaP384Sha384,
        "RSA_PKCS1_V15_SHA256" => A::RsaPkcs1v15Sha256,
        "RSA_PKCS1_V15_SHA384" => A::RsaPkcs1v15Sha384,
        "RSA_PKCS1_V15_SHA512" => A::RsaPkcs1v15Sha512,
        "RSA_PSS_SHA256" => A::RsaPssSha256,
        "RSA_PSS_SHA384" => A::RsaPssSha384,
        "RSA_PSS_SHA512" => A::RsaPssSha512,
        _ => {
            return Err(ops::rest_error(
                StatusCode::BAD_REQUEST,
                "InvalidAlgorithm",
                &format!("unknown signing_algorithm: {s}"),
            ))
        }
    })
}

/// Parse the optional `message_type` field. Defaults to RAW; returns
/// `true` when DIGEST was requested.
#[cfg(feature = "crypto-endpoints")]
fn parse_message_type_is_digest(body: &serde_json::Value) -> Result<bool, RestError> {
    match body
        .get("message_type")
        .and_then(|v| v.as_str())
        .unwrap_or("RAW")
    {
        "RAW" | "MESSAGE_TYPE_UNSPECIFIED" => Ok(false),
        "DIGEST" => Ok(true),
        other => Err(ops::rest_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            &format!("unknown message_type: {other}"),
        )),
    }
}

#[cfg(feature = "crypto-endpoints")]
fn parse_mac_algorithm(s: &str) -> Result<keyrack_core::provider::MacAlgorithm, RestError> {
    use keyrack_core::provider::MacAlgorithm as M;
    Ok(match s {
        "HMAC_SHA_256" => M::HmacSha256,
        "HMAC_SHA_384" => M::HmacSha384,
        "HMAC_SHA_512" => M::HmacSha512,
        _ => {
            return Err(ops::rest_error(
                StatusCode::BAD_REQUEST,
                "InvalidAlgorithm",
                &format!("unknown mac_algorithm: {s}"),
            ))
        }
    })
}

#[cfg(feature = "crypto-endpoints")]
async fn generate_mac(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::GenerateMac, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        let alg_str = body
            .get("mac_algorithm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let alg = parse_mac_algorithm(alg_str)?;
        let message = base64_decode(body.get("message").and_then(|v| v.as_str()).unwrap_or(""))?;
        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| {
                ops::rest_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "NoVersion",
                    "no primary version",
                )
            })?;
        let mac_entry = state
            .providers
            .resolve_for_primary(&record)
            .map_err(map_core_err)?;
        let mac = mac_entry
            .provider
            .generate_mac(&primary.key_handle, alg, &message)
            .await
            .map_err(map_core_err)?;
        Ok(Json(serde_json::json!({
            "mac": base64_encode(&mac),
            "key_id": record.lid.to_string(),
            "mac_algorithm": alg_str,
        })))
    })
    .await
}

#[cfg(feature = "crypto-endpoints")]
async fn verify_mac(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::VerifyMac, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        let alg_str = body
            .get("mac_algorithm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let alg = parse_mac_algorithm(alg_str)?;
        let message = base64_decode(body.get("message").and_then(|v| v.as_str()).unwrap_or(""))?;
        let mac = base64_decode(body.get("mac").and_then(|v| v.as_str()).unwrap_or(""))?;
        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| {
                ops::rest_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "NoVersion",
                    "no primary version",
                )
            })?;
        let mac_entry = state
            .providers
            .resolve_for_primary(&record)
            .map_err(map_core_err)?;
        let mac_valid = mac_entry
            .provider
            .verify_mac(&primary.key_handle, alg, &message, &mac)
            .await
            .map_err(map_core_err)?;
        Ok(Json(serde_json::json!({
            "mac_valid": mac_valid,
            "key_id": record.lid.to_string(),
            "mac_algorithm": alg_str,
        })))
    })
    .await
}

#[cfg(feature = "crypto-endpoints")]
async fn generate_data_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let ec_hash = body
        .get("encryption_context")
        .and_then(|v| v.as_object())
        .and_then(build_ec)
        .as_ref()
        .map(keyrack_core::encryption_context::EncryptionContext::hash);
    let mut op_ctx = OpContext::key(AuditAction::GenerateDataKey, principal, &key_id);
    op_ctx.encryption_context_hash = ec_hash;
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        if !record.state.permits_encrypt() {
            return Err(ops::rest_error(
                StatusCode::CONFLICT,
                "InvalidState",
                "key not in Enabled state",
            ));
        }
        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| {
                ops::rest_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "NoVersion",
                    "no primary version",
                )
            })?;
        let ec = body
            .get("encryption_context")
            .and_then(|v| v.as_object())
            .and_then(build_ec);
        let ec_aad = ec
            .as_ref()
            .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
            .unwrap_or_default();
        let ec_hash = ec.as_ref().map_or(
            [0u8; 32],
            keyrack_core::encryption_context::EncryptionContext::hash,
        );
        let header = keyrack_core::header::CiphertextHeader::new(
            record.lid,
            record.current_key_version,
            ec_hash,
        );
        let aad = header.build_aad(&ec_aad);
        #[allow(clippy::cast_possible_truncation)]
        let dek_len = body
            .get("number_of_bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(32) as usize;
        let gdek_entry = state
            .providers
            .resolve_for_primary(&record)
            .map_err(map_core_err)?;
        let output = gdek_entry
            .provider
            .generate_data_key(&primary.key_handle, dek_len, &aad)
            .await
            .map_err(map_core_err)?;
        Ok(Json(serde_json::json!({
            "plaintext_data_key": base64_encode(&output.plaintext_key.into_inner()),
            "encrypted_data_key": base64_encode(&header.wrap_payload(&output.encrypted_key)),
            "key_id": record.lid.to_string(),
        })))
    })
    .await
}

#[cfg(feature = "crypto-endpoints")]
async fn re_encrypt(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let dst_key_id = body
        .get("destination_key_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let ec_hash = body
        .get("destination_encryption_context")
        .and_then(|v| v.as_object())
        .and_then(build_ec)
        .as_ref()
        .map(keyrack_core::encryption_context::EncryptionContext::hash);
    let mut op_ctx = OpContext::key(AuditAction::ReEncrypt, principal, &key_id);
    op_ctx.encryption_context_hash = ec_hash;
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let src_lid = parse_lid_rest(&key_id)?;
        let dst_lid = parse_lid_rest(&dst_key_id)?;
        let src_record = state
            .storage
            .get_key(&src_lid)
            .await
            .map_err(map_core_err)?;
        let dst_record = state
            .storage
            .get_key(&dst_lid)
            .await
            .map_err(map_core_err)?;
        let blob_b64 = body
            .get("ciphertext_blob")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let blob = base64_decode(blob_b64)?;
        let (header, ciphertext) = keyrack_core::header::CiphertextHeader::unwrap_payload(&blob)
            .map_err(|e| {
                ops::rest_error(StatusCode::BAD_REQUEST, "InvalidCiphertext", &e.to_string())
            })?;
        let src_ec = body
            .get("source_encryption_context")
            .and_then(|v| v.as_object())
            .and_then(build_ec);
        let dst_ec = body
            .get("destination_encryption_context")
            .and_then(|v| v.as_object())
            .and_then(build_ec);
        let src_version = src_record
            .key_versions
            .iter()
            .find(|v| v.version_number == header.key_version)
            .ok_or_else(|| {
                ops::rest_error(
                    StatusCode::NOT_FOUND,
                    "VersionNotFound",
                    "source key version not found",
                )
            })?;
        let src_ec_aad = src_ec
            .as_ref()
            .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
            .unwrap_or_default();
        let src_aad = header.build_aad(&src_ec_aad);
        let src_re_entry = state
            .providers
            .resolve_for_version(&src_record, header.key_version)
            .map_err(map_core_err)?;
        let dst_re_entry = state
            .providers
            .resolve_for_primary(&dst_record)
            .map_err(map_core_err)?;
        let dst_primary = dst_record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| {
                ops::rest_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "NoVersion",
                    "dest has no primary",
                )
            })?;
        let dst_ec_hash = dst_ec.as_ref().map_or(
            [0u8; 32],
            keyrack_core::encryption_context::EncryptionContext::hash,
        );
        let new_header = keyrack_core::header::CiphertextHeader::new(
            dst_record.lid,
            dst_record.current_key_version,
            dst_ec_hash,
        );
        let dst_ec_aad = dst_ec
            .as_ref()
            .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
            .unwrap_or_default();
        let dst_aad = new_header.build_aad(&dst_ec_aad);
        let output = if std::sync::Arc::ptr_eq(&src_re_entry.provider, &dst_re_entry.provider) {
            src_re_entry
                .provider
                .re_encrypt(
                    &src_version.key_handle,
                    ciphertext,
                    &src_aad,
                    &dst_primary.key_handle,
                    &dst_aad,
                )
                .await
                .map_err(map_core_err)?
        } else {
            let plaintext = src_re_entry
                .provider
                .decrypt(&src_version.key_handle, ciphertext, &src_aad)
                .await
                .map_err(map_core_err)?;
            dst_re_entry
                .provider
                .encrypt(&dst_primary.key_handle, plaintext.expose(), &dst_aad)
                .await
                .map_err(map_core_err)?
        };
        Ok(Json(serde_json::json!({
            "ciphertext_blob": base64_encode(&new_header.wrap_payload(&output.ciphertext)),
            "source_key_id": src_record.lid.to_string(),
            "destination_key_id": dst_record.lid.to_string(),
        })))
    })
    .await
}

#[cfg(feature = "crypto-endpoints")]
async fn generate_random(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::resource(AuditAction::GenerateRandom, principal, "", "System");
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        #[allow(clippy::cast_possible_truncation)]
        let n = body
            .get("number_of_bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(32) as usize;
        let random = state
            .providers
            .default_entry()
            .provider
            .generate_random(n)
            .await
            .map_err(map_core_err)?;
        Ok(Json(
            serde_json::json!({ "random_bytes": base64_encode(random.expose()) }),
        ))
    })
    .await
}

// ── Tags ────────────────────────────────────────────────────────────

async fn list_resource_tags(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::ListResourceTags, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        let tags: Vec<_> = record
            .user_tags
            .iter()
            .map(|(k, v)| serde_json::json!({"key": k, "value": v}))
            .collect();
        Ok(Json(serde_json::json!({ "tags": tags })))
    })
    .await
}

async fn tag_resource(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::TagResource, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let mut record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        if let Some(tags) = body.get("tags").and_then(|v| v.as_array()) {
            for tag in tags {
                if let (Some(k), Some(v)) = (
                    tag.get("key").and_then(|v| v.as_str()),
                    tag.get("value").and_then(|v| v.as_str()),
                ) {
                    record.user_tags.set(k, v);
                }
            }
        }
        record.occ_version += 1;
        record.updated_at = chrono::Utc::now();
        state
            .storage
            .update_key(&record)
            .await
            .map_err(map_core_err)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

async fn untag_resource(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::key(AuditAction::UntagResource, principal, &key_id);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let lid = parse_lid_rest(&key_id)?;
        let mut record = state.storage.get_key(&lid).await.map_err(map_core_err)?;
        if let Some(keys) = body.get("tag_keys").and_then(|v| v.as_array()) {
            for key in keys {
                if let Some(k) = key.as_str() {
                    record.user_tags.remove(k);
                }
            }
        }
        record.occ_version += 1;
        record.updated_at = chrono::Utc::now();
        state
            .storage
            .update_key(&record)
            .await
            .map_err(map_core_err)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

// ── Aliases ─────────────────────────────────────────────────────────

async fn create_alias(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let alias_name = body
        .get("alias_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let mut op_ctx = OpContext::alias(AuditAction::CreateAlias, principal, &alias_name);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        let target_key_id = body
            .get("target_key_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let lid = parse_lid_rest(target_key_id)?;
        let alias = keyrack_core::storage::AliasRecord {
            alias_name: alias_name.clone(),
            target_lid: lid,
            created_at: chrono::Utc::now(),
        };
        state
            .storage
            .create_alias(&alias)
            .await
            .map_err(map_core_err)?;
        Ok((
            StatusCode::CREATED,
            Json(serde_json::json!({ "alias_name": alias_name, "target_key_id": target_key_id })),
        ))
    })
    .await
}

async fn list_aliases(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::alias(AuditAction::ListAliases, principal, "");
    op_ctx.request_id = request_id;
    ops::execute_rest(
        &state,
        op_ctx,
        |state| async move {
            let aliases = state.storage.list_aliases().await.map_err(map_core_err)?;
            let items: Vec<_> = aliases.iter().map(|a| serde_json::json!({ "alias_name": a.alias_name, "target_key_id": a.target_lid.to_string() })).collect();
            Ok(Json(serde_json::json!({ "aliases": items })))
        },
    ).await
}

async fn delete_alias(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(alias_name): Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let request_id = ops::extract_request_id_rest(&headers);
    let principal = ops::extract_principal_rest(&state, &headers).await;
    let mut op_ctx = OpContext::alias(AuditAction::DeleteAlias, principal, &alias_name);
    op_ctx.request_id = request_id;
    ops::execute_rest(&state, op_ctx, |state| async move {
        state
            .storage
            .delete_alias(&alias_name)
            .await
            .map_err(map_core_err)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

// ── Health / Readiness / Metrics ────────────────────────────────────

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let storage_ok = state.storage.ping().await.is_ok();

    let caps = state.providers.default_entry().provider.capabilities();
    let provider_ok = !caps.key_specs.is_empty();

    let status = if storage_ok && provider_ok {
        "ok"
    } else {
        "degraded"
    };
    let code = if storage_ok && provider_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        code,
        Json(serde_json::json!({
            "status": status,
            "components": {
                "storage": if storage_ok { "ok" } else { "error" },
                "provider": if provider_ok { "ok" } else { "error" },
            }
        })),
    )
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let storage_ok = state.storage.ping().await.is_ok();
    if storage_ok {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ready", "storage": "ok" })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "not_ready", "storage": "error" })),
        )
    }
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    state.metrics_handle.render()
}

// ── Helpers ─────────────────────────────────────────────────────────

fn parse_lid_rest(s: &str) -> Result<keyrack_core::lid::Lid, RestError> {
    s.parse().map_err(|_| {
        ops::rest_error(
            StatusCode::BAD_REQUEST,
            "InvalidKeyId",
            &format!("invalid key_id: {s}"),
        )
    })
}

#[cfg(feature = "crypto-endpoints")]
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(feature = "crypto-endpoints")]
fn base64_decode(s: &str) -> Result<Vec<u8>, RestError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| {
            ops::rest_error(
                StatusCode::BAD_REQUEST,
                "InvalidBase64",
                "invalid base64 encoding",
            )
        })
}
