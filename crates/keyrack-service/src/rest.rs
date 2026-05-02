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

//! REST gateway layer.
//!
//! Provides a JSON-over-HTTP surface for all `KeyService` operations.
//! REST is mandatory for V1 per `KEYRACK_SPEC.md` §3.1 — the console,
//! CLI, SDKs, and Terraform provider all consume REST.
//!
//! Route conventions:
//! - Resource routes: `GET /v1/keys`, `POST /v1/keys`, `GET /v1/keys/:key_id`
//! - Action endpoints: `POST /v1/keys/:key_id/actions-encrypt`
//! - Sub-resource paths: `GET /v1/keys/:key_id/versions`

use crate::state::ServiceState;
use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::Router;
use std::sync::Arc;

type AppState = Arc<ServiceState>;

pub fn router(state: AppState) -> Router {
    Router::new()
        // ── Key lifecycle ───────────────────────────────────
        .route("/v1/keys", post(create_key))
        .route("/v1/keys", get(list_keys))
        .route("/v1/keys/{key_id}", get(get_key))
        .route("/v1/keys/{key_id}", put(update_key))
        .route("/v1/keys/{key_id}/describe", get(describe_key))
        .route("/v1/keys/{key_id}/actions-enable", post(enable_key))
        .route("/v1/keys/{key_id}/actions-disable", post(disable_key))
        .route(
            "/v1/keys/{key_id}/actions-schedule-deletion",
            post(schedule_key_deletion),
        )
        .route(
            "/v1/keys/{key_id}/actions-cancel-deletion",
            post(cancel_key_deletion),
        )
        .route("/v1/keys/{key_id}/actions-rotate", post(rotate_key))
        // ── Crypto operations ───────────────────────────────
        .route("/v1/keys/{key_id}/actions-encrypt", post(encrypt))
        .route("/v1/keys/{key_id}/actions-decrypt", post(decrypt))
        .route("/v1/keys/{key_id}/actions-sign", post(sign))
        .route("/v1/keys/{key_id}/actions-verify", post(verify))
        .route(
            "/v1/keys/{key_id}/actions-generate-data-key",
            post(generate_data_key),
        )
        .route(
            "/v1/keys/{key_id}/actions-re-encrypt",
            post(re_encrypt),
        )
        .route("/v1/generate-random", post(generate_random))
        // ── Tags ────────────────────────────────────────────
        .route("/v1/keys/{key_id}/tags", get(list_resource_tags))
        .route("/v1/keys/{key_id}/tags", post(tag_resource))
        .route("/v1/keys/{key_id}/tags", delete(untag_resource))
        // ── Aliases ─────────────────────────────────────────
        .route("/v1/aliases", post(create_alias))
        .route("/v1/aliases", get(list_aliases))
        .route("/v1/aliases/{alias_name}", delete(delete_alias))
        // ── Health / ops ────────────────────────────────────
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_stub))
        .with_state(state)
}

/// Map a `KeyRackError` into an HTTP response.
#[allow(clippy::needless_pass_by_value)]
fn map_err(err: keyrack_core::error::KeyRackError) -> (StatusCode, Json<ErrorBody>) {
    use keyrack_core::error::KeyRackError;
    let (code, kind) = match &err {
        KeyRackError::KeyNotFound(_) => (StatusCode::NOT_FOUND, "KeyNotFound"),
        KeyRackError::OptimisticConcurrencyConflict { .. } => (StatusCode::CONFLICT, "OccConflict"),
        KeyRackError::InvalidStateTransition { .. } => {
            (StatusCode::CONFLICT, "InvalidStateTransition")
        }
        KeyRackError::OperationNotPermitted { .. } => (StatusCode::FORBIDDEN, "OperationNotPermitted"),
        KeyRackError::ImmutableTag { .. } => (StatusCode::BAD_REQUEST, "ImmutableTag"),
        KeyRackError::EncryptionContextMismatch => {
            (StatusCode::BAD_REQUEST, "EncryptionContextMismatch")
        }
        KeyRackError::AuthorizationDenied { .. } => (StatusCode::FORBIDDEN, "AuthorizationDenied"),
        KeyRackError::DepthLimitExceeded { .. } => {
            (StatusCode::BAD_REQUEST, "DepthLimitExceeded")
        }
        KeyRackError::CycleDetected { .. } => (StatusCode::BAD_REQUEST, "CycleDetected"),
        KeyRackError::CascadeDisableFailed { .. }
        | KeyRackError::Provider(_)
        | KeyRackError::Storage(_)
        | KeyRackError::Other(_) => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
    };
    (
        code,
        Json(ErrorBody {
            error: kind.into(),
            message: err.to_string(),
        }),
    )
}

#[derive(serde::Serialize)]
struct ErrorBody {
    error: String,
    message: String,
}

// ── Handlers ────────────────────────────────────────────────────────

async fn create_key(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let spec_str = body.get("key_spec").and_then(|v| v.as_str()).unwrap_or("AES_256");
    let spec = match spec_str {
        "AES_256" => keyrack_core::key::KeySpec::Aes256,
        "ED25519" => keyrack_core::key::KeySpec::Ed25519,
        "ECDSA_P256" => keyrack_core::key::KeySpec::EcdsaP256Sha256,
        "RSA_2048" => keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 },
        "RSA_3072" => keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size: 3072 },
        "RSA_4096" => keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size: 4096 },
        _ => return Err((StatusCode::BAD_REQUEST, Json(ErrorBody { error: "InvalidKeySpec".into(), message: format!("unknown key_spec: {spec_str}") }))),
    };

    let handle = state.provider.generate_key(&spec).await.map_err(map_err)?;
    let attrs = keyrack_core::attr::AttributeSet::new();
    let canonical = keyrack_core::canon::canonicalize(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &attrs,
    );
    let lid = keyrack_core::lid::Lid::derive(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &canonical,
    );

    let now = chrono::Utc::now();
    let key_usage = match spec {
        keyrack_core::key::KeySpec::Aes256 => keyrack_core::key::KeyUsage::EncryptDecrypt,
        _ => keyrack_core::key::KeyUsage::SignVerify,
    };

    let desc = body
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    let record = keyrack_core::key::KeyRecord {
        lid,
        canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
        parent_lid: None,
        occ_version: 1,
        current_key_version: 1,
        state: keyrack_core::key::KeyState::Enabled,
        key_usage,
        key_spec: spec,
        origin: keyrack_core::key::KeyOrigin::KeyRack,
        provider_class: keyrack_core::key::ProviderClass::Software,
        identity_tags: keyrack_core::tags::IdentityTags::from_attribute_set(&attrs),
        user_tags: keyrack_core::tags::UserTags::new(),
        created_at: now,
        updated_at: now,
        scheduled_deletion_at: None,
        description: desc,
        key_versions: vec![keyrack_core::key::KeyVersionRecord {
            version_number: 1,
            key_handle: handle,
            created_at: now,
            is_primary: true,
        }],
    };

    state.storage.create_key(&record).await.map_err(map_err)?;
    Ok((StatusCode::CREATED, Json(serde_json::to_value(&record).unwrap_or_default())))
}

async fn get_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> impl IntoResponse {
    let lid = parse_lid_rest(&key_id)?;
    let record = state.storage.get_key(&lid).await.map_err(map_err)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::to_value(&record).unwrap_or_default()))
}

async fn describe_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> impl IntoResponse {
    let lid = parse_lid_rest(&key_id)?;
    let record = state.storage.get_key(&lid).await.map_err(map_err)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::to_value(&record).unwrap_or_default()))
}

async fn update_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let lid = parse_lid_rest(&key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(map_err)?;
    if let Some(desc) = body.get("description").and_then(|v| v.as_str()) {
        desc.clone_into(&mut record.description);
    }
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state.storage.update_key(&record).await.map_err(map_err)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::to_value(&record).unwrap_or_default()))
}

async fn list_keys(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let filter = keyrack_core::storage::KeyFilter {
        user_tags: vec![],
        limit: Some(100),
        cursor: None,
    };
    let page = state.storage.list_keys(&filter).await.map_err(map_err)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::to_value(&page).unwrap_or_default()))
}

async fn enable_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> impl IntoResponse {
    let lid = parse_lid_rest(&key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(map_err)?;
    record.transition_to(keyrack_core::key::KeyState::Enabled).map_err(|(from, to)| {
        (StatusCode::CONFLICT, Json(ErrorBody { error: "InvalidStateTransition".into(), message: format!("cannot transition from {from} to {to}") }))
    })?;
    state.storage.update_key(&record).await.map_err(map_err)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::to_value(&record).unwrap_or_default()))
}

async fn disable_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> impl IntoResponse {
    let lid = parse_lid_rest(&key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(map_err)?;
    record.transition_to(keyrack_core::key::KeyState::Disabled).map_err(|(from, to)| {
        (StatusCode::CONFLICT, Json(ErrorBody { error: "InvalidStateTransition".into(), message: format!("cannot transition from {from} to {to}") }))
    })?;
    state.storage.update_key(&record).await.map_err(map_err)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::to_value(&record).unwrap_or_default()))
}

async fn schedule_key_deletion(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let lid = parse_lid_rest(&key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(map_err)?;
    let days = body.get("grace_period_days").and_then(serde_json::Value::as_u64).unwrap_or(7);
    record.transition_to(keyrack_core::key::KeyState::PendingDeletion).map_err(|(from, to)| {
        (StatusCode::CONFLICT, Json(ErrorBody { error: "InvalidStateTransition".into(), message: format!("cannot transition from {from} to {to}") }))
    })?;
    #[allow(clippy::cast_possible_wrap)]
    {
        record.scheduled_deletion_at = Some(chrono::Utc::now() + chrono::Duration::days(days as i64));
    }
    state.storage.update_key(&record).await.map_err(map_err)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::to_value(&record).unwrap_or_default()))
}

async fn cancel_key_deletion(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> impl IntoResponse {
    let lid = parse_lid_rest(&key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(map_err)?;
    if record.state != keyrack_core::key::KeyState::PendingDeletion {
        return Err((StatusCode::CONFLICT, Json(ErrorBody {
            error: "InvalidStateTransition".into(),
            message: "can only cancel deletion from PendingDeletion".into(),
        })));
    }
    record.transition_to(keyrack_core::key::KeyState::Disabled).map_err(|(from, to)| {
        (StatusCode::CONFLICT, Json(ErrorBody { error: "InvalidStateTransition".into(), message: format!("cannot transition from {from} to {to}") }))
    })?;
    record.scheduled_deletion_at = None;
    state.storage.update_key(&record).await.map_err(map_err)?;
    Ok(Json(serde_json::to_value(&record).unwrap_or_default()))
}

async fn rotate_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> impl IntoResponse {
    let lid = parse_lid_rest(&key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(map_err)?;
    if record.state != keyrack_core::key::KeyState::Enabled {
        return Err((StatusCode::CONFLICT, Json(ErrorBody { error: "InvalidState".into(), message: "key must be Enabled to rotate".into() })));
    }
    let handle = state.provider.generate_key(&record.key_spec).await.map_err(map_err)?;
    let new_version = record.current_key_version + 1;
    for v in &mut record.key_versions {
        v.is_primary = false;
    }
    record.key_versions.push(keyrack_core::key::KeyVersionRecord {
        version_number: new_version,
        key_handle: handle,
        created_at: chrono::Utc::now(),
        is_primary: true,
    });
    record.current_key_version = new_version;
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state.storage.update_key(&record).await.map_err(map_err)?;
    Ok(Json(serde_json::to_value(&record).unwrap_or_default()))
}

// ── Crypto action handlers ──────────────────────────────────────────

async fn encrypt(
    State(_state): State<AppState>,
    Path(_key_id): Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(ErrorBody { error: "NotImplemented".into(), message: "REST encrypt not yet wired".into() }))
}

async fn decrypt(
    State(_state): State<AppState>,
    Path(_key_id): Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(ErrorBody { error: "NotImplemented".into(), message: "REST decrypt not yet wired".into() }))
}

async fn sign(
    State(_state): State<AppState>,
    Path(_key_id): Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(ErrorBody { error: "NotImplemented".into(), message: "REST sign not yet wired".into() }))
}

async fn verify(
    State(_state): State<AppState>,
    Path(_key_id): Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(ErrorBody { error: "NotImplemented".into(), message: "REST verify not yet wired".into() }))
}

async fn generate_data_key(
    State(_state): State<AppState>,
    Path(_key_id): Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(ErrorBody { error: "NotImplemented".into(), message: "REST generate_data_key not yet wired".into() }))
}

async fn re_encrypt(
    State(_state): State<AppState>,
    Path(_key_id): Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(ErrorBody { error: "NotImplemented".into(), message: "REST re_encrypt not yet wired".into() }))
}

async fn generate_random(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    #[allow(clippy::cast_possible_truncation)]
    let n = body.get("number_of_bytes").and_then(serde_json::Value::as_u64).unwrap_or(32) as usize;
    let random = state.provider.generate_random(n).await.map_err(map_err)?;
    let encoded = base64_encode(random.expose());
    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::json!({ "random_bytes": encoded })))
}

// ── Tags ────────────────────────────────────────────────────────────

async fn list_resource_tags(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> impl IntoResponse {
    let lid = parse_lid_rest(&key_id)?;
    let record = state.storage.get_key(&lid).await.map_err(map_err)?;
    let tags: Vec<_> = record.user_tags.iter().map(|(k, v)| serde_json::json!({"key": k, "value": v})).collect();
    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::json!({ "tags": tags })))
}

async fn tag_resource(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let lid = parse_lid_rest(&key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(map_err)?;
    if let Some(tags) = body.get("tags").and_then(|v| v.as_array()) {
        for tag in tags {
            if let (Some(k), Some(v)) = (tag.get("key").and_then(|v| v.as_str()), tag.get("value").and_then(|v| v.as_str())) {
                record.user_tags.set(k, v);
            }
        }
    }
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state.storage.update_key(&record).await.map_err(map_err)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>(StatusCode::NO_CONTENT)
}

async fn untag_resource(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let lid = parse_lid_rest(&key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(map_err)?;
    if let Some(keys) = body.get("tag_keys").and_then(|v| v.as_array()) {
        for key in keys {
            if let Some(k) = key.as_str() {
                record.user_tags.remove(k);
            }
        }
    }
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state.storage.update_key(&record).await.map_err(map_err)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>(StatusCode::NO_CONTENT)
}

// ── Aliases ─────────────────────────────────────────────────────────

async fn create_alias(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let alias_name = body.get("alias_name").and_then(|v| v.as_str()).unwrap_or("");
    let target_key_id = body.get("target_key_id").and_then(|v| v.as_str()).unwrap_or("");
    let lid = parse_lid_rest(target_key_id)?;
    let alias = keyrack_core::storage::AliasRecord {
        alias_name: alias_name.to_owned(),
        target_lid: lid,
        created_at: chrono::Utc::now(),
    };
    state.storage.create_alias(&alias).await.map_err(map_err)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>((StatusCode::CREATED, Json(serde_json::json!({
        "alias_name": alias_name,
        "target_key_id": target_key_id,
    }))))
}

async fn list_aliases(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let aliases = state.storage.list_aliases().await.map_err(map_err)?;
    let items: Vec<_> = aliases.iter().map(|a| serde_json::json!({
        "alias_name": a.alias_name,
        "target_key_id": a.target_lid.to_string(),
    })).collect();
    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::json!({ "aliases": items })))
}

async fn delete_alias(
    State(state): State<AppState>,
    Path(alias_name): Path<String>,
) -> impl IntoResponse {
    state.storage.delete_alias(&alias_name).await.map_err(map_err)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>(StatusCode::NO_CONTENT)
}

// ── Helpers ─────────────────────────────────────────────────────────

// ── Health / Readiness / Metrics ─────────────────────────────────────

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let storage_ok = state.storage.ping().await.is_ok();
    if storage_ok {
        (StatusCode::OK, Json(serde_json::json!({ "status": "ready", "storage": "ok" })))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "status": "not_ready", "storage": "error" })))
    }
}

async fn metrics_stub() -> impl IntoResponse {
    (StatusCode::OK, "# HELP keyrack_up KeyRack service is up\n# TYPE keyrack_up gauge\nkeyrack_up 1\n")
}

fn parse_lid_rest(s: &str) -> Result<keyrack_core::lid::Lid, (StatusCode, Json<ErrorBody>)> {
    s.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "InvalidKeyId".into(),
                message: format!("invalid key_id: {s}"),
            }),
        )
    })
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}
