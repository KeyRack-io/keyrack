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

pub mod aws_backend;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{body::Bytes, Json, Router};
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum KmsProxyError {
    #[error("upstream KMS error: {0}")]
    UpstreamError(String),

    #[error("metadata store error: {0}")]
    MetadataError(String),

    #[error("request parse error: {0}")]
    ParseError(#[from] keyrack_aws_common::KmsError),
}

const AMZ_JSON_CONTENT_TYPE: &str = "application/x-amz-json-1.1";

impl IntoResponse for KmsProxyError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match &self {
            Self::UpstreamError(msg) => (
                StatusCode::BAD_GATEWAY,
                keyrack_aws_common::error_response("DependencyException", msg),
            ),
            Self::MetadataError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                keyrack_aws_common::error_response("InternalServiceError", msg),
            ),
            Self::ParseError(e) => (
                StatusCode::BAD_REQUEST,
                keyrack_aws_common::error_response("ValidationException", &e.to_string()),
            ),
        };
        (
            status,
            [(header::CONTENT_TYPE, AMZ_JSON_CONTENT_TYPE)],
            Json(body),
        )
            .into_response()
    }
}

// ── KMS backend trait ───────────────────────────────────────────────

#[async_trait]
pub trait KmsBackend: Send + Sync {
    async fn forward_request(
        &self,
        action: keyrack_aws_common::KmsAction,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, KmsProxyError>;
}

// ── Key metadata ────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyMetadata {
    pub aws_key_id: String,
    pub aws_arn: Option<String>,
    pub description: Option<String>,
    pub key_state: String,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub rotation_count: u64,
}

// ── Metadata store trait ────────────────────────────────────────────

#[async_trait]
pub trait MetadataStore: Send + Sync {
    async fn record_key_event(
        &self,
        key_id: &str,
        action: &keyrack_aws_common::KmsAction,
        response: &serde_json::Value,
    ) -> Result<(), KmsProxyError>;

    async fn get_key_metadata(&self, key_id: &str) -> Result<Option<KeyMetadata>, KmsProxyError>;

    async fn list_tracked_keys(&self) -> Result<Vec<KeyMetadata>, KmsProxyError>;
}

// ── In-memory metadata store ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InMemoryMetadataStore {
    keys: Arc<Mutex<HashMap<String, KeyMetadata>>>,
}

impl InMemoryMetadataStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryMetadataStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MetadataStore for InMemoryMetadataStore {
    async fn record_key_event(
        &self,
        key_id: &str,
        action: &keyrack_aws_common::KmsAction,
        response: &serde_json::Value,
    ) -> Result<(), KmsProxyError> {
        let now = Utc::now();
        let mut store = self.keys.lock().await;

        let arn = response
            .pointer("/KeyMetadata/Arn")
            .or_else(|| response.get("KeyId"))
            .and_then(serde_json::Value::as_str)
            .filter(|s| s.starts_with("arn:"))
            .map(String::from);

        let description = response
            .pointer("/KeyMetadata/Description")
            .and_then(serde_json::Value::as_str)
            .map(String::from);

        let key_state = response
            .pointer("/KeyMetadata/KeyState")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Unknown")
            .to_string();

        if let Some(existing) = store.get_mut(key_id) {
            existing.last_seen_at = now;
            if let Some(ref a) = arn {
                existing.aws_arn = Some(a.clone());
            }
            if let Some(ref d) = description {
                existing.description = Some(d.clone());
            }
            if key_state != "Unknown" {
                existing.key_state = key_state;
            }
            if *action == keyrack_aws_common::KmsAction::EnableKeyRotation {
                existing.rotation_count += 1;
            }
        } else {
            store.insert(
                key_id.to_string(),
                KeyMetadata {
                    aws_key_id: key_id.to_string(),
                    aws_arn: arn,
                    description,
                    key_state,
                    created_at: now,
                    last_seen_at: now,
                    rotation_count: 0,
                },
            );
        }

        Ok(())
    }

    async fn get_key_metadata(&self, key_id: &str) -> Result<Option<KeyMetadata>, KmsProxyError> {
        let store = self.keys.lock().await;
        Ok(store.get(key_id).cloned())
    }

    async fn list_tracked_keys(&self) -> Result<Vec<KeyMetadata>, KmsProxyError> {
        let store = self.keys.lock().await;
        Ok(store.values().cloned().collect())
    }
}

// ── Shared proxy state ──────────────────────────────────────────────

pub struct ProxyState {
    pub backend: Box<dyn KmsBackend>,
    pub metadata: Box<dyn MetadataStore>,
}

// ── Proxy handler ───────────────────────────────────────────────────

/// Main KMS proxy handler.
///
/// Parses the `X-Amz-Target` header, forwards the request to the
/// configured `KmsBackend`, records key metadata, and returns the
/// upstream response.
pub async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, KmsProxyError> {
    let target = headers
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            KmsProxyError::ParseError(keyrack_aws_common::KmsError::MalformedRequest(
                "missing X-Amz-Target header".into(),
            ))
        })?;

    let action = keyrack_aws_common::parse_action(target)?;

    let body: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        KmsProxyError::ParseError(keyrack_aws_common::KmsError::MalformedRequest(
            e.to_string(),
        ))
    })?;

    tracing::info!(?action, "proxying KMS request");

    let response = state.backend.forward_request(action, body.clone()).await?;

    if let Some(key_id) = extract_key_id(&action, &body, &response) {
        if let Err(e) = state
            .metadata
            .record_key_event(&key_id, &action, &response)
            .await
        {
            tracing::warn!(%e, "failed to record key metadata (non-fatal)");
        }
    }

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, AMZ_JSON_CONTENT_TYPE)],
        Json(response),
    ))
}

/// Extracts the key ID from the request body or response, depending on
/// the action type. Returns `None` for actions that don't involve a
/// specific key (e.g. `GenerateRandom`, `ListKeys`).
fn extract_key_id(
    action: &keyrack_aws_common::KmsAction,
    request: &serde_json::Value,
    response: &serde_json::Value,
) -> Option<String> {
    use keyrack_aws_common::KmsAction;

    match action {
        KmsAction::GenerateRandom | KmsAction::ListKeys | KmsAction::ListAliases => None,
        KmsAction::CreateKey => response
            .pointer("/KeyMetadata/KeyId")
            .and_then(serde_json::Value::as_str)
            .map(String::from),
        _ => request
            .get("KeyId")
            .and_then(serde_json::Value::as_str)
            .map(String::from)
            .or_else(|| {
                request
                    .get("TargetKeyId")
                    .and_then(serde_json::Value::as_str)
                    .map(String::from)
            }),
    }
}

// ── Admin router ────────────────────────────────────────────────────

/// Returns an Axum router with admin/observability endpoints for
/// inspecting tracked key metadata and service health.
pub fn admin_router() -> Router<Arc<ProxyState>> {
    Router::new()
        .route("/admin/keys", get(admin_list_keys))
        .route("/admin/keys/{key_id}", get(admin_get_key))
        .route("/admin/health", get(admin_health))
}

async fn admin_list_keys(
    State(state): State<Arc<ProxyState>>,
) -> Result<impl IntoResponse, KmsProxyError> {
    let keys = state.metadata.list_tracked_keys().await?;
    Ok(Json(serde_json::json!({ "keys": keys })))
}

async fn admin_get_key(
    State(state): State<Arc<ProxyState>>,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, KmsProxyError> {
    match state.metadata.get_key_metadata(&key_id).await? {
        Some(meta) => {
            Ok((StatusCode::OK, Json(serde_json::to_value(meta).unwrap())).into_response())
        }
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(keyrack_aws_common::error_response(
                "NotFoundException",
                &format!("Key {key_id} is not tracked"),
            )),
        )
            .into_response()),
    }
}

async fn admin_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "keyrack-aws-proxy",
    }))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_store_tracks_keys() {
        let store = InMemoryMetadataStore::new();
        let action = keyrack_aws_common::KmsAction::CreateKey;
        let response = serde_json::json!({
            "KeyMetadata": {
                "KeyId": "abc-123",
                "Arn": "arn:aws:kms:us-east-1:000000000000:key/abc-123",
                "Description": "test key",
                "KeyState": "Enabled"
            }
        });

        store
            .record_key_event("abc-123", &action, &response)
            .await
            .unwrap();

        let meta = store.get_key_metadata("abc-123").await.unwrap().unwrap();
        assert_eq!(meta.aws_key_id, "abc-123");
        assert_eq!(
            meta.aws_arn.as_deref(),
            Some("arn:aws:kms:us-east-1:000000000000:key/abc-123")
        );
        assert_eq!(meta.description.as_deref(), Some("test key"));
        assert_eq!(meta.key_state, "Enabled");
        assert_eq!(meta.rotation_count, 0);
    }

    #[tokio::test]
    async fn in_memory_store_updates_existing() {
        let store = InMemoryMetadataStore::new();
        let response = serde_json::json!({
            "KeyMetadata": { "KeyId": "abc-123", "KeyState": "Enabled" }
        });
        store
            .record_key_event(
                "abc-123",
                &keyrack_aws_common::KmsAction::CreateKey,
                &response,
            )
            .await
            .unwrap();

        let rotation_resp = serde_json::json!({});
        store
            .record_key_event(
                "abc-123",
                &keyrack_aws_common::KmsAction::EnableKeyRotation,
                &rotation_resp,
            )
            .await
            .unwrap();

        let meta = store.get_key_metadata("abc-123").await.unwrap().unwrap();
        assert_eq!(meta.rotation_count, 1);
    }

    #[tokio::test]
    async fn in_memory_store_list_keys() {
        let store = InMemoryMetadataStore::new();
        let resp = serde_json::json!({});

        store
            .record_key_event("key-1", &keyrack_aws_common::KmsAction::DescribeKey, &resp)
            .await
            .unwrap();
        store
            .record_key_event("key-2", &keyrack_aws_common::KmsAction::DescribeKey, &resp)
            .await
            .unwrap();

        let keys = store.list_tracked_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn extract_key_id_from_create_response() {
        let action = keyrack_aws_common::KmsAction::CreateKey;
        let req = serde_json::json!({ "Description": "my key" });
        let resp = serde_json::json!({
            "KeyMetadata": { "KeyId": "new-key-id" }
        });
        assert_eq!(
            extract_key_id(&action, &req, &resp),
            Some("new-key-id".into())
        );
    }

    #[test]
    fn extract_key_id_from_encrypt_request() {
        let action = keyrack_aws_common::KmsAction::Encrypt;
        let req = serde_json::json!({ "KeyId": "my-key" });
        let resp = serde_json::json!({});
        assert_eq!(extract_key_id(&action, &req, &resp), Some("my-key".into()));
    }

    #[test]
    fn extract_key_id_returns_none_for_generate_random() {
        let action = keyrack_aws_common::KmsAction::GenerateRandom;
        let req = serde_json::json!({});
        let resp = serde_json::json!({});
        assert_eq!(extract_key_id(&action, &req, &resp), None);
    }
}
