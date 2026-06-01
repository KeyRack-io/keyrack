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

//! HTTP server for the Cedar PDP.

use crate::engine::CedarEngine;
use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use keyrack_core::pdp::AuthzRequest;
use std::sync::Arc;

pub fn router(engine: Arc<CedarEngine>) -> Router {
    Router::new()
        .route("/v1/authorize", post(authorize))
        .route("/healthz", get(healthz))
        .route("/v1/policies/count", get(policy_count))
        .with_state(engine)
}

async fn authorize(
    State(engine): State<Arc<CedarEngine>>,
    Json(req): Json<AuthzRequest>,
) -> impl IntoResponse {
    match engine.evaluate(&req).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(&resp).unwrap_or_default())),
        Err(e) => {
            tracing::error!(error = %e, "Cedar evaluation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
        }
    }
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn policy_count(State(engine): State<Arc<CedarEngine>>) -> impl IntoResponse {
    let count = engine.policy_count().await;
    Json(serde_json::json!({ "policy_count": count }))
}
