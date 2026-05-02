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
