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

use keyrack_cedar_pdp::engine::CedarEngine;
use keyrack_cedar_pdp::server;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let policy_path =
        std::env::var("CEDAR_POLICY_PATH").unwrap_or_else(|_| "policies.cedar".into());
    let schema_path = std::env::var("CEDAR_SCHEMA_PATH").ok();

    let policies_src = std::fs::read_to_string(&policy_path).unwrap_or_else(|_| {
        tracing::warn!(path = %policy_path, "policy file not found, using empty policy set");
        String::new()
    });

    let schema_src = schema_path.as_ref().and_then(|p| {
        std::fs::read_to_string(p)
            .map_err(|e| {
                tracing::warn!(path = %p, error = %e, "schema file not found");
                e
            })
            .ok()
    });

    let engine = Arc::new(
        CedarEngine::new(&policies_src, schema_src.as_deref())
            .map_err(|e| format!("failed to initialize Cedar engine: {e}"))?,
    );

    let addr: std::net::SocketAddr = std::env::var("CEDAR_PDP_ADDR")
        .unwrap_or_else(|_| "[::1]:8181".into())
        .parse()?;

    tracing::info!(%addr, "starting keyrack-cedar-pdp");

    let router = server::router(engine);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
