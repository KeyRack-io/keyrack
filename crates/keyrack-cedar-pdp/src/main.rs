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
