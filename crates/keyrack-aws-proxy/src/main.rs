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

use std::sync::Arc;

use axum::routing::post;
use axum::Router;
use keyrack_aws_proxy::{
    admin_router, aws_backend::AwsKmsBackend, proxy_handler, InMemoryMetadataStore, ProxyState,
};
use tokio::net::TcpListener;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,keyrack_aws_proxy=debug".into()),
        )
        .init();

    let region = env_or("AWS_REGION", "us-east-1");
    let proxy_port: u16 = env_or("PROXY_PORT", "8080").parse()?;
    let admin_port: u16 = env_or("ADMIN_PORT", "8081").parse()?;
    let custom_endpoint = std::env::var("KMS_ENDPOINT").ok();

    tracing::info!(
        %region,
        %proxy_port,
        %admin_port,
        custom_endpoint = custom_endpoint.as_deref().unwrap_or("<default>"),
        "starting keyrack-aws-proxy"
    );

    let backend = AwsKmsBackend::new(&region, custom_endpoint.as_deref()).await;
    let metadata = InMemoryMetadataStore::new();

    let state = Arc::new(ProxyState {
        backend: Box::new(backend),
        metadata: Box::new(metadata),
    });

    let proxy_router = Router::new()
        .route("/", post(proxy_handler))
        .fallback(proxy_handler)
        .with_state(state.clone());

    let admin_app = admin_router().with_state(state);

    let proxy_listener = TcpListener::bind(format!("0.0.0.0:{proxy_port}")).await?;
    let admin_listener = TcpListener::bind(format!("0.0.0.0:{admin_port}")).await?;

    tracing::info!("proxy listening on 0.0.0.0:{proxy_port}");
    tracing::info!("admin API listening on 0.0.0.0:{admin_port}");

    tokio::try_join!(
        async { axum::serve(proxy_listener, proxy_router).await.map_err(anyhow::Error::from) },
        async { axum::serve(admin_listener, admin_app).await.map_err(anyhow::Error::from) },
    )?;

    Ok(())
}
