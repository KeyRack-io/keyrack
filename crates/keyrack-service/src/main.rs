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

use keyrack_service::config::ServiceConfig;
use keyrack_service::grpc::KeyServiceImpl;
use keyrack_service::proto::key_service_server::KeyServiceServer;
use keyrack_service::state::ServiceState;
use std::sync::Arc;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = load_config()?;

    let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus metrics recorder");

    let state = Arc::new(build_state(&config, metrics_handle).await?);

    let grpc_addr = config.grpc_addr.parse()?;
    let rest_addr: std::net::SocketAddr = config.rest_addr.parse()?;

    let cancel = tokio_util::sync::CancellationToken::new();

    let rest_router = keyrack_service::rest::router(Arc::clone(&state));
    let grpc_service = KeyServiceServer::new(KeyServiceImpl::new(Arc::clone(&state)));

    tracing::info!(%grpc_addr, %rest_addr, "starting KeyRack gRPC + REST service");

    let rest_cancel = cancel.clone();
    let rest_listener = tokio::net::TcpListener::bind(rest_addr).await?;
    let rest_handle = tokio::spawn(async move {
        axum::serve(rest_listener, rest_router)
            .with_graceful_shutdown(rest_cancel.cancelled_owned())
            .await
    });

    let grpc_cancel = cancel.clone();
    let grpc_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(grpc_service)
            .serve_with_shutdown(grpc_addr, grpc_cancel.cancelled())
            .await
    });

    let deletion_handle = tokio::spawn(keyrack_service::workers::deletion_worker(
        Arc::clone(&state),
        cancel.clone(),
    ));
    let rotation_expiry_handle = tokio::spawn(keyrack_service::workers::rotation_expiry_worker(
        Arc::clone(&state),
        cancel.clone(),
    ));

    shutdown_signal().await;

    const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    tracing::info!("initiating graceful shutdown (drain timeout: {DRAIN_TIMEOUT:?})");
    cancel.cancel();

    match tokio::time::timeout(DRAIN_TIMEOUT, async {
        let _ = grpc_handle.await;
        let _ = rest_handle.await;
        let _ = deletion_handle.await;
        let _ = rotation_expiry_handle.await;
    }).await {
        Ok(_) => tracing::info!("all servers and workers drained"),
        Err(_) => tracing::warn!("drain timeout reached, forcing shutdown"),
    }

    tracing::info!("flushing audit sink");
    if let Err(e) = state.audit.flush().await {
        tracing::error!(error = %e, "audit flush failed during shutdown");
    }

    tracing::info!("KeyRack service stopped");

    Ok(())
}

fn load_config() -> Result<ServiceConfig, Box<dyn std::error::Error>> {
    let config_path = std::env::var("KEYRACK_CONFIG").ok();
    if let Some(path) = config_path {
        let yaml = std::fs::read_to_string(&path)?;
        Ok(ServiceConfig::from_yaml(&yaml)?)
    } else {
        tracing::info!("no KEYRACK_CONFIG set, using defaults");
        Ok(ServiceConfig::default())
    }
}

async fn build_state(
    config: &ServiceConfig,
    metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
) -> Result<ServiceState, Box<dyn std::error::Error>> {
    use keyrack_core::authn::{
        Authenticator, AuthenticatorChain, BootstrapTokenAuthenticator,
        InsecureAuthenticator, JwtAuthenticator, MtlsAuthenticator,
    };
    use keyrack_service::config::{AuditConfig, AuthnConfig, PdpConfig, ProviderConfig, StorageConfig};

    let storage: Arc<dyn keyrack_core::storage::StorageBackend> = match &config.storage {
        StorageConfig::Sqlite { path } => Arc::new(keyrack_sqlite::SqliteStorage::open(path)?),
        StorageConfig::Postgres { database_url } => {
            Arc::new(keyrack_postgres::PostgresStorage::connect(database_url).await?)
        }
        StorageConfig::Memory => Arc::new(keyrack_sqlite::SqliteStorage::in_memory()?),
    };

    let provider: Arc<dyn keyrack_core::provider::CryptoProvider> = match &config.provider {
        ProviderConfig::Software => {
            Arc::new(keyrack_core::provider::software::SoftwareProvider::new())
        }
        ProviderConfig::InMemory => {
            Arc::new(keyrack_core::provider::inmem::InMemoryProvider::new())
        }
        ProviderConfig::Pkcs11 {
            lib_path,
            token_label,
            pin,
        } => {
            let pkcs11_config = keyrack_pkcs11::Pkcs11ProviderConfig {
                lib_path: lib_path.clone(),
                token_label: token_label.clone(),
                pin: pin.clone(),
            };
            Arc::new(keyrack_pkcs11::Pkcs11Provider::new(&pkcs11_config)?)
        }
        ProviderConfig::Kmip { .. } => {
            return Err("KMIP provider not yet implemented".into());
        }
        ProviderConfig::VaultTransit {
            vault_addr,
            vault_token,
            mount_path,
        } => {
            Arc::new(
                keyrack_vault::VaultTransitProvider::new(
                    vault_addr,
                    vault_token,
                    mount_path.as_deref(),
                )
                .await?,
            )
        }
    };

    let provider_class_enum = match &config.provider {
        ProviderConfig::Software => keyrack_core::key::ProviderClass::Software,
        ProviderConfig::InMemory => keyrack_core::key::ProviderClass::InMemory,
        ProviderConfig::Pkcs11 { .. } => keyrack_core::key::ProviderClass::Pkcs11,
        ProviderConfig::Kmip { .. } => keyrack_core::key::ProviderClass::Kmip,
        ProviderConfig::VaultTransit { .. } => keyrack_core::key::ProviderClass::VaultTransit,
    };
    let provider_class = match &config.provider {
        ProviderConfig::Software => "software",
        ProviderConfig::InMemory => "in_memory",
        ProviderConfig::Pkcs11 { .. } => "pkcs11",
        ProviderConfig::Kmip { .. } => "kmip",
        ProviderConfig::VaultTransit { .. } => "vault_transit",
    };
    if config.provider_deny.iter().any(|d| d == provider_class) {
        return Err(format!("provider class '{provider_class}' is in the deny list").into());
    }

    let pdp: Arc<dyn keyrack_core::pdp::PolicyDecisionPoint> = match &config.pdp {
        PdpConfig::AlwaysAllow => Arc::new(keyrack_core::pdp::AlwaysAllow),
        PdpConfig::AlwaysDeny => Arc::new(keyrack_core::pdp::AlwaysDeny),
        PdpConfig::Http {
            endpoint,
            timeout_ms,
        } => Arc::new(keyrack_service::pdp_http::HttpPdpClient::new(
            endpoint,
            std::time::Duration::from_millis(*timeout_ms),
        )?),
        PdpConfig::Grpc {
            endpoint,
            timeout_ms,
        } => Arc::new(keyrack_service::pdp_grpc::GrpcPdpClient::new(
            endpoint,
            std::time::Duration::from_millis(*timeout_ms),
        )),
    };

    let audit: Arc<dyn keyrack_core::audit::AuditSink> = {
        let base_sink: Box<dyn keyrack_core::audit::AuditSink> = match &config.audit {
            AuditConfig::Stdout => Box::new(keyrack_core::audit::StdoutSink),
            AuditConfig::File { path } => Box::new(keyrack_core::audit::FileSink::new(path)),
            AuditConfig::Nats { url } => {
                Box::new(keyrack_nats::NatsAuditSink::connect(url).await?)
            }
        };

        if config.sign_audit_events {
            let signer = keyrack_core::audit::AuditSigner::generate();
            let vk = signer.verifying_key();
            let vk_hex: String = vk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            tracing::info!(verifying_key = %vk_hex, "audit event signing enabled");
            Arc::new(keyrack_core::audit::SigningAuditSink::new(base_sink, signer))
        } else {
            Arc::from(base_sink)
        }
    };

    let authn: Arc<AuthenticatorChain> = {
        let authenticators: Vec<Box<dyn Authenticator>> = match &config.authn {
            AuthnConfig::Insecure => {
                tracing::warn!("authentication disabled (insecure mode) — dev/test only");
                vec![Box::new(InsecureAuthenticator)]
            }
            AuthnConfig::Mtls => {
                vec![Box::new(MtlsAuthenticator)]
            }
            AuthnConfig::Jwt { jwks_url } => {
                let jwt_auth = JwtAuthenticator::new(jwks_url, None).await
                    .map_err(|e| -> Box<dyn std::error::Error> { format!("JWT authenticator init failed: {e}").into() })?;
                vec![Box::new(jwt_auth)]
            }
            AuthnConfig::BootstrapToken { max_age_secs } => {
                let token = std::env::var("KMS_BOOTSTRAP_TOKEN").unwrap_or_default();
                if token.is_empty() {
                    tracing::warn!("bootstrap_token auth configured but KMS_BOOTSTRAP_TOKEN is empty");
                }
                vec![Box::new(BootstrapTokenAuthenticator::new(
                    &token,
                    std::time::Duration::from_secs(*max_age_secs),
                ))]
            }
        };
        Arc::new(AuthenticatorChain::new(authenticators))
    };

    let nats_publisher = if let Some(nats_cfg) = &config.nats_notify {
        let publisher = keyrack_nats::NatsStateChangedPublisher::connect(
            &nats_cfg.url,
            nats_cfg.state_changed_subject_prefix.clone(),
        )
        .await?;
        Some(Arc::new(publisher))
    } else {
        None
    };

    Ok(ServiceState {
        storage,
        provider,
        pdp,
        audit,
        authn,
        metrics_handle,
        max_plaintext_bytes: config.max_plaintext_bytes,
        nats_publisher,
        provider_class: provider_class_enum,
    })
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => { tracing::info!("received SIGINT, shutting down"); }
            _ = sigterm.recv() => { tracing::info!("received SIGTERM, shutting down"); }
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        tracing::info!("received Ctrl+C, shutting down");
    }
}
