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

use keyrack_service::config::ServiceConfig;
use keyrack_service::grpc::KeyServiceImpl;
use keyrack_service::proto::key_service_server::KeyServiceServer;
use keyrack_service::state::ServiceState;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

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

    if let Some(tls_cfg) = &config.tls {
        let (reloader, _cert_rx) = keyrack_service::cert_reload::CertReloader::new(
            &tls_cfg.server_cert,
            &tls_cfg.server_key,
        );
        tokio::spawn(reloader.watch_loop(std::time::Duration::from_secs(30)));
        tracing::info!("TLS cert hot-reload watcher started (polling every 30s)");
    }

    let rest_cancel = cancel.clone();
    let rest_listener = tokio::net::TcpListener::bind(rest_addr).await?;
    let rest_handle = tokio::spawn(async move {
        axum::serve(rest_listener, rest_router)
            .with_graceful_shutdown(rest_cancel.cancelled_owned())
            .await
    });

    let grpc_cancel = cancel.clone();
    let grpc_handle = tokio::spawn(async move {
        let mut builder = Server::builder();

        if let Some(tls_cfg) = &config.tls {
            use tonic::transport::{Certificate, Identity, ServerTlsConfig};

            let cert_pem = tokio::fs::read(&tls_cfg.server_cert)
                .await
                .expect("failed to read TLS server certificate");
            let key_pem = tokio::fs::read(&tls_cfg.server_key)
                .await
                .expect("failed to read TLS server key");
            let identity = Identity::from_pem(cert_pem, key_pem);

            let mut tls = ServerTlsConfig::new().identity(identity);

            if let Some(ca_path) = &tls_cfg.ca_cert {
                let ca_pem = tokio::fs::read(ca_path)
                    .await
                    .expect("failed to read TLS CA certificate");
                tls = tls.client_ca_root(Certificate::from_pem(ca_pem));
                tracing::info!("mTLS enabled: client certificates will be validated");
            }

            builder = builder.tls_config(tls).expect("invalid TLS configuration");
            tracing::info!("TLS enabled on gRPC server");

            // TODO: Extract peer certificates from the TLS connection into
            // PeerCertificates request extensions so MtlsAuthenticator can
            // derive identity. Transport-level mTLS validation is active; this
            // only affects identity propagation to the PDP/audit layer.
        }

        if let Some(ka) = &config.grpc_keepalive {
            builder = builder
                .http2_keepalive_interval(Some(Duration::from_secs(ka.time_secs)))
                .http2_keepalive_timeout(Some(Duration::from_secs(ka.timeout_secs)));
            tracing::info!(
                time_secs = ka.time_secs,
                timeout_secs = ka.timeout_secs,
                "gRPC HTTP/2 keepalive enabled"
            );
        }

        builder
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

    tracing::info!("initiating graceful shutdown (drain timeout: {DRAIN_TIMEOUT:?})");
    cancel.cancel();

    if let Ok(()) = tokio::time::timeout(DRAIN_TIMEOUT, async {
        let _ = grpc_handle.await;
        let _ = rest_handle.await;
        let _ = deletion_handle.await;
        let _ = rotation_expiry_handle.await;
    })
    .await
    {
        tracing::info!("all servers and workers drained");
    } else {
        tracing::warn!("drain timeout reached, forcing shutdown");
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

async fn build_authenticators(
    config: &keyrack_service::config::AuthnConfig,
) -> Result<Vec<Box<dyn keyrack_core::authn::Authenticator>>, Box<dyn std::error::Error>> {
    use keyrack_core::authn::{
        BootstrapTokenAuthenticator, ForwardedIdentityAuthenticator, InsecureAuthenticator,
        JwtAuthenticator, MtlsAuthenticator,
    };
    use keyrack_service::config::AuthnConfig;

    match config {
        AuthnConfig::Insecure => {
            tracing::warn!("authentication disabled (insecure mode) — dev/test only");
            Ok(vec![Box::new(InsecureAuthenticator)])
        }
        AuthnConfig::Mtls => Ok(vec![Box::new(MtlsAuthenticator)]),
        AuthnConfig::Jwt {
            jwks_url,
            issuer,
            audience,
            claims_namespace,
        } => {
            if let Some(aud) = audience {
                tracing::info!(
                    audience = %aud,
                    "audience configured but not enforced at authn layer; \
                     the `aud` claim is available in principal attributes for PDP enforcement"
                );
            }
            let mut jwt_auth = JwtAuthenticator::new(jwks_url, issuer.as_deref())
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    format!("JWT authenticator init failed: {e}").into()
                })?;
            if let Some(ns) = claims_namespace {
                jwt_auth = jwt_auth.with_claims_namespace(ns.clone());
            }
            Ok(vec![Box::new(jwt_auth)])
        }
        AuthnConfig::BootstrapToken { max_age_secs } => {
            let token = std::env::var("KMS_BOOTSTRAP_TOKEN").unwrap_or_default();
            if token.is_empty() {
                tracing::warn!("bootstrap_token auth configured but KMS_BOOTSTRAP_TOKEN is empty");
            }
            Ok(vec![Box::new(BootstrapTokenAuthenticator::new(
                &token,
                std::time::Duration::from_secs(*max_age_secs),
            ))])
        }
        AuthnConfig::ForwardedIdentity => Ok(vec![Box::new(ForwardedIdentityAuthenticator)]),
        AuthnConfig::Chain { authenticators } => {
            let mut all: Vec<Box<dyn keyrack_core::authn::Authenticator>> = Vec::new();
            for sub in authenticators {
                let mut sub_auths = Box::pin(build_authenticators(sub)).await?;
                all.append(&mut sub_auths);
            }
            Ok(all)
        }
    }
}

async fn build_provider(
    cfg: &keyrack_service::config::ProviderConfig,
) -> Result<
    (
        Arc<dyn keyrack_core::provider::CryptoProvider>,
        keyrack_core::key::ProviderClass,
    ),
    Box<dyn std::error::Error>,
> {
    use keyrack_service::config::ProviderConfig;
    let (provider, class): (Arc<dyn keyrack_core::provider::CryptoProvider>, _) = match cfg {
        ProviderConfig::Software => (
            Arc::new(keyrack_core::provider::software::SoftwareProvider::new()),
            keyrack_core::key::ProviderClass::Software,
        ),
        ProviderConfig::InMemory => (
            Arc::new(keyrack_core::provider::inmem::InMemoryProvider::new()),
            keyrack_core::key::ProviderClass::InMemory,
        ),
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
            (
                Arc::new(keyrack_pkcs11::Pkcs11Provider::new(&pkcs11_config)?),
                keyrack_core::key::ProviderClass::Pkcs11,
            )
        }
        ProviderConfig::Kmip { .. } => {
            return Err("KMIP provider not yet implemented".into());
        }
        ProviderConfig::VaultTransit {
            vault_addr,
            vault_token,
            mount_path,
        } => (
            Arc::new(
                keyrack_vault::VaultTransitProvider::new(
                    vault_addr,
                    vault_token,
                    mount_path.as_deref(),
                )
                .await?,
            ),
            keyrack_core::key::ProviderClass::VaultTransit,
        ),
    };
    Ok((provider, class))
}

fn provider_class_str(class: keyrack_core::key::ProviderClass) -> &'static str {
    match class {
        keyrack_core::key::ProviderClass::Software => "software",
        keyrack_core::key::ProviderClass::InMemory => "in_memory",
        keyrack_core::key::ProviderClass::Pkcs11 => "pkcs11",
        keyrack_core::key::ProviderClass::Kmip => "kmip",
        keyrack_core::key::ProviderClass::VaultTransit => "vault_transit",
    }
}

async fn build_state(
    config: &ServiceConfig,
    metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
) -> Result<ServiceState, Box<dyn std::error::Error>> {
    use keyrack_core::authn::AuthenticatorChain;
    use keyrack_core::key::ProviderRef;
    use keyrack_core::registry::{ProviderEntry, ProviderRegistry, StaticProviderRegistry};
    use keyrack_service::config::{AuditConfig, PdpConfig, StorageConfig};
    use keyrack_service::routing::ProviderRouter;

    let storage: Arc<dyn keyrack_core::storage::StorageBackend> = match &config.storage {
        StorageConfig::Sqlite { path } => Arc::new(keyrack_sqlite::SqliteStorage::open(path)?),
        StorageConfig::Postgres { database_url } => {
            Arc::new(keyrack_postgres::PostgresStorage::connect(database_url).await?)
        }
        StorageConfig::Memory => Arc::new(keyrack_sqlite::SqliteStorage::in_memory()?),
    };

    let storage: Arc<dyn keyrack_core::storage::StorageBackend> =
        if let Some(cache_cfg) = &config.cache {
            let ttl = std::time::Duration::from_secs(cache_cfg.ttl_secs);
            tracing::info!(
                max_capacity = cache_cfg.max_capacity,
                ttl_secs = cache_cfg.ttl_secs,
                "key record cache enabled"
            );
            Arc::new(keyrack_service::cache::CachingStorage::new(
                storage,
                cache_cfg.max_capacity,
                ttl,
            ))
        } else {
            storage
        };

    // Build the provider registry from the resolved named-provider list.
    let (named_providers, default_name) = config
        .resolved_providers()
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let mut entries: Vec<(ProviderRef, ProviderEntry)> = Vec::new();
    for np in &named_providers {
        let (provider, class) = build_provider(&np.provider).await?;
        let class_str = provider_class_str(class);
        if config.provider_deny.iter().any(|d| d == class_str) {
            return Err(format!(
                "provider '{}' class '{class_str}' is in the deny list",
                np.name
            )
            .into());
        }
        tracing::info!(name = %np.name, class = class_str, "registered provider");
        entries.push((
            ProviderRef::new(np.name.clone()),
            ProviderEntry { provider, class },
        ));
    }

    let default_ref = ProviderRef::new(default_name.clone());
    let registry = StaticProviderRegistry::new(entries, default_ref.clone())
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    // Build the provider router from routing rules.
    let router_rules: Vec<(std::collections::BTreeMap<String, String>, ProviderRef)> = config
        .provider_routing
        .iter()
        .map(|rule| {
            (
                rule.match_tags.clone(),
                ProviderRef::new(rule.provider.clone()),
            )
        })
        .collect();

    // Validate that every rule's provider exists in the registry.
    for rule in &config.provider_routing {
        let pref = ProviderRef::new(rule.provider.clone());
        registry
            .resolve(&pref)
            .map_err(|_| -> Box<dyn std::error::Error> {
                format!(
                    "provider_routing rule references unknown provider '{}'",
                    rule.provider
                )
                .into()
            })?;
    }

    let provider_router = ProviderRouter::new(router_rules, default_ref);

    let pdp: Arc<dyn keyrack_core::pdp::PolicyDecisionPoint> = match &config.pdp {
        PdpConfig::AlwaysAllow => Arc::new(keyrack_core::pdp::AlwaysAllow),
        PdpConfig::AlwaysDeny => Arc::new(keyrack_core::pdp::AlwaysDeny),
        PdpConfig::Http {
            endpoint,
            timeout_ms,
            ca_cert,
            client_cert,
            client_key,
        } => Arc::new(keyrack_service::pdp_http::HttpPdpClient::new(
            endpoint,
            std::time::Duration::from_millis(*timeout_ms),
            ca_cert.as_deref(),
            client_cert.as_deref(),
            client_key.as_deref(),
        )?),
        PdpConfig::Grpc {
            endpoint,
            timeout_ms,
            ca_cert,
            client_cert,
            client_key,
        } => Arc::new(keyrack_service::pdp_grpc::GrpcPdpClient::new(
            endpoint,
            std::time::Duration::from_millis(*timeout_ms),
            ca_cert.as_deref(),
            client_cert.as_deref(),
            client_key.as_deref(),
        )?),
        PdpConfig::Cedar {
            endpoint,
            timeout_ms,
        } => {
            tracing::info!(endpoint = %endpoint, "using Cedar sidecar PDP via HTTP");
            Arc::new(keyrack_service::pdp_http::HttpPdpClient::new(
                endpoint,
                std::time::Duration::from_millis(*timeout_ms),
                None,
                None,
                None,
            )?)
        }
    };

    let audit: Arc<dyn keyrack_core::audit::AuditSink> = {
        let base_sink: Box<dyn keyrack_core::audit::AuditSink> = match &config.audit {
            AuditConfig::Stdout => Box::new(keyrack_core::audit::StdoutSink),
            AuditConfig::File { path } => Box::new(keyrack_core::audit::FileSink::new(path)),
            AuditConfig::Nats { url } => {
                let mut sink = keyrack_nats::NatsAuditSink::connect(url).await?;
                if let Some(nats_cfg) = &config.nats_notify {
                    sink = sink.with_prefix(&nats_cfg.audit_subject_prefix);
                }
                Box::new(sink)
            }
        };

        if config.sign_audit_events {
            let signer = if let Some(path) = &config.audit_signing_key_path {
                let key_path = std::path::Path::new(path);
                let signing_key = if key_path.exists() {
                    let bytes =
                        std::fs::read(key_path).map_err(|e| -> Box<dyn std::error::Error> {
                            format!("failed to read audit signing key at {path}: {e}").into()
                        })?;
                    if bytes.len() != 32 {
                        return Err(format!(
                            "audit signing key at {path} must be exactly 32 bytes, got {}",
                            bytes.len()
                        )
                        .into());
                    }
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&bytes);
                    ed25519_dalek::SigningKey::from_bytes(&seed)
                } else {
                    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
                    if let Some(parent) = key_path.parent() {
                        std::fs::create_dir_all(parent).ok();
                    }
                    std::fs::write(key_path, key.to_bytes()).map_err(
                        |e| -> Box<dyn std::error::Error> {
                            format!("failed to persist audit signing key to {path}: {e}").into()
                        },
                    )?;
                    tracing::info!(%path, "generated and persisted new audit signing key");
                    key
                };
                keyrack_core::audit::AuditSigner::new(signing_key)
            } else {
                tracing::info!(
                    "using ephemeral audit signing key (will not persist across restarts)"
                );
                keyrack_core::audit::AuditSigner::generate()
            };
            let vk = signer.verifying_key();
            let vk_hex: String = vk.as_bytes().iter().fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            });
            tracing::info!(verifying_key = %vk_hex, "audit event signing enabled");
            Arc::new(keyrack_core::audit::SigningAuditSink::new(
                base_sink, signer,
            ))
        } else {
            Arc::from(base_sink)
        }
    };

    let authn: Arc<AuthenticatorChain> = {
        let authenticators = build_authenticators(&config.authn).await?;
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
        providers: Arc::new(registry),
        provider_router,
        pdp,
        audit,
        authn,
        metrics_handle,
        max_plaintext_bytes: config.max_plaintext_bytes,
        nats_publisher,
    })
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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
