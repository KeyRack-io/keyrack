// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::body::Body;
use axum::http::{Request, StatusCode};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::hsm::{HsmConnection, HsmProviderType};
use keyrack_core::key::{KeySpec, ProviderClass, ProviderRef};
use keyrack_core::provider::{
    CryptoProvider, EncryptOutput, KeyHandle, ProviderCapabilities, SigningAlgorithm,
};
use keyrack_core::registry::{
    DynamicProviderRegistry, ProviderEntry, ProviderRegistry, StaticProviderRegistry,
};
use keyrack_core::sensitive::Sensitive;
use keyrack_service::state::ServiceState;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt as _;

struct TokenProbe {
    available: AtomicBool,
    calls: AtomicUsize,
    hang: bool,
}

impl TokenProbe {
    fn new(available: bool, hang: bool) -> Arc<Self> {
        Arc::new(Self {
            available: AtomicBool::new(available),
            calls: AtomicUsize::new(0),
            hang,
        })
    }
}

#[async_trait::async_trait]
impl CryptoProvider for TokenProbe {
    async fn check_readiness(&self) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.hang {
            std::future::pending::<()>().await;
        }
        if self.available.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(KeyRackError::ProviderUnavailable(
                "token unavailable; private backend detail".into(),
            ))
        }
    }
    async fn generate_key(&self, _: &KeySpec) -> Result<KeyHandle> {
        panic!("readiness must not create keys")
    }
    async fn encrypt(&self, _: &KeyHandle, _: &[u8], _: &[u8]) -> Result<EncryptOutput> {
        panic!("readiness must not encrypt")
    }
    async fn decrypt(&self, _: &KeyHandle, _: &[u8], _: &[u8]) -> Result<Sensitive<Vec<u8>>> {
        panic!("readiness must not decrypt")
    }
    async fn sign(&self, _: &KeyHandle, _: SigningAlgorithm, _: &[u8]) -> Result<Vec<u8>> {
        panic!("readiness must not sign")
    }
    async fn verify(&self, _: &KeyHandle, _: SigningAlgorithm, _: &[u8], _: &[u8]) -> Result<bool> {
        panic!("readiness must not verify")
    }
    async fn generate_random(&self, _: usize) -> Result<Sensitive<Vec<u8>>> {
        panic!("readiness must not use random generation as a probe")
    }
    async fn destroy_key(&self, _: &KeyHandle) -> Result<()> {
        panic!("readiness must not destroy keys")
    }
    fn capabilities(&self) -> ProviderCapabilities {
        panic!("capabilities do not establish live readiness")
    }
}

fn entry(provider: Arc<TokenProbe>) -> ProviderEntry {
    ProviderEntry {
        provider,
        class: ProviderClass::Pkcs11,
    }
}

fn state(providers: Arc<dyn ProviderRegistry>) -> Arc<ServiceState> {
    Arc::new(ServiceState {
        storage: Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap()),
        providers,
        provider_router: keyrack_service::routing::ProviderRouter::new(
            vec![],
            ProviderRef::new("default"),
        )
        .unwrap(),
        pdp: Arc::new(keyrack_core::pdp::AlwaysAllow),
        audit: Arc::new(keyrack_core::audit::FanoutSink::new(vec![])),
        authn: Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![])),
        metrics_handle: metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle(),
        max_plaintext_bytes: 4096,
        legacy_compromised_key_decrypt: false,
        nats_publisher: None,
    })
}

async fn ready(state: Arc<ServiceState>) -> (StatusCode, String) {
    let response = keyrack_service::rest::router(state)
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn nondefault_token_outage_fails_readiness_and_recovery_restores_it() {
    let default = TokenProbe::new(true, false);
    let named = TokenProbe::new(true, false);
    let app = state(Arc::new(
        StaticProviderRegistry::new(
            [
                (ProviderRef::new("default"), entry(default.clone())),
                (ProviderRef::new("named-token"), entry(named.clone())),
            ],
            ProviderRef::new("default"),
        )
        .unwrap(),
    ));
    assert_eq!(ready(app.clone()).await.0, StatusCode::OK);
    named.available.store(false, Ordering::SeqCst);
    let (status, body) = ready(app.clone()).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "healthy storage and default must not hide a named token outage"
    );
    assert!(!body.contains("private backend detail"));
    named.available.store(true, Ordering::SeqCst);
    assert_eq!(ready(app).await.0, StatusCode::OK);
    assert_eq!(default.calls.load(Ordering::SeqCst), 3);
    assert_eq!(named.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn dynamically_registered_token_participates_in_readiness() {
    let registry = Arc::new(
        DynamicProviderRegistry::new(
            [(
                ProviderRef::new("default"),
                entry(TokenProbe::new(true, false)),
            )],
            ProviderRef::new("default"),
        )
        .unwrap(),
    );
    let app = state(registry.clone());
    assert_eq!(ready(app.clone()).await.0, StatusCode::OK);
    registry
        .register(
            ProviderRef::new("new-token"),
            entry(TokenProbe::new(false, false)),
        )
        .unwrap();
    assert_eq!(ready(app).await.0, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn persisted_token_missing_after_rehydration_fails_readiness() {
    let app = state(Arc::new(
        StaticProviderRegistry::new(
            [(
                ProviderRef::new("default"),
                entry(TokenProbe::new(true, false)),
            )],
            ProviderRef::new("default"),
        )
        .unwrap(),
    ));
    // Even a stored Healthy status cannot stand in for an actual live provider.
    app.storage
        .create_hsm_connection(
            &HsmConnection::new(
                "failed-rehydration",
                HsmProviderType::Hsm,
                "/missing/lib.so",
                "test",
            )
            .with_pkcs11("token", "file:token.pin"),
        )
        .await
        .unwrap();
    assert_eq!(ready(app).await.0, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn hung_token_is_bounded_and_does_not_starve_the_async_executor() {
    let app = state(Arc::new(
        StaticProviderRegistry::new(
            [(
                ProviderRef::new("default"),
                entry(TokenProbe::new(true, true)),
            )],
            ProviderRef::new("default"),
        )
        .unwrap(),
    ));
    let call = tokio::spawn(ready(app));
    let heartbeat = tokio::time::timeout(std::time::Duration::from_millis(100), async {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    })
    .await;
    assert!(heartbeat.is_ok());
    let response = tokio::time::timeout(std::time::Duration::from_secs(3), call)
        .await
        .expect("readiness must finish within its 2-second budget")
        .unwrap();
    assert_eq!(response.0, StatusCode::SERVICE_UNAVAILABLE);
}
