// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use keyrack_core::error::KeyRackError;
use keyrack_core::key::KeySpec;
use keyrack_core::provider::{software::SoftwareProvider, CryptoProvider, KeyHandle};
use keyrack_service::deferred_provider::{AvailabilityProbe, DeferredProvider, ProviderFactory};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

#[tokio::test]
async fn deferred_construction_retries_permission_refusal_and_delegates_after_recovery() {
    let allowed = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));
    let backend: Arc<dyn CryptoProvider> = Arc::new(SoftwareProvider::new());
    let factory: ProviderFactory = {
        let allowed = allowed.clone();
        let attempts = attempts.clone();
        let backend = backend.clone();
        Arc::new(move || {
            let allowed = allowed.clone();
            let attempts = attempts.clone();
            let backend = backend.clone();
            Box::pin(async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                if !allowed.load(Ordering::SeqCst) {
                    return Err(KeyRackError::AuthorizationDenied {
                        reason: "access revoked".into(),
                    });
                }
                Ok(backend)
            })
        })
    };
    let provider = DeferredProvider::new("external".into(), backend.capabilities(), factory, None);
    let unavailable = provider.generate_random(8).await.unwrap_err();
    assert!(
        matches!(unavailable, KeyRackError::ProviderUnavailable(_)),
        "construction must not delay requests"
    );
    // Even provider defaults that normally succeed must not silently succeed
    // while construction has not completed.
    let handle = KeyHandle {
        key_id: "missing".into(),
        key_spec: KeySpec::Aes256,
    };
    assert!(matches!(
        provider.make_key_exportable(&handle).await,
        Err(KeyRackError::ProviderUnavailable(_))
    ));
    assert_eq!(provider.capabilities(), backend.capabilities());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "constructor retries must back off"
    );
    allowed.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(4), async {
        while provider.check_readiness().await.is_err() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("deferred constructor must recover without restart");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let encrypted = provider
        .encrypt(&handle, b"payload", b"context")
        .await
        .unwrap();
    let clear = provider
        .decrypt(&handle, &encrypted.ciphertext, b"context")
        .await
        .unwrap();
    assert_eq!(clear.expose(), b"payload");
    provider.destroy_key(&handle).await.unwrap();
}

#[tokio::test]
async fn live_probe_overrides_noop_readiness_and_recovers() {
    let available = Arc::new(AtomicBool::new(true));
    let probe: AvailabilityProbe = {
        let available = available.clone();
        Arc::new(move || {
            let available = available.clone();
            Box::pin(async move {
                if available.load(Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(KeyRackError::AuthorizationDenied {
                        reason: "private backend detail".into(),
                    })
                }
            })
        })
    };
    let backend: Arc<dyn CryptoProvider> = Arc::new(SoftwareProvider::new());
    let capabilities = backend.capabilities();
    let provider = DeferredProvider::new(
        "external".into(),
        capabilities,
        Arc::new(move || {
            let backend = backend.clone();
            Box::pin(async move { Ok(backend) })
        }),
        Some(probe),
    );
    tokio::task::yield_now().await;
    assert!(provider.check_readiness().await.is_ok());
    available.store(false, Ordering::SeqCst);
    let error = provider.check_readiness().await.unwrap_err();
    assert!(
        matches!(error, KeyRackError::ProviderUnavailable(_)),
        "backend denial must mean unavailable"
    );
    assert!(!error.to_string().contains("private backend detail"));
    available.store(true, Ordering::SeqCst);
    assert!(provider.check_readiness().await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn backoff_doubles_to_cap_and_drop_stops_construction() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let factory: ProviderFactory = {
        let attempts = attempts.clone();
        Arc::new(move || {
            attempts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(KeyRackError::Provider("unreachable".into())) })
        })
    };
    let provider = DeferredProvider::new(
        "external".into(),
        SoftwareProvider::new().capabilities(),
        factory,
        None,
    );
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    for (index, seconds) in [1, 2, 4, 8, 16, 30, 30, 30].into_iter().enumerate() {
        tokio::time::advance(
            Duration::from_secs(seconds)
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        )
        .await;
        tokio::task::yield_now().await;
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            index + 1,
            "backoff must not retry early"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            index + 2,
            "backoff must retry and remain capped"
        );
    }
    drop(provider);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(120)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        9,
        "dropping wrapper must stop constructor task"
    );
}

#[tokio::test(start_paused = true)]
async fn hung_constructor_times_out_before_retrying() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let factory: ProviderFactory = {
        let attempts = attempts.clone();
        Arc::new(move || {
            attempts.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending())
        })
    };
    let provider = DeferredProvider::new(
        "external".into(),
        SoftwareProvider::new().capabilities(),
        factory,
        None,
    );
    tokio::task::yield_now().await;
    for _ in 0..20 {
        assert!(matches!(
            provider.generate_random(1).await,
            Err(KeyRackError::ProviderUnavailable(_))
        ));
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "timeout must still observe retry backoff"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "hung construction must time out and retry"
    );
}

#[tokio::test]
async fn cancelling_native_wait_does_not_release_constructor_admission() {
    use keyrack_service::deferred_provider::blocking_factory;
    let calls = Arc::new(AtomicUsize::new(0));
    let released = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let factory = {
        let calls = calls.clone();
        let released = released.clone();
        blocking_factory(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            let (lock, wake) = &*released;
            let _guard = wake
                .wait_while(lock.lock().unwrap(), |done| !*done)
                .unwrap();
            Ok(Arc::new(SoftwareProvider::new()) as Arc<dyn CryptoProvider>)
        })
    };
    let first = tokio::spawn(factory());
    tokio::time::timeout(Duration::from_secs(2), async {
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    first.abort();
    let _ = first.await;
    // Record before releasing, but release even if a mutant would fail; never
    // strand a native test thread while reporting a regression.
    let second = tokio::time::timeout(Duration::from_millis(50), factory()).await;
    let count = calls.load(Ordering::SeqCst);
    let (lock, wake) = &*released;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    assert!(
        matches!(second, Ok(Err(KeyRackError::ProviderUnavailable(_)))),
        "cancelled native wait must retain admission"
    );
    assert_eq!(
        count, 1,
        "native constructor must not overlap after cancellation"
    );
}

struct RevocableBackend {
    allowed: AtomicBool,
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl CryptoProvider for RevocableBackend {
    async fn generate_random(
        &self,
        length: usize,
    ) -> keyrack_core::error::Result<keyrack_core::sensitive::Sensitive<Vec<u8>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.allowed.load(Ordering::SeqCst) {
            Ok(keyrack_core::sensitive::Sensitive::new(vec![0; length]))
        } else {
            Err(KeyRackError::AuthorizationDenied {
                reason: "access revoked".into(),
            })
        }
    }
    async fn generate_key(&self, _: &KeySpec) -> keyrack_core::error::Result<KeyHandle> {
        unreachable!()
    }
    async fn encrypt(
        &self,
        _: &KeyHandle,
        _: &[u8],
        _: &[u8],
    ) -> keyrack_core::error::Result<keyrack_core::provider::EncryptOutput> {
        unreachable!()
    }
    async fn decrypt(
        &self,
        _: &KeyHandle,
        _: &[u8],
        _: &[u8],
    ) -> keyrack_core::error::Result<keyrack_core::sensitive::Sensitive<Vec<u8>>> {
        unreachable!()
    }
    async fn sign(
        &self,
        _: &KeyHandle,
        _: keyrack_core::provider::SigningAlgorithm,
        _: &[u8],
    ) -> keyrack_core::error::Result<Vec<u8>> {
        unreachable!()
    }
    async fn verify(
        &self,
        _: &KeyHandle,
        _: keyrack_core::provider::SigningAlgorithm,
        _: &[u8],
        _: &[u8],
    ) -> keyrack_core::error::Result<bool> {
        unreachable!()
    }
    async fn destroy_key(&self, _: &KeyHandle) -> keyrack_core::error::Result<()> {
        unreachable!()
    }
    fn capabilities(&self) -> keyrack_core::provider::ProviderCapabilities {
        SoftwareProvider::new().capabilities()
    }
}

#[tokio::test]
async fn backend_permission_failure_is_unavailable_without_replaying_operations() {
    let backend = Arc::new(RevocableBackend {
        allowed: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    let factory: ProviderFactory = {
        let backend = backend.clone();
        Arc::new(move || {
            let backend = backend.clone();
            Box::pin(async move { Ok(backend as Arc<dyn CryptoProvider>) })
        })
    };
    let provider = DeferredProvider::new("external".into(), backend.capabilities(), factory, None);
    tokio::task::yield_now().await;
    assert!(
        matches!(
            provider.generate_random(8).await,
            Err(KeyRackError::ProviderUnavailable(_))
        ),
        "backend permission refusal must map to unavailable"
    );
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        1,
        "failed operations must not be replayed"
    );
    backend.allowed.store(true, Ordering::SeqCst);
    assert_eq!(provider.generate_random(8).await.unwrap().expose().len(), 8);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
}
