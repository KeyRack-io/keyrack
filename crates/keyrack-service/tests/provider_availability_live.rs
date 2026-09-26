// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use keyrack_core::provider::CryptoProvider;
use keyrack_service::config::ProviderConfig;
use keyrack_service::provider_startup::{defer_remote_provider, remote_capabilities};
use std::sync::Arc;
use std::time::Duration;

/// Requires a disposable SOFTHSM2_CONF with an empty token directory.
#[tokio::test]
#[ignore = "requires an isolated native-token fixture"]
async fn deferred_native_constructor_discovers_a_token_initialized_after_start() {
    let library = std::env::var("KEYRACK_AVAILABILITY_PKCS11_LIB").unwrap();
    let label = uuid::Uuid::new_v4().simple().to_string();
    let pin = uuid::Uuid::new_v4().simple().to_string();
    let audit: Arc<dyn keyrack_core::audit::AuditSink> =
        Arc::new(keyrack_core::audit::FanoutSink::new(vec![]));
    let config = ProviderConfig::Pkcs11 {
        lib_path: library.clone(),
        token_label: label.clone(),
        token_label_ref: None,
        pin: Some(pin.clone().into()),
        pin_ref: None,
    };
    let (provider, class) = defer_remote_provider("external", &config, &audit)
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        provider.check_readiness().await.is_err(),
        "absent token must initially be unavailable"
    );
    assert_eq!(provider.capabilities(), remote_capabilities(class));
    let result = std::process::Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            &label,
            "--pin",
            &pin,
            "--so-pin",
            &pin,
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "token initialization failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    tokio::time::timeout(Duration::from_secs(45), async {
        while provider.check_readiness().await.is_err() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("deferred native constructor must discover a token without restart");
    let direct = keyrack_pkcs11::Pkcs11Provider::new(&keyrack_pkcs11::Pkcs11ProviderConfig {
        lib_path: library,
        token_label: label,
        pin,
    })
    .unwrap();
    assert_eq!(
        remote_capabilities(class),
        direct.capabilities(),
        "offline capabilities must match the live provider"
    );
    assert_eq!(provider.generate_random(8).await.unwrap().expose().len(), 8);
}
