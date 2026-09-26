// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use serde_json::json;

const AAD: &[u8] = b"\0\xffauthenticated-header-and-encryption-context";
const PLAINTEXT: &[u8] = b"associated-data-control";

async fn provider() -> VaultTransitProvider {
    let addr = std::env::var("VAULT_ADDR").expect("VAULT_ADDR required");
    let token = std::env::var("VAULT_TOKEN").expect("VAULT_TOKEN required");
    VaultTransitProvider::new(&addr, &token, None)
        .await
        .unwrap()
}

fn authentication_failure(result: Result<Sensitive<Vec<u8>>>) {
    let Err(error) = result else {
        panic!("unauthenticated plaintext was accepted");
    };
    match error {
        KeyRackError::Provider(message) => {
            assert!(message.contains("400 Bad Request"), "{message}");
            assert!(
                message.contains("cipher: message authentication failed"),
                "{message}"
            );
        }
        other => panic!("expected Vault authentication failure, got {other}"),
    }
}

#[tokio::test]
#[ignore = "requires live Vault (VAULT_ADDR + VAULT_TOKEN)"]
async fn matching_associated_data_round_trips() {
    let provider = provider().await;
    let key = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let encrypted = provider.encrypt(&key, PLAINTEXT, AAD).await.unwrap();
    let plaintext = provider
        .decrypt(&key, &encrypted.ciphertext, AAD)
        .await
        .unwrap();
    // Avoid printing plaintext on assertion failure.
    assert!(plaintext.expose().as_slice().eq(PLAINTEXT));
    provider.destroy_key(&key).await.unwrap();
}

#[tokio::test]
#[ignore = "requires live Vault (VAULT_ADDR + VAULT_TOKEN)"]
async fn tampered_associated_data_is_authentication_failure() {
    let provider = provider().await;
    let key = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let encrypted = provider.encrypt(&key, PLAINTEXT, AAD).await.unwrap();
    let mut changed = AAD.to_vec();
    changed[0] ^= 1;
    let result = provider
        .decrypt(&key, &encrypted.ciphertext, &changed)
        .await;
    provider.destroy_key(&key).await.unwrap();
    authentication_failure(result);
}

#[tokio::test]
#[ignore = "requires live Vault (VAULT_ADDR + VAULT_TOKEN)"]
async fn omitted_associated_data_is_authentication_failure() {
    let provider = provider().await;
    let key = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let encrypted = provider.encrypt(&key, PLAINTEXT, AAD).await.unwrap();
    let result = provider.decrypt(&key, &encrypted.ciphertext, b"").await;
    provider.destroy_key(&key).await.unwrap();
    authentication_failure(result);
}

#[tokio::test]
#[ignore = "requires live Vault (VAULT_ADDR + VAULT_TOKEN)"]
async fn legacy_ciphertext_without_associated_data_is_authentication_failure() {
    let provider = provider().await;
    let key = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let metadata: serde_json::Value = provider
        .vault_get(&format!("keys/{}", key.key_id))
        .await
        .unwrap();
    assert_eq!(metadata["data"]["derived"], false);
    for body in [
        json!({"plaintext": B64.encode(PLAINTEXT)}),
        json!({"plaintext": B64.encode(PLAINTEXT), "context": B64.encode(AAD)}),
    ] {
        let old: EncryptResponse = provider
            .vault_post(&format!("encrypt/{}", key.key_id), &body)
            .await
            .unwrap();
        // Positive control establishes this is valid ciphertext without AAD.
        let plaintext = provider
            .decrypt(&key, old.data.ciphertext.as_bytes(), b"")
            .await
            .unwrap();
        // Avoid printing plaintext on assertion failure.
        assert!(plaintext.expose().as_slice().eq(PLAINTEXT));
        authentication_failure(
            provider
                .decrypt(&key, old.data.ciphertext.as_bytes(), AAD)
                .await,
        );
    }
    provider.destroy_key(&key).await.unwrap();
}

// Armed before the seal request; disarmed only after Vault confirms restoration.
struct UnsealGuard {
    addr: String,
    key: Option<zeroize::Zeroizing<String>>,
}

async fn unseal(addr: &str, key: &str) -> Result<()> {
    let response = http_client_builder()
        .build()
        .map_err(|error| transport_error("unseal client failed", &error))?
        .put(format!("{addr}/v1/sys/unseal"))
        .json(&json!({"key": key}))
        .send()
        .await
        .map_err(|error| transport_error("unseal request failed", &error))?
        .error_for_status()
        .map_err(|error| transport_error("unseal status failed", &error))?;
    let status: serde_json::Value = response
        .json()
        .await
        .map_err(|error| transport_error("unseal response failed", &error))?;
    if status["sealed"] != false {
        return Err(KeyRackError::Provider("Vault remains sealed".into()));
    }
    Ok(())
}

impl UnsealGuard {
    async fn restore(&mut self) -> Result<()> {
        if let Some(key) = &self.key {
            unseal(&self.addr, key).await?;
            self.key = None;
        }
        Ok(())
    }
}

impl Drop for UnsealGuard {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let addr = self.addr.clone();
        // Join a separate runtime: spawning on the unwinding test's runtime
        // could lose cleanup at shutdown, and nested block_on would panic.
        let cleanup = std::thread::Builder::new().spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    KeyRackError::Provider(format!("unseal runtime failed: {error}"))
                })?;
            runtime.block_on(unseal(&addr, &key))
        });
        // Never cause a second panic during unwinding. The runner still
        // tears down its owned fixture if restoration itself fails.
        match cleanup {
            Ok(thread) => match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("Vault unseal cleanup failed: {error}"),
                Err(_) => eprintln!("Vault unseal cleanup panicked"),
            },
            Err(error) => eprintln!("Vault unseal cleanup thread failed: {error}"),
        }
    }
}

#[tokio::test]
#[ignore = "requires exclusively owned Vault with KEYRACK_VAULT_TEST_UNSEAL_KEY; run serially"]
async fn sealed_vault_is_unavailable_and_restores_existing_ciphertext() {
    // Only the disposable runner supplies this capability; arbitrary live
    // VAULT_ADDR/VAULT_TOKEN settings alone must never authorize sealing.
    let unseal_key = zeroize::Zeroizing::new(
        std::env::var("KEYRACK_VAULT_TEST_UNSEAL_KEY")
            .expect("owned fixture unseal key required before sealing"),
    );
    let provider = provider().await;
    let key = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let encrypted = provider.encrypt(&key, PLAINTEXT, AAD).await.unwrap();
    let mut cleanup = UnsealGuard {
        addr: provider.vault_addr.clone(),
        key: Some(unseal_key.clone()),
    };
    let seal = provider
        .client
        .put(format!("{}/v1/sys/seal", provider.vault_addr))
        .header("X-Vault-Token", &provider.token)
        .send()
        .await;
    // Collect observations without asserting or unwrapping while sealed.
    let health = provider
        .client
        .get(format!("{}/v1/sys/health", provider.vault_addr))
        .send()
        .await;
    let result = provider.decrypt(&key, &encrypted.ciphertext, AAD).await;
    let construction = VaultTransitProvider::new(&provider.vault_addr, &provider.token, None).await;
    cleanup.restore().await.unwrap();
    let plaintext = provider
        .decrypt(&key, &encrypted.ciphertext, AAD)
        .await
        .unwrap();
    // Avoid printing plaintext on assertion failure.
    assert!(plaintext.expose().as_slice().eq(PLAINTEXT));
    assert!(seal.unwrap().status().is_success());
    assert_eq!(
        health.unwrap().status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    for error in [
        result.expect_err("sealed decrypt must fail"),
        construction.err().expect("sealed health check must fail"),
    ] {
        assert!(
            matches!(error, KeyRackError::ProviderUnavailable(ref message)
            if message.contains("503 Service Unavailable") && message.contains("Vault is sealed")),
            "{error}"
        );
    }

    // Exercise Drop during a real panic on the current-thread test runtime.
    let cleanup = UnsealGuard {
        addr: provider.vault_addr.clone(),
        key: Some(unseal_key),
    };
    let client = provider.client.clone();
    let token = provider.token.clone();
    let panic: std::result::Result<(), _> = tokio::spawn(async move {
        let guard = cleanup;
        client
            .put(format!("{}/v1/sys/seal", guard.addr))
            .header("X-Vault-Token", token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let health = client
            .get(format!("{}/v1/sys/health", guard.addr))
            .send()
            .await
            .unwrap();
        assert_eq!(health.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        panic!("injected panic after sealing");
    })
    .await;
    let panic = panic.expect_err("injected panic must reach the join handle");
    assert!(panic.is_panic());
    assert_eq!(
        panic.into_panic().downcast_ref::<&str>(),
        Some(&"injected panic after sealing")
    );
    // No explicit unseal: Drop must finish before the task reports its panic.
    let plaintext = provider
        .decrypt(&key, &encrypted.ciphertext, AAD)
        .await
        .unwrap();
    assert!(plaintext.expose().as_slice().eq(PLAINTEXT));
    provider.destroy_key(&key).await.unwrap();
}

#[tokio::test]
#[ignore = "requires live Vault (VAULT_ADDR + VAULT_TOKEN)"]
async fn unreachable_vault_is_unavailable_within_timeout() {
    let mut provider = provider().await; // Prove the live fixture works first.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    provider.vault_addr = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let started = std::time::Instant::now();
    let result = provider
        .vault_get::<serde_json::Value>("keys/unreachable")
        .await;
    assert!(started.elapsed() < REQUEST_TIMEOUT);
    assert!(
        matches!(result, Err(KeyRackError::ProviderUnavailable(ref message)) if message.contains("vault GET failed: connection failed:"))
    );
    let started = std::time::Instant::now();
    let result = VaultTransitProvider::new(&provider.vault_addr, &provider.token, None).await;
    assert!(started.elapsed() < REQUEST_TIMEOUT);
    assert!(
        matches!(result, Err(KeyRackError::ProviderUnavailable(ref message)) if message.contains("vault health check failed: connection failed:"))
    );
}
