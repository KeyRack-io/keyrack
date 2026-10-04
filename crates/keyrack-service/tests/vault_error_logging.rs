// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use keyrack_core::error::KeyRackError;
use keyrack_core::provider::{software::SoftwareProvider, CryptoProvider};
use keyrack_service::deferred_provider::{DeferredProvider, ProviderFactory};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn vault_connection_failure_and_deferred_construction_log_omit_urls() {
    // This integration-test binary has a single subscriber/test; spawned
    // constructor tasks must use the same capture as the caller.
    let logs = LogBuffer::default();
    let writer = logs.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    for scheme in ["http", "https"] {
        let endpoint = format!("{scheme}://{addr}/private-backend");
        let factory: ProviderFactory = Arc::new(move || {
            let endpoint = endpoint.clone();
            Box::pin(async move {
                keyrack_vault::VaultTransitProvider::new(&endpoint, "token", None)
                    .await
                    .map(|provider| Arc::new(provider) as Arc<dyn CryptoProvider>)
            })
        });
        let error = factory().await.err().expect("closed port must fail");
        assert!(matches!(error, KeyRackError::ProviderUnavailable(_)));
        let message = error.to_string();
        assert!(message.contains("connection failed"));
        assert!(
            !message.contains("http://") && !message.contains("https://"),
            "{message}"
        );
        logs.0.lock().unwrap().clear();
        let provider = DeferredProvider::new(
            "external-vault".into(),
            SoftwareProvider::new().capabilities(),
            factory,
            None,
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
                if output.contains("provider construction failed; retrying") {
                    assert!(output.contains("provider unavailable:"));
                    assert!(output.contains("connection failed"));
                    assert!(
                        !output.contains("http://") && !output.contains("https://"),
                        "{output}"
                    );
                    assert!(!output.contains("private-backend"));
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a construction failure must actually be logged");
        drop(provider);
        tokio::task::yield_now().await;
    }
}
