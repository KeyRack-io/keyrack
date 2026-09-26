// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn server(
    status: u16,
    body: &'static str,
    delay_headers: bool,
    delay_body: bool,
) -> (String, tokio::task::JoinHandle<Value>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let body_start = loop {
            let mut chunk = [0; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&chunk[..count]);
            assert!(request.len() < 16_384);
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let headers = std::str::from_utf8(&request[..body_start]).unwrap();
        let length = headers
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        while request.len() < body_start + length {
            let mut chunk = [0; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&chunk[..count]);
        }
        let captured = if length == 0 {
            Value::Null
        } else {
            serde_json::from_slice(&request[body_start..body_start + length]).unwrap()
        };
        if delay_headers {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let header = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        stream.write_all(header.as_bytes()).await.unwrap();
        if delay_body {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        stream.write_all(body.as_bytes()).await.unwrap();
        captured
    });
    (addr, task)
}

fn provider(addr: String) -> VaultTransitProvider {
    VaultTransitProvider {
        // Short overrides exist only in this test module.
        client: http_client_builder()
            .no_proxy()
            .connect_timeout(Duration::from_millis(100))
            .timeout(Duration::from_millis(150))
            .build()
            .unwrap(),
        vault_addr: addr,
        token: "test-token".into(),
        mount: "transit".into(),
    }
}

async fn operation(provider: &VaultTransitProvider, kind: u8) -> Result<()> {
    match kind {
        0 => provider.health_check().await,
        1 => provider
            .vault_post::<_, Value>("encrypt/key", &json!({}))
            .await
            .map(|_| ()),
        2 => provider.vault_post_no_body("keys/key", &json!({})).await,
        3 => provider.vault_delete("keys/key").await,
        _ => provider.vault_get::<Value>("keys/key").await.map(|_| ()),
    }
}

#[tokio::test]
async fn encryption_requests_use_associated_data_and_never_context() {
    for aad in [b"\0\xffheader-and-context".as_slice(), b"".as_slice()] {
        let (addr, capture) = server(
            200,
            r#"{"data":{"ciphertext":"vault:v1:fixture"}}"#,
            false,
            false,
        )
        .await;
        let handle = KeyHandle {
            key_id: "key".into(),
            key_spec: KeySpec::Aes256,
        };
        provider(addr)
            .encrypt(&handle, b"input", aad)
            .await
            .unwrap();
        let body = capture.await.unwrap();
        assert_eq!(body["plaintext"], B64.encode(b"input"));
        assert!(body.get("context").is_none());
        if aad.is_empty() {
            assert!(body.get("associated_data").is_none());
        } else {
            assert_eq!(body["associated_data"], B64.encode(aad));
        }

        let (addr, capture) =
            server(200, r#"{"data":{"plaintext":"aW5wdXQ="}}"#, false, false).await;
        provider(addr)
            .decrypt(&handle, b"vault:v1:fixture", aad)
            .await
            .unwrap();
        let body = capture.await.unwrap();
        assert_eq!(body["ciphertext"], "vault:v1:fixture");
        assert!(body.get("context").is_none());
        if aad.is_empty() {
            assert!(body.get("associated_data").is_none());
        } else {
            assert_eq!(body["associated_data"], B64.encode(aad));
        }
    }
}

#[tokio::test]
async fn only_http_503_changes_the_existing_status_error_class() {
    for status in [400, 403, 404, 500, 503] {
        for kind in 0..5 {
            let (addr, task) =
                server(status, r#"{"errors":["specific failure"]}"#, false, false).await;
            let error = operation(&provider(addr), kind).await.unwrap_err();
            match (status, error) {
                (503, KeyRackError::ProviderUnavailable(message))
                | (400 | 403 | 404 | 500, KeyRackError::Provider(message)) => {
                    assert!(message.contains(&status.to_string()));
                    assert!(message.contains("specific failure"));
                }
                (_, other) => panic!("unexpected class: {other}"),
            }
            task.await.unwrap();
        }
    }
}

#[tokio::test]
async fn stalled_headers_and_response_bodies_are_unavailable() {
    for kind in 0..5 {
        // Success paths without a response body need only the header check;
        // failing responses exercise body reads in every helper.
        for (status, delay_headers) in [(200, true), (400, false), (503, false)] {
            let (addr, task) = server(
                status,
                r#"{"errors":["delayed"]}"#,
                delay_headers,
                !delay_headers,
            )
            .await;
            let started = std::time::Instant::now();
            let result = operation(&provider(addr), kind).await;
            task.abort();
            assert!(started.elapsed() < Duration::from_secs(2));
            let KeyRackError::ProviderUnavailable(message) = result.unwrap_err() else {
                panic!("timeout must be unavailable");
            };
            assert!(
                message.contains("timed out") || message.contains("deadline has elapsed"),
                "{message}"
            );
        }
    }
}

#[tokio::test]
async fn malformed_success_json_keeps_provider_error() {
    for kind in [1, 4] {
        let (addr, task) = server(200, "invalid-json", false, false).await;
        let error = operation(&provider(addr), kind).await.unwrap_err();
        assert!(
            matches!(error, KeyRackError::Provider(ref message) if message.contains("failed to parse vault response"))
        );
        task.await.unwrap();
    }
}
