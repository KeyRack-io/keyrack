// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::fixture::context;

mod qualification;

#[test]
fn authenticated_local_fixture_rejects_each_semantic_context_change() {
    let original = context();
    let mut source = LocalFixture::new(&original).unwrap();
    assert_eq!(source.open(&original).unwrap().0.len(), 32);
    let canonical = original.canonical_bytes().unwrap();
    // Direct AEAD perturbation establishes authentication of every V1 byte,
    // independently of structural validation or adjacent descriptor comparisons.
    for index in 0..canonical.len() {
        let mut changed = canonical.clone();
        changed[index] ^= 1;
        assert!(Aes256Gcm::new_from_slice(source.parent.as_ref())
            .unwrap()
            .decrypt(
                &Nonce::from(source.nonce),
                Payload {
                    msg: &source.ciphertext,
                    aad: &changed
                }
            )
            .is_err());
    }
    let mut changed = original.clone();
    changed.child.version = std::num::NonZeroU64::new(2).unwrap();
    assert!(source.open(&changed).is_err());
    assert_eq!(source.open(&original).unwrap().0.len(), 32);
}

#[test]
#[ignore = "requires the A2-owned live Vault fixture; no mock fallback"]
fn real_vault_native_wrapped_only_authenticates_every_v1_context_byte() {
    let address = std::env::var("VAULT_ADDR").expect("VAULT_ADDR required");
    let token = crate::credential::load(std::path::Path::new(
        &std::env::var("KEYRACK_WORKER_VAULT_TOKEN_FILE").expect("worker token file required"),
    ))
    .unwrap();
    let parent =
        std::env::var("KEYRACK_WORKER_VAULT_PARENT").expect("derived fixture parent required");
    let context = context();
    let mut source = VaultFixture::new(&address, token, parent).unwrap();
    source = crate::core::creation::tests::generated_source(source);
    let canonical = crate::fixture::custody_context(&context)
        .canonical_bytes()
        .unwrap();
    let first = source.open(&context).unwrap();
    assert_eq!(first.0.len(), 32);
    for index in 0..canonical.len() {
        let mut changed = canonical.clone();
        changed[index] ^= 1;
        assert!(
            source.open_bytes(&changed).is_err(),
            "Vault accepted changed byte {index}"
        );
    }
    let again = source.open(&context).unwrap();
    // Keep secret values out of assertion failure output.
    assert!(first.0.as_slice().eq(again.0.as_slice()));
    // Never format either value in assertion diagnostics.
    qualification::verify_pinned_vault_binding(&source, &canonical);
}

#[test]
#[ignore = "requires the A2-owned live Vault fixture and coordinator deny token"]
fn real_vault_coordinator_has_no_parent_decrypt_path() {
    let address = std::env::var("VAULT_ADDR").unwrap();
    let parent = std::env::var("KEYRACK_WORKER_VAULT_PARENT").unwrap();
    let token = Zeroizing::new(
        std::fs::read_to_string(
            std::env::var("KEYRACK_WORKER_VAULT_COORDINATOR_TOKEN_FILE").unwrap(),
        )
        .unwrap(),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let valid = client
        .get(format!("{address}/v1/auth/token/lookup-self"))
        .header("X-Vault-Token", token.as_str())
        .send()
        .unwrap();
    assert!(
        valid.status().is_success(),
        "negative control token must itself be valid"
    );
    let denied = client
        .post(format!("{address}/v1/transit/decrypt/{parent}"))
        .header("X-Vault-Token", token.as_str())
        .json(&json!({"ciphertext": "vault:v1:dummy"}))
        .send()
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
}

#[test]
#[ignore = "requires the A2-owned live Vault fixture and test-admin parent-loss control"]
fn real_vault_parent_loss_respects_separate_authority_and_residency_bounds() {
    use crate::core::{
        AuthorityMessage, Clock, Grant, Limits, Operation, Signed, Worker, SIGNING_DOMAIN,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::{cell::Cell, rc::Rc};
    struct TestClock(Rc<Cell<u64>>);
    impl Clock for TestClock {
        fn millis(&self) -> u64 {
            self.0.get()
        }
    }

    let address = std::env::var("VAULT_ADDR").unwrap();
    let admin = Zeroizing::new(
        std::fs::read_to_string(std::env::var("KEYRACK_WORKER_VAULT_ADMIN_TOKEN_FILE").unwrap())
            .unwrap(),
    );
    let worker_token = crate::credential::load(std::path::Path::new(
        &std::env::var("KEYRACK_WORKER_VAULT_TOKEN_FILE").unwrap(),
    ))
    .unwrap();
    // Create and destroy only this test's fresh dedicated parent. Never delete
    // the shared fixture parent or any caller-supplied production key name.
    let name = format!("worker-fixture-loss-{}", rand::random::<u64>());
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let response = client
        .post(format!("{address}/v1/transit/keys/{name}"))
        .header("X-Vault-Token", admin.as_str())
        .json(&json!({"type": "aes256-gcm96", "derived": true}))
        .send()
        .unwrap();
    assert!(response.status().is_success());
    let context = context();
    let source = VaultFixture::new(&address, worker_token, name.clone()).unwrap();
    let clock = Rc::new(Cell::new(0));
    let signer = SigningKey::generate(&mut OsRng);
    let mut worker = Worker::new(
        signer.verifying_key(),
        "development-only".into(),
        source,
        TestClock(clock.clone()),
        Limits {
            resident_keys: 1,
            residence_ms: 2_000,
            uses_per_residency: 10,
            authority_horizon_ms: 5_000,
        },
    )
    .unwrap();
    crate::core::creation::tests::authorize(&mut worker, &signer);
    let authorize = |instance: &str, sequence: u64, expiry| {
        let body = serde_json::to_string(&AuthorityMessage::Grant(Grant {
            worker: instance.into(),
            principal: "alice".into(),
            context_sha256: digest(&context.canonical_bytes().unwrap()),
            operation: Operation::Encrypt,
            input_sha256: digest(b"data"),
            generation: 1,
            sequence: sequence + 1,
            not_before_ms: 0,
            expires_ms: expiry,
            ancestor_expires_ms: expiry,
            residency_until_ms: 4_000,
        }))
        .unwrap();
        let mut message = SIGNING_DOMAIN.to_vec();
        message.extend_from_slice(body.as_bytes());
        Signed {
            signature: signer.sign(&message).to_bytes().to_vec(),
            body,
        }
    };
    let grant = authorize(&worker.instance, 1, 1_000);
    worker
        .execute(&grant, "alice", &context, Operation::Encrypt, b"data")
        .unwrap();
    let response = client
        .post(format!("{address}/v1/transit/keys/{name}/config"))
        .header("X-Vault-Token", admin.as_str())
        .json(&json!({"deletion_allowed": true}))
        .send()
        .unwrap();
    assert!(response.status().is_success());
    let response = client
        .delete(format!("{address}/v1/transit/keys/{name}"))
        .header("X-Vault-Token", admin.as_str())
        .send()
        .unwrap();
    assert!(response.status().is_success());
    clock.set(999);
    let grant = authorize(&worker.instance, 2, 1_000);
    assert!(worker
        .execute(&grant, "alice", &context, Operation::Encrypt, b"data")
        .is_ok());
    clock.set(1_000);
    let grant = authorize(&worker.instance, 3, 1_000);
    assert_eq!(
        worker.execute(&grant, "alice", &context, Operation::Encrypt, b"data"),
        Err(Error::Expired)
    );
    clock.set(2_000);
    assert_eq!(worker.expire().len(), 1);
    let grant = authorize(&worker.instance, 4, 3_000);
    assert_eq!(
        worker.execute(&grant, "alice", &context, Operation::Encrypt, b"data"),
        Err(Error::Material)
    );
}

#[test]
fn native_adapter_rejects_malformed_or_plaintext_replies_without_evidence() {
    use crate::core::creation::tests::{grant, plan, sign};
    use crate::core::{Limits, MonotonicClock, Worker};
    use ed25519_dalek::SigningKey;
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        time::Instant,
    };

    // Explicit protocol-negative unit fixture. Live acceptance still requires
    // Vault and has no substitution path to this server.
    for bad in [
        json!({"ciphertext": "vault:v1:"}),
        json!({"ciphertext": "vault:v1:!!!"}),
        json!({"ciphertext": format!("vault:v1:{}", STANDARD.encode([0; 59]))}),
        json!({"ciphertext": format!("vault:v2:{}", STANDARD.encode([0; 60]))}),
        json!({"ciphertext": "x".repeat(4097)}),
        json!({"ciphertext": format!("vault:v1:{}", STANDARD.encode([0; 60])), "plaintext": "must-not-be-observed"}),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let context = crate::fixture::custody_context(&context());
        let canonical = context.canonical_bytes().unwrap();
        let server = std::thread::spawn(move || {
            for (index, data) in [json!({"derived": true, "convergent_encryption": false, "type": "aes256-gcm96", "exportable": false, "allow_plaintext_backup": false}), bad].into_iter().enumerate() {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "native request missing");
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("accept failed: {e}"),
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new(); reader.read_line(&mut line).unwrap();
                assert!(line.starts_with(if index == 0 { "GET /v1/transit/keys/" } else { "POST /v1/transit/datakey/wrapped/" }));
                let mut length = 0;
                loop {
                    line.clear(); reader.read_line(&mut line).unwrap();
                    if line == "\r\n" { break; }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") { length = value.trim().parse().unwrap(); }
                }
                let mut body = vec![0; length]; reader.read_exact(&mut body).unwrap();
                if index == 1 {
                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(STANDARD.decode(body["context"].as_str().unwrap()).unwrap(), canonical);
                    assert_eq!(body["bits"], 256);
                    assert_eq!(body["key_version"], 1);
                }
                let body = json!({"data": data}).to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            }
        });
        let source = VaultFixture::new(
            &address,
            Zeroizing::new("unit-fixture-only".into()),
            "worker-fixture-unit".into(),
        )
        .unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let mut worker = Worker::new(
            key.verifying_key(),
            "development-only".into(),
            source,
            MonotonicClock::new(),
            Limits {
                resident_keys: 1,
                residence_ms: 1_000,
                uses_per_residency: 3,
                authority_horizon_ms: 10_000,
            },
        )
        .unwrap();
        worker.reserve_creation(plan(), context).unwrap();
        assert!(worker.generate(&sign(grant(&worker), &key)).is_err());
        let mut retry = grant(&worker);
        retry.sequence = std::num::NonZeroU64::new(2).unwrap();
        assert!(worker.generate(&sign(retry, &key)).is_err());
        assert!(!worker.creation_allows_use());
        server.join().unwrap();
    }
}
