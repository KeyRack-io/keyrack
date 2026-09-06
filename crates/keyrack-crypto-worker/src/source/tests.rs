// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::fixture::context;

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
    let token = std::fs::read_to_string(
        std::env::var("KEYRACK_WORKER_VAULT_TOKEN_FILE").expect("worker token file required"),
    )
    .unwrap();
    let parent =
        std::env::var("KEYRACK_WORKER_VAULT_PARENT").expect("derived fixture parent required");
    let context = context();
    let mut source = VaultFixture::new(&address, token, parent, &context).unwrap();
    let canonical = context.canonical_bytes().unwrap();
    assert_eq!(source.generation.context_sha256, digest(&canonical));
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
    assert!(first.0.as_slice() == again.0.as_slice());
    // Never format either value in assertion diagnostics.
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
    let worker_token =
        std::fs::read_to_string(std::env::var("KEYRACK_WORKER_VAULT_TOKEN_FILE").unwrap()).unwrap();
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
    let source = VaultFixture::new(&address, worker_token, name.clone(), &context).unwrap();
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
    let authorize = |instance: &str, sequence, expiry| {
        let body = serde_json::to_string(&AuthorityMessage::Grant(Grant {
            worker: instance.into(),
            principal: "alice".into(),
            context_sha256: digest(&context.canonical_bytes().unwrap()),
            operation: Operation::Encrypt,
            input_sha256: digest(b"data"),
            generation: 1,
            sequence,
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
