// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ciphertext binding on the Vault Transit provider, exercised through the
//! real service binary.
//!
//! A ciphertext blob is the 80-byte `CiphertextHeader` followed by the
//! provider payload. The header and the encryption context are bound to the
//! payload only as AES-GCM associated data, so each case below edits a field
//! that nothing else in the decrypt path would catch: the service resolves the
//! key from the request and never compares the header's LID, and it checks the
//! header's context hash only against the context the caller supplied. Every
//! case must be refused by the provider's authentication tag.
//!
//! These tests need a live Vault with the Transit engine mounted at `transit`
//! (`VAULT_ADDR`, `VAULT_TOKEN`). `scripts/test-vault-provider.sh` provides
//! one and refuses to pass if any of them is missing.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use keyrack_core::encryption_context::EncryptionContext;
use keyrack_core::header::CiphertextHeader;
use keyrack_core::lid::Lid;
use keyrack_service::proto;
use proto::key_service_client::KeyServiceClient;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SERVICE_BIN: &str = env!("CARGO_BIN_EXE_keyrack-service");

/// Vault's error text when AES-GCM tag verification fails.
const AEAD_REFUSAL: &str = "message authentication failed";

type Context = [(&'static str, &'static str)];

const TENANT_A: &Context = &[("tenant", "alpha"), ("purpose", "invoices")];
const TENANT_B: &Context = &[("tenant", "bravo"), ("purpose", "invoices")];

fn context_map(context: &Context) -> HashMap<String, String> {
    context
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn context_hash(context: &Context) -> [u8; 32] {
    let mut ec = EncryptionContext::new();
    for (k, v) in context {
        ec.insert(*k, *v);
    }
    ec.hash()
}

/// Decode `blob`, apply `edit` to its header, and re-encode it in front of the
/// original provider payload.
fn edit_header(blob: &[u8], edit: impl FnOnce(&mut CiphertextHeader)) -> Vec<u8> {
    let (mut header, payload) = CiphertextHeader::unwrap_payload(blob).expect("service blob");
    edit(&mut header);
    header.wrap_payload(payload)
}

/// How one surface answered a decrypt request.
enum Outcome {
    Plaintext(Vec<u8>),
    Refused { code: String, message: String },
}

impl Outcome {
    fn is_aead_refusal(&self) -> bool {
        matches!(self, Self::Refused { message, .. } if message.contains(AEAD_REFUSAL))
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plaintext(plaintext) => {
                write!(f, "decrypted to {:?}", String::from_utf8_lossy(plaintext))
            }
            Self::Refused { code, message } => write!(f, "refused ({code}): {message}"),
        }
    }
}

struct Fixture {
    dir: PathBuf,
    child: Option<Child>,
    rest: String,
    grpc: String,
    client: reqwest::Client,
}

impl Fixture {
    async fn start() -> Self {
        let vault_addr = std::env::var("VAULT_ADDR")
            .expect("VAULT_ADDR must point at a Vault with Transit mounted; refusing to skip");
        let vault_token = std::env::var("VAULT_TOKEN").expect("VAULT_TOKEN for the Vault fixture");
        let dir = std::env::temp_dir().join(format!("keyrack-vault-aad-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).expect("create isolated fixture directory");
        // Hold both reservations until both ports have been selected.
        let rest_listener = TcpListener::bind("127.0.0.1:0").expect("REST port");
        let grpc_listener = TcpListener::bind("127.0.0.1:0").expect("gRPC port");
        let rest_port = rest_listener.local_addr().unwrap().port();
        let grpc_port = grpc_listener.local_addr().unwrap().port();
        let config = format!(
            "grpc_addr: '127.0.0.1:{grpc_port}'\n\
             rest_addr: '127.0.0.1:{rest_port}'\n\
             storage:\n  type: memory\n\
             provider:\n  type: vault_transit\n  vault_addr: '{vault_addr}'\n  vault_token: '{vault_token}'\n\
             pdp:\n  type: always_allow\n\
             audit:\n  type: file\n  path: '{}'\n\
             authn:\n  type: insecure\n",
            dir.join("audit.jsonl").display(),
        );
        std::fs::write(dir.join("config.yaml"), config).expect("write fixture config");
        let stdout = std::fs::File::create(dir.join("stdout")).expect("capture stdout");
        let stderr = std::fs::File::create(dir.join("stderr")).expect("capture stderr");
        let mut fixture = Self {
            dir,
            child: None,
            rest: format!("http://127.0.0.1:{rest_port}"),
            grpc: format!("http://127.0.0.1:{grpc_port}"),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        };
        drop(rest_listener);
        drop(grpc_listener);
        fixture.child = Some(
            Command::new(SERVICE_BIN)
                .env("KEYRACK_CONFIG", fixture.dir.join("config.yaml"))
                .env("RUST_LOG", "info")
                .env("NO_COLOR", "1")
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr))
                .spawn()
                .expect("start real service binary"),
        );
        fixture.await_healthy().await;
        fixture
    }

    async fn await_healthy(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("service exited {status}: {}", self.logs());
            }
            if self
                .client
                .get(format!("{}/healthz", self.rest))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
                && KeyServiceClient::connect(self.grpc.clone()).await.is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        panic!("service did not become healthy: {}", self.logs());
    }

    fn logs(&self) -> String {
        format!(
            "{}\n{}",
            std::fs::read_to_string(self.dir.join("stdout")).unwrap_or_default(),
            std::fs::read_to_string(self.dir.join("stderr")).unwrap_or_default()
        )
    }

    async fn create_key(&self) -> String {
        let response = self
            .client
            .post(format!("{}/v1/keys", self.rest))
            .json(&json!({"key_spec": "AES_256", "exportable": false}))
            .send()
            .await
            .expect("create key on the Vault provider");
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        assert_eq!(status, StatusCode::CREATED, "create key: {body}");
        body["lid"].as_str().expect("key LID").to_owned()
    }

    async fn encrypt(&self, key: &str, plaintext: &[u8], context: &Context) -> Vec<u8> {
        KeyServiceClient::connect(self.grpc.clone())
            .await
            .unwrap()
            .encrypt(proto::EncryptRequest {
                key_id: key.into(),
                plaintext: plaintext.into(),
                encryption_context: context_map(context),
            })
            .await
            .expect("encrypt with an encryption context")
            .into_inner()
            .ciphertext_blob
    }

    async fn decrypt_grpc(&self, key: &str, blob: &[u8], context: &Context) -> Outcome {
        let result = KeyServiceClient::connect(self.grpc.clone())
            .await
            .unwrap()
            .decrypt(proto::DecryptRequest {
                key_id: key.into(),
                ciphertext_blob: blob.into(),
                encryption_context: context_map(context),
            })
            .await;
        match result {
            Ok(response) => Outcome::Plaintext(response.into_inner().plaintext),
            Err(status) => Outcome::Refused {
                code: format!("{:?}", status.code()),
                message: status.message().to_owned(),
            },
        }
    }

    async fn decrypt_rest(&self, key: &str, blob: &[u8], context: &Context) -> Outcome {
        let response = self
            .client
            .post(format!("{}/v1/keys/{key}/actions-decrypt", self.rest))
            .json(&json!({
                "ciphertext_blob": B64.encode(blob),
                "encryption_context": context_map(context),
            }))
            .send()
            .await
            .expect("REST request reached real binary");
        let status = response.status();
        let body: Value = response.json().await.expect("JSON REST response");
        if status.is_success() {
            let plaintext = body["plaintext"].as_str().expect("plaintext field");
            Outcome::Plaintext(B64.decode(plaintext).expect("base64 plaintext"))
        } else {
            Outcome::Refused {
                code: format!("{status} {}", body["error"].as_str().unwrap_or_default()),
                message: body["message"].as_str().unwrap_or_default().to_owned(),
            }
        }
    }

    /// Decrypt on both surfaces.
    async fn decrypt(
        &self,
        key: &str,
        blob: &[u8],
        context: &Context,
    ) -> [(&'static str, Outcome); 2] {
        [
            ("gRPC", self.decrypt_grpc(key, blob, context).await),
            ("REST", self.decrypt_rest(key, blob, context).await),
        ]
    }

    async fn assert_decrypts(&self, key: &str, blob: &[u8], context: &Context, expected: &[u8]) {
        for (surface, outcome) in self.decrypt(key, blob, context).await {
            match outcome {
                Outcome::Plaintext(plaintext) => assert_eq!(
                    plaintext, expected,
                    "positive control on {surface}: wrong plaintext"
                ),
                Outcome::Refused { .. } => {
                    panic!("positive control on {surface}: untampered blob refused: {outcome}")
                }
            }
        }
    }

    /// Every surface must refuse `blob` because the provider's authentication
    /// tag did not verify, not for any earlier reason.
    async fn assert_aead_refusal(&self, case: &str, key: &str, blob: &[u8], context: &Context) {
        let outcomes = self.decrypt(key, blob, context).await;
        for (surface, outcome) in &outcomes {
            println!("{case} via {surface}: {outcome}");
        }
        for (surface, outcome) in outcomes {
            assert!(
                outcome.is_aead_refusal(),
                "{case} via {surface}: expected refusal by the provider's AES-GCM tag \
                 ({AEAD_REFUSAL:?}), got {outcome}"
            );
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The request's key ID selects the key; the header's LID is only bound by
/// the associated data.
#[tokio::test]
#[ignore = "needs a live Vault Transit fixture; run by scripts/test-vault-provider.sh"]
async fn tampered_header_lid_is_refused() {
    let fixture = Fixture::start().await;
    let key = fixture.create_key().await;
    let plaintext = b"bound to the key named in its header";
    let blob = fixture.encrypt(&key, plaintext, TENANT_A).await;
    fixture
        .assert_decrypts(&key, &blob, TENANT_A, plaintext)
        .await;

    let tampered = edit_header(&blob, |header| {
        let mut lid = *header.lid.as_bytes();
        lid[0] ^= 0x01;
        header.lid = Lid::from_bytes(lid);
    });
    assert_ne!(tampered, blob);

    fixture
        .assert_aead_refusal("LID tamper", &key, &tampered, TENANT_A)
        .await;
}

/// Rewriting the header's context hash to match a different caller-supplied
/// context passes the service's own hash comparison; only the associated data
/// still binds the context used at encryption.
#[tokio::test]
#[ignore = "needs a live Vault Transit fixture; run by scripts/test-vault-provider.sh"]
async fn swapped_encryption_context_is_refused() {
    let fixture = Fixture::start().await;
    let key = fixture.create_key().await;
    let plaintext = b"readable only under tenant alpha";
    let blob = fixture.encrypt(&key, plaintext, TENANT_A).await;
    fixture
        .assert_decrypts(&key, &blob, TENANT_A, plaintext)
        .await;

    // Without the header rewrite the service's hash check refuses first.
    for (surface, outcome) in fixture.decrypt(&key, &blob, TENANT_B).await {
        assert!(
            matches!(&outcome, Outcome::Refused { message, .. }
                if message.contains("encryption context mismatch")),
            "unrewritten header via {surface} must fail the service's context check: {outcome}"
        );
    }

    let swapped = edit_header(&blob, |header| {
        header.encryption_context_hash = context_hash(TENANT_B);
    });

    fixture
        .assert_aead_refusal("context swap", &key, &swapped, TENANT_B)
        .await;
}

/// The header of one ciphertext in front of another's provider payload, both
/// under the same key but with different contexts.
#[tokio::test]
#[ignore = "needs a live Vault Transit fixture; run by scripts/test-vault-provider.sh"]
async fn spliced_header_and_payload_are_refused() {
    let fixture = Fixture::start().await;
    let key = fixture.create_key().await;
    let plaintext_a = b"tenant alpha record";
    let plaintext_b = b"tenant bravo record";
    let blob_a = fixture.encrypt(&key, plaintext_a, TENANT_A).await;
    let blob_b = fixture.encrypt(&key, plaintext_b, TENANT_B).await;
    fixture
        .assert_decrypts(&key, &blob_a, TENANT_A, plaintext_a)
        .await;
    fixture
        .assert_decrypts(&key, &blob_b, TENANT_B, plaintext_b)
        .await;

    let (header_a, _) = CiphertextHeader::unwrap_payload(&blob_a).expect("blob A");
    let (_, payload_b) = CiphertextHeader::unwrap_payload(&blob_b).expect("blob B");
    let spliced = header_a.wrap_payload(payload_b);

    fixture
        .assert_aead_refusal("splice", &key, &spliced, TENANT_A)
        .await;
}
