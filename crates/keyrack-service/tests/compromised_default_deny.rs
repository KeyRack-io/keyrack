// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Black-box acceptance for compromised-key default denial. All twelve tests
//! use the real service binary and only APIs available before this change, so
//! a baseline run measures security assertions, not missing Rust APIs.

use base64::Engine as _;
use keyrack_service::proto;
use proto::key_service_client::KeyServiceClient;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tonic::transport::Channel;

const SERVICE_BIN: &str = env!("CARGO_BIN_EXE_keyrack-service");
const LEGACY_FLAG: &str = "legacy_compromised_key_decrypt";
const PLAINTEXT: &[u8] = b"compromise acceptance plaintext";

struct Fixture {
    dir: PathBuf,
    child: Option<Child>,
    rest: String,
    grpc: String,
    client: reqwest::Client,
    starts: usize,
}

impl Fixture {
    async fn start(legacy: Option<bool>, cache: bool) -> Self {
        let dir =
            std::env::temp_dir().join(format!("keyrack-compromised-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).expect("create isolated fixture directory");
        // Hold both reservations until both ports have been selected.
        let rest_listener = TcpListener::bind("127.0.0.1:0").expect("REST port");
        let grpc_listener = TcpListener::bind("127.0.0.1:0").expect("gRPC port");
        let rest_port = rest_listener.local_addr().unwrap().port();
        let grpc_port = grpc_listener.local_addr().unwrap().port();
        let mut config = format!(
            "grpc_addr: '127.0.0.1:{grpc_port}'\n\
             rest_addr: '127.0.0.1:{rest_port}'\n\
             storage:\n  type: sqlite\n  path: '{}'\n\
             provider:\n  type: software\n\
             pdp:\n  type: always_allow\n\
             audit:\n  type: file\n  path: '{}'\n\
             authn:\n  type: insecure\n",
            dir.join("keys.sqlite").display(),
            dir.join("audit.jsonl").display(),
        );
        if let Some(enabled) = legacy {
            writeln!(config, "{LEGACY_FLAG}: {enabled}").unwrap();
        }
        if cache {
            config.push_str("cache:\n  max_capacity: 32\n  ttl_secs: 3600\n");
        }
        std::fs::write(dir.join("config.yaml"), config).expect("write fixture config");
        let mut fixture = Self {
            dir,
            child: None,
            rest: format!("http://127.0.0.1:{rest_port}"),
            grpc: format!("http://127.0.0.1:{grpc_port}"),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            starts: 0,
        };
        drop(rest_listener);
        drop(grpc_listener);
        fixture.spawn().await;
        fixture
    }

    async fn spawn(&mut self) {
        self.starts += 1;
        let stdout = std::fs::File::create(self.dir.join(format!("{}.stdout", self.starts)))
            .expect("capture stdout");
        let stderr = std::fs::File::create(self.dir.join(format!("{}.stderr", self.starts)))
            .expect("capture stderr");
        self.child = Some(
            Command::new(SERVICE_BIN)
                .env("KEYRACK_CONFIG", self.dir.join("config.yaml"))
                .env("RUST_LOG", "info")
                .env("NO_COLOR", "1")
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr))
                .spawn()
                .expect("start real service binary"),
        );
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

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    async fn restart(&mut self) {
        self.stop();
        self.spawn().await;
    }

    fn logs(&self) -> String {
        format!(
            "{}\n{}",
            std::fs::read_to_string(self.dir.join(format!("{}.stdout", self.starts)))
                .unwrap_or_default(),
            std::fs::read_to_string(self.dir.join(format!("{}.stderr", self.starts)))
                .unwrap_or_default()
        )
    }

    fn audit_events(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.join("audit.jsonl"))
            .expect("read audit sink")
            .lines()
            .map(|line| serde_json::from_str(line).expect("valid structured audit event"))
            .collect()
    }

    async fn grpc(&self) -> KeyServiceClient<Channel> {
        KeyServiceClient::connect(self.grpc.clone()).await.unwrap()
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let response = self
            .client
            .post(format!("{}{path}", self.rest))
            .json(&body)
            .send()
            .await
            .expect("REST request reached real binary");
        let status = response.status();
        let body = response.json().await.expect("JSON REST response");
        (status, body)
    }

    async fn action(&self, key: &str, action: &str, body: Value) -> (StatusCode, Value) {
        self.post(&format!("/v1/keys/{key}/actions-{action}"), body)
            .await
    }

    async fn create(&self, spec: &str, exportable: bool) -> String {
        let (status, body) = self
            .post(
                "/v1/keys",
                json!({"key_spec": spec, "exportable": exportable}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create fixture key: {body}");
        body["lid"].as_str().expect("key LID").to_owned()
    }

    async fn encrypt(&self, key: &str) -> Vec<u8> {
        let result = self
            .grpc()
            .await
            .encrypt(proto::EncryptRequest {
                key_id: key.into(),
                plaintext: PLAINTEXT.into(),
                ..Default::default()
            })
            .await
            .expect("positive control: encrypt while enabled")
            .into_inner();
        result.ciphertext_blob
    }

    async fn compromise(&self, key: &str) {
        let (status, body) = self.action(key, "report-compromise", json!({})).await;
        assert!(status.is_success(), "report compromise: {status} {body}");
    }

    #[allow(clippy::result_large_err)] // Keep the actual gRPC status for lifecycle assertions.
    async fn decrypt(&self, key: &str, blob: &[u8]) -> Result<Vec<u8>, tonic::Status> {
        self.grpc()
            .await
            .decrypt(proto::DecryptRequest {
                key_id: key.into(),
                ciphertext_blob: blob.into(),
                ..Default::default()
            })
            .await
            .map(|response| response.into_inner().plaintext)
    }

    async fn schedule(&self, key: &str) {
        let (status, body) = self
            .action(key, "schedule-deletion", json!({"grace_period_days": 30}))
            .await;
        assert!(status.is_success(), "schedule deletion: {status} {body}");
    }

    async fn cancel_and_enable(&self, key: &str) {
        // Either refusing rehabilitation here or retaining the sticky denial on
        // the resulting record is valid. A transport/provider error is not.
        for action in ["cancel-deletion", "enable"] {
            let (status, body) = self.action(key, action, json!({})).await;
            assert!(
                status.is_success() || status == StatusCode::CONFLICT,
                "lifecycle request must be evaluated: {action}: {status} {body}"
            );
        }
    }

    async fn try_launder(&self, key: &str) {
        self.schedule(key).await;
        self.cancel_and_enable(key).await;
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn assert_state_denial<T: std::fmt::Debug>(result: Result<T, tonic::Status>, context: &str) {
    let error = result.expect_err(context);
    assert_eq!(
        error.code(),
        tonic::Code::FailedPrecondition,
        "must be lifecycle denial, not missing provider material: {context}: {error}"
    );
}

fn assert_rest_state_denial(status: StatusCode, body: &Value, context: &str) {
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "must be lifecycle denial: {context}: {body}"
    );
}

#[tokio::test]
async fn acceptance_01_rest_decrypt_compromised_is_default_denied() {
    let fixture = Fixture::start(Some(false), false).await;
    let key = fixture.create("AES_256", false).await;
    let blob = fixture.encrypt(&key).await;
    let request =
        json!({"ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(blob)});
    let (status, body) = fixture.action(&key, "decrypt", request.clone()).await;
    assert!(status.is_success(), "positive REST decrypt control: {body}");
    fixture.compromise(&key).await;
    let (status, body) = fixture.action(&key, "decrypt", request).await;
    assert_rest_state_denial(status, &body, "ordinary REST Decrypt on compromised key");
}

#[tokio::test]
async fn acceptance_02_grpc_decrypt_compromised_is_default_denied() {
    let fixture = Fixture::start(Some(false), false).await;
    let mut client = fixture.grpc().await;
    let key = client
        .create_key(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .metadata
        .unwrap()
        .key_id;
    let blob = client
        .encrypt(proto::EncryptRequest {
            key_id: key.clone(),
            plaintext: PLAINTEXT.into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .ciphertext_blob;
    let request = proto::DecryptRequest {
        key_id: key.clone(),
        ciphertext_blob: blob,
        ..Default::default()
    };
    assert_eq!(
        client
            .decrypt(request.clone())
            .await
            .unwrap()
            .into_inner()
            .plaintext,
        PLAINTEXT
    );
    client
        .report_key_compromise(proto::ReportKeyCompromiseRequest { key_id: key })
        .await
        .unwrap();
    assert_state_denial(client.decrypt(request).await, "independent gRPC Decrypt");
}

#[tokio::test]
async fn acceptance_03_reencrypt_compromised_source_is_default_denied() {
    let fixture = Fixture::start(Some(false), false).await;
    let source = fixture.create("AES_256", false).await;
    let destination = fixture.create("AES_256", false).await;
    let blob = fixture.encrypt(&source).await;
    let request = proto::ReEncryptRequest {
        source_key_id: source.clone(),
        destination_key_id: destination.clone(),
        ciphertext_blob: blob.clone(),
        ..Default::default()
    };
    fixture
        .grpc()
        .await
        .re_encrypt(request.clone())
        .await
        .unwrap();
    fixture.compromise(&source).await;
    let grpc_result = fixture.grpc().await.re_encrypt(request).await;
    let (status, body) = fixture
        .action(
            &source,
            "re-encrypt",
            json!({
                "destination_key_id": destination,
                "ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(blob),
            }),
        )
        .await;
    assert_state_denial(grpc_result, "ReEncrypt gRPC source");
    assert_rest_state_denial(status, &body, "ReEncrypt REST source");
}

#[tokio::test]
async fn acceptance_04_cached_pre_compromise_decrypt_is_not_reused() {
    let fixture = Fixture::start(Some(false), true).await;
    let key = fixture.create("AES_256", false).await;
    let blob = fixture.encrypt(&key).await;
    // Repeated successful requests warm the configured 1-hour record cache.
    // No TTL expiry, restart, or external invalidation can explain the denial.
    for _ in 0..3 {
        assert_eq!(fixture.decrypt(&key, &blob).await.unwrap(), PLAINTEXT);
    }
    fixture.compromise(&key).await;
    assert_state_denial(
        fixture.decrypt(&key, &blob).await,
        "cached pre-compromise state must not authorize Decrypt",
    );
}

#[tokio::test]
async fn acceptance_05_deletion_cancellation_does_not_restore_decrypt() {
    let fixture = Fixture::start(Some(false), false).await;
    let key = fixture.create("AES_256", false).await;
    let blob = fixture.encrypt(&key).await;
    fixture.compromise(&key).await;
    fixture.try_launder(&key).await;
    assert_state_denial(
        fixture.decrypt(&key, &blob).await,
        "Compromised -> PendingDeletion -> Disabled -> Enabled must not restore Decrypt",
    );
}

#[tokio::test]
async fn acceptance_06_deletion_cancellation_does_not_restore_raw_export() {
    let fixture = Fixture::start(Some(false), false).await;
    let key = fixture.create("AES_256", true).await;
    let request = proto::GetKeyMaterialRequest {
        key_id: key.clone(),
        ..Default::default()
    };
    let initial = fixture
        .grpc()
        .await
        .get_key_material(request.clone())
        .await
        .expect("positive raw-export control")
        .into_inner();
    assert_eq!(initial.key_material.len(), 32);
    assert!(!initial.wrapped, "this is raw material, not wrapped export");
    fixture.compromise(&key).await;
    fixture.try_launder(&key).await;
    assert_state_denial(
        fixture.grpc().await.get_key_material(request).await,
        "laundering must not re-permit raw material export",
    );
}

#[tokio::test]
async fn acceptance_07_compromise_history_survives_real_process_restart() {
    let mut fixture = Fixture::start(Some(false), false).await;
    let compromised = fixture.create("AES_256", false).await;
    let blob = fixture.encrypt(&compromised).await;
    let never_compromised = fixture.create("AES_256", false).await;
    fixture.compromise(&compromised).await;
    fixture.schedule(&compromised).await;
    fixture.schedule(&never_compromised).await;
    let old_pid = fixture.child.as_ref().unwrap().id();
    fixture.restart().await;
    assert_ne!(fixture.child.as_ref().unwrap().id(), old_pid);

    // Both live states were PendingDeletion before restart. The difference
    // must therefore survive in storage, not be reconstructed from live state.
    for key in [&compromised, &never_compromised] {
        let metadata = fixture
            .grpc()
            .await
            .get_key(proto::GetKeyRequest {
                key_id: key.clone(),
            })
            .await
            .unwrap()
            .into_inner()
            .metadata
            .unwrap();
        assert_eq!(metadata.state, i32::from(proto::KeyState::PendingDeletion));
    }
    for action in ["cancel-deletion", "enable"] {
        let (status, body) = fixture.action(&never_compromised, action, json!({})).await;
        assert!(
            status.is_success(),
            "never-compromised deletion cancellation must remain supported: {body}"
        );
    }
    fixture.cancel_and_enable(&compromised).await;
    let metadata = fixture
        .grpc()
        .await
        .get_key(proto::GetKeyRequest {
            key_id: compromised.clone(),
        })
        .await
        .unwrap()
        .into_inner()
        .metadata
        .unwrap();
    // Check lifecycle state, not merely a failed decrypt: the software
    // provider loses its process-local keys on restart, which would otherwise
    // make a broken implementation appear secure by returning ProviderError.
    assert_ne!(
        metadata.state,
        i32::from(proto::KeyState::Enabled),
        "persisted compromise history must block rehabilitation after restart"
    );
    assert_state_denial(
        fixture.decrypt(&compromised, &blob).await,
        "restart denial must be lifecycle failure, never missing provider material",
    );
    let fresh = fixture.create("AES_256", false).await;
    let fresh_blob = fixture.encrypt(&fresh).await;
    assert_eq!(
        fixture.decrypt(&fresh, &fresh_blob).await.unwrap(),
        PLAINTEXT
    );
}

#[tokio::test]
async fn acceptance_08_rotation_does_not_rehabilitate_any_version() {
    let fixture = Fixture::start(Some(false), false).await;
    let key = fixture.create("AES_256", false).await;
    let version_one = fixture.encrypt(&key).await;
    let (status, body) = fixture.action(&key, "rotate", json!({})).await;
    assert!(status.is_success(), "positive rotation control: {body}");
    let version_two = fixture.encrypt(&key).await;
    for blob in [&version_one, &version_two] {
        assert_eq!(fixture.decrypt(&key, blob).await.unwrap(), PLAINTEXT);
    }
    fixture.compromise(&key).await;
    let (status, body) = fixture.action(&key, "rotate", json!({})).await;
    assert_rest_state_denial(status, &body, "rotation while Compromised");
    fixture.try_launder(&key).await;
    let rotation = fixture.action(&key, "rotate", json!({})).await;
    let old_decrypt = fixture.decrypt(&key, &version_one).await;
    let new_decrypt = fixture.decrypt(&key, &version_two).await;
    assert_rest_state_denial(rotation.0, &rotation.1, "rotation after laundering attempt");
    assert_state_denial(old_decrypt, "historical ciphertext after compromise");
    assert_state_denial(new_decrypt, "current ciphertext after compromise");
}

#[tokio::test]
async fn acceptance_09_legacy_decrypt_and_source_reencrypt_emit_per_use_evidence() {
    let fixture = Fixture::start(Some(true), false).await;
    let source = fixture.create("AES_256", false).await;
    let destination = fixture.create("AES_256", false).await;
    let blob = fixture.encrypt(&source).await;
    // Ordinary use must not be labelled as an exceptional use.
    assert_eq!(fixture.decrypt(&source, &blob).await.unwrap(), PLAINTEXT);
    assert!(fixture
        .audit_events()
        .iter()
        .all(|event| event["metadata"][LEGACY_FLAG].is_null()));
    fixture.compromise(&source).await;
    let before = fixture.audit_events().len();
    let warnings_before = fixture
        .logs()
        .lines()
        .filter(|line| line.contains("WARN") && line.contains(LEGACY_FLAG))
        .count();
    assert_eq!(fixture.decrypt(&source, &blob).await.unwrap(), PLAINTEXT);
    let (status, body) = fixture
        .action(
            &source,
            "decrypt",
            json!({"ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(&blob)}),
        )
        .await;
    assert!(status.is_success(), "legacy REST Decrypt: {body}");
    let reencrypted = fixture
        .grpc()
        .await
        .re_encrypt(proto::ReEncryptRequest {
            source_key_id: source.clone(),
            destination_key_id: destination.clone(),
            ciphertext_blob: blob.clone(),
            ..Default::default()
        })
        .await
        .expect("legacy source-side ReEncrypt")
        .into_inner();
    assert_eq!(
        fixture
            .decrypt(&destination, &reencrypted.ciphertext_blob)
            .await
            .unwrap(),
        PLAINTEXT
    );
    let (status, body) = fixture
        .action(
            &source,
            "re-encrypt",
            json!({
                "destination_key_id": destination,
                "ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(blob),
            }),
        )
        .await;
    assert!(
        status.is_success(),
        "legacy REST source-side ReEncrypt: {body}"
    );
    let events = fixture.audit_events();
    let marked: Vec<_> = events[before..]
        .iter()
        .filter(|event| !event["metadata"][LEGACY_FLAG].is_null())
        .collect();
    assert_eq!(
        marked.len(),
        4,
        "one structured marker per exceptional use: {events:?}"
    );
    for event in &marked {
        assert_eq!(event["metadata"][LEGACY_FLAG], json!("true"));
        assert_eq!(event["resource"]["id"], source);
        assert!(
            matches!(
                event["action"].as_str(),
                Some("kms:Decrypt" | "kms:ReEncrypt" | "kms:ReEncryptFrom")
            ),
            "marker belongs to exceptional decrypt/source operation: {event}"
        );
    }
    let warnings = fixture.logs();
    assert_eq!(
        warnings
            .lines()
            .filter(|line| line.contains("WARN") && line.contains(LEGACY_FLAG))
            .count()
            - warnings_before,
        4,
        "one named warning per exceptional use, distinct from startup: {warnings}"
    );
}

async fn prohibited_operations(
    fixture: &Fixture,
    aes: &str,
    signing: &str,
    source: &str,
    blob: &[u8],
) {
    let mut client = fixture.grpc().await;
    let encrypt = client
        .encrypt(proto::EncryptRequest {
            key_id: aes.into(),
            plaintext: PLAINTEXT.into(),
            ..Default::default()
        })
        .await;
    let sign = client
        .sign(proto::SignRequest {
            key_id: signing.into(),
            message: PLAINTEXT.into(),
            signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
            ..Default::default()
        })
        .await;
    let destination = client
        .re_encrypt(proto::ReEncryptRequest {
            source_key_id: source.into(),
            destination_key_id: aes.into(),
            ciphertext_blob: blob.into(),
            ..Default::default()
        })
        .await;
    let export = client
        .get_key_material(proto::GetKeyMaterialRequest {
            key_id: aes.into(),
            ..Default::default()
        })
        .await;
    assert_state_denial(encrypt, "legacy flag must not permit Encrypt");
    assert_state_denial(sign, "legacy flag must not permit Sign");
    assert_state_denial(
        destination,
        "legacy flag must not permit ReEncrypt destination",
    );
    assert_state_denial(export, "legacy flag must not permit raw export");
}

#[tokio::test]
async fn acceptance_10_legacy_flag_does_not_enable_non_decrypt_operations() {
    let fixture = Fixture::start(Some(true), false).await;
    let aes = fixture.create("AES_256", true).await;
    let signing = fixture.create("ED25519", false).await;
    let source = fixture.create("AES_256", false).await;
    let blob = fixture.encrypt(&source).await;
    // Positive controls rule out bad algorithms, missing material, or a
    // non-exportable fixture masquerading as successful lifecycle enforcement.
    fixture.encrypt(&aes).await;
    fixture
        .grpc()
        .await
        .sign(proto::SignRequest {
            key_id: signing.clone(),
            message: PLAINTEXT.into(),
            signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let raw = fixture
        .grpc()
        .await
        .get_key_material(proto::GetKeyMaterialRequest {
            key_id: aes.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(raw.key_material.len(), 32);
    fixture
        .grpc()
        .await
        .re_encrypt(proto::ReEncryptRequest {
            source_key_id: source.clone(),
            destination_key_id: aes.clone(),
            ciphertext_blob: blob.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    fixture.compromise(&aes).await;
    fixture.compromise(&signing).await;
    // These direct prohibitions already existed on the baseline; retain them
    // as controls. The baseline failure is the genuine laundering bypass below.
    prohibited_operations(&fixture, &aes, &signing, &source, &blob).await;
    fixture.try_launder(&aes).await;
    fixture.try_launder(&signing).await;
    prohibited_operations(&fixture, &aes, &signing, &source, &blob).await;
}

#[tokio::test]
async fn acceptance_11_legacy_opt_in_warns_by_name_on_every_start() {
    let mut fixture = Fixture::start(Some(true), false).await;
    for start in 1..=2 {
        let logs = fixture.logs();
        assert!(
            logs.lines()
                .any(|line| line.contains("WARN") && line.contains(LEGACY_FLAG)),
            "startup {start} must WARN naming the legacy flag: {logs}"
        );
        if start == 1 {
            fixture.restart().await;
        }
    }
}

#[tokio::test]
async fn acceptance_12_missing_legacy_config_is_not_permission() {
    let fixture = Fixture::start(None, false).await;
    assert!(!std::fs::read_to_string(fixture.dir.join("config.yaml"))
        .unwrap()
        .contains(LEGACY_FLAG));
    let key = fixture.create("AES_256", false).await;
    let blob = fixture.encrypt(&key).await;
    fixture.compromise(&key).await;
    assert_state_denial(
        fixture.decrypt(&key, &blob).await,
        "absent legacy config must default deny",
    );
}

#[tokio::test]
async fn cache_second_process_compromise_cannot_reuse_first_process_enabled_record() {
    let fixture = Fixture::start(Some(false), true).await;
    let key = fixture.create("AES_256", false).await;
    let blob = fixture.encrypt(&key).await;
    for _ in 0..3 {
        assert_eq!(fixture.decrypt(&key, &blob).await.unwrap(), PLAINTEXT);
    }
    let mut second = Fixture::start(Some(false), false).await;
    second.stop();
    let config_path = second.dir.join("config.yaml");
    let config = std::fs::read_to_string(&config_path).unwrap().replace(
        &second.dir.join("keys.sqlite").display().to_string(),
        &fixture.dir.join("keys.sqlite").display().to_string(),
    );
    std::fs::write(config_path, config).unwrap();
    second.spawn().await;
    // This lifecycle update is written by a different process, with no shared
    // cache instance or notification bus. The first still owns the actual
    // software-provider key, so its answer tests state enforcement, not key loss.
    second.compromise(&key).await;
    assert_state_denial(
        fixture.decrypt(&key, &blob).await,
        "a second process's durable compromise must override a warm Enabled cache",
    );
}
