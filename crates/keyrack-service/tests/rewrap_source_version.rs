// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the version RPCs report about a retained key version, exercised
//! through the real service binary.
//!
//! A `KeyVersionRecord` has no lifecycle state of its own, so the state
//! reported for a version is the owning logical key's. Being non-primary is an
//! ordinal fact about rotation order and is reported by `is_primary`. Reporting
//! non-primary versions as `Disabled` made a retained, perfectly decryptable
//! source version read as unusable to any consumer that gates on the reported
//! state, which is how a rewrap that went pending during an outage was refused
//! after the healthy key rotated underneath it.
//!
//! The state assertions here are written in the terms a rewrap consumer uses,
//! not in terms of the enum, via [`consumer_accepts_source`].

use base64::Engine as _;
use keyrack_service::proto;
use proto::key_service_client::KeyServiceClient;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tonic::transport::Channel;

const SERVICE_BIN: &str = env!("CARGO_BIN_EXE_keyrack-service");
const PLAINTEXT: &[u8] = b"data encrypted under the version that was primary then";

/// The eligibility rule a rewrap consumer applies to a source version: it must
/// be the version named by the ciphertext envelope, and its reported state must
/// permit use. Reproduced here so these tests fail for the reason the caller
/// fails, rather than merely pinning an enum value.
fn consumer_accepts_source(version: &proto::KeyVersionMetadata, envelope_version: u32) -> bool {
    version.version == envelope_version && version.state == i32::from(proto::KeyState::Enabled)
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
        let dir = std::env::temp_dir().join(format!("keyrack-rewrap-src-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).expect("create isolated fixture directory");
        // Hold both reservations until both ports have been selected.
        let rest_listener = TcpListener::bind("127.0.0.1:0").expect("REST port");
        let grpc_listener = TcpListener::bind("127.0.0.1:0").expect("gRPC port");
        let rest_port = rest_listener.local_addr().unwrap().port();
        let grpc_port = grpc_listener.local_addr().unwrap().port();
        let config = format!(
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

    async fn grpc(&self) -> KeyServiceClient<Channel> {
        KeyServiceClient::connect(self.grpc.clone()).await.unwrap()
    }

    async fn action(&self, key: &str, action: &str, body: Value) -> (StatusCode, Value) {
        let response = self
            .client
            .post(format!("{}/v1/keys/{key}/actions-{action}", self.rest))
            .json(&body)
            .send()
            .await
            .expect("REST request reached real binary");
        let status = response.status();
        let body = response.json().await.expect("JSON REST response");
        (status, body)
    }

    async fn create(&self) -> String {
        let response = self
            .client
            .post(format!("{}/v1/keys", self.rest))
            .json(&json!({"key_spec": "AES_256", "exportable": false}))
            .send()
            .await
            .expect("create fixture key");
        assert_eq!(response.status(), StatusCode::CREATED);
        let body: Value = response.json().await.unwrap();
        body["lid"].as_str().expect("key LID").to_owned()
    }

    async fn encrypt(&self, key: &str) -> Vec<u8> {
        self.grpc()
            .await
            .encrypt(proto::EncryptRequest {
                key_id: key.into(),
                plaintext: PLAINTEXT.into(),
                ..Default::default()
            })
            .await
            .expect("positive control: encrypt under the current primary version")
            .into_inner()
            .ciphertext_blob
    }

    /// Rotation makes a new version primary and retains the old one. This is
    /// the "healthy KEK rotated underneath a pending rewrap" step.
    async fn rotate(&self, key: &str) {
        let (status, body) = self.action(key, "rotate", json!({})).await;
        assert!(status.is_success(), "positive rotation control: {body}");
    }

    async fn version(&self, key: &str, version: u32) -> proto::KeyVersionMetadata {
        self.grpc()
            .await
            .get_key_version(proto::GetKeyVersionRequest {
                key_id: key.into(),
                version,
            })
            .await
            .expect("GetKeyVersion for a retained version")
            .into_inner()
            .version
            .expect("version metadata")
    }

    async fn versions(&self, key: &str) -> Vec<proto::KeyVersionMetadata> {
        self.grpc()
            .await
            .list_key_versions(proto::ListKeyVersionsRequest {
                key_id: key.into(),
                ..Default::default()
            })
            .await
            .expect("ListKeyVersions")
            .into_inner()
            .versions
    }

    #[allow(clippy::result_large_err)] // Keep the status for lifecycle assertions.
    async fn re_encrypt(
        &self,
        source: &str,
        destination: &str,
        blob: &[u8],
    ) -> Result<Vec<u8>, tonic::Status> {
        self.grpc()
            .await
            .re_encrypt(proto::ReEncryptRequest {
                source_key_id: source.into(),
                destination_key_id: destination.into(),
                ciphertext_blob: blob.into(),
                ..Default::default()
            })
            .await
            .map(|response| response.into_inner().ciphertext_blob)
    }

    #[allow(clippy::result_large_err)] // Keep the status for lifecycle assertions.
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

    async fn rest_re_encrypt(
        &self,
        source: &str,
        destination: &str,
        blob: &[u8],
    ) -> (StatusCode, Value) {
        self.action(
            source,
            "re-encrypt",
            json!({
                "destination_key_id": destination,
                "ciphertext_blob": base64::engine::general_purpose::STANDARD.encode(blob),
            }),
        )
        .await
    }

    async fn compromise(&self, key: &str) {
        let (status, body) = self.action(key, "report-compromise", json!({})).await;
        assert!(status.is_success(), "report compromise: {status} {body}");
    }

    async fn disable(&self, key: &str) {
        let (status, body) = self.action(key, "disable", json!({})).await;
        assert!(status.is_success(), "disable key: {status} {body}");
    }

    /// Attempt to walk a compromised key back to a benign-looking live state.
    /// Refusal and a retained sticky denial are both valid outcomes (§PR #33);
    /// what must not happen is the version reporting as usable afterwards.
    async fn try_launder(&self, key: &str) {
        let (status, body) = self
            .action(key, "schedule-deletion", json!({"grace_period_days": 30}))
            .await;
        assert!(status.is_success(), "schedule deletion: {status} {body}");
        for action in ["cancel-deletion", "enable"] {
            let (status, body) = self.action(key, action, json!({})).await;
            assert!(
                status.is_success() || status == StatusCode::CONFLICT,
                "lifecycle request must be evaluated: {action}: {status} {body}"
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

fn assert_state_denial<T: std::fmt::Debug>(result: Result<T, tonic::Status>, context: &str) {
    let error = result.expect_err(context);
    assert_eq!(
        error.code(),
        tonic::Code::FailedPrecondition,
        "must be a lifecycle denial, not missing provider material: {context}: {error}"
    );
}

/// The reported defect: a rewrap goes pending during an outage, the healthy key
/// rotates, and the retry is then refused because the retained source version
/// reports as unusable. The rewrap itself proves the data was decryptable
/// throughout, so the report was wrong rather than the operation unsafe.
#[tokio::test]
async fn retained_source_version_stays_usable_after_the_key_rotates() {
    let fixture = Fixture::start().await;
    let source = fixture.create().await;
    let destination = fixture.create().await;
    let pending = fixture.encrypt(&source).await;

    fixture.rotate(&source).await;
    // The envelope still names version 1; version 2 is now primary.
    let retained = fixture.version(&source, 1).await;
    let primary = fixture.version(&source, 2).await;

    assert!(
        !retained.is_primary,
        "version 1 is no longer primary and must say so through is_primary"
    );
    assert!(primary.is_primary, "version 2 is the new primary");
    assert_eq!(
        retained.state,
        i32::from(proto::KeyState::Enabled),
        "a retained version of a healthy key must not report a policy state it does not have"
    );
    assert!(
        consumer_accepts_source(&retained, 1),
        "the retained version named by the envelope must be an eligible rewrap source"
    );

    let rewrapped = fixture
        .re_encrypt(&source, &destination, &pending)
        .await
        .expect("rewrap from the retained source version");
    assert_eq!(
        fixture.decrypt(&destination, &rewrapped).await.unwrap(),
        PLAINTEXT,
        "the data was decryptable under the retained version all along"
    );
    let (status, body) = fixture
        .rest_re_encrypt(&source, &destination, &pending)
        .await;
    assert!(
        status.is_success(),
        "REST rewrap of the same envelope: {body}"
    );
}

/// `ListKeyVersions` must distinguish the primary without overloading state,
/// so a consumer reading the list alone can still tell them apart.
#[tokio::test]
async fn listed_versions_report_retention_separately_from_state() {
    let fixture = Fixture::start().await;
    let key = fixture.create().await;
    fixture.rotate(&key).await;
    fixture.rotate(&key).await;

    let versions = fixture.versions(&key).await;
    assert_eq!(versions.len(), 3, "two rotations retain three versions");
    assert_eq!(
        versions.iter().filter(|v| v.is_primary).count(),
        1,
        "exactly one version is primary: {versions:?}"
    );
    assert!(
        versions
            .iter()
            .all(|v| v.state == i32::from(proto::KeyState::Enabled)),
        "every retained version of a healthy key reports the key's state: {versions:?}"
    );
    assert!(
        versions.iter().find(|v| v.is_primary).unwrap().version == 3,
        "the newest version is primary: {versions:?}"
    );
}

/// The boundary: this is not permission to rewrap from a key an operator has
/// withdrawn. Core still permits decrypt of a `Disabled` key for data
/// recovery, so the assertion is about what is reported to a consumer that
/// gates on state — every version of a disabled key must read as ineligible,
/// including the primary one, which previously reported `Enabled`.
#[tokio::test]
async fn disabled_key_versions_are_reported_ineligible_as_rewrap_sources() {
    let fixture = Fixture::start().await;
    let key = fixture.create().await;
    let blob = fixture.encrypt(&key).await;
    fixture.rotate(&key).await;
    // Positive control: eligible before the withdrawal, so the assertions
    // below measure the disable and not a broken fixture.
    assert!(consumer_accepts_source(&fixture.version(&key, 1).await, 1));

    fixture.disable(&key).await;

    for version in 1..=2 {
        let reported = fixture.version(&key, version).await;
        assert_eq!(
            reported.state,
            i32::from(proto::KeyState::Disabled),
            "version {version} of a disabled key must report Disabled"
        );
        assert!(
            !consumer_accepts_source(&reported, version),
            "version {version} of a disabled key must not be an eligible source"
        );
    }
    // Non-regression on the data-recovery latitude Core deliberately keeps.
    assert_eq!(fixture.decrypt(&key, &blob).await.unwrap(), PLAINTEXT);
}

/// PR #33's denial must survive this change: a compromised key's versions
/// report `Compromised`, and native rewrap from it stays refused outright.
#[tokio::test]
async fn compromised_key_versions_are_refused_as_rewrap_sources() {
    let fixture = Fixture::start().await;
    let source = fixture.create().await;
    let destination = fixture.create().await;
    let blob = fixture.encrypt(&source).await;
    fixture.rotate(&source).await;
    fixture.compromise(&source).await;

    // The permissive half of the same defect. Deriving state from the ordinal
    // made the primary version of a compromised key report Enabled, so a
    // consumer gating on the reported state would have accepted it.
    assert!(
        !consumer_accepts_source(&fixture.version(&source, 2).await, 2),
        "the primary version of a compromised key must never read as eligible"
    );
    for version in 1..=2 {
        let reported = fixture.version(&source, version).await;
        assert_eq!(
            reported.state,
            i32::from(proto::KeyState::Compromised),
            "version {version} of a compromised key must report Compromised"
        );
        assert!(!consumer_accepts_source(&reported, version));
    }
    assert_state_denial(
        fixture.re_encrypt(&source, &destination, &blob).await,
        "rewrap from a compromised source",
    );
    assert_state_denial(
        fixture.decrypt(&source, &blob).await,
        "decrypt of a compromised source",
    );
}

/// Compromise history is durable and must not be masked by a later live state.
/// Reporting the live state alone would let a laundered key's versions read as
/// usable while [`KeyRecord::permits_decrypt`] refuses them.
///
/// [`KeyRecord::permits_decrypt`]: keyrack_core::key::KeyRecord::permits_decrypt
#[tokio::test]
async fn compromise_history_is_not_masked_by_a_later_lifecycle_state() {
    let fixture = Fixture::start().await;
    let source = fixture.create().await;
    let destination = fixture.create().await;
    let blob = fixture.encrypt(&source).await;
    fixture.rotate(&source).await;
    fixture.compromise(&source).await;
    fixture.try_launder(&source).await;

    assert!(
        !consumer_accepts_source(&fixture.version(&source, 2).await, 2),
        "a laundered key's primary version must never read as eligible"
    );
    for version in 1..=2 {
        let reported = fixture.version(&source, version).await;
        assert_eq!(
            reported.state,
            i32::from(proto::KeyState::Compromised),
            "version {version} must keep reporting compromise history after laundering"
        );
        assert!(
            !consumer_accepts_source(&reported, version),
            "a laundered key's version {version} must not become an eligible source"
        );
    }
    assert_state_denial(
        fixture.re_encrypt(&source, &destination, &blob).await,
        "rewrap after a laundering attempt",
    );
    assert_state_denial(
        fixture.decrypt(&source, &blob).await,
        "decrypt after a laundering attempt",
    );
}
