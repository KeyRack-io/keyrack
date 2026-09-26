// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use keyrack_core::provider::CryptoProvider;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Service {
    dir: PathBuf,
    child: Child,
    base: String,
    client: reqwest::Client,
}
impl Service {
    fn start(provider: &Value) -> Self {
        let rest = TcpListener::bind("127.0.0.1:0").unwrap();
        let grpc = TcpListener::bind("127.0.0.1:0").unwrap();
        let dir =
            std::env::temp_dir().join(format!("keyrack-availability-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let config = json!({
            "rest_addr": rest.local_addr().unwrap().to_string(),
            "grpc_addr": grpc.local_addr().unwrap().to_string(),
            "storage": {"type":"memory"},
            "providers": [ {"name":"platform", "type":"software"}, provider ],
            "default_provider": "external",
            "pdp": {"type":"always_allow"}, "authn":{"type":"insecure"},
            "audit":{"type":"file", "path":dir.join("audit.jsonl")}
        });
        let base = format!("http://{}", rest.local_addr().unwrap());
        std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
        let output = std::fs::File::create(dir.join("output")).unwrap();
        drop((rest, grpc));
        let child = Command::new(env!("CARGO_BIN_EXE_keyrack-service"))
            .env("KEYRACK_CONFIG", dir.join("config.json"))
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap();
        Self {
            dir,
            child,
            base,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }
    fn logs(&self) -> String {
        std::fs::read_to_string(self.dir.join("output")).unwrap()
    }
    async fn readiness(&mut self, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "service must stay running: {}",
                self.logs()
            );
            if let Ok(response) = self
                .client
                .get(format!("{}/readyz", self.base))
                .send()
                .await
            {
                let status = response.status();
                let body: Value = response.json().await.unwrap();
                assert_eq!(
                    status,
                    StatusCode::OK,
                    "optional backend must not gate readiness: {body}"
                );
                assert_eq!(body["provider_states"]["platform"]["status"], "available");
                assert_eq!(body["provider_states"]["external"]["custody"], "customer");
                if body["provider_states"]["external"]["status"] == expected {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "provider never became {expected}: {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    async fn post(&self, path: &str, value: Value) -> (StatusCode, Value) {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .json(&value)
            .send()
            .await
            .unwrap();
        (response.status(), response.json().await.unwrap())
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn vault(addr: &str, token: &str) -> Value {
    json!({"name":"external", "custody":"customer", "type":"vault_transit", "vault_addr":addr,"vault_token":token})
}

#[tokio::test]
async fn unreachable_optional_vault_boots_and_refuses_operations() {
    // Keep the port reserved but never accept: construction cannot succeed.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut service = Service::start(&vault(
        &format!("http://{}", listener.local_addr().unwrap()),
        "token",
    ));
    service.readiness("unavailable").await;
    let (status, body) = service
        .post("/v1/keys", json!({"key_spec":"AES_256"}))
        .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "unconstructed provider must refuse: {body}"
    );
}

#[tokio::test]
async fn invalid_optional_configuration_fails_before_listening() {
    for provider in [
        vault("not a URL", "token"),
        json!({"name":"external","custody":"customer","type":"pkcs11","lib_path":"/missing/library.so","token_label":"token","pin":"pin"}),
    ] {
        let mut service = Service::start(&provider);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = service.child.try_wait().unwrap() {
                assert!(!status.success(), "invalid configuration must fail startup");
                assert!(
                    service.logs().contains("invalid"),
                    "must fail for local configuration: {}",
                    service.logs()
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "invalid configuration was deferred instead of rejected"
            );
            assert!(
                service
                    .client
                    .get(format!("{}/healthz", service.base))
                    .send()
                    .await
                    .is_err(),
                "invalid provider must not start listener"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

// The runner supplies this capability only for its own disposable instance.
// Restore on unwinding too, so a failed assertion cannot poison later checks.
struct Unseal {
    address: String,
    key: String,
}
impl Unseal {
    fn restore(&self) {
        let mut child = Command::new("curl")
            .args([
                "--silent",
                "--fail",
                "--max-time",
                "10",
                "-X",
                "PUT",
                "--data-binary",
                "@-",
                &format!("{}/v1/sys/unseal", self.address),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(json!({"key":self.key}).to_string().as_bytes())
            .unwrap();
        assert!(
            child.wait().unwrap().success(),
            "fixture unseal must succeed"
        );
    }
}
impl Drop for Unseal {
    fn drop(&mut self) {
        self.restore();
    }
}

#[tokio::test]
#[ignore = "requires the isolated Vault fixture from scripts/test-vault-provider.sh"]
async fn sealed_optional_vault_boots_and_recovers_existing_ciphertext_without_restart() {
    let address = std::env::var("VAULT_ADDR").unwrap();
    let token = std::env::var("VAULT_TOKEN").unwrap();
    let restore = Unseal {
        address: address.clone(),
        key: std::env::var("KEYRACK_VAULT_TEST_UNSEAL_KEY")
            .expect("owned fixture unseal capability required"),
    };
    let client = reqwest::Client::new();
    let seal = || {
        client
            .put(format!("{address}/v1/sys/seal"))
            .header("X-Vault-Token", &token)
            .send()
    };
    assert!(seal().await.unwrap().status().is_success());
    let mut service = Service::start(&vault(&address, &token));
    let pid = service.child.id();
    service.readiness("unavailable").await;
    assert_eq!(
        service
            .post("/v1/keys", json!({"key_spec":"AES_256"}))
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    restore.restore();
    service.readiness("available").await;
    let direct = keyrack_vault::VaultTransitProvider::new(&address, &token, None)
        .await
        .unwrap();
    assert_eq!(
        direct.capabilities(),
        keyrack_service::provider_startup::remote_capabilities(
            keyrack_core::key::ProviderClass::VaultTransit
        ),
        "offline capabilities must match live Vault"
    );
    let (status, key) = service
        .post("/v1/keys", json!({"key_spec":"AES_256"}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{key}");
    let lid = key["lid"].as_str().unwrap();
    let encrypt = format!("/v1/keys/{lid}/actions-encrypt");
    let (status, ciphertext) = service
        .post(&encrypt, json!({"plaintext":"cmVjb3Zlcnk="}))
        .await;
    assert_eq!(status, StatusCode::OK, "{ciphertext}");
    assert!(seal().await.unwrap().status().is_success());
    service.readiness("unavailable").await;
    assert_eq!(
        service
            .post(&encrypt, json!({"plaintext":"cmVjb3Zlcnk="}))
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    restore.restore();
    service.readiness("available").await;
    let (status, plaintext) = service
        .post(
            &format!("/v1/keys/{lid}/actions-decrypt"),
            json!({"ciphertext_blob":ciphertext["ciphertext_blob"]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{plaintext}");
    assert_eq!(plaintext["plaintext"], "cmVjb3Zlcnk=");
    assert_eq!(
        service.child.id(),
        pid,
        "recovery must use the original process"
    );
}
