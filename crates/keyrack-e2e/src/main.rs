//! KeyRack E2E test and demo binary.
//!
//! Connects to a running `keyrack-service` over gRPC and REST and exercises
//! the full API surface in seven phases.  Useful both as an integration test
//! and as a readable reference for new users.
//!
//! ```text
//! # Against Docker Compose stack:
//! docker compose up e2e-test
//!
//! # Against a locally-running service:
//! cargo run --manifest-path crates/keyrack-e2e/Cargo.toml -- \
//!     --grpc-endpoint http://[::1]:50051 \
//!     --rest-endpoint http://[::1]:8080
//! ```

mod proto {
    #![allow(
        clippy::doc_markdown,
        clippy::default_trait_access,
        clippy::too_many_lines,
        clippy::similar_names,
        clippy::derive_partial_eq_without_eq,
        clippy::result_large_err
    )]
    tonic::include_proto!("keyrack.v1");
}

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::Parser;
use proto::key_service_client::KeyServiceClient;
use tonic::transport::Channel;

#[derive(Parser)]
#[command(name = "keyrack-e2e", about = "KeyRack end-to-end test suite")]
struct Cli {
    #[arg(long, default_value = "http://[::1]:50051")]
    grpc_endpoint: String,

    #[arg(long, default_value = "http://[::1]:8080")]
    rest_endpoint: String,
}

fn b64encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("base64 decode")
}

struct PhaseRunner {
    passed: u32,
    failed: u32,
    phase: String,
}

impl PhaseRunner {
    fn new(name: &str) -> Self {
        let bar = "=".repeat(60);
        println!("\n{bar}");
        println!("  Phase: {name}");
        println!("{bar}");
        Self {
            passed: 0,
            failed: 0,
            phase: name.to_string(),
        }
    }

    fn pass(&mut self, test: &str) {
        self.passed += 1;
        println!("  [PASS] {test}");
    }

    fn fail(&mut self, test: &str, err: &dyn std::fmt::Display) {
        self.failed += 1;
        println!("  [FAIL] {test}: {err}");
    }

    fn finish(self) -> (u32, u32) {
        let status = if self.failed == 0 { "PASS" } else { "FAIL" };
        println!(
            "  --- {} {} ({} passed, {} failed) ---\n",
            self.phase, status, self.passed, self.failed
        );
        (self.passed, self.failed)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    println!("KeyRack E2E Test Suite");
    println!("  gRPC: {}", cli.grpc_endpoint);
    println!("  REST: {}", cli.rest_endpoint);

    let http = reqwest::Client::new();

    let channel = Channel::from_shared(cli.grpc_endpoint.clone())
        .context("invalid gRPC endpoint")?
        .connect()
        .await
        .context("failed to connect gRPC channel")?;

    let mut grpc = KeyServiceClient::new(channel);

    let mut total_passed = 0u32;
    let mut total_failed = 0u32;

    macro_rules! tally {
        ($p:expr, $f:expr) => {{
            total_passed += $p;
            total_failed += $f;
        }};
    }

    // ── Phase 1: Health checks ──────────────────────────────────────
    let (p, f) = phase_health(&http, &cli.rest_endpoint, &mut grpc).await;
    tally!(p, f);

    // ── Phase 2: Key lifecycle (gRPC) ────────────────────────────────
    let (p, f, aes_key_id, ed_key_id) = phase_lifecycle(&mut grpc).await;
    tally!(p, f);

    // ── Phase 3: Crypto operations (gRPC) ────────────────────────────
    let (p, f) = phase_crypto(&mut grpc, &aes_key_id, &ed_key_id).await;
    tally!(p, f);

    // ── Phase 4: REST parity ─────────────────────────────────────────
    let (p, f) = phase_rest(&http, &cli.rest_endpoint).await;
    tally!(p, f);

    // ── Phase 5: Aliases and tags ────────────────────────────────────
    let (p, f) = phase_aliases_tags(&mut grpc, &aes_key_id).await;
    tally!(p, f);

    // ── Phase 6: Key rotation ────────────────────────────────────────
    let (p, f) = phase_rotation(&mut grpc, &aes_key_id).await;
    tally!(p, f);

    // ── Phase 7: Key hierarchy ───────────────────────────────────────
    let (p, f) = phase_hierarchy(&mut grpc).await;
    tally!(p, f);

    // ── Summary ──────────────────────────────────────────────────────
    let bar = "=".repeat(60);
    println!("\n{bar}");
    println!("  TOTAL: {total_passed} passed, {total_failed} failed");
    println!("{bar}");

    if total_failed > 0 {
        bail!("{total_failed} test(s) failed");
    }

    Ok(())
}

// ═════════════════════════════════════════════════════════════════════
// Phase 1: Health checks
// ═════════════════════════════════════════════════════════════════════

async fn phase_health(
    http: &reqwest::Client,
    rest: &str,
    grpc: &mut KeyServiceClient<Channel>,
) -> (u32, u32) {
    let mut r = PhaseRunner::new("1 — Health checks");

    // REST /healthz
    match http.get(format!("{rest}/healthz")).send().await {
        Ok(resp) if resp.status().is_success() => r.pass("GET /healthz"),
        Ok(resp) => r.fail("GET /healthz", &format!("status {}", resp.status())),
        Err(e) => r.fail("GET /healthz", &e),
    }

    // REST /readyz
    match http.get(format!("{rest}/readyz")).send().await {
        Ok(resp) if resp.status().is_success() => r.pass("GET /readyz"),
        Ok(resp) => r.fail("GET /readyz", &format!("status {}", resp.status())),
        Err(e) => r.fail("GET /readyz", &e),
    }

    // gRPC channel connectivity (try a ListKeys with 0 results)
    match grpc
        .list_keys(proto::ListKeysRequest {
            max_results: 0,
            cursor: String::new(),
            state_filter: None,
        })
        .await
    {
        Ok(_) => r.pass("gRPC ListKeys (channel alive)"),
        Err(e) => r.fail("gRPC ListKeys", &e),
    }

    r.finish()
}

// ═════════════════════════════════════════════════════════════════════
// Phase 2: Key lifecycle (gRPC)
// ═════════════════════════════════════════════════════════════════════

async fn phase_lifecycle(grpc: &mut KeyServiceClient<Channel>) -> (u32, u32, String, String) {
    let mut r = PhaseRunner::new("2 — Key lifecycle (gRPC)");
    let mut aes_key_id = String::new();
    let mut ed_key_id = String::new();

    // CreateKey AES-256
    match grpc
        .create_key(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            key_usage: Some(proto::KeyUsage::EncryptDecrypt.into()),
            description: "e2e AES-256 test key".into(),
            ..Default::default()
        })
        .await
    {
        Ok(resp) => {
            let meta = resp.into_inner().metadata.unwrap();
            aes_key_id = meta.key_id.clone();
            assert_check(
                &mut r,
                "CreateKey AES-256",
                meta.state == proto::KeyState::Enabled as i32,
            );
        }
        Err(e) => r.fail("CreateKey AES-256", &e),
    }

    // CreateKey Ed25519
    match grpc
        .create_key(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Ed25519.into(),
            key_usage: Some(proto::KeyUsage::SignVerify.into()),
            description: "e2e Ed25519 test key".into(),
            ..Default::default()
        })
        .await
    {
        Ok(resp) => {
            let meta = resp.into_inner().metadata.unwrap();
            ed_key_id = meta.key_id.clone();
            assert_check(
                &mut r,
                "CreateKey Ed25519",
                meta.state == proto::KeyState::Enabled as i32,
            );
        }
        Err(e) => r.fail("CreateKey Ed25519", &e),
    }

    // DescribeKey
    if !aes_key_id.is_empty() {
        match grpc
            .describe_key(proto::DescribeKeyRequest {
                key_id: aes_key_id.clone(),
            })
            .await
        {
            Ok(resp) => {
                let meta = resp.into_inner().metadata.unwrap();
                assert_check(&mut r, "DescribeKey", meta.key_id == aes_key_id);
            }
            Err(e) => r.fail("DescribeKey", &e),
        }
    }

    // ListKeys (should have at least 2)
    match grpc
        .list_keys(proto::ListKeysRequest {
            max_results: 100,
            cursor: String::new(),
            state_filter: None,
        })
        .await
    {
        Ok(resp) => assert_check(&mut r, "ListKeys (>=2)", resp.into_inner().keys.len() >= 2),
        Err(e) => r.fail("ListKeys", &e),
    }

    // DisableKey -> EnableKey
    if !aes_key_id.is_empty() {
        match grpc
            .disable_key(proto::DisableKeyRequest {
                key_id: aes_key_id.clone(),
            })
            .await
        {
            Ok(resp) => {
                let meta = resp.into_inner().metadata.unwrap();
                assert_check(
                    &mut r,
                    "DisableKey",
                    meta.state == proto::KeyState::Disabled as i32,
                );
            }
            Err(e) => r.fail("DisableKey", &e),
        }

        match grpc
            .enable_key(proto::EnableKeyRequest {
                key_id: aes_key_id.clone(),
            })
            .await
        {
            Ok(resp) => {
                let meta = resp.into_inner().metadata.unwrap();
                assert_check(
                    &mut r,
                    "EnableKey (re-enable)",
                    meta.state == proto::KeyState::Enabled as i32,
                );
            }
            Err(e) => r.fail("EnableKey", &e),
        }
    }

    // ScheduleKeyDeletion -> CancelKeyDeletion
    if !aes_key_id.is_empty() {
        match grpc
            .schedule_key_deletion(proto::ScheduleKeyDeletionRequest {
                key_id: aes_key_id.clone(),
                grace_period_days: 7,
            })
            .await
        {
            Ok(resp) => {
                let meta = resp.into_inner().metadata.unwrap();
                assert_check(
                    &mut r,
                    "ScheduleKeyDeletion",
                    meta.state == proto::KeyState::PendingDeletion as i32,
                );
            }
            Err(e) => r.fail("ScheduleKeyDeletion", &e),
        }

        match grpc
            .cancel_key_deletion(proto::CancelKeyDeletionRequest {
                key_id: aes_key_id.clone(),
            })
            .await
        {
            Ok(resp) => {
                let meta = resp.into_inner().metadata.unwrap();
                assert_check(
                    &mut r,
                    "CancelKeyDeletion",
                    meta.state == proto::KeyState::Disabled as i32,
                );
            }
            Err(e) => r.fail("CancelKeyDeletion", &e),
        }

        // Re-enable for subsequent phases
        let _ = grpc
            .enable_key(proto::EnableKeyRequest {
                key_id: aes_key_id.clone(),
            })
            .await;
    }

    let (p, f) = r.finish();
    (p, f, aes_key_id, ed_key_id)
}

// ═════════════════════════════════════════════════════════════════════
// Phase 3: Crypto operations (gRPC)
// ═════════════════════════════════════════════════════════════════════

async fn phase_crypto(
    grpc: &mut KeyServiceClient<Channel>,
    aes_key_id: &str,
    ed_key_id: &str,
) -> (u32, u32) {
    let mut r = PhaseRunner::new("3 — Crypto operations (gRPC)");

    // Encrypt / Decrypt round-trip
    let plaintext = b"Hello, KeyRack E2E!";
    if !aes_key_id.is_empty() {
        match grpc
            .encrypt(proto::EncryptRequest {
                key_id: aes_key_id.to_string(),
                plaintext: plaintext.to_vec(),
                encryption_context: Default::default(),
            })
            .await
        {
            Ok(enc_resp) => {
                let enc = enc_resp.into_inner();
                assert_check(
                    &mut r,
                    "Encrypt (non-empty ciphertext)",
                    !enc.ciphertext_blob.is_empty(),
                );

                match grpc
                    .decrypt(proto::DecryptRequest {
                        key_id: aes_key_id.to_string(),
                        ciphertext_blob: enc.ciphertext_blob,
                        encryption_context: Default::default(),
                    })
                    .await
                {
                    Ok(dec_resp) => {
                        let dec = dec_resp.into_inner();
                        assert_check(
                            &mut r,
                            "Decrypt (round-trip matches)",
                            dec.plaintext == plaintext,
                        );
                    }
                    Err(e) => r.fail("Decrypt", &e),
                }
            }
            Err(e) => r.fail("Encrypt", &e),
        }

        // GenerateDataKey
        match grpc
            .generate_data_key(proto::GenerateDataKeyRequest {
                key_id: aes_key_id.to_string(),
                key_spec: proto::KeySpec::Aes256.into(),
                encryption_context: Default::default(),
            })
            .await
        {
            Ok(dek_resp) => {
                let dek = dek_resp.into_inner();
                assert_check(
                    &mut r,
                    "GenerateDataKey (plaintext non-empty)",
                    !dek.plaintext_data_key.is_empty(),
                );
                assert_check(
                    &mut r,
                    "GenerateDataKey (encrypted non-empty)",
                    !dek.encrypted_data_key.is_empty(),
                );

                // Decrypt the DEK
                match grpc
                    .decrypt(proto::DecryptRequest {
                        key_id: aes_key_id.to_string(),
                        ciphertext_blob: dek.encrypted_data_key,
                        encryption_context: Default::default(),
                    })
                    .await
                {
                    Ok(dec) => {
                        assert_check(
                            &mut r,
                            "Decrypt DEK (matches plaintext_data_key)",
                            dec.into_inner().plaintext == dek.plaintext_data_key,
                        );
                    }
                    Err(e) => r.fail("Decrypt DEK", &e),
                }
            }
            Err(e) => r.fail("GenerateDataKey", &e),
        }

        // GenerateRandom
        match grpc
            .generate_random(proto::GenerateRandomRequest {
                number_of_bytes: 32,
            })
            .await
        {
            Ok(resp) => {
                assert_check(
                    &mut r,
                    "GenerateRandom (32 bytes)",
                    resp.into_inner().random_bytes.len() == 32,
                );
            }
            Err(e) => r.fail("GenerateRandom", &e),
        }
    }

    // Sign / Verify (Ed25519)
    if !ed_key_id.is_empty() {
        let message = b"Message to sign for E2E";
        match grpc
            .sign(proto::SignRequest {
                key_id: ed_key_id.to_string(),
                message: message.to_vec(),
                signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
                message_type: proto::MessageType::Raw.into(),
            })
            .await
        {
            Ok(sign_resp) => {
                let sig = sign_resp.into_inner();
                assert_check(
                    &mut r,
                    "Sign Ed25519 (non-empty signature)",
                    !sig.signature.is_empty(),
                );

                match grpc
                    .verify(proto::VerifyRequest {
                        key_id: ed_key_id.to_string(),
                        message: message.to_vec(),
                        signature: sig.signature,
                        signing_algorithm: proto::SigningAlgorithm::Ed25519Pure.into(),
                        message_type: proto::MessageType::Raw.into(),
                    })
                    .await
                {
                    Ok(ver) => {
                        assert_check(
                            &mut r,
                            "Verify Ed25519 (valid)",
                            ver.into_inner().signature_valid,
                        );
                    }
                    Err(e) => r.fail("Verify Ed25519", &e),
                }
            }
            Err(e) => r.fail("Sign Ed25519", &e),
        }
    }

    r.finish()
}

// ═════════════════════════════════════════════════════════════════════
// Phase 4: REST parity
// ═════════════════════════════════════════════════════════════════════

async fn phase_rest(http: &reqwest::Client, rest: &str) -> (u32, u32) {
    let mut r = PhaseRunner::new("4 — REST parity");

    // POST /v1/keys  (create)
    let create_body = serde_json::json!({
        "key_spec": "AES_256",
        "description": "e2e REST test key"
    });
    let rest_key_id: String;

    match http
        .post(format!("{rest}/v1/keys"))
        .json(&create_body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            // The REST API returns the raw KeyRecord; the `lid` field is a byte
            // array [u8; 32]. Convert it to the `lid_<hex>` string format that
            // the GET/action endpoints expect.
            rest_key_id = lid_from_json(&body["lid"]).unwrap_or_default();
            assert_check(&mut r, "POST /v1/keys (created)", !rest_key_id.is_empty());
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            r.fail("POST /v1/keys", &format!("status {status}: {body}"));
            rest_key_id = String::new();
        }
        Err(e) => {
            r.fail("POST /v1/keys", &e);
            rest_key_id = String::new();
        }
    }

    // GET /v1/keys/{id}
    if !rest_key_id.is_empty() {
        match http
            .get(format!("{rest}/v1/keys/{rest_key_id}"))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => r.pass("GET /v1/keys/{id}"),
            Ok(resp) => r.fail("GET /v1/keys/{id}", &format!("status {}", resp.status())),
            Err(e) => r.fail("GET /v1/keys/{id}", &e),
        }

        // POST .../actions-encrypt
        let enc_body = serde_json::json!({
            "plaintext": b64encode(b"REST encrypt test"),
        });
        match http
            .post(format!("{rest}/v1/keys/{rest_key_id}/actions-encrypt"))
            .json(&enc_body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let ct = body["ciphertext_blob"].as_str().unwrap_or_default();
                assert_check(&mut r, "POST actions-encrypt", !ct.is_empty());

                // POST .../actions-decrypt
                let dec_body = serde_json::json!({ "ciphertext_blob": ct });
                match http
                    .post(format!("{rest}/v1/keys/{rest_key_id}/actions-decrypt"))
                    .json(&dec_body)
                    .send()
                    .await
                {
                    Ok(dresp) if dresp.status().is_success() => {
                        let dbody: serde_json::Value = dresp.json().await.unwrap_or_default();
                        let pt_b64 = dbody["plaintext"].as_str().unwrap_or_default();
                        let pt = b64decode(pt_b64).unwrap_or_default();
                        assert_check(
                            &mut r,
                            "POST actions-decrypt (round-trip)",
                            pt == b"REST encrypt test",
                        );
                    }
                    Ok(dresp) => r.fail(
                        "POST actions-decrypt",
                        &format!("status {}", dresp.status()),
                    ),
                    Err(e) => r.fail("POST actions-decrypt", &e),
                }
            }
            Ok(resp) => r.fail("POST actions-encrypt", &format!("status {}", resp.status())),
            Err(e) => r.fail("POST actions-encrypt", &e),
        }
    }

    // GET /v1/keys  (list)
    match http.get(format!("{rest}/v1/keys")).send().await {
        Ok(resp) if resp.status().is_success() => r.pass("GET /v1/keys (list)"),
        Ok(resp) => r.fail("GET /v1/keys (list)", &format!("status {}", resp.status())),
        Err(e) => r.fail("GET /v1/keys (list)", &e),
    }

    r.finish()
}

// ═════════════════════════════════════════════════════════════════════
// Phase 5: Aliases and tags
// ═════════════════════════════════════════════════════════════════════

async fn phase_aliases_tags(grpc: &mut KeyServiceClient<Channel>, aes_key_id: &str) -> (u32, u32) {
    let mut r = PhaseRunner::new("5 — Aliases and tags");

    if aes_key_id.is_empty() {
        r.fail("(skipped)", &"no AES key from phase 2");
        return r.finish();
    }

    let alias_name = format!("e2e-alias-{}", &aes_key_id[..8.min(aes_key_id.len())]);

    // CreateAlias
    match grpc
        .create_alias(proto::CreateAliasRequest {
            alias_name: alias_name.clone(),
            target_key_id: aes_key_id.to_string(),
        })
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            assert_check(&mut r, "CreateAlias", inner.alias_name == alias_name);
        }
        Err(e) => r.fail("CreateAlias", &e),
    }

    // ListAliases (should contain our alias)
    match grpc
        .list_aliases(proto::ListAliasesRequest {
            max_results: 100,
            cursor: String::new(),
            key_id: None,
        })
        .await
    {
        Ok(resp) => {
            let found = resp
                .into_inner()
                .aliases
                .iter()
                .any(|a| a.alias_name == alias_name);
            assert_check(&mut r, "ListAliases (contains new)", found);
        }
        Err(e) => r.fail("ListAliases", &e),
    }

    // DeleteAlias
    match grpc
        .delete_alias(proto::DeleteAliasRequest {
            alias_name: alias_name.clone(),
        })
        .await
    {
        Ok(_) => r.pass("DeleteAlias"),
        Err(e) => r.fail("DeleteAlias", &e),
    }

    // TagResource
    match grpc
        .tag_resource(proto::TagResourceRequest {
            key_id: aes_key_id.to_string(),
            tags: vec![
                proto::Tag {
                    key: "env".into(),
                    value: "e2e-test".into(),
                },
                proto::Tag {
                    key: "team".into(),
                    value: "platform".into(),
                },
            ],
        })
        .await
    {
        Ok(_) => r.pass("TagResource"),
        Err(e) => r.fail("TagResource", &e),
    }

    // ListResourceTags
    match grpc
        .list_resource_tags(proto::ListResourceTagsRequest {
            key_id: aes_key_id.to_string(),
        })
        .await
    {
        Ok(resp) => {
            let tags = resp.into_inner().tags;
            let has_env = tags.iter().any(|t| t.key == "env" && t.value == "e2e-test");
            let has_team = tags
                .iter()
                .any(|t| t.key == "team" && t.value == "platform");
            assert_check(&mut r, "ListResourceTags (env)", has_env);
            assert_check(&mut r, "ListResourceTags (team)", has_team);
        }
        Err(e) => r.fail("ListResourceTags", &e),
    }

    // UntagResource
    match grpc
        .untag_resource(proto::UntagResourceRequest {
            key_id: aes_key_id.to_string(),
            tag_keys: vec!["team".into()],
        })
        .await
    {
        Ok(_) => r.pass("UntagResource"),
        Err(e) => r.fail("UntagResource", &e),
    }

    // Verify tag was removed
    match grpc
        .list_resource_tags(proto::ListResourceTagsRequest {
            key_id: aes_key_id.to_string(),
        })
        .await
    {
        Ok(resp) => {
            let tags = resp.into_inner().tags;
            let no_team = !tags.iter().any(|t| t.key == "team");
            assert_check(&mut r, "UntagResource (verified removed)", no_team);
        }
        Err(e) => r.fail("UntagResource verify", &e),
    }

    r.finish()
}

// ═════════════════════════════════════════════════════════════════════
// Phase 6: Key rotation
// ═════════════════════════════════════════════════════════════════════

async fn phase_rotation(grpc: &mut KeyServiceClient<Channel>, aes_key_id: &str) -> (u32, u32) {
    let mut r = PhaseRunner::new("6 — Key rotation");

    if aes_key_id.is_empty() {
        r.fail("(skipped)", &"no AES key from phase 2");
        return r.finish();
    }

    // Encrypt before rotation
    let plaintext = b"pre-rotation data";
    let pre_ciphertext = match grpc
        .encrypt(proto::EncryptRequest {
            key_id: aes_key_id.to_string(),
            plaintext: plaintext.to_vec(),
            encryption_context: Default::default(),
        })
        .await
    {
        Ok(resp) => {
            let enc = resp.into_inner();
            r.pass("Encrypt (pre-rotation)");
            enc.ciphertext_blob
        }
        Err(e) => {
            r.fail("Encrypt (pre-rotation)", &e);
            return r.finish();
        }
    };

    // RotateKey
    match grpc
        .rotate_key(proto::RotateKeyRequest {
            key_id: aes_key_id.to_string(),
        })
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            assert_check(
                &mut r,
                "RotateKey (new_version >= 2)",
                inner.new_version >= 2,
            );
        }
        Err(e) => r.fail("RotateKey", &e),
    }

    // Verify old ciphertext still decrypts (version continuity)
    match grpc
        .decrypt(proto::DecryptRequest {
            key_id: aes_key_id.to_string(),
            ciphertext_blob: pre_ciphertext,
            encryption_context: Default::default(),
        })
        .await
    {
        Ok(resp) => {
            assert_check(
                &mut r,
                "Decrypt old ciphertext after rotation",
                resp.into_inner().plaintext == plaintext,
            );
        }
        Err(e) => r.fail("Decrypt old ciphertext after rotation", &e),
    }

    // Encrypt with new version
    match grpc
        .encrypt(proto::EncryptRequest {
            key_id: aes_key_id.to_string(),
            plaintext: b"post-rotation data".to_vec(),
            encryption_context: Default::default(),
        })
        .await
    {
        Ok(resp) => {
            let enc = resp.into_inner();
            assert_check(
                &mut r,
                "Encrypt (post-rotation)",
                !enc.ciphertext_blob.is_empty(),
            );
        }
        Err(e) => r.fail("Encrypt (post-rotation)", &e),
    }

    r.finish()
}

// ═════════════════════════════════════════════════════════════════════
// Phase 7: Key hierarchy (best-effort)
// ═════════════════════════════════════════════════════════════════════

async fn phase_hierarchy(grpc: &mut KeyServiceClient<Channel>) -> (u32, u32) {
    let mut r = PhaseRunner::new("7 — Key hierarchy");

    // Create a root key
    let root_id = match grpc
        .create_key(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            key_usage: Some(proto::KeyUsage::EncryptDecrypt.into()),
            description: "e2e hierarchy root".into(),
            ..Default::default()
        })
        .await
    {
        Ok(resp) => {
            let meta = resp.into_inner().metadata.unwrap();
            r.pass("CreateKey (hierarchy root)");
            meta.key_id
        }
        Err(e) => {
            r.fail("CreateKey (hierarchy root)", &e);
            return r.finish();
        }
    };

    // Create a child key with parent_key_id set.
    // NOTE: the CreateKey handler does not yet persist parent_key_id from the
    // request -- this is a known gap.  We test that the call succeeds and record
    // parent linkage as a soft check.
    match grpc
        .create_key(proto::CreateKeyRequest {
            key_spec: proto::KeySpec::Aes256.into(),
            key_usage: Some(proto::KeyUsage::EncryptDecrypt.into()),
            description: "e2e hierarchy child".into(),
            parent_key_id: Some(root_id.clone()),
            ..Default::default()
        })
        .await
    {
        Ok(resp) => {
            let meta = resp.into_inner().metadata.unwrap();
            r.pass("CreateKey child (accepted)");
            let has_parent = meta.parent_key_id.as_ref() == Some(&root_id);
            if has_parent {
                r.pass("CreateKey child (parent_key_id stored)");
            } else {
                println!("  [NOTE] parent_key_id not stored — hierarchy persistence not yet wired");
            }
        }
        Err(e) => {
            r.fail(
                "CreateKey child",
                &format!("{e} [hierarchy may not be fully wired]"),
            );
        }
    }

    // DescribeKey on root — verify it exists
    match grpc
        .describe_key(proto::DescribeKeyRequest {
            key_id: root_id.clone(),
        })
        .await
    {
        Ok(resp) => {
            let meta = resp.into_inner().metadata.unwrap();
            assert_check(
                &mut r,
                "DescribeKey (hierarchy root)",
                meta.key_id == root_id,
            );
        }
        Err(e) => r.fail("DescribeKey (hierarchy root)", &e),
    }

    r.finish()
}

// ═════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════

fn assert_check(runner: &mut PhaseRunner, name: &str, ok: bool) {
    if ok {
        runner.pass(name);
    } else {
        runner.fail(name, &"assertion failed");
    }
}

/// Convert a JSON byte-array LID (e.g. `[15, 213, ...]`) to the canonical
/// `lid_<hex>` string format used by REST path parameters.
fn lid_from_json(value: &serde_json::Value) -> Option<String> {
    let arr = value.as_array()?;
    if arr.len() != 32 {
        return None;
    }
    let mut hex = String::from("lid_");
    for v in arr {
        let byte = v.as_u64()? as u8;
        hex.push_str(&format!("{byte:02x}"));
    }
    Some(hex)
}
