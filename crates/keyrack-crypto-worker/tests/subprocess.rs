// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! The signing authority lives in the test parent. The subprocess gets only its
//! public key and owns secret creation/materialization. This wire is provisional.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use keyrack_core::{
    creation::CreationOwner,
    custody::{
        AuthorityGrant, AuthorityIdentity, AuthorityScope, Canonical, ClockDomain, CreationResult,
        CryptoOperation, CustodyContext, CustodyMaterialDescriptor, Evidence, EvidenceKey,
        RequestBinding, Validity, WrappingIdentifier,
    },
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};
use uuid::Uuid;

struct Harness {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    hello: Value,
    key: SigningKey,
    transcript: String,
    reservation: Value,
}
impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Harness {
    fn new(vault: bool) -> Self {
        Self::configured(vault, None)
    }
    fn configured(vault: bool, inert_credential: Option<&std::path::Path>) -> Self {
        let key = SigningKey::generate(&mut OsRng);
        let reservation = json!({"operation": Uuid::new_v4(), "attempt": Uuid::new_v4(),
            "owner": {"instance": Uuid::new_v4(), "generation": 7},
            "envelope_ref": "fixture-subprocess-envelope", "principal": "alice"});
        let mut command = Command::new(env!("CARGO_BIN_EXE_keyrack-worker-provisional"));
        command
            .arg("--provisional-harness")
            .arg(STANDARD.encode(key.verifying_key().as_bytes()))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if vault {
            command.env("KEYRACK_WORKER_CREATION_PLAN", reservation.to_string());
            for name in [
                "VAULT_ADDR",
                "KEYRACK_WORKER_VAULT_TOKEN_FILE",
                "KEYRACK_WORKER_VAULT_PARENT",
            ] {
                if let Some(path) = inert_credential {
                    match name {
                        "VAULT_ADDR" => {
                            command.env(name, "http://127.0.0.1:1");
                        }
                        "KEYRACK_WORKER_VAULT_PARENT" => {
                            command.env(name, "worker-fixture-inert");
                        }
                        _ => {
                            command.env(name, path);
                        }
                    }
                } else {
                    command.env(
                        name,
                        std::env::var(name).expect("live worker fixture configuration required"),
                    );
                }
            }
        }
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let hello: Value = serde_json::from_str(&line).expect("worker must reach ready state");
        assert_ne!(
            hello["pid"].as_u64().unwrap(),
            u64::from(std::process::id())
        );
        Self {
            child,
            input: Some(input),
            output,
            hello,
            key,
            transcript: line,
            reservation,
        }
    }
    fn create_native(&mut self) {
        let context = CustodyContext::from_canonical_bytes(
            &STANDARD
                .decode(self.hello["custody_context"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let request = RequestBinding::from_canonical_bytes(
            &STANDARD
                .decode(self.hello["creation_request"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let owner: CreationOwner =
            serde_json::from_value(self.reservation["owner"].clone()).unwrap();
        assert_eq!(request.operation.to_string(), self.reservation["operation"]);
        assert_eq!(request.attempt.to_string(), self.reservation["attempt"]);
        assert_eq!(request.context_sha256, context.sha256().unwrap());
        assert_eq!(
            STANDARD.encode(request.executor.as_bytes()),
            self.hello["worker"]
        );
        // Independently reconstruct the proposed transcript from launcher intent.
        let mut bytes = b"KeyRack:PROPOSED-worker-generate-request-v1\0".to_vec();
        bytes.extend_from_slice(&request.context_sha256);
        bytes.extend_from_slice(request.operation.as_bytes());
        bytes.extend_from_slice(request.attempt.as_bytes());
        bytes.extend_from_slice(owner.instance.as_bytes());
        bytes.extend_from_slice(&owner.generation.to_be_bytes());
        for value in [
            &self.reservation["envelope_ref"],
            &self.reservation["principal"],
        ] {
            let text = value.as_str().unwrap();
            bytes.extend_from_slice(&(text.len() as u32).to_be_bytes());
            bytes.extend_from_slice(text.as_bytes());
        }
        bytes.extend_from_slice(&256_u16.to_be_bytes());
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(request.request_sha256, expected);
        let mut authority = Evidence {
            issuer: WrappingIdentifier::new("development-authority").unwrap(),
            key_id: WrappingIdentifier::new("development-authority-key").unwrap(),
            claims: AuthorityGrant {
                authority: AuthorityIdentity {
                    issuer: WrappingIdentifier::new("development-authority").unwrap(),
                    scope: AuthorityScope::SecurityDomain {
                        provider_ref: context.wrapping.provider_ref.clone(),
                        security_domain: context.wrapping.security_domain.clone(),
                    },
                    generation: NonZeroU64::new(1).unwrap(),
                },
                request: request.clone(),
                principal: WrappingIdentifier::new("alice").unwrap(),
                operation: CryptoOperation::GenerateWrapped,
                sequence: NonZeroU64::new(1).unwrap(),
                validity: Validity {
                    clock: ClockDomain::ExecutorMonotonicMilliseconds(request.executor),
                    not_before: 0,
                    not_after: 30_000,
                },
                ancestor_not_after: 30_000,
            },
            signature: [0; 64],
        };
        authority.signature = self
            .key
            .sign(&authority.signing_bytes().unwrap())
            .to_bytes();
        let command = json!({"command": "generate", "grant": STANDARD.encode(authority.canonical_bytes().unwrap())});
        let before = self.request(1, "encrypt", b"data", 30_000);
        assert_eq!(
            self.send(&before)["error"],
            "material unavailable or unauthenticated"
        );
        let mut forged = authority.clone();
        forged.signature[0] ^= 1;
        assert!(self.send(&json!({"command": "generate", "grant": STANDARD.encode(forged.canonical_bytes().unwrap())})).get("error").is_some());
        let output = self.send(&command);
        let receipt = Evidence::<CreationResult>::from_canonical_bytes(
            &STANDARD
                .decode(
                    output["creation"]
                        .as_str()
                        .expect("creation evidence required"),
                )
                .unwrap(),
        )
        .unwrap();
        let material = CustodyMaterialDescriptor::from_canonical_bytes(
            &STANDARD
                .decode(output["material"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let trusted = EvidenceKey {
            issuer: WrappingIdentifier::new("development-worker-observation").unwrap(),
            key_id: WrappingIdentifier::new("incarnation-key").unwrap(),
            // Trusted spawned process channel for this test, not key distribution.
            key: ed25519_dalek::VerifyingKey::from_bytes(
                &STANDARD
                    .decode(self.hello["observation_key"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        };
        receipt
            .authenticate(&trusted)
            .unwrap()
            .claims()
            .check_attempt(&request, owner, &material)
            .unwrap();
        assert_eq!(material.context, context);
        assert_eq!(
            material.envelope_ref.as_str(),
            self.reservation["envelope_ref"]
        );
        assert_eq!(
            STANDARD
                .decode(output["authority"].as_str().unwrap())
                .unwrap(),
            authority.canonical_bytes().unwrap()
        );
        assert!(self.send(&command).get("error").is_some());
    }
    fn signed(&self, message: &Value) -> Value {
        let body = serde_json::to_string(message).unwrap();
        let mut bytes = b"KeyRack:UNAPPROVED-worker-harness-authority\0".to_vec();
        bytes.extend_from_slice(body.as_bytes());
        json!({"body": body, "signature": self.key.sign(&bytes).to_bytes().to_vec()})
    }
    fn request(&self, sequence: u64, operation: &str, input: &[u8], expires: u64) -> Value {
        let hash: [u8; 32] = Sha256::digest(input).into();
        let signed = self.signed(&json!({"kind": "grant", "body": {
            "worker": self.hello["worker"], "principal": "alice", "context_sha256": self.hello["context_sha256"],
            "operation": operation, "input_sha256": hash, "generation": 1, "sequence": sequence + u64::from(!self.hello["creation_request"].is_null()),
            "not_before_ms": 0, "expires_ms": expires, "ancestor_expires_ms": expires,
            "residency_until_ms": 60_000,
        }}));
        json!({"command": "execute", "signed": signed, "principal": "alice", "operation": operation, "input": STANDARD.encode(input)})
    }
    fn send(&mut self, value: &Value) -> Value {
        writeln!(
            self.input.as_mut().unwrap(),
            "{}",
            serde_json::to_string(value).unwrap()
        )
        .unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
        let mut line = String::new();
        self.output.read_line(&mut line).unwrap();
        self.transcript.push_str(&line);
        serde_json::from_str(&line).unwrap()
    }

    fn finish(&mut self) {
        drop(self.input.take());
        assert!(self.child.wait().unwrap().success());
        let mut stderr = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(
            stderr.is_empty(),
            "successful worker must not log request or credential data"
        );
    }
}

fn round_trip(vault: bool) {
    let mut worker = Harness::new(vault);
    if vault {
        worker.create_native();
    }
    let request = worker.request(1, "encrypt", b"application data", 30_000);
    let mut forged = request.clone();
    forged["signed"]["signature"][0] = json!(256);
    assert!(worker.send(&forged).get("error").is_some());
    let encrypted = worker.send(&request.clone());
    assert!(encrypted.get("output").is_some());
    assert_eq!(encrypted.as_object().unwrap().len(), 1); // No key/credential field.
    assert!(worker.send(&request).get("error").is_some());
    let bytes = STANDARD
        .decode(encrypted["output"].as_str().unwrap())
        .unwrap();
    let decrypt = worker.request(2, "decrypt", &bytes, 30_000);
    let result = worker.send(&decrypt);
    assert_eq!(
        STANDARD.decode(result["output"].as_str().unwrap()).unwrap(),
        b"application data"
    );
    let expired = worker.request(3, "encrypt", b"data", 0);
    assert_eq!(worker.send(&expired)["error"], "expired authority");
    let signed = worker.signed(&json!({"kind": "fence", "body": {
        "worker": worker.hello["worker"], "security_domain": "development-only", "generation": 2, "expires_ms": 30_000,
    }}));
    let result = worker.send(&json!({"command": "fence", "signed": signed}));
    assert_eq!(result["local_fence"]["purged"].as_array().unwrap().len(), 1);
    let request = worker.request(4, "encrypt", b"data", 30_000);
    assert_eq!(worker.send(&request)["error"], "replayed or fenced request");
    assert!(worker
        .send(&json!({"command": "export_key"}))
        .get("error")
        .is_some());
    assert!(worker
        .send(&json!({"command": "private-sentinel-that-must-not-be-echoed"}))
        .get("error")
        .is_some());
    assert!(!worker
        .transcript
        .contains("private-sentinel-that-must-not-be-echoed"));
    if vault {
        let token = zeroize::Zeroizing::new(
            std::fs::read_to_string(std::env::var("KEYRACK_WORKER_VAULT_TOKEN_FILE").unwrap())
                .unwrap(),
        );
        assert!(
            !worker.transcript.contains(token.as_str()),
            "worker credential leaked to coordinator"
        );
    }
    worker.finish();
}

#[test]
fn separate_process_round_trip_authority_and_local_fence() {
    round_trip(false);
}

#[test]
fn restarted_process_rejects_old_signed_grant() {
    let old = Harness::new(false);
    let old_request = old.request(1, "encrypt", b"data", 30_000);
    let mut new = Harness::new(false);
    // Re-sign for the new verifier, while retaining the old incarnation scope.
    let body: Value =
        serde_json::from_str(old_request["signed"]["body"].as_str().unwrap()).unwrap();
    let mut request = old_request;
    request["signed"] = new.signed(&body);
    assert_eq!(new.send(&request)["error"], "invalid authority");
}

#[test]
fn blocked_coordinator_output_terminates_without_holding_custody_loop() {
    let mut worker = Harness::new(false);
    // Do not drain output. The producer can block on stdin without hanging the
    // runner, which independently checks that the custody process terminates.
    let requests: Vec<_> = (1..=100)
        .map(|seq| worker.request(seq, "encrypt", &vec![42; 16_384], 30_000))
        .collect();
    let stdin = worker.input.take().unwrap();
    let producer = std::thread::spawn(move || {
        let mut stdin = stdin;
        for request in requests {
            if writeln!(stdin, "{request}").is_err() {
                break;
            }
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = worker.child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "worker blocked on coordinator output"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    producer.join().unwrap();
}

#[test]
#[ignore = "requires the A2-owned live Vault fixture; no mock fallback"]
fn real_vault_worker_subprocess_round_trip() {
    round_trip(true);
}

#[cfg(unix)]
#[test]
fn startup_refuses_group_or_world_accessible_worker_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let token = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(token.path(), "credential-sentinel-must-not-be-logged").unwrap();
    let key = SigningKey::generate(&mut OsRng);
    for mode in [0o640, 0o604] {
        std::fs::set_permissions(token.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_keyrack-worker-provisional"))
            .arg("--provisional-harness")
            .arg(STANDARD.encode(key.verifying_key().as_bytes()))
            .env_clear()
            .env("KEYRACK_WORKER_VAULT_TOKEN_FILE", token.path())
            // Deliberately no Vault address: credential rejection must happen
            // first, with no connection or ready event and no token in errors.
            .output()
            .unwrap();
        assert!(!output.status.success(), "mode {mode:o}");
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "worker credential file must be a private regular file owned by worker uid\n"
        );
    }
}

#[cfg(unix)]
#[test]
fn invalid_credential_environment_never_falls_back_to_local_fixture() {
    use std::os::unix::ffi::OsStringExt;
    let key = SigningKey::generate(&mut OsRng);
    let output = Command::new(env!("CARGO_BIN_EXE_keyrack-worker-provisional"))
        .arg("--provisional-harness")
        .arg(STANDARD.encode(key.verifying_key().as_bytes()))
        .env_clear()
        .env(
            "KEYRACK_WORKER_VAULT_TOKEN_FILE",
            std::ffi::OsString::from_vec(vec![0xff]),
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "worker credential file must be a private regular file owned by worker uid\n"
    );
}

#[cfg(unix)]
#[test]
fn native_startup_reaches_authority_wait_without_contacting_vault() {
    use std::os::unix::fs::PermissionsExt;
    let token = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(token.path(), "inert-startup-test-credential").unwrap();
    std::fs::set_permissions(token.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
    // No server on this fixture address. Construction must reach the grant wait
    // without a metadata lookup or datakey request; startup used to fail here.
    let mut worker = Harness::configured(true, Some(token.path()));
    assert!(worker.hello["creation_request"].is_string());
    let before = worker.request(1, "encrypt", b"data", 30_000);
    assert_eq!(
        worker.send(&before)["error"],
        "material unavailable or unauthenticated"
    );
    assert!(worker.send(&json!({"command": "generate", "grant": STANDARD.encode(b"invalid canonical authority")})).get("error").is_some());
    assert!(!worker.transcript.contains("inert-startup-test-credential"));
    worker.finish();
}
