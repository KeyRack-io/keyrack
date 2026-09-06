// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! The signing authority lives in the test parent. The subprocess gets only its
//! public key and owns secret creation/materialization. This wire is provisional.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

struct Harness {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    hello: Value,
    key: SigningKey,
    transcript: String,
}
impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Harness {
    fn new(vault: bool) -> Self {
        let key = SigningKey::generate(&mut OsRng);
        let mut command = Command::new(env!("CARGO_BIN_EXE_keyrack-worker-provisional"));
        command
            .arg("--provisional-harness")
            .arg(STANDARD.encode(key.verifying_key().as_bytes()))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if vault {
            for name in [
                "VAULT_ADDR",
                "KEYRACK_WORKER_VAULT_TOKEN_FILE",
                "KEYRACK_WORKER_VAULT_PARENT",
            ] {
                command.env(
                    name,
                    std::env::var(name).expect("live worker fixture configuration required"),
                );
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
        }
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
            "operation": operation, "input_sha256": hash, "generation": 1, "sequence": sequence,
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
