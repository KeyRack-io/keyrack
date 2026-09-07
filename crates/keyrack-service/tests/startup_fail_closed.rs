// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of KeyRack.
//
// KeyRack is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// KeyRack is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with KeyRack. If not, see <https://www.gnu.org/licenses/>.
//
// Alternative commercial licensing is available; contact the Licensor.

//! Startup-posture regression tests that drive the real `keyrack-service`
//! binary, because the defects they cover live in the wiring between config
//! and runtime rather than inside any single unit.
//!
//! Covered:
//!
//! 1. Omitting `pdp:` is a hard startup error instead of a silent
//!    `always_allow` (authorization fails closed).
//! 2. `sign_audit_events: true` without a persistent key is a hard startup
//!    error unless the ephemeral key is explicitly opted into.
//! 3. Audit events are BLAKE3 hash-chained in a **default, unsigned**
//!    deployment, so `previous_hash` is real tamper evidence rather than an
//!    unpopulated schema field.

use std::io::Read as _;
use std::io::Write as _;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SERVICE_BIN: &str = env!("CARGO_BIN_EXE_keyrack-service");
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A scratch directory that cleans itself up.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let unique = format!(
            "keyrack-startup-{tag}-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn write(&self, name: &str, contents: &str) -> std::path::PathBuf {
        let path = self.0.join(name);
        let mut file = std::fs::File::create(&path).expect("create temp file");
        file.write_all(contents.as_bytes()).expect("write config");
        path
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Kills the service on drop so a test failure never leaks a listener.
struct ServiceProcess(Child);

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port that was free a moment ago. Racy in principle, fine in practice,
/// and far safer than the fixed 50051/8080 defaults inside a test runner.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn spawn_service(config_path: &std::path::Path) -> Child {
    Command::new(SERVICE_BIN)
        .env("KEYRACK_CONFIG", config_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyrack-service")
}

/// Run the service and require that it refuses to start, returning its output.
///
/// A service that keeps running is itself the failure this asserts against, so
/// the wait is bounded and a survivor is killed and reported.
fn expect_startup_failure(config_path: &std::path::Path) -> String {
    let mut child = spawn_service(config_path);
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        match child.try_wait().expect("poll keyrack-service") {
            Some(status) => {
                let mut stderr = String::new();
                if let Some(pipe) = child.stderr.as_mut() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                let mut stdout = String::new();
                if let Some(pipe) = child.stdout.as_mut() {
                    let _ = pipe.read_to_string(&mut stdout);
                }
                assert!(
                    !status.success(),
                    "keyrack-service exited successfully; it must fail closed.\n\
                     stderr:\n{stderr}\nstdout:\n{stdout}"
                );
                return format!("{stderr}\n{stdout}");
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "keyrack-service started and kept serving; it must fail closed on this config"
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

#[test]
fn omitting_the_pdp_block_is_a_hard_startup_error() {
    let dir = TempDir::new("no-pdp");
    // Everything a service needs except an authorization decision.
    let config = dir.write(
        "keyrack.yaml",
        &format!(
            "grpc_addr: \"127.0.0.1:{}\"\n\
             rest_addr: \"127.0.0.1:{}\"\n\
             storage:\n  type: memory\n\
             provider:\n  type: software\n\
             audit:\n  type: stdout\n\
             authn:\n  type: insecure\n",
            free_port(),
            free_port()
        ),
    );

    let output = expect_startup_failure(&config);

    assert!(
        output.contains("`pdp:` is required"),
        "startup error must name the missing pdp block; got:\n{output}"
    );
}

#[test]
fn signing_without_a_persistent_key_is_a_hard_startup_error() {
    let dir = TempDir::new("ephemeral-key");
    let config = dir.write(
        "keyrack.yaml",
        &format!(
            "grpc_addr: \"127.0.0.1:{}\"\n\
             rest_addr: \"127.0.0.1:{}\"\n\
             storage:\n  type: memory\n\
             provider:\n  type: software\n\
             pdp:\n  type: always_allow\n\
             audit:\n  type: stdout\n\
             authn:\n  type: insecure\n\
             sign_audit_events: true\n",
            free_port(),
            free_port()
        ),
    );

    let output = expect_startup_failure(&config);

    assert!(
        output.contains("audit_signing_key_path"),
        "startup error must name the missing signing key path; got:\n{output}"
    );
}

/// The headline defect: a default deployment does not enable signing, and
/// before this fix `previous_hash` was only ever written by the signer. An
/// unsigned deployment therefore produced an audit log with no chain at all.
#[test]
fn unsigned_audit_events_are_hash_chained() {
    let dir = TempDir::new("unsigned-chain");
    let audit_log = dir.path("audit.log");
    let rest_port = free_port();
    let config = dir.write(
        "keyrack.yaml",
        &format!(
            "grpc_addr: \"127.0.0.1:{}\"\n\
             rest_addr: \"127.0.0.1:{rest_port}\"\n\
             storage:\n  type: memory\n\
             provider:\n  type: software\n\
             pdp:\n  type: always_allow\n\
             audit:\n  type: file\n  path: \"{}\"\n\
             authn:\n  type: insecure\n\
             sign_audit_events: false\n",
            free_port(),
            audit_log.display()
        ),
    );

    let service = ServiceProcess(spawn_service(&config));
    let base = format!("http://127.0.0.1:{rest_port}");
    wait_for_health(&base);

    // Three key creations produce at least three audit events, which is
    // enough to exercise genesis plus two links.
    for i in 0..3 {
        create_key(&base, &format!("chain probe {i}"));
    }

    let events = read_audit_log(&audit_log);
    drop(service);

    assert!(
        events.len() >= 3,
        "expected at least 3 audit events, got {}",
        events.len()
    );

    let mut expected_prev = GENESIS_HASH.to_string();
    for (idx, (line, event)) in events.iter().enumerate() {
        let previous_hash = event
            .get("previous_hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "event {} has no previous_hash — the audit log is not chained:\n{line}",
                    idx + 1
                )
            });
        assert_eq!(
            previous_hash,
            expected_prev,
            "event {} breaks the hash chain",
            idx + 1
        );
        assert!(
            event.get("signature").is_none(),
            "signing is off, so no event should carry a signature:\n{line}"
        );

        // An unsigned event's chain link is BLAKE3 over exactly the bytes the
        // sink wrote, so the chain is checkable from the log with no key.
        expected_prev = blake3::hash(line.as_bytes()).to_hex().to_string();
    }
}

fn wait_for_health(base: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build http client");

    while Instant::now() < deadline {
        if client
            .get(format!("{base}/healthz"))
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("keyrack-service never became healthy on {base}");
}

fn create_key(base: &str, description: &str) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build http client");

    let response = client
        .post(format!("{base}/v1/keys"))
        .json(&serde_json::json!({
            "key_spec": "AES_256",
            "description": description,
        }))
        .send()
        .expect("create key request");

    assert!(
        response.status().is_success(),
        "create key failed: {}",
        response.status()
    );
}

/// Each audit line paired with its parsed form. The raw line matters: it is
/// the chain-link preimage for an unsigned event.
fn read_audit_log(path: &std::path::Path) -> Vec<(String, serde_json::Value)> {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read audit log {}: {e}", path.display()));

    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let parsed = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("malformed audit line: {e}\n{line}"));
            (line.to_string(), parsed)
        })
        .collect()
}
