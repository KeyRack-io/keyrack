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

//! `keyrack audit verify` must be able to check a hash chain with no key.
//!
//! Signing is opt-in, chaining is not. A verifier that demands a signing key
//! makes the chain unusable in exactly the deployments that only have a chain,
//! which is most of them.
//!
//! The chain rule is re-derived by hand here rather than reused from
//! `keyrack-core`, so the test pins the on-disk format instead of agreeing
//! with the implementation by construction.

use keyrack_core::audit::{
    AuditAction, AuditEvent, AuditPrincipal, AuditResource, AuditResult, EventType,
};
use std::io::Write as _;
use std::process::Command;

const CLI_BIN: &str = env!("CARGO_BIN_EXE_keyrack");
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "keyrack-audit-verify-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn write(&self, name: &str, contents: &str) -> std::path::PathBuf {
        let path = self.0.join(name);
        let mut file = std::fs::File::create(&path).expect("create temp file");
        file.write_all(contents.as_bytes()).expect("write file");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn event(resource: &str) -> AuditEvent {
    AuditEvent::new(
        EventType::CryptoOperation,
        AuditAction::Encrypt,
        AuditPrincipal {
            id: "user:alice".into(),
            principal_type: "User".into(),
        },
        AuditResource {
            id: resource.into(),
            resource_type: "Key".into(),
        },
        AuditResult::Success,
    )
}

/// An unsigned, hash-chained JSONL log: each line's `previous_hash` is BLAKE3
/// over the preceding line exactly as written.
fn chained_log(resources: &[&str]) -> String {
    let mut previous_hash = GENESIS_HASH.to_string();
    let mut lines = Vec::new();

    for resource in resources {
        let mut event = event(resource);
        event.previous_hash = Some(previous_hash.clone());
        let line = serde_json::to_string(&event).expect("serialize event");
        previous_hash = blake3::hash(line.as_bytes()).to_hex().to_string();
        lines.push(line);
    }

    let mut log = lines.join("\n");
    log.push('\n');
    log
}

fn run_verify(log_path: &std::path::Path) -> std::process::Output {
    Command::new(CLI_BIN)
        .args(["audit", "verify"])
        .arg(log_path)
        .output()
        .expect("run keyrack audit verify")
}

#[test]
fn verifies_a_hash_chain_without_a_signing_key() {
    let dir = TempDir::new("chain-ok");
    let log = dir.write("audit.log", &chained_log(&["k1", "k2", "k3"]));

    let output = run_verify(&log);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "chain-only verification must succeed without --key.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("3/3 events OK"),
        "unexpected output:\n{stdout}"
    );
}

#[test]
fn rejects_a_tampered_hash_chain_without_a_signing_key() {
    let dir = TempDir::new("chain-tampered");
    let chained = chained_log(&["k1", "k2", "k3"]);

    // Rewrite the first event's resource, leaving every recorded link intact.
    // The chain must notice, and it must notice with no key involved.
    let tampered = chained.replacen("\"id\":\"k1\"", "\"id\":\"k_evil\"", 1);
    assert_ne!(tampered, chained, "tamper step did not modify the log");
    let log = dir.write("audit.log", &tampered);

    let output = run_verify(&log);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !output.status.success(),
        "a tampered chain must fail verification.\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("hash chain break"),
        "failure must be reported as a chain break:\n{stdout}"
    );
}
