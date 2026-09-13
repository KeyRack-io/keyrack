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

//! Durable metadata must never silently outlive ephemeral key material.

use keyrack_service::config::ServiceConfig;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn config(body: &str) -> ServiceConfig {
    ServiceConfig::from_yaml(&format!("pdp: {{type: always_deny}}\n{body}")).unwrap()
}

#[test]
fn persistent_metadata_rejects_every_ephemeral_provider_variant() {
    for storage in [
        "{type: sqlite, path: /data/keyrack.db}",
        "{type: postgres, database_url: postgres://localhost/keyrack}",
    ] {
        for provider in ["software", "in_memory"] {
            let candidate = config(&format!(
                "storage: {storage}\nprovider: {{type: {provider}}}\n"
            ));
            let error = candidate
                .validate()
                .expect_err("persistent metadata with ephemeral keys must fail startup");
            assert!(
                error.contains("persistent metadata is paired with ephemeral provider(s): default"),
                "{error}"
            );
            assert!(error.contains("DEVELOPMENT ONLY"), "{error}");
            assert!(error.contains("lost at restart"), "{error}");
        }
    }
}

#[test]
fn nondefault_ephemeral_provider_cannot_hide_behind_durable_default_or_denylist() {
    let candidate = config("storage: {type: sqlite, path: /data/keyrack.db}\nproviders:\n  - {name: hsm, type: pkcs11, lib_path: /missing.so, token_label: token, pin_ref: 'file:pin'}\n  - {name: scratch, type: software}\n  - {name: other, type: in_memory}\ndefault_provider: hsm\nprovider_deny: [scratch, other]\n");
    assert_eq!(
        candidate
            .ephemeral_providers_with_persistent_metadata()
            .unwrap(),
        ["scratch", "other"]
    );
    let error = candidate.validate().unwrap_err();
    assert!(error.contains("scratch, other"), "{error}");
}

#[test]
fn explicit_memory_and_sqlite_memory_are_allowed_but_lookalike_filenames_are_not() {
    for storage in [
        "{type: memory}",
        "{type: sqlite, path: ':memory:'}",
        "{type: sqlite, path: ''}",
    ] {
        let candidate = config(&format!("storage: {storage}\n"));
        candidate.validate().unwrap();
        assert!(candidate
            .ephemeral_providers_with_persistent_metadata()
            .unwrap()
            .is_empty());
    }
    for path in [
        "./:memory:",
        " :memory:",
        ":memory: ",
        "file:metadata.db?mode=rwc",
        "file:metadata.db?mode=memory",
    ] {
        let candidate = config(&format!("storage: {{type: sqlite, path: '{path}'}}\n"));
        assert!(
            candidate.validate().is_err(),
            "path must conservatively require acknowledgement: {path}"
        );
    }
}

#[test]
fn superseded_legacy_software_provider_is_not_active() {
    let candidate = config("storage: {type: sqlite, path: /data/keyrack.db}\nprovider: {type: software}\nproviders:\n  - {name: hsm, type: pkcs11, lib_path: /missing.so, token_label: token, pin_ref: 'file:pin'}\n");
    candidate.validate().unwrap();
    assert!(candidate
        .ephemeral_providers_with_persistent_metadata()
        .unwrap()
        .is_empty());
}

#[test]
fn only_explicit_development_acknowledgement_allows_persistent_ephemeral_pairing() {
    let candidate = config("dev_only_allow_ephemeral_provider_with_persistent_metadata: true\n");
    candidate.validate().unwrap();
    assert_eq!(
        candidate
            .ephemeral_providers_with_persistent_metadata()
            .unwrap(),
        ["default"]
    );
    for flag in [
        "",
        "dev_only_allow_ephemeral_provider_with_persistent_metadata: false\n",
    ] {
        let candidate = config(flag);
        assert!(candidate.validate().is_err());
    }
}

struct RunningService {
    child: std::process::Child,
    directory: std::path::PathBuf,
}

impl RunningService {
    fn spawn(acknowledge: bool) -> Self {
        let directory =
            std::env::temp_dir().join(format!("keyrack-durability-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let config_path = directory.join("service.yaml");
        let config = format!("pdp: {{type: always_deny}}\nauthn: {{type: insecure}}\ngrpc_addr: '127.0.0.1:0'\nrest_addr: '127.0.0.1:0'\nstorage: {{type: sqlite, path: '{}'}}\nprovider: {{type: software}}\ndev_only_allow_ephemeral_provider_with_persistent_metadata: {acknowledge}\n", directory.join("metadata.db").display());
        std::fs::write(&config_path, config).unwrap();
        let output = std::fs::File::create(directory.join("output.log")).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_keyrack-service"))
            .env("KEYRACK_CONFIG", config_path)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap();
        Self { child, directory }
    }

    fn output(&self) -> String {
        std::fs::read_to_string(self.directory.join("output.log")).unwrap()
    }
}

impl Drop for RunningService {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn process_refuses_unsafe_topology_before_creating_metadata() {
    let mut service = RunningService::spawn(false);
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        assert!(
            !service.directory.join("metadata.db").exists(),
            "startup validation must run before opening metadata"
        );
        if let Some(status) = service.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "unsafe service stayed running: {}",
            service.output()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(!status.success());
    assert!(
        !service.directory.join("metadata.db").exists(),
        "startup validation must run before opening metadata"
    );
    assert!(
        service
            .output()
            .contains("persistent metadata is paired with ephemeral provider(s): default"),
        "{}",
        service.output()
    );
}

#[test]
fn process_emits_conspicuous_warning_when_development_acknowledgement_is_used() {
    let mut service = RunningService::spawn(true);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output = service.output();
        if output.contains("WARN")
            && output.contains("dev_only_allow_ephemeral_provider_with_persistent_metadata")
            && output.contains("DEVELOPMENT ONLY")
        {
            break;
        }
        assert!(
            service.child.try_wait().unwrap().is_none(),
            "acknowledged service exited: {output}"
        );
        assert!(
            Instant::now() < deadline,
            "acknowledgement must produce a conspicuous warning: {output}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
