// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Run with `--features softhsm-init-tests` and `KEYRACK_SOFTHSM_TEST_LIB` pointing
//! at a real `SoftHSM` module. Every fixture owns a disposable store and synthetic
//! credentials; no existing token or operator credential is accessed.
#![cfg(feature = "softhsm-init-tests")]

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard};

const LABEL: &str = "keyrack-init-test";
const USER: &str = "synthetic-user-9821";
const SO: &str = "synthetic-so-6734";
static MODULE_ENV: Mutex<()> = Mutex::new(());

struct Fixture {
    root: PathBuf,
    library: String,
    _guard: MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let guard = MODULE_ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let library = std::env::var("KEYRACK_SOFTHSM_TEST_LIB")
            .expect("softhsm-init-tests requires KEYRACK_SOFTHSM_TEST_LIB; no silent skip");
        let root =
            std::env::temp_dir().join(format!("keyrack-softhsm-init-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("tokens")).unwrap();
        std::fs::create_dir(root.join("secrets")).unwrap();
        std::fs::write(
            root.join("softhsm2.conf"),
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
                root.join("tokens").display()
            ),
        )
        .unwrap();
        let fixture = Self {
            root,
            library,
            _guard: guard,
        };
        fixture.secret("token-label", LABEL);
        fixture.secret("user-pin", USER);
        fixture.secret("so-pin", SO);
        fixture
    }

    fn secret(&self, name: &str, value: &str) {
        std::fs::write(self.root.join("secrets").join(name), value).unwrap();
    }

    fn command(&self) -> Command {
        // The mutation proof runner supplies an isolated rebuilt executable.
        let executable = std::env::var_os("KEYRACK_SOFTHSM_INIT_TEST_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_keyrack-softhsm-init").into());
        let mut command = Command::new(executable);
        command
            .env("KEYRACK_SOFTHSM_LIB", &self.library)
            .env("KEYRACK_SECRET_ROOT", self.root.join("secrets"))
            .env("SOFTHSM2_CONF", self.root.join("softhsm2.conf"))
            .env_remove("KEYRACK_SOFTHSM_TOKEN_LABEL_REF")
            .env_remove("KEYRACK_SOFTHSM_USER_PIN_REF")
            .env_remove("KEYRACK_SOFTHSM_SO_PIN_REF");
        command
    }

    fn run(&self) -> Output {
        self.command().output().unwrap()
    }

    fn module<T>(&self, action: impl FnOnce(&Pkcs11) -> T) -> T {
        let previous = std::env::var_os("SOFTHSM2_CONF");
        std::env::set_var("SOFTHSM2_CONF", self.root.join("softhsm2.conf"));
        let module = Pkcs11::new(&self.library).unwrap();
        module
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .unwrap();
        let result = action(&module);
        module.finalize().unwrap();
        match previous {
            Some(value) => std::env::set_var("SOFTHSM2_CONF", value),
            None => std::env::remove_var("SOFTHSM2_CONF"),
        }
        result
    }

    fn initialized(&self) -> Vec<(String, String, bool)> {
        self.module(|module| {
            let mut tokens: Vec<_> = module
                .get_slots_with_initialized_token()
                .unwrap()
                .into_iter()
                .map(|slot| {
                    let token = module.get_token_info(slot).unwrap();
                    (
                        token.label().to_owned(),
                        token.serial_number().to_owned(),
                        token.user_pin_initialized(),
                    )
                })
                .collect();
            tokens.sort();
            tokens
        })
    }

    fn partial_token(&self, label: &str) {
        self.module(|module| {
            let empty = module
                .get_slots_with_token()
                .unwrap()
                .into_iter()
                .find(|slot| !module.get_token_info(*slot).unwrap().token_initialized())
                .unwrap();
            module.init_token(empty, &pin(SO), label).unwrap();
        });
    }

    fn marker(&self, create: bool) -> usize {
        self.module(|module| {
            let slots = module.get_slots_with_initialized_token().unwrap();
            assert_eq!(slots.len(), 1);
            let session = module.open_rw_session(slots[0]).unwrap();
            session.login(UserType::User, Some(&pin(USER))).unwrap();
            let attrs = [
                Attribute::Class(ObjectClass::DATA),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Label(b"preserve-me".to_vec()),
            ];
            if create {
                session.create_object(&attrs).unwrap();
            }
            let count = session.find_objects(&attrs).unwrap().len();
            session.logout().unwrap();
            session.close().unwrap();
            count
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn pin(value: &str) -> AuthPin {
    AuthPin::new(value.to_owned().into_boxed_str())
}

fn succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn refused(output: &Output, reason: &str) {
    assert!(
        !output.status.success(),
        "initializer accepted forbidden input"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(reason), "unexpected refusal: {stderr}");
    for value in [USER, SO, "synthetic-wrong-1647"] {
        assert!(!stderr.contains(value));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(value));
    }
}

#[test]
fn fresh_and_repeated_initialization_preserve_private_objects() {
    let fixture = Fixture::new();
    succeeded(&fixture.run());
    let before = fixture.initialized();
    assert_eq!(before.len(), 1);
    assert!(before[0].2);
    assert_eq!(fixture.marker(true), 1);
    succeeded(&fixture.run());
    assert_eq!(fixture.initialized(), before);
    assert_eq!(fixture.marker(false), 1);
}

#[test]
fn partial_initialization_resumes_without_reinitializing_token() {
    let fixture = Fixture::new();
    fixture.partial_token(LABEL);
    let before = fixture.initialized();
    assert!(!before[0].2);
    succeeded(&fixture.run());
    let after = fixture.initialized();
    assert_eq!(after[0].1, before[0].1);
    assert!(after[0].2);
    assert_eq!(fixture.marker(true), 1);
}

#[test]
fn wrong_existing_user_pin_is_rejected_without_reset() {
    let fixture = Fixture::new();
    succeeded(&fixture.run());
    assert_eq!(fixture.marker(true), 1);
    fixture.secret("user-pin", "synthetic-wrong-1647");
    refused(&fixture.run(), "user PIN verification failed");
    assert_eq!(fixture.marker(false), 1);
}

#[test]
fn wrong_existing_so_pin_is_rejected_without_reset() {
    let fixture = Fixture::new();
    succeeded(&fixture.run());
    assert_eq!(fixture.marker(true), 1);
    fixture.secret("so-pin", "synthetic-wrong-1647");
    refused(&fixture.run(), "SO PIN verification failed");
    assert_eq!(fixture.marker(false), 1);
}

#[test]
fn wrong_label_cannot_adopt_or_reset_existing_store() {
    let fixture = Fixture::new();
    fixture.partial_token("unrelated-token");
    let before = fixture.initialized();
    refused(&fixture.run(), "different token label");
    assert_eq!(fixture.initialized(), before);
}

#[test]
fn duplicate_labels_cannot_select_arbitrary_token() {
    let fixture = Fixture::new();
    fixture.partial_token(LABEL);
    fixture.partial_token(LABEL);
    let before = fixture.initialized();
    assert_eq!(before.len(), 2);
    refused(&fixture.run(), "multiple initialized tokens");
    assert_eq!(fixture.initialized(), before);
}

#[test]
fn invalid_label_and_pin_are_rejected_before_token_mutation() {
    let fixture = Fixture::new();
    fixture.secret("token-label", &"é".repeat(17));
    refused(&fixture.run(), "token label must");
    assert!(fixture.initialized().is_empty());
    fixture.secret("token-label", LABEL);
    fixture.secret("user-pin", "x");
    refused(&fixture.run(), "PIN length is outside");
    assert!(fixture.initialized().is_empty());
}

#[test]
fn secret_references_and_cli_reject_before_token_mutation() {
    let fixture = Fixture::new();
    let outside = fixture.root.join("outside-pin");
    std::fs::write(&outside, USER).unwrap();
    refused(
        &fixture
            .command()
            .env(
                "KEYRACK_SOFTHSM_USER_PIN_REF",
                format!("file:{}", outside.display()),
            )
            .output()
            .unwrap(),
        "required secret file cannot be resolved",
    );
    assert!(fixture.initialized().is_empty());
    refused(
        &fixture.command().arg(USER).output().unwrap(),
        "arguments are not accepted",
    );
    assert!(fixture.initialized().is_empty());
    std::fs::remove_file(fixture.root.join("secrets/so-pin")).unwrap();
    refused(&fixture.run(), "required secret file cannot be resolved");
    assert!(fixture.initialized().is_empty());
}
