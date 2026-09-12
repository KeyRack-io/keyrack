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

//! Custody loss by **permission removal**, which is a different fault from
//! custody loss by moving the token directory away.
//!
//! Moving the directory gives an immediate, fail-fast error and the token
//! returns on the same slot with the same label, so `C_Initialize` during
//! recovery succeeds and the module is only ever *initialized without the
//! token*. Removing read permission can instead make `C_Initialize` itself
//! fail, which leaves the library finalized and every later call answering
//! `CKR_CRYPTOKI_NOT_INITIALIZED` — a state recovery created and did not
//! recognise.
//!
//! Restoration timing is the second variable. A recovery attempt arms the
//! interval that rations reinitialization, so custody returning *inside* that
//! interval is the case where a caller is refused the recovery that would now
//! work. Both are exercised here.
//!
//! Requires `softhsm-tests`, `KMS_PKCS11_LIB`, `KMS_PKCS11_PIN`,
//! `KMS_PKCS11_TOKEN_LABEL` and `KEYRACK_TEST_TOKEN_DIR`, and must run as a
//! user whose permissions actually restrict it: as root, `chmod` does not
//! deny access and the fault cannot be injected at all.

#![cfg(feature = "softhsm-tests")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use keyrack_core::error::KeyRackError;
use keyrack_core::key::KeySpec;
use keyrack_core::provider::CryptoProvider;
use keyrack_pkcs11::{Pkcs11Provider, Pkcs11ProviderConfig};

/// Directory holding the `SoftHSM` token objects, whose permissions stand in for
/// custody of the token.
fn token_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("KEYRACK_TEST_TOKEN_DIR")
            .expect("KEYRACK_TEST_TOKEN_DIR is required: it is the custody this test removes"),
    )
}

fn config() -> Pkcs11ProviderConfig {
    Pkcs11ProviderConfig {
        lib_path: std::env::var("KMS_PKCS11_LIB").expect("KMS_PKCS11_LIB is required"),
        token_label: std::env::var("KMS_PKCS11_TOKEN_LABEL")
            .expect("KMS_PKCS11_TOKEN_LABEL is required"),
        pin: std::env::var("KMS_PKCS11_PIN").expect("KMS_PKCS11_PIN is required"),
    }
}

fn set_mode(dir: &PathBuf, mode: u32) {
    let mut perms = fs::metadata(dir)
        .expect("token directory is readable before its permissions are changed")
        .permissions();
    perms.set_mode(mode);
    fs::set_permissions(dir, perms).expect("permissions are the test's to change");
}

/// Refuses to run as a user for whom `chmod` is advisory. Without this the
/// test would report a pass having never injected the fault.
fn require_permissions_bite(dir: &PathBuf) {
    set_mode(dir, 0o000);
    let denied = fs::read_dir(dir).is_err();
    set_mode(dir, 0o700);
    assert!(
        denied,
        "this user can read a 0o000 directory, so custody loss cannot be injected; \
         run as a non-root user"
    );
}

/// Custody is lost by permission removal, `C_Initialize` fails during the
/// recovery that follows, custody returns **inside** the interval that rations
/// reinitialization, and the next operation is a rotation — the exact sequence
/// observed in hosted qualification.
///
/// The assertion is deliberately about what the caller is told, not about
/// whether this attempt happened to succeed: a caller that is handed a
/// permanent error stops retrying, and no retry budget can rescue it. A
/// retryable answer is what the recovery mechanism needs from every path that
/// does not itself complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custody_returning_inside_the_throttle_interval_is_not_answered_permanently() {
    let dir = token_dir();
    require_permissions_bite(&dir);

    let provider = Pkcs11Provider::new(&config()).expect("provider initializes with custody");
    let handle = provider
        .generate_key(&KeySpec::Aes256)
        .await
        .expect("key generation with custody");
    let aad = b"custody-permission-loss";
    provider
        .encrypt(&handle, b"baseline", aad)
        .await
        .expect("baseline encrypt with custody");

    // ── custody lost, and the recovery attempt it provokes runs while the
    // directory is unreadable, which is what fails C_Initialize and leaves the
    // library finalized.
    set_mode(&dir, 0o000);
    let during = provider
        .encrypt(&handle, b"during outage", aad)
        .await
        .expect_err("custody is gone; this call cannot succeed");
    eprintln!("during outage: {during:?}");

    // A caller that is told nothing about why recovery did not complete cannot
    // act on the answer, and an operator cannot attribute it afterwards
    // without the module's own logs.
    let reported = during.to_string();
    assert!(
        matches!(during, KeyRackError::ProviderUnavailable(_)),
        "an incomplete recovery is temporary and must read as retryable: {during:?}"
    );
    assert!(
        reported.contains("recovery incomplete"),
        "the answer must say recovery did not complete and why, got: {reported}"
    );

    // ── custody returns inside the interval that rations reinitialization.
    tokio::time::sleep(Duration::from_millis(500)).await;
    set_mode(&dir, 0o700);
    let restored = Instant::now();

    // ── the next operation is a rotation, still inside that interval. This is
    // the call that hosted qualification was answered permanently on.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let rotation = provider.generate_key(&KeySpec::Aes256).await;
    let elapsed = restored.elapsed();
    eprintln!("rotation {elapsed:?} after restoration: {rotation:?}");
    assert!(
        elapsed < MIN_REINIT_INTERVAL,
        "the point of this test is that custody returned inside the interval; \
         it returned {elapsed:?} ago, which no longer exercises it"
    );
    rotation.expect(
        "a rotation after custody returns must recover, whatever a previous attempt \
         left behind and however recently it ran",
    );

    // The token is genuinely usable again, not merely answering.
    provider
        .encrypt(&handle, b"after recovery", aad)
        .await
        .expect("the recovered token does real work");
}

/// Mirrors the provider's own interval. Kept as a literal so a change to the
/// production value shows up here as a deliberate edit rather than silently
/// moving what this test exercises.
const MIN_REINIT_INTERVAL: Duration = Duration::from_secs(2);
