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

//! Properties that only a live third-party KMIP server can establish.
//!
//! Whether additional authenticated data is actually covered by the
//! authentication tag is a property of the server, not of this client: a
//! server that accepts the field and ignores it produces a ciphertext that
//! decrypts under any context, and no amount of local testing can tell the
//! difference. So it is asserted here, against a server nobody here wrote.
//!
//! They are `#[ignore]`d so that a workspace test run does not need a server,
//! and are run by `conformance/kmip-provider/run-proof.sh`, which starts one
//! and sets the variables below. `#[ignore]` rather than an environment check
//! that returns early: an absent server has to be reported as "not run", not
//! as a pass, or an unproven backend keeps looking proven.

use keyrack_core::key::KeySpec;
use keyrack_core::provider::CryptoProvider;
use keyrack_kmip::{KmipProvider, KmipProviderConfig};

/// Install a TLS provider, as the service binary does during startup.
///
/// Idempotent: `install_default` fails when one is already installed, and
/// several tests in this file run in the same process.
fn install_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn config_from_env() -> KmipProviderConfig {
    let var = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "{name} is not set. These tests assert against a live KMIP server; run them \
                 through conformance/kmip-provider/run-proof.sh, which starts one. Reporting \
                 success without a server would be the opposite of the point."
            )
        })
    };

    KmipProviderConfig {
        endpoint: var("KEYRACK_KMIP_PROOF_ENDPOINT"),
        client_cert_path: Some(var("KEYRACK_KMIP_PROOF_CLIENT_CERT")),
        client_key_path: Some(var("KEYRACK_KMIP_PROOF_CLIENT_KEY")),
        ca_cert_path: Some(var("KEYRACK_KMIP_PROOF_CA_CERT")),
        timeout_secs: 30,
        username: None,
        password: None,
    }
}

#[tokio::test]
#[ignore = "needs a live KMIP server: conformance/kmip-provider/run-proof.sh"]
async fn additional_authenticated_data_is_bound_by_the_server() {
    install_tls_provider();
    let provider = KmipProvider::new(config_from_env());
    let handle = provider
        .generate_key(&KeySpec::Aes256)
        .await
        .expect("generate_key against the neutral server");

    let context = b"tenant=acme,purpose=payments";
    let out = provider
        .encrypt(&handle, b"bound to a context", context)
        .await
        .expect("encrypt with additional authenticated data");

    let recovered = provider
        .decrypt(&handle, &out.ciphertext, context)
        .await
        .expect("the same context must decrypt");
    assert_eq!(recovered.expose(), b"bound to a context");

    let wrong_context = b"tenant=evil,purpose=payments";
    let result = provider
        .decrypt(&handle, &out.ciphertext, wrong_context)
        .await;
    assert!(
        result.is_err(),
        "decryption succeeded under a different context, so the server accepted the \
         AuthenticatedEncryptionAdditionalData field and did not bind it. Every ciphertext \
         this server produces is then replayable under any context, which is exactly the \
         guarantee the field is supposed to provide"
    );

    provider.destroy_key(&handle).await.expect("destroy_key");
}

#[tokio::test]
#[ignore = "needs a live KMIP server: conformance/kmip-provider/run-proof.sh"]
async fn a_key_is_usable_immediately_after_generate_key() {
    // KMIP objects are created Pre-Active and cannot be used for cryptography
    // until activated, so this fails against any conformant server if
    // generate_key returns without activating.
    install_tls_provider();
    let provider = KmipProvider::new(config_from_env());
    let handle = provider
        .generate_key(&KeySpec::Aes256)
        .await
        .expect("generate_key against the neutral server");

    provider
        .encrypt(&handle, b"usable without a separate activation step", b"")
        .await
        .expect("a key returned by generate_key must be usable, not Pre-Active");

    provider.destroy_key(&handle).await.expect("destroy_key");
}

#[tokio::test]
#[ignore = "needs a live KMIP server: conformance/kmip-provider/run-proof.sh"]
async fn a_destroyed_key_is_gone() {
    // Destroy is refused on an Active object, so this also covers the revoke
    // that has to precede it.
    install_tls_provider();
    let provider = KmipProvider::new(config_from_env());
    let handle = provider
        .generate_key(&KeySpec::Aes256)
        .await
        .expect("generate_key against the neutral server");

    provider
        .destroy_key(&handle)
        .await
        .expect("destroy_key must succeed on a key this provider activated");

    let result = provider.encrypt(&handle, b"after destroy", b"").await;
    assert!(
        result.is_err(),
        "a destroyed key still encrypted, so Destroy did not take effect"
    );
}
