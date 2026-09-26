// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

fn settings() -> (String, String, String) {
    (
        std::env::var("KEYRACK_VAULT_TLS_ADDR").expect("TLS fixture address required"),
        std::env::var("VAULT_TOKEN").expect("fixture token required"),
        std::env::var("KEYRACK_VAULT_CA_CERT").expect("fixture CA required"),
    )
}

fn verification_failure(result: Result<VaultTransitProvider>, cause: &str) {
    let error = result.err().expect("TLS verification must fail");
    let KeyRackError::Provider(message) = error else {
        panic!("TLS verification must be a provider error, got {error}");
    };
    assert!(message.contains("TLS verification failed"), "{message}");
    assert!(message.contains(cause), "{message}");
}

#[tokio::test]
#[ignore = "requires owned TLS Vault fixture"]
async fn tls_private_ca_and_bundle_round_trip() {
    let (addr, token, ca) = settings();
    let bundle = std::env::var("KEYRACK_VAULT_CA_BUNDLE").unwrap();
    for path in [&ca, &bundle] {
        let provider = VaultTransitProvider::new_with_ca_cert(&addr, &token, None, Some(path))
            .await
            .unwrap();
        let key = provider.generate_key(&KeySpec::Aes256).await.unwrap();
        let encrypted = provider
            .encrypt(&key, b"TLS control", b"authenticated context")
            .await
            .unwrap();
        let plaintext = provider
            .decrypt(&key, &encrypted.ciphertext, b"authenticated context")
            .await
            .unwrap();
        assert!(plaintext.expose().as_slice().eq(b"TLS control"));
        provider.destroy_key(&key).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires owned TLS Vault fixture"]
async fn tls_default_and_unrelated_roots_are_refused() {
    let (addr, token, _) = settings();
    verification_failure(
        VaultTransitProvider::new(&addr, &token, None).await,
        "UnknownIssuer",
    );
    let other = std::env::var("KEYRACK_VAULT_OTHER_CA_CERT").unwrap();
    verification_failure(
        VaultTransitProvider::new_with_ca_cert(&addr, &token, None, Some(&other)).await,
        "UnknownIssuer",
    );
}

#[tokio::test]
#[ignore = "requires owned TLS Vault fixture"]
async fn tls_private_ca_does_not_bypass_hostname_verification() {
    let (addr, token, ca) = settings();
    let url = reqwest::Url::parse(&addr).unwrap();
    let port = url.port().unwrap();
    // DNS alone is overridden; CA loading, timeouts, TLS verification and the
    // construction-time health check use the production construction path.
    let client = configured_client(Some(&ca), |builder| {
        builder
            .no_proxy()
            .resolve("wrong-host.invalid", ([127, 0, 0, 1], port).into())
    })
    .unwrap();
    verification_failure(
        VaultTransitProvider::with_client(
            &format!("https://wrong-host.invalid:{port}"),
            &token,
            None,
            client,
        )
        .await,
        "certificate not valid for name \"wrong-host.invalid\"",
    );
}

#[tokio::test]
#[ignore = "requires owned TLS Vault fixture"]
async fn tls_ca_file_errors_fail_construction() {
    let (addr, token, ca) = settings();
    let directory = std::path::Path::new(&ca).parent().unwrap();
    for filename in ["missing.pem", "invalid.pem", "empty.pem", "invalid-der.pem"] {
        let path = directory.join(filename);
        let path = path.to_str().unwrap();
        let error = VaultTransitProvider::new_with_ca_cert(&addr, &token, None, Some(path))
            .await
            .err()
            .expect("invalid CA file must fail construction");
        assert!(
            matches!(error, KeyRackError::Provider(ref message)
            if message.contains("Vault Transit CA file") && message.contains(path)),
            "{error}"
        );
    }
}

#[test]
fn tls_certificate_errors_survive_io_wrappers() {
    for (error, expected) in [
        (
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
            "UnknownIssuer",
        ),
        (
            rustls::Error::NoCertificatesPresented,
            "no certificates presented",
        ),
    ] {
        let wrapped = std::io::Error::other(std::io::Error::other(error));
        assert_eq!(
            tls_verification_failure(&wrapped).as_deref(),
            Some(expected)
        );
    }
    // A transport error whose text resembles TLS is not certificate evidence.
    assert!(tls_verification_failure(&std::io::Error::other(
        "invalid peer certificate: UnknownIssuer"
    ))
    .is_none());
}
