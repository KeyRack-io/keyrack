// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use keyrack_service::config::ProviderConfig;
use keyrack_service::provider_startup::validate_remote_config;

#[test]
fn malformed_remote_configuration_is_not_deferred() {
    for address in [
        "not a url",
        "ftp://localhost",
        "http://",
        "http://user:secret@localhost",
        "http://localhost/?query",
        "http://localhost/#fragment",
    ] {
        let config = ProviderConfig::VaultTransit {
            vault_addr: address.into(),
            vault_token: "token".into(),
            mount_path: None,
        };
        assert!(
            validate_remote_config(&config).is_err(),
            "invalid address must fail locally: {address}"
        );
    }
    for (token, mount) in [
        ("", "transit"),
        ("token\ninvalid", "transit"),
        ("token", ""),
        ("token", "../transit"),
        ("token", "transit?other"),
        ("token", "transit%2fother"),
    ] {
        let config = ProviderConfig::VaultTransit {
            vault_addr: "http://127.0.0.1:1".into(),
            vault_token: token.into(),
            mount_path: Some(mount.into()),
        };
        assert!(
            validate_remote_config(&config).is_err(),
            "invalid local credentials/mount must fail before deferral"
        );
    }
    let valid = ProviderConfig::VaultTransit {
        vault_addr: "http://127.0.0.1:1".into(),
        vault_token: "revoked-but-syntactically-valid".into(),
        mount_path: Some("nested/transit".into()),
    };
    assert!(
        validate_remote_config(&valid).is_ok(),
        "local validation must not connect or authenticate"
    );
}

#[test]
fn missing_native_library_is_a_local_configuration_error() {
    let config = ProviderConfig::Pkcs11 {
        lib_path: "/path/that/does/not/exist/provider.so".into(),
        token_label: "token".into(),
        token_label_ref: None,
        pin: Some("pin".to_owned().into()),
        pin_ref: None,
    };
    assert!(validate_remote_config(&config)
        .unwrap_err()
        .contains("invalid PKCS#11 library"));
}
