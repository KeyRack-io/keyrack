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

#[test]
fn custody_defaults_to_platform_and_rejects_unknown_values() {
    use keyrack_service::config::NamedProvider;
    use keyrack_service::readiness::ProviderCustody;
    let default: NamedProvider = serde_yaml::from_str("name: one\ntype: software").unwrap();
    assert_eq!(default.custody, ProviderCustody::Platform);
    for (value, expected) in [
        ("platform", ProviderCustody::Platform),
        ("customer", ProviderCustody::Customer),
    ] {
        let entry: NamedProvider =
            serde_yaml::from_str(&format!("name: one\ntype: software\ncustody: {value}")).unwrap();
        assert_eq!(entry.custody, expected);
    }
    assert!(
        serde_yaml::from_str::<NamedProvider>("name: one\ntype: software\ncustody: optional")
            .is_err()
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn loadable_non_pkcs11_library_is_a_local_configuration_error() {
    #[cfg(target_os = "linux")]
    let library = "libc.so.6";
    #[cfg(target_os = "macos")]
    let library = "/usr/lib/libSystem.B.dylib";
    assert!(
        matches!(
            cryptoki::context::Pkcs11::new(library),
            Err(cryptoki::error::Error::MissingSymbol(_))
        ),
        "fixture must load but lack PKCS#11 symbols"
    );
    let config = ProviderConfig::Pkcs11 {
        lib_path: library.into(),
        token_label: "token".into(),
        token_label_ref: None,
        pin: Some("pin".to_owned().into()),
        pin_ref: None,
    };
    assert!(
        validate_remote_config(&config).is_err(),
        "loadable non-PKCS11 library must fail locally"
    );
}
