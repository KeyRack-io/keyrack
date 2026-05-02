// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Change Date: 2030-01-01
// Change License: Apache License, Version 2.0

//! PKCS#11 provider conformance tests against SoftHSM2.
//!
//! These tests require the `softhsm-tests` feature and the following
//! environment variables:
//!
//! - `KMS_PKCS11_LIB` — path to the SoftHSM shared library
//! - `KMS_PKCS11_TOKEN_LABEL` — initialized token label
//! - `KMS_PKCS11_PIN` — user PIN for the token
//!
//! Run via Docker: `./scripts/e2e-docker.sh`

#![cfg(feature = "softhsm-tests")]

use keyrack_pkcs11::{Pkcs11Provider, Pkcs11ProviderConfig};

fn make_provider() -> Pkcs11Provider {
    let config = Pkcs11ProviderConfig {
        lib_path: std::env::var("KMS_PKCS11_LIB")
            .expect("KMS_PKCS11_LIB must be set for SoftHSM tests"),
        token_label: std::env::var("KMS_PKCS11_TOKEN_LABEL")
            .expect("KMS_PKCS11_TOKEN_LABEL must be set"),
        pin: std::env::var("KMS_PKCS11_PIN").expect("KMS_PKCS11_PIN must be set"),
    };
    Pkcs11Provider::new(&config).expect("failed to initialize PKCS#11 provider")
}

keyrack_test_support::provider_conformance_tests!(make_provider());
