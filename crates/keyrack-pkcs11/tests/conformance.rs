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
