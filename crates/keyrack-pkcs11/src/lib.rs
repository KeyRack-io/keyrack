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

//! PKCS#11 cryptographic provider for hardware HSMs.
//!
//! Wraps the PKCS#11 C API via the [`cryptoki`] crate (safe Rust bindings).
//! Tested against `SoftHSM2` in Docker; production deployments use real
//! HSM hardware via the same PKCS#11 shared library interface.

#![forbid(unsafe_code)]

mod ecdsa_der;
mod provider;

pub use provider::{Pkcs11Provider, Pkcs11ProviderConfig};
