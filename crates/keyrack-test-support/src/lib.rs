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

//! Shared test fixtures and conformance harness for `KeyRack`.
//!
//! This crate provides:
//!
//! - **Conformance test macros** that any `CryptoProvider` or
//!   `StorageBackend` implementation must pass. Phase 2 shim
//!   implementations (AWS KMS, Barbican) validate against this
//!   harness.
//! - **Shared test helpers** for constructing test records, LIDs,
//!   and attribute sets.

#![forbid(unsafe_code)]

pub mod conformance;
pub mod fixtures;
pub mod service_conformance;
