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

//! Standalone Cedar PDP companion for `KeyRack`.
//!
//! This binary wraps the `cedar-policy` crate, serves the `KeyRack`
//! authz request schema over HTTP, and hot-reloads policy bundles.
//!
//! Operators who want Cedar without OPA-level complexity deploy this
//! as a sidecar.  Operators who already use OPA, `AuthZed`, AVP, or
//! another PDP point `KeyRack` at their existing service instead and
//! ignore this binary.
//!
//! **WARNING:** Embedding the PDP in the same trust domain as the key
//! plane collapses the trust boundary.  This binary is documented as
//! dev/test/single-binary smallest-deployment use only.

pub mod engine;
pub mod server;
