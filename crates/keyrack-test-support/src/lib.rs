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
