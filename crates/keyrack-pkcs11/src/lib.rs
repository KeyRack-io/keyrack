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

//! PKCS#11 cryptographic provider for hardware HSMs.
//!
//! Wraps the PKCS#11 C API via the [`cryptoki`] crate (safe Rust bindings).
//! `SoftHSM2` is supported as a software token loaded into this process. Its
//! explicit experimental context-derived wrapping profile requires a startup
//! self-test. No hardware token is qualified for that profile.

#![forbid(unsafe_code)]

mod ecdsa_der;
mod provider;

pub use provider::context_wrapping::CONTEXT_DERIVED_WRAPPING_MECHANISM;
pub use provider::{Pkcs11Provider, Pkcs11ProviderConfig};

#[cfg(feature = "native-a2-conformance")]
pub use provider::native_a2::{NativeA2Session, NativeEnvelope, NativeWrapMode};

#[cfg(feature = "native-a2-conformance")]
pub use provider::native_a2::adapter::NativeA2ConformanceAdapter;
