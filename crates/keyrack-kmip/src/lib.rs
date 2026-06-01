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

//! KMIP client provider for HYOK (Hold Your Own Key) and external HSMs.
//!
//! Implements [`CryptoProvider`] by delegating cryptographic operations
//! to a remote KMIP 2.1 server over TLS. This provider is used when
//! customers retain key custody on their own HSM infrastructure.
//!
//! The KMIP wire protocol uses TTLV (Tag-Type-Length-Value) encoding.
//! This implementation provides a minimal KMIP client sufficient for
//! the `KeyRack` operation set: Create, Get, Encrypt, Decrypt, Sign,
//! Verify, Destroy, and RNG Retrieve.
//!
//! ## Connection model
//!
//! Each `KmipProvider` holds the endpoint and TLS configuration.
//! Connections use `tokio::net::TcpStream` + `tokio-rustls` for
//! TLS transport. A single connection is established lazily on first
//! use and reused for subsequent operations; connection pooling is a
//! future enhancement.

#![forbid(unsafe_code)]

pub mod connection;
pub mod messages;
mod provider;
pub mod ttlv;

pub use provider::{KmipProvider, KmipProviderConfig};
