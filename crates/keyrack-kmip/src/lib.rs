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
