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
//! Verify, and Destroy.
//!
//! ## Connection model
//!
//! Each `KmipProvider` holds the endpoint and TLS configuration.
//! Operations use `tokio::net::TcpStream` + `tokio-rustls` for
//! TLS transport. Connection pooling is a future enhancement.
//!
//! ## Limitations (W1 scope)
//!
//! - TTLV encoding is not yet wired to a real TLS transport; the
//!   current implementation returns `Unimplemented` errors for all
//!   operations, serving as a typed contract and build target.
//! - Full KMIP 2.1 TTLV encoding/decoding will be implemented when
//!   a KMIP test server is available in the CI environment.

#![forbid(unsafe_code)]

mod provider;

pub use provider::{KmipProvider, KmipProviderConfig};
