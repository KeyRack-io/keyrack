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

//! `KeyRack` gRPC + REST service.
//!
//! Implements the full V1 API surface from `KEYRACK_SPEC.md` §3.1.
//! The service delegates to `keyrack-core` traits for crypto, storage,
//! authorization (PDP), and audit.

#![forbid(unsafe_code)]

pub mod cache;
pub mod cert_reload;
pub mod config;
pub mod convert;
pub mod domain;
pub mod grpc;
pub mod metrics;
pub mod ops;
pub mod pdp_grpc;
pub mod pdp_http;
pub mod rest;
pub mod routing;
pub mod secret_ref;
pub mod state;
pub mod workers;

pub mod proto {
    #![allow(
        clippy::doc_markdown,
        clippy::default_trait_access,
        clippy::too_many_lines,
        clippy::similar_names,
        clippy::derive_partial_eq_without_eq,
        clippy::result_large_err
    )]
    tonic::include_proto!("keyrack.v1");
}
