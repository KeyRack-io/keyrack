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
