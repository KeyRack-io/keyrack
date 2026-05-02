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

//! gRPC PDP client implementing `PolicyDecisionPoint`.
//!
//! For stricter typing / lower latency than the HTTP path.
//! Connects to a PDP that exposes the `KeyRack` authz schema
//! over gRPC.
//!
//! Stubbed: the full implementation requires a shared `.proto`
//! definition for the PDP authz service, which is owned by the
//! a partner PDP team (see `PDP_WIRE_FORMAT_REQS.md`).  Once the
//! proto lands, this module will use the generated client stub.

use async_trait::async_trait;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::pdp::{AuthzRequest, AuthzResponse, PolicyDecisionPoint};

/// Placeholder gRPC PDP client.
///
/// Will be fleshed out once the PDP team delivers the `.proto`
/// definition.  For now, every evaluation returns an error
/// indicating that the gRPC PDP path is not yet available.
pub struct GrpcPdpClient {
    endpoint: String,
}

impl GrpcPdpClient {
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

#[async_trait]
impl PolicyDecisionPoint for GrpcPdpClient {
    async fn evaluate(&self, _request: &AuthzRequest) -> Result<AuthzResponse> {
        Err(KeyRackError::Other(format!(
            "gRPC PDP client at {} not yet implemented — awaiting PDP proto definition",
            self.endpoint
        )))
    }
}

impl std::fmt::Debug for GrpcPdpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcPdpClient")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}
