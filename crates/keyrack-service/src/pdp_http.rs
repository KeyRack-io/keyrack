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

//! HTTP PDP client implementing `PolicyDecisionPoint`.
//!
//! Sends JSON-encoded [`AuthzRequest`] to an external PDP endpoint
//! (OPA, custom HTTP service) and deserializes the
//! [`AuthzResponse`].  Production default.

use async_trait::async_trait;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::pdp::{AuthzRequest, AuthzResponse, Decision, PolicyDecisionPoint};
use std::time::Duration;

pub struct HttpPdpClient {
    endpoint: String,
    timeout: Duration,
    client: reqwest::Client,
}

impl HttpPdpClient {
    pub fn new(endpoint: impl Into<String>, timeout: Duration) -> Result<Self> {
        let endpoint = endpoint.into();
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| KeyRackError::Other(format!("failed to build HTTP PDP client: {e}")))?;

        Ok(Self {
            endpoint,
            timeout,
            client,
        })
    }
}

#[async_trait]
impl PolicyDecisionPoint for HttpPdpClient {
    async fn evaluate(&self, request: &AuthzRequest) -> Result<AuthzResponse> {
        let resp = self
            .client
            .post(&self.endpoint)
            .json(request)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(pdp_endpoint = %self.endpoint, error = %e, "PDP HTTP request failed");
                KeyRackError::Other(format!("PDP unavailable: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(
                pdp_endpoint = %self.endpoint,
                status = %status,
                body = %body,
                "PDP returned error status"
            );
            return Ok(AuthzResponse {
                request_id: request.request_id.clone(),
                decision: Decision::Forbid,
                reasons: vec![format!("PDP returned HTTP {status}")],
                policy_version: None,
            });
        }

        resp.json::<AuthzResponse>().await.map_err(|e| {
            tracing::error!(
                pdp_endpoint = %self.endpoint,
                error = %e,
                "failed to deserialize PDP response"
            );
            KeyRackError::Other(format!("PDP response parse error: {e}"))
        })
    }
}

impl std::fmt::Debug for HttpPdpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpPdpClient")
            .field("endpoint", &self.endpoint)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}
