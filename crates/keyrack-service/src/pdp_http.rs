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

//! HTTP PDP client implementing `PolicyDecisionPoint`.
//!
//! Sends JSON-encoded [`AuthzRequest`] to an external PDP endpoint
//! (OPA, custom HTTP service) and deserializes the
//! [`AuthzResponse`].  Production default.

use async_trait::async_trait;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::pdp::{AuthzRequest, AuthzResponse, Decision, PolicyDecisionPoint, PolicyReason};
use std::time::Duration;

pub struct HttpPdpClient {
    endpoint: String,
    timeout: Duration,
    client: reqwest::Client,
}

impl HttpPdpClient {
    pub fn new(
        endpoint: impl Into<String>,
        timeout: Duration,
        ca_cert: Option<&str>,
        client_cert: Option<&str>,
        client_key: Option<&str>,
    ) -> Result<Self> {
        let endpoint = endpoint.into();
        let mut builder = reqwest::Client::builder().timeout(timeout);

        if let Some(ca_path) = ca_cert {
            let pem = std::fs::read(ca_path).map_err(|e| {
                KeyRackError::Other(format!("failed to read PDP CA cert {ca_path}: {e}"))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| KeyRackError::Other(format!("invalid PDP CA cert: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }

        if let (Some(cert_path), Some(key_path)) = (client_cert, client_key) {
            let mut id_pem = std::fs::read(cert_path).map_err(|e| {
                KeyRackError::Other(format!("failed to read PDP client cert {cert_path}: {e}"))
            })?;
            let key_pem = std::fs::read(key_path).map_err(|e| {
                KeyRackError::Other(format!("failed to read PDP client key {key_path}: {e}"))
            })?;
            id_pem.push(b'\n');
            id_pem.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&id_pem)
                .map_err(|e| KeyRackError::Other(format!("invalid PDP client identity: {e}")))?;
            builder = builder.identity(identity);
        }

        let client = builder
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
                reasons: vec![PolicyReason {
                    policy_id: "external".into(),
                    reason_code: None,
                    human_message: Some(format!("PDP returned HTTP {status}")),
                }],
                obligations: vec![],
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
