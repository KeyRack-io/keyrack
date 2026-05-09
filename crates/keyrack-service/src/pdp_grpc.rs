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

use crate::proto;
use crate::proto::pdp_service_client::PdpServiceClient;
use async_trait::async_trait;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::pdp::{AuthzRequest, AuthzResponse, Decision, PolicyDecisionPoint, PolicyReason};
use std::time::Duration;
use tokio::sync::RwLock;
use tonic::transport::Channel;

pub struct GrpcPdpClient {
    endpoint: String,
    timeout: Duration,
    channel: RwLock<Option<Channel>>,
}

impl GrpcPdpClient {
    pub fn new(endpoint: impl Into<String>, timeout: Duration) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout,
            channel: RwLock::new(None),
        }
    }

    async fn get_channel(&self) -> Result<Channel> {
        {
            let guard = self.channel.read().await;
            if let Some(ch) = guard.as_ref() {
                return Ok(ch.clone());
            }
        }
        let mut guard = self.channel.write().await;
        if let Some(ch) = guard.as_ref() {
            return Ok(ch.clone());
        }
        let channel = Channel::from_shared(self.endpoint.clone())
            .map_err(|e| KeyRackError::Other(format!("invalid PDP gRPC endpoint: {e}")))?
            .timeout(self.timeout)
            .connect()
            .await
            .map_err(|e| {
                KeyRackError::Other(format!("failed to connect to PDP at {}: {e}", self.endpoint))
            })?;
        *guard = Some(channel.clone());
        Ok(channel)
    }
}

fn decision_from_proto(d: proto::PdpDecision) -> Decision {
    match d {
        proto::PdpDecision::Permit => Decision::Permit,
        proto::PdpDecision::Forbid => Decision::Forbid,
        proto::PdpDecision::Indeterminate | proto::PdpDecision::Unspecified => {
            Decision::Indeterminate
        }
    }
}

fn authz_to_proto(req: &AuthzRequest) -> proto::PdpAuthorizeRequest {
    let context_struct = if req.context.entries.is_empty() {
        None
    } else {
        serde_json::to_value(&req.context.entries)
            .ok()
            .and_then(json_to_prost_struct)
    };

    let attr_struct = if req.resource.attributes.is_empty() {
        None
    } else {
        serde_json::to_value(&req.resource.attributes)
            .ok()
            .and_then(json_to_prost_struct)
    };

    proto::PdpAuthorizeRequest {
        request_id: req.request_id.clone(),
        action: req.action.to_string(),
        principal: Some(proto::PdpPrincipal {
            id: req.principal.id.clone(),
            r#type: req.principal.principal_type.clone(),
        }),
        resource: Some(proto::PdpResource {
            id: req.resource.id.clone(),
            r#type: req.resource.resource_type.clone(),
            attributes: attr_struct,
        }),
        context: context_struct,
    }
}

fn json_to_prost_struct(val: serde_json::Value) -> Option<prost_types::Struct> {
    let obj = val.as_object()?;
    let fields = obj
        .iter()
        .filter_map(|(k, v)| json_to_prost_value(v).map(|pv| (k.clone(), pv)))
        .collect();
    Some(prost_types::Struct { fields })
}

fn json_to_prost_value(val: &serde_json::Value) -> Option<prost_types::Value> {
    let kind = match val {
        serde_json::Value::Null => prost_types::value::Kind::NullValue(0),
        serde_json::Value::Bool(b) => prost_types::value::Kind::BoolValue(*b),
        serde_json::Value::Number(n) => {
            prost_types::value::Kind::NumberValue(n.as_f64().unwrap_or(0.0))
        }
        serde_json::Value::String(s) => prost_types::value::Kind::StringValue(s.clone()),
        serde_json::Value::Array(arr) => {
            let values: Vec<_> = arr.iter().filter_map(json_to_prost_value).collect();
            prost_types::value::Kind::ListValue(prost_types::ListValue { values })
        }
        serde_json::Value::Object(obj) => {
            let fields = obj
                .iter()
                .filter_map(|(k, v)| json_to_prost_value(v).map(|pv| (k.clone(), pv)))
                .collect();
            prost_types::value::Kind::StructValue(prost_types::Struct { fields })
        }
    };
    Some(prost_types::Value { kind: Some(kind) })
}

#[async_trait]
impl PolicyDecisionPoint for GrpcPdpClient {
    async fn evaluate(&self, request: &AuthzRequest) -> Result<AuthzResponse> {
        let channel = self.get_channel().await?;
        let mut client = PdpServiceClient::new(channel);

        let proto_req = authz_to_proto(request);
        let response = client
            .authorize(proto_req)
            .await
            .map_err(|e| {
                if let Ok(mut guard) = self.channel.try_write() {
                    *guard = None;
                }
                tracing::error!(
                    pdp_endpoint = %self.endpoint,
                    error = %e,
                    "PDP gRPC request failed"
                );
                KeyRackError::Other(format!("PDP gRPC error: {e}"))
            })?
            .into_inner();

        let decision = proto::PdpDecision::try_from(response.decision)
            .unwrap_or(proto::PdpDecision::Indeterminate);

        Ok(AuthzResponse {
            request_id: response.request_id,
            decision: decision_from_proto(decision),
            reasons: response
                .reasons
                .into_iter()
                .map(|s| PolicyReason {
                    policy_id: "external".into(),
                    reason_code: None,
                    human_message: Some(s),
                })
                .collect(),
            obligations: vec![],
            policy_version: response.policy_version,
            rate_limit_class: None,
        })
    }
}

impl std::fmt::Debug for GrpcPdpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcPdpClient")
            .field("endpoint", &self.endpoint)
            .field("timeout", &self.timeout)
            .finish()
    }
}
