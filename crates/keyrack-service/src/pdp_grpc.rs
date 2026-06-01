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

//! gRPC PDP client implementing `PolicyDecisionPoint`.

use crate::proto;
use crate::proto::pdp_service_client::PdpServiceClient;
use async_trait::async_trait;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::pdp::{
    AttributeValue, AuthzRequest, AuthzResponse, Decision, Obligation, PolicyDecisionPoint,
    PolicyReason,
};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::sync::RwLock;
use tonic::transport::Channel;

pub struct GrpcPdpClient {
    endpoint: String,
    timeout: Duration,
    channel: RwLock<Option<Channel>>,
    tls_config: Option<tonic::transport::ClientTlsConfig>,
}

impl GrpcPdpClient {
    pub fn new(
        endpoint: impl Into<String>,
        timeout: Duration,
        ca_cert: Option<&str>,
        client_cert: Option<&str>,
        client_key: Option<&str>,
    ) -> Result<Self> {
        let endpoint = endpoint.into();

        let tls_config = if ca_cert.is_some() || client_cert.is_some() {
            use tonic::transport::{Certificate, ClientTlsConfig, Identity};

            let mut tls = ClientTlsConfig::new();
            if let Some(ca_path) = ca_cert {
                let pem = std::fs::read(ca_path)
                    .map_err(|e| KeyRackError::Other(format!("failed to read PDP CA cert {ca_path}: {e}")))?;
                tls = tls.ca_certificate(Certificate::from_pem(pem));
            }
            if let (Some(cert_path), Some(key_path)) = (client_cert, client_key) {
                let cert_pem = std::fs::read(cert_path)
                    .map_err(|e| KeyRackError::Other(format!("failed to read PDP client cert: {e}")))?;
                let key_pem = std::fs::read(key_path)
                    .map_err(|e| KeyRackError::Other(format!("failed to read PDP client key: {e}")))?;
                tls = tls.identity(Identity::from_pem(cert_pem, key_pem));
            }
            Some(tls)
        } else {
            None
        };

        Ok(Self {
            endpoint,
            timeout,
            channel: RwLock::new(None),
            tls_config,
        })
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
        let mut ep = Channel::from_shared(self.endpoint.clone())
            .map_err(|e| KeyRackError::Other(format!("invalid PDP gRPC endpoint: {e}")))?
            .timeout(self.timeout);

        if let Some(tls) = &self.tls_config {
            ep = ep.tls_config(tls.clone())
                .map_err(|e| KeyRackError::Other(format!("PDP gRPC TLS config error: {e}")))?;
        }

        let channel = ep
            .connect()
            .await
            .map_err(|e| {
                KeyRackError::Other(format!("failed to connect to PDP at {}: {e}", self.endpoint))
            })?;
        *guard = Some(channel.clone());
        Ok(channel)
    }
}

// ---------------------------------------------------------------------------
// AttributeValue ↔ proto conversion
// ---------------------------------------------------------------------------

fn attr_to_proto(val: &AttributeValue) -> proto::PdpAttributeValue {
    let value = match val {
        AttributeValue::String(s) => {
            proto::pdp_attribute_value::Value::StringValue(s.clone())
        }
        AttributeValue::Bool(b) => proto::pdp_attribute_value::Value::BoolValue(*b),
        AttributeValue::Integer(n) => proto::pdp_attribute_value::Value::IntValue(*n),
        AttributeValue::StringList(list) => {
            proto::pdp_attribute_value::Value::StringList(proto::PdpStringList {
                values: list.clone(),
            })
        }
        AttributeValue::Record(map) => {
            proto::pdp_attribute_value::Value::Record(proto::PdpAttributeRecord {
                fields: attr_map_to_proto(map),
            })
        }
        AttributeValue::RecordList(records) => {
            proto::pdp_attribute_value::Value::RecordList(proto::PdpRecordList {
                records: records
                    .iter()
                    .map(|r| proto::PdpAttributeRecord {
                        fields: attr_map_to_proto(r),
                    })
                    .collect(),
            })
        }
    };
    proto::PdpAttributeValue { value: Some(value) }
}

fn attr_map_to_proto(
    map: &BTreeMap<String, AttributeValue>,
) -> std::collections::HashMap<String, proto::PdpAttributeValue> {
    map.iter().map(|(k, v)| (k.clone(), attr_to_proto(v))).collect()
}

fn attr_from_proto(pv: &proto::PdpAttributeValue) -> Option<AttributeValue> {
    match pv.value.as_ref()? {
        proto::pdp_attribute_value::Value::StringValue(s) => {
            Some(AttributeValue::String(s.clone()))
        }
        proto::pdp_attribute_value::Value::BoolValue(b) => Some(AttributeValue::Bool(*b)),
        proto::pdp_attribute_value::Value::IntValue(n) => Some(AttributeValue::Integer(*n)),
        proto::pdp_attribute_value::Value::StringList(sl) => {
            Some(AttributeValue::StringList(sl.values.clone()))
        }
        proto::pdp_attribute_value::Value::Record(rec) => {
            Some(AttributeValue::Record(attr_map_from_proto(&rec.fields)))
        }
        proto::pdp_attribute_value::Value::RecordList(rl) => {
            Some(AttributeValue::RecordList(
                rl.records
                    .iter()
                    .map(|r| attr_map_from_proto(&r.fields))
                    .collect(),
            ))
        }
        proto::pdp_attribute_value::Value::Timestamp(_) => None,
    }
}

fn attr_map_from_proto(
    map: &std::collections::HashMap<String, proto::PdpAttributeValue>,
) -> BTreeMap<String, AttributeValue> {
    map.iter()
        .filter_map(|(k, v)| attr_from_proto(v).map(|av| (k.clone(), av)))
        .collect()
}

// ---------------------------------------------------------------------------
// Request serialization
// ---------------------------------------------------------------------------

fn authz_to_proto(req: &AuthzRequest) -> proto::PdpAuthorizeRequest {
    proto::PdpAuthorizeRequest {
        pdp_api_version: req.pdp_api_version.clone(),
        request_id: req.request_id.clone(),
        action: req.action.to_string(),
        principal: Some(proto::PdpPrincipal {
            id: req.principal.id.clone(),
            r#type: req.principal.principal_type.clone(),
            attributes: attr_map_to_proto(&req.principal.attributes),
        }),
        resource: Some(proto::PdpResource {
            id: req.resource.id.clone(),
            r#type: req.resource.resource_type.clone(),
            attributes: attr_map_to_proto(&req.resource.attributes),
        }),
        context: Some(proto::PdpRequestContext {
            entries: attr_map_to_proto(&req.context.entries),
        }),
    }
}

// ---------------------------------------------------------------------------
// Response deserialization
// ---------------------------------------------------------------------------

fn decision_from_proto(d: proto::PdpDecision) -> Decision {
    match d {
        proto::PdpDecision::Permit => Decision::Permit,
        proto::PdpDecision::Forbid => Decision::Forbid,
        proto::PdpDecision::Indeterminate | proto::PdpDecision::Unspecified => {
            Decision::Indeterminate
        }
    }
}

fn reason_from_proto(r: proto::PdpPolicyReason) -> PolicyReason {
    PolicyReason {
        policy_id: r.policy_id,
        reason_code: if r.reason_code.is_empty() {
            None
        } else {
            Some(r.reason_code)
        },
        human_message: if r.human_message.is_empty() {
            None
        } else {
            Some(r.human_message)
        },
    }
}

fn obligation_from_proto(o: proto::PdpObligation) -> Obligation {
    Obligation {
        obligation_id: o.obligation_id,
        parameters: attr_map_from_proto(&o.parameters),
    }
}

fn response_from_proto(response: proto::PdpAuthorizeResponse) -> AuthzResponse {
    let decision = proto::PdpDecision::try_from(response.decision)
        .unwrap_or(proto::PdpDecision::Indeterminate);

    AuthzResponse {
        request_id: response.request_id,
        decision: decision_from_proto(decision),
        reasons: response.reasons.into_iter().map(reason_from_proto).collect(),
        obligations: response
            .obligations
            .into_iter()
            .map(obligation_from_proto)
            .collect(),
        policy_version: if response.policy_version.is_empty() {
            None
        } else {
            Some(response.policy_version)
        },
    }
}

// ---------------------------------------------------------------------------
// PolicyDecisionPoint impl
// ---------------------------------------------------------------------------

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

        Ok(response_from_proto(response))
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
