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

use std::time::SystemTime;

use async_trait::async_trait;
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use keyrack_aws_common::KmsAction;
use serde_json::Value;

use crate::KmsProxyError;

/// Real AWS KMS backend that signs requests with SigV4 and forwards them
/// to the actual AWS KMS endpoint. This is the production backend for
/// the proxy — it acts as a transparent pass-through while the proxy
/// layer records metadata on the side.
pub struct AwsKmsBackend {
    client: reqwest::Client,
    region: String,
    endpoint: Option<String>,
    credentials_provider: SharedCredentialsProvider,
}

impl AwsKmsBackend {
    /// Load the default AWS credential chain and build the backend.
    ///
    /// Panics if no credentials provider can be constructed (e.g. no IAM
    /// role, no env vars, no `~/.aws/credentials`).
    pub async fn new(region: &str, endpoint: Option<&str>) -> Self {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;

        let credentials_provider = sdk_config
            .credentials_provider()
            .expect(
                "AWS credentials provider not configured — \
                 set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or attach an IAM role",
            )
            .clone();

        Self {
            client: reqwest::Client::new(),
            region: region.to_string(),
            endpoint: endpoint.map(String::from),
            credentials_provider,
        }
    }

    fn kms_url(&self) -> String {
        self.endpoint.clone().unwrap_or_else(|| {
            format!("https://kms.{}.amazonaws.com", self.region)
        })
    }

    fn kms_host(&self) -> String {
        if let Some(ref ep) = self.endpoint {
            ep.trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("localhost")
                .to_string()
        } else {
            format!("kms.{}.amazonaws.com", self.region)
        }
    }
}

fn action_name(action: &KmsAction) -> &'static str {
    match action {
        KmsAction::CreateKey => "CreateKey",
        KmsAction::Encrypt => "Encrypt",
        KmsAction::Decrypt => "Decrypt",
        KmsAction::Sign => "Sign",
        KmsAction::Verify => "Verify",
        KmsAction::GenerateDataKey => "GenerateDataKey",
        KmsAction::GenerateDataKeyWithoutPlaintext => "GenerateDataKeyWithoutPlaintext",
        KmsAction::ReEncrypt => "ReEncrypt",
        KmsAction::GenerateRandom => "GenerateRandom",
        KmsAction::DescribeKey => "DescribeKey",
        KmsAction::ListKeys => "ListKeys",
        KmsAction::EnableKey => "EnableKey",
        KmsAction::DisableKey => "DisableKey",
        KmsAction::ScheduleKeyDeletion => "ScheduleKeyDeletion",
        KmsAction::CancelKeyDeletion => "CancelKeyDeletion",
        KmsAction::GetKeyPolicy => "GetKeyPolicy",
        KmsAction::PutKeyPolicy => "PutKeyPolicy",
        KmsAction::ListAliases => "ListAliases",
        KmsAction::CreateAlias => "CreateAlias",
        KmsAction::DeleteAlias => "DeleteAlias",
        KmsAction::TagResource => "TagResource",
        KmsAction::UntagResource => "UntagResource",
        KmsAction::ListResourceTags => "ListResourceTags",
        KmsAction::GetKeyRotationStatus => "GetKeyRotationStatus",
        KmsAction::EnableKeyRotation => "EnableKeyRotation",
        KmsAction::DisableKeyRotation => "DisableKeyRotation",
    }
}

#[async_trait]
impl crate::KmsBackend for AwsKmsBackend {
    async fn forward_request(
        &self,
        action: KmsAction,
        body: Value,
    ) -> Result<Value, KmsProxyError> {
        let url = self.kms_url();
        let host = self.kms_host();
        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            KmsProxyError::UpstreamError(format!("failed to serialize request body: {e}"))
        })?;
        let target_header = format!("TrentService.{}", action_name(&action));

        // ── Resolve credentials ────────────────────────────────────
        let creds = self
            .credentials_provider
            .provide_credentials()
            .await
            .map_err(|e| {
                KmsProxyError::UpstreamError(format!("failed to load AWS credentials: {e}"))
            })?;

        let identity: aws_smithy_runtime_api::client::identity::Identity = creds.into();

        // ── SigV4 signing ──────────────────────────────────────────
        let headers_to_sign: Vec<(&str, &str)> = vec![
            ("content-type", "application/x-amz-json-1.1"),
            ("host", &host),
            ("x-amz-target", &target_header),
        ];

        let signing_params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name("kms")
            .time(SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .map_err(|e| {
                KmsProxyError::UpstreamError(format!("failed to build signing params: {e}"))
            })?;

        let signable_request = SignableRequest::new(
            "POST",
            &url,
            headers_to_sign.into_iter(),
            SignableBody::Bytes(&body_bytes),
        )
        .map_err(|e| {
            KmsProxyError::UpstreamError(format!("failed to build signable request: {e}"))
        })?;

        let (signing_instructions, _signature) =
            sign(signable_request, &signing_params.into())
                .map_err(|e| {
                    KmsProxyError::UpstreamError(format!("SigV4 signing failed: {e}"))
                })?
                .into_parts();

        // ── Build & send the real request ──────────────────────────
        let mut request = self
            .client
            .post(&url)
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amz-target", &target_header)
            .body(body_bytes);

        for (name, value) in signing_instructions.headers() {
            let name: &str = name.as_ref();
            let value: &str = value.as_ref();
            request = request.header(name, value);
        }

        let response = request.send().await.map_err(|e| {
            KmsProxyError::UpstreamError(format!("HTTP request to AWS KMS failed: {e}"))
        })?;

        let status = response.status();
        let response_body: Value = response.json().await.map_err(|e| {
            KmsProxyError::UpstreamError(format!(
                "failed to parse AWS KMS response body: {e}"
            ))
        })?;

        if !status.is_success() {
            let error_type = response_body["__type"]
                .as_str()
                .unwrap_or("UnknownError");
            let message = response_body["Message"]
                .as_str()
                .or_else(|| response_body["message"].as_str())
                .unwrap_or("unknown error from AWS KMS");
            return Err(KmsProxyError::UpstreamError(format!(
                "AWS KMS returned {status}: {error_type}: {message}"
            )));
        }

        Ok(response_body)
    }
}
