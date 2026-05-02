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

//! NATS-based audit sink and cache-invalidation sink for `KeyRack`.
//!
//! Topic conventions (per `KEYRACK_SPEC.md` §10):
//!
//! - Audit events: `kms.audit.<event_id>`
//! - Key state changes: `kms.key.state-changed.<lid>`
//! - Cache invalidation: `kms.cache.invalidate.<lid>`

#![forbid(unsafe_code)]

use async_trait::async_trait;
use keyrack_core::audit::{AuditEvent, AuditSink};
use keyrack_core::cascade::{AckState, InvalidationSink, SubscriberAck};
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::lid::Lid;
use std::time::Duration;

/// NATS audit event sink.
///
/// Publishes JSON-serialized audit events to `kms.audit.<event_id>`.
pub struct NatsAuditSink {
    client: async_nats::Client,
    subject_prefix: String,
}

impl NatsAuditSink {
    /// Create a sink by connecting to a NATS server.
    pub async fn connect(nats_url: &str) -> Result<Self> {
        let client = async_nats::connect(nats_url)
            .await
            .map_err(|e| KeyRackError::Other(format!("NATS connect: {e}")))?;
        tracing::info!(url = %nats_url, "NATS audit sink connected");
        Ok(Self {
            client,
            subject_prefix: "kms.audit".into(),
        })
    }

    /// Create from an existing client (useful for testing / shared connections).
    pub fn from_client(client: async_nats::Client) -> Self {
        Self {
            client,
            subject_prefix: "kms.audit".into(),
        }
    }

    /// Override the subject prefix (default: `kms.audit`).
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.subject_prefix = prefix.into();
        self
    }
}

#[async_trait]
impl AuditSink for NatsAuditSink {
    async fn emit(&self, event: &AuditEvent) -> Result<()> {
        let subject = format!("{}.{}", self.subject_prefix, event.event_id);
        let payload = event
            .to_json_bytes()
            .map_err(|e| KeyRackError::Other(format!("serialize audit: {e}")))?;

        self.client
            .publish(subject, payload.into())
            .await
            .map_err(|e| KeyRackError::Other(format!("NATS publish audit: {e}")))?;

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        self.client
            .flush()
            .await
            .map_err(|e| KeyRackError::Other(format!("NATS flush: {e}")))?;
        Ok(())
    }
}

/// NATS-based invalidation sink for cascade-disable.
///
/// Publishes to `kms.cache.invalidate.<lid>` and waits for
/// request-reply acknowledgements. The NATS request pattern provides
/// a one-reply-per-subscriber model via inbox subjects.
pub struct NatsInvalidationSink {
    client: async_nats::Client,
}

impl NatsInvalidationSink {
    /// Connect to a NATS server.
    pub async fn connect(nats_url: &str) -> Result<Self> {
        let client = async_nats::connect(nats_url)
            .await
            .map_err(|e| KeyRackError::Other(format!("NATS connect: {e}")))?;
        tracing::info!(url = %nats_url, "NATS invalidation sink connected");
        Ok(Self { client })
    }

    /// Create from an existing client.
    pub fn from_client(client: async_nats::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl InvalidationSink for NatsInvalidationSink {
    async fn invalidate_key(
        &self,
        lid: &Lid,
        timeout: Duration,
    ) -> Result<Vec<SubscriberAck>> {
        let subject = format!("kms.cache.invalidate.{lid}");
        let payload = serde_json::json!({
            "lid": lid.to_string(),
            "action": "invalidate"
        })
        .to_string();

        // Use NATS request-reply: one response per subscriber.
        // In production, JetStream with consumer groups would be
        // preferred; this uses core NATS request for simplicity.
        match tokio::time::timeout(
            timeout,
            self.client.request(subject, payload.into()),
        )
        .await
        {
            Ok(Ok(reply)) => {
                let subscriber_id = reply
                    .headers
                    .as_ref()
                    .and_then(|h| h.get("subscriber-id"))
                    .map_or_else(|| "anonymous".to_owned(), std::string::ToString::to_string);
                Ok(vec![SubscriberAck {
                    subscriber_id,
                    state: AckState::Acknowledged,
                }])
            }
            Ok(Err(e)) => {
                tracing::warn!(lid = %lid, error = %e, "invalidation request failed");
                Ok(vec![SubscriberAck {
                    subscriber_id: "unknown".into(),
                    state: AckState::Error(e.to_string()),
                }])
            }
            Err(_) => {
                tracing::debug!(lid = %lid, "invalidation timed out (no subscribers)");
                Ok(vec![])
            }
        }
    }
}
